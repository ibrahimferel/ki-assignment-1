"""In-memory limits on login and registration attempts.

This module knows nothing about Flask, the database or passwords. The routes
pass in the client address and an already normalized username.

Rules (a sliding window: blocked while ``limit`` events are younger than
``window`` seconds, free again as soon as the oldest one ages out):

* login, per (address, username): 5 attempts per 15 minutes
* login, per address:             20 attempts per 15 minutes
* registration, per address:      10 attempts per hour

Design decisions:

* ``acquire_*`` checks the limits AND records the attempt in one step under
  one lock, so parallel requests can not slip past a limit before any of them
  has been counted. A refused call records nothing, so hammering a blocked
  key does not extend the block.
* ``login_succeeded`` clears the (address, username) count and gives back the
  address count of that one attempt. The rest of the address count stays: an
  attacker with an account of their own must not be able to reset it.
* Keys are never stored as text. Each one is a keyed BLAKE2b digest of the
  address and the username with a random per-process key, so memory holds no
  usernames or addresses and every entry has the same small size.
* Memory is bounded: each rule keeps at most a fixed number of keys. When it
  is full the key that was least recently used is dropped (its count starts
  from zero again). That favours not locking everybody out over remembering
  every attacker.
* The address is whatever the caller passes (the routes use
  ``request.remote_addr`` only; a forwarded-for header is never trusted).
  IPv6 addresses are grouped by their /64 prefix.

Limits of this design: the counts live in this process only. A restart
empties them and several worker processes do not share them. This module
never logs and never prints.
"""

import hashlib
import ipaddress
import math
import secrets
import threading
import time
from collections import OrderedDict, deque

__all__ = [
    "Decision",
    "LOGIN_IP_LIMIT",
    "LOGIN_PAIR_LIMIT",
    "LOGIN_WINDOW",
    "MALFORMED_USERNAME",
    "MAX_LOGIN_IP_KEYS",
    "MAX_PAIR_KEYS",
    "MAX_REGISTER_IP_KEYS",
    "REGISTER_LIMIT",
    "REGISTER_WINDOW",
    "Throttle",
    "UNKNOWN_ADDRESS",
    "normalize_address",
]

LOGIN_PAIR_LIMIT = 5
LOGIN_IP_LIMIT = 20
LOGIN_WINDOW = 15 * 60
REGISTER_LIMIT = 10
REGISTER_WINDOW = 60 * 60

MAX_PAIR_KEYS = 10_000
MAX_LOGIN_IP_KEYS = 5_000
MAX_REGISTER_IP_KEYS = 5_000

# The username part of the key when the submitted username is not valid, so
# all malformed names from one address share a single bucket.
MALFORMED_USERNAME = "\x00malformed"
UNKNOWN_ADDRESS = "unknown"


def normalize_address(remote_addr):
    """The text used as the client's identity for the limits.

    IPv4 stays as it is, IPv4-mapped IPv6 becomes plain IPv4, other IPv6
    becomes its /64 network. Anything missing or unreadable is ``"unknown"``
    (one shared bucket).
    """
    if not isinstance(remote_addr, str):
        return UNKNOWN_ADDRESS
    try:
        # Python 3.9+ also accepts an IPv6 zone such as "fe80::1%eth0".
        address = ipaddress.ip_address(remote_addr)
    except ValueError:
        return UNKNOWN_ADDRESS
    if address.version == 6:
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network((address, 64), strict=False))
    return str(address)


class Decision:
    """The answer of an ``acquire_*`` call.

    ``allowed`` says whether the attempt may go on. When it may not,
    ``retry_after`` is the number of whole seconds (at least 1) to wait.
    ``ticket`` is only set for an allowed login attempt; hand it to
    ``login_succeeded`` if the login worked.
    """

    __slots__ = ("allowed", "retry_after", "ticket")

    def __init__(self, allowed, retry_after=0, ticket=None):
        self.allowed = allowed
        self.retry_after = retry_after
        self.ticket = ticket


class _Ticket:
    __slots__ = ("pair_key", "ip_key", "stamp", "spent")

    def __init__(self, pair_key, ip_key, stamp):
        self.pair_key = pair_key
        self.ip_key = ip_key
        self.stamp = stamp
        self.spent = False


class _Window:
    """Sliding-window event log for many keys. Not thread safe by itself."""

    def __init__(self, limit, window, max_keys):
        for name, value in (
            ("limit", limit),
            ("window", window),
            ("max_keys", max_keys),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an int")
            if value < 1:
                raise ValueError(f"{name} must be at least 1")
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        # key -> deque of event times, oldest first. Keys are ordered by the
        # time of their newest event, so the front is the least recently used.
        self._events = OrderedDict()

    def __len__(self):
        return len(self._events)

    def wait(self, key, now):
        """Seconds until ``key`` may act again (0 when it may act now)."""
        events = self._events.get(key)
        if events is None:
            return 0.0
        cutoff = now - self.window
        while events and events[0] <= cutoff:
            events.popleft()
        if not events:
            del self._events[key]
            return 0.0
        if len(events) < self.limit:
            return 0.0
        return events[0] + self.window - now

    def add(self, key, now):
        events = self._events.get(key)
        if events is None:
            events = deque()
            self._events[key] = events
        events.append(now)
        self._events.move_to_end(key)
        while len(self._events) > self.max_keys:
            self._events.popitem(last=False)

    def remove_one(self, key, stamp):
        events = self._events.get(key)
        if events is None:
            return
        try:
            events.remove(stamp)
        except ValueError:
            return
        if not events:
            del self._events[key]

    def clear(self, key):
        self._events.pop(key, None)


def _retry_seconds(wait):
    """Whole seconds to wait; ``wait`` is above 0, so this is at least 1."""
    return math.ceil(wait)


class Throttle:
    """Login and registration limits. One instance per application."""

    def __init__(
        self,
        clock=time.monotonic,
        *,
        pair_limit=LOGIN_PAIR_LIMIT,
        login_ip_limit=LOGIN_IP_LIMIT,
        login_window=LOGIN_WINDOW,
        register_limit=REGISTER_LIMIT,
        register_window=REGISTER_WINDOW,
        max_pair_keys=MAX_PAIR_KEYS,
        max_login_ip_keys=MAX_LOGIN_IP_KEYS,
        max_register_ip_keys=MAX_REGISTER_IP_KEYS,
    ):
        self._clock = clock
        self._lock = threading.Lock()
        self._salt = secrets.token_bytes(16)
        self._pair = _Window(pair_limit, login_window, max_pair_keys)
        self._login_ip = _Window(
            login_ip_limit, login_window, max_login_ip_keys
        )
        self._register_ip = _Window(
            register_limit, register_window, max_register_ip_keys
        )

    def _digest(self, *parts):
        # Every part is length-prefixed, so ("a", "bc") and ("ab", "c") can
        # never produce the same key.
        mixer = hashlib.blake2b(key=self._salt, digest_size=16)
        for part in parts:
            data = part.encode("utf-8", "surrogatepass")
            mixer.update(len(data).to_bytes(4, "big"))
            mixer.update(data)
        return mixer.digest()

    def sizes(self):
        """How many keys each rule holds (for tests and monitoring)."""
        with self._lock:
            return {
                "login_pair": len(self._pair),
                "login_ip": len(self._login_ip),
                "register_ip": len(self._register_ip),
            }

    def acquire_login(self, remote_addr, username):
        """Count one login attempt, or refuse it.

        ``username`` must already be normalized, or ``MALFORMED_USERNAME``.
        """
        if not isinstance(username, str):
            raise TypeError("username must be a string")
        address = normalize_address(remote_addr)
        with self._lock:
            now = self._clock()
            ip_key = self._digest("login-ip", address)
            pair_key = self._digest("login-pair", address, username)
            wait = max(
                self._pair.wait(pair_key, now),
                self._login_ip.wait(ip_key, now),
            )
            if wait > 0:
                return Decision(False, _retry_seconds(wait))
            self._pair.add(pair_key, now)
            self._login_ip.add(ip_key, now)
            return Decision(True, 0, _Ticket(pair_key, ip_key, now))

    def login_succeeded(self, ticket):
        """Forget the failures of this (address, username) and give back the
        address count of this one attempt. Calling it twice does nothing."""
        with self._lock:
            if ticket.spent:
                return
            ticket.spent = True
            self._pair.clear(ticket.pair_key)
            self._login_ip.remove_one(ticket.ip_key, ticket.stamp)

    def acquire_register(self, remote_addr):
        """Count one registration attempt, or refuse it."""
        address = normalize_address(remote_addr)
        with self._lock:
            now = self._clock()
            key = self._digest("register-ip", address)
            wait = self._register_ip.wait(key, now)
            if wait > 0:
                return Decision(False, _retry_seconds(wait))
            self._register_ip.add(key, now)
            return Decision(True)
