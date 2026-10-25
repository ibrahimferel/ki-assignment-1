"""Tests for app/auth/throttle.py (the limiter on its own, no Flask)."""

import ast
import random
import threading
import time
from pathlib import Path

import pytest

from app.auth import throttle
from app.auth.throttle import (
    LOGIN_IP_LIMIT,
    LOGIN_PAIR_LIMIT,
    LOGIN_WINDOW,
    MALFORMED_USERNAME,
    MAX_LOGIN_IP_KEYS,
    MAX_PAIR_KEYS,
    MAX_REGISTER_IP_KEYS,
    REGISTER_LIMIT,
    REGISTER_WINDOW,
    Throttle,
    normalize_address,
)

SOURCE = Path(throttle.__file__)
IP = "203.0.113.7"


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def gate(clock):
    return Throttle(clock)


def attempts(gate, count, ip=IP, user="alice"):
    return [gate.acquire_login(ip, user) for _ in range(count)]


# ------------------------------------------------------------------ the rules


def test_the_numbers_are_the_agreed_ones():
    assert LOGIN_PAIR_LIMIT == 5
    assert LOGIN_IP_LIMIT == 20
    assert LOGIN_WINDOW == 900
    assert REGISTER_LIMIT == 10
    assert REGISTER_WINDOW == 3600
    assert MAX_PAIR_KEYS == 10_000
    assert MAX_LOGIN_IP_KEYS == 5_000
    assert MAX_REGISTER_IP_KEYS == 5_000
    assert MALFORMED_USERNAME == "\x00malformed"


def test_the_default_gate_uses_the_agreed_numbers():
    gate = Throttle()
    results = attempts(gate, 6)
    assert [d.allowed for d in results] == [True] * 5 + [False]
    assert results[5].retry_after == 900


def test_the_fifth_attempt_passes_and_the_sixth_is_refused(gate):
    results = attempts(gate, 6)
    assert [d.allowed for d in results] == [True] * 5 + [False]
    assert all(d.ticket is not None for d in results[:5])
    assert results[5].ticket is None
    assert results[5].retry_after == 900


def test_retry_after_counts_down_from_the_oldest_attempt(gate, clock):
    attempts(gate, 5)
    clock.advance(100)
    assert gate.acquire_login(IP, "alice").retry_after == 800
    clock.advance(0.5)
    # 799.5 seconds left, rounded up
    assert gate.acquire_login(IP, "alice").retry_after == 800
    clock.advance(798.9)
    assert gate.acquire_login(IP, "alice").retry_after == 1  # never 0


def test_retry_after_is_a_plain_int(gate):
    attempts(gate, 5)
    assert type(gate.acquire_login(IP, "alice").retry_after) is int


def test_the_window_edge_is_exact(gate, clock):
    attempts(gate, 5)
    first = clock.now
    clock.now = first + 899.999
    assert not gate.acquire_login(IP, "alice").allowed
    clock.now = first + 900  # exactly 900 s after the first attempts
    assert gate.acquire_login(IP, "alice").allowed


def test_attempts_age_out_one_by_one(gate, clock):
    for _ in range(5):
        assert gate.acquire_login(IP, "alice").allowed
        clock.advance(100)
    # t = 500: attempts at 0, 100, 200, 300, 400 -> blocked
    assert not gate.acquire_login(IP, "alice").allowed
    clock.advance(400)  # t = 900: only the attempt at 0 has aged out
    assert gate.acquire_login(IP, "alice").allowed
    blocked = gate.acquire_login(IP, "alice")
    assert not blocked.allowed
    assert blocked.retry_after == 100  # until the attempt made at t = 100


def test_a_refused_attempt_is_not_counted_so_the_block_is_not_extended(
    gate, clock
):
    attempts(gate, 5)
    for _ in range(50):
        clock.advance(10)
        assert not gate.acquire_login(IP, "alice").allowed
    clock.advance(400.0)  # 900 s after the first five
    assert gate.acquire_login(IP, "alice").allowed


def test_other_usernames_and_other_addresses_are_not_affected(gate):
    attempts(gate, 5, ip=IP, user="alice")
    assert not gate.acquire_login(IP, "alice").allowed
    assert gate.acquire_login(IP, "bobby").allowed
    assert gate.acquire_login("198.51.100.9", "alice").allowed


def test_the_address_limit_counts_all_usernames(gate):
    for number in range(20):
        assert gate.acquire_login(IP, f"user{number}").allowed
    blocked = gate.acquire_login(IP, "brand-new")
    assert not blocked.allowed
    assert blocked.retry_after == 900
    assert gate.acquire_login("198.51.100.9", "brand-new").allowed


def test_the_address_limit_has_its_own_fifteen_minute_window(gate, clock):
    for number in range(20):
        gate.acquire_login(IP, f"user{number}")
        clock.advance(10)
    # first attempt was at t0, now t0 + 200
    blocked = gate.acquire_login(IP, "x")
    assert not blocked.allowed and blocked.retry_after == 700
    clock.advance(700)
    assert gate.acquire_login(IP, "x").allowed


def test_the_longer_of_two_waits_is_reported(clock):
    gate = small(clock, pair_limit=2, login_ip_limit=3)
    gate.acquire_login(IP, "other")  # address event at t0
    clock.advance(50)
    gate.acquire_login(IP, "alice")
    gate.acquire_login(IP, "alice")  # pair full; address full too
    clock.advance(10)
    blocked = gate.acquire_login(IP, "alice")
    assert not blocked.allowed
    assert blocked.retry_after == 90  # the pair rule (50 + 100 - 60), not 40


def test_the_address_rule_can_be_the_blocker_while_the_pair_is_free(gate):
    for number in range(20):
        gate.acquire_login(IP, f"user{number}")
    assert not gate.acquire_login(IP, "user0").allowed
    assert gate.sizes()["login_pair"] == 20


def test_malformed_usernames_share_one_bucket(gate):
    attempts(gate, 5, user=MALFORMED_USERNAME)
    assert not gate.acquire_login(IP, MALFORMED_USERNAME).allowed
    assert gate.acquire_login(IP, "alice").allowed


# --------------------------------------------------------------------- success


def small(clock, **kw):
    options = dict(pair_limit=2, login_ip_limit=4, login_window=100,
                   register_limit=3, register_window=1000)
    options.update(kw)
    return Throttle(clock, **options)


def test_success_clears_the_pair_count(clock):
    gate = small(clock)
    gate.acquire_login(IP, "alice")
    ticket = gate.acquire_login(IP, "alice").ticket
    assert not gate.acquire_login(IP, "alice").allowed
    gate.login_succeeded(ticket)
    assert gate.acquire_login(IP, "alice").allowed
    assert gate.acquire_login(IP, "alice").allowed
    assert not gate.acquire_login(IP, "alice").allowed


def test_success_gives_back_exactly_one_address_attempt(clock):
    gate = small(clock)
    gate.acquire_login(IP, "a")
    gate.acquire_login(IP, "b")
    ticket = gate.acquire_login(IP, "c").ticket
    gate.acquire_login(IP, "d")  # address now at 4 of 4
    assert not gate.acquire_login(IP, "e").allowed
    gate.login_succeeded(ticket)  # 3 of 4
    assert gate.acquire_login(IP, "e").allowed
    assert not gate.acquire_login(IP, "f").allowed


def test_success_does_not_touch_other_pairs_or_addresses(clock):
    gate = small(clock)
    gate.acquire_login(IP, "bobby")
    gate.acquire_login(IP, "bobby")
    gate.acquire_login("198.51.100.9", "alice")
    gate.acquire_login("198.51.100.9", "alice")
    ticket = gate.acquire_login(IP, "alice").ticket
    gate.login_succeeded(ticket)
    assert not gate.acquire_login(IP, "bobby").allowed
    assert not gate.acquire_login("198.51.100.9", "alice").allowed


def test_a_successful_login_in_between_does_not_reset_the_address(clock):
    # An attacker who owns one account logs in with it between guesses. That
    # must not reset the address count.
    gate = small(clock, login_ip_limit=6, pair_limit=5)
    for number in range(6):
        own = gate.acquire_login(IP, "mine")
        assert own.allowed
        gate.login_succeeded(own.ticket)
        assert gate.acquire_login(IP, f"victim{number}").allowed
    assert not gate.acquire_login(IP, "victim-last").allowed
    assert not gate.acquire_login(IP, "mine").allowed


def test_success_twice_gives_back_only_once(clock):
    gate = small(clock)
    ticket = gate.acquire_login(IP, "a").ticket
    gate.acquire_login(IP, "b")
    gate.acquire_login(IP, "c")
    gate.acquire_login(IP, "d")  # 4 of 4
    gate.login_succeeded(ticket)  # 3 of 4
    gate.login_succeeded(ticket)  # must change nothing
    assert gate.acquire_login(IP, "e").allowed  # 4 of 4
    assert not gate.acquire_login(IP, "f").allowed


def test_success_after_the_attempt_has_aged_out_is_harmless(clock):
    gate = small(clock)
    ticket = gate.acquire_login(IP, "a").ticket
    clock.advance(1000)
    gate.login_succeeded(ticket)
    assert gate.acquire_login(IP, "a").allowed


def test_allowed_decisions_ask_for_no_waiting(gate):
    login = gate.acquire_login(IP, "alice")
    register = gate.acquire_register(IP)
    assert login.allowed and login.retry_after == 0
    assert register.allowed and register.retry_after == 0


def test_a_refused_lookup_leaves_no_empty_key_behind(clock):
    gate = small(clock, login_ip_limit=3)
    gate.acquire_login(IP, "alice")  # t = 0
    clock.advance(60)
    gate.acquire_login(IP, "b")
    clock.advance(10)
    gate.acquire_login(IP, "c")
    clock.advance(30)  # t = 100: alice's attempt has just aged out
    assert gate.acquire_login(IP, "d").allowed  # the address is full again
    clock.advance(1)
    assert not gate.acquire_login(IP, "alice").allowed  # blocked by address
    assert gate.sizes()["login_pair"] == 3  # b, c, d; alice was dropped


def test_trying_again_makes_a_key_recent(clock):
    gate = small(clock, pair_limit=3, login_ip_limit=100, max_pair_keys=3)
    for name in ("a", "b", "c"):
        gate.acquire_login(IP, name)
        clock.advance(1)
    gate.acquire_login(IP, "a")  # a is now the most recent
    clock.advance(1)
    gate.acquire_login(IP, "d")  # evicts b, not a
    assert gate.sizes()["login_pair"] == 3
    gate.acquire_login(IP, "a")
    gate.acquire_login(IP, "a")
    assert not gate.acquire_login(IP, "a").allowed  # a kept all 3 attempts
    assert gate.acquire_login(IP, "b").allowed  # b was forgotten


def test_giving_back_the_only_attempt_leaves_nothing_behind(clock):
    gate = small(clock)
    ticket = gate.acquire_login(IP, "alice").ticket
    gate.login_succeeded(ticket)
    assert gate.sizes() == {"login_pair": 0, "login_ip": 0, "register_ip": 0}


# ---------------------------------------------------------------- registration


def test_registration_allows_ten_an_hour(gate, clock):
    results = [gate.acquire_register(IP) for _ in range(11)]
    assert [d.allowed for d in results] == [True] * 10 + [False]
    assert results[10].retry_after == 3600
    assert all(d.ticket is None for d in results)
    clock.advance(3599)
    assert not gate.acquire_register(IP).allowed
    clock.advance(1)
    assert gate.acquire_register(IP).allowed


def test_registration_refusals_do_not_extend_the_block(gate, clock):
    first = clock.now
    for _ in range(10):
        gate.acquire_register(IP)
    for _ in range(20):
        clock.advance(100)
        assert not gate.acquire_register(IP).allowed
    clock.now = first + 3600  # counted from the first ten, not the refusals
    assert gate.acquire_register(IP).allowed


def test_registration_and_login_counts_are_separate(gate):
    for _ in range(10):
        gate.acquire_register(IP)
    assert not gate.acquire_register(IP).allowed
    assert gate.acquire_login(IP, "alice").allowed
    attempts(gate, 4, user="alice")
    assert not gate.acquire_login(IP, "alice").allowed
    assert gate.acquire_register("198.51.100.9").allowed


def test_registration_is_per_address(gate):
    for _ in range(10):
        gate.acquire_register(IP)
    assert gate.acquire_register("198.51.100.9").allowed


# --------------------------------------------------------- the client address


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203.0.113.7", "203.0.113.7"),
        ("127.0.0.1", "127.0.0.1"),
        ("::ffff:203.0.113.7", "203.0.113.7"),
        ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"),
        ("2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"),
        ("2001:db8:1:3::1", "2001:db8:1:3::/64"),
        ("fe80::1%eth0", "fe80::/64"),
        ("::1", "::/64"),
        (None, "unknown"),
        ("", "unknown"),
        ("not an address", "unknown"),
        ("203.0.113.7:8000", "unknown"),
        ("203.0.113.256", "unknown"),
        (b"203.0.113.7", "unknown"),
        (7, "unknown"),
    ],
)
def test_normalize_address(raw, expected):
    assert normalize_address(raw) == expected


def test_one_ipv6_network_is_one_client(gate):
    for number in range(20):
        address = f"2001:db8:1:2::{number:x}"
        assert gate.acquire_login(address, f"u{number}").allowed
    assert not gate.acquire_login("2001:db8:1:2:aaaa::1", "new").allowed
    assert gate.acquire_login("2001:db8:1:3::1", "new").allowed


def test_a_mapped_address_counts_as_the_plain_one(gate):
    attempts(gate, 5, ip="203.0.113.7")
    assert not gate.acquire_login("::ffff:203.0.113.7", "alice").allowed


def test_missing_addresses_share_one_bucket(gate):
    for _ in range(10):
        gate.acquire_register(None)
    assert not gate.acquire_register("garbage").allowed
    assert gate.acquire_register(IP).allowed


# ----------------------------------------------------------- memory is bounded


def test_each_rule_keeps_at_most_its_maximum_number_of_keys(clock):
    gate = small(clock, max_pair_keys=3, max_login_ip_keys=2,
                 max_register_ip_keys=2)
    for number in range(50):
        gate.acquire_login(f"10.0.0.{number}", f"user{number}")
        gate.acquire_register(f"10.0.1.{number}")
        sizes = gate.sizes()
        assert sizes["login_pair"] <= 3
        assert sizes["login_ip"] <= 2
        assert sizes["register_ip"] <= 2
    assert gate.sizes() == {"login_pair": 3, "login_ip": 2, "register_ip": 2}


def test_the_least_recently_used_key_is_dropped_first(clock):
    gate = small(clock, pair_limit=1, login_ip_limit=100, max_pair_keys=3)
    for name in ("a", "b", "c"):
        assert gate.acquire_login(IP, name).allowed
        clock.advance(1)
    assert not gate.acquire_login(IP, "a").allowed  # a is full, a lookup
    assert gate.acquire_login(IP, "d").allowed  # evicts "a", the oldest
    assert gate.acquire_login(IP, "a").allowed  # forgotten: counted anew
    assert not gate.acquire_login(IP, "d").allowed  # d, c were kept
    assert not gate.acquire_login(IP, "c").allowed


def test_a_lookup_does_not_make_a_key_look_recent(clock):
    gate = small(clock, pair_limit=1, login_ip_limit=100, max_pair_keys=2)
    gate.acquire_login(IP, "a")
    clock.advance(1)
    gate.acquire_login(IP, "b")
    for _ in range(5):
        assert not gate.acquire_login(IP, "a").allowed  # refused lookups
    gate.acquire_login(IP, "c")  # evicts "a" (oldest by attempt time)
    assert gate.acquire_login(IP, "a").allowed


def test_expired_keys_are_removed_when_they_are_looked_at(gate, clock):
    attempts(gate, 1)
    assert gate.sizes()["login_pair"] == 1
    clock.advance(901)
    gate.acquire_login(IP, "alice")
    assert gate.sizes() == {"login_pair": 1, "login_ip": 1, "register_ip": 0}


def test_no_key_ever_holds_more_than_its_limit(clock):
    gate = small(clock)
    rng = random.Random(7)
    for _ in range(500):
        clock.advance(rng.random() * 20)
        gate.acquire_login(rng.choice(["1.1.1.1", "2.2.2.2"]),
                           rng.choice(["a", "b", "c"]))
    for window in (gate._pair, gate._login_ip):
        assert all(len(q) <= window.limit for q in window._events.values())


# ------------------------------------------------------------- the state kept


def test_no_username_or_address_is_kept_as_text(gate):
    gate.acquire_login("203.0.113.7", "alice")
    gate.acquire_register("203.0.113.7")
    for window in (gate._pair, gate._login_ip, gate._register_ip):
        for key in window._events:
            assert isinstance(key, bytes) and len(key) == 16
            assert b"alice" not in key and b"203.0.113.7" not in key


def test_keys_depend_on_a_random_per_instance_salt():
    first, second = Throttle(), Throttle()
    assert first._digest("login-pair", "1.1.1.1", "a") == first._digest(
        "login-pair", "1.1.1.1", "a")
    assert first._digest("x", "a") != second._digest("x", "a")


def test_digest_parts_can_not_run_together(gate):
    assert gate._digest("a", "bc") != gate._digest("ab", "c")
    assert gate._digest("", "abc") != gate._digest("abc", "")


def test_the_three_rules_use_different_keys_for_one_address(gate):
    gate.acquire_login(IP, "alice")
    gate.acquire_register(IP)
    keys = [set(w._events) for w in (gate._pair, gate._login_ip,
                                     gate._register_ip)]
    assert not (keys[0] & keys[1] or keys[0] & keys[2] or keys[1] & keys[2])


def test_lone_surrogates_in_a_username_do_not_crash(gate):
    assert gate.acquire_login(IP, "bad\udc80name").allowed


def test_the_username_must_be_text(gate):
    for value in (None, 5, b"alice"):
        with pytest.raises(TypeError):
            gate.acquire_login(IP, value)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"pair_limit": 0}, {"pair_limit": -1}, {"login_ip_limit": 0},
        {"login_window": 0}, {"register_limit": 0}, {"register_window": 0},
        {"max_pair_keys": 0}, {"max_login_ip_keys": 0},
        {"max_register_ip_keys": 0},
    ],
)
def test_nonsense_settings_are_refused(kwargs):
    with pytest.raises(ValueError):
        Throttle(**kwargs)


@pytest.mark.parametrize(
    "kwargs", [{"pair_limit": 1.5}, {"login_window": "900"},
               {"register_limit": True}, {"max_pair_keys": None}]
)
def test_settings_must_be_whole_numbers(kwargs):
    with pytest.raises(TypeError):
        Throttle(**kwargs)


# ------------------------------------------------- against a simple model


def test_it_agrees_with_a_naive_model_on_random_sequences():
    for seed in range(200):
        rng = random.Random(seed)
        clock = Clock(0.0)
        gate = Throttle(clock, pair_limit=2, login_ip_limit=4,
                        login_window=10, register_limit=3, register_window=25)
        pair, ips, regs = {}, {}, {}
        open_tickets = []
        for _ in range(120):
            clock.advance(rng.choice([0, 0, 1, 3, 6, 11, 30]))
            now = clock.now
            action = rng.choice(["login", "login", "register", "success"])
            ip = rng.choice(["1.1.1.1", "2.2.2.2"])
            name = rng.choice(["a", "b", "c"])
            if action == "login":
                p = [t for t in pair.get((ip, name), []) if t > now - 10]
                i = [t for t in ips.get(ip, []) if t > now - 10]
                expect = len(p) < 2 and len(i) < 4
                pair[(ip, name)], ips[ip] = p, i
                decision = gate.acquire_login(ip, name)
                assert decision.allowed == expect, (seed, now)
                if expect:
                    p.append(now)
                    i.append(now)
                    open_tickets.append((ip, name, now, decision.ticket, []))
                else:
                    assert decision.retry_after >= 1
            elif action == "register":
                r = [t for t in regs.get(ip, []) if t > now - 25]
                expect = len(r) < 3
                regs[ip] = r
                decision = gate.acquire_register(ip)
                assert decision.allowed == expect, (seed, now)
                if expect:
                    r.append(now)
            elif open_tickets:
                entry = open_tickets.pop(rng.randrange(len(open_tickets)))
                t_ip, t_name, stamp, ticket, _ = entry
                gate.login_succeeded(ticket)
                pair[(t_ip, t_name)] = []
                if stamp in ips.get(t_ip, []):
                    ips[t_ip].remove(stamp)


# ---------------------------------------------------------------- concurrency


def run_in_threads(count, work):
    barrier = threading.Barrier(count)
    results = [None] * count
    errors = []

    def runner(index):
        try:
            barrier.wait()
            results[index] = work(index)
        except Exception as error:  # pragma: no cover - reported below
            errors.append(error)

    threads = [
        threading.Thread(target=runner, args=(i,)) for i in range(count)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors, errors
    return results


def slow_down(window):
    """Make ``window.wait`` pause after it has answered, so another thread
    can run between the check and the recording unless a lock stops it."""
    real_wait = window.wait

    def slow_wait(key, now):
        answer = real_wait(key, now)
        time.sleep(0.003)
        return answer

    window.wait = slow_wait


def test_parallel_attempts_can_not_pass_the_pair_limit(clock):
    gate = Throttle(clock)
    slow_down(gate._pair)
    results = run_in_threads(
        32, lambda i: gate.acquire_login(IP, "alice").allowed)
    assert results.count(True) == 5


def test_parallel_attempts_can_not_pass_the_address_limit(clock):
    gate = Throttle(clock)
    slow_down(gate._login_ip)
    results = run_in_threads(
        64, lambda i: gate.acquire_login(IP, f"user{i}").allowed)
    assert results.count(True) == 20


def test_parallel_registrations_can_not_pass_the_limit(clock):
    gate = Throttle(clock)
    slow_down(gate._register_ip)
    results = run_in_threads(
        32, lambda i: gate.acquire_register(IP).allowed)
    assert results.count(True) == 10


class SlowTicket(throttle._Ticket):
    """A ticket whose ``spent`` flag pauses after being read."""

    @property
    def spent(self):
        value = self.__dict__.get("_spent", False)
        time.sleep(0.01)
        return value

    @spent.setter
    def spent(self, value):
        self.__dict__["_spent"] = value


def test_two_successes_for_one_ticket_refund_only_once(clock):
    gate = small(clock, login_ip_limit=10)
    first = gate.acquire_login(IP, "alice").ticket
    for name in ("b", "c", "d"):
        gate.acquire_login(IP, name)  # the address holds 4 attempts
    ticket = SlowTicket(first.pair_key, first.ip_key, first.stamp)
    run_in_threads(2, lambda i: gate.login_succeeded(ticket))
    (events,) = gate._login_ip._events.values()
    assert len(events) == 3


def test_parallel_mixed_traffic_keeps_memory_bounded(clock):
    gate = small(clock, max_pair_keys=50, max_login_ip_keys=20,
                 max_register_ip_keys=20, pair_limit=3, login_ip_limit=50)

    def work(index):
        rng = random.Random(index)
        for step in range(300):
            ip = f"10.0.{rng.randrange(40)}.{rng.randrange(40)}"
            decision = gate.acquire_login(ip, f"user{rng.randrange(500)}")
            if decision.allowed and rng.random() < 0.3:
                gate.login_succeeded(decision.ticket)
            gate.acquire_register(ip)
        return gate.sizes()

    run_in_threads(16, work)
    sizes = gate.sizes()
    assert sizes["login_pair"] <= 50
    assert sizes["login_ip"] <= 20
    assert sizes["register_ip"] <= 20


def test_a_success_and_a_new_attempt_can_run_together(clock):
    gate = small(clock, pair_limit=100, login_ip_limit=1000)
    tickets = [gate.acquire_login(IP, "alice").ticket for _ in range(50)]

    def work(index):
        if index % 2:
            gate.login_succeeded(tickets[index])
        else:
            gate.acquire_login(IP, "alice")

    run_in_threads(50, work)
    assert gate.sizes()["login_pair"] <= 1


# ---------------------------------------------------- the module itself


def test_the_module_is_plain_python_with_no_logging():
    tree = ast.parse(SOURCE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module.split(".")[0])
    assert imported == {
        "hashlib", "ipaddress", "math", "secrets", "threading", "time",
        "collections",
    }
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert not {"print", "open", "logging", "logger", "request"} & names


def test_the_default_clock_is_the_monotonic_clock():
    assert Throttle()._clock is time.monotonic
