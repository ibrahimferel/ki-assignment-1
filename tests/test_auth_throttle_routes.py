"""Tests for the attempt limits as seen through the login and register pages.

The limiter itself is tested in test_auth_throttle.py. Here every test uses
real requests, real CSRF tokens and a limiter with a clock the test controls.
"""

import logging
import re

import pytest
from argon2 import PasswordHasher
from flask_login import current_user, login_required
from sqlalchemy import func, select

from app import create_app
from app.auth import services
from app.auth.routes import LOGIN_FAILED, TOO_MANY_ATTEMPTS
from app.auth.throttle import Throttle
from app.config import TestingConfig
from app.extensions import db
from app.models import User

GOOD = "correct horse battery"
WRONG = "wrong password!"
IP = "203.0.113.7"

TOKEN_PATTERN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
VALUE_PATTERN = re.compile(r'value="[^"]*"')


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture(autouse=True)
def cheap_hasher(monkeypatch):
    cheap = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    monkeypatch.setattr(services, "_HASHER", cheap)
    monkeypatch.setattr(services, "_dummy", None)


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def site(web, clock):
    """The conftest ``web`` app with a limiter on a clock we control."""
    web.extensions["throttle"] = Throttle(clock)

    @web.get("/protected")
    @login_required
    def protected():
        return "secret for " + current_user.username

    return web


@pytest.fixture()
def browser(site):
    client = site.test_client()
    client.environ_base["REMOTE_ADDR"] = IP
    return client


def client_from(site, address):
    client = site.test_client()
    client.environ_base["REMOTE_ADDR"] = address
    return client


def add_user(site, username="alice", password=GOOD):
    with site.app_context():
        services.register_user(username, password)


def user_count(site):
    with site.app_context():
        return db.session.execute(select(func.count(User.id))).scalar_one()


def text_of(response):
    return response.get_data(as_text=True)


def token_from(browser, url):
    found = TOKEN_PATTERN.search(text_of(browser.get(url)))
    assert found, "no CSRF token in the page"
    return found.group(1)


def login(browser, username, password, **headers):
    data = {
        "csrf_token": token_from(browser, "/auth/login"),
        "username": username,
        "password": password,
    }
    return browser.post("/auth/login", data=data, headers=headers)


def register(browser, username, password, confirm=None):
    data = {
        "csrf_token": token_from(browser, "/auth/register"),
        "username": username,
        "password": password,
        "confirm": password if confirm is None else confirm,
    }
    return browser.post("/auth/register", data=data)


def is_logged_in(browser):
    return browser.get("/protected").status_code == 200


def shape(response):
    """The page without the parts that legitimately differ per request."""
    html = VALUE_PATTERN.sub('value=""', text_of(response))
    return response.status_code, response.headers.get("Retry-After"), html


def cookies_set_by(site, response):
    """What the response asks the browser to store: the decoded session
    cookie (or None) and whether the remember cookie is only being deleted."""
    serializer = site.session_interface.get_signing_serializer(site)
    session_payload = None
    remember_only_deleted = True
    for line in response.headers.getlist("Set-Cookie"):
        name, _, rest = line.partition("=")
        value = rest.split(";", 1)[0]
        if name == "session":
            session_payload = dict(serializer.loads(value))
        elif name == "remember_token":
            remember_only_deleted = remember_only_deleted and value == ""
        else:
            raise AssertionError(f"unexpected cookie {name}")
    return session_payload, remember_only_deleted


LOGIN_KEYS = {"_user_id", "_id", "_fresh", "_remember"}


def fill_pair(browser, username="alice", count=5):
    for _ in range(count):
        assert login(browser, username, WRONG).status_code == 200


# ---------------------------------------------------------------------- login


def test_the_sixth_failed_login_for_one_pair_is_refused(site, browser):
    add_user(site)
    fill_pair(browser)
    response = login(browser, "alice", WRONG)
    assert response.status_code == 429
    assert TOO_MANY_ATTEMPTS in text_of(response)
    assert LOGIN_FAILED not in text_of(response)
    assert response.headers["Retry-After"] == "900"
    assert response.headers["Cache-Control"] == "no-store"
    assert 'name="csrf_token"' in text_of(response)  # the form is shown again


def test_the_right_password_is_refused_while_blocked(
    site, browser, monkeypatch
):
    add_user(site)
    fill_pair(browser)
    calls = []

    def spy_login_user(*args, **kwargs):
        calls.append("login_user")

    def spy_authenticate(*args, **kwargs):
        calls.append("authenticate")

    monkeypatch.setattr("app.auth.routes.login_user", spy_login_user)
    monkeypatch.setattr("app.auth.routes.authenticate", spy_authenticate)
    response = login(browser, "alice", GOOD)
    assert response.status_code == 429
    assert calls == []  # neither the password check nor login_user ran
    payload, remember_only_deleted = cookies_set_by(site, response)
    assert not LOGIN_KEYS & set(payload or {})  # nobody was logged in
    assert remember_only_deleted
    monkeypatch.undo()
    assert not is_logged_in(browser)


def test_a_refused_login_starts_no_login_session_for_anyone(site, browser):
    add_user(site)
    fill_pair(browser)
    fresh = client_from(site, IP)
    response = login(fresh, "alice", GOOD)
    assert response.status_code == 429
    payload, remember_only_deleted = cookies_set_by(site, response)
    assert set(payload) == {"csrf_token"}  # only the form token, as ever
    assert remember_only_deleted
    assert not is_logged_in(fresh)


def test_a_refused_login_sets_the_same_cookies_as_an_ordinary_failure(
    site, browser
):
    # Flask-Login re-sends an anonymous visitor's session cookie (token only)
    # on every POST. The 429 answer must not differ from that in any way.
    add_user(site)
    ordinary = cookies_set_by(site, login(browser, "alice", WRONG))
    fill_pair(browser, count=4)
    refused = login(browser, "alice", WRONG)
    assert refused.status_code == 429
    assert cookies_set_by(site, refused) == ordinary


def test_the_block_lifts_after_the_window(site, browser, clock):
    add_user(site)
    fill_pair(browser)
    assert login(browser, "alice", GOOD).status_code == 429
    clock.advance(899)
    assert login(browser, "alice", GOOD).status_code == 429
    clock.advance(1)
    assert login(browser, "alice", GOOD).status_code == 302
    assert is_logged_in(browser)


def test_retry_after_counts_down_and_refusals_do_not_extend_it(
    site, browser, clock
):
    add_user(site)
    fill_pair(browser)
    seen = []
    for _ in range(4):
        clock.advance(100)
        response = login(browser, "alice", WRONG)
        assert response.status_code == 429
        seen.append(int(response.headers["Retry-After"]))
    assert seen == [800, 700, 600, 500]


def test_get_pages_still_work_while_blocked(site, browser):
    add_user(site)
    fill_pair(browser)
    assert browser.get("/auth/login").status_code == 200
    assert browser.get("/auth/register").status_code == 200
    assert browser.get("/").status_code == 200


def test_other_usernames_and_other_addresses_are_not_affected(site, browser):
    add_user(site)
    add_user(site, "bobby")
    fill_pair(browser)
    assert login(browser, "alice", WRONG).status_code == 429
    assert login(browser, "bobby", WRONG).status_code == 200
    other = client_from(site, "198.51.100.9")
    assert login(other, "alice", GOOD).status_code == 302


def test_usernames_are_compared_in_their_normalized_form(site, browser):
    add_user(site)
    for name in ("Alice", " alice ", "ALICE"):
        assert login(browser, name, WRONG).status_code == 200
    for name in ("alice", "Alice"):
        assert login(browser, name, WRONG).status_code == 200
    assert login(browser, "  ALICE", WRONG).status_code == 429


def test_malformed_usernames_share_one_bucket(site, browser):
    add_user(site)
    names = ["a", "bad name", "ünal", "x" * 80, ""]
    for name in names:
        assert login(browser, name, WRONG).status_code == 200
    assert login(browser, "yet another one!", WRONG).status_code == 429
    assert login(browser, "alice", GOOD).status_code == 302  # valid names fine


def test_the_twenty_first_attempt_from_one_address_is_refused(site, browser):
    for number in range(20):
        assert login(browser, f"user{number:02d}", WRONG).status_code == 200
    response = login(browser, "user99", WRONG)
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "900"
    other = client_from(site, "198.51.100.9")
    assert login(other, "user99", WRONG).status_code == 200


def test_a_forged_forwarded_header_does_not_change_the_key(site, browser):
    add_user(site)
    forged = [
        {"X-Forwarded-For": "10.0.0.1"},
        {"X-Forwarded-For": "10.0.0.2, 10.0.0.3"},
        {"X-Real-IP": "10.0.0.4"},
        {"Forwarded": "for=10.0.0.5"},
        {"X-Forwarded-For": "10.0.0.6", "X-Real-IP": "10.0.0.7"},
    ]
    for headers in forged:
        assert login(browser, "alice", WRONG, **headers).status_code == 200
    # the sixth attempt is refused whatever it claims to come from
    response = login(
        browser, "alice", WRONG, **{"X-Forwarded-For": "10.9.9.9"}
    )
    assert response.status_code == 429
    response = login(browser, "alice", GOOD, **{"X-Real-IP": "192.0.2.77"})
    assert response.status_code == 429


def test_a_forged_header_can_not_put_a_victim_in_the_attackers_bucket(
    site, browser
):
    add_user(site)
    for _ in range(5):
        login(browser, "alice", WRONG, **{"X-Forwarded-For": "198.51.100.9"})
    victim = client_from(site, "198.51.100.9")
    assert login(victim, "alice", GOOD).status_code == 302


def test_success_resets_the_pair_but_not_the_whole_address(site, browser):
    add_user(site)
    fill_pair(browser, count=4)
    assert login(browser, "alice", GOOD).status_code == 302
    browser.post("/auth/logout", data={"csrf_token": token_from(browser, "/")})
    fill_pair(browser, count=5)  # the pair started again from zero
    assert login(browser, "alice", WRONG).status_code == 429


def test_a_success_in_between_does_not_reset_the_address_count(site, browser):
    add_user(site, "mine")
    attacker = browser
    for number in range(20):
        assert login(attacker, "mine", GOOD).status_code == 302
        attacker.post(
            "/auth/logout", data={"csrf_token": token_from(attacker, "/")}
        )
        assert login(attacker, f"victim{number:02d}", WRONG).status_code == 200
    assert login(attacker, "victim99", WRONG).status_code == 429


def test_the_429_page_is_the_same_for_a_real_and_an_unknown_username(
    site, browser
):
    add_user(site)
    fill_pair(browser, "alice")
    fill_pair(browser, "nobody")
    real = shape(login(browser, "alice", GOOD))
    unknown = shape(login(browser, "nobody", GOOD))
    assert real[0] == 429
    assert real == unknown


def test_the_429_page_is_the_same_for_every_cause(site, browser):
    # Refused by the pair limit, and refused by the address limit.
    add_user(site)
    fill_pair(browser, "alice")
    by_pair = shape(login(browser, "alice", WRONG))
    other = client_from(site, "198.51.100.9")
    for number in range(20):
        login(other, f"user{number:02d}", WRONG)
    by_address = shape(login(other, "somebody", WRONG))
    assert by_pair == by_address


def test_a_refused_login_costs_no_password_work(site, browser, monkeypatch):
    add_user(site)
    fill_pair(browser)
    hashed = []
    monkeypatch.setattr(
        services, "_verify", lambda *a, **k: hashed.append(1) or False
    )
    response = login(browser, "alice", "x" * 5_000)  # below the 16 KiB limit
    assert response.status_code == 429
    assert hashed == []


def test_the_limiter_is_asked_before_the_password_is_checked(
    site, browser, monkeypatch
):
    add_user(site)
    order = []
    gate = site.extensions["throttle"]
    real_acquire, real_ok = gate.acquire_login, gate.login_succeeded
    real_auth = services.authenticate

    def acquire(*args):
        order.append("acquire")
        return real_acquire(*args)

    def succeeded(ticket):
        order.append("succeeded")
        return real_ok(ticket)

    def auth(*args):
        order.append("authenticate")
        return real_auth(*args)

    monkeypatch.setattr(gate, "acquire_login", acquire)
    monkeypatch.setattr(gate, "login_succeeded", succeeded)
    monkeypatch.setattr("app.auth.routes.authenticate", auth)
    login(browser, "alice", WRONG)
    assert order == ["acquire", "authenticate"]
    order.clear()
    login(browser, "alice", GOOD)
    assert order == ["acquire", "authenticate", "succeeded"]


def test_the_limiter_gets_the_remote_address_and_the_normalized_name(
    site, browser, monkeypatch
):
    seen = []
    gate = site.extensions["throttle"]
    real = gate.acquire_login

    def spy(address, name):
        seen.append((address, name))
        return real(address, name)

    monkeypatch.setattr(gate, "acquire_login", spy)
    login(browser, "  AliCe ", WRONG, **{"X-Forwarded-For": "10.1.1.1"})
    login(browser, "no good!", WRONG)
    assert seen == [(IP, "alice"), (IP, "\x00malformed")]


def test_one_ipv6_network_is_one_client(site):
    first = client_from(site, "2001:db8:1:2::1")
    second = client_from(site, "2001:db8:1:2:abcd::9")
    for number in range(10):
        login(first, f"user{number:02d}", WRONG)
        login(second, f"user{number + 10:02d}", WRONG)
    assert login(first, "user99", WRONG).status_code == 429
    elsewhere = client_from(site, "2001:db8:1:3::1")
    assert login(elsewhere, "user99", WRONG).status_code == 200


def test_requests_that_are_not_counted(site, browser):
    add_user(site)
    for _ in range(60):
        browser.get("/auth/login")
        browser.get("/auth/register")
        browser.get("/")
    for _ in range(60):  # no CSRF token: refused with 400 before the limiter
        response = browser.post(
            "/auth/login", data={"username": "alice", "password": WRONG}
        )
        assert response.status_code == 400
        response = browser.post(
            "/auth/register",
            data={"username": "bobby", "password": GOOD, "confirm": GOOD},
        )
        assert response.status_code == 400
    assert site.extensions["throttle"].sizes() == {
        "login_pair": 0, "login_ip": 0, "register_ip": 0}
    fill_pair(browser)
    assert login(browser, "alice", WRONG).status_code == 429


def test_a_wrong_csrf_token_is_not_counted(site, browser):
    token_from(browser, "/auth/login")
    for _ in range(30):
        response = browser.post(
            "/auth/login",
            data={
                "csrf_token": "wrong",
                "username": "alice",
                "password": WRONG,
            },
        )
        assert response.status_code == 400
    assert site.extensions["throttle"].sizes()["login_ip"] == 0


# ------------------------------------------------------------ registration


def test_the_eleventh_registration_attempt_is_refused(site, browser):
    for number in range(10):
        response = register(browser, f"user{number:02d}", "short")
        assert response.status_code == 200  # refused by the password policy
    response = register(browser, "user99", GOOD)
    assert response.status_code == 429
    assert TOO_MANY_ATTEMPTS in text_of(response)
    assert response.headers["Retry-After"] == "3600"
    assert response.headers["Cache-Control"] == "no-store"
    assert user_count(site) == 0  # even a valid sign-up was not carried out


def test_registrations_that_work_count_too(site, browser):
    for number in range(10):
        assert register(browser, f"user{number:02d}", GOOD).status_code == 302
    assert register(browser, "user99", GOOD).status_code == 429
    assert user_count(site) == 10


def test_a_refused_registration_does_not_reach_register_user(
    site, browser, monkeypatch
):
    for number in range(10):
        register(browser, f"user{number:02d}", "short")
    calls = []
    monkeypatch.setattr(
        "app.auth.routes.register_user", lambda *a: calls.append(a)
    )
    response = register(browser, "user99", GOOD)
    assert response.status_code == 429
    assert calls == []
    assert 'value="' + GOOD not in text_of(response)
    assert GOOD not in text_of(response)


def test_registration_limit_lifts_after_an_hour(site, browser, clock):
    for number in range(10):
        register(browser, f"user{number:02d}", "short")
    assert register(browser, "user99", GOOD).status_code == 429
    clock.advance(3599)
    assert register(browser, "user99", GOOD).status_code == 429
    clock.advance(1)
    assert register(browser, "user99", GOOD).status_code == 302


def test_registration_is_counted_per_address(site, browser):
    for number in range(10):
        register(browser, f"user{number:02d}", "short")
    assert register(browser, "user99", GOOD).status_code == 429
    other = client_from(site, "198.51.100.9")
    assert register(other, "user99", GOOD).status_code == 302


def test_forged_headers_do_not_change_the_registration_key(site, browser):
    for number in range(10):
        browser.post(
            "/auth/register",
            data={
                "csrf_token": token_from(browser, "/auth/register"),
                "username": f"user{number:02d}",
                "password": "short",
                "confirm": "short",
            },
            headers={"X-Forwarded-For": f"10.0.0.{number}"},
        )
    response = browser.post(
        "/auth/register",
        data={
            "csrf_token": token_from(browser, "/auth/register"),
            "username": "user99",
            "password": GOOD,
            "confirm": GOOD,
        },
        headers={"X-Forwarded-For": "192.0.2.200"},
    )
    assert response.status_code == 429


def test_registration_and_login_limits_are_separate(site, browser):
    add_user(site)
    for number in range(10):
        register(browser, f"user{number:02d}", "short")
    assert register(browser, "user99", GOOD).status_code == 429
    assert login(browser, "alice", GOOD).status_code == 302


def test_a_form_that_does_not_validate_is_not_counted(site, browser):
    for _ in range(40):
        response = register(browser, "alice", GOOD, confirm="different")
        assert response.status_code == 200
    assert site.extensions["throttle"].sizes()["register_ip"] == 0
    assert register(browser, "alice", GOOD).status_code == 302


def test_the_register_429_page_is_the_same_for_a_taken_and_a_free_name(
    site, browser
):
    add_user(site, "taken")
    for number in range(10):
        register(browser, f"user{number:02d}", "short")
    free = shape(register(browser, "free-name", GOOD))
    taken = shape(register(browser, "taken", GOOD))
    assert free[0] == 429
    assert free == taken


def test_register_pages_show_the_message_in_an_alert(site, browser):
    for number in range(10):
        register(browser, f"user{number:02d}", "short")
    html = text_of(register(browser, "user99", GOOD))
    assert f'<p class="error" role="alert">{TOO_MANY_ATTEMPTS}</p>' in html


def test_the_refusal_text_is_this_exact_sentence():
    assert TOO_MANY_ATTEMPTS == "Too many attempts. Please try again later."


def test_the_register_429_page_still_shows_the_hints(site, browser):
    for number in range(10):
        register(browser, f"user{number:02d}", "short")
    html = " ".join(text_of(register(browser, "user99", GOOD)).split())
    assert "3 to 32 characters" in html and "10 to 128 characters" in html


def test_the_normal_register_page_has_no_error_block(site, browser):
    assert 'role="alert"' not in text_of(browser.get("/auth/register"))


# ------------------------------------------------------------------- the rest


def test_each_application_has_its_own_limiter():
    first = create_app(TestingConfig())
    second = create_app(TestingConfig())
    assert isinstance(first.extensions["throttle"], Throttle)
    assert first.extensions["throttle"] is not second.extensions["throttle"]


def test_the_default_limiter_uses_the_real_clock_and_numbers(web):
    gate = web.extensions["throttle"]
    assert [gate.acquire_register(IP).allowed for _ in range(11)] == (
        [True] * 10 + [False]
    )


def test_a_failed_attempt_leaves_other_apps_alone(site, browser):
    other = create_app(TestingConfig())
    with other.app_context():
        db.create_all()
    fill_pair(browser)
    assert login(browser, "alice", WRONG).status_code == 429
    assert other.extensions["throttle"].sizes()["login_pair"] == 0


def test_no_password_or_username_reaches_the_log(site, browser, caplog):
    caplog.set_level(logging.DEBUG)
    add_user(site, "secretname")
    for _ in range(6):
        login(browser, "secretname", "Hunter2-hunter2!")
    for number in range(11):
        register(browser, "othername", f"Pass-{number}-Word!")
    secrets_ = ("secretname", "Hunter2-hunter2!", "othername", "Pass-3-Word!")
    for secret in secrets_:
        assert secret not in caplog.text


def test_the_limiter_state_holds_no_usernames(site, browser):
    add_user(site)
    fill_pair(browser)
    gate = site.extensions["throttle"]
    for window in (gate._pair, gate._login_ip, gate._register_ip):
        for key in window._events:
            assert isinstance(key, bytes)
            assert b"alice" not in key and IP.encode() not in key
