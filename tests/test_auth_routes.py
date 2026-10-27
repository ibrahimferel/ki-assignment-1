"""Tests for the registration, login and logout pages.

Every test talks to the app through real HTTP requests (Flask's test client)
and real CSRF tokens read from the pages, like a browser would. The ``web``
fixture from conftest.py is used on purpose: it keeps no application context
open around the test, so each request is independent.
"""

import json
import logging
import re
from urllib.parse import parse_qs, quote, urlsplit

import pytest
from argon2 import PasswordHasher
from flask import session
from flask_login import current_user, login_required, logout_user
from sqlalchemy import func, select

from app.auth import services
from app.auth.redirects import MAX_NEXT_LENGTH, safe_next_url
from app.auth.routes import LOGIN_FAILED
from app.extensions import db, login_manager
from app.models import User

GOOD = "correct horse battery"  # 21 characters, not on the common list
OTHER = "another long password"

TOKEN_PATTERN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
VALUE_PATTERN = re.compile(r'value="[^"]*"')


@pytest.fixture(autouse=True)
def cheap_hasher(monkeypatch):
    """Fast Argon2 for the whole module; a fresh dummy hash every test."""
    cheap = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    monkeypatch.setattr(services, "_HASHER", cheap)
    monkeypatch.setattr(services, "_dummy", None)


@pytest.fixture()
def site(web):
    """The conftest ``web`` app plus a few test-only routes."""

    @web.get("/protected")
    @login_required
    def protected():
        return "secret for " + current_user.username

    @web.get("/mark")
    def mark():
        session["marker"] = "before-login"
        return "marked"

    @web.get("/session-keys")
    def session_keys():
        return json.dumps(sorted(session.keys()))

    return web


@pytest.fixture()
def browser(site):
    return site.test_client()


def add_user(site, username="alice", password=GOOD):
    with site.app_context():
        services.register_user(username, password)


def user_count(site):
    with site.app_context():
        return db.session.execute(select(func.count(User.id))).scalar_one()


def token_in(html):
    found = TOKEN_PATTERN.search(html)
    assert found, "no CSRF token in the page"
    return found.group(1)


def token_from(browser, url):
    return token_in(browser.get(url).get_data(as_text=True))


def post_login(browser, username, password, next_url=None, **extra):
    url = "/auth/login"
    if next_url is not None:
        url += "?next=" + quote(next_url, safe="")
    data = {"csrf_token": token_from(browser, url)}
    data.update({"username": username, "password": password})
    data.update(extra)
    return browser.post(url, data=data)


def post_register(browser, username, password, confirm=None):
    data = {
        "csrf_token": token_from(browser, "/auth/register"),
        "username": username,
        "password": password,
        "confirm": password if confirm is None else confirm,
    }
    return browser.post("/auth/register", data=data)


def post_logout(browser):
    token = token_from(browser, "/")
    return browser.post("/auth/logout", data={"csrf_token": token})


def text_of(response):
    return response.get_data(as_text=True)


def keys_of(browser):
    return json.loads(text_of(browser.get("/session-keys")))


def is_logged_in(browser):
    return browser.get("/protected").status_code == 200


# ----------------------------------------------------------- the route table


def test_the_route_table_is_exactly_the_documented_one(site):
    rules = {
        (rule.rule, tuple(sorted(rule.methods - {"HEAD", "OPTIONS"})))
        for rule in site.url_map.iter_rules()
        if rule.endpoint != "static" and rule.rule not in {
            "/protected", "/mark", "/session-keys"}
    }
    assert rules == {
        ("/", ("GET",)),
        ("/auth/login", ("GET", "POST")),
        ("/auth/register", ("GET", "POST")),
        ("/auth/logout", ("POST",)),
        ("/storage/", ("GET",)),
        ("/storage/upload", ("POST",)),
        ("/storage/personal", ("POST",)),
        ("/storage/<int:file_id>/download/<algorithm>", ("GET",)),
        ("/storage/<int:file_id>/view", ("GET",)),
        ("/storage/<int:file_id>/comparison", ("GET",)),
        ("/storage/<int:file_id>/personal", ("GET",)),
        ("/storage/<int:file_id>/personal/update", ("POST",)),
        ("/storage/<int:file_id>/delete", ("POST",)),
    }


def test_unauthorised_visitors_are_sent_to_the_login_page(site):
    assert login_manager.login_view == "auth.login"


# ----------------------------------------------------------------- the pages


def test_register_page_has_the_form(browser):
    response = browser.get("/auth/register")
    html = text_of(response)
    assert response.status_code == 200
    assert 'method="post"' in html
    for name in ("csrf_token", "username", "password", "confirm"):
        assert f'name="{name}"' in html
    assert re.search(r'<input[^>]*name="password"[^>]*type="password"', html) \
        or re.search(r'<input[^>]*type="password"[^>]*name="password"', html)
    assert 'maxlength="32"' in html and 'maxlength="128"' in html
    assert 'minlength="3"' in html and 'minlength="10"' in html


def test_login_page_has_the_form(browser):
    response = browser.get("/auth/login")
    html = text_of(response)
    assert response.status_code == 200
    assert 'method="post"' in html
    for name in ("csrf_token", "username", "password"):
        assert f'name="{name}"' in html
    assert 'autocomplete="current-password"' in html
    assert 'autocomplete="username"' in html


def test_the_login_form_posts_back_to_the_login_address(browser):
    html = text_of(browser.get("/auth/login"))
    assert 'action="/auth/login"' in html


def test_pages_never_load_anything_from_outside(browser):
    for url in ("/auth/login", "/auth/register", "/"):
        html = text_of(browser.get(url))
        assert "http://" not in html and "https://" not in html
        scripts = re.findall(r"<script\b[^>]*>.*?</script>", html, re.I | re.S)
        allowed = {
            "/": ['<script src="/static/js/landing.js" defer></script>'],
            "/auth/register": ['<script src="/static/js/register.js" defer></script>'],
            "/auth/login": ['<script src="/static/js/login.js" defer></script>'],
        }
        assert scripts == allowed[url]


def test_page_titles_and_cross_links(browser):
    login = text_of(browser.get("/auth/login"))
    register = text_of(browser.get("/auth/register"))
    assert "<title>Log in - Encrypted file store</title>" in login
    assert "<title>Register - Encrypted file store</title>" in register
    assert 'href="/auth/register"' in login
    assert 'href="/auth/login"' in register


def test_register_page_states_the_real_limits(browser):
    html = " ".join(text_of(browser.get("/auth/register")).split())
    assert "3 to 32 characters: letters" in html
    assert "10 to 128 characters." in html


def test_register_fields_have_the_right_autocomplete(browser):
    html = text_of(browser.get("/auth/register"))
    assert re.findall(r'autocomplete="([^"]+)"', html) == [
        "username", "new-password", "new-password"]
    assert 'minlength="3"' in html and html.count("minlength") == 2


# -------------------------------------------------------------- registration


def test_register_creates_the_account(site, browser):
    response = post_register(browser, "Alice.Smith", GOOD)
    assert response.status_code == 302
    assert response.headers["Location"] == "/auth/login"
    with site.app_context():
        user = db.session.execute(select(User)).scalar_one()
        assert user.username == "alice.smith"
        assert user.password_hash.startswith("$argon2id$")
        assert GOOD not in user.password_hash


def test_register_shows_the_success_message_once(site, browser):
    post_register(browser, "alice", GOOD)
    first = text_of(browser.get("/auth/login"))
    second = text_of(browser.get("/auth/login"))
    assert "Account created. You can log in now." in first
    assert "Account created" not in second


def test_a_new_account_can_log_in_straight_away(site, browser):
    post_register(browser, "alice", GOOD)
    assert post_login(browser, "alice", GOOD).status_code == 302
    assert is_logged_in(browser)


def test_register_does_not_log_the_new_user_in(site, browser):
    post_register(browser, "alice", GOOD)
    assert not is_logged_in(browser)


REGISTER_ERRORS = [
    ("a", GOOD, None, "Username is too short."),
    ("x" * 33, GOOD, None, "Username is too long."),
    ("bad name", GOOD, None, "Username may only contain"),
    (".dot", GOOD, None, "must start and end with a letter"),
    ("ünal", GOOD, None, "Username may only contain"),
    ("alice", "short", None, "Password is too short."),
    ("alice", "x" * 129, None, "Password is too long."),
    # 5_000 characters: far above the limits of the service, below the 16 KiB
    # body limit of /auth/* (bigger bodies are answered 413, see
    # tests/test_auth_body_limit.py).
    ("alice", "x" * 5_000, None, "Password is too long."),
    ("alice", "bad\x00password", None, "characters that are not allowed"),
    ("alice", "password123", None, "Password is too common."),
    ("longusername", "LongUserName", None, "must not be the username"),
    ("alice", GOOD, "a different one", "Passwords do not match."),
]


@pytest.mark.parametrize(
    ("username", "password", "confirm", "message"), REGISTER_ERRORS
)
def test_register_refuses_bad_input_and_says_why(
    site, browser, username, password, confirm, message
):
    response = post_register(browser, username, password, confirm)
    html = text_of(response)
    assert response.status_code == 200
    assert message in html
    assert user_count(site) == 0
    assert 'name="csrf_token"' in html  # the form is shown again
    assert f'value="{password}"' not in html
    assert "x" * 50 not in html


def error_after(html, start, end):
    """The error paragraphs between the inputs named ``start`` and ``end``."""
    first = html.index(f'name="{start}"')
    last = html.index(f'name="{end}"')
    return re.findall(r'class="error"[^>]*>([^<]+)<', html[first:last])


def test_register_errors_appear_under_the_right_field(site, browser):
    html = text_of(post_register(browser, "alice", "short"))
    assert error_after(html, "password", "confirm") == [
        "Password is too short."]
    assert error_after(html, "username", "password") == []
    html = text_of(post_register(browser, "a", GOOD))
    assert error_after(html, "username", "password") == [
        "Username is too short."]
    assert error_after(html, "password", "confirm") == []
    html = text_of(post_register(browser, "alice", GOOD, "other one"))
    assert "Passwords do not match." in html.split('name="confirm"')[1]


def test_register_refuses_a_name_that_is_taken(site, browser):
    add_user(site, "alice", GOOD)
    response = post_register(browser, "ALICE", OTHER)
    assert response.status_code == 200
    assert "Username is already taken." in text_of(response)
    assert user_count(site) == 1


def test_register_with_missing_fields_is_a_normal_error(site, browser):
    token = token_from(browser, "/auth/register")
    response = browser.post("/auth/register", data={"csrf_token": token})
    assert response.status_code == 200
    assert "Username is too short." in text_of(response)
    assert user_count(site) == 0


def test_register_without_a_csrf_token_is_refused(site, browser):
    response = browser.post(
        "/auth/register",
        data={"username": "alice", "password": GOOD, "confirm": GOOD},
    )
    assert response.status_code == 400
    assert user_count(site) == 0


def test_register_with_a_wrong_csrf_token_is_refused(site, browser):
    browser.get("/auth/register")
    response = browser.post(
        "/auth/register",
        data={
            "csrf_token": "wrong",
            "username": "alice",
            "password": GOOD,
            "confirm": GOOD,
        },
    )
    assert response.status_code == 400
    assert user_count(site) == 0


def test_register_escapes_what_the_visitor_typed(site, browser):
    response = post_register(browser, "<script>alert(1)</script>", GOOD)
    html = text_of(response)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_a_logged_in_user_is_sent_home_from_register(site, browser):
    add_user(site)
    post_login(browser, "alice", GOOD)
    response = browser.get("/auth/register")
    assert response.status_code == 302 and response.headers["Location"] == "/"
    response = browser.post("/auth/register", data={})
    assert response.status_code in (302, 400)


# --------------------------------------------------------------------- login


def test_login_succeeds_and_goes_home(site, browser):
    add_user(site)
    response = post_login(browser, "alice", GOOD)
    assert response.status_code == 302
    assert response.headers["Location"] == "/"
    assert "Logged in as alice." in text_of(browser.get("/"))
    assert is_logged_in(browser)


@pytest.mark.parametrize("name", ["ALICE", "  alice  ", "Alice"])
def test_login_normalizes_the_username(site, browser, name):
    add_user(site)
    assert post_login(browser, name, GOOD).status_code == 302
    assert is_logged_in(browser)


def test_the_login_cookie_is_not_permanent(site, browser):
    add_user(site)
    cookie = post_login(browser, "alice", GOOD).headers["Set-Cookie"]
    assert cookie.startswith("session=")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
    assert "Expires" not in cookie and "Max-Age" not in cookie
    assert "Secure" not in cookie  # the test config is plain http


def test_login_sets_no_remember_me_cookie(site, browser):
    add_user(site)
    response = post_login(browser, "alice", GOOD, remember="y")
    cookies = " ".join(response.headers.getlist("Set-Cookie"))
    assert "remember_token" not in cookies
    assert browser.get_cookie("remember_token") is None


def test_login_starts_from_an_empty_session(site, browser):
    add_user(site)
    browser.get("/mark")
    assert "marker" in keys_of(browser)
    before = browser.get_cookie("session").value
    post_login(browser, "alice", GOOD)
    after = browser.get_cookie("session").value
    keys = keys_of(browser)
    assert after != before
    assert "marker" not in keys
    assert "csrf_token" not in keys
    assert {"_user_id", "_id", "_fresh"} <= set(keys)


FAILED_LOGINS = [
    ("alice", "wrong password!"),
    ("alice", GOOD.upper()),
    ("alice", ""),
    ("nobody", GOOD),
    ("", ""),
    ("a", GOOD),
    ("bad name", GOOD),
    ("ünal", GOOD),
    ("a" * 500, GOOD),
    ("alice", "x" * 500),
    ("alice", "x" * 5_000),  # below the 16 KiB body limit of /auth/*
    ("alice", "bad\x00password"),
]


@pytest.mark.parametrize(("username", "password"), FAILED_LOGINS)
def test_every_failed_login_shows_the_same_message(
    site, browser, username, password
):
    add_user(site)
    response = post_login(browser, username, password)
    assert response.status_code == 200
    assert LOGIN_FAILED in text_of(response)
    assert LOGIN_FAILED == "Invalid username or password."
    assert not is_logged_in(browser)
    assert "_user_id" not in keys_of(browser)


def test_wrong_password_and_unknown_user_look_identical(site, browser):
    add_user(site)

    def shape(response):
        html = VALUE_PATTERN.sub('value=""', text_of(response))
        return response.status_code, html

    wrong = shape(post_login(browser, "alice", "wrong password!"))
    unknown = shape(post_login(browser, "nobody", "wrong password!"))
    assert wrong == unknown


def test_login_never_echoes_the_password(site, browser):
    add_user(site)
    secret = "SuperSecret-123!"
    html = text_of(post_login(browser, "alice", secret))
    assert secret not in html
    assert re.search(r'name="password"[^>]*value=""', html) or re.search(
        r'type="password"[^>]*value=""', html
    )


def test_login_escapes_the_username_it_shows_again(site, browser):
    html = text_of(post_login(browser, '"><b>x</b>', GOOD))
    assert "<b>x</b>" not in html
    assert "&#34;&gt;&lt;b&gt;x" in html


def test_login_with_missing_fields_is_a_normal_failure(site, browser):
    add_user(site)
    token = token_from(browser, "/auth/login")
    response = browser.post("/auth/login", data={"csrf_token": token})
    assert response.status_code == 200
    assert LOGIN_FAILED in text_of(response)


def test_login_without_a_csrf_token_is_refused(site, browser):
    add_user(site)
    response = browser.post(
        "/auth/login", data={"username": "alice", "password": GOOD}
    )
    assert response.status_code == 400
    assert not is_logged_in(browser)


def test_login_with_a_wrong_csrf_token_is_refused(site, browser):
    add_user(site)
    browser.get("/auth/login")
    response = browser.post(
        "/auth/login",
        data={"csrf_token": "wrong", "username": "alice", "password": GOOD},
    )
    assert response.status_code == 400
    assert not is_logged_in(browser)


def test_a_token_from_another_visitor_is_refused(site, browser):
    add_user(site)
    stranger = site.test_client()
    token = token_from(stranger, "/auth/login")
    response = browser.post(
        "/auth/login",
        data={"csrf_token": token, "username": "alice", "password": GOOD},
    )
    assert response.status_code == 400


def test_a_logged_in_user_is_sent_home_from_login(site, browser):
    add_user(site)
    post_login(browser, "alice", GOOD)
    for url in ("/auth/login", "/auth/login?next=/protected"):
        response = browser.get(url)
        assert response.status_code == 302
        assert response.headers["Location"] == "/"


def test_strong_protection_works_end_to_end(site, browser):
    add_user(site)
    browser.environ_base["HTTP_USER_AGENT"] = "browser-one"
    post_login(browser, "alice", GOOD)
    first = browser.get("/protected", headers={"User-Agent": "browser-one"})
    assert first.status_code == 200
    other = browser.get("/protected", headers={"User-Agent": "browser-two"})
    assert other.status_code == 302
    assert not is_logged_in(browser)


# ------------------------------------------------------------- the next page


def test_login_required_pages_send_visitors_to_login_and_back(site, browser):
    add_user(site)
    first = browser.get("/protected")
    assert first.status_code == 302
    location = first.headers["Location"]
    assert urlsplit(location).path == "/auth/login"
    assert parse_qs(urlsplit(location).query) == {"next": ["/protected"]}
    page = text_of(browser.get(location))
    assert "Please log in to continue." in page
    assert 'class="flash flash-info"' in page
    data = {
        "csrf_token": token_in(page),
        "username": "alice",
        "password": GOOD,
    }
    done = browser.post(location, data=data)
    assert done.status_code == 302
    assert done.headers["Location"] == "/protected"
    assert text_of(browser.get("/protected")) == "secret for alice"


SAFE_NEXT = [
    "/protected",
    "/files?id=3&kind=pdf",
    "/a/b/c",
    "/a/b#section",
    "/%2F/evil.com",  # an encoded slash stays inside the path
    "/",
]

UNSAFE_NEXT = [
    "//evil.com",
    "///evil.com",
    "/\\evil.com",
    "\\\\evil.com",
    "https://evil.com",
    "http://evil.com/x",
    "javascript:alert(1)",
    "data:text/html,x",
    "/\t/evil.com",
    "/\n/evil.com",
    "/\r/evil.com",
    " //evil.com",
    "/ /evil.com",
    "evil.com",
    "?x=1",
    "#x",
    "/./\t/evil.com",
    "/.//evil.com",
    "/café",
    "/" + "a" * MAX_NEXT_LENGTH,
]


@pytest.mark.parametrize("target", SAFE_NEXT)
def test_login_follows_a_safe_next(site, browser, target):
    add_user(site)
    response = post_login(browser, "alice", GOOD, next_url=target)
    assert response.status_code == 302
    assert response.headers["Location"] == target


@pytest.mark.parametrize("target", UNSAFE_NEXT)
def test_login_never_follows_an_unsafe_next(site, browser, target):
    add_user(site)
    response = post_login(browser, "alice", GOOD, next_url=target)
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_a_failed_login_keeps_a_safe_next_in_the_form(site, browser):
    add_user(site)
    response = post_login(browser, "alice", "wrong", next_url="/a?b=1&c=2")
    action = re.search(r'<form[^>]*action="([^"]+)"', text_of(response))
    query = parse_qs(urlsplit(action.group(1).replace("&amp;", "&")).query)
    assert query == {"next": ["/a?b=1&c=2"]}


def test_a_failed_login_drops_an_unsafe_next_from_the_form(site, browser):
    add_user(site)
    response = post_login(browser, "alice", "wrong", next_url="//evil.com")
    html = text_of(response)
    assert "evil.com" not in html
    assert 'action="/auth/login"' in html


def test_next_is_ignored_when_it_is_not_text(site, browser):
    add_user(site)
    data = {"csrf_token": token_from(browser, "/auth/login")}
    data.update(username="alice", password=GOOD)
    response = browser.post("/auth/login?next=", data=data)
    assert response.headers["Location"] == "/"


# ------------------------------------------------------- safe_next_url itself


@pytest.mark.parametrize("target", SAFE_NEXT)
def test_safe_next_url_accepts(target):
    assert safe_next_url(target) == target


@pytest.mark.parametrize("target", UNSAFE_NEXT)
def test_safe_next_url_refuses(target):
    assert safe_next_url(target) is None


@pytest.mark.parametrize(
    "target",
    [None, "", 5, 5.0, b"/x", ["/x"], object(), "\x00", "/\x7f", "/\x85"],
)
def test_safe_next_url_refuses_odd_values(target):
    assert safe_next_url(target) is None


def test_the_next_length_limit_is_2048():
    assert MAX_NEXT_LENGTH == 2048


def test_safe_next_url_length_limit():
    longest = "/" + "a" * (MAX_NEXT_LENGTH - 1)
    assert len(longest) == MAX_NEXT_LENGTH
    assert safe_next_url(longest) == longest
    assert safe_next_url(longest + "a") is None


# -------------------------------------------------------------------- logout


def test_logout_is_post_only(site, browser):
    add_user(site)
    post_login(browser, "alice", GOOD)
    assert browser.get("/auth/logout").status_code == 405
    assert is_logged_in(browser)


def test_logout_needs_a_csrf_token(site, browser):
    add_user(site)
    post_login(browser, "alice", GOOD)
    assert browser.post("/auth/logout").status_code == 400
    assert is_logged_in(browser)


def test_logout_calls_flask_logins_logout_user(site, browser, monkeypatch):
    calls = []
    real = logout_user

    def spy():
        calls.append(1)
        return real()

    monkeypatch.setattr("app.auth.routes.logout_user", spy)
    add_user(site)
    post_login(browser, "alice", GOOD)
    post_logout(browser)
    assert calls == [1]


def test_logout_ends_the_session(site, browser):
    add_user(site)
    post_login(browser, "alice", GOOD)
    response = post_logout(browser)
    assert response.status_code == 302
    assert response.headers["Location"] == "/auth/login"
    assert not is_logged_in(browser)
    assert keys_of(browser) == ["_flashes"] or keys_of(browser) == []
    page = text_of(browser.get("/auth/login"))
    assert "You have been logged out." in page
    assert not {"_user_id", "_id", "_fresh"} & set(keys_of(browser))


def test_logout_when_nobody_is_logged_in_is_harmless(site, browser):
    token = token_from(browser, "/auth/login")
    response = browser.post("/auth/logout", data={"csrf_token": token})
    assert response.status_code == 302
    assert response.headers["Location"] == "/auth/login"


def test_after_logout_the_old_forms_are_useless(site, browser):
    add_user(site)
    post_login(browser, "alice", GOOD)
    token = token_from(browser, "/")
    post_logout(browser)
    response = browser.post("/auth/logout", data={"csrf_token": token})
    assert response.status_code == 400  # the session (and its token) is gone


def test_known_limitation_a_copied_cookie_still_works_after_logout(
    site, browser
):
    # The session lives in the cookie itself and the server keeps no list of
    # sessions, so a copied cookie stays valid until it expires (2 hours).
    add_user(site)
    post_login(browser, "alice", GOOD)
    stolen = browser.get_cookie("session").value
    post_logout(browser)
    thief = site.test_client()
    thief.set_cookie("session", stolen)
    assert thief.get("/protected").status_code == 200


# --------------------------------------------------------------- the headers


def test_auth_pages_are_not_cached(site, browser):
    add_user(site)
    for response in (
        browser.get("/auth/login"),
        browser.get("/auth/register"),
        post_login(browser, "alice", "wrong"),
        browser.post("/auth/login", data={}),  # refused: no CSRF token
        post_login(browser, "alice", GOOD),
        browser.get("/auth/login"),  # redirect for a logged-in user
        post_logout(browser),
    ):
        assert response.headers["Cache-Control"] == "no-store"


def test_other_pages_get_no_store_from_the_global_default(site, browser):
    # Since CP8a every page is no-store (app/security_headers.py); this used
    # to check that only the auth pages were.
    assert browser.get("/").headers.get("Cache-Control") == "no-store"


# ------------------------------------------------------------ the placeholder


def test_home_for_a_visitor_shows_the_links(site, browser):
    html = text_of(browser.get("/"))
    assert "Logged in as" not in html
    assert 'href="/auth/login"' in html and 'href="/auth/register"' in html
    assert "/auth/logout" not in html


def test_home_for_a_user_shows_the_name_and_a_logout_form(site, browser):
    add_user(site)
    post_login(browser, "alice", GOOD)
    html = text_of(browser.get("/"))
    assert "Logged in as alice." in html
    assert 'action="/auth/logout"' in html and 'method="post"' in html
    assert TOKEN_PATTERN.search(html)


# ---------------------------------------------------------------- no leaking


def test_no_password_or_hash_reaches_the_log(site, browser, caplog):
    caplog.set_level(logging.DEBUG)
    add_user(site)
    post_register(browser, "bobby", OTHER)
    post_login(browser, "alice", "wrong password!")
    post_login(browser, "alice", GOOD)
    post_logout(browser)
    with site.app_context():
        hashes = [u.password_hash for u in db.session.scalars(select(User))]
    for secret in (GOOD, OTHER, "wrong password!", *hashes):
        assert secret not in caplog.text


def test_no_response_contains_a_password_hash(site, browser):
    add_user(site)
    with site.app_context():
        stored = db.session.execute(select(User.password_hash)).scalar_one()
    for response in (
        post_login(browser, "alice", GOOD),
        browser.get("/"),
        post_login(site.test_client(), "alice", "wrong"),
    ):
        assert stored not in text_of(response)
        assert stored not in str(response.headers)
