"""Security checks that look at the whole application, not one page.

Two kinds of checks live here:

* An inventory taken from ``app.url_map``. Every route that changes state
  must refuse a request without a CSRF token, and every route outside the
  explicit public list must refuse an anonymous visitor. A route added later
  and forgotten is caught here without anyone having to remember it. The
  fixed route table itself is pinned in test_auth_routes.py and is not
  repeated.
* A sweep of everything the application sends or prints during a realistic
  session (pages, headers, decoded cookies, stdout, stderr and the log) for
  passwords, the stored password hash and the secret keys.

The checks are plain functions that take an application, so the tests at the
end can plant a bad route or a leak and prove that the check really finds it.
"""

import base64
import json
import re
from urllib.parse import urlsplit

import pytest
from argon2 import PasswordHasher
from flask_login import login_required
from sqlalchemy import select

from app.auth import services
from app.extensions import csrf, db
from app.models import User

GOOD = "correct horse battery"  # 21 characters, not on the common list
# Unique strings that must never come back out of the application.
SENTINEL_WRONG = "zq9-wrong-sentinel"
SENTINEL_NEW = "zq9-new-sentinel"
SENTINEL_BAD = "zq9-bad-sentinel"

LOGIN_PATH = "/auth/login"
# The only routes an anonymous visitor may use. Review this list in CP7,
# when "/" stops being a placeholder.
PUBLIC_RULES = frozenset({"/", "/auth/login", "/auth/register"})
STATIC_ENDPOINT = "static"
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
AUTOMATIC_METHODS = frozenset({"HEAD", "OPTIONS"})

# A value that fits each URL converter. Anything not listed makes the
# inventory fail loudly instead of guessing.
SAMPLE_VALUES = {
    "UnicodeConverter": "x",
    "PathConverter": "x/y",
    "IntegerConverter": "1",
    "FloatConverter": "1.5",
    "UUIDConverter": "00000000-0000-0000-0000-000000000001",
}

TOKEN_PATTERN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')


@pytest.fixture(autouse=True)
def cheap_hasher(monkeypatch):
    """Fast Argon2 for the whole module; a fresh dummy hash every test."""
    cheap = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    monkeypatch.setattr(services, "_HASHER", cheap)
    monkeypatch.setattr(services, "_dummy", None)


# ------------------------------------------------------------ the inventory


class UnknownConverter(AssertionError):
    """A route takes a URL value this file does not know how to fill in."""


def inventory(app):
    """Every (rule, method) the application answers, static files aside."""
    pairs = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint == STATIC_ENDPOINT:
            continue
        for method in rule.methods - AUTOMATIC_METHODS:
            pairs.append((rule, method))
    return sorted(pairs, key=lambda pair: (pair[0].rule, pair[1]))


def url_for_rule(rule):
    """A concrete path for ``rule``; fails loudly for an unknown converter."""
    values = {}
    for name in sorted(rule.arguments):
        kind = type(rule._converters[name]).__name__
        if kind not in SAMPLE_VALUES:
            raise UnknownConverter(
                f"{rule.rule}: no sample value for converter {kind}; "
                "add one to SAMPLE_VALUES"
            )
        values[name] = SAMPLE_VALUES[kind]
    return rule.build(values, append_unknown=False)[1]


def token_for(client):
    """A valid CSRF token for ``client``, read from a real page."""
    for path in (LOGIN_PATH, "/"):
        found = TOKEN_PATTERN.search(
            client.get(path).get_data(as_text=True)
        )
        if found:
            return found.group(1)
    raise AssertionError("no page offered a CSRF token")


def log_in(client, username="alice", password=GOOD):
    response = client.post(
        LOGIN_PATH,
        data={
            "csrf_token": token_for(client),
            "username": username,
            "password": password,
        },
    )
    assert response.status_code == 302, "test login failed"


def add_user(app, username="alice", password=GOOD):
    with app.app_context():
        services.register_user(username, password)


def csrf_offenders(app, credentials=None):
    """Unsafe routes that do not answer 400 to a missing or wrong token.

    With ``credentials`` the requests are sent by a logged-in user, and a
    refused request must not end that login either.
    """
    client = app.test_client()
    if credentials:
        log_in(client, *credentials)
    offenders = []
    for rule, method in inventory(app):
        if method not in UNSAFE_METHODS:
            continue
        path = url_for_rule(rule)
        for label, data in (
            ("no token", {}),
            ("wrong token", {"csrf_token": "wrong"}),
        ):
            status = client.open(path, method=method, data=data).status_code
            if status != 400:
                offenders.append(f"{method} {rule.rule} ({label}): {status}")
        if credentials and client.get(LOGIN_PATH).status_code != 302:
            offenders.append(f"{method} {rule.rule}: ended the login")
            log_in(client, *credentials)
    return offenders


def stuck_at_400(app):
    """Unsafe routes that answer 400 even WITH a valid token.

    Without this, "every route refuses a missing token" would also pass for
    an application that refuses everything.
    """
    client = app.test_client()
    stuck = []
    for rule, method in inventory(app):
        if method not in UNSAFE_METHODS:
            continue
        # A fresh token each time: a route such as logout ends the session
        # and with it the token.
        response = client.open(
            url_for_rule(rule),
            method=method,
            data={"csrf_token": token_for(client)},
        )
        if response.status_code == 400:
            stuck.append(f"{method} {rule.rule}")
    return stuck


def open_routes(app):
    """Non-public routes that an anonymous visitor can use.

    Allowed answers are 401 or a redirect to the login page. Anything else,
    a 200 above all, is an offender. POST routes get a valid CSRF token so
    the check tests the login rule, not the CSRF rule.
    """
    client = app.test_client()
    offenders = []
    for rule, method in inventory(app):
        if rule.rule in PUBLIC_RULES:
            continue
        data = None
        if method in UNSAFE_METHODS:
            data = {"csrf_token": token_for(client)}
        response = client.open(url_for_rule(rule), method=method, data=data)
        status = response.status_code
        if status == 302:
            target = urlsplit(response.headers["Location"]).path
            allowed = target == LOGIN_PATH
        else:
            allowed = status == 401
        if not allowed:
            offenders.append(f"{method} {rule.rule}: {status}")
    return offenders


# ------------------------------------------- the inventory on the real app


def test_the_public_list_matches_the_real_routes(web):
    rules = {rule.rule for rule in web.url_map.iter_rules()}
    assert PUBLIC_RULES <= rules
    assert STATIC_ENDPOINT in {r.endpoint for r in web.url_map.iter_rules()}


def test_the_inventory_sees_state_changing_and_protected_routes(web):
    pairs = inventory(web)
    assert any(method in UNSAFE_METHODS for _, method in pairs)
    assert any(rule.rule not in PUBLIC_RULES for rule, _ in pairs)


def test_every_unsafe_route_refuses_a_missing_or_wrong_token(web):
    assert csrf_offenders(web) == []


def test_every_unsafe_route_refuses_it_for_a_logged_in_user_too(web):
    add_user(web)
    assert csrf_offenders(web, ("alice", GOOD)) == []


def test_no_unsafe_route_refuses_a_valid_token(web):
    assert stuck_at_400(web) == []


def test_every_route_outside_the_public_list_needs_a_login(web):
    assert open_routes(web) == []


# ------------------------------------------- the checks find what they seek


def test_the_csrf_check_finds_an_exempt_route(web):
    @web.post("/planted-exempt")
    @csrf.exempt
    def planted_exempt():
        return "done"

    assert csrf_offenders(web) == [
        "POST /planted-exempt (no token): 200",
        "POST /planted-exempt (wrong token): 200",
    ]


def test_the_csrf_check_finds_a_route_that_ends_the_login(web):
    from flask_login import logout_user

    @web.post("/planted-logout")
    @csrf.exempt
    def planted_logout():
        logout_user()
        return "bye"

    add_user(web)
    found = csrf_offenders(web, ("alice", GOOD))
    assert "POST /planted-logout: ended the login" in found
    assert "POST /planted-logout (no token): 200" in found


def test_the_stuck_check_finds_a_route_that_always_answers_400(web):
    @web.post("/planted-stuck")
    def planted_stuck():
        return "no", 400

    assert stuck_at_400(web) == ["POST /planted-stuck"]


def test_the_login_check_finds_an_open_route(web):
    @web.get("/planted-open")
    def planted_open():
        return "anyone can read this"

    assert open_routes(web) == ["GET /planted-open: 200"]


def test_the_login_check_accepts_a_protected_route(web):
    @web.get("/planted-closed")
    @login_required
    def planted_closed():
        return "members only"

    assert open_routes(web) == []


def test_the_login_check_finds_a_redirect_to_somewhere_else(web):
    @web.get("/planted-away")
    def planted_away():
        from flask import redirect

        return redirect("/elsewhere")

    assert open_routes(web) == ["GET /planted-away: 302"]


def test_url_values_are_filled_in_by_converter(web):
    @web.get("/planted-id/<int:item_id>")
    @web.get("/planted-name/<name>")
    @web.get("/planted-path/<path:where>")
    @web.get("/planted-uuid/<uuid:thing>")
    @web.get("/planted-float/<float:ratio>")
    @login_required
    def planted_values(**kwargs):
        return "ok"

    paths = sorted(
        url_for_rule(rule)
        for rule, _ in inventory(web)
        if rule.rule.startswith("/planted-")
    )
    assert paths == [
        "/planted-float/1.5",
        "/planted-id/1",
        "/planted-name/x",
        "/planted-path/x/y",
        "/planted-uuid/00000000-0000-0000-0000-000000000001",
    ]
    assert open_routes(web) == []


def test_an_unknown_converter_fails_loudly(web):
    @web.get("/planted-any/<any(a,b):kind>")
    def planted_any(kind):
        return kind

    with pytest.raises(UnknownConverter, match="AnyConverter"):
        open_routes(web)


def test_an_unknown_converter_on_a_post_route_fails_loudly(web):
    @web.post("/planted-any/<any(a,b):kind>")
    def planted_any_post(kind):
        return kind

    with pytest.raises(UnknownConverter, match="AnyConverter"):
        csrf_offenders(web)
    with pytest.raises(UnknownConverter, match="AnyConverter"):
        stuck_at_400(web)


# ----------------------------------------------- the other unsafe methods


def test_put_patch_and_delete_need_a_csrf_token_too(web):
    @web.route("/planted-write", methods=["PUT", "PATCH", "DELETE"])
    def planted_write():
        return "changed"

    client = web.test_client()
    token = token_for(client)
    for method in ("PUT", "PATCH", "DELETE"):
        assert client.open("/planted-write", method=method).status_code == 400
        wrong = {"X-CSRFToken": "wrong"}
        assert (
            client.open(
                "/planted-write", method=method, headers=wrong
            ).status_code
            == 400
        )
        right = {"X-CSRFToken": token}
        assert (
            client.open(
                "/planted-write", method=method, headers=right
            ).status_code
            == 200
        )
    assert csrf_offenders(web) == []


def test_the_csrf_time_limit_is_the_documented_one(web):
    # Flask-WTF's own default; a changed value would be a silent policy
    # change. test_app_setup.py shows an expired token is refused.
    assert web.config["WTF_CSRF_TIME_LIMIT"] == 3600


# ---------------------------------------------------------- the secrets sweep


def variants(value):
    """Every form in which ``value`` could show up in output."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    return {
        value,
        value.hex().encode(),
        value.hex().upper().encode(),
        base64.b64encode(value),
        base64.urlsafe_b64encode(value),
        base64.urlsafe_b64encode(value).rstrip(b"="),
    }


def secrets_to_hide(app):
    with app.app_context():
        stored = db.session.execute(select(User.password_hash)).scalars().all()
    named = {
        "password": GOOD,
        "wrong password": SENTINEL_WRONG,
        "new password": SENTINEL_NEW,
        "bad password": SENTINEL_BAD,
        "SECRET_KEY": app.config["SECRET_KEY"],
        "MASTER_KEY": app.config["MASTER_KEY"],
    }
    named.update({f"stored hash {i}": h for i, h in enumerate(stored)})
    found = {name: variants(value) for name, value in named.items()}
    found["any Argon2 hash"] = {b"$argon2"}
    return found


def leaks(blob, patterns):
    return sorted(
        name
        for name, options in patterns.items()
        if any(option in blob for option in options)
    )


def blobs_of(app, label, response):
    """Everything one response shows: body, headers and decoded cookies."""
    parts = [response.get_data(), str(response.headers).encode()]
    serializer = app.session_interface.get_signing_serializer(app)
    for line in response.headers.getlist("Set-Cookie"):
        parts.append(line.encode())
        name, _, value = line.split(";", 1)[0].partition("=")
        if name == app.config["SESSION_COOKIE_NAME"] and value:
            parts.append(json.dumps(serializer.loads(value)).encode())
    return label, response.status_code, b"\n".join(parts)


def run_session(app):
    """A realistic visit: pages, mistakes, a lock-out, login and logout.

    Returns (label, status, everything-shown) for every response.
    """
    seen = []

    def see(label, response):
        seen.append(blobs_of(app, label, response))
        return response

    def post(client, path, label, data=None, **kwargs):
        data = dict(data or {})
        data.setdefault("csrf_token", token_for(client))
        return see(label, client.post(path, data=data, **kwargs))

    def pages(client, who):
        for rule, method in inventory(app):
            if method == "GET":
                see(f"{who} GET {rule.rule}", client.get(url_for_rule(rule)))

    visitor = app.test_client()
    pages(visitor, "anonymous")
    see("404", visitor.get("/no-such-page"))
    see("static 404", visitor.get("/static/no-such-file.css"))
    see("405", visitor.get("/auth/logout"))
    see(
        "400 login without token",
        visitor.post(
            LOGIN_PATH, data={"username": "alice", "password": GOOD}
        ),
    )
    post(
        visitor,
        "/auth/register",
        "register ok",
        {"username": "alice", "password": GOOD, "confirm": GOOD},
    )
    post(
        visitor,
        "/auth/register",
        "register bad password",
        {"username": "bobby", "password": SENTINEL_BAD, "confirm": "no"},
    )
    post(
        visitor,
        "/auth/register",
        "register taken name",
        {
            "username": "alice",
            "password": SENTINEL_NEW,
            "confirm": SENTINEL_NEW,
        },
    )
    post(
        visitor,
        LOGIN_PATH,
        "login unknown user",
        {"username": "nobody", "password": SENTINEL_WRONG},
    )
    post(
        visitor,
        LOGIN_PATH + "?next=https%3A%2F%2Fevil.example%2F",
        "login hostile next",
        {"username": "alice", "password": SENTINEL_WRONG},
    )

    member = app.test_client()
    post(
        member,
        LOGIN_PATH + "?next=%2F",
        "login ok",
        {"username": "alice", "password": GOOD},
    )
    pages(member, "member")
    post(member, "/auth/logout", "logout")

    guesser = app.test_client()
    for attempt in range(7):
        post(
            guesser,
            LOGIN_PATH,
            f"guess {attempt}",
            {"username": "alice", "password": SENTINEL_WRONG},
        )
    return seen


def test_the_session_reaches_every_kind_of_answer(web):
    seen = run_session(web)
    assert {status for _, status, _ in seen} >= {200, 302, 400, 404, 405, 429}
    assert all(blob for _, _, blob in seen)


def test_no_response_shows_a_password_a_hash_or_a_key(web):
    seen = run_session(web)
    patterns = secrets_to_hide(web)
    assert "stored hash 0" in patterns
    found = {
        label: leaks(blob, patterns)
        for label, _, blob in seen
        if leaks(blob, patterns)
    }
    assert found == {}


def test_nothing_is_printed_or_logged_that_shows_a_secret(
    web, capsys, caplog
):
    caplog.set_level(0)
    run_session(web)
    patterns = secrets_to_hide(web)
    printed = capsys.readouterr()
    shown = (printed.out + printed.err + caplog.text).encode()
    assert leaks(shown, patterns) == []


def test_the_scanner_finds_each_kind_of_secret(web):
    add_user(web)
    patterns = secrets_to_hide(web)
    with web.app_context():
        stored = db.session.execute(select(User.password_hash)).scalar_one()
    planted = {
        "password": GOOD.encode(),
        "SECRET_KEY": web.config["SECRET_KEY"].encode(),
        "MASTER_KEY": web.config["MASTER_KEY"].hex().encode(),
        "stored hash 0": stored.encode(),
        "any Argon2 hash": b"x $argon2id$v=19$m=8 y",
    }
    for name, blob in planted.items():
        assert name in leaks(b"before " + blob + b" after", patterns)
    master_b64 = base64.b64encode(web.config["MASTER_KEY"])
    assert "MASTER_KEY" in leaks(master_b64, patterns)
    assert leaks(b"nothing to see here", patterns) == []


def test_the_sweep_reads_inside_the_session_cookie(web):
    add_user(web)
    client = web.test_client()
    response = client.post(
        LOGIN_PATH,
        data={
            "csrf_token": token_for(client),
            "username": "alice",
            "password": GOOD,
        },
    )
    _, _, blob = blobs_of(web, "login", response)
    assert b"_user_id" in blob  # the decoded payload is part of the blob


# ------------------------------------------------------------ the cookie


SESSION_KEYS = {"csrf_token", "_user_id", "_id", "_fresh"}


def session_payload(app, response):
    serializer = app.session_interface.get_signing_serializer(app)
    name = app.config["SESSION_COOKIE_NAME"]
    for line in response.headers.getlist("Set-Cookie"):
        cookie, _, value = line.split(";", 1)[0].partition("=")
        if cookie == name and value:
            return value, serializer.loads(value)
    raise AssertionError("no session cookie in the response")


def test_the_login_cookie_holds_only_the_known_keys(web):
    add_user(web)
    address, agent = "203.0.113.77", "inventory-agent/9.9"
    client = web.test_client()
    client.environ_base.update(
        {"REMOTE_ADDR": address, "HTTP_USER_AGENT": agent}
    )
    response = client.post(
        LOGIN_PATH,
        data={
            "csrf_token": token_for(client),
            "username": "alice",
            "password": GOOD,
        },
    )
    raw, payload = session_payload(web, response)
    assert set(payload) <= SESSION_KEYS
    assert payload["_user_id"] == "1"
    assert payload["_fresh"] is True
    # Flask-Login keeps only a SHA-512 digest of address and browser.
    assert re.fullmatch(r"[0-9a-f]{128}", payload["_id"])
    text = raw + json.dumps(payload)
    assert address not in text
    assert agent not in text
    assert "alice" not in text
    assert GOOD not in text


def test_the_anonymous_cookie_holds_only_the_csrf_token(web):
    client = web.test_client()
    response = client.get(LOGIN_PATH)
    _, payload = session_payload(web, response)
    assert set(payload) == {"csrf_token"}


# -------------------------------------------------------------- a server error


def test_an_unexpected_error_shows_nothing_about_itself(web, caplog):
    detail = "detail-" + GOOD + "-" + web.config["SECRET_KEY"]

    @web.get("/planted-boom")
    def planted_boom():
        raise RuntimeError(detail)

    web.config["PROPAGATE_EXCEPTIONS"] = False
    assert web.debug is False
    response = web.test_client().get("/planted-boom")
    body = response.get_data(as_text=True)
    assert response.status_code == 500
    assert detail not in body
    assert GOOD not in body
    assert web.config["SECRET_KEY"] not in body
    for word in ("Traceback", "RuntimeError", ".py", "planted_boom"):
        assert word not in body
    assert detail not in str(response.headers)
    assert leaks(body.encode(), secrets_to_hide(web)) == []
