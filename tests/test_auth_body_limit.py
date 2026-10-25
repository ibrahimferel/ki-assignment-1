"""Tests for app/request_limits.py: the 16 KiB body limit of /auth/*.

The sizes are the size of the whole request body in bytes. A request is
refused with 413 when its Content-Length is bigger than the limit; a body of
exactly 16 KiB is accepted.
"""

import ast
import io
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlencode

import pytest
from argon2 import PasswordHasher
from flask import request

import app as app_package
from app import request_limits
from app.auth import services
from app.auth.services import PASSWORD_MAX, USERNAME_MAX
from app.extensions import db
from app.models import User
from app.request_limits import AUTH_MAX_BODY_BYTES

LIMIT = 16 * 1024
GOOD = "correct horse battery"
TOKEN_PATTERN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
FORM = "application/x-www-form-urlencoded"
FORCED = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@pytest.fixture(autouse=True)
def cheap_hasher(monkeypatch):
    cheap = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    monkeypatch.setattr(services, "_HASHER", cheap)
    monkeypatch.setattr(services, "_dummy", None)


@pytest.fixture()
def site(web):
    """The ``web`` app with an account and a route outside /auth."""

    @web.post("/t/size")
    def t_size():
        return str(len(request.form.get("pad", ""))), 200

    @web.post("/t/limit-seen")
    def t_limit_seen():
        return str(request.max_content_length), 200

    with web.app_context():
        services.register_user("alice", GOOD)
    return web


def token_for(client):
    page = client.get("/auth/login").get_data(as_text=True)
    return TOKEN_PATTERN.search(page).group(1)


def body_of(size, token, **fields):
    """An urlencoded body of exactly ``size`` bytes (padded with ``pad``)."""
    parts = {"csrf_token": token, **fields}
    base = urlencode(parts) + "&pad="
    assert len(base) <= size, "size too small for the fields"
    body = (base + "x" * (size - len(base))).encode()
    assert len(body) == size
    return body


def post(client, path, body, content_type=FORM):
    return client.post(path, data=body, content_type=content_type)


def login_fields():
    return {"username": "alice", "password": "wrong password!"}


def fields_for(path):
    return login_fields() if path != "/auth/logout" else {}


AUTH_PATHS = ["/auth/login", "/auth/register", "/auth/logout"]


# ------------------------------------------------------- the exact limits


def test_the_limit_is_16_kib_and_not_configurable():
    assert AUTH_MAX_BODY_BYTES == LIMIT == 16384


@pytest.mark.parametrize("path", AUTH_PATHS)
@pytest.mark.parametrize(
    "size", [LIMIT - 1, LIMIT, LIMIT + 1, 2 * LIMIT, 60_000]
)
def test_a_body_over_16_kib_is_refused_with_413_and_nothing_else(
    site, path, size
):
    client = site.test_client()
    response = post(
        client, path, body_of(size, token_for(client), **fields_for(path))
    )
    refused = response.status_code == 413
    assert refused == (size > LIMIT), response.status_code
    if size <= LIMIT:
        assert response.status_code in (200, 302)


@pytest.mark.parametrize("size", [LIMIT, LIMIT + 1])
def test_multipart_has_the_same_limit(site, size):
    client = site.test_client()
    token = token_for(client)
    boundary = "XBOUNDARY"
    head = (
        f"--{boundary}\r\nContent-Disposition: form-data; "
        f'name="csrf_token"\r\n\r\n{token}\r\n'
        f"--{boundary}\r\nContent-Disposition: form-data; "
        f'name="pad"\r\n\r\n'
    )
    tail = f"\r\n--{boundary}--\r\n"
    fill = size - len(head) - len(tail)
    body = (head + "x" * fill + tail).encode()
    assert len(body) == size
    response = post(
        client,
        "/auth/login",
        body,
        content_type=f"multipart/form-data; boundary={boundary}",
    )
    assert (response.status_code == 413) == (size > LIMIT)


def test_a_body_without_content_length_is_not_read_and_not_413(site):
    client = site.test_client()
    token = token_for(client)
    response = client.open(
        "/auth/login",
        method="POST",
        input_stream=io.BytesIO(body_of(LIMIT + 500, token, **login_fields())),
        content_type=FORM,
        environ_overrides={"CONTENT_LENGTH": ""},
    )
    # No Content-Length: the body counts as empty, so the CSRF check fails.
    assert response.status_code == 400


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_get_and_head_ignore_a_big_body(site, method):
    response = site.test_client().open(
        "/auth/login", method=method, data=b"x" * 60_000,
        content_type="text/plain",
    )
    assert response.status_code == 200


def test_other_routes_keep_the_global_limit(site):
    client = site.test_client()
    token = token_for(client)
    response = post(client, "/t/size", body_of(60_000, token))
    assert response.status_code == 200
    base = len(urlencode({"csrf_token": token}) + "&pad=")
    assert response.get_data(as_text=True) == str(60_000 - base)
    seen = post(client, "/t/limit-seen", body_of(300, token))
    assert seen.get_data(as_text=True) == str(
        site.config["MAX_CONTENT_LENGTH"]
    )


def test_a_missing_page_under_auth_is_a_plain_404(site):
    client = site.test_client()
    assert post(client, "/auth/nothing", b"x" * 60_000).status_code == 404
    assert client.get("/auth/logout").status_code == 405


# ------------------------------------------------- the global limit, too


def test_the_smaller_global_limit_wins(site):
    site.config["MAX_CONTENT_LENGTH"] = 2048
    client = site.test_client()
    token = token_for(client)
    assert post(
        client, "/auth/login", body_of(2048, token, **login_fields())
    ).status_code == 200
    assert post(
        client, "/auth/login", body_of(2049, token, **login_fields())
    ).status_code == 413
    seen = post(client, "/t/limit-seen", body_of(300, token))
    assert seen.get_data(as_text=True) == "2048"


@pytest.mark.parametrize("global_limit", [None, LIMIT + 1, 50 * 1024 * 1024])
def test_a_larger_or_missing_global_limit_gives_16_kib(site, global_limit):
    site.config["MAX_CONTENT_LENGTH"] = global_limit
    client = site.test_client()
    token = token_for(client)
    fields = login_fields()
    assert post(
        client, "/auth/login", body_of(LIMIT, token, **fields)
    ).status_code == 200
    assert post(
        client, "/auth/login", body_of(LIMIT + 1, token, **fields)
    ).status_code == 413
    assert post(
        client, "/auth/register", body_of(60_000, token)
    ).status_code == 413


def test_without_a_global_limit_other_routes_are_not_limited(site):
    site.config["MAX_CONTENT_LENGTH"] = None
    client = site.test_client()
    token = token_for(client)
    assert post(
        client, "/t/size", body_of(60_000, token)
    ).status_code == 200
    seen = post(client, "/t/limit-seen", body_of(300, token))
    assert seen.get_data(as_text=True) == "None"


# ------------------------------------------- the order inside the request


def test_a_413_comes_before_csrf_throttle_and_password_work(
    site, monkeypatch
):
    def fail(*args, **kwargs):
        raise AssertionError("must not run for an oversized request")

    monkeypatch.setattr("app.auth.routes.authenticate", fail)
    monkeypatch.setattr(services, "_verify", fail)
    gate = site.extensions["throttle"]
    monkeypatch.setattr(gate, "acquire_login", fail)
    monkeypatch.setattr(gate, "acquire_register", fail)
    client = site.test_client()
    # No cookie and no token at all: still 413, not 400.
    response = post(client, "/auth/login", b"a=" + b"x" * (LIMIT + 10))
    assert response.status_code == 413
    response = post(client, "/auth/register", b"a=" + b"x" * (LIMIT + 10))
    assert response.status_code == 413


def test_413_is_not_a_login_attempt(site):
    client = site.test_client()
    for _ in range(12):
        response = post(
            client,
            "/auth/login",
            body_of(
                LIMIT + 1, token_for(client), username="alice",
                password="wrong password!",
            ),
        )
        assert response.status_code == 413
    answers = []
    for _ in range(6):
        token = token_for(client)
        answers.append(
            post(client, "/auth/login", body_of(300, token, **login_fields()))
            .status_code
        )
    # Exactly five failures are allowed per name; the sixth is refused.
    assert answers == [200, 200, 200, 200, 200, 429]


def test_413_does_not_use_the_registration_allowance(site):
    client = site.test_client()
    for _ in range(12):
        assert post(
            client, "/auth/register", body_of(LIMIT + 1, token_for(client))
        ).status_code == 413
    answers = [
        post(
            client,
            "/auth/register",
            body_of(
                300, token_for(client), username="a", password="short",
                confirm="short",
            ),
        ).status_code
        for _ in range(10)
    ]
    assert answers == [200] * 10


def test_a_blocked_client_still_gets_413_for_an_oversized_request(site):
    client = site.test_client()
    for _ in range(5):
        post(client, "/auth/login", body_of(300, token_for(client),
                                            **login_fields()))
    blocked = post(
        client, "/auth/login",
        body_of(300, token_for(client), **login_fields()),
    )
    assert blocked.status_code == 429
    big = post(
        client, "/auth/login", body_of(LIMIT + 1, token_for(client),
                                       **login_fields())
    )
    assert big.status_code == 413


# ---------------------------------------------------- what a 413 looks like


def test_every_413_is_the_same_standard_page_with_the_security_headers(site):
    client = site.test_client()
    site.config["MAX_CONTENT_LENGTH"] = 2048
    global_413 = post(client, "/t/size", b"a=" + b"x" * 3000)
    site.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
    answers = [
        post(client, path, b"a=" + b"x" * (LIMIT + 5))
        for path in AUTH_PATHS
    ]
    answers.append(
        post(client, "/auth/login", b"y" * 100_000, content_type="text/plain")
    )
    assert {r.status_code for r in answers} == {413}
    assert {r.get_data() for r in answers} == {global_413.get_data()}
    for response in answers:
        text = response.get_data(as_text=True)
        assert "Request Entity Too Large" in text
        assert not re.search(r"16384|16 ?KiB|csrf|alice|password", text, re.I)
        assert response.headers["Cache-Control"] == "no-store"
        assert "Content-Security-Policy" in response.headers
        for name, value in FORCED.items():
            assert response.headers[name] == value, name
        assert "Set-Cookie" not in response.headers
        assert "Retry-After" not in response.headers


# ------------------------------------- the biggest form that is allowed


def hangul_syllables(count):
    """``count`` different Hangul syllables written as three jamo each.

    Each one is 3 characters / 9 UTF-8 bytes / 27 characters when every byte
    is percent-encoded, and NFKC turns it into ONE character. A scan of all
    code points found no character with more bytes per normalized character,
    so this is the worst case for the password fields.
    """
    lead = [chr(c) for c in range(0x1100, 0x1113)]
    vowel = [chr(c) for c in range(0x1161, 0x1176)]
    tail = [chr(c) for c in range(0x11A8, 0x11C3)]
    all_syllables = [a + b + c for a in lead for b in vowel for c in tail]
    return "".join(all_syllables[i * 7] for i in range(count))


def percent_encode_every_byte(text):
    return "".join(f"%{byte:02X}" for byte in text.encode("utf-8"))


def biggest_register_body(token):
    password = hangul_syllables(PASSWORD_MAX)
    username = "a" * (USERNAME_MAX - 2) + "b1"
    parts = [
        f"csrf_token={token}",
        f"username={percent_encode_every_byte(username)}",
        f"password={percent_encode_every_byte(password)}",
        f"confirm={percent_encode_every_byte(password)}",
    ]
    return "&".join(parts).encode(), username, password


def test_the_biggest_valid_registration_form_is_accepted_with_margin(site):
    client = site.test_client()
    body, username, password = biggest_register_body(token_for(client))
    normalized = unicodedata.normalize("NFKC", password)
    # It really is the maximum on every axis the service checks.
    assert len(normalized) == PASSWORD_MAX == 128
    assert len(password) == 3 * PASSWORD_MAX  # raw length is below the 1024
    assert len(username) == USERNAME_MAX == 32
    assert len(password.encode()) == 9 * PASSWORD_MAX
    # Three bytes of text per percent-encoded byte, no shortcuts.
    assert len(percent_encode_every_byte(password)) == 27 * PASSWORD_MAX
    margin = LIMIT - len(body)
    # Measured (token length 91): body 7139 bytes, margin 9245 bytes.
    assert len(body) < LIMIT
    assert margin >= 8 * 1024, (len(body), margin)
    response = post(client, "/auth/register", body)
    assert response.status_code == 302
    with site.app_context():
        assert db.session.query(User).filter_by(username=username).count() == 1
    # The same long password logs in (a login form is smaller than this).
    login_body = "&".join([
        f"csrf_token={token_for(client)}",
        f"username={percent_encode_every_byte(username)}",
        f"password={percent_encode_every_byte(password)}",
    ]).encode()
    assert len(login_body) < len(body) < LIMIT
    assert post(client, "/auth/login", login_body).status_code == 302


def test_one_more_character_is_refused_by_the_service_not_by_the_limit(site):
    client = site.test_client()
    password = hangul_syllables(PASSWORD_MAX) + "x"
    body = "&".join([
        f"csrf_token={token_for(client)}",
        "username=bigname",
        f"password={percent_encode_every_byte(password)}",
        f"confirm={percent_encode_every_byte(password)}",
    ]).encode()
    assert len(body) < LIMIT
    response = post(client, "/auth/register", body)
    assert response.status_code == 200
    assert "Password is too long." in response.get_data(as_text=True)


def test_a_multibyte_username_is_not_valid_so_it_is_not_a_size_case(site):
    client = site.test_client()
    body = "&".join([
        f"csrf_token={token_for(client)}",
        f"username={percent_encode_every_byte('ａ' * 32)}",
        f"password={percent_encode_every_byte(GOOD)}",
        f"confirm={percent_encode_every_byte(GOOD)}",
    ]).encode()
    response = post(client, "/auth/register", body)
    assert response.status_code == 200
    assert "Username may only contain" in response.get_data(as_text=True)


# ------------------------------------------------------- the module itself

MODULE_TREE = ast.parse(Path(request_limits.__file__).read_text())


def test_the_module_imports_only_flask_and_never_logs_or_prints():
    modules = set()
    for node in ast.walk(MODULE_TREE):
        if isinstance(node, ast.ImportFrom):
            modules.add(node.module)
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
    assert modules == {"flask"}
    names = {n.id for n in ast.walk(MODULE_TREE) if isinstance(n, ast.Name)}
    assert not names & {"print", "logging", "logger", "session", "os"}


def test_the_public_names():
    assert request_limits.__all__ == [
        "AUTH_MAX_BODY_BYTES",
        "register_auth_body_limit",
    ]


def test_the_limit_is_registered_once_and_alone(site):
    import inspect

    source = inspect.getsource(app_package.create_app)
    assert source.count("register_auth_body_limit(app)") == 1
    assert source.count("import register_auth_body_limit") == 1
    hooks = site.url_value_preprocessors.get(None, [])
    assert [hook.__name__ for hook in hooks] == ["_limit_auth_body"]
    assert not site.url_value_preprocessors.get("auth")
