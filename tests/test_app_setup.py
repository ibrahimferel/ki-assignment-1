"""Tests for the security wiring done by ``create_app``.

Covers Flask-Login (user loader, session protection), CSRF protection and the
session cookie settings. The routes used here exist only inside these tests;
the real login routes come later.
"""

import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import pytest
from flask import session
from flask_login import current_user, login_user
from flask_wtf.csrf import generate_csrf

from app import _load_user, create_app
from app.config import TestingConfig
from app.extensions import csrf, db, login_manager
from app.models import User

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def web(tmp_path):
    """An app with a few test-only routes and two saved users.

    Unlike the ``app`` fixture in conftest.py, no application context stays
    open around the test. That matters here: with an outer context, ``g`` is
    shared by all requests, so Flask-Login would remember the user of the
    first request and these tests could not see a session being dropped.
    """
    config = TestingConfig()
    config.STORAGE_DIR = tmp_path / "storage"
    app = create_app(config)

    @app.get("/token")
    def token():
        return generate_csrf()

    @app.post("/post")
    def post():
        return "posted"

    @app.get("/set")
    def set_session():
        session["x"] = 1
        session.permanent = True
        return "ok"

    @app.get("/noop")
    def noop():
        return "noop"

    @app.get("/in/<int:user_id>")
    def log_in(user_id):
        login_user(db.session.get(User, user_id))
        return "in"

    @app.get("/in-permanent/<int:user_id>")
    def log_in_permanent(user_id):
        login_user(db.session.get(User, user_id))
        session.permanent = True
        return "in"

    @app.get("/who")
    def who():
        if current_user.is_authenticated:
            return current_user.username
        return "anon"

    with app.app_context():
        db.create_all()
        for name in ("alice", "bobby"):
            db.session.add(User(username=name, password_hash="x" * 20))
        db.session.commit()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


@pytest.fixture()
def client(web):
    return web.test_client()


def set_cookie(response):
    return response.headers.get("Set-Cookie", "")


# ----------------------------------------------------------------- extensions


def test_extensions_are_bound_to_the_app(web):
    assert web.extensions["csrf"] is csrf
    assert web.login_manager is login_manager


def test_session_protection_is_strong(web):
    assert login_manager.session_protection == "strong"


def test_importing_app_alone_imports_no_models_and_no_auth_services():
    code = (
        "import sys; import app\n"
        "print('app.models' in sys.modules, "
        "'app.auth.services' in sys.modules)\n"
    )
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-W",
            "error",
            "-c",
            f"import sys; sys.path.insert(0, {str(PROJECT_ROOT)!r})\n" + code,
        ],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    assert result.stdout.split() == ["False", "False"], result.stderr


# ------------------------------------------------------------ cookie settings


def test_cookie_settings_of_the_default_app(web):
    assert web.config["SESSION_COOKIE_HTTPONLY"] is True
    assert web.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert web.config["SESSION_COOKIE_SECURE"] is False
    assert web.config["PERMANENT_SESSION_LIFETIME"] == timedelta(hours=2)
    assert web.config["SESSION_REFRESH_EACH_REQUEST"] is False


class WeakConfig(TestingConfig):
    """A config that tries to weaken every cookie setting."""

    __test__ = False

    def __init__(self):
        super().__init__()
        self.SESSION_COOKIE_HTTPONLY = False
        self.SESSION_COOKIE_SAMESITE = "None"
        self.PERMANENT_SESSION_LIFETIME = timedelta(days=99)
        self.SESSION_REFRESH_EACH_REQUEST = True


def test_a_config_cannot_weaken_the_cookie_settings():
    weak = create_app(WeakConfig())
    assert weak.config["SESSION_COOKIE_HTTPONLY"] is True
    assert weak.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert weak.config["PERMANENT_SESSION_LIFETIME"] == timedelta(hours=2)
    assert weak.config["SESSION_REFRESH_EACH_REQUEST"] is False


def test_only_the_secure_flag_comes_from_the_config():
    config = TestingConfig()
    config.SESSION_COOKIE_SECURE = True
    secure = create_app(config)
    assert secure.config["SESSION_COOKIE_SECURE"] is True
    assert create_app(TestingConfig()).config["SESSION_COOKIE_SECURE"] is False


def test_permanent_cookie_flags_and_expiry(web, client):
    cookie = set_cookie(client.get("/set"))
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert "Secure" not in cookie
    assert "Path=/" in cookie
    expires = parsedate_to_datetime(
        next(p for p in cookie.split("; ") if p.startswith("Expires="))[8:]
    )
    remaining = expires - datetime.now(timezone.utc)
    assert timedelta(hours=1, minutes=58) < remaining <= timedelta(hours=2)


def test_the_cookie_gets_the_secure_flag_when_configured(tmp_path):
    config = TestingConfig()
    config.STORAGE_DIR = tmp_path / "storage"
    config.SESSION_COOKIE_SECURE = True
    flask_app = create_app(config)

    @flask_app.get("/set")
    def set_session():
        session["x"] = 1
        return "ok"

    cookie = set_cookie(flask_app.test_client().get("/set"))
    assert "Secure" in cookie and "HttpOnly" in cookie


def test_the_cookie_is_not_renewed_by_requests_that_change_nothing(
    web, client
):
    login = client.get("/in/1")
    assert "Set-Cookie" in login.headers
    assert "Set-Cookie" not in client.get("/noop").headers
    assert "Set-Cookie" not in client.get("/who").headers


def test_a_session_cookie_without_permanent_has_no_expiry_date(web, client):
    # A browser-session cookie: it also ends when the browser is closed.
    cookie = set_cookie(client.get("/in/1"))
    assert "Expires" not in cookie and "Max-Age" not in cookie
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_the_two_hour_limit_is_enforced_even_without_permanent(
    web, client, monkeypatch
):
    # The server rejects a signed cookie older than PERMANENT_SESSION_LIFETIME
    # whether or not the session is marked permanent.
    client.get("/in/1")
    assert client.get("/who").get_data(as_text=True) == "alice"
    real_time = time.time

    monkeypatch.setattr(time, "time", lambda: real_time() + 2 * 3600 - 60)
    assert client.get("/who").get_data(as_text=True) == "alice"
    monkeypatch.setattr(time, "time", lambda: real_time() + 2 * 3600 + 60)
    assert client.get("/who").get_data(as_text=True) == "anon"


# ----------------------------------------------------------------------- CSRF


def test_post_without_a_token_is_refused(web, client):
    assert client.post("/post").status_code == 400


def test_post_with_a_wrong_token_is_refused(web, client):
    client.get("/token")
    response = client.post("/post", headers={"X-CSRFToken": "nope"})
    assert response.status_code == 400


def test_post_with_the_right_token_in_the_header_works(web, client):
    token = client.get("/token").get_data(as_text=True)
    response = client.post("/post", headers={"X-CSRFToken": token})
    assert response.status_code == 200


def test_post_with_the_right_token_in_the_form_works(web, client):
    token = client.get("/token").get_data(as_text=True)
    response = client.post("/post", data={"csrf_token": token})
    assert response.status_code == 200


def test_a_token_from_another_session_is_refused(web, client):
    token = client.get("/token").get_data(as_text=True)
    stranger = web.test_client()
    response = stranger.post("/post", headers={"X-CSRFToken": token})
    assert response.status_code == 400


def test_get_needs_no_token(web, client):
    assert client.get("/noop").status_code == 200


def test_an_old_token_is_refused(web, client):
    token = client.get("/token").get_data(as_text=True)
    web.config["WTF_CSRF_TIME_LIMIT"] = -1  # every token is already too old
    response = client.post("/post", headers={"X-CSRFToken": token})
    assert response.status_code == 400


# ------------------------------------------------ Flask-Login + the loader


def test_a_logged_in_user_is_current_user(web, client):
    client.get("/in/2")
    assert client.get("/who").get_data(as_text=True) == "bobby"


def test_a_user_deleted_after_login_becomes_anonymous(web, client):
    client.get("/in/1")
    assert client.get("/who").get_data(as_text=True) == "alice"
    with web.app_context():
        db.session.delete(db.session.get(User, 1))
        db.session.commit()
    assert client.get("/who").get_data(as_text=True) == "anon"


def test_strong_protection_drops_the_session_when_the_browser_changes(
    web, client
):
    client.get("/in/1", headers={"User-Agent": "browser-one"})
    same = client.get("/who", headers={"User-Agent": "browser-one"})
    assert same.get_data(as_text=True) == "alice"
    other = client.get("/who", headers={"User-Agent": "browser-two"})
    assert other.get_data(as_text=True) == "anon"
    # The session was deleted, so the original browser is out as well.
    back = client.get("/who", headers={"User-Agent": "browser-one"})
    assert back.get_data(as_text=True) == "anon"


def test_a_permanent_session_defeats_strong_protection(web, client):
    # Flask-Login treats a permanent session like "basic" mode: it only marks
    # it not fresh and keeps the user logged in. The login route must
    # therefore NOT set session.permanent (the 2-hour limit still applies).
    client.get("/in-permanent/1", headers={"User-Agent": "browser-one"})
    other = client.get("/who", headers={"User-Agent": "browser-two"})
    assert other.get_data(as_text=True) == "alice"


def test_login_user_refuses_a_user_without_an_id(web):
    with web.test_request_context():
        with pytest.raises(ValueError):
            login_user(User(username="alice", password_hash="x" * 20))


def test_the_loader_finds_users_by_plain_decimal_id(web):
    with web.app_context():
        assert _load_user("1").username == "alice"
        assert _load_user("2").username == "bobby"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "0",
        "99",
        "01",
        "001",
        "02",
        "+1",
        " 1",
        "1 ",
        "1_0",
        "1.0",
        "-1",
        "1\n",
        "١",  # Arabic-Indic digit one
        "１",  # fullwidth digit one
        "9" * 30,
        "1" * 19,
        "abc",
    ],
)
def test_the_loader_refuses_odd_ids(web, value):
    with web.app_context():
        assert _load_user(value) is None


def test_the_loader_passes_only_plain_ids_on_to_get_user(web, monkeypatch):
    seen = []

    def spy(user_id):
        seen.append(user_id)

    monkeypatch.setattr("app.auth.services.get_user", spy)
    with web.app_context():
        for value in ("1", "1" * 19, "1" * 20, "\u0661", "007", "x", ""):
            assert _load_user(value) is None
    # 19 digits is the longest id SQLite can store; nothing odd gets through.
    assert seen == [1, int("1" * 19)]


@pytest.mark.parametrize("value", [None, 1, 1.0, b"1", True])
def test_the_loader_refuses_non_strings(web, value):
    with web.app_context():
        assert _load_user(value) is None
