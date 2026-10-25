"""Application factory."""

from datetime import timedelta
from typing import Optional

from flask import Flask

from app.config import Config
from app.extensions import csrf, db, login_manager

__all__ = ["create_app"]

# How long a login stays valid. The cookie is NOT renewed on every request,
# so a stolen cookie has a hard end date.
SESSION_LIFETIME = timedelta(hours=2)

# The longest id SQLite can store has 19 digits.
_MAX_ID_DIGITS = 19


def _load_user(user_id):
    """Flask-Login ``user_loader``: turn the id kept in the session into a
    ``User``, or ``None`` if it is not a plain decimal id of a saved user."""
    if (
        not isinstance(user_id, str)
        or not user_id.isascii()
        or not user_id.isdigit()
        or len(user_id) > _MAX_ID_DIGITS
        or str(int(user_id)) != user_id  # refuses "007"
    ):
        return None
    from app.auth.services import get_user

    return get_user(int(user_id))


def create_app(config_object: Optional[object] = None) -> Flask:
    """Create and configure a Flask application.

    ``config_object`` must be an *instance*, for example ``TestingConfig()``.
    When it is omitted, ``Config()`` is used: it reads and validates the
    environment and raises ``ConfigError`` if the settings are invalid.
    Tables are NOT created here; creating them is a separate explicit step.
    """
    if config_object is None:
        config_object = Config()
    elif isinstance(config_object, type):
        raise TypeError(
            "config_object must be an instance, not a class. "
            "Use create_app(TestingConfig()), not create_app(TestingConfig)."
        )

    app = Flask(__name__)
    app.config.from_object(config_object)

    # Session cookie settings that no config object can weaken. Only
    # SESSION_COOKIE_SECURE comes from the configuration (it depends on
    # whether the site is served over HTTPS).
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = SESSION_LIFETIME
    app.config["SESSION_REFRESH_EACH_REQUEST"] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.user_loader(_load_user)
    # "strong": a session is dropped when the client address or browser
    # changes, for example when a phone moves between networks.
    login_manager.session_protection = "strong"
    csrf.init_app(app)

    # Import the models so their tables are registered with ``db`` before
    # anyone calls ``db.create_all()``. Importing here (not at the top of the
    # file) keeps ``import app`` free of side effects.
    from app import models  # noqa: F401

    # Pages. Imported here for the same reason as the models.
    from app.auth.routes import auth_bp
    from app.auth.throttle import Throttle
    from app.placeholder import main_bp
    from app.security_headers import register_security_headers

    # One limiter per application: its counts live in this process only.
    app.extensions["throttle"] = Throttle()
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to continue."
    login_manager.login_message_category = "info"

    # Security headers on every response (also errors and static files).
    register_security_headers(app)

    return app
