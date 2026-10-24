"""Application factory."""

from typing import Optional

from flask import Flask

from app.config import Config
from app.extensions import db

__all__ = ["create_app"]


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

    db.init_app(app)

    # Import the models so their tables are registered with ``db`` before
    # anyone calls ``db.create_all()``. Importing here (not at the top of the
    # file) keeps ``import app`` free of side effects.
    from app import models  # noqa: F401

    return app
