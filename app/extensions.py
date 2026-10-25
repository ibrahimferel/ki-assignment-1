"""Flask extension objects.

The objects are created here, without an application, and bound to the app
inside ``create_app()`` with ``init_app``. Keeping them in their own module
lets ``models.py`` and the feature packages import them without importing
``app/__init__.py``, which would cause circular imports.
"""

from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

__all__ = ["csrf", "db", "login_manager"]

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
