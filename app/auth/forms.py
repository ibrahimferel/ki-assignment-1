"""Forms for the login and registration pages.

The forms only collect input and carry the CSRF token. The real rules for
usernames and passwords live in ``app.auth.services``.
"""

from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField
from wtforms.validators import EqualTo

from app.auth.services import (
    PASSWORD_MAX,
    PASSWORD_MIN,
    USERNAME_MAX,
    USERNAME_MIN,
)

__all__ = ["LoginForm", "RegisterForm"]


class LoginForm(FlaskForm):
    # No validators and no length limits here: a malformed login must fail
    # exactly like a wrong password, inside ``authenticate``.
    username = StringField(
        "Username",
        render_kw={
            "autocomplete": "username",
            "autofocus": True,
            "required": True,
        },
    )
    password = PasswordField(
        "Password",
        render_kw={"autocomplete": "current-password", "required": True},
    )


class RegisterForm(FlaskForm):
    username = StringField(
        "Username",
        render_kw={
            "autocomplete": "username",
            "autofocus": True,
            "required": True,
            "minlength": USERNAME_MIN,
            "maxlength": USERNAME_MAX,
        },
    )
    password = PasswordField(
        "Password",
        render_kw={
            "autocomplete": "new-password",
            "required": True,
            "minlength": PASSWORD_MIN,
            "maxlength": PASSWORD_MAX,
        },
    )
    confirm = PasswordField(
        "Repeat password",
        validators=[EqualTo("password", message="Passwords do not match.")],
        render_kw={
            "autocomplete": "new-password",
            "required": True,
            "maxlength": PASSWORD_MAX,
        },
    )
