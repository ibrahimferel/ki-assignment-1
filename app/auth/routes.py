"""Pages for registration, login and logout.

Rules these routes follow:

* Every POST needs a CSRF token (``CSRFProtect`` plus the form token).
* A failed login always shows the same message, whatever the reason.
* A successful login starts from an empty session (no session fixation) and
  is NOT permanent: ``session.permanent`` would turn Flask-Login's "strong"
  protection into "basic" mode. The 2-hour limit still applies.
* Logout is POST-only, so a link or an image can not log anyone out.
* ``next`` is only followed when ``safe_next_url`` accepts it.
* Auth pages are sent with ``Cache-Control: no-store``.
* Login and registration attempts are counted before any password work is
  done (see ``app.auth.throttle``). A refused attempt gets status 429 with a
  ``Retry-After`` header and the same page, whatever the reason, and never
  reaches ``authenticate`` or ``register_user``. The client address is
  ``request.remote_addr`` only; no header is trusted.
"""

from flask import (
    Blueprint,
    current_app,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_user, logout_user

from app.auth.forms import LoginForm, RegisterForm
from app.auth.redirects import safe_next_url
from app.auth.services import (
    PASSWORD_MAX,
    PASSWORD_MIN,
    USERNAME_MAX,
    USERNAME_MIN,
    PasswordPolicyError,
    UsernamePolicyError,
    UsernameTakenError,
    authenticate,
    normalize_username,
    register_user,
)
from app.auth.throttle import MALFORMED_USERNAME

__all__ = ["LOGIN_FAILED", "auth_bp"]

LOGIN_FAILED = "Invalid username or password."
TOO_MANY_ATTEMPTS = "Too many attempts. Please try again later."

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.after_request
def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


def _text(field):
    """The submitted text of a form field; a missing field counts as ''."""
    return field.data if isinstance(field.data, str) else ""


def _home():
    return redirect(url_for("main.index"))


def _throttle():
    return current_app.extensions["throttle"]


def _throttle_name(field):
    """The username part of the login limit key: the normalized name, or one
    fixed value for every name that is not valid."""
    try:
        return normalize_username(_text(field))
    except UsernamePolicyError:
        return MALFORMED_USERNAME


def _too_many(template, decision, **context):
    """The page for a refused attempt: status 429, the same text for every
    cause, and how long to wait."""
    response = make_response(
        render_template(template, error=TOO_MANY_ATTEMPTS, **context), 429
    )
    response.headers["Retry-After"] = str(decision.retry_after)
    return response


def _limits():
    return {
        "username_min": USERNAME_MIN,
        "username_max": USERNAME_MAX,
        "password_min": PASSWORD_MIN,
        "password_max": PASSWORD_MAX,
    }


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return _home()
    form = RegisterForm()
    if form.validate_on_submit():
        decision = _throttle().acquire_register(request.remote_addr)
        if not decision.allowed:
            return _too_many(
                "auth/register.html", decision, form=form, limits=_limits()
            )
        try:
            register_user(_text(form.username), _text(form.password))
        except UsernamePolicyError as error:
            form.username.errors.append(error.message)
        except UsernameTakenError as error:
            form.username.errors.append(error.message)
        except PasswordPolicyError as error:
            form.password.errors.append(error.message)
        else:
            flash("Account created. You can log in now.", "success")
            return redirect(url_for("auth.login"))
    return render_template(
        "auth/register.html", form=form, limits=_limits(), error=None
    )


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return _home()
    form = LoginForm()
    next_url = safe_next_url(request.args.get("next"))
    error = None
    if form.validate_on_submit():
        decision = _throttle().acquire_login(
            request.remote_addr, _throttle_name(form.username)
        )
        if not decision.allowed:
            return _too_many(
                "auth/login.html", decision, form=form, next_url=next_url
            )
        user = authenticate(_text(form.username), _text(form.password))
        if user is not None:
            _throttle().login_succeeded(decision.ticket)
            session.clear()  # nothing from before the login survives
            login_user(user, remember=False)
            return redirect(next_url or url_for("main.index"))
        error = LOGIN_FAILED
    return render_template(
        "auth/login.html", form=form, error=error, next_url=next_url
    )


@auth_bp.post("/logout")
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
