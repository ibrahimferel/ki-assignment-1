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
"""

from flask import (
    Blueprint,
    flash,
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
    register_user,
)

__all__ = ["LOGIN_FAILED", "auth_bp"]

LOGIN_FAILED = "Invalid username or password."

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


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return _home()
    form = RegisterForm()
    if form.validate_on_submit():
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
    limits = {
        "username_min": USERNAME_MIN,
        "username_max": USERNAME_MAX,
        "password_min": PASSWORD_MIN,
        "password_max": PASSWORD_MAX,
    }
    return render_template("auth/register.html", form=form, limits=limits)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return _home()
    form = LoginForm()
    next_url = safe_next_url(request.args.get("next"))
    error = None
    if form.validate_on_submit():
        user = authenticate(_text(form.username), _text(form.password))
        if user is not None:
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
