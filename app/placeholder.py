"""Public landing page and temporary signed-in storage test page at "/"."""

from flask import Blueprint, render_template
from flask_login import current_user, login_required

__all__ = ["main_bp"]

main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def index():
    template = "placeholder_home.html" if current_user.is_authenticated else "landing.html"
    return render_template(template)


@main_bp.get("/sharing")
@login_required
def sharing_page():
    """The page for requesting, approving, unlocking and viewing shared data.

    It only serves HTML; all data comes from the JSON API under
    ``/sharing/requests`` (see ``static/js/sharing.js``).
    """
    return render_template("sharing.html")
