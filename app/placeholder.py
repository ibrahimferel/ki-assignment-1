"""Public landing page and temporary signed-in storage test page at "/"."""

from flask import Blueprint, render_template
from flask_login import current_user

__all__ = ["main_bp"]

main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def index():
    template = "placeholder_home.html" if current_user.is_authenticated else "landing.html"
    return render_template(template)
