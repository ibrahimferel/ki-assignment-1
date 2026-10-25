"""TEMPORARY home page at "/".

It exists only so that login and logout have somewhere to go. The team
member who builds the real pages replaces this module: register a blueprint
named "main" with an ``index`` endpoint and remove ``main_bp`` from
``create_app``.
"""

from flask import Blueprint, render_template

__all__ = ["main_bp"]

main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def index():
    return render_template("placeholder_home.html")
