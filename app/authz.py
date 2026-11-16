"""Ownership checks for data that belongs to a user.

Use these helpers in every route that reads, changes or lists a user's
data (see docs/auth-integration.md):

* ``get_owned_or_404(StoredFile, file_id)`` returns the row, or answers 404.
* ``owned_select(StoredFile)`` is the starting point for list pages.

For the requester side of a sharing request (Assignment 2) there are two
twins that filter ``requester_id`` instead of ``owner_id``:

* ``get_requested_or_404(AccessRequest, request_id)``
* ``requested_select(AccessRequest)``

Rules built into all four helpers:

* The owner is always ``current_user``. It can not be passed in, so a route
  can not check the wrong user by mistake and a request can not choose it.
* The check is part of the SQL (``WHERE id = :id AND owner_id = :owner``).
  Another user's row is never loaded, and "does not exist" and "belongs to
  someone else" take exactly the same path and give exactly the same answer:
  the plain 404 page, with nothing about the id or the owner in it.
* An anonymous visitor gets 401 before anything else, and before the id is
  looked at, so the answer says nothing about the data. Routes still need
  ``@login_required`` (the inventory test in test_security_inventory.py fails
  for a route without it).
* An id that is not a plain ``int`` in the range SQLite can store answers 404
  (a huge number would otherwise make SQLite raise and give a 500).
* Only models with a direct ``owner_id`` column are accepted. A model
  without one (``CipherCopy``) raises ``TypeError``: reach it through its
  owner, for example ``stored.copies``. The two ``requested`` helpers need a
  ``requester_id`` column in the same way (only ``AccessRequest`` has one).
* The requested helpers check WHO asked, nothing else: they also return a
  pending or rejected request. What the requester may then see (for example
  only an approved and unlocked request) is up to the caller.

This module never logs and never prints.
"""

from flask import abort
from flask_login import current_user
from sqlalchemy import select
from sqlalchemy.orm.attributes import InstrumentedAttribute

from app.extensions import db

__all__ = [
    "get_owned_or_404",
    "get_requested_or_404",
    "owned_select",
    "requested_select",
]

# The largest id SQLite can store.
MAX_ID = 2**63 - 1


def _owner_column(model):
    """The ``owner_id`` column of ``model``; ``TypeError`` if it has none."""
    column = getattr(model, "owner_id", None)
    if not isinstance(column, InstrumentedAttribute):
        name = getattr(model, "__name__", repr(model))
        raise TypeError(
            f"{name} has no owner_id column; reach it through its owner"
        )
    return column


def _requester_column(model):
    """The ``requester_id`` column of ``model``; ``TypeError`` if none."""
    column = getattr(model, "requester_id", None)
    if not isinstance(column, InstrumentedAttribute):
        name = getattr(model, "__name__", repr(model))
        raise TypeError(
            f"{name} has no requester_id column; reach it through the "
            "request it belongs to"
        )
    return column


def _current_owner_id():
    """The id of the logged-in user; anonymous visitors get a 401.

    The name is historical: the requested helpers use it too.
    """
    if not current_user.is_authenticated:
        abort(401)
    return current_user.id


def get_owned_or_404(model, object_id, *, options=()):
    """The ``model`` row with this id that belongs to the current user.

    Answers 404 (the same page for every reason) when there is no such row,
    when it belongs to someone else, or when ``object_id`` is not a plain
    ``int`` between 1 and 2**63 - 1. ``options`` are SQLAlchemy loader
    options, for example ``selectinload(StoredFile.copies)``.
    """
    column = _owner_column(model)
    owner_id = _current_owner_id()
    if (
        isinstance(object_id, bool)
        or not isinstance(object_id, int)
        or not 1 <= object_id <= MAX_ID
    ):
        abort(404)
    statement = select(model).where(model.id == object_id, column == owner_id)
    if options:
        statement = statement.options(*options)
    found = db.session.execute(statement).scalars().first()
    if found is None:
        abort(404)
    return found


def owned_select(model):
    """``select(model)`` limited to the current user's rows (list pages)."""
    column = _owner_column(model)
    return select(model).where(column == _current_owner_id())


def get_requested_or_404(model, object_id, *, options=()):
    """The ``model`` row with this id that the current user requested.

    The twin of ``get_owned_or_404`` with exactly the same rules, except that
    the row must have ``requester_id`` equal to the current user (for example
    the access requests this user made). Answers 404 (the same page for every
    reason) when there is no such row, when it was made by someone else
    (including the owner of the data), or when ``object_id`` is not a plain
    ``int`` between 1 and 2**63 - 1.
    """
    column = _requester_column(model)
    requester_id = _current_owner_id()
    if (
        isinstance(object_id, bool)
        or not isinstance(object_id, int)
        or not 1 <= object_id <= MAX_ID
    ):
        abort(404)
    statement = select(model).where(
        model.id == object_id, column == requester_id
    )
    if options:
        statement = statement.options(*options)
    found = db.session.execute(statement).scalars().first()
    if found is None:
        abort(404)
    return found


def requested_select(model):
    """``select(model)`` limited to the rows the current user requested."""
    column = _requester_column(model)
    return select(model).where(column == _current_owner_id())
