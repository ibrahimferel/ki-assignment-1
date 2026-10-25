"""A small request-body limit for the login and registration pages.

``MAX_CONTENT_LENGTH`` (50 MB by default, for file uploads) applies to the
whole application. The ``auth`` forms only carry a few short fields, so for
them the limit is 16 KiB: a bigger request is answered with the standard
413 page. The limit is set per request, before Flask reads any form data
(``url_value_preprocessor`` runs before every ``before_request`` function,
including the CSRF check), so nothing big is parsed, checked or hashed.

* The effective limit is the smaller of ``MAX_CONTENT_LENGTH`` and 16 KiB.
  If ``MAX_CONTENT_LENGTH`` is not set (``None``) the limit is 16 KiB.
* It holds for every method of the ``auth`` blueprint. A GET or HEAD does not
  read its body, so it is not affected.
* A 413 is answered before the throttle, the password check and the CSRF
  check run, so it is never counted as a login attempt (and a client that is
  blocked by the throttle still gets 413 for an oversized request). It is
  also not rate limited itself.
* The 413 page is the standard one, the same for every route; the security
  headers are added to it like to any other answer.
* Limit of the web server, not of this module: a request without a
  ``Content-Length`` (chunked) is not refused. The Werkzeug development
  server cuts a chunked urlencoded body at the limit instead of answering
  413. See docs/auth-integration.md.

This module never logs and never prints.
"""

from flask import request

__all__ = ["AUTH_MAX_BODY_BYTES", "register_auth_body_limit"]

AUTH_MAX_BODY_BYTES = 16 * 1024
_AUTH_BLUEPRINT = "auth"


def register_auth_body_limit(app):
    """Limit the body of every request to the ``auth`` blueprint."""

    @app.url_value_preprocessor
    def _limit_auth_body(endpoint, values):
        if request.blueprint != _AUTH_BLUEPRINT:
            return
        current = request.max_content_length
        if current is None or current > AUTH_MAX_BODY_BYTES:
            request.max_content_length = AUTH_MAX_BODY_BYTES

    return app
