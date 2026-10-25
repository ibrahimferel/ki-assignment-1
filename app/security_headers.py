"""Security headers for every response.

One ``after_request`` hook runs for every kind of answer: pages, redirects,
errors (400, 404, 405, 413, 429, 500) and static files.

Always set, and overwritten if a route tries to change them:

* ``X-Content-Type-Options: nosniff``: the browser must not guess types.
* ``X-Frame-Options: DENY``: no framing (clickjacking).
* ``Referrer-Policy: no-referrer``: no address is sent to other sites.
* ``Permissions-Policy``: camera, microphone, location, payment and USB off.
* ``Cross-Origin-Opener-Policy`` and ``Cross-Origin-Resource-Policy``:
  ``same-origin``.
* ``Cache-Control: no-store`` on every answer except static files. A route
  can not choose its own caching (``private, max-age=60`` is overwritten),
  and Flask's ``send_file``, which sets ``no-cache`` itself, is overwritten
  too, so code that sends user data does not have to remember anything.

Set only if the route did not set it (a route may make it STRICTER; it
must not loosen it, see docs/auth-integration.md; the code can not tell a
stricter value from a looser one, so this is a rule of the document):

* ``Content-Security-Policy``: everything from this site only, no inline
  script or style, no framing, no plug-ins, no ``<base>``, forms post to this
  site only. A route that serves user content may add ``sandbox``.

Only when the session cookie is ``Secure`` (the site is served over HTTPS):

* ``Strict-Transport-Security: max-age=31536000``, without
  ``includeSubDomains`` and without ``preload``. Over plain http browsers
  ignore it, and a development setup must not be pinned to HTTPS.

Left out on purpose: ``X-XSS-Protection`` (obsolete and itself a risk in old
browsers) and ``Cross-Origin-Embedder-Policy`` (it can break resources).

Not controlled here: the ``Server`` header of the development server.
This module never logs and never prints.
"""

from flask import request

__all__ = [
    "CONTENT_SECURITY_POLICY",
    "FORCED_HEADERS",
    "HSTS_VALUE",
    "register_security_headers",
]

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'; object-src 'none'"
)

FORCED_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

HSTS_VALUE = "max-age=31536000"


def register_security_headers(app):
    """Add the headers above to every response of ``app``."""

    @app.after_request
    def _add_security_headers(response):
        for name, value in FORCED_HEADERS.items():
            response.headers[name] = value
        response.headers.setdefault(
            "Content-Security-Policy", CONTENT_SECURITY_POLICY
        )
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        # Read now, not when the app was created: it is the same setting
        # Flask uses for the cookie, at the same moment.
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = HSTS_VALUE
        return response

    return app
