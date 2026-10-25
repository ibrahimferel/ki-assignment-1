"""Tests for app/security_headers.py.

Every kind of answer is requested (pages, redirects, errors, static files)
and each one must carry the headers. The templates of the repository are
scanned too: the Content-Security-Policy blocks inline script and style, so a
template that uses them would simply stop working in a browser. What a
browser really does with the policy can not be tested here; that part is
the manual checklist in docs/auth-integration.md.
"""

import ast
import inspect
import io
import re
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from flask import abort, make_response, redirect, send_file
from flask_login import login_required

import app as app_package
from app import security_headers
from app.auth import services
from app.security_headers import (
    CONTENT_SECURITY_POLICY,
    FORCED_HEADERS,
    HSTS_VALUE,
)

GOOD = "correct horse battery"
TOKEN_PATTERN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
TEMPLATES = Path(app_package.__file__).parent / "templates"

FORCED = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
CSP = (
    "default-src 'self'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'; object-src 'none'"
)
SECURITY_NAMES = list(FORCED) + [
    "Content-Security-Policy",
    "Cache-Control",
    "Strict-Transport-Security",
]


@pytest.fixture(autouse=True)
def cheap_hasher(monkeypatch):
    """Fast Argon2 for the whole module; a fresh dummy hash every test."""
    cheap = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    monkeypatch.setattr(services, "_HASHER", cheap)
    monkeypatch.setattr(services, "_dummy", None)


@pytest.fixture()
def site(web, tmp_path):
    """The ``web`` app with synthetic routes and a real static file."""
    static = tmp_path / "static"
    static.mkdir()
    (static / "x.css").write_text("body { margin: 0 }")
    web.static_folder = str(static)
    web.config["PROPAGATE_EXCEPTIONS"] = False
    web.config["MAX_CONTENT_LENGTH"] = 2048

    @web.get("/t/ok")
    def t_ok():
        return "ok"

    @web.get("/t/redirect")
    def t_redirect():
        return redirect("/t/ok")

    @web.get("/t/unauthorized")
    def t_unauthorized():
        abort(401)

    @web.get("/t/boom")
    def t_boom():
        raise RuntimeError("boom")

    @web.get("/t/protected")
    @login_required
    def t_protected():
        return "members only"

    @web.get("/t/private-cache")
    def t_private_cache():
        response = make_response("cached")
        response.headers["Cache-Control"] = "private, max-age=60"
        return response

    @web.get("/t/public-cache")
    def t_public_cache():
        response = make_response("public")
        response.headers["Cache-Control"] = "public, max-age=31536000"
        return response

    @web.get("/t/etag-cache")
    def t_etag_cache():
        response = make_response("etag")
        response.cache_control.max_age = 600
        response.add_etag()
        return response

    @web.get("/t/send-file-path")
    def t_send_file_path():
        return send_file(
            Path(web.static_folder) / "x.css", conditional=True, max_age=3600
        )

    @web.get("/t/stricter-csp")
    def t_stricter_csp():
        response = make_response("sandboxed")
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; sandbox"
        )
        return response

    @web.get("/t/weaken")
    def t_weaken():
        response = make_response("weak")
        response.headers["X-Content-Type-Options"] = "sniff"
        response.headers["X-Frame-Options"] = "ALLOWALL"
        response.headers["Referrer-Policy"] = "unsafe-url"
        response.headers["Permissions-Policy"] = "camera=*"
        response.headers["Cross-Origin-Opener-Policy"] = "unsafe-none"
        response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
        return response

    @web.get("/t/weak-hsts")
    def t_weak_hsts():
        response = make_response("weak hsts")
        response.headers["Strict-Transport-Security"] = "max-age=0"
        return response

    @web.get("/t/send-file")
    def t_send_file():
        return send_file(
            io.BytesIO(b"plain"), download_name="a.txt", as_attachment=True
        )

    with web.app_context():
        services.register_user("alice", GOOD)
    return web


def token_for(client):
    for path in ("/auth/login", "/"):
        found = TOKEN_PATTERN.search(client.get(path).get_data(as_text=True))
        if found:
            return found.group(1)
    raise AssertionError("no CSRF token")


def login_post(client, password, token=True):
    data = {"username": "alice", "password": password}
    if token:
        data["csrf_token"] = token_for(client)
    return client.post("/auth/login", data=data)


def every_answer(site):
    """One response of each kind, by label."""
    client = site.test_client()
    answers = {
        "200 page": client.get("/t/ok"),
        "200 login page": client.get("/auth/login"),
        "200 home": client.get("/"),
        "302 redirect": client.get("/t/redirect"),
        "302 login required": client.get("/t/protected"),
        "401": client.get("/t/unauthorized"),
        "400 no token": login_post(client, GOOD, token=False),
        "404": client.get("/t/no-such-page"),
        "405": client.get("/auth/logout"),
        "413": client.post(
            "/auth/login",
            data={"username": "a", "password": "x" * 5000},
        ),
        "500": client.get("/t/boom"),
        "200 static": client.get("/static/x.css"),
        "404 static": client.get("/static/missing.css"),
        "OPTIONS": client.options("/t/ok"),
        "HEAD": client.head("/t/ok"),
    }
    throttled = site.test_client()
    for _ in range(5):
        login_post(throttled, "wrong password!")
    answers["429"] = login_post(throttled, "wrong password!")
    for response in answers.values():
        response.get_data()
        response.close()  # file bodies must be closed (-W error)
    return answers


@pytest.fixture()
def answers(site):
    found = every_answer(site)
    assert {r.status_code for r in found.values()} >= {
        200, 302, 400, 401, 404, 405, 413, 429, 500,
    }
    return found


# ---------------------------------------------------------- the forced ones


def test_every_answer_carries_the_forced_headers(answers):
    wrong = [
        f"{label}: {name}={response.headers.get(name)!r}"
        for label, response in answers.items()
        for name, value in FORCED.items()
        if response.headers.get(name) != value
    ]
    assert wrong == []


def test_the_module_and_this_file_agree_on_the_values():
    assert FORCED_HEADERS == FORCED
    assert CONTENT_SECURITY_POLICY == CSP
    assert HSTS_VALUE == "max-age=31536000"


def test_a_route_can_not_weaken_a_forced_header(site):
    response = site.test_client().get("/t/weaken")
    assert response.status_code == 200
    for name, value in FORCED.items():
        assert response.headers.getlist(name) == [value], name


def test_each_header_appears_once(answers):
    repeated = [
        f"{label}: {name}"
        for label, response in answers.items()
        for name in SECURITY_NAMES
        if len(response.headers.getlist(name)) > 1
    ]
    assert repeated == []


def test_obsolete_or_risky_headers_are_not_sent(answers):
    sent = [
        f"{label}: {name}"
        for label, response in answers.items()
        for name in ("X-XSS-Protection", "Cross-Origin-Embedder-Policy")
        if name in response.headers
    ]
    assert sent == []


# --------------------------------------------------------------- the policy


def directives(policy):
    found = {}
    for part in policy.split(";"):
        words = part.split()
        if words:
            found[words[0]] = words[1:]
    return found


def test_every_answer_has_the_policy(answers):
    wrong = [
        label
        for label, response in answers.items()
        if response.headers.get("Content-Security-Policy") != CSP
    ]
    assert wrong == []


def test_the_policy_is_strict():
    assert directives(CSP) == {
        "default-src": ["'self'"],
        "base-uri": ["'none'"],
        "form-action": ["'self'"],
        "frame-ancestors": ["'none'"],
        "object-src": ["'none'"],
    }
    for loose in ("unsafe-inline", "unsafe-eval", "*", "data:", "blob:",
                  "http:", "https:"):
        assert loose not in CSP


def test_a_route_may_make_the_policy_stricter(site):
    response = site.test_client().get("/t/stricter-csp")
    assert response.headers.getlist("Content-Security-Policy") == [
        "default-src 'none'; sandbox"
    ]


# -------------------------------------------------------------- the caching


def test_everything_but_static_files_is_no_store(answers):
    wrong = [
        f"{label}: {response.headers.get('Cache-Control')!r}"
        for label, response in answers.items()
        if "static" not in label
        and response.headers.get("Cache-Control") != "no-store"
    ]
    assert wrong == []


def test_static_files_are_served_with_headers_but_not_no_store(answers):
    response = answers["200 static"]
    assert response.status_code == 200
    assert "no-store" not in response.headers.get("Cache-Control", "")
    assert response.headers["Content-Security-Policy"] == CSP
    assert answers["404 static"].status_code == 404
    assert "no-store" not in answers["404 static"].headers.get(
        "Cache-Control", ""
    )


CACHE_ROUTES = ["/t/private-cache", "/t/public-cache", "/t/etag-cache",
                "/t/send-file", "/t/send-file-path"]


@pytest.mark.parametrize("path", CACHE_ROUTES)
def test_a_route_can_not_choose_its_own_cache_control(site, path):
    # private/public/max-age/ETag and send_file's own "no-cache" are all
    # replaced: the only value a non-static answer can have is no-store.
    response = site.test_client().get(path)
    response.get_data()
    response.close()
    assert response.status_code == 200
    assert response.headers.getlist("Cache-Control") == ["no-store"]


def test_a_conditional_answer_304_is_no_store_too(site):
    client = site.test_client()
    first = client.get("/t/send-file-path")
    first.get_data()
    first.close()
    second = client.get(
        "/t/send-file-path", headers={"If-None-Match": first.headers["ETag"]}
    )
    second.get_data()
    second.close()
    assert second.status_code == 304
    assert second.headers.getlist("Cache-Control") == ["no-store"]
    for name, value in FORCED.items():
        assert second.headers.get(name) == value, name


def test_send_file_alone_would_say_no_cache(site):
    # Why the rule above exists: without it send_file would win.
    with site.test_request_context():
        plain = send_file(io.BytesIO(b"plain"), download_name="a.txt")
        try:
            assert plain.headers.get("Cache-Control") == "no-cache"
        finally:
            plain.close()


def test_static_files_keep_the_cache_headers_of_flask(site):
    response = site.test_client().get("/static/x.css")
    response.get_data()
    response.close()
    assert response.headers.get("Cache-Control") == "no-cache"
    assert response.headers.get("ETag")


# --------------------------------------------------------------------- HSTS


def test_no_hsts_over_plain_http_settings(answers):
    assert [
        label
        for label, response in answers.items()
        if "Strict-Transport-Security" in response.headers
    ] == []


def test_hsts_with_a_secure_cookie_setting_on_every_answer(site):
    site.config["SESSION_COOKIE_SECURE"] = True
    client = site.test_client()
    for path in ("/t/ok", "/t/no-such-page", "/t/boom", "/static/x.css",
                 "/auth/login", "/auth/logout"):
        response = client.get(path)
        response.get_data()
        response.close()
        assert response.headers.getlist("Strict-Transport-Security") == [
            "max-age=31536000"
        ], path
    value = response.headers["Strict-Transport-Security"]
    assert "includeSubDomains" not in value and "preload" not in value


def test_a_route_can_not_weaken_hsts(site):
    site.config["SESSION_COOKIE_SECURE"] = True
    response = site.test_client().get("/t/weak-hsts")
    assert response.headers.getlist("Strict-Transport-Security") == [
        "max-age=31536000"
    ]


def test_hsts_follows_the_setting_at_the_moment_of_the_request(site):
    client = site.test_client()
    assert "Strict-Transport-Security" not in client.get("/t/ok").headers
    site.config["SESSION_COOKIE_SECURE"] = True
    assert "Strict-Transport-Security" in client.get("/t/ok").headers
    site.config["SESSION_COOKIE_SECURE"] = False
    assert "Strict-Transport-Security" not in client.get("/t/ok").headers


# ------------------------------------------------- templates and the policy

TAG = re.compile(r"<\s*([a-zA-Z][\w:-]*)([^<>]*)>")
ATTR = re.compile(
    r"([\w:@.-]+)(?:\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s\"'>]+))?"
)
RESOURCE_ATTRS = {
    "img": ("src", "srcset"),
    "iframe": ("src",),
    "frame": ("src",),
    "video": ("src", "poster"),
    "audio": ("src",),
    "source": ("src", "srcset"),
    "track": ("src",),
    "embed": ("src",),
    "object": ("data",),
    "input": ("src",),
}


def is_foreign(value):
    value = value.strip().strip("\"'").lower()
    return value.startswith(("http://", "https://", "//", "data:", "blob:"))


def csp_violations(html):
    """What in ``html`` the Content-Security-Policy would block."""
    found = []
    for name, raw in TAG.findall(html):
        name = name.lower()
        attrs = {}
        for key, value in ATTR.findall(raw):
            attrs[key.lower()] = value.strip("\"'") if value else ""
        if name == "script":
            if "src" not in attrs:
                found.append("inline <script>")
            elif is_foreign(attrs["src"]):
                found.append("script from another source")
        if name == "style":
            found.append("inline <style>")
        if name == "base":
            found.append("<base> element")
        if name == "link" and is_foreign(attrs.get("href", "")):
            found.append("link to another source")
        if name == "form" and is_foreign(attrs.get("action", "")):
            found.append("form posting to another site")
        for attr in RESOURCE_ATTRS.get(name, ()):
            if is_foreign(attrs.get(attr, "")):
                found.append(f"<{name} {attr}> from another source")
        if "style" in attrs:
            found.append("style attribute")
        for key in attrs:
            if re.fullmatch(r"on\w+", key):
                found.append(f"event handler {key}")
        for key in ("href", "src", "action", "formaction", "data"):
            if attrs.get(key, "").strip().lower().startswith("javascript:"):
                found.append("javascript: URL")
    if re.search(r"@import|url\(\s*[\"']?(https?:|//)", html):
        found.append("CSS import or url() to another source")
    return found


GOOD_SNIPPETS = [
    '<script src="/static/js/files.js"></script>',
    '<script src="{{ url_for(\'static\', filename=\'js/a.js\') }}"></script>',
    '<link rel="stylesheet" href="/static/css/app.css">',
    '<form method="post" action="/files/upload"></form>',
    '<img src="/files/1/download" alt="">',
    '<a href="https://example.org/">leaves the site</a>',
    '<p class="note">text</p>',
    "<video src=\"/files/2/download\" controls></video>",
]
BAD_SNIPPETS = {
    "inline <script>": "<script>alert(1)</script>",
    "script from another source": '<script src="https://cdn.example/a.js">'
                                  "</script>",
    "inline <style>": "<style>p { color: red }</style>",
    "style attribute": '<p style="color: red">x</p>',
    "event handler onclick": '<button onclick="go()">x</button>',
    "event handler onerror": '<img src="/a.png" onerror="x()">',
    "javascript: URL": '<a href="javascript:void(0)">x</a>',
    "link to another source": '<link rel="stylesheet" '
                              'href="//fonts.example/css">',
    "form posting to another site": '<form action="https://evil.example/">'
                                    "</form>",
    "<img src> from another source": '<img src="data:image/png;base64,AA==">',
    "<video src> from another source": '<video src="blob:abc"></video>',
    "<iframe src> from another source": '<iframe src="http://x.example/">'
                                        "</iframe>",
    "<base> element": '<base href="/">',
    "CSS import or url() to another source": "@import 'a.css';",
}


@pytest.mark.parametrize("snippet", GOOD_SNIPPETS)
def test_the_scanner_accepts_what_the_policy_allows(snippet):
    assert csp_violations(snippet) == []


@pytest.mark.parametrize(
    "expected, snippet", sorted(BAD_SNIPPETS.items()), ids=lambda v: v[:30]
)
def test_the_scanner_finds_what_the_policy_blocks(expected, snippet):
    assert expected in csp_violations(snippet)


def test_every_template_in_the_repository_works_with_the_policy():
    files = sorted(TEMPLATES.rglob("*.html"))
    assert files, "no templates found"
    found = {
        str(path.relative_to(TEMPLATES)): csp_violations(path.read_text())
        for path in files
    }
    assert {k: v for k, v in found.items() if v} == {}


def test_the_pages_as_rendered_work_with_the_policy(site):
    anonymous = site.test_client()
    pages = {
        "login": anonymous.get("/auth/login"),
        "register": anonymous.get("/auth/register"),
        "home (visitor)": anonymous.get("/"),
        "login failed": login_post(anonymous, "wrong password!"),
    }
    member = site.test_client()
    assert login_post(member, GOOD).status_code == 302
    pages["home (member)"] = member.get("/")
    pages["404"] = member.get("/t/no-such-page")
    for label, response in pages.items():
        assert response.get_data(as_text=True)
        assert csp_violations(response.get_data(as_text=True)) == [], label


# --------------------------------------------------------- the module itself

MODULE_TREE = ast.parse(Path(security_headers.__file__).read_text())


def test_the_module_imports_only_flask_and_never_logs_or_prints():
    modules = set()
    for node in ast.walk(MODULE_TREE):
        if isinstance(node, ast.ImportFrom):
            modules.add(node.module)
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
    assert modules == {"flask"}
    names = {n.id for n in ast.walk(MODULE_TREE) if isinstance(n, ast.Name)}
    assert not names & {"print", "logging", "logger", "session"}


def test_create_app_registers_the_headers_exactly_once():
    source = inspect.getsource(app_package.create_app)
    assert source.count("register_security_headers(app)") == 1
    assert source.count("import register_security_headers") == 1


def test_the_public_names():
    assert security_headers.__all__ == [
        "CONTENT_SECURITY_POLICY",
        "FORCED_HEADERS",
        "HSTS_VALUE",
        "register_security_headers",
    ]
