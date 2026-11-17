"""The /sharing page (Assignment 2, Member 4): the HTML shell for sharing.js.

The page itself carries no data; the JSON API is tested in
``test_sharing_routes.py``. These tests check what the browser code relies
on: login is required, the CSRF token is on the page, and the page follows
the content security policy (no inline script or style).
"""

import re

from sharing_fixtures import TOKEN_PATTERN


def test_sharing_page_requires_login(web):
    response = web.test_client().get("/sharing")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_sharing_page_has_what_sharing_js_needs(web_trio, web, login_as):
    client = web.test_client()
    login_as(client, web_trio.a)
    response = client.get("/sharing")
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    # sharing.js reads the CSRF token from this input.
    assert TOKEN_PATTERN.search(html)
    # The data attributes sharing.js uses to find the API.
    assert 'data-requests-url="/sharing/requests"' in html
    assert 'data-records-url="/storage/"' in html
    assert "/static/js/sharing.js" in html
    assert "/static/css/sharing.css" in html


def test_sharing_page_has_no_inline_script_or_style(web_trio, web, login_as):
    client = web.test_client()
    login_as(client, web_trio.a)
    html = client.get("/sharing").get_data(as_text=True)
    # Every <script> must load a file and have no code between its tags.
    for attributes, body in re.findall(r"<script([^>]*)>(.*?)</script>", html, re.S):
        assert "src=" in attributes
        assert not body.strip()
    assert not re.search(r"\sstyle=", html)
    assert not re.search(r"\son[a-z]+=", html)


def test_vault_page_links_to_sharing(web_trio, web, login_as):
    client = web.test_client()
    login_as(client, web_trio.a)
    assert 'href="/sharing"' in client.get("/").get_data(as_text=True)
