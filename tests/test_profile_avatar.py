"""Profile photo: the signed-in user can set/clear their own avatar; the
endpoint strictly validates the image data URI (type, base64, size) and the
stored value renders back in the UI chrome."""

import base64

# 1x1 transparent PNG
PNG = ("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAA"
       "C0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


def test_set_and_render_avatar(login):
    c, _ = login("owner@example.com")
    r = c.post("/ui/profile/avatar", data={"data": PNG}, follow_redirects=False)
    assert r.status_code == 303, r.text
    # It renders into the chrome (background-image on the avatar span).
    page = c.get("/ui/agents").text
    assert PNG in page


def test_remove_avatar(login):
    c, _ = login("owner@example.com")
    c.post("/ui/profile/avatar", data={"data": PNG}, follow_redirects=False)
    r = c.post("/ui/profile/avatar", data={"data": ""}, follow_redirects=False)
    assert r.status_code == 303
    assert PNG not in c.get("/ui/agents").text


def test_rejects_non_image(login):
    c, _ = login("owner@example.com")
    # not a data URI
    assert c.post("/ui/profile/avatar", data={"data": "hello"},
                  follow_redirects=False).status_code == 422
    # svg is deliberately excluded (script vector), not in the allowlist
    svg = "data:image/svg+xml;base64," + base64.b64encode(b"<svg/>").decode()
    assert c.post("/ui/profile/avatar", data={"data": svg},
                  follow_redirects=False).status_code == 422


def test_rejects_oversized(login):
    c, _ = login("owner@example.com")
    big = "data:image/png;base64," + base64.b64encode(b"\x89PNG" + b"A" * 300_000).decode()
    assert c.post("/ui/profile/avatar", data={"data": big},
                  follow_redirects=False).status_code == 413


def test_requires_login(client):
    # No session -> ui_actor bounces to /login (303 with Location).
    r = client.post("/ui/profile/avatar", data={"data": PNG}, follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "/login" in r.headers.get("location", "")
