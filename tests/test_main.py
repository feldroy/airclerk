from unittest.mock import patch

import air
from airclerk.main import router, sanitize_next
from starlette.testclient import TestClient


def test_check():
    assert 1 == 1


class TestSanitizeNext:
    """Test suite for sanitize_next function to prevent open-redirect vulnerabilities."""

    def test_valid_absolute_path(self):
        assert sanitize_next("/protected") == "/protected"

    def test_valid_path_with_query(self):
        assert sanitize_next("/a/b?x=1") == "/a/b?x=1"

    def test_valid_path_with_hash(self):
        assert sanitize_next("/page#section") == "/page#section"

    def test_valid_path_with_query_and_hash(self):
        assert sanitize_next("/a/b?x=1#h") == "/a/b?x=1#h"

    def test_valid_root_path(self):
        assert sanitize_next("/") == "/"

    def test_invalid_full_url_https(self):
        assert sanitize_next("https://example.com") == "/"

    def test_invalid_full_url_http(self):
        assert sanitize_next("http://example.com") == "/"

    def test_invalid_protocol_relative(self):
        assert sanitize_next("//example.com") == "/"

    def test_invalid_javascript_uri(self):
        assert sanitize_next("javascript:alert(1)") == "/"

    def test_invalid_empty_string(self):
        assert sanitize_next("") == "/"

    def test_invalid_whitespace_only(self):
        assert sanitize_next("   ") == "/"

    def test_invalid_relative_path(self):
        assert sanitize_next("relative/path") == "/"

    def test_whitespace_stripped(self):
        assert sanitize_next("  /protected  ") == "/protected"

    def test_custom_default(self):
        assert sanitize_next("invalid", default="/home") == "/home"

    def test_case_insensitive_protocol_check(self):
        assert sanitize_next("HTTPS://example.com") == "/"
        assert sanitize_next("JavaScript:alert(1)") == "/"


class _UnauthenticatedState:
    is_signed_in = False


class _FakeClerk:
    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def authenticate_request(self, *args, **kwargs):
        return _UnauthenticatedState()


def test_login_uses_force_redirect_url_for_explicit_next():
    app = air.Air()
    app.include_router(router)

    with patch("airclerk.main.Clerk", _FakeClerk):
        with TestClient(app) as client:
            response = client.get("/login?next=/protected")

    assert response.status_code == 200
    assert "forceRedirectUrl: '/protected'" in response.text
    assert "{ redirectUrl:" not in response.text


def test_logout_keeps_redirect_url_for_sign_out():
    app = air.Air()
    app.include_router(router)

    with TestClient(app) as client:
        response = client.post("/logout")

    assert response.status_code == 200
    assert "signOut({ redirectUrl: '/' })" in response.text
    assert "forceRedirectUrl" not in response.text
