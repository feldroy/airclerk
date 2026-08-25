from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import air
import airclerk
from airclerk.main import sanitize_next
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


class _AuthenticatedState:
    is_signed_in = True
    payload = {
        "sub": "user_123",
        "sid": "session_123",
        "org_id": "org_123",
        "org_role": "org:member",
    }


class _FakeUsers:
    def __init__(self):
        self.calls = []

    def get(self, *, user_id):
        self.calls.append(user_id)
        return type("FakeUser", (), {"id": user_id, "name": "Full profile"})()


class _FakeClerk:
    instances = []

    def __init__(self, **kwargs):
        self.users = _FakeUsers()
        self.auth_calls = 0
        self.auth_options = []
        self.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def authenticate_request(self, *args, **kwargs):
        self.auth_calls += 1
        self.auth_options.append(args[1])
        return _AuthenticatedState()


class _UnauthenticatedFakeClerk(_FakeClerk):
    def authenticate_request(self, *args, **kwargs):
        return _UnauthenticatedState()


def test_claims_dependency_redirects_unauthenticated_requests():
    app = air.Air()

    @app.page
    def protected(claims=airclerk.require_auth_claims):
        return air.P(claims["sub"])

    with patch("airclerk.main.Clerk", _UnauthenticatedFakeClerk):
        with TestClient(app) as client:
            response = client.get("/protected?a=1&b=2", follow_redirects=False)

    assert response.status_code == 303
    location = response.headers["location"]
    assert parse_qs(urlparse(location).query)["next"] == ["/protected?a=1&b=2"]


def test_claims_dependency_does_not_fetch_full_user():
    _FakeClerk.instances.clear()
    app = air.Air()

    @app.page
    def protected(claims=airclerk.require_auth_claims):
        return air.P(claims["sub"])

    with patch("airclerk.main.Clerk", _FakeClerk):
        with TestClient(app) as client:
            response = client.get("/protected", headers={"cookie": "__session=token"})

    assert response.status_code == 200
    assert "user_123" in response.text
    assert all(not clerk.users.calls for clerk in _FakeClerk.instances)
    assert all(
        option.accepts_token == ["session_token"]
        for clerk in _FakeClerk.instances
        for option in clerk.auth_options
    )


def test_full_user_dependency_fetches_profile_on_request():
    _FakeClerk.instances.clear()
    app = air.Air()

    @app.page
    def protected(user=airclerk.require_user):
        return air.P(user.name)

    with patch("airclerk.main.Clerk", _FakeClerk):
        with TestClient(app) as client:
            response = client.get("/protected", headers={"cookie": "__session=token"})

    assert response.status_code == 200
    assert "Full profile" in response.text
    calls = [user_id for clerk in _FakeClerk.instances for user_id in clerk.users.calls]
    assert calls == ["user_123"]


def test_optional_claims_dependency_returns_none_without_authentication():
    app = air.Air()

    @app.page
    def optional(claims=airclerk.optional_auth_claims):
        return air.P("signed out" if claims is None else "signed in")

    with patch("airclerk.main.Clerk", _UnauthenticatedFakeClerk):
        with TestClient(app) as client:
            response = client.get("/optional")

    assert response.status_code == 200
    assert "signed out" in response.text


def test_optional_dependencies_fetch_only_when_full_user_is_requested():
    _FakeClerk.instances.clear()
    app = air.Air()

    @app.page
    def claims(claims=airclerk.optional_auth_claims):
        return air.P(claims["sub"])

    @app.page
    def user(user=airclerk.optional_user):
        return air.P(user.name)

    with patch("airclerk.main.Clerk", _FakeClerk):
        with TestClient(app) as client:
            claims_response = client.get(
                "/claims", headers={"cookie": "__session=token"}
            )
            user_response = client.get("/user", headers={"cookie": "__session=token"})

    assert claims_response.status_code == 200
    assert "user_123" in claims_response.text
    assert user_response.status_code == 200
    assert "Full profile" in user_response.text
    calls = [user_id for clerk in _FakeClerk.instances for user_id in clerk.users.calls]
    assert calls == ["user_123"]


def test_required_dependencies_reuse_authentication():
    _FakeClerk.instances.clear()
    app = air.Air()

    @app.page
    def profile(claims=airclerk.require_auth_claims, user=airclerk.require_user):
        return air.P(claims["sub"], user.name)

    with patch("airclerk.main.Clerk", _FakeClerk):
        with TestClient(app) as client:
            response = client.get("/profile", headers={"cookie": "__session=token"})

    assert response.status_code == 200
    assert "user_123" in response.text
    assert "Full profile" in response.text
    assert sum(clerk.auth_calls for clerk in _FakeClerk.instances) == 1


def test_optional_dependencies_reuse_authentication():
    _FakeClerk.instances.clear()
    app = air.Air()

    @app.page
    def profile(
        claims=airclerk.optional_auth_claims,
        user=airclerk.optional_user,
    ):
        return air.P(claims["sub"], user.name)

    with patch("airclerk.main.Clerk", _FakeClerk):
        with TestClient(app) as client:
            response = client.get("/profile", headers={"cookie": "__session=token"})

    assert response.status_code == 200
    assert "user_123" in response.text
    assert "Full profile" in response.text
    assert sum(clerk.auth_calls for clerk in _FakeClerk.instances) == 1
