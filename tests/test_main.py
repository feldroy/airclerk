from airclerk.main import sanitize_next


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
