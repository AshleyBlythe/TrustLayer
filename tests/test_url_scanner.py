"""Tests for trustlayer URL scanner."""

import unittest
from unittest.mock import MagicMock, patch
from trustlayer.url_scanner import _same_origin, _normalise_url, scan_url


class TestSameOrigin(unittest.TestCase):
    def test_same_scheme_host(self):
        self.assertTrue(_same_origin("https://example.com/a", "https://example.com/b"))

    def test_different_host(self):
        self.assertFalse(_same_origin("https://example.com", "https://other.com"))

    def test_different_scheme(self):
        self.assertFalse(_same_origin("https://example.com", "http://example.com"))

    def test_subdomain_is_different(self):
        self.assertFalse(_same_origin("https://example.com", "https://api.example.com"))


class TestNormaliseUrl(unittest.TestCase):
    def test_relative_path(self):
        result = _normalise_url("https://example.com/page", "/about")
        self.assertEqual(result, "https://example.com/about")

    def test_strips_fragment(self):
        result = _normalise_url("https://example.com/", "/page#section")
        self.assertEqual(result, "https://example.com/page")

    def test_javascript_scheme_rejected(self):
        result = _normalise_url("https://example.com/", "javascript:void(0)")
        self.assertIsNone(result)

    def test_mailto_rejected(self):
        result = _normalise_url("https://example.com/", "mailto:user@example.com")
        self.assertIsNone(result)


class TestCrossOriginRedirect(unittest.TestCase):
    def _make_mock_response(self, final_url, body=b"<html></html>",
                             headers=None, status=200):
        mock_resp = MagicMock()
        mock_resp.geturl.return_value = final_url
        mock_resp.read.return_value = body
        mock_resp.headers = MagicMock()
        mock_resp.headers.get.return_value = "text/html"
        mock_resp.headers.__iter__ = MagicMock(return_value=iter([]))
        if headers:
            mock_resp.headers.get.side_effect = lambda k, d="": headers.get(k.lower(), d)
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    def test_cross_origin_redirect_noted(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_resp = self._make_mock_response("https://other.com/page")
            mock_open.return_value = mock_resp
            result = scan_url("https://example.com")
        redirect_findings = [f for f in result.findings if f.check_id == "URL-001"]
        self.assertTrue(len(redirect_findings) >= 1)

    def test_cross_origin_not_followed(self):
        with patch("urllib.request.urlopen") as mock_open:
            mock_resp = self._make_mock_response("https://other.com/page")
            mock_open.return_value = mock_resp
            result = scan_url("https://example.com")
        # Should only have crawled 1 URL (the redirect target is different origin)
        self.assertEqual(result.scanned_urls, 1)


class TestMalformedOversizedResponse(unittest.TestCase):
    def test_oversized_response_truncated(self):
        large_body = b"A" * (1024 * 1024 + 100)
        mock_resp = MagicMock()
        mock_resp.geturl.return_value = "https://example.com/"
        mock_resp.read.return_value = large_body
        mock_resp.headers = MagicMock()
        mock_resp.headers.get.return_value = "text/html"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = scan_url("https://example.com/")
        self.assertTrue(any("truncated" in e for e in result.errors))

    def test_http_error_recorded(self):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
            "https://example.com/404", 404, "Not Found", {}, None
        )):
            result = scan_url("https://example.com/404")
        self.assertTrue(any("404" in e for e in result.errors))

    def test_url_error_recorded(self):
        import urllib.error
        with patch("urllib.request.urlopen",
                   side_effect=urllib.error.URLError("connection refused")):
            result = scan_url("https://unreachable.invalid/")
        self.assertTrue(any("URL error" in e for e in result.errors))


if __name__ == "__main__":
    unittest.main()
