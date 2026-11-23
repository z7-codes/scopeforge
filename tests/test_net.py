import unittest
import urllib.request
from unittest.mock import patch

from scopeforge import __version__, net
from scopeforge.budget import Budget
from scopeforge.errors import ScopeError
from scopeforge.models import Scope


def _response(url: str, status: int, location: str = "") -> net.Response:
    headers = {"Location": location} if location else {}
    return net.Response(url, status, headers, b"ok", 0.1)


class FakeResponse:
    status = 200
    headers = {"Content-Type": "text/plain"}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size):
        return b"x" * size


class NetTests(unittest.TestCase):
    def test_single_gate_calls_fetch_once(self):
        session = net.Session(budget=Budget(delay=0), scope=Scope("t", ["example.com"]))
        with patch("scopeforge.net.fetch", return_value=net.Response("u", 200, {}, b"ok", 0.1)) as mocked:
            session.get("https://example.com/a")
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(session.budget.sent, 1)

    def test_session_headers_reach_fetch(self):
        session = net.Session(
            budget=Budget(delay=0),
            scope=Scope("t", ["example.com"]),
            headers={"Cookie": "a=b"},
        )
        with patch("scopeforge.net.fetch", return_value=net.Response("u", 200, {}, b"ok", 0.1)) as mocked:
            session.get("https://example.com/a")
        self.assertEqual(mocked.call_args.args[3], {"Cookie": "a=b"})

    def test_scope_is_checked_before_fetch(self):
        session = net.Session(budget=Budget(delay=0), scope=Scope("t", ["example.com"]))
        with patch("scopeforge.net.fetch") as mocked:
            with self.assertRaises(ScopeError):
                session.get("https://evil.test/a")
        mocked.assert_not_called()

    def test_body_is_capped(self):
        with patch("scopeforge.net._OPENER.open", return_value=FakeResponse()):
            result = net.fetch("https://example.com", max_bytes=64)
        self.assertEqual(len(result.body), 64)

    def test_redirect_handler_installed(self):
        self.assertTrue(any(isinstance(handler, net._NoRedirect) for handler in net._OPENER.handlers))

    def test_user_agent_tracks_package_version(self):
        self.assertEqual(net.USER_AGENT, f"ScopeForge/{__version__} scope-safe-recon")

    def test_ua_override_keeps_default_accept(self):
        seen: dict[str, str] = {}
        original = urllib.request.Request

        def spy(url, headers=None, **kwargs):
            seen.update(headers or {})
            return original(url, headers=headers, **kwargs)

        with patch("scopeforge.net.urllib.request.Request", side_effect=spy):
            with patch("scopeforge.net._OPENER.open", return_value=FakeResponse()):
                net.fetch("https://example.com", headers={"User-Agent": "custom"})
        self.assertEqual(seen["User-Agent"], "custom")
        self.assertEqual(seen["Accept"], net.ACCEPT)
        self.assertNotIn("user-agent", seen)

    def test_redirect_not_followed_by_default(self):
        session = net.Session(budget=Budget(delay=0), scope=Scope("t", ["example.com"]))
        response = _response("https://example.com/a", 302, "https://example.com/b")
        with patch("scopeforge.net.fetch", return_value=response) as mocked:
            result = session.get("https://example.com/a")
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(result.status, 302)

    def test_redirect_followed_once_in_scope(self):
        session = net.Session(
            budget=Budget(delay=0), scope=Scope("t", ["example.com"]), allow_redirect=True
        )
        responses = [
            _response("https://example.com/a", 302, "/b"),
            _response("https://example.com/b", 200),
        ]
        with patch("scopeforge.net.fetch", side_effect=responses) as mocked:
            result = session.get("https://example.com/a")
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(session.budget.sent, 2)
        self.assertEqual(result.url, "https://example.com/b")
        self.assertEqual(result.status, 200)

    def test_redirect_rechecks_scope(self):
        session = net.Session(
            budget=Budget(delay=0), scope=Scope("t", ["example.com"]), allow_redirect=True
        )
        response = _response("https://example.com/a", 302, "https://evil.test/b")
        with patch("scopeforge.net.fetch", return_value=response) as mocked:
            with self.assertRaises(ScopeError):
                session.get("https://example.com/a")
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(session.budget.sent, 1)

    def test_redirect_cap_is_one_hop(self):
        session = net.Session(
            budget=Budget(delay=0), scope=Scope("t", ["example.com"]), allow_redirect=True
        )
        responses = [
            _response("https://example.com/a", 302, "/b"),
            _response("https://example.com/b", 302, "/c"),
            _response("https://example.com/c", 200),
        ]
        with patch("scopeforge.net.fetch", side_effect=responses) as mocked:
            result = session.get("https://example.com/a")
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(result.url, "https://example.com/b")
        self.assertEqual(result.status, 302)


if __name__ == "__main__":
    unittest.main()
