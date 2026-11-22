import unittest
from unittest.mock import patch

from scopeforge import net
from scopeforge.budget import Budget
from scopeforge.errors import ScopeError
from scopeforge.models import Scope


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


if __name__ == "__main__":
    unittest.main()
