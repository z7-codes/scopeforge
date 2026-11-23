import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from scopeforge import cli
from scopeforge.cli import parse_headers
from scopeforge.errors import UsageError
from scopeforge.net import Response
from scopeforge.scope import add_scope

SOFT_404 = b"<html>Nothing here</html>"


def fake_fetch(url: str, *args, **kwargs) -> Response:
    if urlsplit(url).path == "/.env":
        return Response(url, 200, {"Content-Type": "text/plain"}, b"APP_ENV=prod\nAPI_URL=https://x.test\n", 0.01)
    return Response(url, 404, {"Content-Type": "text/html"}, SOFT_404, 0.01)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SCOPEFORGE_HOME": self.tmp.name})
        self.env.start()
        add_scope("t", ["example.com"], [], "policy")
        self.call(["config", "delay", "0"])

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def call(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_parse_headers(self):
        self.assertEqual(
            parse_headers(["X-Test: 1"], "a=b"),
            {"X-Test": "1", "Cookie": "a=b"},
        )
        self.assertEqual(
            parse_headers(["User-Agent: from-header"], "", "from-ua"),
            {"User-Agent": "from-ua"},
        )
        self.assertEqual(
            parse_headers(["user-agent: lower", "accept: text/plain"]),
            {"User-Agent": "lower", "Accept": "text/plain"},
        )
        with self.assertRaises(UsageError):
            parse_headers(["bogus"])

    def test_help_has_no_inject_command(self):
        help_text = cli.build_parser().format_help()
        self.assertNotIn("inject", help_text.lower())
        self.assertIn("scan", help_text)
        self.assertIn("probe", help_text)

    def test_scope_commands(self):
        code, out, _ = self.call(["scope", "list"])
        self.assertEqual(code, 0)
        self.assertIn("example.com", out)

    def test_scan_requires_ownership(self):
        code, _, err = self.call(["scan", "https://example.com", "--scope", "t"])
        self.assertEqual(code, 2)
        self.assertIn("--i-own-this", err)

    def test_lab_scan_with_confirmation(self):
        with patch("scopeforge.net.fetch", side_effect=fake_fetch):
            code, out, _ = self.call(["scan", "http://localhost:3000", "--lab", "--i-own-this"])
        self.assertEqual(code, 0)
        self.assertIn("Exposure scan", out)

    def test_budget_exit_code(self):
        self.assertEqual(self.call(["config", "max_requests", "1"])[0], 0)
        with patch("scopeforge.net.fetch", side_effect=fake_fetch):
            code, _, err = self.call(["scan", "http://localhost:3000", "--lab", "--i-own-this"])
        self.assertEqual(code, 3)
        self.assertIn("budget", err.lower())

    def test_budget_five_requests_exit_code(self):
        self.assertEqual(self.call(["config", "max_requests", "5"])[0], 0)
        with patch("scopeforge.net.fetch", side_effect=fake_fetch):
            code, _, err = self.call(
                ["scan", "http://localhost:3000", "--lab", "--delay", "0", "--i-own-this"]
            )
        self.assertEqual(code, 3)
        self.assertIn("budget", err.lower())

    def test_probe_outside_scope_is_blocked(self):
        with patch("scopeforge.net.fetch") as mocked:
            code, _, err = self.call(
                ["probe", "https://evil.test/search?q=test", "--scope", "t", "--i-own-this"]
            )
        self.assertEqual(code, 2)
        mocked.assert_not_called()
        self.assertIn("scope", err.lower())

    def test_unknown_command(self):
        with self.assertRaises(SystemExit) as raised:
            cli.main(["nope"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
