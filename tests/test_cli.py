import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from scopeforge import cli
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

    def test_unknown_command(self):
        with self.assertRaises(SystemExit) as raised:
            cli.main(["nope"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
