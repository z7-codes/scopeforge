import contextlib
import io
import os
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from scopeforge import inject
from scopeforge.budget import Budget
from scopeforge.errors import UsageError
from scopeforge.lab_serve import LabHandler, serve
from scopeforge.net import Response, Session
from scopeforge.preflight import check as preflight_check
from scopeforge.scope import add_scope


def lab_fetch(url: str, *args, **kwargs) -> Response:
    query = parse_qs(urlsplit(url).query)
    if "id" in query:
        value = query["id"][0].lower()
        body = b"<div id='result'>Welcome, admin</div>" if "1=1" in value else b"<div id='result'>no rows</div>"
        return Response(url, 200, {}, body, 0.01)
    if "q" in query:
        value = query["q"][0]
        return Response(url, 200, {}, f"<div id='result'>{value}</div>".encode(), 0.01)
    return Response(url, 404, {}, b"not found", 0.01)


class AirgeddonUxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SCOPEFORGE_HOME": self.tmp.name, "NO_COLOR": "1"})
        self.env.start()
        add_scope("labscope", ["127.0.0.1"], [], "local lab")

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_preflight_required_missing_returns_two(self):
        values = iter([False] + [True] * 100)
        with patch("scopeforge.preflight._present", side_effect=lambda _command: next(values)):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(preflight_check(), 2)

    def test_host_header_out_of_scope_warns(self):
        scope = add_scope("t", ["example.com"], [], "policy")
        session = Session(Budget(50), scope=scope, headers={"Host": "evil.test"})
        stderr = io.StringIO()
        with patch("scopeforge.net.fetch", return_value=Response("http://example.com", 200, {}, b"ok", 0.01)):
            with contextlib.redirect_stderr(stderr):
                session.get("http://example.com")
        self.assertIn("Host header", stderr.getvalue())

    def test_lab_server_rejects_non_loopback_bind(self):
        with self.assertRaises(UsageError):
            serve(8099, "0.0.0.0")

    def test_lab_server_endpoints(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(thread.join, 2)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            reflected = urllib.request.urlopen(base + "/?q=z7check", timeout=3).read().decode()
            sqli = urllib.request.urlopen(base + "/sqli?id=%27+OR+1%3D1--", timeout=3).read().decode()
            traversal = urllib.request.urlopen(base + "/traverse?file=../../etc/passwd", timeout=3).read().decode()
            env_body = urllib.request.urlopen(base + "/.env", timeout=3).read().decode()
        finally:
            server.shutdown()
        self.assertIn("z7check", reflected)
        self.assertIn("Welcome, admin", sqli)
        self.assertIn("root:x:0:0", traversal)
        self.assertIn("SECRET_KEY", env_body)

    def test_inject_uses_paired_baselines(self):
        session = Session(Budget(100), lab=True)
        with patch("scopeforge.net.fetch", side_effect=lab_fetch):
            result = inject.run(
                session,
                "labscope",
                ["http://127.0.0.1:8099/sqli?id=1", "http://127.0.0.1:8099/?q=start"],
                ["sqli_boolean", "xss_reflect"],
                2,
            )
        self.assertEqual(result.classes, ["sqli_boolean", "xss_reflect"])
        self.assertGreaterEqual(len(result.findings), 2)
        self.assertTrue(all(item.payload_class in result.classes for item in result.findings))
        self.assertTrue(all(item.baseline_status == 200 for item in result.findings))
        self.assertIn("payload ladder", inject.render(result).lower())

    def test_inject_budget_preflight(self):
        session = Session(Budget(2), lab=True)
        with self.assertRaises(UsageError):
            inject.run(session, "labscope", ["http://127.0.0.1:8099/?q=start"], ["xss_reflect"], 1)


if __name__ == "__main__":
    unittest.main()
