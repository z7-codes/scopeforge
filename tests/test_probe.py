import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from scopeforge import probe
from scopeforge.budget import Budget
from scopeforge.errors import ScopeError
from scopeforge.net import Session


class EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"<html><body><div>{self.path}</div></body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SCOPEFORGE_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_params_and_substitution(self):
        url = "http://localhost/page?id=1&lang=en"
        self.assertEqual(probe.params_of(url), ["id", "lang"])
        changed = probe.substitute(url, "lang", "Z7CHECK")
        self.assertIn("id=1", changed)
        self.assertIn("lang=Z7CHECK", changed)

    def test_non_lab_requires_scope(self):
        session = Session(budget=Budget(delay=0))
        with self.assertRaises(ScopeError):
            probe.run(session, "lab", ["https://example.com/page?q=x"])

    def test_local_probe_reflection(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/page?name=test"
            session = Session(budget=Budget(delay=0), lab=True)
            result = probe.run(session, "lab", [url], marker="Z7CHECK")
            self.assertEqual(len(result.findings), 1)
            item = result.findings[0]
            self.assertEqual(item.parameter, "name")
            self.assertTrue(item.reflection)
            self.assertEqual(item.injected_status, 200)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_render_states_boundary(self):
        self.assertIn("Benign probe", probe.render(probe.ProbeResult([], 0, 0)))
        self.assertIn("not a vulnerability declaration", probe.render(probe.ProbeResult([], 0, 0)))


if __name__ == "__main__":
    unittest.main()
