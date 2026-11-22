import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scopeforge.probe import build_marker_urls, probe_urls, render_probe, validate_probe_target


class EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"<html><body><div>{self.path}</div></body></html>".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


class ProbeTests(unittest.TestCase):
    def test_build_marker_urls_without_query(self):
        urls = build_marker_urls("http://localhost/page", "Z7CHECK")
        self.assertEqual(urls, ["http://localhost/page?q=Z7CHECK"])

    def test_build_marker_urls_with_query(self):
        urls = build_marker_urls("http://localhost/page?id=1&lang=en", "Z7CHECK")
        self.assertEqual(len(urls), 2)
        self.assertIn("id=Z7CHECK", urls[0])
        self.assertIn("lang=Z7CHECK", urls[1])

    def test_ownership_required(self):
        with self.assertRaises(ValueError):
            probe_urls(["http://127.0.0.1/page?q=x"], "Z7CHECK", "", False, 0)

    def test_non_lab_requires_scope(self):
        with self.assertRaises(ValueError):
            validate_probe_target("https://example.com/page?q=x", "")

    def test_local_probe_reflection(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/page?name=test"
            results = probe_urls([url], "Z7CHECK", "", True, 0)
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0]["reflected"])
            self.assertEqual(results[0]["status_code"], 200)
            self.assertEqual(results[0]["status"], "needs-validation")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_render(self):
        results = [{"url": "http://localhost/?q=[redacted]", "status_code": 200, "reflected": True, "context": "html-text", "next_step": "check", "excerpt": ""}]
        self.assertIn("ScopeForge benign marker probe", render_probe(results))
        self.assertIn('"reflected"', render_probe(results, "json"))
        self.assertIn("| URL | Status | Reflected |", render_probe(results, "md"))


if __name__ == "__main__":
    unittest.main()
