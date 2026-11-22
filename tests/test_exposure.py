import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scopeforge.exposure import Baseline, build_worksheet, classify, normalize_body, run_scan, similarity
from scopeforge.paths import get_rule
from scopeforge.scope import add_scope

BASE = Baseline(status=200, size=48, body="<html><body>app shell</body></html>")


class ScanHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.env":
            body = b"APP_KEY=base64:abc\nDB_PASSWORD=hunter2\nMAIL_HOST=smtp.local\n"
            ctype = "text/plain"
            status = 200
        else:
            body = b"<html><body>app shell</body></html>"
            ctype = "text/html"
            status = 404
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


class SoftFourOhFourTests(unittest.TestCase):
    def test_identical_shell_is_soft_404(self):
        verdict, _ = classify(get_rule("/.env"), 200, b"<html><body>app shell</body></html>", BASE, "text/html")
        self.assertEqual(verdict, "soft-404")

    def test_volatile_numbers_do_not_break_match(self):
        body = b"<html><body>app shell</body></html>"
        self.assertGreater(similarity(normalize_body(body), BASE.body), 0.98)

    def test_same_size_same_status_is_soft_404(self):
        body = b"<html><body>nope  page</body></html>"
        verdict, _ = classify(get_rule("/.env"), 200, body, BASE, "text/html")
        self.assertIn(verdict, ("soft-404", "maybe"))


class ValidatorTests(unittest.TestCase):
    def test_dotenv_exposed(self):
        body = b"APP_KEY=base64:abc\nDB_PASSWORD=hunter2\nMAIL_HOST=smtp.local\n"
        verdict, _ = classify(get_rule("/.env"), 200, body, BASE, "text/plain")
        self.assertEqual(verdict, "exposed")

    def test_html_page_named_env_is_not_exposed(self):
        body = b"<html><body>APP_KEY=x\nDB_PASSWORD=y</body></html>"
        verdict, _ = classify(get_rule("/.env"), 200, body, BASE, "text/html")
        self.assertNotEqual(verdict, "exposed")

    def test_git_head(self):
        body = b"ref: refs/heads/main\n"
        verdict, _ = classify(get_rule("/.git/HEAD"), 200, body, BASE, "text/plain")
        self.assertEqual(verdict, "exposed")

    def test_zip_magic(self):
        body = b"PK\x03\x04" + b"\x00" * 100
        verdict, _ = classify(get_rule("/backup.zip"), 200, body, BASE, "application/zip")
        self.assertEqual(verdict, "exposed")

    def test_sql_dump(self):
        body = b"-- MySQL dump 10.13\nCREATE TABLE users (id int);\n"
        verdict, _ = classify(get_rule("/db.sql"), 200, body, BASE, "text/plain")
        self.assertEqual(verdict, "exposed")

    def test_openapi(self):
        body = b'{"openapi": "3.0.0", "paths": {}}'
        verdict, _ = classify(get_rule("/openapi.json"), 200, body, BASE, "application/json")
        self.assertEqual(verdict, "exposed")

    def test_actuator_up(self):
        body = b'{"status": "UP"}'
        verdict, _ = classify(get_rule("/actuator"), 200, body, BASE, "application/json")
        self.assertEqual(verdict, "exposed")


class StatusTests(unittest.TestCase):
    def test_server_error_bucket(self):
        verdict, _ = classify(get_rule("/.env"), 500, b"boom", BASE, "text/html")
        self.assertEqual(verdict, "error")

    def test_protected_path_is_maybe(self):
        verdict, _ = classify(get_rule("/server-status"), 403, b"denied", BASE, "text/html")
        self.assertEqual(verdict, "maybe")


class ScanTests(unittest.TestCase):
    def test_local_structural_scan(self):
        tmp = tempfile.TemporaryDirectory()
        previous = os.environ.get("SCOPEFORGE_HOME")
        os.environ["SCOPEFORGE_HOME"] = tmp.name
        server = ThreadingHTTPServer(("127.0.0.1", 0), ScanHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            add_scope("lab", ["127.0.0.1"], [], "local test")
            findings, sent = run_scan(
                f"http://127.0.0.1:{server.server_port}",
                "lab",
                tier="high",
                delay=0,
                max_requests=20,
            )
            self.assertGreaterEqual(sent, 4)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].surface, "dotenv")
            self.assertEqual(findings[0].confidence, "high")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            if previous is None:
                os.environ.pop("SCOPEFORGE_HOME", None)
            else:
                os.environ["SCOPEFORGE_HOME"] = previous
            tmp.cleanup()


class WorksheetTests(unittest.TestCase):
    def test_worksheet_contains_all_sections(self):
        content = build_worksheet("demo", "example.com", "policy")
        self.assertIn("# ScopeForge Public Exposure Worksheet", content)
        self.assertIn("Domain: example.com", content)
        for section in ("RECON", "EXPOSURE", "SQLI", "XSS", "CTF"):
            self.assertIn("## " + section, content)

    def test_worksheet_queries_are_scoped(self):
        content = build_worksheet("demo", "example.com")
        self.assertIn("`site:example.com", content)
        self.assertIn("Run these searches manually", content)
        self.assertIn("A public result is a lead, not proof", content)


if __name__ == "__main__":
    unittest.main()
