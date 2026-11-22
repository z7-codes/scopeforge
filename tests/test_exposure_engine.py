import os
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from scopeforge import exposure
from scopeforge.budget import Budget
from scopeforge.models import Scope
from scopeforge.net import Response, Session

SOFT_404 = b"<html><head><title>Not Found</title></head><body>Nothing here</body></html>"


def fake_fetch(url: str, *args, **kwargs) -> Response:
    path = urlsplit(url).path
    if path.startswith("/z7sf-"):
        return Response(url, 404, {"Content-Type": "text/html"}, SOFT_404, 0.01)
    if path == "/.env":
        body = b"APP_ENV=production\nAPI_URL=https://api.example.test\n"
        return Response(url, 200, {"Content-Type": "text/plain"}, body, 0.01)
    return Response(url, 404, {"Content-Type": "text/html"}, SOFT_404, 0.01)


class ExposureEngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SCOPEFORGE_HOME": self.tmp.name})
        self.env.start()
        self.session = Session(budget=Budget(delay=0), scope=Scope("t", ["example.com"]))

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_rules_are_tiered(self):
        self.assertGreaterEqual(len(exposure.load_rules("high")), 10)
        self.assertEqual(len(exposure.load_rules("all")), 32)
        with self.assertRaises(ValueError):
            exposure.load_rules("critical")

    def test_structural_match_is_reported(self):
        with patch("scopeforge.net.fetch", side_effect=fake_fetch):
            result = exposure.run(self.session, "t", "https://example.com", tier="high")
        self.assertEqual(len(result.findings), 1)
        item = result.findings[0]
        self.assertEqual(item.confidence, "high")
        self.assertEqual(item.url, "https://example.com/.env")
        self.assertIn("structural match", item.signal)
        self.assertIn("Exposure scan", exposure.render(result))

    def test_soft_404_is_suppressed(self):
        def generic(url, *args, **kwargs):
            return Response(url, 200, {"Content-Type": "text/html"}, SOFT_404, 0.01)

        with patch("scopeforge.net.fetch", side_effect=generic):
            result = exposure.run(self.session, "t", "https://example.com", tier="high")
        self.assertEqual(result.findings, [])

    def test_resume_skips_seen_paths(self):
        with patch("scopeforge.net.fetch", side_effect=fake_fetch):
            result = exposure.run(self.session, "t", "https://example.com", tier="high", seen={"/.env"})
        self.assertEqual(result.findings, [])
        self.assertEqual(result.skipped, 1)

    def test_worksheet_is_scope_bound(self):
        text = exposure.build_worksheet("t", "example.com", "policy")
        self.assertIn("site:example.com", text)
        self.assertIn("Policy: policy".replace("Policy", "Scope source"), text)


if __name__ == "__main__":
    unittest.main()
