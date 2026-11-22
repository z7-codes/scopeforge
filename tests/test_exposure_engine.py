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

    def test_git_head_chains_to_git_paths(self):
        requested = []

        def git_fetch(url: str, *args, **kwargs) -> Response:
            path = urlsplit(url).path
            if path == "/.git/HEAD":
                return Response(url, 200, {"Content-Type": "text/plain"}, b"ref: refs/heads/main\n", 0.01)
            if path == "/.git/config":
                return Response(url, 200, {"Content-Type": "text/plain"}, b"[core]\nrepositoryformatversion = 0\n", 0.01)
            return fake_fetch(url, *args, **kwargs)

        def tracking(url, *args, **kwargs):
            requested.append(urlsplit(url).path)
            return git_fetch(url, *args, **kwargs)

        with patch("scopeforge.net.fetch", side_effect=tracking):
            result = exposure.run(self.session, "t", "https://example.com", tier="high")
        self.assertIn("/.git/HEAD", requested)
        self.assertIn("/.git/config", requested)
        self.assertGreaterEqual(len(result.findings), 2)

    def test_dotenv_does_not_chain_to_git(self):
        requested = []

        def tracking(url, *args, **kwargs):
            requested.append(urlsplit(url).path)
            if urlsplit(url).path == "/.env":
                return fake_fetch(url, *args, **kwargs)
            return Response(url, 404, {"Content-Type": "text/html"}, SOFT_404, 0.01)

        with patch("scopeforge.net.fetch", side_effect=tracking):
            exposure.run(self.session, "t", "https://example.com", tier="high")
        self.assertIn("/.env", requested)
        self.assertEqual(requested.count("/.git/config"), 1)
        self.assertEqual(requested.count("/.git/logs/HEAD"), 1)

    def test_resume_skips_seen_paths(self):
        with patch("scopeforge.net.fetch", side_effect=fake_fetch):
            result = exposure.run(self.session, "t", "https://example.com", tier="high", seen={"/.env"})
        self.assertEqual(result.findings, [])
        self.assertEqual(result.skipped, 1)

    def test_resume_all_paths_sends_nothing(self):
        seen = {item.path for item in exposure.load_rules("high")}
        with patch("scopeforge.net.fetch") as mocked:
            result = exposure.run(self.session, "t", "https://example.com", tier="high", seen=seen)
        mocked.assert_not_called()
        self.assertEqual(result.sent, 0)
        self.assertEqual(result.skipped, len(seen))

    def test_worksheet_is_scope_bound(self):
        text = exposure.build_worksheet("t", "example.com", "policy")
        self.assertIn("site:example.com", text)
        self.assertIn("Policy: policy".replace("Policy", "Scope source"), text)


if __name__ == "__main__":
    unittest.main()
