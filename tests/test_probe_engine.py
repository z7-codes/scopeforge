import os
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from scopeforge import probe
from scopeforge.budget import Budget
from scopeforge.models import Scope
from scopeforge.net import Response, Session
from scopeforge.state import run_key

URL = "https://example.com/search?q=one&lang=en"


def fake_fetch(url: str, *args, **kwargs) -> Response:
    params = parse_qs(urlsplit(url).query)
    if params.get("q") == ["z7sf7q"]:
        body = b"<html>hello z7sf7q lang=en</html>"
    else:
        body = b"<html>hello one lang=en</html>"
    return Response(url, 200, {"Content-Type": "text/html"}, body, 0.01)


class ProbeEngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SCOPEFORGE_HOME": self.tmp.name})
        self.env.start()
        self.session = Session(budget=Budget(delay=0), scope=Scope("t", ["example.com"]))

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_marker_is_benign(self):
        self.assertEqual(probe.marker_for(), "z7sf7q")

    def test_reflected_marker_is_reported(self):
        with patch("scopeforge.net.fetch", side_effect=fake_fetch):
            result = probe.run(self.session, "t", [URL])
        self.assertEqual(len(result.findings), 1)
        item = result.findings[0]
        self.assertEqual(item.parameter, "q")
        self.assertEqual(item.payload, "z7sf7q")
        self.assertTrue(item.reflection)
        self.assertEqual(item.context, "html-text")
        self.assertIn("Benign probe", probe.render(result))

    def test_resume_skips_seen_parameter(self):
        key = run_key(URL, "q", "z7sf7q")
        with patch("scopeforge.net.fetch", side_effect=fake_fetch):
            result = probe.run(self.session, "t", [URL], seen={key})
        self.assertEqual(result.findings, [])
        self.assertEqual(result.skipped, 1)

    def test_missing_query_is_skipped(self):
        with patch("scopeforge.net.fetch", side_effect=fake_fetch):
            result = probe.run(self.session, "t", ["https://example.com/"])
        self.assertEqual(result.findings, [])
        self.assertEqual(result.skipped, 1)


if __name__ == "__main__":
    unittest.main()
