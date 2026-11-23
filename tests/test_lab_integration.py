import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit

from scopeforge import cli
from scopeforge.analyzer import analyze_record
from scopeforge.net import Response, fetch

LAB_URL = os.environ.get("SF_LAB_URL", "")


@unittest.skipUnless(LAB_URL, "set SF_LAB_URL to run lab integration")
class LabIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SCOPEFORGE_HOME": self.tmp.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.tmp.cleanup)
        self.call(["config", "delay", "0"])

    def call(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def assert_scan_result(self, code, out, err, banner):
        self.assertIn(code, (0, 4))
        if code == 0:
            self.assertIn(banner, out)
        else:
            lowered = err.lower()
            self.assertTrue("nothing found" in lowered or "no findings" in lowered, err)

    def routed_fetch(self, url, *args, **kwargs):
        if url.startswith(LAB_URL):
            return fetch(url, *args, **kwargs)
        return Response(url, 404, {"Content-Type": "text/html"}, b"<html>Nothing here</html>", 0.01)

    def test_soft404_and_benign_marker(self):
        self.assertTrue(urlsplit(LAB_URL).hostname)
        with patch("scopeforge.net.fetch", side_effect=self.routed_fetch):
            code, out, err = self.call(["scan", LAB_URL, "--lab", "--tier", "all", "--i-own-this", "--no-resume"])
        self.assert_scan_result(code, out, err, "Exposure scan")

        probe_url = f"{LAB_URL}/?{urlencode({'q': 'test'})}"
        with patch("scopeforge.net.fetch", side_effect=self.routed_fetch):
            code, out, err = self.call(["probe", probe_url, "--lab", "--i-own-this", "--no-resume"])
        self.assert_scan_result(code, out, err, "Benign probe")

    def test_probe_sends_real_requests_to_lab(self):
        calls: list[str] = []
        orig = fetch

        def counting_fetch(url, *args, **kwargs):
            calls.append(url)
            return orig(url, *args, **kwargs)

        probe_url = f"{LAB_URL}/rest/products/search?q=test"
        with patch("scopeforge.net.fetch", side_effect=counting_fetch):
            code, out, err = self.call(
                ["probe", probe_url, "--lab", "--i-own-this", "--no-resume", "--max-params", "1"]
            )
        self.assert_scan_result(code, out, err, "Benign probe")
        self.assertGreaterEqual(len(calls), 2)
        self.assertTrue(all(url.startswith(LAB_URL) for url in calls))

    def test_sqli_error_family_classification(self):
        result = analyze_record(
            {
                "category": "sqli",
                "url": LAB_URL,
                "parameter": "q",
                "error_family": "mysql_error",
                "authorized": True,
            }
        )
        self.assertEqual(result["status"], "likely")
        self.assertIn("Verify", result["next_step"])


if __name__ == "__main__":
    unittest.main()
