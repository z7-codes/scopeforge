import contextlib
import io
import json
import os
import unittest
from unittest.mock import patch

from dorklens import __version__, cli
from dorklens.search import SearchHit, SearchResult


class CliTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"NO_COLOR": "1"})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_default_invocation_generates_dorks(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main(["example.com", "--limit", "2"])
        self.assertEqual(code, 0)
        self.assertIn("site:example.com", output.getvalue())

    def test_version(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as raised:
                cli.main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn(__version__, output.getvalue())

    def test_dorks_json_is_parseable(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli.main(["dorks", "example.com", "--category", "sensitive-files", "--format", "json", "--limit", "2"])
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["domain"], "example.com")
        self.assertEqual(len(payload["queries"]), 2)

    def test_search_json_output(self):
        result = SearchResult(
            domain="example.com",
            category="all",
            provider="file",
            hits=[SearchHit("https://example.com/.env", "dork", "sensitive-files", "file")],
        )
        output = io.StringIO()
        with patch("dorklens.cli.search_module.search", return_value=result):
            with contextlib.redirect_stdout(output):
                code = cli.main(["search", "example.com", "--format", "json"])
        self.assertEqual(code, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["hits"][0]["url"], "https://example.com/.env")


if __name__ == "__main__":
    unittest.main()
