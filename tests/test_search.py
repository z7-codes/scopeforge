import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote_plus

from scopeforge import search
from scopeforge.errors import SearchError, UsageError
from scopeforge.net import Response


class SearchTests(unittest.TestCase):
    def test_from_file_skips_comments(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "urls.txt"
            path.write_text("# comment\nhttps://a.test\n\nhttps://b.test\n", encoding="utf-8")
            self.assertEqual(search.from_file(str(path)), ["https://a.test", "https://b.test"])

    def test_ddg_extracts_decoded_urls(self):
        target = quote_plus("https://target.test/path")
        html = f'<a class="result__a" href="/l/?uddg={target}&amp;rut=abc">t</a>'
        with patch("scopeforge.search.fetch", return_value=Response("u", 200, {}, html.encode(), 0.1)):
            self.assertEqual(search.ddg("q"), ["https://target.test/path"])

    def test_auto_reports_failures_instead_of_silent_empty(self):
        with patch.dict(os.environ, {}, clear=True), patch("scopeforge.search.fetch") as mocked:
            mocked.return_value.text = ""
            with self.assertRaises(SearchError) as raised:
                search.search("q", "auto")
        self.assertIn("all providers failed", str(raised.exception))
        self.assertIn("ddg: 0 results", str(raised.exception))
        mocked.assert_called_once()

    def test_file_provider_is_first_class(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "urls.txt"
            path.write_text("https://a.test\n", encoding="utf-8")
            self.assertEqual(search.search("ignored", "file", 10, str(path)), ["https://a.test"])
        with self.assertRaises(UsageError):
            search.search("ignored", "file")


if __name__ == "__main__":
    unittest.main()
