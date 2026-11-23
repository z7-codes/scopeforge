import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dorklens import search


class SearchTests(unittest.TestCase):
    def test_ddg_parses_wrapped_urls(self):
        html = '<a rel="nofollow" href="/l/?uddg=https%3A%2F%2Fexample.com%2F.env">result</a>'
        with patch("dorklens.search.fetch", return_value=html):
            urls = search.ddg("site:example.com filetype:env", 10)
        self.assertEqual(urls, ["https://example.com/.env"])

    def test_file_provider_imports_local_urls(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "urls.txt"
            path.write_text("https://example.com/.env\n# comment\nhttps://example.com/admin\n", encoding="utf-8")
            result = search.search("example.com", provider="file", input_file=str(path))
        self.assertEqual(len(result.hits), 2)
        self.assertEqual(result.hits[0].provider, "file")

    def test_results_are_deduplicated_and_redacted(self):
        with patch("dorklens.search._call_provider") as mocked:
            mocked.side_effect = [
                ["https://example.com/?api_key=abc123"],
                ["https://example.com/?api_key=abc123", "https://example.com/login"],
            ]
            result = search.search(
                "example.com",
                category="inurl-parameters",
                provider="ddg",
                max_queries=2,
                max_results=10,
            )
        urls = [item.url for item in result.hits]
        self.assertIn("https://example.com/?api_key=[redacted]", urls)
        self.assertEqual(len(urls), len(set(urls)))


if __name__ == "__main__":
    unittest.main()
