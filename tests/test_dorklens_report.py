import tempfile
import unittest
from pathlib import Path

from dorklens import report
from dorklens.errors import UsageError
from dorklens.search import SearchHit, SearchResult


def sample_result() -> SearchResult:
    return SearchResult(
        domain="example.com",
        category="all",
        provider="auto",
        queries=['site:example.com filetype:env ".env"'],
        hits=[
            SearchHit(
                url="https://example.com/.env",
                query='site:example.com filetype:env ".env"',
                category="sensitive-files",
                provider="ddg",
            )
        ],
    )


class ReportTests(unittest.TestCase):
    def test_classify_sensitive_hit(self):
        label, _reason = report.classify(sample_result().hits[0])
        self.assertEqual(label, "High-priority exposure signal")

    def test_markdown_has_signal_language(self):
        text = report.render_markdown(sample_result())
        self.assertIn("High-priority exposure signal", text)
        self.assertIn("Manual verification required.", text)
        self.assertNotIn("vulnerab", text.lower())

    def test_json_round_trip(self):
        result = sample_result()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "results.json"
            path.write_text(report.render_json(result), encoding="utf-8")
            loaded = report.load_results(str(path))
        self.assertEqual(loaded.domain, "example.com")
        self.assertEqual(len(loaded.hits), 1)

    def test_invalid_json_raises_usage_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.json"
            path.write_text("{bad", encoding="utf-8")
            with self.assertRaises(UsageError):
                report.load_results(str(path))


if __name__ == "__main__":
    unittest.main()
