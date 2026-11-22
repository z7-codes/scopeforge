import unittest

from scopeforge.analyzer import analyze_record, analyze_records, redact, render_analysis


class AnalyzerTests(unittest.TestCase):
    def test_unauthorized_is_blocked(self):
        result = analyze_record({"category": "xss", "url": "https://example.com", "reflection": True})
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["score"], 0)

    def test_xss_signal(self):
        result = analyze_record(
            {
                "category": "xss",
                "url": "https://example.com/search?q=Z7CHECK",
                "parameter": "q",
                "context": "html-attribute",
                "reflection": True,
                "authorized": True,
            }
        )
        self.assertEqual(result["status"], "likely")
        self.assertGreaterEqual(result["score"], 60)

    def test_sqli_signal(self):
        result = analyze_record(
            {
                "category": "sqli",
                "url": "https://example.com/product?id=1",
                "parameter": "id",
                "error_family": "mysql_error",
                "authorized": True,
            }
        )
        self.assertEqual(result["status"], "likely")
        self.assertIn("Verify", result["next_step"])

    def test_manual_confirmation(self):
        result = analyze_record(
            {
                "category": "exposure",
                "surface": "public-report",
                "authorized": True,
                "manual_confirmed": True,
                "evidence_summary": "Reviewed manually in authorized scope.",
            }
        )
        self.assertEqual(result["status"], "evidence-confirmed")
        self.assertEqual(result["score"], 92)

    def test_redaction(self):
        value = redact("email=test@example.com&token=eyJabc123def456ghi789&secret=deadbeef" * 2)
        self.assertNotIn("test@example.com", value)
        self.assertNotIn("eyJabc", value)
        self.assertIn("email=[redacted]", value)
        self.assertIn("token=[redacted]", value)

    def test_render(self):
        results = analyze_records([{"category": "recon", "authorized": True, "surface": "docs"}])
        self.assertIn("ScopeForge analysis", render_analysis(results))
        self.assertIn('"status"', render_analysis(results, "json"))
        self.assertIn("| ID | Category | Status |", render_analysis(results, "md"))


if __name__ == "__main__":
    unittest.main()
