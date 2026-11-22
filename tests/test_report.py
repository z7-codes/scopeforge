import unittest

from scopeforge.report import render_report


def analysis(identifier, status, score, **extra):
    return {
        "id": identifier,
        "category": "reflection",
        "status": status,
        "score": score,
        "scope": "main",
        "url": "https://example.com/search?q=[redacted]",
        "parameter": "q",
        "context": "html-text",
        "reason": "Benign marker reflected in html-text context.",
        "next_step": "Confirm encoding manually.",
        **extra,
    }


class ReportTests(unittest.TestCase):
    def test_empty_report_is_not_submittable(self):
        text = render_report("main", [])
        self.assertIn("Nothing here is ready to submit.", text)
        self.assertIn("Known Issues", text)

    def test_sections_and_ordering(self):
        records = [
            analysis("a-needs", "needs-validation", 10),
            analysis("a-blocked", "blocked", 0),
            analysis("a-confirm", "evidence-confirmed", 92, evidence_summary="reviewed in scope"),
            analysis("a-likely", "likely", 68),
        ]
        text = render_report("main", records, "policy-2026-11-22")
        self.assertLess(text.index("## Confirmed evidence drafts"), text.index("## Needs validation"))
        self.assertLess(text.index("## Needs validation"), text.index("## Blocked"))
        self.assertLess(text.index("a-likely"), text.index("a-needs"))
        self.assertIn("Scope source: policy-2026-11-22", text)
        self.assertIn("Draft only", text)

    def test_confirmed_draft_has_manual_boundary(self):
        text = render_report("main", [analysis("a-confirm", "evidence-confirmed", 92, evidence_summary="reviewed")])
        self.assertIn("Manual reproduction outline", text)
        self.assertIn("do not add attack payloads", text)
        self.assertIn("Impact template", text)
        self.assertIn("[Operator:", text)
        self.assertNotIn("Vulnerable", text)

    def test_markdown_cells_are_escaped(self):
        record = analysis("a-blocked", "blocked", 0, reason="a | b")
        self.assertIn("a \\| b", render_report("main", [record]))

    def test_scope_source_placeholder(self):
        self.assertIn("[operator: add program policy", render_report("main", []))


if __name__ == "__main__":
    unittest.main()
