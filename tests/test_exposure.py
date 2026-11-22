import unittest

from scopeforge.exposure import build_worksheet


class ExposureTests(unittest.TestCase):
    def test_worksheet_contains_all_sections(self):
        content = build_worksheet("demo", "example.com", "policy")
        self.assertIn("# ScopeForge Public Exposure Worksheet", content)
        self.assertIn("Domain: example.com", content)
        for section in ("RECON", "EXPOSURE", "SQLI", "XSS", "CTF"):
            self.assertIn("## " + section, content)

    def test_worksheet_queries_are_scoped(self):
        content = build_worksheet("demo", "example.com")
        self.assertIn("`site:example.com", content)
        self.assertIn("Run these searches manually", content)
        self.assertIn("A public result is a lead, not proof", content)


if __name__ == "__main__":
    unittest.main()
