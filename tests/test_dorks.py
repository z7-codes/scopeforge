import unittest

from scopeforge.dorks import CATEGORIES, build_plan, render_plan
from scopeforge.models import Scope


class DorkTests(unittest.TestCase):
    def test_all_queries_are_scoped(self):
        scope = Scope("main", ["*.example.com"])
        for category in CATEGORIES:
            records = build_plan(scope, category, limit=100)
            self.assertTrue(records)
            for item in records:
                self.assertTrue(item["query"].startswith("site:example.com "))
                self.assertIn("no payloads", item["safety"])

    def test_limit(self):
        scope = Scope("main", ["example.com", "example.org"])
        records = build_plan(scope, "recon", limit=3)
        self.assertEqual(len(records), 3)

    def test_render_formats(self):
        records = build_plan(Scope("main", ["example.com"]), "xss", limit=2)
        self.assertIn("ScopeForge plan", render_plan(records))
        self.assertIn('"query"', render_plan(records, "json"))
        self.assertIn("| ID | Category | Query |", render_plan(records, "md"))

    def test_unknown_category(self):
        with self.assertRaises(ValueError):
            build_plan(Scope("main", ["example.com"]), "nope")


if __name__ == "__main__":
    unittest.main()
