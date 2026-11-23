import unittest

from dorklens import dorks


class DorkTests(unittest.TestCase):
    def test_normalize_domain(self):
        self.assertEqual(dorks.normalize_domain("Example.COM/path"), "example.com")
        self.assertEqual(dorks.normalize_domain("https://www.example.com:8443/a"), "www.example.com")

    def test_build_all_includes_target_in_every_query(self):
        plans = dorks.build("example.com")
        self.assertGreater(len(plans), 100)
        self.assertTrue(all("example.com" in item.query for item in plans))
        self.assertTrue(any(item.category == "directory-listing" for item in plans))

    def test_category_filter_and_limit(self):
        plans = dorks.build("example.com", "directory-listing", 3)
        self.assertEqual(len(plans), 3)
        self.assertTrue(all(item.category == "directory-listing" for item in plans))

    def test_catalog_has_no_exploit_payloads(self):
        forbidden = (" or 1=1", "<script", "../../", "'; drop", "%27")
        for plan in dorks.build("example.com"):
            lowered = plan.query.lower()
            self.assertFalse(any(item in lowered for item in forbidden), plan.query)


if __name__ == "__main__":
    unittest.main()
