import unittest

from scopeforge.data import load


class PayloadSafetyTests(unittest.TestCase):
    def test_payload_catalog_is_marker_only(self):
        classes = load("payloads")["classes"]
        self.assertEqual(set(classes), {"marker"})
        self.assertEqual(classes["marker"]["canary"], "z7sf7q")
        self.assertEqual(classes["marker"]["steps"], ["z7sf7q"])
        self.assertEqual(classes["marker"]["pairs"], [])
        self.assertEqual(classes["marker"]["category"], "reflection")


if __name__ == "__main__":
    unittest.main()
