import unittest

from scopeforge.data import load
from scopeforge.inject import available_classes


class PayloadSafetyTests(unittest.TestCase):
    def test_marker_class_is_preserved(self):
        classes = load("payloads")["classes"]
        self.assertEqual(classes["marker"]["canary"], "z7sf7q")
        self.assertEqual(classes["marker"]["steps"], ["z7sf7q"])
        self.assertEqual(classes["marker"]["pairs"], [])
        self.assertEqual(classes["marker"]["category"], "reflection")

    def test_ladder_classes_are_paired(self):
        classes = load("payloads")["classes"]
        self.assertEqual(load("payloads")["version"], 2)
        self.assertEqual(
            set(available_classes()),
            {"sqli_boolean", "xss_reflect", "traversal", "ssti", "open_redirect"},
        )
        for name in available_classes():
            pairs = classes[name]["pairs"]
            self.assertTrue(pairs, name)
            for pair in pairs:
                self.assertEqual(len(pair), 2, name)
                self.assertTrue(pair[0], name)
                self.assertTrue(pair[1], name)
                self.assertNotEqual(pair[0], pair[1], name)


if __name__ == "__main__":
    unittest.main()
