import unittest

from scopeforge.diff import compare, normalize


class DiffTests(unittest.TestCase):
    def test_normalize_volatile_fields(self):
        raw = b'name="csrf" value="abc" id=550e8400-e29b-41d4-a716-446655440000 abcdef0123456789abcdef'
        value = normalize(raw)
        self.assertNotIn("csrf", value)
        self.assertNotIn("550e8400", value)
        self.assertNotIn("abcdef0123456789abcdef", value)

    def test_identical_is_ignored(self):
        result = compare(b"same body", b"same body")
        self.assertFalse(result.interesting)
        self.assertGreaterEqual(result.similarity, 0.92)

    def test_diverged_body_is_interesting(self):
        result = compare(b"short", b"a completely different response body with many words")
        self.assertTrue(result.interesting)
        self.assertIn("diverged", result.reason)

    def test_large_size_delta_is_interesting(self):
        result = compare(b"a" * 5000, b"a" * 5250)
        self.assertTrue(result.interesting)
        self.assertIn("size delta", result.reason)


if __name__ == "__main__":
    unittest.main()
