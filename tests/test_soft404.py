import unittest
from types import SimpleNamespace

from scopeforge.net import Response
from scopeforge.soft404 import Baseline, build, classify, normalize, similarity


def response(status: int, body: bytes, ctype: str = "text/html") -> Response:
    return Response("https://example.com/x", status, {"Content-Type": ctype}, body, 0.01)


class Soft404Tests(unittest.TestCase):
    def test_normalize(self):
        value = normalize(b"ID 12345678-1234 abcdabcdabcdabcd   \n")
        self.assertIn("id 0", value)
        self.assertIn("h", value)
        self.assertNotIn("12345678", value)

    def test_similarity(self):
        self.assertEqual(similarity("", ""), 1.0)
        self.assertGreater(similarity("abc", "abc"), 0.99)

    def test_classify_validator_hit(self):
        verdict, reason = classify(lambda body, ctype: True, 200, b"proof", Baseline(404, 10, "x"), "text/plain")
        self.assertEqual(verdict, "exposed")
        self.assertIn("structural", reason)

    def test_classify_404(self):
        verdict, _ = classify(None, 404, b"missing", Baseline(404, 10, "missing"), "text/html")
        self.assertEqual(verdict, "absent")

    def test_classify_soft_404(self):
        baseline = Baseline(404, 10, normalize(b"not found"))
        verdict, _ = classify(None, 200, b"NOT FOUND", baseline, "text/html")
        self.assertEqual(verdict, "soft-404")

    def test_build_uses_median_sample(self):
        session = SimpleNamespace(
            get=lambda url: response(404, b"x" * len(url.split("/")[-1]))
        )
        baseline = build(session, "https://example.com", samples=3)
        self.assertEqual(baseline.status, 404)
        self.assertGreater(baseline.size, 0)


if __name__ == "__main__":
    unittest.main()
