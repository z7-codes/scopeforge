import unittest

from scopeforge.errors import ScopeError
from scopeforge.models import Scope
from scopeforge.scope import guard

SCOPE = Scope(name="t", domains=["example.com", "*.example.org"], exclusions=["staging.example.org"])


class GuardTests(unittest.TestCase):
    def test_exact_allowed(self):
        self.assertTrue(guard(SCOPE, "https://example.com/a").allowed)

    def test_wildcard_allowed(self):
        self.assertTrue(guard(SCOPE, "https://api.example.org/a").allowed)

    def test_exclusion_blocked(self):
        with self.assertRaises(ScopeError):
            guard(SCOPE, "https://staging.example.org")

    def test_outside_blocked(self):
        with self.assertRaises(ScopeError):
            guard(SCOPE, "https://evil.test")

    def test_scheme_required(self):
        with self.assertRaises(ScopeError):
            guard(SCOPE, "example.com")

    def test_lab_without_scope_allowed(self):
        self.assertTrue(guard(None, "http://localhost:3000", lab=True).allowed)

    def test_lab_without_flag_blocked(self):
        with self.assertRaises(ScopeError):
            guard(None, "http://localhost:3000")


if __name__ == "__main__":
    unittest.main()
