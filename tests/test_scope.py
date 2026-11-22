import os
import tempfile
import unittest

from scopeforge.models import Scope
from scopeforge.scope import add_scope, check_scope, get_scope, normalize_token, valid_host


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SCOPEFORGE_HOME"] = self.tmp.name

    def tearDown(self):
        os.environ.pop("SCOPEFORGE_HOME", None)
        self.tmp.cleanup()

    def test_normalize_token(self):
        self.assertEqual(normalize_token("HTTPS://WWW.Example.com/path"), "www.example.com")
        self.assertEqual(normalize_token("*.example.com"), "*.example.com")
        self.assertEqual(normalize_token("localhost:8080"), "localhost")

    def test_valid_host(self):
        self.assertTrue(valid_host("example.com"))
        self.assertTrue(valid_host("*.example.com"))
        self.assertTrue(valid_host("127.0.0.1"))
        self.assertFalse(valid_host("not a domain"))

    def test_exact_scope(self):
        scope = Scope("main", ["example.com"], ["admin.example.com"])
        self.assertTrue(check_scope(scope, "https://www.example.com/a").allowed)
        self.assertFalse(check_scope(scope, "https://admin.example.com").allowed)
        self.assertFalse(check_scope(scope, "https://evil.example.net").allowed)

    def test_wildcard_scope(self):
        scope = Scope("main", ["*.example.com"], ["dev.example.com"])
        self.assertTrue(check_scope(scope, "api.example.com").allowed)
        self.assertTrue(check_scope(scope, "example.com").allowed)
        self.assertFalse(check_scope(scope, "dev.example.com").allowed)
        self.assertFalse(check_scope(scope, "example.org").allowed)

    def test_add_and_get_scope(self):
        scope = add_scope("main", ["example.com"], ["staging.example.com"], "policy")
        loaded = get_scope("main")
        self.assertEqual(loaded.name, scope.name)
        self.assertEqual(loaded.exclusions, ["staging.example.com"])
        self.assertEqual(loaded.source, "policy")


if __name__ == "__main__":
    unittest.main()
