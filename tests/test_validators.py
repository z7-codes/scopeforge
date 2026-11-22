import unittest

from scopeforge.errors import DataError
from scopeforge.validators import REGISTRY, env, git_head, openapi, resolve


class ValidatorTests(unittest.TestCase):
    def test_git_head(self):
        self.assertTrue(git_head(b"ref: refs/heads/main\n", "text/plain"))
        self.assertFalse(git_head(b"<html>not git</html>", "text/html"))

    def test_env_needs_structure(self):
        self.assertTrue(env(b"APP_ENV=prod\nAPI_URL=https://x.test\n", "text/plain"))
        self.assertFalse(env(b"<html>APP_ENV=prod</html>", "text/html"))

    def test_openapi(self):
        self.assertTrue(openapi(b'{"openapi":"3.0.0","paths":{}}', "application/json"))
        self.assertFalse(openapi(b"not json", "text/plain"))

    def test_registry_is_callable(self):
        self.assertTrue(REGISTRY)
        for name, handler in REGISTRY.items():
            with self.subTest(name=name):
                self.assertTrue(callable(handler))

    def test_unknown_validator(self):
        with self.assertRaises(DataError):
            resolve("nope")


if __name__ == "__main__":
    unittest.main()
