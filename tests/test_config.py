import os
import tempfile
import unittest
from unittest.mock import patch

from scopeforge.config import load_config, set_value


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SCOPEFORGE_HOME": self.tmp.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_numeric_bounds(self):
        with self.assertRaises(ValueError):
            set_value("max_requests", "0")
        with self.assertRaises(ValueError):
            set_value("delay", "11")
        self.assertEqual(set_value("max_requests", "10").max_requests, 10)

    def test_lab_suffixes(self):
        self.assertEqual(load_config().lab_suffixes, [".localhost", ".test"])
        self.assertEqual(set_value("lab_suffixes", ".lab, .dev").lab_suffixes, [".lab", ".dev"])


if __name__ == "__main__":
    unittest.main()
