import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scopeforge import findings


class FindingStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SCOPEFORGE_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def make(self, url="https://example.com/search?q=1", **extra):
        return findings.add("t", "probe", "reflection", url, **extra)

    def test_add_and_list(self):
        item = self.make(confidence="medium")
        self.assertTrue(item.id.startswith("f-"))
        listed = findings.list_all("t")
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0].id, item.id)

    def test_filters(self):
        self.make(confidence="low")
        self.make(confidence="high", url="https://example.com/other")
        self.assertEqual(len(findings.list_all("t", min_confidence="high")), 1)
        self.assertEqual(len(findings.list_all("other")), 0)

    def test_status_and_redaction(self):
        item = self.make()
        findings.set_status(item.id, "confirmed", "token=eyJabc123def456ghi789")
        updated = findings.get(item.id)
        self.assertEqual(updated.status, "confirmed")
        self.assertNotIn("eyJabc", updated.note)

    def test_validation(self):
        with self.assertRaises(ValueError):
            findings.add("", "probe", "reflection", "https://example.com")
        with self.assertRaises(ValueError):
            self.make(confidence="critical")
        with self.assertRaises(ValueError):
            findings.set_status("f-nope", "confirmed")

    def test_render(self):
        self.make()
        self.assertIn("Findings - 1", findings.render(findings.list_all()))
        self.assertIn('"id"', findings.render(findings.list_all(), "json"))

    def test_render_rejects_unknown_format(self):
        with self.assertRaises(ValueError):
            findings.render([], "yaml")

    def test_devil_sorts_by_signal_length(self):
        short = self.make(signal="a")
        long = self.make(signal="longer signal", url="https://example.com/other")
        self.assertEqual([item.id for item in findings.list_all("t", devil=True)], [long.id, short.id])

    def test_lock_is_released(self):
        self.make()
        self.assertFalse((Path(self.tmp.name) / ".findings.json.lock").exists())

    def test_stale_lock_is_recovered(self):
        lock = Path(self.tmp.name) / ".findings.json.lock"
        lock.write_text("", encoding="utf-8")
        old = time.time() - 31
        os.utime(lock, (old, old))
        self.make()
        self.assertFalse(lock.exists())


if __name__ == "__main__":
    unittest.main()
