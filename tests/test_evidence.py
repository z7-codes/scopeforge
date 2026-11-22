import json
import os
import tempfile
import unittest
from unittest.mock import patch

from scopeforge import evidence, state
from scopeforge.models import Finding


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SCOPEFORGE_HOME": self.tmp.name})
        self.env.start()
        self.finding = Finding(
            id="f-abcdef12",
            scope="t",
            kind="exposure",
            category="exposure",
            url="https://example.com/.env",
            confidence="high",
            surface="dotenv",
            signal="structural match",
            excerpt="APP_ENV=prod",
        )

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_write_creates_evidence_file(self):
        path = evidence.write(self.finding, "reviewed in scope")
        records = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["id"], "EV-abcdef12")
        self.assertEqual(records[0]["scope"], "t")
        self.assertTrue(records[0]["manual_confirmed"])
        self.assertEqual(records[0]["evidence_summary"], "reviewed in scope")

    def test_write_is_idempotent_for_same_finding(self):
        first = evidence.write(self.finding)
        second = evidence.write(self.finding)
        self.assertEqual(first, second)
        self.assertEqual(len(json.loads(first.read_text(encoding="utf-8"))), 1)

    def test_empty_fields_are_dropped(self):
        record = evidence.to_record(self.finding)
        self.assertNotIn("parameter", record)
        self.assertNotIn("payload", record)

    def test_paths_reject_traversal(self):
        with self.assertRaises(ValueError):
            evidence.path_for("../evil")
        with self.assertRaises(ValueError):
            state.state_path("a/b")


if __name__ == "__main__":
    unittest.main()
