import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from scopeforge.cli import main


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SCOPEFORGE_HOME"] = self.tmp.name

    def tearDown(self):
        os.environ.pop("SCOPEFORGE_HOME", None)
        self.tmp.cleanup()

    def run_cli(self, *args):
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_full_flow(self):
        code, out, err = self.run_cli(
            "scope", "add", "main", "--domain", "example.com", "--source", "policy-2026-11-22"
        )
        self.assertEqual(code, 0, err)
        self.assertIn("scope saved: main", out)

        code, out, err = self.run_cli("scope", "list")
        self.assertEqual(code, 0, err)
        self.assertIn("main:", out)

        code, out, err = self.run_cli("plan", "main", "--category", "xss", "--limit", "2", "--format", "json")
        self.assertEqual(code, 0, err)
        records = json.loads(out)
        self.assertEqual(len(records), 2)

        code, out, err = self.run_cli(
            "lead", "add", "--scope", "main", "--candidate", "https://example.com/search?q=test",
            "--source", "manual", "--category", "xss"
        )
        self.assertEqual(code, 0, err)
        self.assertIn("lead added:", out)

        code, out, err = self.run_cli("lead", "list", "--scope", "main", "--format", "json")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(json.loads(out)), 1)

        evidence = [
            {
                "id": "EV-001",
                "scope": "main",
                "category": "xss",
                "url": "https://example.com/search?q=Z7CHECK",
                "parameter": "q",
                "context": "html-text",
                "reflection": True,
                "authorized": True,
            }
        ]
        evidence_path = Path(self.tmp.name) / "evidence.json"
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

        code, out, err = self.run_cli("analyze", str(evidence_path), "--format", "json")
        self.assertEqual(code, 0, err)
        analysis = json.loads(out)
        self.assertEqual(analysis[0]["status"], "likely")

        analysis_path = Path(self.tmp.name) / "analysis.json"
        analysis_path.write_text(json.dumps(analysis), encoding="utf-8")
        report_path = Path(self.tmp.name) / "report.md"

        code, out, err = self.run_cli("report", str(analysis_path), "--scope", "main", "--output", str(report_path))
        self.assertEqual(code, 0, err)
        self.assertIn("report written", out)
        self.assertIn("# ScopeForge Evidence Report", report_path.read_text(encoding="utf-8"))

    def test_lab(self):
        code, out, err = self.run_cli("lab", "localhost")
        self.assertEqual(code, 0, err)
        self.assertIn("ScopeForge Lab Mode", out)
        self.assertIn("No requests are sent", out)

    def test_analyze_output(self):
        evidence_path = Path(self.tmp.name) / "evidence.json"
        evidence = [{"category": "recon", "authorized": True, "surface": "docs"}]
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        output_path = Path(self.tmp.name) / "analysis.json"

        code, out, err = self.run_cli(
            "analyze", str(evidence_path), "--format", "json", "--output", str(output_path)
        )
        self.assertEqual(code, 0, err)
        self.assertIn("analysis written", out)
        data = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(data[0]["status"], "needs-validation")

    def test_text_output_is_ascii(self):
        code, out, err = self.run_cli("scope", "add", "main", "--domain", "example.com")
        self.assertEqual(code, 0, err)
        commands = [
            ("scope", "list"),
            ("plan", "main"),
            ("lead", "list"),
            ("lab", "localhost"),
        ]
        for args in commands:
            code, out, err = self.run_cli(*args)
            self.assertEqual(code, 0, err)
            self.assertTrue(out.isascii(), out)

    def test_missing_scope_error(self):
        code, out, err = self.run_cli("plan", "missing")
        self.assertEqual(code, 2)
        self.assertIn("scope not found", err)


if __name__ == "__main__":
    unittest.main()
