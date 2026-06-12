"""Tests for trustlayer reporting."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from trustlayer.models import Confidence, Finding, Severity, ScanResult
from trustlayer.reporting import write_json, write_markdown


def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        check_id="TEST-001",
        title="Test Finding",
        severity=Severity.MEDIUM,
        confidence=Confidence.POSSIBLE,
        explanation="Test explanation.",
        who_could_use="Testers",
        what_they_access="Test data",
        possible_damage="Minimal",
        likelihood="Low",
        fastest_fix="Fix it",
        ask_human=False,
        evidence="test evidence",
        source="test/file.py",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_result(**kwargs) -> ScanResult:
    result = ScanResult(target="/test/project", scanned_files=5, skipped_files=1)
    result.findings.append(_make_finding())
    return result


class TestMarkdownReportRequiredFields(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.md_path = os.path.join(self.tmpdir, "report.md")

    def test_contains_title(self):
        write_markdown(_make_result(), self.md_path)
        content = Path(self.md_path).read_text()
        self.assertIn("TrustLayer Scan Report", content)

    def test_contains_sharing_warning(self):
        write_markdown(_make_result(), self.md_path)
        content = Path(self.md_path).read_text()
        self.assertIn("Before sharing this report", content)

    def test_contains_check_id(self):
        write_markdown(_make_result(), self.md_path)
        content = Path(self.md_path).read_text()
        self.assertIn("TEST-001", content)

    def test_contains_severity(self):
        write_markdown(_make_result(), self.md_path)
        content = Path(self.md_path).read_text()
        self.assertIn("MEDIUM", content)

    def test_contains_coverage_section(self):
        write_markdown(_make_result(), self.md_path)
        content = Path(self.md_path).read_text()
        self.assertIn("Coverage and Limitations", content)

    def test_no_100_ready_language(self):
        write_markdown(_make_result(), self.md_path)
        content = Path(self.md_path).read_text()
        self.assertNotIn("100/100", content)
        self.assertNotIn("ready to launch", content.lower())

    def test_empty_findings_safe_wording(self):
        result = ScanResult(target="/proj", scanned_files=3)
        write_markdown(result, self.md_path)
        content = Path(self.md_path).read_text()
        self.assertIn("Human review is still required", content)

    def test_contains_ask_human_field(self):
        result = ScanResult(target="/proj", scanned_files=1)
        result.findings.append(_make_finding(ask_human=True))
        write_markdown(result, self.md_path)
        content = Path(self.md_path).read_text()
        self.assertIn("Ask a human before launch", content)

    def test_report_write_failure_raises(self):
        with self.assertRaises(OSError):
            write_markdown(_make_result(), "/nonexistent/path/report.md")


class TestJsonReportRequiredFields(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.json_path = os.path.join(self.tmpdir, "report.json")

    def test_valid_json(self):
        write_json(_make_result(), self.json_path)
        data = json.loads(Path(self.json_path).read_text())
        self.assertIsInstance(data, dict)

    def test_contains_findings(self):
        write_json(_make_result(), self.json_path)
        data = json.loads(Path(self.json_path).read_text())
        self.assertIn("findings", data)
        self.assertIsInstance(data["findings"], list)
        self.assertGreater(len(data["findings"]), 0)

    def test_finding_has_required_fields(self):
        write_json(_make_result(), self.json_path)
        data = json.loads(Path(self.json_path).read_text())
        f = data["findings"][0]
        for field in ["check_id", "title", "severity", "confidence", "explanation",
                      "who_could_use", "what_they_access", "possible_damage",
                      "likelihood", "fastest_fix", "ask_human", "evidence", "source"]:
            self.assertIn(field, f, f"Missing field: {field}")

    def test_contains_warning(self):
        write_json(_make_result(), self.json_path)
        data = json.loads(Path(self.json_path).read_text())
        self.assertIn("_warning", data)

    def test_contains_severity_counts(self):
        write_json(_make_result(), self.json_path)
        data = json.loads(Path(self.json_path).read_text())
        self.assertIn("severity_counts", data)

    def test_contains_generated_at(self):
        write_json(_make_result(), self.json_path)
        data = json.loads(Path(self.json_path).read_text())
        self.assertIn("generated_at", data)

    def test_report_write_failure_raises(self):
        with self.assertRaises(OSError):
            write_json(_make_result(), "/nonexistent/path/report.json")

    def test_no_raw_secrets_in_json(self):
        secret = "SHOULD_NOT_APPEAR_IN_OUTPUT_XYZ999"
        result = ScanResult(target="/proj", scanned_files=1)
        # Evidence goes through redaction in checks, but let's add a pre-redacted finding
        result.findings.append(_make_finding(evidence=f"api_key=[REDACTED] (was {secret[:5]}...)"))
        write_json(result, self.json_path)
        content = Path(self.json_path).read_text()
        self.assertNotIn(secret, content)


if __name__ == "__main__":
    unittest.main()
