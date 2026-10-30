"""The triage score must explain evidence without claiming exploitability."""

import tempfile
import unittest
from pathlib import Path

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.core.review_priority import score_review_priority
from php_deserial_sast.models import (CodeLocation, Confidence, Finding,
                                      Severity, VulnerabilityType)
from php_deserial_sast.scanner import PHPDeserializationScanner


class ReviewPriorityTests(unittest.TestCase):
    def scan(self, name, body):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("<?php\n" + body, encoding="utf-8")
            result = PHPDeserializationScanner(ScannerConfig(
                target_path=directory, enable_gadgets=False, php_version="8.1",
            )).scan()
            self.assertFalse(result.errors)
            return next(f for f in result.findings if f.metadata.get("engine") == "taint")

    def test_direct_source_ranks_above_guarded_and_unresolved(self):
        direct = self.scan("direct.php", "unserialize($_POST['payload']);")
        guarded = self.scan("guarded.php", (
            "if (custom_guard($_POST['payload'])) "
            "{ unserialize($_POST['payload']); }"
        ))
        unresolved = self.scan("unresolved.php", "unserialize(unknown_decode($_POST['payload']));")
        self.assertEqual(direct.assessment.review_priority.band, "URGENT")
        self.assertGreater(direct.assessment.review_priority.score,
                           guarded.assessment.review_priority.score)
        self.assertGreater(direct.assessment.review_priority.score,
                           unresolved.assessment.review_priority.score)
        for finding in (direct, guarded, unresolved):
            priority = finding.assessment.review_priority
            self.assertEqual(priority.score, sum(priority.factors.values()))
            self.assertEqual(Finding.model_validate_json(
                finding.model_dump_json()).assessment.review_priority, priority)
            self.assertFalse(finding.assessment.exploitability_verified)

    def test_test_scope_lowers_priority_without_changing_severity(self):
        production = self.scan("direct.php", "unserialize($_GET['x']);")
        test = self.scan("tests/direct.php", "unserialize($_GET['x']);")
        self.assertEqual(production.severity, test.severity)
        self.assertLess(test.assessment.review_priority.score,
                        production.assessment.review_priority.score)
        self.assertIn("scope:tests", test.assessment.review_priority.factors)

    def test_review_candidate_is_capped_even_with_high_impact(self):
        finding = Finding(
            id="candidate", rule_id="review", vuln_type=VulnerabilityType.CUSTOM_RULE_MATCH,
            title="Review", description="Review", severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            location=CodeLocation(file_path="x.php", start_line=1, start_col=1,
                                  end_line=1, end_col=2), code_snippet="unserialize($x)",
        )
        priority = score_review_priority(finding, "syntactic_review", "review_candidate", set())
        self.assertLessEqual(priority.score, 29)
        self.assertEqual(priority.score, sum(priority.factors.values()))
        self.assertEqual(priority.band, "LOW")


if __name__ == "__main__":
    unittest.main()
