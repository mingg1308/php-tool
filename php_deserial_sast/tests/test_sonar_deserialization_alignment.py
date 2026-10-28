"""S4508-style review and S5135-style source-to-sink evidence stay separate."""
import tempfile
import unittest
from pathlib import Path

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.scanner import PHPDeserializationScanner


class SonarDeserializationAlignmentTests(unittest.TestCase):
    def scan(self, code, *, enable_taint=True):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "sample.php").write_text("<?php\n" + code, encoding="utf-8")
            return PHPDeserializationScanner(ScannerConfig(
                target_path=directory, enable_gadgets=False,
                enable_taint=enable_taint, php_version="8.1",
            )).scan()

    def test_constant_base64_is_review_only_without_taint(self):
        result = self.scan("unserialize(base64_decode('YTowOnt9'));", enable_taint=False)
        self.assertFalse(result.errors)
        self.assertTrue(result.findings)
        self.assertTrue(all(f.severity.value == "MEDIUM" for f in result.findings))
        self.assertTrue(all(f.assessment.detection_level == "review_candidate"
                            for f in result.findings))
        self.assertTrue(any(f.metadata["rule_metadata"].get("methodology_reference") == "S4508"
                            for f in result.findings))

    def test_local_file_is_review_only_without_source_evidence(self):
        result = self.scan("unserialize(file_get_contents(__DIR__ . '/cache.ser'));")
        self.assertFalse(result.errors)
        self.assertFalse(any(f.assessment.detection_level == "direct_untrusted_deserialization"
                             for f in result.findings))
        self.assertTrue(all(f.severity.value == "MEDIUM" for f in result.findings))

    def test_request_through_base64_has_taint_evidence(self):
        result = self.scan("unserialize(base64_decode($_POST['payload']));")
        self.assertFalse(result.errors)
        finding = next(f for f in result.findings if f.metadata.get("engine") == "taint")
        self.assertEqual(finding.metadata["methodology_reference"], "S5135")
        self.assertEqual(finding.assessment.detection_level, "direct_untrusted_deserialization")

    def test_direct_request_pattern_remains_when_taint_disabled(self):
        result = self.scan("unserialize($_POST['payload']);", enable_taint=False)
        self.assertFalse(result.errors)
        self.assertTrue(any(f.rule_id == "php-insecure-unserialize-direct"
                            and f.metadata["rule_metadata"].get("methodology_reference") == "S5135"
                            for f in result.findings))

    def test_restricted_classes_do_not_raise_object_injection(self):
        result = self.scan("unserialize($_POST['payload'], ['allowed_classes' => false]);")
        self.assertFalse(result.errors)
        self.assertFalse(result.findings)
        self.assertTrue(any(entry.disposition == "restricted_unserialize"
                            for entry in result.sink_inventory))


if __name__ == "__main__":
    unittest.main()
