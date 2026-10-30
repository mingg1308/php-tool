"""Runtime version guards must distinguish vulnerable and patched branches."""
import unittest
from pathlib import Path

from php_deserial_sast.core.parser import PHPParser
from php_deserial_sast.core.taint_engine import TaintEngine
from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.models import Severity
from php_deserial_sast.scanner import PHPDeserializationScanner


def scan(code, version):
    root, source = PHPParser().parse_source("<?php\n" + code)
    assert not root.has_error
    return TaintEngine("fixture.php", source, root, php_version=version).analyze()


class PhpVersionBranchTests(unittest.TestCase):
    def test_drupal_style_patch(self):
        code = """if (version_compare(PHP_VERSION, '7.0.0', '>=')) {
            unserialize($_GET['value'], ['allowed_classes' => FALSE]);
        } else {
            unserialize($_GET['value']);
        }"""
        self.assertEqual(len(scan(code, "7.4")), 0)
        self.assertEqual(len(scan(code, "5.6")), 1)
        self.assertEqual(len(scan(code, None)), 1)

    def test_unsafe_new_branch_and_safe_old_branch(self):
        code = """if (version_compare(PHP_VERSION, '7.0.0', '>=')) {
            unserialize($_GET['value']);
        } else {
            unserialize($_GET['value'], ['allowed_classes' => false]);
        }"""
        self.assertEqual(len(scan(code, "7.4")), 1)
        self.assertEqual(len(scan(code, "5.6")), 0)

    def test_unknown_condition_keeps_both_paths(self):
        code = """if (version_compare($runtime, '7.0.0', '>=')) {
            unserialize($_GET['value']);
        } else {
            unserialize($_GET['other']);
        }"""
        self.assertEqual(len(scan(code, "7.4")), 2)

    def test_version_branch_in_called_function(self):
        code = """function decode($value) {
            if (version_compare(PHP_VERSION, '7.0.0', '>=')) {
                return unserialize($value, ['allowed_classes' => false]);
            } else {
                return unserialize($value);
            }
        }
        decode($_GET['value']);"""
        self.assertEqual(len(scan(code, "7.4")), 0)
        self.assertEqual(len(scan(code, "5.6")), 1)

    def test_php_function_name_is_case_insensitive(self):
        code = """if (VERSION_COMPARE(PHP_VERSION, '7.0.0', '>=')) {
            unserialize($_GET['value'], ['allowed_classes' => false]);
        } else {
            unserialize($_GET['value']);
        }"""
        self.assertEqual(len(scan(code, "7.4")), 0)

    def test_namespace_constant_named_php_version_is_not_runtime_evidence(self):
        code = """namespace App;
        const PHP_VERSION = '5.6.0';
        if (version_compare(PHP_VERSION, '7.0.0', '>=')) {
            unserialize($_GET['first']);
        } else {
            unserialize($_GET['second']);
        }"""
        self.assertEqual(len(scan(code, "7.4")), 2)

    def test_default_scanner_does_not_flag_patched_branch_as_high(self):
        path = Path(__file__).parent / "version_guard_patched.php"
        report = PHPDeserializationScanner(ScannerConfig(
            target_path=str(path), php_version="7.4", min_severity=Severity.INFO,
            enable_gadgets=False)).scan()
        self.assertFalse(report.errors)
        self.assertEqual(report.findings, [])
        legacy = PHPDeserializationScanner(ScannerConfig(
            target_path=str(path), php_version="5.6", min_severity=Severity.INFO,
            enable_gadgets=False)).scan()
        self.assertFalse(legacy.errors)
        self.assertTrue(any(f.severity.rank >= Severity.HIGH.rank for f in legacy.findings))


if __name__ == "__main__":
    unittest.main()
