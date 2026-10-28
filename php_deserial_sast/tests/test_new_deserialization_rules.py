"""Focused positive and negative examples for conditional review rules."""

import unittest
import tempfile
from pathlib import Path

from php_deserial_sast.config import DEFAULT_BUILTIN_RULES_DIR, ScannerConfig
from php_deserial_sast.core.parser import ASTIndex, PHPParser
from php_deserial_sast.rules.engine import RuleEngine
from php_deserial_sast.models import Severity
from php_deserial_sast.scanner import PHPDeserializationScanner


class NewDeserializationRulesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = RuleEngine(DEFAULT_BUILTIN_RULES_DIR)
        cls.parser = PHPParser()

    def matches(self, code):
        root, source = self.parser.parse_source("<?php\n" + code)
        self.assertFalse(root.has_error)
        index = ASTIndex(root)
        return [finding.rule_id for finding in self.engine.evaluate_file(
            "sample.php", source, root, index
        )]

    def test_session_decode_direct_request_has_conditional_review(self):
        ids = self.matches('session_decode($_POST["payload"]);')
        self.assertIn("php-session-decode-direct-request-review", ids)

    def test_session_decode_indirect_input_is_hotspot_only(self):
        ids = self.matches("session_decode($payload);")
        self.assertIn("php-session-decode-review", ids)
        self.assertNotIn("php-session-decode-direct-request-review", ids)

    def test_session_encode_and_fixed_data_do_not_raise_direct_request(self):
        ids = self.matches('session_encode(); session_decode("fixed");')
        self.assertNotIn("php-session-decode-direct-request-review", ids)

    def test_unserialize_magic_method_side_effect(self):
        ids = self.matches(
            'class Example { public function __unserialize(array $data): void {'
            ' system($data["command"]); } }'
        )
        self.assertIn("php-magic-unserialize-dangerous-sink", ids)

    def test_regular_method_does_not_match_magic_method_rule(self):
        ids = self.matches(
            'class Example { public function run(array $data): void {'
            ' system($data["command"]); } }'
        )
        self.assertNotIn("php-magic-unserialize-dangerous-sink", ids)

    def test_direct_session_finding_replaces_generic_hotspot(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "sample.php").write_text(
                '<?php\nsession_decode($_POST["payload"]);', encoding="utf-8"
            )
            result = PHPDeserializationScanner(ScannerConfig(
                target_path=directory, enable_taint=False, enable_gadgets=False,
                min_severity=Severity.INFO,
            )).scan()
        ids = [finding.rule_id for finding in result.findings]
        self.assertFalse(result.errors)
        self.assertEqual(ids, ["php-session-decode-direct-request-review"])


if __name__ == "__main__":
    unittest.main()
