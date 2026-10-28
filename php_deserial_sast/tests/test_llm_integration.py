"""Exercise the scanner's LLM handoff without an external API call."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.llm.verifier import LLMVerifier
from php_deserial_sast.models import Severity
from php_deserial_sast.scanner import PHPDeserializationScanner


class LLMIntegrationTests(unittest.TestCase):
    def scan(self, mocked_response):
        with tempfile.TemporaryDirectory() as parent:
            source = Path(parent) / 'case.php'
            source.write_text("<?php unserialize($_GET['data']);", encoding='utf-8')
            config = ScannerConfig(
                target_path=str(source), enable_llm=True,
                llm_provider='gemini', llm_api_key='test-only-key',
                enable_gadgets=False, enable_rules=False,
                min_severity=Severity.INFO,
            )
            with patch.object(LLMVerifier, '_call_gemini', return_value=mocked_response) as provider:
                result = PHPDeserializationScanner(config).scan()
            return result, provider.call_args_list

    def test_valid_json_attaches_verdict_to_high_finding(self):
        response = json.dumps({
            'is_vulnerable': True,
            'confidence_score': 0.8,
            'verdict': 'LIKELY',
            'reasoning': 'Request data reaches unserialize.',
            'exploitability_assessment': 'REQUIRES_PREREQUISITES',
            'prerequisites': ['available gadget class'],
        })
        result, calls = self.scan(response)
        self.assertTrue(calls)
        self.assertIn('unserialize', calls[0].args[0])
        self.assertFalse([error for error in result.errors if error.phase == 'llm'])
        self.assertTrue(any(f.llm_verification and f.llm_verification.verdict == 'LIKELY'
                            for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)))

    def test_invalid_json_records_llm_error(self):
        result, calls = self.scan('not JSON')
        self.assertTrue(calls)
        self.assertTrue(any(error.phase == 'llm' for error in result.errors))
        self.assertFalse(any(f.llm_verification for f in result.findings))

    def test_missing_key_is_reported_without_silent_verdict(self):
        with tempfile.TemporaryDirectory() as parent:
            source = Path(parent) / 'case.php'
            source.write_text("<?php unserialize($_GET['data']);", encoding='utf-8')
            config = ScannerConfig(
                target_path=str(source), enable_llm=True,
                llm_provider='gemini', enable_gadgets=False,
                enable_rules=False, min_severity=Severity.INFO,
            )
            with patch.dict(os.environ, {'GEMINI_API_KEY': ''}):
                result = PHPDeserializationScanner(config).scan()
        self.assertTrue(any(error.phase == 'llm' and 'GEMINI_API_KEY' in error.message
                            for error in result.errors))
        self.assertFalse(any(f.llm_verification for f in result.findings))


if __name__ == '__main__':
    unittest.main()
