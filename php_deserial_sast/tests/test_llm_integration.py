"""Exercise the scanner's LLM handoff without an external API call."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.llm.verifier import LLMVerifier
from php_deserial_sast.models import Severity
from php_deserial_sast.scanner import PHPDeserializationScanner


class LLMIntegrationTests(unittest.TestCase):
    def test_medium_finding_is_eligible_when_configured(self):
        finding = MagicMock()
        finding.severity = Severity.MEDIUM
        medium_scanner = PHPDeserializationScanner(ScannerConfig(
            target_path='.', enable_llm=False, llm_min_severity=Severity.MEDIUM,
        ))
        high_scanner = PHPDeserializationScanner(ScannerConfig(
            target_path='.', enable_llm=False, llm_min_severity=Severity.HIGH,
        ))
        self.assertTrue(medium_scanner._llm_eligible(finding))
        self.assertFalse(high_scanner._llm_eligible(finding))

    def test_gemini_http_response_is_read_without_proxy(self):
        response = MagicMock()
        response.json.return_value = {"candidates": [{"content": {"parts": [{"text": '{"ok":true}'}]}}]}
        client = MagicMock()
        client.post.return_value = response
        context = MagicMock()
        context.__enter__.return_value = client
        with patch("php_deserial_sast.llm.verifier.httpx.Client", return_value=context) as factory:
            raw = LLMVerifier(provider="gemini", api_key="test-only-key")._call_gemini("test prompt")
        self.assertEqual(raw, '{"ok":true}')
        self.assertFalse(factory.call_args.kwargs["trust_env"])
        self.assertEqual(client.post.call_args.kwargs["headers"]["x-goog-api-key"], "test-only-key")

    def test_gemini_retries_transient_service_error(self):
        unavailable = MagicMock()
        unavailable.status_code = 503
        unavailable.headers = {}
        success = MagicMock()
        success.status_code = 200
        success.headers = {}
        success.json.return_value = {"candidates": [{"content": {"parts": [{"text": '{"ok":true}'}]}}]}
        client = MagicMock()
        client.post.side_effect = [unavailable, success]
        context = MagicMock()
        context.__enter__.return_value = client
        with patch.dict(os.environ, {
            "GEMINI_MAX_ATTEMPTS": "2",
            "GEMINI_RETRY_BASE_SECONDS": "0",
            "GEMINI_MIN_INTERVAL_SECONDS": "0",
        }), patch("php_deserial_sast.llm.verifier.httpx.Client", return_value=context), \
                patch("php_deserial_sast.llm.verifier.time.sleep") as sleeper:
            raw = LLMVerifier(provider="gemini", api_key="test-only-key")._call_gemini("test prompt")
        self.assertEqual(raw, '{"ok":true}')
        self.assertEqual(client.post.call_count, 2)
        sleeper.assert_called_once_with(0.0)

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
