"""Regression checks for documented legacy and conditional PHP object decoders."""

import tempfile
import unittest
from pathlib import Path

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.models import Severity
from php_deserial_sast.scanner import PHPDeserializationScanner


class AdditionalDeserializationRuleTests(unittest.TestCase):
    def scan(self, source, version=None, **options):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'case.php')
            path.write_text('<?php\n' + source, encoding='utf-8')
            result = PHPDeserializationScanner(ScannerConfig(
                target_path=str(path), php_version=version,
                enable_gadgets=False, min_severity=Severity.INFO, **options,
            )).scan()
            self.assertFalse(result.errors)
            return result

    def test_wddx_taint_flow_and_legacy_version(self):
        result = self.scan("$payload = base64_decode($_POST['data']); wddx_deserialize($payload);", '7.3')
        flow = [finding for finding in result.findings
                if finding.rule_id == 'php-wddx-deserialize-tainted-input']
        self.assertEqual(len(flow), 1)
        self.assertEqual(flow[0].metadata['sink_name'], 'wddx_deserialize')
        self.assertEqual(flow[0].assessment.evidence_level, 'observed_source_flow')

    def test_wddx_removed_since_php_7_4(self):
        result = self.scan("wddx_deserialize($_POST['data']);", '8.1')
        self.assertFalse([f for f in result.findings if 'wddx' in f.rule_id])
        self.assertFalse([s for s in result.sink_inventory if s.sink_name == 'wddx_deserialize'])

    def test_wddx_rules_only_keeps_specific_request_review(self):
        result = self.scan("wddx_deserialize($_POST['data']);", '7.3', enable_taint=False)
        self.assertEqual([f.rule_id for f in result.findings if 'wddx' in f.rule_id],
                         ['php-wddx-deserialize-direct-request-review'])

    def test_unknown_wddx_runtime_is_conditional(self):
        result = self.scan("wddx_deserialize($_POST['data']);")
        flow = [f for f in result.findings if f.rule_id == 'php-wddx-deserialize-tainted-input']
        self.assertEqual(len(flow), 1)
        self.assertEqual(flow[0].severity, Severity.MEDIUM)
        self.assertIn('legacy_wddx_runtime_unverified', flow[0].assessment.limitations)
        self.assertEqual(flow[0].assessment.detection_level, 'conditional_path')

    def test_yaml_direct_request_and_explicit_decode_setting(self):
        result = self.scan("ini_set('yaml.decode_php', 1); yaml_parse($_POST['data']);")
        ids = {finding.rule_id for finding in result.findings}
        self.assertIn('php-yaml-object-decoding-enabled-review', ids)
        self.assertIn('php-yaml-parse-direct-request-review', ids)

    def test_yaml_indirect_input_with_disabled_setting_has_no_yaml_alert(self):
        result = self.scan("ini_set('yaml.decode_php', 0); yaml_parse($data);")
        self.assertFalse([f for f in result.findings if f.rule_id.startswith('php-yaml-')])

    def test_yaml_direct_request_after_dominating_disable_is_not_reported(self):
        result = self.scan("ini_set('yaml.decode_php', 0); yaml_parse($_POST['data']);")
        self.assertFalse([f for f in result.findings if f.rule_id == 'php-yaml-parse-direct-request-review'])

    def test_yaml_reenabled_after_disable_remains_reviewable(self):
        result = self.scan("ini_set('yaml.decode_php', 0); ini_set('yaml.decode_php', 1); yaml_parse($_POST['data']);")
        self.assertIn('php-yaml-parse-direct-request-review',
                      {finding.rule_id for finding in result.findings})

    def test_yaml_direct_request_with_optional_arguments(self):
        result = self.scan("yaml_parse($_POST['data'], 0, $count);")
        self.assertIn('php-yaml-parse-direct-request-review',
                      {finding.rule_id for finding in result.findings})

    def test_shadowed_builtin_names_do_not_raise_new_rules(self):
        result = self.scan(
            'function wddx_deserialize($x) { return $x; } '
            'function yaml_parse($x) { return $x; } '
            "wddx_deserialize($_POST['data']); yaml_parse($_POST['data']);",
            '7.3',
        )
        self.assertFalse([finding for finding in result.findings
                          if finding.rule_id.startswith(('php-wddx-', 'php-yaml-'))])

    def test_typed_spl_unserialize_and_unrelated_method(self):
        result = self.scan(
            'function load(SplObjectStorage $store, $data) { $store->unserialize($data); } '
            'class Repository { function unserialize($data) {} } '
            'function other(Repository $repo, $data) { $repo->unserialize($data); }'
        )
        findings = [f for f in result.findings if f.rule_id == 'php-spl-explicit-unserialize-review']
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata['receiver_class'], 'splobjectstorage')

    def test_no_typed_rules_when_rules_disabled(self):
        result = self.scan('function load(SplObjectStorage $s, $d) {$s->unserialize($d);}',
                           enable_rules=False)
        self.assertFalse([f for f in result.findings if f.rule_id == 'php-spl-explicit-unserialize-review'])

    def test_serializable_unserialize_callback_direct_side_effect(self):
        result = self.scan(
            'class LegacyJob implements Serializable {'
            ' public function serialize() { return ""; }'
            ' public function unserialize($data) { system($data); }'
            '}'
        )
        findings = [f for f in result.findings
                    if f.rule_id == 'php-serializable-unserialize-side-effect-review']
        self.assertEqual(len(findings), 1)
        self.assertIn('system', findings[0].metadata['direct_sinks'])

    def test_non_serializable_unserialize_method_is_not_callback(self):
        result = self.scan('class Job { public function unserialize($data) { system($data); } }')
        self.assertFalse([f for f in result.findings
                          if f.rule_id == 'php-serializable-unserialize-side-effect-review'])


if __name__ == '__main__':
    unittest.main()
