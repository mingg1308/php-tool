"""Real-case semantics without assuming that a library has a hostile caller."""

import json
import tempfile
import unittest
from pathlib import Path

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.scanner import PHPDeserializationScanner


class RealCaseAlignmentTests(unittest.TestCase):
    def scan_package(self, name, version, code, *, library=None, gadgets=False):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent, name.rsplit('/', 1)[-1] + '-' + version)
            root.mkdir()
            (root / 'composer.json').write_text(json.dumps({'name': name, 'type': 'library'}), encoding='utf-8')
            source = root / 'src' / 'Http' / 'Auth' / 'AccessTokenAuthenticator.php'
            source.parent.mkdir(parents=True)
            source.write_text('<?php\n' + code, encoding='utf-8')
            return PHPDeserializationScanner(ScannerConfig(
                target_path=str(root), enable_gadgets=gadgets,
                library_mode=library, php_version='8.1',
            )).scan()

    def test_auto_library_and_affected_advisory_are_conditional(self):
        result = self.scan_package('saloonphp/saloon', '3.0.0',
            "class AccessTokenAuthenticator { public static function unserialize($string) { return unserialize($string, ['allowed_classes' => true]); } }")
        self.assertFalse(result.errors)
        self.assertTrue(result.analysis['library_mode'])
        self.assertEqual(result.analysis['package_context']['version_source'], 'directory_name_unverified')
        flow = next(f for f in result.findings if f.rule_id == 'php-library-api-exposure')
        self.assertEqual(flow.assessment.detection_level, 'conditional_path')
        review = next(f for f in result.findings if f.rule_id == 'php-unserialize-allows-all-classes')
        self.assertEqual(review.metadata['known_advisory']['id'], 'CVE-2026-33942')
        self.assertFalse(review.metadata['known_advisory']['exploitability_verified'])

    def test_explicit_application_mode_disables_api_assumption(self):
        result = self.scan_package('saloonphp/saloon', '3.0.0',
            "class AccessTokenAuthenticator { public static function unserialize($string) { return unserialize($string, ['allowed_classes' => true]); } }",
            library=False)
        self.assertFalse(result.analysis['library_mode'])
        self.assertFalse(any(f.rule_id == 'php-library-api-exposure' for f in result.findings))

    def test_tcpdf_fixed_boundary_is_outside_old_cve(self):
        result = self.scan_package('tecnickcom/tcpdf', '6.2.22', "class TCPDF {}")
        advisory = result.analysis['package_context']['advisories'][0]
        self.assertEqual(advisory['id'], 'CVE-2018-17057')
        self.assertEqual(advisory['status'], 'outside_affected_range')

    def test_fixed_closure_is_not_dynamic_gadget_sink(self):
        result = self.scan_package('demo/box', '1.0.0',
            "class Box { public $items; function __destruct(){array_filter($this->items, function($x){return $x;});} }",
            gadgets=True)
        self.assertFalse(result.errors)
        self.assertFalse(any(chain.sink_function == 'array_filter' for chain in result.gadget_chains))

    def test_literal_unlink_callback_is_file_delete(self):
        result = self.scan_package('demo/box', '1.0.0',
            "class Box { public $paths; function __destruct(){array_map('unlink', $this->paths);} }",
            gadgets=True)
        self.assertFalse(result.errors)
        self.assertTrue(any(chain.sink_type == 'FILE_DELETE' and chain.sink_function == 'array_map'
                            for chain in result.gadget_chains))

    def test_foreach_callback_identifies_candidate_property(self):
        result = self.scan_package('demo/box', '1.0.0',
            "class Box { protected $processors; function __destruct(){foreach($this->processors as $processor){call_user_func($processor, 'x');}} }",
            gadgets=True)
        self.assertFalse(result.errors)
        self.assertTrue(any('processors' in chain.candidate_serialized_properties
                            for chain in result.gadget_chains))

    def test_monolog_reference_requires_matching_gadget_evidence(self):
        result = self.scan_package('monolog/monolog', '1.23.0',
            "class FingersCrossedHandler { protected $processors; function __destruct(){foreach($this->processors as $processor){call_user_func($processor, 'x');}} }",
            gadgets=True)
        self.assertFalse(result.errors)
        referenced = [f for f in result.findings if f.metadata.get('published_gadget_reference')]
        self.assertTrue(referenced)
        self.assertEqual(referenced[0].metadata['published_gadget_reference']['id'], 'PHPGGC Monolog/RCE7')
        self.assertFalse(referenced[0].metadata['published_gadget_reference']['exploitability_verified'])


if __name__ == '__main__':
    unittest.main()
