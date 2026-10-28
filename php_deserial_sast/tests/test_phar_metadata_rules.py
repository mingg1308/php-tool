import tempfile
import unittest
from pathlib import Path

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.scanner import PHPDeserializationScanner


class PharMetadataRuleTests(unittest.TestCase):
    def scan(self, source, version='8.1', **options):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory, 'case.php')
            target.write_text('<?php\n' + source, encoding='utf-8')
            result = PHPDeserializationScanner(ScannerConfig(
                target_path=str(target), php_version=version,
                enable_gadgets=False, **options)).scan()
            self.assertFalse(result.errors)
            return [f for f in result.findings
                    if f.rule_id == 'php-phar-explicit-metadata-review']

    def test_explicit_metadata_still_matters_on_php8(self):
        findings = self.scan('function inspect($path) {$archive = new Phar($path); $archive->getMetadata();}')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata['receiver_class'], 'phar')
        self.assertFalse(findings[0].assessment.exploitability_verified)

    def test_typed_phar_file_info(self):
        findings = self.scan('function inspect(PharFileInfo $entry) {$entry->getMetadata();}')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata['receiver_class'], 'pharfileinfo')

    def test_literal_restriction_on_php8(self):
        for allowed in ('false', '[]'):
            with self.subTest(allowed=allowed):
                source = "function inspect(Phar $archive) {$archive->getMetadata(['allowed_classes'=>" + allowed + "]);}"
                self.assertFalse(self.scan(source))

    def test_unknown_options_and_old_runtime_remain_reviewable(self):
        source = "function inspect(Phar $archive, $options) {$archive->getMetadata($options);}"
        self.assertEqual(len(self.scan(source)), 1)
        restricted = "function inspect(Phar $archive) {$archive->getMetadata(['allowed_classes'=>false]);}"
        self.assertEqual(len(self.scan(restricted, '7.4')), 1)

    def test_unrelated_get_metadata_is_not_a_phar_sink(self):
        source = 'class Repository {function getMetadata(){return [];} } function inspect(Repository $repo){$repo->getMetadata();}'
        self.assertFalse(self.scan(source))

    def test_rule_toggle_disables_metadata_review(self):
        source = 'function inspect(Phar $archive) {$archive->getMetadata();}'
        self.assertFalse(self.scan(source, enable_rules=False))
