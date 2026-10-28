"""A database read is conditional input until its write provenance is known."""

import tempfile
import unittest
from pathlib import Path

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.scanner import PHPDeserializationScanner


class PersistentStoreReadTests(unittest.TestCase):
    def scan(self, code):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'entry.php').write_text('<?php\n' + code, encoding='utf-8')
            return PHPDeserializationScanner(ScannerConfig(
                target_path=directory, php_version='7.4', enable_gadgets=False,
            )).scan()

    def test_wpdb_result_field_is_conditional_persistent_input(self):
        result = self.scan(
            'class wpdb {function get_results($sql){return [];}} '
            'function upgrade(){global $wpdb; '
            '$rows=$wpdb->get_results("SELECT option_value FROM options"); '
            'foreach($rows as $row){unserialize($row->option_value);}}'
        )
        self.assertFalse(result.errors)
        flows = [finding for finding in result.findings
                 if finding.rule_id == 'php-unserialize-tainted-input']
        self.assertEqual(len(flows), 1)
        finding = flows[0]
        self.assertEqual(finding.metadata['analysis_status'],
                         'conditional_persistent_data_flow')
        self.assertEqual(finding.metadata['source_assumption'],
                         'persistent_store_read_unverified')
        self.assertEqual(finding.severity.value, 'MEDIUM')
        self.assertEqual(finding.flow_evidence[0].source_kind, 'persistent_data')
        self.assertFalse(finding.assessment.exploitability_verified)

    def test_assignment_in_while_condition_reaches_foreach_body(self):
        result = self.scan(
            'class wpdb {function get_results($sql){return [];}} '
            'function upgrade(){global $wpdb; '
            'while($rows=$wpdb->get_results("SELECT option_value FROM options")) {'
            'foreach($rows as $row){$value=$row->option_value; '
            'unserialize($value);} break;}}'
        )
        flows = [finding for finding in result.findings
                 if finding.metadata.get('source_assumption') ==
                 'persistent_store_read_unverified']
        self.assertEqual(len(flows), 1)

    def test_unrelated_receiver_or_constant_has_no_persistent_route(self):
        for code in (
            'class wpdb {function get_results($sql){return [];}} '
            '$rows=$other->get_results("SELECT value"); '
            'foreach($rows as $row){unserialize($row->value);}',
            'class wpdb {function get_results($sql){return [];}} '
            '$rows=$wpdb->get_results("SELECT value"); '
            'foreach($rows as $row){unserialize("a:0:{}");}',
            'class wpdb {function get_results($sql){return [];}} '
            '$rows=$wpdb->get_results("SELECT value"); '
            'foreach($rows as $row){$row->value="a:0:{}"; unserialize($row->value);}',
        ):
            with self.subTest(code=code):
                result = self.scan(code)
                self.assertFalse(any(f.metadata.get('source_assumption') ==
                                     'persistent_store_read_unverified'
                                     for f in result.findings))

    def test_request_insert_matches_literal_read_table_and_column(self):
        result = self.scan(
            'class wpdb {function get_results($sql){return [];} '
            'function insert($table,$data){return 1;}} '
            '$wpdb->insert("options", ["option_value"=>$_POST["payload"]]); '
            '$rows=$wpdb->get_results("SELECT option_value FROM options"); '
            'foreach($rows as $row){unserialize($row->option_value);}'
        )
        self.assertFalse(result.errors)
        finding = next(f for f in result.findings
                       if f.metadata.get('source_assumption') == 'persistent_store_read_unverified')
        self.assertEqual(finding.metadata['persistent_store_write_provenance'],
                         'static_table_column_and_request_match')
        self.assertEqual(finding.metadata['persistent_store_write_candidates'][0]['table'], 'options')
        self.assertTrue(finding.metadata['persistent_store_runtime_order_unverified'])
        self.assertFalse(finding.assessment.exploitability_verified)

    def test_unrelated_column_has_no_write_match(self):
        result = self.scan(
            'class wpdb {function get_results($sql){return [];} '
            'function insert($table,$data){return 1;}} '
            '$wpdb->insert("options", ["other_value"=>$_POST["payload"]]); '
            '$rows=$wpdb->get_results("SELECT option_value FROM options"); '
            'foreach($rows as $row){unserialize($row->option_value);}'
        )
        finding = next(f for f in result.findings
                       if f.metadata.get('source_assumption') == 'persistent_store_read_unverified')
        self.assertNotIn('persistent_store_write_candidates', finding.metadata)


if __name__ == '__main__':
    unittest.main()
