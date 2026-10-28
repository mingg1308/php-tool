import tempfile
import unittest
from pathlib import Path

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.scanner import PHPDeserializationScanner


class DependencyPOPEvidenceTests(unittest.TestCase):
    def scan(self, files, gadgets=False):
        with tempfile.TemporaryDirectory() as directory:
            for name, code in files.items():
                Path(directory, name).write_text('<?php\n' + code, encoding='utf-8')
            return PHPDeserializationScanner(ScannerConfig(
                target_path=directory, enable_gadgets=gadgets, php_version='8.1')).scan()

    def test_unrelated_exception_and_fallback_not_attached(self):
        result = self.scan({'a.php': "unserialize($_GET['x']);",
                            'b.php': 'function unrelated(){try{risky();}catch(Exception $e){} foreach(items() as $x){}}'})
        finding = next(f for f in result.findings if f.flow_evidence)
        coverage = finding.metadata['dependency_coverage']
        self.assertEqual(coverage['fallback_scopes'], [])
        self.assertEqual(coverage['exception_scopes'], [])
        self.assertFalse(coverage['complete_dependency_graph'])
        self.assertEqual(len(coverage['files']), 1)
        self.assertNotIn('exception_types_and_finally_completions_approximated', finding.assessment.limitations)

    def test_resolved_dependency_fallback_attached(self):
        result = self.scan({'a.php': "restore($_GET['x']);",
                            'b.php': 'function restore($x){foreach(items() as $v){} unserialize($x);}'})
        finding = next(f for f in result.findings if f.flow_evidence)
        coverage = finding.metadata['dependency_coverage']
        self.assertEqual(len(coverage['files']), 2)
        self.assertTrue(coverage['fallback_scopes'])
        self.assertIn('cfg_dependency_scope_fallback', finding.assessment.limitations)

    def test_pop_constraints_never_claim_exploitability(self):
        gadget = 'class Gadget {public $cmd; function __destruct(){system($this->cmd);}}'
        for options, expected in [('', 'compatible'),
                                  (", ['allowed_classes'=>false]", 'excluded'),
                                  (", ['allowed_classes'=>[]]", 'excluded'),
                                  (", ['allowed_classes'=>['Gadget']]", 'compatible'),
                                  (", ['allowed_classes'=>['Other']]", 'excluded'),
                                  (", ['allowed_classes'=>$runtime]", 'unknown')]:
            with self.subTest(options=options):
                result = self.scan({'gadget.php': gadget,
                                    'entry.php': "unserialize($_GET['x']" + options + ');'}, True)
                candidates = [f for f in result.findings if f.gadget_chain]
                self.assertTrue(candidates)
                details = candidates[0].metadata['deserialization_constraints']
                self.assertEqual(details['observed_site_count'], 1)
                self.assertEqual(details['compatibility_counts'], {expected: 1})
                self.assertEqual(len(details['candidate_source_sinks']),
                                 1 if expected == 'compatible' else 0)
                self.assertFalse(details['exploitability_verified'])
                self.assertEqual(details['property_control'], 'unproven')
                self.assertEqual(details['runtime_class_loading'], 'unproven')
                self.assertEqual(candidates[0].assessment.evidence_level, 'candidate_call_chain')

    def test_pop_candidate_without_application_entry_retained(self):
        result = self.scan({'gadget.php': 'class Gadget {public $cmd; function __destruct(){system($this->cmd);}}'}, True)
        candidate = next(f for f in result.findings if f.gadget_chain)
        self.assertEqual(candidate.metadata['deserialization_constraints']['observed_site_count'], 0)

    def test_same_file_wakeup_links_source_without_claiming_exploitability(self):
        result = self.scan({'entry.php': "class Gadget {public $cmd; function __wakeup(){if(isset($this->cmd)){eval($this->cmd);}}} unserialize($_GET['x']);"}, True)
        candidate = next(f for f in result.findings if f.gadget_chain)
        details = candidate.metadata['deserialization_constraints']
        self.assertEqual(details['runtime_class_loading'], 'top_level_class_declared_before_sink')
        self.assertEqual(details['property_control'], 'public_serialized_property_candidate')
        self.assertEqual(details['candidate_properties'], ['cmd'])
        self.assertEqual(len(details['linked_source_sinks']), 1)
        linked_path = details['linked_candidate_paths'][0]
        self.assertEqual(linked_path['entry_class'], 'Gadget')
        self.assertEqual(linked_path['candidate_serialized_properties'], ['cmd'])
        self.assertEqual(linked_path['impact_function'], 'eval')
        self.assertFalse(linked_path['exploitability_verified'])
        self.assertFalse(details['exploitability_verified'])
        source = next(f for f in result.findings if f.flow_evidence)
        self.assertEqual(source.metadata['candidate_gadget_links'][0]['gadget_finding_id'], candidate.id)
        self.assertEqual(source.metadata['candidate_exploit_paths'][0]['gadget_finding_id'], candidate.id)

    def test_nested_or_cross_file_class_is_not_statically_loaded(self):
        result = self.scan({'gadget.php': "if ($flag) {class Gadget {public $cmd; function __wakeup(){eval($this->cmd);}}}",
                            'entry.php': "unserialize($_GET['x']);"}, True)
        candidate = next(f for f in result.findings if f.gadget_chain)
        details = candidate.metadata['deserialization_constraints']
        self.assertEqual(details['runtime_class_loading'], 'unproven')
        self.assertEqual(details['property_control'], 'unproven')
        self.assertFalse(details['linked_source_sinks'])

    def test_pop_namespaced_allowlist_string_escapes(self):
        result = self.scan({
            'gadget.php': 'namespace App; class Gadget {public $cmd; function __destruct(){system($this->cmd);}}',
            'entry.php': r"unserialize($_GET['x'], ['allowed_classes'=>['App\\Gadget']]);",
        }, True)
        candidate = next(f for f in result.findings if f.gadget_chain)
        self.assertEqual(candidate.metadata['deserialization_constraints']['compatibility_counts'], {'compatible': 1})


    def test_unresolved_calls_are_local_bounded_and_visible_in_assessment(self):
        result = self.scan({'a.php': "unserialize(unknown_decode($_GET['x']));",
                            'b.php': 'function unrelated(){$unknown->other();}'})
        finding = next(f for f in result.findings if f.flow_evidence)
        coverage = finding.metadata['dependency_coverage']
        self.assertEqual(coverage['unresolved_call_count'], 1)
        self.assertIn('unknown_decode', coverage['unresolved_calls'][0]['call'])
        self.assertIn('dependency_calls_unresolved', finding.assessment.limitations)
        result = self.scan({'a.php': "unserialize($_GET['x']); return; unknown();"})
        finding = next(f for f in result.findings if f.flow_evidence)
        self.assertEqual(finding.metadata['dependency_coverage']['unresolved_call_count'], 0)
        result = self.scan({'a.php': 'unknown();' * 40 + "unserialize($_GET['x']);"})
        finding = next(f for f in result.findings if f.flow_evidence)
        coverage = finding.metadata['dependency_coverage']
        self.assertEqual(coverage['unresolved_call_count'], 40)
        self.assertEqual(len(coverage['unresolved_calls']), 32)
        self.assertTrue(coverage['unresolved_calls_truncated'])
