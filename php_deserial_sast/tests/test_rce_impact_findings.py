"""Conditional impact findings must retain evidence without claiming execution."""

import tempfile
import unittest
from pathlib import Path

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.models import Severity
from php_deserial_sast.scanner import PHPDeserializationScanner


class RceImpactFindingTests(unittest.TestCase):
    def scan(self, files, severity='INFO'):
        with tempfile.TemporaryDirectory() as directory:
            for name, body in files.items():
                path = Path(directory, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('<?php\n' + body, encoding='utf-8')
            return PHPDeserializationScanner(ScannerConfig(
                target_path=directory, php_version='7.3', enable_llm=False,
                min_severity=Severity(severity),
            )).scan()

    @staticmethod
    def impact_findings(result):
        return [finding for finding in result.findings
                if finding.rule_id == 'php-deserialization-rce-impact-candidate']

    def test_groups_multiple_session_triggers_at_one_eval_site(self):
        result = self.scan({
            'load.php': "$data=file_get_contents($_FILES['save']['tmp_name']); $hero=unserialize($data); $_SESSION['hero']=$hero;",
            'a.php': "$_SESSION['hero']->run();",
            'b.php': "$_SESSION['hero']->run();",
            'classes.php': "class Calculator { public $expression; public function run() { eval($this->expression); } }",
        })
        self.assertFalse(result.errors)
        candidates = self.impact_findings(result)
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(Path(candidate.location.file_path).name, 'classes.php')
        self.assertEqual(candidate.metadata['impact_function'], 'eval')
        self.assertEqual(len(candidate.metadata['trigger_sites']), 2)
        self.assertEqual(len(candidate.metadata['route_ids']), 2)
        self.assertFalse(candidate.assessment.exploitability_verified)
        self.assertEqual(candidate.assessment.detection_level, 'review_candidate')
        self.assertIn('object_class_and_properties', candidate.assessment.limitations)
        self.assertTrue(all(route.impact_category == 'RCE'
                            for route in result.routes if route.route_id in candidate.metadata['route_ids']))

    def test_magic_method_gadget_is_linked_to_source(self):
        result = self.scan({
            'entry.php': "class Demo { public $code; function __wakeup(){eval($this->code);} } $obj=unserialize($_POST['data']);",
        })
        candidates = self.impact_findings(result)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].metadata['route_kind'], 'candidate_gadget')
        self.assertEqual(candidates[0].metadata['impact_function'], 'eval')
        self.assertFalse(candidates[0].assessment.exploitability_verified)

    def test_overwrite_and_harmless_method_do_not_create_impact_finding(self):
        overwritten = self.scan({
            'load.php': "$hero=unserialize($_POST['data']); $hero='safe'; $_SESSION['hero']=$hero;",
            'play.php': "$_SESSION['hero']->run(); class Calculator { function run(){eval('1');} }",
        })
        harmless = self.scan({
            'load.php': "$hero=unserialize($_POST['data']); $_SESSION['hero']=$hero;",
            'play.php': "$_SESSION['hero']->run(); class Player { function run(){return true;} }",
        })
        self.assertEqual(self.impact_findings(overwritten), [])
        self.assertEqual(self.impact_findings(harmless), [])

    def test_dynamic_invocation_is_not_assumed_to_be_rce(self):
        result = self.scan({
            'load.php': "$hero=unserialize($_POST['data']); $_SESSION['hero']=$hero;",
            'play.php': "$_SESSION['hero']->run(); class Callback { public $fn; function run(){call_user_func($this->fn);} }",
        })
        self.assertEqual(self.impact_findings(result), [])

    def test_high_threshold_hides_medium_candidate_but_keeps_source(self):
        result = self.scan({
            'load.php': "$hero=unserialize($_POST['data']); $_SESSION['hero']=$hero;",
            'play.php': "$_SESSION['hero']->run(); class Calculator { public $code; function run(){eval($this->code);} }",
        }, severity='HIGH')
        self.assertEqual(self.impact_findings(result), [])
        self.assertTrue(any(f.rule_id == 'php-unserialize-tainted-input' for f in result.findings))
        self.assertTrue(any(r.impact_function == 'eval' for r in result.routes))


if __name__ == '__main__':
    unittest.main()
