import unittest

from php_deserial_sast.tests.test_dataflow_regression import analyze, CASES
from php_deserial_sast.tests.test_upgrade_models import UPGRADE_CASES


class DemandSummaryTests(unittest.TestCase):
    def test_labeled_cases_match_eager_analysis(self):
        cases = [(name, code, expected, True) for name, (code, expected) in CASES.items()]
        cases += [(name, *values) for name, values in UPGRADE_CASES.items()]
        for name, code, expected, effects in cases:
            with self.subTest(name=name):
                eager, _ = analyze(code, True, effects)
                demanded, project = analyze(code, True, effects, True)
                self.assertTrue(project.converged)
                self.assertEqual(bool(demanded), expected)
                signature = lambda findings: {(f.rule_id, f.location.start_line, f.location.start_col,
                                               f.severity, f.confidence) for f in findings}
                self.assertEqual(signature(demanded), signature(eager))

    def test_unused_recursive_returns_not_materialized(self):
        code = '''function irrelevant($x){if(rand())return irrelevant($x['next']);return $x;}
                  function used($x){return $x;} unserialize(used($_GET['x']));'''
        findings, project = analyze(code, False, False, True)
        self.assertTrue(findings)
        unused = next(f for f in project.functions if f.name == 'irrelevant')
        used = next(f for f in project.functions if f.name == 'used')
        self.assertNotIn(unused.key, project.return_demands)
        self.assertFalse(project.returns[unused.key])
        self.assertTrue(project.returns[used.key])

    def test_late_top_level_dependency_chain(self):
        code = ''.join(f'function f{i}($x){{return f{i+1}($x);}}' for i in range(40))
        code += 'function f40($x){return $x;} function sink($x){unserialize($x);} sink(f0($_GET["x"]));'
        findings, project = analyze(code, False, False, True)
        self.assertTrue(project.converged)
        self.assertTrue(findings)
        self.assertEqual(len(project.return_demands), 41)

    def test_demand_with_mutual_recursion(self):
        code = '''function a($x){if(rand())return b($x);return $x;}
                  function b($x){return a($x);} unserialize(b($_GET['x']));'''
        findings, project = analyze(code, False, False, True)
        self.assertTrue(project.converged)
        self.assertTrue(findings)
