"""Many guard routes must not displace an unguarded path or another source."""
import unittest
from php_deserial_sast.tests.test_dataflow_regression import analyze


class SummaryGuardBudgetTests(unittest.TestCase):
    def test_sources_and_unguarded_routes_survive_many_guard_alternatives(self):
        branches = ''.join(f'if (check{i}($v)) {{decode($v);}}' for i in range(40))
        findings, project = analyze(
            'function decode($x){unserialize($x);}'
            'function routes($v,$w){' + branches + 'decode($v); decode($w);}'
            "routes($_POST['a'], $_GET['b']);"
        )
        self.assertTrue(project.converged)
        self.assertTrue(project.summary_evidence_truncated)
        self.assertTrue(findings)
        evidence = [route for finding in findings for route in finding.flow_evidence]
        self.assertEqual(len({r.source_origin for r in evidence}), 2)
        self.assertEqual(len({r.source_origin for r in evidence if not r.review_conditions}), 2)
        self.assertTrue(any(r.review_conditions for r in evidence))


if __name__ == '__main__':
    unittest.main()
