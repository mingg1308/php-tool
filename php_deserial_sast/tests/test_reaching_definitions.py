"""Behavioral oracles for scalar GEN/KILL across branch joins."""
import unittest
from php_deserial_sast.tests.test_dataflow_regression import analyze
from php_deserial_sast.core.control_flow import coverage


class ReachingDefinitionsTests(unittest.TestCase):
    def test_branch_join_overwrites(self):
        cases = [
            ("if ($_GET['f']) {$x='a';} else {$x='b';}", False),
            ("if ($_GET['f']) {$x='a';} elseif ($_GET['g']) {$x='b';} else {$x='c';}", False),
            ("if ($_GET['f']) {$x='a';} elseif ($_GET['g']) {$x='b';}", True),
            ("if ($_GET['f']) {$x='a';} else {$x=$_POST['b'];}", True),
            ("if ($_GET['f']) {if ($_GET['g']) {$x='a';} else {$x='b';}} else {$x='c';}", False),
            ("if ($_GET['f']) {$x='a';} else {$x .= 'b';}", True),
        ]
        for body, expected in cases:
            with self.subTest(body=body):
                findings, project = analyze("$x=$_GET['x'];" + body + "unserialize($x);")
                self.assertEqual(bool(findings), expected)
                self.assertGreater(coverage(project)["definition_variables"], 0)

    def test_parameter_seed_killed_only_on_all_paths(self):
        for otherwise, expected in [("else {$x='safe';}", False), ("", True)]:
            findings, _ = analyze("function f($x){if ($_GET['f']) {$x='safe';}" + otherwise +
                                  "unserialize($x);} f($_GET['x']);")
            self.assertEqual(bool(findings), expected)

    def test_rhs_and_old_value_remain_visible(self):
        for rhs in ("$x", "$x . 'suffix'", "base64_decode($x)"):
            findings, _ = analyze("$x=$_GET['x']; if ($_GET['f']) {$x=" + rhs +
                                  ";} else {$x='safe';} unserialize($x);")
            self.assertTrue(findings)

    def test_field_and_conditional_write_fallback(self):
        cases = [
            "$x=$_GET['x']; $_GET['f'] && ($x='safe'); unserialize($x);",
            "$x=['v'=>$_GET['x']]; if ($_GET['f']) {$x['v']='safe';} unserialize($x['v']);",
            "$x=$_GET['x']; while ($_GET['f']) {$x='safe';} unserialize($x);",
        ]
        for code in cases:
            with self.subTest(code=code):
                findings, _ = analyze(code)
                self.assertTrue(findings)

    def test_summary_recomputed_without_stale_taint(self):
        findings, project = analyze("""
            function a($x){return b($x);}
            function b($x){if ($_GET['f']) {$x='a';} else {$x='b';} return $x;}
            unserialize(a($_GET['x']));
        """)
        self.assertTrue(project.converged)
        self.assertFalse(findings)
