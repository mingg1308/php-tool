"""End-to-end reachability expectations, not snapshots of graph internals."""
import unittest
from php_deserial_sast.tests.test_dataflow_regression import analyze
from php_deserial_sast.core.control_flow import coverage
from php_deserial_sast.core.taint_engine import TaintEngine


class ControlFlowTests(unittest.TestCase):
    def test_cfg_budget_preserves_finding_with_explicit_fallback(self):
        from unittest.mock import patch
        with patch('php_deserial_sast.core.control_flow.CFG_NODE_LIMIT', 10):
            findings, project = analyze("$items=$_POST['items']; foreach ($items as $v) {unserialize($v);}")
        self.assertTrue(findings)
        self.assertIn('cfg_node_budget', coverage(project)['fallback_reasons'])

    def test_termination_cases(self):
        cases = [
            ("return; unserialize($_GET['x']);", False),
            ("throw new Exception(); unserialize($_GET['x']);", False),
            ("function f($x){return; unserialize($x);} f($_GET['x']);", False),
            ("function f($x){unserialize($x);} return; f($_GET['x']);", False),
            ("function f($x){return 'safe'; return $x;} unserialize(f($_GET['x']));", False),
            ("if ($_GET['flag']) {return;} else {throw new Exception();} unserialize($_GET['x']);", False),
            ("if ($_GET['a']) {return;} elseif ($_GET['b']) {return;} else {return;} unserialize($_GET['x']);", False),
            ("if ($_GET['a']) {return;} elseif ($_GET['b']) {return;} unserialize($_GET['x']);", True),
            ("if ($_GET['flag']) {return;} unserialize($_GET['x']);", True),
            ("return unserialize($_GET['x']);", True),
            ("throw new Exception(unserialize($_GET['x']));", True),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                findings, _ = analyze(code)
                self.assertEqual(bool(findings), expected)

    def test_terminated_write_cannot_reach_join(self):
        for terminal in ("return;", "throw new Exception();"):
            code = "$x='safe'; if ($_GET['flag']) {$x=$_GET['x']; " + terminal + "} unserialize($x);"
            findings, _ = analyze(code)
            self.assertFalse(findings)
        findings, _ = analyze("$x='safe'; if ($_GET['flag']) {$x=$_GET['x'];} unserialize($x);")
        self.assertTrue(findings)

    def test_fallback_does_not_prune_unknown_control_flow(self):
        cases = [
            ("foreach_binding", "foreach ($_GET as &$x) {unserialize($x); break;}"),
            ("goto_statement", "goto target; return; target: unserialize($_GET['x']);"),
        ]
        for kind, code in cases:
            with self.subTest(kind=kind):
                findings, project = analyze(code)
                self.assertTrue(findings)
                self.assertIn(kind, coverage(project)["fallback_reasons"])

    def test_surviving_branch_overwrite(self):
        cases = [
            ("if ($_GET['f']) {return;} else {$x='safe';}", False),
            ("if ($_GET['f']) {$x='safe';} else {return;}", False),
            ("if ($_GET['f']) {return;} elseif ($_GET['g']) {throw new Exception();} else {$x='safe';}", False),
            ("if ($_GET['f']) {$x='safe';}", True),
            ("$_GET['f'] && ($x='safe');", True),
            ("$_GET['f'] || ($x='safe');", True),
            ("$_GET['f'] ?? ($x='safe');", True),
            ("$_GET['f'] ? ($x='safe') : null;", True),
        ]
        for body, expected in cases:
            with self.subTest(body=body):
                findings, _ = analyze("$x=$_GET['x']; " + body + " unserialize($x);")
                self.assertEqual(bool(findings), expected)

    def test_nested_function_is_a_separate_entry(self):
        findings, project = analyze("function outer(){return; function inner(){unserialize($_GET['x']);}}")
        self.assertTrue(findings)
        self.assertEqual(coverage(project)["supported_scopes"], 3)

    def test_inventory_distinguishes_unreachable_from_no_source(self):
        _, project = analyze("return; unserialize($_GET['x']);")
        file = project.files["fixture.php"]
        engine = TaintEngine(file.path, file.source, file.root, project=project, php_version="8.1")
        self.assertFalse(engine.analyze())
        self.assertEqual(engine.sink_inventory[0].disposition, "unreachable_in_scope_cfg")

    def test_dead_try_tail_does_not_resume_after_finally(self):
        for terminal in ("return;", "throw new Exception();"):
            with self.subTest(terminal=terminal):
                findings, _ = analyze("try{" + terminal + " $dead=1;}finally{$cleanup=1;} unserialize($_GET['x']);")
                self.assertFalse(findings)
        findings, _ = analyze("function f($x){try{return 'safe'; $dead=1;}finally{$cleanup=1;} return $x;} unserialize(f($_GET['x']));")
        self.assertFalse(findings)
        findings, _ = analyze("try{if($_GET['flag']){return;} $live=1;}finally{$cleanup=1;} unserialize($_GET['x']);")
        self.assertTrue(findings)
