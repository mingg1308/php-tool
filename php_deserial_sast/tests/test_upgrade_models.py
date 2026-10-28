"""Labeled, minimal cases for the stage-12 model changes."""
import unittest
from unittest.mock import patch

from php_deserial_sast.core.dataflow import Flow
from php_deserial_sast.tests.test_dataflow_regression import analyze


UPGRADE_CASES = {
    'heap_alias_write': ("$a=new Box(); $b=$a; $b->x=$_GET['x']; unserialize($a->x);", True, True),
    'heap_alias_read': ("$a=new Box(); $b=$a; $a->x=$_GET['x']; unserialize($b->x);", True, True),
    'heap_separate_objects': ("$a=new Box(); $b=new Box(); $b->x=$_GET['x']; unserialize($a->x);", False, True),
    'heap_reassignment': ("$a=new Box(); $b=$a; $b->x=$_GET['x']; $a=new Box(); unserialize($a->x);", False, True),
    'heap_old_alias_retained': ("$a=new Box(); $b=$a; $b->x=$_GET['x']; $a=new Box(); unserialize($b->x);", True, True),
    'heap_property_sibling': ("$a=new Box(); $b=$a; $b->bad=$_GET['x']; $a->good='a:0:{}'; unserialize($b->good);", False, True),
    'heap_overwrite': ("$a=new Box(); $b=$a; $a->x=$_GET['x']; $b->x='a:0:{}'; unserialize($a->x);", False, True),
    'finally_override_safe': ("function f($x){try{return $x;}finally{return 'a:0:{}';}} unserialize(f($_GET['x']));", False, False),
    'finally_override_tainted': ("function f($x){try{return 'a:0:{}';}finally{return $x;}} unserialize(f($_GET['x']));", True, False),
    'finally_conditional_return': ("function f($x){try{return $x;}finally{if(rand())return 'a:0:{}';}} unserialize(f($_GET['x']));", True, False),
    'finally_branch_override': ("function f($x){try{return $x;}finally{if(rand())return 'a:0:{}';else return 'a:0:{}';}} unserialize(f($_GET['x']));", False, False),
    'finally_throw_override': ("function f($x){try{return $x;}finally{throw new Exception();}} unserialize(f($_GET['x']));", False, False),
    'finally_nested_override': ("function f($x){try{try{return $x;}finally{return $x;}}finally{return 'a:0:{}';}} unserialize(f($_GET['x']));", False, False),
    'finally_preserve_return_value': ("function f($x){try{return $x;}finally{$x='a:0:{}';}} unserialize(f($_GET['x']));", True, False),
}


class UpgradeModelTests(unittest.TestCase):
    def test_labeled_cases(self):
        for name, (code, expected, effects) in UPGRADE_CASES.items():
            with self.subTest(name=name):
                findings, project = analyze(code, False, effects)
                self.assertTrue(project.converged)
                self.assertEqual(bool(findings), expected)

    def test_heap_remains_opt_in(self):
        code = UPGRADE_CASES['heap_alias_write'][0]
        _, project = analyze(code, False, False)
        self.assertFalse(project.files['fixture.php'].heap_events)

    def test_bind_groups_reuse_exact_tuple(self):
        class CountedTuple(tuple):
            visits = 0
            def __iter__(self):
                self.visits += 1
                return super().__iter__()
        _, project = analyze('function f($x){return $x;} f($_GET["x"]);')
        engine = project.files['fixture.php']
        target = project.functions[0]
        call = next(n for n in engine.nodes[-1] if n.type == 'function_call_expression')
        shared = CountedTuple((Flow('request', 'request'),))
        flows = tuple(Flow('parameter', 'f', 0, (str(i),)) for i in range(100))
        with patch.object(engine, 'evaluate', return_value=shared):
            result = engine.bind(flows, target, call, False)
        self.assertEqual(shared.visits, 1)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].origin, 'request')

    def test_bind_groups_do_not_merge_different_flags(self):
        _, project = analyze('function f($x){return $x;} f($_GET["x"]);')
        engine = project.files['fixture.php']
        call = next(n for n in engine.nodes[-1] if n.type == 'function_call_expression')
        flows = (Flow('parameter', 'f', 0), Flow('parameter', 'f', 0, uncertain=True),
                 Flow('parameter', 'f', 0, blocked_phar=True))
        with patch.object(engine, 'evaluate', return_value=(Flow('request', 'request'),)):
            result = engine.bind(flows, project.functions[0], call, False)
        self.assertEqual({(f.uncertain, f.blocked_phar) for f in result},
                         {(False, False), (True, False), (False, True)})
