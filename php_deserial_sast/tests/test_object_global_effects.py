"""Small labeled fixtures for object and explicit global side effects."""
import unittest
from php_deserial_sast.tests.test_dataflow_regression import analyze

BOX = "class Box {function set($v){$this->x=$v;} function get(){return $this->x;} function load(){unserialize($this->x);} function wrap($v){$this->set($v);}} "
CASES = {
    'setter': (BOX + "$b=new Box(); $b->set($_GET['x']); unserialize($b->x);", True),
    'safe_setter': (BOX + "$b=new Box(); $b->set('safe'); unserialize($b->x);", False),
    'getter': (BOX + "$b=new Box(); $b->x=$_GET['x']; unserialize($b->get());", True),
    'receiver_sink': (BOX + "$b=new Box(); $b->x=$_GET['x']; $b->load();", True),
    'setter_wrapper': (BOX + "$b=new Box(); $b->wrap($_GET['x']); unserialize($b->x);", True),
    'setter_getter': (BOX + "$b=new Box(); $b->set($_GET['x']); unserialize($b->get());", True),
    'setter_alias': (BOX + "$a=new Box(); $b=$a; $b->set($_GET['x']); unserialize($a->x);", True),
    'getter_alias': (BOX + "$a=new Box(); $b=$a; $a->x=$_GET['x']; unserialize($b->get());", True),
    'separate_instances': (BOX + "$a=new Box(); $b=new Box(); $b->set($_GET['x']); unserialize($a->x);", False),
    'new_instance': (BOX + "$b=new Box(); $b->set($_GET['x']); $b=new Box(); unserialize($b->x);", False),
    'property_case': (BOX + "$b=new Box(); $b->set($_GET['x']); unserialize($b->X);", False),
    'local_overwrite': (BOX + "$b=new Box(); $b->set($_GET['x']); $b->x='safe'; unserialize($b->x);", False),
    'before_effect': (BOX + "$b=new Box(); unserialize($b->x); $b->set($_GET['x']);", False),
    'property_whitespace': (BOX + "$b=new Box(); $b -> x=$_GET['x']; unserialize($b->get());", True),
    'parameter_write': ("function fill($b,$v){$b->x=$v;} $b=new Box(); fill($b,$_GET['x']); unserialize($b->x);", True),
    'parameter_named': ("function fill($b,$v){$b->x=$v;} $b=new Box(); fill(v:$_GET['x'],b:$b); unserialize($b->x);", True),
    'parameter_wrapper': ("function fill($b,$v){$b->x=$v;} function wrap($c,$v){fill($c,$v);} $b=new Box(); wrap($b,$_GET['x']); unserialize($b->x);", True),
    'parameter_getter': ("function getx($b){return $b->x;} $b=new Box(); $b->x=$_GET['x']; unserialize(getx($b));", True),
    'parameter_rebound': ("function fill($b){$b=new Box(); $b->x=$_GET['x'];} $b=new Box(); fill($b); unserialize($b->x);", False),
    'parameter_field': ("function fill($b,$v){$b->x['bad']=$v;} $b=new Box(); fill($b,$_GET['x']); unserialize($b->x['bad']);", True),
    'parameter_sibling': ("function fill($b,$v){$b->x['bad']=$v;} $b=new Box(); fill($b,$_GET['x']); unserialize($b->x['good']);", False),
    'callee_overwrite': ("function fill($b,$v){$b->x=$v; $b->x='safe';} $b=new Box(); fill($b,$_GET['x']); unserialize($b->x);", False),
    'global_write': ("function fill(){$GLOBALS['x']=$_GET['x'];} fill(); unserialize($x);", True),
    'global_read': ("function getx(){return $GLOBALS['x'];} $x=$_GET['x']; unserialize(getx());", True),
    'global_wrapper': ("function wrap(){fill();} function fill(){$GLOBALS['x']=$_GET['x'];} wrap(); unserialize($GLOBALS['x']);", True),
    'global_local_separate': ("function getx(){$x='safe'; return $GLOBALS['x'];} $x=$_GET['x']; unserialize(getx());", True),
    'global_local_not_bound': ("function getx(){$GLOBALS['x']='safe'; return $x;} $x=$_GET['x']; unserialize(getx());", False),
    'global_sibling': ("function fill(){$GLOBALS['x']=$_GET['x'];} fill(); unserialize($GLOBALS['y']);", False),
    'global_overwrite': ("function fill(){$GLOBALS['x']=$_GET['x']; $GLOBALS['x']='safe';} fill(); unserialize($x);", False),
    'global_array': ("function fill(){$GLOBALS['x']['bad']=$_GET['x'];} fill(); unserialize($x['bad']);", True),
}

class ObjectGlobalEffectsTests(unittest.TestCase):
    def test_labeled_cases_eager_and_demand(self):
        for demand in (False, True):
            for name, (code, expected) in CASES.items():
                with self.subTest(name=name, demand=demand):
                    findings, project = analyze(code, False, True, demand)
                    self.assertTrue(project.converged)
                    self.assertEqual(bool(findings), expected)

    def test_effects_remain_explicit_opt_in(self):
        findings, _ = analyze(CASES['setter'][0], False, False)
        self.assertFalse(findings)

    def test_unknown_reassignment_does_not_reuse_parameter_type(self):
        code = BOX + "function endpoint(Box $b){$b=unknown(); $b->load();}"
        _, project = analyze(code)
        engine = project.files['fixture.php']
        call = next(n for nodes in engine.nodes.values() for n in nodes if engine.text(n) == '$b->load()')
        self.assertIsNone(project.resolve(engine, call))
