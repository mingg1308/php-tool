"""Check optimized effect binding against the previous merge semantics."""
import unittest
from dataclasses import replace
from unittest.mock import patch
from php_deserial_sast.tests.test_dataflow_regression import analyze
from php_deserial_sast.core.dataflow import Flow, merge, trace_steps

class EffectBindingCompactionTests(unittest.TestCase):
    def test_repeated_global_paths_keep_identity_and_shortest_trace(self):
        _, project = analyze("function identity($v){return $v;} identity($_GET['x']);")
        engine = project.files['fixture.php']
        call = next(n for nodes in engine.nodes.values() for n in nodes if engine.text(n) == "identity($_GET['x'])")
        target = project.resolve(engine, call)
        step = engine.step(call, "source")
        sources = tuple(Flow("request", "source" + str(i), steps=(step,)) for i in range(20))
        flows = tuple(Flow("global", "$shared", fields=(str(i),), steps=(step,) * (40-i%40), blocked_phar=bool(i%2)) for i in range(80))
        expected = ()
        for flow in flows:
            bound = engine._append(sources, call, "Global value bound at the caller.", "$shared", uncertain=True)
            bound = tuple(replace(value, blocked_phar=value.blocked_phar or flow.blocked_phar,
                                 steps=trace_steps(value.steps + flow.steps)) for value in bound)
            expected = merge(expected, bound)
        with patch.object(engine, "global_visible", return_value=True), patch.object(engine, "read", return_value=sources):
            actual = engine.bind(flows, target, call, True)
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 40)

class DemandEffectTests(unittest.TestCase):
    def test_unused_effect_is_not_evaluated(self):
        code = "function unused(&$v){$v=$_GET['x'];} unserialize($_POST['x']);"
        _, project = analyze(code, False, True, True)
        target = next(f for f in project.functions if f.name == "unused")
        self.assertNotIn(target.key, project.effect_demands)
        self.assertFalse(project.effects[target.key])

    def test_return_and_effect_demands_do_not_mask_each_other(self):
        code = "function fill(&$v){$v=$_GET['x']; return 'safe';} function wrapper(){ $v=''; $r=fill($v); unserialize($r); unserialize($v); } wrapper();"
        eager, eager_project = analyze(code, False, True, False)
        demand, demand_project = analyze(code, False, True, True)
        self.assertTrue(eager_project.converged and demand_project.converged)
        self.assertTrue(demand)
        def signature(findings):
            return {(f.location.start_line,f.location.start_col,f.rule_id) for f in findings}
        self.assertEqual(signature(eager), signature(demand))
        target = next(f for f in demand_project.functions if f.name == "fill")
        self.assertIn(target.key, demand_project.return_demands)
        self.assertIn(target.key, demand_project.effect_demands)
