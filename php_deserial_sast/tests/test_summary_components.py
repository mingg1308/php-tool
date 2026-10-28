"""Scheduling must reduce repeated work without discarding summary facts."""
import unittest
from unittest.mock import patch

from php_deserial_sast.core.dataflow import summary_components
from php_deserial_sast.tests.test_dataflow_regression import analyze


SCHEMA = """
function schema($value,$args) {
    if(isset($args['anyOf'])) $value=schema($value,$args['anyOf']);
    if(isset($args['oneOf'])) $value=schema($value,$args['oneOf']);
    if(isset($args['items'])) $value=schema($value,$args['items']);
    if(rand()) return $args['default'];
    return $value;
}
"""


class SummaryComponentTests(unittest.TestCase):
    def test_deep_graph_without_python_recursion(self):
        graph = {i: [i + 1] for i in range(3000)}
        graph[3000] = []
        self.assertEqual(summary_components(graph), [[i] for i in range(3000, -1, -1)])

    def test_cycles_and_disconnected_functions(self):
        graph = {'entry': ['a'], 'a': ['b'], 'b': ['a', 'leaf'],
                 'leaf': [], 'self': ['self'], 'isolated': []}
        components = summary_components(graph)
        positions = {key: i for i, group in enumerate(components) for key in group}
        self.assertEqual(sum(map(len, components)), len(graph))
        self.assertEqual(positions['a'], positions['b'])
        self.assertLess(positions['leaf'], positions['a'])
        self.assertLess(positions['a'], positions['entry'])

    def test_acyclic_functions_evaluated_once(self):
        code = ''.join(f'function f{i}($x){{return f{i+1}($x);}}' for i in range(100))
        code += 'function f100($x){return $x;} unserialize(f0($_GET["x"]));'
        findings, project = analyze(code, False, False)
        self.assertTrue(findings)
        self.assertTrue(project.converged)
        self.assertEqual(project.summary_evaluations, 101)

    def test_recursive_fields_preserve_facts_and_isolate_callers(self):
        wrappers = ''.join(f'function wrapper{i}($v,$a){{return schema($v,$a);}}' for i in range(30))
        for value, schema, expected in [('$_GET["x"]', '[]', True),
                                        ("'a:0:{}'", '[]', False),
                                        ("'a:0:{}'", "['items'=>['default'=>$_GET['x']]]", True)]:
            with self.subTest(value=value, schema=schema):
                code = wrappers + SCHEMA + f'unserialize(wrapper0({value},{schema}));'
                findings, current = analyze(code, False, False)
                # One component reproduces the previous global worklist.
                with patch('php_deserial_sast.core.dataflow.summary_components',
                           side_effect=lambda graph: [list(graph)]):
                    old_findings, previous = analyze(code, False, False)
                self.assertTrue(current.converged and previous.converged)
                self.assertEqual(bool(findings), expected)
                self.assertEqual(bool(findings), bool(old_findings))
                self.assertEqual(current._signature(current.returns, current.sinks),
                                 previous._signature(previous.returns, previous.sinks))
                self.assertLess(current.summary_evaluations, previous.summary_evaluations)

    def test_recursive_sink_and_reference_effect_propagation(self):
        code = '''function caller(&$x,$v){a($x,$v);}
        function a(&$x,$v){if(rand()) b($x,$v); $x=$v;}
        function b(&$x,$v){if(rand()) a($x,$v); unserialize($v);}
        $x='safe'; caller($x,$_GET['x']); unserialize($x);'''
        findings, current = analyze(code)
        with patch('php_deserial_sast.core.dataflow.summary_components',
                   side_effect=lambda graph: [list(graph)]):
            old_findings, previous = analyze(code)
        self.assertTrue(current.converged and previous.converged)
        self.assertEqual(len(findings), len(old_findings))
        self.assertTrue(findings)
        self.assertEqual(current._signature(current.returns, current.sinks),
                         previous._signature(previous.returns, previous.sinks))
        signature = lambda p: {k: {(i, fields, flow.key()) for i, fields, flows in effects for flow in flows}
                               for k, effects in p.effects.items()}
        self.assertEqual(signature(current), signature(previous))


if __name__ == '__main__':
    unittest.main()
