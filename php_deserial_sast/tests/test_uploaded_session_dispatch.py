"""Uploaded serialized objects and their conditional later dispatch."""

import tempfile
import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.scanner import PHPDeserializationScanner
from php_deserial_sast.core.deserialized_dispatch import _reachable_sinks


class UploadedSessionDispatchTests(unittest.TestCase):
    def test_session_method_search_marks_depth_limit(self):
        class Graph:
            def get_successors(self, node):
                return {'Demo::run': [('next', None)],
                        'next': [('later', None)]}.get(node, [])

        owner = SimpleNamespace(full_name='Demo', name='Demo')
        method = SimpleNamespace(name='run')
        sinks, truncated = _reachable_sinks(Graph(), owner, method, max_depth=1)
        self.assertEqual(sinks, [])
        self.assertTrue(truncated)

    def scan(self, files, extra_files=None):
        with tempfile.TemporaryDirectory() as directory:
            for name, source in files.items():
                path = Path(directory, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('<?php\n' + source, encoding='utf-8')
            for name, content in (extra_files or {}).items():
                path = Path(directory, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding='utf-8')
            return PHPDeserializationScanner(ScannerConfig(
                target_path=directory, enable_llm=False, php_version='7.3',
            )).scan()

    def test_upload_to_session_method_and_gadget_properties(self):
        result = self.scan({
            'load.php': "$data=file_get_contents($_FILES['save']['tmp_name']); $loaded=@unserialize($data); $_SESSION['hero']=$loaded;",
            'game.php': "$_SESSION['hero']->run(); $_SESSION['hero']->fight();",
            'classes.php': (
                'class Calculator {public $expression; public function run(){eval($this->expression);}}'
                'class Trainer {public function fight(){return 0;}}'
                'class TrumCuoi extends Trainer {public function fight(){return 1;}}'
                'class Database {public $conn; function __destruct(){$this->conn->close();}}'
                'class Logger {public $filepath; function close(){system("rm " . $this->filepath);}}'
            ),
        })
        self.assertFalse(result.errors)
        flow = next(f for f in result.findings if f.rule_id == 'php-unserialize-tainted-input')
        self.assertEqual(flow.flow_evidence[0].source_kind, 'request')
        dispatch = flow.metadata['deserialized_session_dispatch']
        self.assertFalse(dispatch['exploitability_verified'])
        run = next(call for call in dispatch['calls'] if call['method'] == 'run')
        calculator = next(cls for cls in run['candidate_classes'] if cls['class'] == 'Calculator')
        self.assertTrue(any(sink['function'] == 'eval' for sink in calculator['dangerous_sinks']))
        session_routes = [route for route in result.routes
                          if route.route_kind == 'candidate_session_dispatch'
                          and route.entry_class == 'Calculator']
        self.assertTrue(session_routes)
        self.assertTrue(all(route.status == 'conditional' and not route.runtime_verified
                            and route.session_key == 'hero' and route.store and route.trigger
                            for route in session_routes))
        fight = next(call for call in dispatch['calls'] if call['method'] == 'fight')
        override = next(cls for cls in fight['candidate_classes'] if cls['class'] == 'TrumCuoi')
        self.assertTrue(override['overrides_parent_method'])
        chain = next(chain for chain in result.gadget_chains if chain.entry_class == 'Database'
                     and chain.sink_function == 'system')
        self.assertEqual(set(chain.candidate_serialized_properties), {'conn', 'filepath'})

    def test_overwritten_object_is_not_linked_to_session_dispatch(self):
        result = self.scan({
            'load.php': "$loaded=unserialize($_GET['save']); $loaded='safe'; $_SESSION['hero']=$loaded;",
            'game.php': "$_SESSION['hero']->run(); class Calculator {function run(){eval('1');}}",
        })
        self.assertFalse(result.errors)
        flow = next(f for f in result.findings if f.rule_id == 'php-unserialize-tainted-input')
        self.assertNotIn('deserialized_session_dispatch', flow.metadata)
        self.assertFalse(any(route.route_kind == 'candidate_session_dispatch'
                             for route in result.routes))

    def test_dispatch_candidate_cap_reports_unexamined_classes(self):
        classes = ' '.join('class Candidate%d { function run() {} }' % index
                           for index in range(30))
        result = self.scan({
            'load.php': "$obj=unserialize($_POST['data']); $_SESSION['hero']=$obj;",
            'play.php': "$_SESSION['hero']->run();",
            'classes.php': classes,
        })
        finding = next(f for f in result.findings
                       if f.rule_id == 'php-unserialize-tainted-input')
        call = finding.metadata['deserialized_session_dispatch']['calls'][0]
        self.assertEqual(call['candidate_class_count'], 24)
        self.assertEqual(call['candidate_classes_unexamined'], 6)
        self.assertTrue(call['candidate_classes_truncated'])

    def test_array_element_saved_to_session_and_rendered_later(self):
        result = self.scan({
            'load.php': (
                "switch ($_GET['action']) { case 'load': "
                "$data=file_get_contents($_FILES['data']['tmp_name']); "
                "$parts=explode('|',$data); $loaded=unserialize($parts[1]); "
                "$students[0]=$loaded; $_SESSION['students']=$students; break; }"
            ),
            'view.php': "foreach ($_SESSION['students'] as $student) { echo \"{$student}\"; }",
            'classes.php': "class Router {public $host; function __toString(){return system($this->host);}}",
        })
        self.assertFalse(result.errors)
        flow = next(f for f in result.findings if f.rule_id == 'php-unserialize-tainted-input')
        dispatch = flow.metadata['deserialized_session_dispatch']
        render = dispatch['render_sites'][0]
        self.assertEqual(render['session_key'], 'students')
        self.assertTrue(any(candidate['class'] == 'Router'
                            and any(sink['function'] == 'system' for sink in candidate['dangerous_sinks'])
                            for candidate in render['candidate_classes']))
        self.assertTrue(render['cross_request_execution_unverified'])

    def test_overwritten_array_element_does_not_link_to_session(self):
        result = self.scan({
            'load.php': ("$loaded=unserialize($_GET['data']); $items[0]=$loaded; "
                         "$items='safe'; $_SESSION['students']=$items;"),
            'view.php': "foreach ($_SESSION['students'] as $student) { echo $student; }",
        })
        flow = next(f for f in result.findings if f.rule_id == 'php-unserialize-tainted-input')
        self.assertNotIn('deserialized_session_dispatch', flow.metadata)

    def test_entrypoint_glob_guard_excludes_router_only_in_level_two(self):
        common = {
            'load.php': ("$loaded=unserialize($_GET['data']); $items[0]=$loaded; "
                         "$_SESSION['students']=$items;"),
            'view.php': "foreach ($_SESSION['students'] as $student) { echo $student; }",
            'libs/router.php': 'class Router {function __toString(){return system("id");}}',
        }
        for guard, expected in [('', 'included'),
                                ("if ($filename !== 'libs/router.php') ", 'excluded'),
                                ("if ($_GET['allow']) ", 'unknown')]:
            with self.subTest(guard=guard):
                files = dict(common)
                files['index.php'] = ("foreach (glob('libs/*.php') as $filename) { "
                                      + guard + "include($filename); } "
                                      "include('load.php'); include('view.php');")
                result = self.scan(files)
                self.assertFalse(result.errors)
                flow = next(f for f in result.findings if f.rule_id == 'php-unserialize-tainted-input')
                render = flow.metadata['deserialized_session_dispatch']['render_sites'][0]
                router = next((c for c in render['candidate_classes'] if c['class'] == 'Router'), None)
                if expected == 'excluded':
                    self.assertIsNone(router)
                    self.assertTrue(any(c['class'] == 'Router' for c in render['excluded_candidates']))
                else:
                    self.assertIsNotNone(router)
                    self.assertEqual(router['class_loading'], expected)

    def test_method_dispatch_excludes_class_skipped_by_bootstrap(self):
        result = self.scan({
            'load.php': "$loaded=unserialize($_GET['data']); $_SESSION['hero']=$loaded;",
            'game.php': "$_SESSION['hero']->run();",
            'libs/calculator.php': 'class Calculator {function run(){eval("1");}}',
            'index.php': ("foreach (glob('libs/*.php') as $filename) { "
                          "if ($filename !== 'libs/calculator.php') include($filename); } "
                          "include('load.php'); include('game.php');"),
        })
        self.assertFalse(result.errors)
        flow = next(f for f in result.findings
                    if f.rule_id == 'php-unserialize-tainted-input')
        call = flow.metadata['deserialized_session_dispatch']['calls'][0]
        self.assertFalse(any(c['class'] == 'Calculator'
                             for c in call['candidate_classes']))
        self.assertTrue(any(c['class'] == 'Calculator'
                            for c in call['excluded_candidates']))

    def test_separate_entrypoints_load_same_session_class(self):
        result = self.scan({
            'load.php': "$hero=unserialize($_POST['hero']); $_SESSION['hero']=$hero;",
            'play.php': "$_SESSION['hero']->run();",
            'classes.php': 'class Calculator {function run(){eval("1");}}',
            'load_route.php': "session_start(); include('classes.php'); include('load.php');",
            'play_route.php': "session_start(); include('classes.php'); include('play.php');",
        })
        self.assertFalse(result.errors)
        flow = next(f for f in result.findings
                    if f.rule_id == 'php-unserialize-tainted-input')
        call = flow.metadata['deserialized_session_dispatch']['calls'][0]
        calculator = next(c for c in call['candidate_classes']
                          if c['class'] == 'Calculator')
        self.assertEqual(calculator['class_loading'], 'included')
        self.assertEqual(len(call['bootstrap_entrypoints']), 2)
        self.assertTrue(call['session_bootstrap']['session_start_on_both_routes'])
        self.assertFalse(call['session_bootstrap']['session_identity_and_request_order_verified'])
        self.assertTrue(call['cross_request_execution_unverified'])
        route = next(route for route in result.routes
                     if route.route_kind == 'candidate_session_dispatch'
                     and route.entry_class == 'Calculator')
        self.assertEqual(len(route.bootstrap_entrypoints), 2)
        self.assertTrue(route.session_start_on_both_routes)
        self.assertFalse(route.runtime_verified)

    def test_self_bootstrapped_load_endpoint_pairs_with_reader(self):
        result = self.scan({
            'load.php': ("session_start(); include('classes.php'); "
                         "$hero=unserialize($_POST['hero']); $_SESSION['hero']=$hero;"),
            'play.php': "$_SESSION['hero']->run();",
            'index.php': "session_start(); include('classes.php'); include('play.php');",
            'classes.php': 'class Calculator {function run(){eval("1");}}',
        })
        self.assertFalse(result.errors)
        flow = next(f for f in result.findings if f.rule_id == 'php-unserialize-tainted-input')
        call = flow.metadata['deserialized_session_dispatch']['calls'][0]
        calculator = next(c for c in call['candidate_classes'] if c['class'] == 'Calculator')
        self.assertEqual(calculator['class_loading'], 'included')
        self.assertEqual(len(call['bootstrap_entrypoints']), 2)
        self.assertTrue(call['session_bootstrap']['session_start_on_both_routes'])
        self.assertFalse(call['session_bootstrap']['session_identity_and_request_order_verified'])

    def test_dormant_session_start_does_not_make_file_an_entrypoint(self):
        result = self.scan({
            'load.php': ("function dormant(){session_start();} "
                         "$hero=unserialize($_POST['hero']); $_SESSION['hero']=$hero;"),
            'play.php': "$_SESSION['hero']->run();",
            'index.php': "session_start(); include('classes.php'); include('play.php');",
            'classes.php': 'class Calculator {function run(){eval("1");}}',
        })
        flow = next(f for f in result.findings if f.rule_id == 'php-unserialize-tainted-input')
        call = flow.metadata['deserialized_session_dispatch']['calls'][0]
        self.assertFalse(call['session_bootstrap']['session_start_on_both_routes'])
        self.assertFalse(call['bootstrap_entrypoints'])

    def test_fixed_magic_constant_includes_connect_both_routes(self):
        result = self.scan({
            'load.php': ("session_start(); require __DIR__ . '/classes.php'; "
                         "$hero=unserialize($_POST['hero']); $_SESSION['hero']=$hero;"),
            'play.php': "$_SESSION['hero']->run();",
            'index.php': ("session_start(); require dirname(__FILE__) . '/classes.php'; "
                          "include __DIR__ . '/play.php';"),
            'classes.php': 'class Calculator {function run(){eval("1");}}',
        })
        self.assertFalse(result.errors)
        flow = next(f for f in result.findings if f.rule_id == 'php-unserialize-tainted-input')
        call = flow.metadata['deserialized_session_dispatch']['calls'][0]
        calculator = next(c for c in call['candidate_classes'] if c['class'] == 'Calculator')
        self.assertEqual(calculator['class_loading'], 'included')
        self.assertTrue(call['session_bootstrap']['session_start_on_both_routes'])

    def test_request_dependent_include_does_not_connect_reader(self):
        result = self.scan({
            'load.php': ("session_start(); include('classes.php'); "
                         "$hero=unserialize($_POST['hero']); $_SESSION['hero']=$hero;"),
            'play.php': "$_SESSION['hero']->run();",
            'index.php': ("session_start(); include('classes.php'); "
                          "include __DIR__ . '/' . $_GET['page'];"),
            'classes.php': 'class Calculator {function run(){eval("1");}}',
        })
        flow = next(f for f in result.findings if f.rule_id == 'php-unserialize-tainted-input')
        call = flow.metadata['deserialized_session_dispatch']['calls'][0]
        self.assertFalse(call['session_bootstrap']['session_start_on_both_routes'])
        self.assertFalse(call['bootstrap_entrypoints'])

    def test_shadowed_dirname_does_not_prove_class_loading(self):
        result = self.scan({
            'load.php': ("session_start(); include('classes.php'); "
                         "$hero=unserialize($_POST['hero']); $_SESSION['hero']=$hero;"),
            'play.php': "$_SESSION['hero']->run();",
            'index.php': ("namespace Demo; function dirname($path){return '/other';} "
                          "session_start(); include dirname(__FILE__) . '/classes.php'; "
                          "include __DIR__ . '/play.php';"),
            'classes.php': 'class Calculator {function run(){eval("1");}}',
        })
        flow = next(f for f in result.findings if f.rule_id == 'php-unserialize-tainted-input')
        call = flow.metadata['deserialized_session_dispatch']['calls'][0]
        calculator = next(c for c in call['candidate_classes'] if c['class'] == 'Calculator')
        self.assertEqual(calculator['class_loading'], 'unknown')

    def test_conditional_literal_include_does_not_prove_class_loading(self):
        result = self.scan({
            'load.php': ("session_start(); include('classes.php'); "
                         "$hero=unserialize($_POST['hero']); $_SESSION['hero']=$hero;"),
            'play.php': "$_SESSION['hero']->run();",
            'index.php': ("session_start(); if ($_GET['enable']) "
                          "{ include __DIR__ . '/classes.php'; } "
                          "include __DIR__ . '/play.php';"),
            'classes.php': 'class Calculator {function run(){eval("1");}}',
        })
        flow = next(f for f in result.findings if f.rule_id == 'php-unserialize-tainted-input')
        call = flow.metadata['deserialized_session_dispatch']['calls'][0]
        calculator = next(c for c in call['candidate_classes'] if c['class'] == 'Calculator')
        self.assertEqual(calculator['class_loading'], 'unknown')

    def test_class_included_after_sink_and_render_is_not_proven_loaded(self):
        result = self.scan({
            'load.php': "$hero=unserialize($_POST['hero']); $_SESSION['hero']=$hero;",
            'play.php': "$_SESSION['hero']->run();",
            'classes.php': 'class Calculator {function run(){eval("1");}}',
            'index.php': ("include('load.php'); include('play.php'); "
                          "include('classes.php');"),
        })
        finding = next(f for f in result.findings
                       if f.rule_id == 'php-unserialize-tainted-input')
        call = finding.metadata['deserialized_session_dispatch']['calls'][0]
        calculator = next(c for c in call['candidate_classes']
                          if c['class'] == 'Calculator')
        self.assertEqual(calculator['class_loading'], 'unknown')
        route = next(route for route in result.routes
                     if route.route_kind == 'candidate_session_dispatch'
                     and route.entry_class == 'Calculator')
        self.assertIn('class_loading_unverified', route.missing_edges)

    def test_conditional_sink_include_before_class_does_not_prove_loading(self):
        result = self.scan({
            'load.php': "$hero=unserialize($_POST['hero']); $_SESSION['hero']=$hero;",
            'play.php': "$_SESSION['hero']->run();",
            'classes.php': 'class Calculator {function run(){eval("1");}}',
            'index.php': ("if ($_GET['load']) include('load.php'); "
                          "if ($_GET['play']) include('play.php'); "
                          "include('classes.php');"),
        })
        finding = next(f for f in result.findings
                       if f.rule_id == 'php-unserialize-tainted-input')
        call = finding.metadata['deserialized_session_dispatch']['calls'][0]
        calculator = next(c for c in call['candidate_classes']
                          if c['class'] == 'Calculator')
        self.assertEqual(calculator['class_loading'], 'unknown')

    def test_composer_psr4_is_candidate_only_when_loader_precedes_routes(self):
        common = {
            'load.php': "$hero=unserialize($_POST['hero']); $_SESSION['hero']=$hero;",
            'play.php': "$_SESSION['hero']->run();",
            'src/Gadget.php': ('namespace App; class Gadget {'
                               'function run(){system("id");}}'),
            'vendor/autoload.php': '',
        }
        composer = json.dumps({'autoload': {'psr-4': {'App\\': 'src/'}}})
        for loader_first, expected in ((True, 'composer_autoload_candidate'),
                                       (False, 'unknown')):
            with self.subTest(loader_first=loader_first):
                index = ("require('vendor/autoload.php'); " if loader_first else '')
                index += "include('load.php'); include('play.php');"
                if not loader_first:
                    index += "require('vendor/autoload.php');"
                result = self.scan({**common, 'index.php': index},
                                   extra_files={'composer.json': composer})
                finding = next(f for f in result.findings
                               if f.rule_id == 'php-unserialize-tainted-input')
                call = finding.metadata['deserialized_session_dispatch']['calls'][0]
                gadget = next(c for c in call['candidate_classes']
                              if c['class'] == 'App\\Gadget')
                self.assertEqual(gadget['class_loading'], expected)
                route = next(route for route in result.routes
                             if route.route_kind == 'candidate_session_dispatch'
                             and route.entry_class == 'App\\Gadget')
                self.assertEqual(route.class_loading, expected)
                self.assertFalse(route.runtime_verified)
        invalid = json.dumps({'autoload': {'psr-4': {'App': 'src/'}}})
        result = self.scan({**common, 'index.php': (
            "require('vendor/autoload.php'); include('load.php'); include('play.php');")},
            extra_files={'composer.json': invalid})
        finding = next(f for f in result.findings
                       if f.rule_id == 'php-unserialize-tainted-input')
        call = finding.metadata['deserialized_session_dispatch']['calls'][0]
        gadget = next(c for c in call['candidate_classes'] if c['class'] == 'App\\Gadget')
        self.assertEqual(gadget['class_loading'], 'unknown')

    def test_definite_session_replacement_blocks_later_method_candidate(self):
        result = self.scan({
            'load.php': "$hero=unserialize($_POST['hero']); $_SESSION['hero']=$hero;",
            'play.php': "$_SESSION['hero']='safe'; $_SESSION['hero']->run();",
            'classes.php': 'class Calculator {function run(){eval("1");}}',
        })
        self.assertFalse(result.errors)
        flow = next(f for f in result.findings
                    if f.rule_id == 'php-unserialize-tainted-input')
        self.assertNotIn('deserialized_session_dispatch', flow.metadata)

    def test_conditional_session_replacement_keeps_candidate(self):
        result = self.scan({
            'load.php': "$hero=unserialize($_POST['hero']); $_SESSION['hero']=$hero;",
            'play.php': "if ($_GET['reset']) $_SESSION['hero']='safe'; $_SESSION['hero']->run();",
            'classes.php': 'class Calculator {function run(){eval("1");}}',
        })
        self.assertFalse(result.errors)
        flow = next(f for f in result.findings
                    if f.rule_id == 'php-unserialize-tainted-input')
        self.assertIn('deserialized_session_dispatch', flow.metadata)


if __name__ == '__main__':
    unittest.main()
