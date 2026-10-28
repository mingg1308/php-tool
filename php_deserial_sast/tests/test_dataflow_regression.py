"""Behavioral regression cases, independently usable by external PHP analyzers."""
import unittest

from php_deserial_sast.core.parser import PHPParser
from php_deserial_sast.core.dataflow import FlowProject
from php_deserial_sast.core.taint_engine import TaintEngine
from php_deserial_sast.core.ast_visitor import ASTVisitor
from php_deserial_sast.core.symbol_table import ProjectSymbolTable


CASES = {
    "direct": ("unserialize($_GET['x']);", True),
    "constant": ("unserialize('a:0:{}');", False),
    "overwrite": ("$v=$_GET['x']; $v='a:0:{}'; unserialize($v);", False),
    "array_sibling": ("$a=['bad'=>$_GET['x'],'good'=>'a:0:{}']; unserialize($a['good']);", False),
    "array_write": ("$a['bad']=$_GET['x']; unserialize($a['bad']);", True),
    "branch_join": ("$v='a:0:{}'; if ($_GET['flag']) {$v=$_GET['x'];} unserialize($v);", True),
    "branch_sibling": ("$v='a:0:{}'; if ($_GET['flag']) {$v=$_GET['x'];} else {unserialize($v);}", False),
    "restricted": ("unserialize($_GET['x'], ['allowed_classes'=>false]);", False),
    "empty_allowlist": ("unserialize($_GET['x'], ['allowed_classes'=>[]]);", False),
    "named_reordered": ("unserialize(options: ['allowed_classes'=>true], data: $_GET['x']);", True),
    "named_restricted": ("unserialize(options: ['allowed_classes'=>false], data: $_GET['x']);", False),
    "foreach_value": ("foreach ($_POST['items'] as $value) {unserialize($value);}", True),
    "foreach_pair": ("foreach ($_POST['items'] as $key=>$value) {unserialize($value);}", True),
    "foreach_constant": ("foreach (['a:0:{}'] as $value) {unserialize($value);}", False),
    "foreach_overwrite": ("foreach ($_POST['items'] as $value) {$value='a:0:{}'; unserialize($value);}", False),
    "filter_input": ("unserialize(filter_input(INPUT_GET, 'x'));", True),
    "filter_input_integer": ("unserialize(filter_input(INPUT_GET, 'x', FILTER_VALIDATE_INT));", False),
    "input_stream": ("$h=fopen('php://input','r'); unserialize(stream_get_contents($h));", True),
    "input_body": ("unserialize(file_get_contents('php://input'));", True),
    "unknown_is_function": ("unserialize(is_custom_decode($_GET['x']));", True),
    "known_numeric": ("unserialize((string)intval($_GET['x']));", False),
    "method_not_builtin": ("unserialize($obj->strlen($_GET['x']));", True),
    "function_call": ("function decode($s){unserialize($s);} decode($_GET['x']);", True),
    "safe_function_call": ("function decode($s){unserialize($s);} decode('a:0:{}');", False),
    "named_user_call": ("function decode($unused,$s){unserialize($s);} decode(s:$_GET['x'],unused:1);", True),
    "separate_calls": ("function identity($s){return $s;} $bad=identity($_GET['x']); unserialize(identity('a:0:{}'));", False),
    "imported_builtin": ("namespace A; use function unserialize as restore; restore($_GET['x']);", True),
    "imported_user_function": ("namespace B {function decode($s){unserialize($s);}} namespace A {use function B\\decode as restore; restore($_GET['x']);}", True),
    "upload_tmp_path": ("unserialize($_FILES['upload']['tmp_name']);", False),
    "upload_tmp_contents": ("unserialize(file_get_contents($_FILES['upload']['tmp_name']));", True),
    "upload_tmp_contents_alias": ("$path=$_FILES['upload']['tmp_name']; $data=file_get_contents($path); unserialize($data);", True),
    "upload_tmp_alias_overwritten": ("$path=$_FILES['upload']['tmp_name']; $path='/var/app/safe.dat'; unserialize(file_get_contents($path));", False),
    "upload_filename": ("unserialize($_FILES['upload']['name']);", True),
    "explode_string": ("$v=explode('|', $_GET['data']); unserialize($v[1]);", True),
    "explode_separator_only": ("$v=explode($_GET['separator'], 'a:0:{}'); unserialize($v[0]);", False),
    "recursive_call": ("function a($s){b($s);} function b($s){if(rand())a($s); unserialize($s);} a($_GET['x']);", True),
    "typed_method": ("class Decoder {function load($x){unserialize($x);}} function endpoint(Decoder $d){$d->load($_GET['x']);}", True),
    "framework_request": ("use Symfony\\Component\\HttpFoundation\\Request; function endpoint(Request $r){unserialize($r->getContent());}", True),
    "ordinary_get_method": ("class Store {function get(){return 'a:0:{}';}} function endpoint(Store $s){unserialize($s->get());}", False),
}


def analyze(code, experimental_foreach_cfg=True, experimental_side_effects=True, experimental_demand_summaries=False):
    path = "fixture.php"
    parser = PHPParser()
    root, source = parser.parse_source("<?php\n" + code)
    if root.has_error:
        raise AssertionError("Fixture must parse without recovery")
    symbols = ProjectSymbolTable()
    ASTVisitor(symbols, path, source).extract_all(root)
    project = FlowProject({path: (root, source)}, symbols,
                          experimental_foreach_cfg=experimental_foreach_cfg,
                          experimental_side_effects=experimental_side_effects,
                          experimental_demand_summaries=experimental_demand_summaries)
    project.build()
    engine = TaintEngine(path, source, root, project=project, php_version="8.1")
    return engine.analyze(), project


class DataflowRegression(unittest.TestCase):
    def test_cases(self):
        for name, (code, expected) in CASES.items():
            with self.subTest(name=name):
                findings, project = analyze(code)
                self.assertTrue(project.converged)
                self.assertEqual(bool(findings), expected)

    def test_long_acyclic_call_chain(self):
        code = "function f0($x){unserialize($x);}\n"
        code += "\n".join(f"function f{i}($x){{f{i-1}($x);}}" for i in range(1, 40))
        findings, project = analyze(code + "\nf39($_GET['x']);")
        self.assertTrue(project.converged)
        self.assertTrue(findings)

    def test_augmented_assignment_chain(self):
        for initial, expected in [("$_GET['x']", True), ("'safe'", False)]:
            findings, project = analyze("$v=" + initial + ";" + "$v .= 'x';" * 40 + "unserialize($v);")
            self.assertTrue(project.converged)
            self.assertEqual(bool(findings), expected)

    def test_rule_inside_respects_function_boundary(self):
        from php_deserial_sast.rules.engine import Rule, RuleEngine
        engine = RuleEngine()
        engine.rules = [Rule({"id": "inside", "pattern": "unserialize($X)",
                             "pattern-inside": "function __wakeup(...) { ... }"})]
        code = "<?php class C {function __wakeup(){unserialize($this->data); $f=function(){unserialize($_GET['x']);};} function other(){unserialize($_GET['x']);}}"
        root, source = PHPParser().parse_source(code)
        findings = engine.evaluate_file("fixture.php", source, root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata["bindings"]["$X"], "$this->data")

    def test_binary_string_preserves_original_source(self):
        source = b"<?php $v='a\x00b';\nunserialize($_GET['x']);"
        root, original = PHPParser().parse_source(source)
        self.assertFalse(root.has_error)
        self.assertEqual(original, source)
        self.assertEqual(root.end_byte, len(source))
        findings, _ = analyze(source.decode().removeprefix("<?php"))
        self.assertTrue(findings)

    def test_missing_target_is_not_clean(self):
        from php_deserial_sast.config import ScannerConfig
        from php_deserial_sast.scanner import PHPDeserializationScanner
        result = PHPDeserializationScanner(ScannerConfig(target_path="missing-target-4bfc5db7", enable_gadgets=False)).scan()
        self.assertTrue(any(error.phase == "discovery" for error in result.errors))

    def test_framework_model_is_not_observed_request(self):
        findings, _ = analyze(CASES["framework_request"][0])
        self.assertEqual(findings[0].metadata["source_assumption"], "modeled_framework_request")

    def test_pop_inherited_entry(self):
        from php_deserial_sast.core.call_graph import CallGraph
        from php_deserial_sast.core.gadget_finder import GadgetFinder
        root, source = PHPParser().parse_source("<?php class Base {function __destruct(){$this->close();} function close(){}} class Child extends Base {public $callback; function close(){call_user_func($this->callback);}}")
        symbols = ProjectSymbolTable()
        ASTVisitor(symbols, "gadget.php", source).extract_all(root)
        chains = GadgetFinder(symbols, CallGraph(symbols)).find_all_gadget_chains()
        self.assertTrue(any(chain.entry_class == "Child" for chain in chains))


if __name__ == "__main__":
    unittest.main()
