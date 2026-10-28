"""Small adversarial cases: a negative means no arbitrary-object taint finding."""
import unittest
from php_deserial_sast.tests.test_dataflow_regression import analyze
from php_deserial_sast.core.parser import PHPParser

CASES = {
    "options_variable_safe": ("$o=['allowed_classes'=>false]; unserialize($_GET['x'],$o);", False),
    "options_overwritten": ("$o=['allowed_classes'=>false]; $o=['allowed_classes'=>true]; unserialize($_GET['x'],$o);", True),
    "options_conditional": ("$o=['allowed_classes'=>false]; if($_GET['b']){$o=['allowed_classes'=>true];} unserialize($_GET['x'],$o);", True),
    "options_spread_unknown": ("unserialize($_GET['x'],['allowed_classes'=>false,...$_GET['options']]);", True),
    "options_duplicate_last_true": ("unserialize($_GET['x'],['allowed_classes'=>false,'allowed_classes'=>true]);", True),
    "options_duplicate_last_false": ("unserialize($_GET['x'],['allowed_classes'=>true,'allowed_classes'=>false]);", False),
    "options_field_mutation": ("$o=['allowed_classes'=>false]; $o['allowed_classes']=true; unserialize($_GET['x'],$o);", True),
    "digit_guard": ("$s=$_GET['x']; if(ctype_digit($s)){unserialize($s);}", False),
    "digit_guard_else": ("$s=$_GET['x']; if(ctype_digit($s)){}else{unserialize($s);}", True),
    "digit_guard_overwrite": ("$s=$_GET['x']; if(ctype_digit($s)){$s=$_POST['x']; unserialize($s);}", True),
    "digit_guard_or": ("$s=$_GET['x']; if(ctype_digit($s)||$_GET['b']){unserialize($s);}", True),
    "digit_guard_direct_source": ("if(ctype_digit($_GET['x'])){unserialize($_GET['x']);}", False),
    "digit_guard_mutating_call": ("function change(&$s){$s=$_GET['y'];} $s=$_GET['x']; if(ctype_digit($s)){change($s); unserialize($s);}", True),
    "digit_guard_shadowed": ("namespace A; function ctype_digit($s){return true;} $s=$_GET['x']; if(ctype_digit($s)){unserialize($s);}", True),
    "options_alias_mutation": ("$o=['allowed_classes'=>false]; $a=&$o; $a['allowed_classes']=true; unserialize($_GET['x'],$o);", True),
    "options_unknown_key": ("unserialize($_GET['x'],['allowed_classes'=>false,$_GET['k']=>true]);", True),
    "nonempty_allowlist": ("unserialize($_GET['x'],['allowed_classes'=>['Gadget']]);", True),
    "string_type_not_safe": ("$s=$_GET['x']; if(is_string($s)){unserialize($s);}", True),
    "custom_predicate_not_safe": ("function is_safe($v){return true;} $s=$_GET['x']; if(is_safe($s)){unserialize($s);}", True),
    "hash_attacker_both_sides": ("$s=$_GET['x']; if(hash_equals($_GET['a'],$_GET['b'])){unserialize($s);}", True),
    "field_strong_overwrite": ("$a['x']=$_GET['x']; $a['x']='safe'; unserialize($a['x']);", False),
    "field_weak_write": ("$a['x']='safe'; $a[$_GET['k']]=$_GET['x']; unserialize($a['x']);", True),
    "array_replaced": ("$a['x']=$_GET['x']; $a=['x'=>'safe']; unserialize($a['x']);", False),
    "ternary_tainted": ("$s=$_GET['b']?'safe':$_POST['x']; unserialize($s);", True),
    "coalesce_tainted": ("$s=$_GET['x']??'safe'; unserialize($s);", True),
    "scalar_cast": ("unserialize((string)(int)$_GET['x']);", False),
    "two_step_decode": ("unserialize(base64_decode(urldecode($_GET['x'])));", True),
    "namespaced_shadow": ("namespace A; function unserialize($s){return $s;} unserialize($_GET['x']);", False),
    "explicit_builtin": ("namespace A; function unserialize($s){return $s;} \\unserialize($_GET['x']);", True),
    "parameter_overwrite": ("function load($x){$x='safe'; unserialize($x);} load($_GET['x']);", False),
}


class SmallCases(unittest.TestCase):
    def test_gadget_routes_keep_distinct_sink_methods_and_alternatives(self):
        from php_deserial_sast.core.gadget_finder import GadgetFinder
        from php_deserial_sast.models import GadgetChain, GadgetStep, Confidence

        def chain(identifier, sink_method, route, length):
            steps = [GadgetStep.model_construct(class_name='Entry', method_name='__destruct',
                                                step_type='ENTRY_MAGIC_METHOD',
                                                target_class=None, target_method=None)]
            steps += [GadgetStep.model_construct(class_name=name, method_name=name,
                                                 step_type='METHOD_CALL_DISPATCH',
                                                 target_class=name, target_method=name)
                      for name in route]
            return GadgetChain.model_construct(
                chain_id=identifier, entry_class='Entry', entry_method='__destruct',
                sink_class='Callback', sink_method=sink_method,
                sink_function='call_user_func', sink_type='RCE', steps=steps,
                length=length, confidence=Confidence.MEDIUM)

        finder = GadgetFinder.__new__(GadgetFinder)
        chains = [chain('a', 'handle', ['short'], 2),
                  chain('b', 'handle', ['flush', 'handleBatch'], 3),
                  chain('c', 'handle', ['other', 'handleBatch', 'flush'], 4),
                  chain('d', 'close', ['short'], 2)]
        retained = finder._deduplicate_chains(chains)
        self.assertEqual({chain.chain_id for chain in retained}, {'a', 'b', 'd'})

    def test_interfile_summary_separates_callers(self):
        from php_deserial_sast.core.ast_visitor import ASTVisitor
        from php_deserial_sast.core.symbol_table import ProjectSymbolTable
        from php_deserial_sast.core.dataflow import FlowProject
        from php_deserial_sast.core.taint_engine import TaintEngine
        for caller, expected in [("decode($_GET['x']);", True), ("decode('safe');", False)]:
            with self.subTest(caller=caller):
                files = {name: PHPParser().parse_source(code) for name, code in {
                    'lib.php': '<?php function decode($s){unserialize($s);}',
                    'app.php': '<?php ' + caller,
                }.items()}
                symbols = ProjectSymbolTable()
                for name, (root, source) in files.items():
                    ASTVisitor(symbols, name, source).extract_all(root)
                project = FlowProject(files, symbols)
                project.build()
                findings = [f for name, (root, source) in files.items()
                            for f in TaintEngine(name, source, root, project=project, php_version='8.1').analyze()]
                self.assertEqual(bool(findings), expected)
                if expected:
                    self.assertEqual(findings[0].location.file_path, 'lib.php')

    def test_phar_version_and_local_prefix(self):
        from php_deserial_sast.core.taint_engine import TaintEngine
        for code, version, expected in [
            ("file_exists($_GET['path']);", '7.4', True),
            ("file_exists($_GET['path']);", '8.1', False),
            ("file_exists(__DIR__.'/'.$_GET['path']);", '7.4', False),
        ]:
            with self.subTest(code=code, version=version):
                root, source = PHPParser().parse_source('<?php ' + code)
                findings = TaintEngine('fixture.php', source, root, php_version=version).analyze()
                self.assertEqual(bool(findings), expected)

    def test_guard_evidence_is_not_suppression(self):
        snippets = [
            "$s=$_GET['x']; if(!hash_equals(hash_hmac('sha256',$s,SECRET),$_GET['sig'])){return;} unserialize($s);",
            "function is_serialized_string($s){return true;} function restore($v){unserialize($v);} $s=$_GET['x']; if(is_serialized_string($s)){restore($s);}",
        ]
        for code in snippets:
            with self.subTest(code=code):
                findings, _ = analyze(code)
                self.assertTrue(findings)
                self.assertEqual(findings[0].metadata['analysis_status'], 'guarded_flow_review')
                self.assertTrue(findings[0].metadata['review_conditions'])
                self.assertFalse(findings[0].metadata['exploitability_verified'])

    def test_unguarded_route_remains_visible(self):
        code = "function restore($s){unserialize($s);} $s=$_GET['x']; if(is_string($s)){restore($s);} restore($_POST['x']);"
        findings, _ = analyze(code)
        self.assertEqual(findings[0].metadata['analysis_status'], 'source_to_sink')

    def test_guard_does_not_cover_later_write(self):
        findings, _ = analyze("$s=$_GET['x']; if(!hash_equals(hash_hmac('sha256',$s,SECRET),$_GET['sig'])){return;} $s=$_POST['new']; unserialize($s);")
        self.assertEqual(findings[0].metadata['analysis_status'], 'source_to_sink')

    def test_guard_on_call_inside_assignment_is_recorded(self):
        code = ("function checked($s){unserialize($s);} "
                "function row($v){if(approved($v)){$v=checked($v);}} "
                "row($_GET['x']);")
        findings, _ = analyze(code)
        self.assertTrue(findings)
        self.assertTrue(any('approved($v)' in guard
                            for guard in findings[0].metadata['review_conditions']))

    def test_guard_on_sibling_array_field_is_not_attached(self):
        prefix = "function approved($x){return true;} $a=['value'=>$_GET['x'],'key'=>'fixed']; "
        unrelated, _ = analyze(prefix + "if(approved($a['key'])){unserialize($a['value']);}")
        relevant, _ = analyze(prefix + "if(approved($a['value'])){unserialize($a['value']);}")
        self.assertTrue(unrelated)
        self.assertFalse(unrelated[0].metadata['review_conditions'])
        self.assertTrue(relevant[0].metadata['review_conditions'])

    def test_proven_serialized_string_guard_excludes_object_route(self):
        helper = ("function is_serialized_string($data){"
                  "if(!is_string($data)){return false;}"
                  "$data=trim($data);"
                  "if(strlen($data)<4){return false;}"
                  "elseif('s'!==$data[0]){return false;}"
                  "else{return true;}"
                  "}")
        guarded = (helper + " function decode($s){unserialize($s);} "
                   "function route($s){if(is_serialized_string($s)){decode($s);}} "
                   "route($_GET['x']);")
        findings, _ = analyze(guarded)
        self.assertFalse(findings)

        direct, _ = analyze(helper + "$s=$_GET['x']; if(is_serialized_string($s)){unserialize($s);}")
        self.assertFalse(direct)

        unguarded, _ = analyze(guarded + " decode($_POST['y']);")
        self.assertTrue(unguarded)
        self.assertEqual(unguarded[0].severity.value, 'CRITICAL')

    def test_unproven_serialized_string_guards_keep_object_route(self):
        helper = ("function is_serialized_string($data){"
                  "if(!is_string($data)){return false;}"
                  "$data=trim($data);"
                  "if(strlen($data)<4){return false;}"
                  "elseif('s'!==$data[0]){return false;}"
                  "else{return true;}"
                  "}")
        cases = [
            "function is_serialized_string($x){return true;} $s=$_GET['x']; if(is_serialized_string($s)){unserialize($s);}",
            helper + "$s=$_GET['x']; if(is_serialized_string($s)||$_GET['force']){unserialize($s);}",
            helper + "$s=$_GET['x']; if(is_serialized_string($s)){}else{unserialize($s);}",
            helper + "$s=$_GET['x']; if(is_serialized_string($s)){$s=$_POST['y'];unserialize($s);}",
        ]
        for code in cases:
            with self.subTest(code=code):
                findings, _ = analyze(code)
                self.assertTrue(findings)

    def test_openssl_decrypt_uses_ciphertext_not_key_as_content_source(self):
        key_only, _ = analyze("unserialize(openssl_decrypt('fixed','aes-256-cbc',$_GET['key']));")
        ciphertext, _ = analyze("unserialize(openssl_decrypt($_GET['blob'],'aes-256-cbc','secret'));")
        named, _ = analyze("unserialize(openssl_decrypt(passphrase:'secret',data:$_GET['blob'],cipher_algo:'aes-256-cbc'));")
        self.assertFalse(key_only)
        self.assertTrue(ciphertext)
        self.assertEqual(ciphertext[0].confidence.value, 'LOW')
        self.assertEqual(ciphertext[0].metadata['analysis_status'], 'unresolved_return_flow')
        self.assertTrue(named)

    def test_cases(self):
        for name, (code, expected) in CASES.items():
            with self.subTest(name=name):
                findings, project = analyze(code)
                self.assertTrue(project.converged)
                self.assertEqual(bool(findings), expected)

    def test_parser_compatibility(self):
        for code in (
            "<?php class C {function __construct(readonly protected string $x){unserialize($_GET['x']);}}",
            "<?php function readonly($x){return $x;} unserialize(readonly($_GET['x']));",
        ):
            with self.subTest(code=code):
                root, original = PHPParser().parse_source(code)
                self.assertFalse(root.has_error)
                self.assertEqual(original, code.encode())
                self.assertEqual(root.end_byte, len(original))
                self.assertTrue(analyze(code.removeprefix('<?php'))[0])

    def test_parser_does_not_rewrite_literals(self):
        code = "<?php /* readonly public */ $s='readonly public'; class C {function __construct(readonly public string $x){}}"
        root, source = PHPParser().parse_source(code)
        from php_deserial_sast.core.parser import find_nodes_by_type, get_node_text
        self.assertFalse(root.has_error)
        strings = [get_node_text(n, source) for n in find_nodes_by_type(root, 'string')]
        self.assertIn("'readonly public'", strings)


if __name__ == '__main__':
    unittest.main()
