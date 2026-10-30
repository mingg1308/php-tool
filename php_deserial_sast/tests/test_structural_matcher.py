import unittest

from php_deserial_sast.core.parser import PHPParser, find_nodes_by_type
from php_deserial_sast.rules.matcher import PatternMatcher


class StructuralMatcherTests(unittest.TestCase):
    def test_nested_nullsafe_call_in_rule_pipeline(self):
        from php_deserial_sast.rules.engine import Rule, RuleEngine
        engine = RuleEngine()
        engine.rules = [Rule({'id': 'nullsafe', 'pattern': '$OBJ?->decode($X)'})]
        root, source = PHPParser().parse_source("<?php consume($reader?->decode($_GET['x']));")
        findings = engine.evaluate_file('fixture.php', source, root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata['bindings']['$X'], "$_GET['x']")

    def test_member_static_and_qualified_calls(self):
        cases = [
            ('$OBJ->decode($X)', '$reader->DECODE(trim($input))', True),
            ('$OBJ->decode($X)', '$reader->encode($input)', False),
            ('$OBJ->decode($X)', "'$reader->decode($input)'", False),
            ('$OBJ?->decode(...)', '$reader?->decode($input, true)', True),
            ('Codec::decode($X)', 'CODEC::DECODE($input)', True),
            ('Codec::decode($X)', 'Other::decode($input)', False),
            ('Vendor\\decode($X)', 'Vendor\\decode($input)', True),
            ('Vendor\\decode($X)', 'decode($input)', False),
            ('$F($X)', '$callback($input)', True),
            ('$OBJ->pair($X,$X)', '$reader->pair($a,$A)', False),
        ]
        for pattern, code, expected in cases:
            with self.subTest(pattern=pattern, code=code):
                root, source = PHPParser().parse_source('<?php ' + code + ';')
                statement = next(n for n in root.named_children if n.type == 'expression_statement')
                matched, _ = PatternMatcher().matches_ast_node(pattern, statement, source)
                self.assertEqual(matched, expected)

    def test_call_structure(self):
        matcher = PatternMatcher()
        cases = [
            ("unserialize($X)", "unserialize(base64_decode(trim($a)))", True),
            ("unserialize($X)", "unserialize(/* comment */ $a)", True),
            ("unserialize($X)", "\\UNSERIALIZE($a)", True),
            ("f('...')", "f('...')", True),
            ("f('...')", "f($a)", False),
            ("file_exists($_GET[...])", "file_exists($_GET['path'])", True),
            ("file_exists($_GET[...])", "file_exists($_POST['path'])", False),
            ("file_exists($_GET[...])", "file_exists($_GET[$key . '-path'])", True),
            ("unserialize($X)", "unserialize($a, ['allowed_classes'=>false])", False),
            ("unserialize($X, ...)", "unserialize($a)", True),
            ("unserialize($X, ...)", "unserialize($a, ['allowed_classes'=>false])", True),
            ("f($X, $X)", "f($a, $A)", False),
            ("f($X, $X)", "f($a['x'], $a[ /*same*/ 'x'])", True),
            ("f($X, $X)", "f($a['x'], $a['y'])", False),
            ("f(g($X))", "f('g($a)')", False),
            ("f(g($X))", "f(g($a))", True),
            ("f(..., $X)", "f($a, $b)", True),
        ]
        for pattern, code, expected in cases:
            with self.subTest(pattern=pattern, code=code):
                root, source = PHPParser().parse_source("<?php " + code + ";")
                call = next(find_nodes_by_type(root, "function_call_expression"))
                matched, _ = matcher.matches_ast_node(pattern, call, source)
                self.assertEqual(matched, expected)

    def test_non_call_expressions_use_structure_and_preserve_case(self):
        cases = [
            ("$X = unserialize($Y)", "$result=unserialize(trim($input))", True),
            ("$X = unserialize($Y)", "'$result = unserialize($input)'", False),
            ("$X = $X", "$a=$A", False),
            ("$X = $X", "$a=$a", True),
            ("$_GET[...]", "$_GET['x']", True),
            ("$_GET[...]", "$_get['x']", False),
            ("$OBJ->payload", "$b->Payload", False),
            ("$OBJ->payload", "$b -> payload", True),
        ]
        for pattern, code, expected in cases:
            with self.subTest(pattern=pattern, code=code):
                root, source = PHPParser().parse_source("<?php " + code + ";")
                statement = next(n for n in root.named_children if n.type == 'expression_statement')
                matched, _ = PatternMatcher().matches_ast_node(pattern, statement, source)
                self.assertEqual(matched, expected)

    def test_nested_property_rule_with_shared_ast_index(self):
        from php_deserial_sast.rules.engine import Rule, RuleEngine
        from php_deserial_sast.core.parser import ASTIndex
        engine = RuleEngine()
        engine.rules = [Rule({'id': 'property', 'pattern': '$OBJ->payload'})]
        root, source = PHPParser().parse_source("<?php consume($obj->payload);")
        findings = engine.evaluate_file('fixture.php', source, root, node_index=ASTIndex(root))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata['bindings']['$OBJ'], '$obj')

    def test_literal_call_index_preserves_nested_and_qualified_matches(self):
        from php_deserial_sast.rules.engine import Rule, RuleEngine
        from php_deserial_sast.core.parser import ASTIndex
        engine = RuleEngine()
        engine.rules = [Rule({'id': 'calls', 'pattern-either': [
            {'pattern': 'unserialize($X)'},
            {'pattern': 'Vendor\\decode($X)'},
        ]})]
        root, source = PHPParser().parse_source(
            "<?php consume(@unserialize($_GET['x'])); "
            "Vendor\\decode($_POST['y']); Other\\decode('safe');"
        )
        for index in (None, ASTIndex(root)):
            with self.subTest(indexed=index is not None):
                findings = engine.evaluate_file('fixture.php', source, root, node_index=index)
                self.assertEqual(len(findings), 2)
                self.assertEqual({f.metadata['bindings']['$X'] for f in findings},
                                 {"$_GET['x']", "$_POST['y']"})
