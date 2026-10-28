import unittest
from pathlib import Path

from php_deserial_sast.core.finding_scope import source_scope
from php_deserial_sast.core.symbol_table import ClassSymbol, ProjectSymbolTable


class FindingScopeTests(unittest.TestCase):
    def test_project_relative_scope(self):
        root = Path.cwd() / 'sample-project'
        cases = {
            'src/Decoder.php': 'production',
            'core/modules/field/tests/modules/field_test/Gadget.php': 'tests',
            'examples/example.php': 'examples',
            'vendor/pkg/src/Codec.php': 'vendor',
            'vendor/pkg/tests/CodecTest.php': 'tests',
            'src/test.php': 'tests',
            'src/contest.php': 'production',
        }
        for relative, expected in cases.items():
            with self.subTest(relative=relative):
                self.assertEqual(source_scope(root, root / relative), expected)

    def test_single_file_target(self):
        file = Path.cwd() / 'scan.php'
        self.assertEqual(source_scope(file, file), 'production')

    def test_payload_generation_file_does_not_replace_application_class(self):
        root = Path.cwd() / 'sample-project'
        production = ClassSymbol(name='Router', full_name='Router',
                                 file_path=str(root / 'src/libs/router.php'))
        payload_test = ClassSymbol(name='Router', full_name='Router',
                                   file_path=str(root / 'src/test.php'))
        for order in ((production, payload_test), (payload_test, production)):
            symbols = ProjectSymbolTable()
            for cls in order:
                symbols.add_class(cls)
            self.assertEqual(symbols.get_class('Router').file_path,
                             production.file_path)
