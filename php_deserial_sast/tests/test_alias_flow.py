import unittest
from php_deserial_sast.tests.test_dataflow_regression import analyze


class AliasFlowTests(unittest.TestCase):
    def test_local_reference_cells(self):
        cases = [
            ("$a='safe'; $b=&$a; $b=$_GET['x']; unserialize($a);", True),
            ("$a=$_GET['x']; $b=&$a; $b='safe'; unserialize($a);", False),
            ("$a=$_GET['x']; $b=&$a; $c=&$b; unserialize($c);", True),
            ("$a=$_GET['x']; $b='safe'; $a=&$b; unserialize($a);", False),
            ("$a=$_GET['x']; $b=&$a; $c='safe'; $b=&$c; unserialize($a);", True),
            ("$a=$_GET['x']; $b=&$a; $c='safe'; $b=&$c; unserialize($b);", False),
            ("function f($a){$b=&$a; unserialize($b);} f($_GET['x']);", True),
            ("$a='safe'; $b='safe'; if($_GET['flag']) {$b=&$a;} $b=$_POST['x']; unserialize($a);", True),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                findings, _ = analyze(code)
                self.assertEqual(bool(findings), expected)
