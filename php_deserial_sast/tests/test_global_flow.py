import unittest

from php_deserial_sast.tests.test_dataflow_regression import analyze


class GlobalFlowTests(unittest.TestCase):
    def test_global_reads_and_writes(self):
        cases = [
            ("function sink(){global $x; unserialize($x);} $x=$_GET['x']; sink();", True),
            ("function sink(){global $x; unserialize($x);} $x='safe'; sink();", False),
            ("function sink(){unserialize($x);} $x=$_GET['x']; sink();", False),
            ("function fill(){global $x; $x=$_GET['x'];} $x=''; fill(); unserialize($x);", True),
            ("function fill(){global $x; $x=$_GET['x']; $x='safe';} $x=''; fill(); unserialize($x);", False),
            ("function fill(){global $x; $x=$_GET['x'];} function wrap(){fill();} $x=''; wrap(); unserialize($x);", True),
            ("function fill(){global $x; $x=$_GET['x'];} function local(){$x='safe'; fill(); unserialize($x);} local();", False),
            ("function fill(){global $x; $x=$_GET['x'];} function local(){global $x; fill(); unserialize($x);} local();", True),
            ("function sink(){global $x; unserialize($x);} function wrap(){sink();} $x=$_GET['x']; wrap();", True),
            ("function sink(){global $x; unserialize($x);} function wrap(){$x='safe';sink();} $x=$_GET['x']; wrap();", True),
            ("function fill($v){global $x; $x=$v;} $x=''; fill($_POST['x']); unserialize($x);", True),
            ("function fill(){global $x; $x=$_GET['x'];} $x=''; fill(); $x='safe'; unserialize($x);", False),
            ("function fill(){global $x; $x=$_GET['x'];} $x=''; unserialize($x); fill();", False),
            ("function value(){global $x; return $x;} $x=$_GET['x']; unserialize(value());", True),
            ("function sink(){global $x;if(ctype_digit($x)){unserialize($x);}} $x=$_GET['x']; sink();", False),
            ("function fill(){global $x; $x=$_GET['x'];} function sink(){global $x; unserialize($x);} function wrap(){fill();sink();} wrap();", True),
            ("function fill(){global $x; $x=$_GET['x']; throw new Exception();} $x=''; try{fill();}catch(Exception $e){} unserialize($x);", True),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                findings, _ = analyze(code)
                self.assertEqual(bool(findings), expected)
