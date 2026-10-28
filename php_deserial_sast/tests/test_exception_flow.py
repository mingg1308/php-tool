import unittest
from php_deserial_sast.tests.test_dataflow_regression import analyze


class ExceptionFlowTests(unittest.TestCase):
    def test_exception_and_finally_paths(self):
        cases = [
            ("try {throw new Exception();} catch (Exception $e) {unserialize($_GET['x']);}", True),
            ("try {return;} finally {unserialize($_GET['x']);}", True),
            ("try {throw new Exception();} finally {unserialize($_GET['x']);}", True),
            ("try {return;} finally {} unserialize($_GET['x']);", False),
            ("try {} finally {return;} unserialize($_GET['x']);", False),
            ("$x=$_GET['x']; try {risky();} finally {$x='safe';} unserialize($x);", False),
            ("$x=$_GET['x']; try {$x='safe';} catch (Exception $e) {unserialize($x);}", True),
            ("while ($_GET['f']) {try {break;} finally {unserialize($_GET['x']);}}", True),
            ("while ($_GET['f']) {try {continue;} finally {unserialize($_GET['x']);}}", True),
            ("try {while ($_GET['f']) {break;} unserialize($_GET['x']);} finally {}", True),
            ("try {try {return;} finally {unserialize($_GET['x']);}} finally {unserialize($_POST['x']);}", True),
            ("try {throw new Exception();} catch (Exception $e) {return;} finally {} unserialize($_GET['x']);", False),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                findings, project = analyze(code)
                self.assertEqual(bool(findings), expected)
                self.assertTrue(all(cfg.supported for cfg in project.files['fixture.php'].cfgs.values()))
