"""Loop-carried taint and zero/one iteration behavior."""
import unittest
from php_deserial_sast.tests.test_dataflow_regression import analyze


class LoopDataflowTests(unittest.TestCase):
    def test_foreach_destructuring(self):
        cases = [
            ("foreach ([[ 'safe', $_GET['x'] ]] as [$a,$b]) {unserialize($a);}", False),
            ("foreach ([[ 'safe', $_GET['x'] ]] as [$a,$b]) {unserialize($b);}", True),
            ("foreach ([[ 'safe', 'safe', $_GET['x'] ]] as [$a,,$c]) {unserialize($c);}", True),
            ("foreach ([[ 'safe', $_GET['x'] ]] as list($a,$b)) {unserialize($b);}", True),
            ("foreach ([['good'=>'safe','bad'=>$_GET['x']]] as ['good'=>$a,'bad'=>$b]) {unserialize($a);}", False),
            ("foreach ([['good'=>'safe','bad'=>$_GET['x']]] as ['good'=>$a,'bad'=>$b]) {unserialize($b);}", True),
            ("foreach ([[['safe',$_GET['x']]]] as [[$a,$b]]) {unserialize($b);}", True),
            ("foreach ($_POST['rows'] as $k=>[$a,$b]) {unserialize($b);}", True),
            ("foreach ($_POST['rows'] as [$a,$b]) {$b='safe'; unserialize($b);}", False),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                findings, project = analyze(code)
                self.assertEqual(bool(findings), expected)
                self.assertTrue(all(cfg.supported for cfg in project.files['fixture.php'].cfgs.values()))

    def test_foreach_key_value_separation(self):
        cases = [
            ("foreach ($_GET as $k=>$v) {unserialize($k);}", True),
            ("foreach (['fixed'=>$_GET['x']] as $k=>$v) {unserialize($k);}", False),
            ("foreach (['fixed'=>$_GET['x']] as $k=>$v) {unserialize($v);}", True),
            ("foreach ([$_GET['x']=>'safe'] as $k=>$v) {unserialize($k);}", True),
            ("foreach ([$_GET['x']=>'safe'] as $k=>$v) {unserialize($v);}", False),
            ("$a=['fixed'=>$_GET['x']]; foreach ($a as $k=>$v) {unserialize($k);}", False),
            ("$a=[]; $a[$_GET['x']]='safe'; foreach ($a as $k=>$v) {unserialize($k);}", True),
            ("$a=[]; $a['fixed']=$_GET['x']; foreach ($a as $k=>$v) {unserialize($k);}", False),
            ("foreach ($_GET as $k=>$v) {$k='safe'; unserialize($k);}", False),
            ("foreach ($_GET as $k=>$v) {break; unserialize($k);}", False),
            ("function f($a){foreach($a as $k=>$v){unserialize($k);}} f(['fixed'=>$_GET['x']]);", False),
            ("function f($a){foreach($a as $k=>$v){unserialize($k);}} f([$_GET['x']=>'safe']);", True),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                findings, project = analyze(code)
                self.assertEqual(bool(findings), expected)
                self.assertTrue(all(cfg.supported for cfg in project.files['fixture.php'].cfgs.values()))

    def test_foreach_can_use_stable_fallback(self):
        from php_deserial_sast.core.control_flow import coverage
        findings, project = analyze("foreach ($_POST['items'] as $v) {unserialize($v);}",
                                    experimental_foreach_cfg=False)
        self.assertTrue(findings)
        self.assertIn('foreach_cfg_disabled', coverage(project)['fallback_reasons'])

    def test_foreach_value_flow(self):
        cases = [
            ("foreach ($_POST['items'] as $v) {unserialize($v);}", True),
            ("foreach (['safe'] as $v) {unserialize($v);}", False),
            ("$v=$_GET['x']; foreach (['safe'] as $v) {unserialize($v);}", False),
            ("$v=$_GET['x']; foreach ($items as $v) {} unserialize($v);", True),
            ("foreach ($_POST['items'] as $v) {$v='safe'; unserialize($v);}", False),
            ("foreach ($_POST['items'] as $v) {break; unserialize($v);}", False),
            ("foreach ($_POST['items'] as $v) {continue; unserialize($v);}", False),
            ("$x='safe'; foreach ($_POST['items'] as $v) {unserialize($x); $x=$v;}", True),
            ("$x='safe'; foreach ($_POST['items'] as $v) {unserialize($x); $x=$v; break;}", False),
            ("$items=$_POST['items']; foreach ($items as $v) {$items=['safe']; unserialize($v);}", True),
            ("$items=['safe']; foreach ($items as $v) {$items=$_POST['items']; unserialize($v);}", False),
            ("foreach ($_POST['items'] as $v) {do {break 2;} while ($_GET['f']); unserialize($v);}", False),
            ("foreach ($_POST['items'] as $v) {do {continue 2;} while ($_GET['f']); unserialize($v);}", False),
            ("foreach (/* source */ $_POST['items'] as /* binding */ $v) {unserialize($v);}", True),
            ("$items=$_POST['items']; foreach ($items as $items) {unserialize($items);}", True),
            ("$items=['safe']; foreach ($items as $items) {unserialize($items);}", False),
            ("function decode($items){foreach ($items as $v) {unserialize($v);}} decode($_POST['items']);", True),
            ("function decode($items){foreach ($items as $v) {unserialize($v);}} decode(['safe']);", False),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                findings, project = analyze(code)
                self.assertEqual(bool(findings), expected)
                file = project.files['fixture.php']
                self.assertTrue(all(cfg.supported for cfg in file.cfgs.values()))
                self.assertFalse(file.loop_limit_reached)

    def test_foreach_complex_binding_fallback(self):
        from php_deserial_sast.core.control_flow import coverage
        for binding in ('$key => &$v', '&$v'):
            findings, project = analyze("foreach ($_POST['items'] as " + binding + ") {unserialize($v);}")
            self.assertTrue(findings)
            self.assertIn('foreach_binding', coverage(project)['fallback_reasons'])

    def test_for_loop_dataflow(self):
        cases = [
            ("for ($x=$_GET['x']; $_GET['f'];) {unserialize($x);}", True),
            ("$x=$_GET['x']; for ($x='safe'; $_GET['f'];) {unserialize($x);}", False),
            ("for ($x='safe'; $_GET['f']; $x=$_GET['x']) {unserialize($x);}", True),
            ("for ($x='safe'; $_GET['f']; $x=$_GET['x']) {unserialize($x); break;}", False),
            ("for ($x='safe'; $_GET['f']; $x=$_GET['x']) {if ($_GET['g']) {unserialize($x);} continue; $x='safe';}", True),
            ("for ($x=$_GET['x']; $_GET['f']; $x='safe') {} unserialize($x);", True),
            ("for (;;) {} unserialize($_GET['x']);", False),
            ("for (;;) {break;} unserialize($_GET['x']);", True),
            ("for (;; unserialize($_GET['x'])) {break;}", False),
            ("for (;; unserialize($_GET['x'])) {continue;}", True),
            ("for ($x=$_GET['x'], $y=$x; $_GET['f'];) {unserialize($y);}", True),
            ("for ($x=$_GET['x'], $x='safe'; $_GET['f'];) {unserialize($x);}", False),
            ("for ($x='safe'; $_GET['f']; $x=$_GET['x'], $x='safe') {unserialize($x);}", False),
            ("for ($x='safe'; $x=$_GET['x'], $_GET['f'];) {unserialize($x);}", True),
            ("for ($x='safe'; $_GET['f']; $x=$_GET['x']) {while ($_GET['g']) {continue 2;} unserialize($x);}", True),
            ("for ($x='safe'; $_GET['f']; $x=$_GET['x']) {do {break 2;} while ($_GET['g']);} unserialize($x);", False),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                findings, project = analyze(code)
                self.assertEqual(bool(findings), expected)
                file = project.files['fixture.php']
                self.assertTrue(all(cfg.supported for cfg in file.cfgs.values()))
                self.assertFalse(file.loop_limit_reached)

    def test_loop_jumps(self):
        cases = [
            ("while ($_GET['f']) {break; unserialize($_GET['x']);}", False),
            ("while ($_GET['f']) {continue; unserialize($_GET['x']);}", False),
            ("$x='safe'; while ($_GET['f']) {$x=$_GET['x']; break;} unserialize($x);", True),
            ("$x='safe'; while ($_GET['f']) {break; $x=$_GET['x'];} unserialize($x);", False),
            ("$x='safe'; while ($_GET['f']) {unserialize($x); $x=$_GET['x']; continue; $x='safe';}", True),
            ("$x='safe'; while ($_GET['f']) {unserialize($x); $x=$_GET['x']; break;}", False),
            ("$x=$_GET['x']; do {$x='safe'; break;} while ($_GET['f']); unserialize($x);", False),
            ("$x=$_GET['x']; do {break; $x='safe';} while ($_GET['f']); unserialize($x);", True),
            ("do {break;} while (unserialize($_GET['x']));", False),
            ("do {continue;} while (unserialize($_GET['x']));", True),
            ("while ($_GET['f']) {do {break 2;} while ($_GET['g']); unserialize($_GET['x']);}", False),
            ("while ($_GET['f']) {do {continue 2;} while ($_GET['g']); unserialize($_GET['x']);}", False),
            ("while ($_GET['f']) {do {break;} while ($_GET['g']); unserialize($_GET['x']);}", True),
            ("while ($_GET['f']) {if ($_GET['g']) {break;} unserialize($_GET['x']);}", True),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                findings, project = analyze(code)
                self.assertEqual(bool(findings), expected)
                file = project.files['fixture.php']
                self.assertTrue(all(cfg.supported for cfg in file.cfgs.values()))
                self.assertFalse(file.loop_limit_reached)

    def test_unsupported_loop_jump_falls_back(self):
        from php_deserial_sast.core.control_flow import coverage
        for level in ('3', '010', '0x1', '(1)'):
            with self.subTest(level=level):
                findings, project = analyze("while ($_GET['f']) {break " + level + "; unserialize($_GET['x']);}")
                self.assertTrue(findings)
                self.assertIn('unsupported_loop_jump', coverage(project)['fallback_reasons'])

    def test_loop_carried_values(self):
        cases = [
            ("$x='safe'; while ($_GET['f']) {unserialize($x); $x=$_GET['x'];}", True),
            ("$x='safe'; $y='safe'; while ($_GET['f']) {unserialize($x); $x=$y; $y=$_GET['x'];}", True),
            ("$x='safe'; $y='safe'; while ($_GET['f']) {$x=$y; $y=$x; unserialize($x);}", False),
            ("$x=$_GET['x']; while ($_GET['f']) {$x='safe';} unserialize($x);", True),
            ("$x=$_GET['x']; do {$x='safe';} while ($_GET['f']); unserialize($x);", False),
            ("$x='safe'; do {unserialize($x); $x=$_GET['x'];} while ($_GET['f']);", True),
            ("$x=$_GET['x']; while ($_GET['f']) {$x='safe'; unserialize($x);}", False),
            ("$x='safe'; while ($_GET['f']) {$x=$_GET['x'];} unserialize($x);", True),
            ("do {return;} while ($_GET['f']); unserialize($_GET['x']);", False),
            ("while ($_GET['f']) {return;} unserialize($_GET['x']);", True),
            ("$x=$_GET['x']; while ($_GET['f']) {$x .= 'a';} unserialize($x);", True),
            ("$x='safe'; while ($_GET['f']) {$x .= 'a';} unserialize($x);", False),
            ("$x='safe'; while ($_GET['f']) {unserialize($x); $x .= $_POST['x'];}", True),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                findings, project = analyze(code)
                self.assertEqual(bool(findings), expected)
                self.assertFalse(project.files['fixture.php'].loop_limit_reached)

    def test_loop_through_function_summary(self):
        findings, project = analyze("""
            function decode($input) {
                $x='safe';
                while ($_GET['f']) {unserialize($x); $x=$input;}
            }
            decode($_POST['payload']);
        """)
        self.assertTrue(findings)
        self.assertTrue(project.converged)
