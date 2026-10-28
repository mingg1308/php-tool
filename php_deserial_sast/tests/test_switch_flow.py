import unittest
from php_deserial_sast.tests.test_dataflow_regression import analyze


class SwitchFlowTests(unittest.TestCase):
    def test_fallback_switch_fallthrough_and_break(self):
        for separator, expected in [('', True), ('break;', False)]:
            with self.subTest(separator=separator):
                code = ("switch ($_GET['action']) { case 1: $value=$_GET['payload']; "
                        + separator + " case 2: foreach (['a'] as $unused) {} "
                        "unserialize($value); }")
                findings, project = analyze(code, experimental_foreach_cfg=False)
                self.assertEqual(bool(findings), expected)
                self.assertFalse(all(cfg.supported for cfg in project.files['fixture.php'].cfgs.values()))

    def test_split_upload_value_within_case(self):
        code = ("switch ($_GET['action']) { case 'load': "
                "$data=file_get_contents($_FILES['data']['tmp_name']); "
                "$parts=explode('|',$data); "
                "for($i=0;$i<count($parts);$i+=2) { "
                "$value=$parts[$i+1]; unserialize($value); } break; }")
        for enabled in (False, True):
            with self.subTest(experimental_foreach_cfg=enabled):
                findings, _ = analyze(code, experimental_foreach_cfg=enabled)
                self.assertTrue(any(f.rule_id == 'php-unserialize-tainted-input'
                                    and f.flow_evidence[0].source_kind == 'request'
                                    for f in findings))

    def test_switch_paths(self):
        cases = [
            ("switch ($_GET['f']) {case 1: break; unserialize($_GET['x']);}", False),
            ("switch ($_GET['f']) {case 1: return; default: return;} unserialize($_GET['x']);", False),
            ("switch ($_GET['f']) {case 1: return;} unserialize($_GET['x']);", True),
            ("$x='safe'; switch ($_GET['f']) {case 1: $x=$_GET['x']; case 2: unserialize($x);}", True),
            ("$x='safe'; switch ($_GET['f']) {case 1: $x=$_GET['x']; break; case 2: unserialize($x);}", False),
            ("$x=$_GET['x']; switch ($_GET['f']) {case 1: $x='safe'; break; default: $x='safe';} unserialize($x);", False),
            ("$x=$_GET['x']; switch ($_GET['f']) {case 1: $x='safe'; break;} unserialize($x);", True),
            ("switch ($_GET['f']) {default: break; case 1: unserialize($_GET['x']);}", True),
            ("while ($_GET['f']) {switch ($_GET['g']) {default: break 2;} unserialize($_GET['x']);}", False),
            ("while ($_GET['f']) {switch ($_GET['g']) {default: continue 2;} unserialize($_GET['x']);}", False),
            ("while ($_GET['f']) {switch ($_GET['g']) {default: continue;} unserialize($_GET['x']);}", True),
            ("switch ($_GET['f']) {case unserialize($_GET['x']): break;}", True),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                findings, project = analyze(code)
                self.assertEqual(bool(findings), expected)
                self.assertTrue(all(cfg.supported for cfg in project.files['fixture.php'].cfgs.values()))
