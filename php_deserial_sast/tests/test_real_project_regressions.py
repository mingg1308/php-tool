"""Counterexamples extracted from XVWA, TCPDF and WordPress scan reviews."""
import unittest
from php_deserial_sast.tests.test_dataflow_regression import analyze
from php_deserial_sast.core.parser import PHPParser
from php_deserial_sast.core.taint_engine import TaintEngine


def phar(code, experimental_foreach_cfg=False):
    root, source = PHPParser().parse_source('<?php ' + code)
    assert not root.has_error
    if experimental_foreach_cfg:
        from php_deserial_sast.core.dataflow import FlowProject
        project = FlowProject({'fixture.php': (root, source)}, experimental_foreach_cfg=True)
        project.build()
        return TaintEngine('fixture.php', source, root, project=project, php_version='7.4').analyze()
    return TaintEngine('fixture.php', source, root, php_version='7.4').analyze()


WRAPPER_FILTER = """
if (strpos($filename, '://') > 0) {
    $wrappers = stream_get_wrappers();
    foreach ($wrappers as $wrapper) {
        if (($wrapper === 'http') || ($wrapper === 'https')) { continue; }
        if (stripos($filename, $wrapper.'://') === 0) { return false; }
    }
}
"""


class RealProjectRegressions(unittest.TestCase):
    def test_wrapper_guard_with_later_write_outside_loop(self):
        for replacement, expected in [("str_replace(' ', '%20', $filename)", False),
                                      ("$_POST['replacement']", True)]:
            with self.subTest(replacement=replacement):
                code = ('function checked($filename){' + WRAPPER_FILTER
                        + 'if (!file_exists($filename)) {$filename=' + replacement + ';}'
                        + "return file_exists($filename);} checked($_GET['x']);")
                findings = phar(code, experimental_foreach_cfg=True)
                self.assertEqual(bool(findings), expected)
                if expected:
                    self.assertEqual(len(findings), 1)

    def test_presence_and_type_checks_do_not_reduce_severity(self):
        for check in ["isset($s)", "!empty($s)", "is_string($s)", "is_serialized($s)"]:
            with self.subTest(check=check):
                findings, _ = analyze("$s=$_GET['x']; if(" + check + "){unserialize($s);}")
                self.assertEqual(findings[0].severity.value, 'CRITICAL')
                self.assertEqual(findings[0].confidence.value, 'HIGH')

    def test_unknown_guard_never_proves_safety(self):
        findings, _ = analyze("function approved($s){return true;} $s=$_GET['x']; if(approved($s)){unserialize($s);}")
        self.assertEqual(findings[0].severity.value, 'CRITICAL')
        self.assertTrue(findings[0].metadata['review_conditions'])

    def test_wrapper_filter(self):
        code = "function checked($filename){" + WRAPPER_FILTER + "return file_exists($filename);} checked($_GET['x']);"
        self.assertFalse(phar(code))

    def test_wrapper_filter_counterexamples(self):
        for filter_code, after in [
            (WRAPPER_FILTER.replace('return false;', '$ignored=true;'), ''),
            (WRAPPER_FILTER.replace("'https'", "'phar'"), ''),
            (WRAPPER_FILTER.replace("stream_get_wrappers()", "['http','https']"), ''),
            (WRAPPER_FILTER, "$filename=$_GET['new'];"),
            (WRAPPER_FILTER.replace("strpos($filename, '://') > 0", "$_GET['flag']"), ''),
        ]:
            with self.subTest(filter=filter_code, after=after):
                self.assertTrue(phar("function checked($filename){" + filter_code + after + "return file_exists($filename);} checked($_GET['x']);"))

    def test_constant_local_prefix(self):
        self.assertFalse(phar("define('ROOT_DIR', __DIR__.'/plugins'); $file=ROOT_DIR.'/'.$_GET['x']; file_exists($file);"))

    def test_constant_prefix_must_be_proven(self):
        for definition in ["define('ROOT_DIR', $_GET['root']);", "", "if($_GET['b']){define('ROOT_DIR','/local');}"]:
            with self.subTest(definition=definition):
                self.assertTrue(phar(definition + "$file=ROOT_DIR.'/'.$_GET['x']; file_exists($file);"))

    def test_configured_default_keeps_finding_and_evidence(self):
        findings = phar("if(!defined('ROOT_DIR')){define('ROOT_DIR',__DIR__);} file_exists(ROOT_DIR.'/'.$_GET['x']);")
        self.assertTrue(findings)
        self.assertEqual(findings[0].metadata['analysis_status'], 'configured_local_path_review')
        self.assertTrue(findings[0].metadata['path_prefix_assumptions'])

    def test_unsafe_override_invalidates_local_default_model(self):
        findings = phar("if($_GET['flag']){define('ROOT_DIR',$_GET['prefix']);} if(!defined('ROOT_DIR')){define('ROOT_DIR',__DIR__);} file_exists(ROOT_DIR.'/'.$_GET['x']);")
        self.assertTrue(findings)
        self.assertFalse(findings[0].metadata['path_prefix_assumptions'])

    def test_wrapper_builtin_shadowing(self):
        code = "namespace A; function stream_get_wrappers(){return ['http'];} function checked($filename){" + WRAPPER_FILTER + "return file_exists($filename);} checked($_GET['x']);"
        self.assertTrue(phar(code))

    def test_validator_return_contract(self):
        function = "function checked($filename){" + WRAPPER_FILTER + "return file_exists($filename);} "
        self.assertFalse(phar(function + "$p=$_GET['x']; if(!checked($p)){return;} file_get_contents($p);"))
        for tail in [
            "$p=$_GET['x']; checked($p); file_get_contents($p);",
            "$p=$_GET['x']; if(!checked($p)){$ignored=true;} file_get_contents($p);",
            "$p=$_GET['x']; if(!checked($p)){return;} $p=$_POST['x']; file_get_contents($p);",
        ]:
            with self.subTest(tail=tail):
                self.assertTrue(phar(function + tail))

    def test_validator_cannot_return_success_before_check(self):
        function = "function checked($filename){if($_GET['b']){return true;}" + WRAPPER_FILTER + "return file_exists($filename);} "
        self.assertTrue(phar(function + "$p=$_GET['x']; if(!checked($p)){return;} file_get_contents($p);"))

    def test_wrapper_guard_does_not_cross_function_scope(self):
        code = "function checked($filename){" + WRAPPER_FILTER + "return file_exists($filename);} function unsafe($filename){return file_exists($filename);} unsafe($_GET['x']);"
        self.assertTrue(phar(code))

    def test_validator_inside_foreach(self):
        function = "function checked($filename){" + WRAPPER_FILTER + "return file_exists($filename);} "
        self.assertFalse(phar(function + "foreach($_GET['paths'] as $p){if(!checked($p)){return;} file_get_contents($p);}"))
        self.assertTrue(phar(function + "foreach($_GET['paths'] as $p){if(!checked($p)){return;} $p=$_POST['x']; file_get_contents($p);}"))


if __name__ == '__main__':
    unittest.main()
