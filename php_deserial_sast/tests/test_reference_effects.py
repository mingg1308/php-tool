import unittest

from php_deserial_sast.tests.test_dataflow_regression import analyze


class ReferenceEffectTests(unittest.TestCase):
    def test_effects_are_opt_in(self):
        import tempfile
        from pathlib import Path
        from php_deserial_sast.config import ScannerConfig
        from php_deserial_sast.scanner import PHPDeserializationScanner
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'reference.php')
            path.write_text("<?php function fill(&$x){$x=$_GET['x'];} $a=''; fill($a); unserialize($a);", encoding='utf8')
            for enabled in (False, True):
                result = PHPDeserializationScanner(ScannerConfig(target_path=str(path),
                    enable_gadgets=False, experimental_side_effects=enabled)).scan()
                self.assertFalse(result.errors)
                self.assertEqual(result.analysis['interprocedural_side_effects']['enabled'], enabled)
                self.assertEqual(any(f.metadata.get('engine') == 'taint' for f in result.findings), enabled)

    def test_effects_at_normal_exit(self):
        cases = [
            ("$x=$_GET['x']; $x='safe';", False),
            ("$x=$_GET['x']; if($_GET['c']){$x='safe';}else{$x='safe';}", False),
            ("$x=$_GET['x']; if($_GET['c']){$x='safe';}", True),
            ("$x=$_GET['x']; return; $x='safe';", True),
            ("if($_GET['c']){$x=$_GET['x']; return;} $x='safe';", True),
            ("$x=$_GET['x']; throw new Exception();", True),
            ("$x['a']=$_GET['x']; $x=[];", False),
        ]
        for body, expected in cases:
            with self.subTest(body=body):
                read = "$a['a']" if "['a']" in body else "$a"
                findings, _ = analyze("function fill(&$x){" + body + "} $a=''; fill($a); unserialize(" + read + ");")
                self.assertEqual(bool(findings), expected)

    def test_wrapper_overwrite(self):
        findings, _ = analyze("function fill(&$x){$x=$_GET['x'];} function wrap(&$p){fill($p);$p='safe';} $a=''; wrap($a); unserialize($a);")
        self.assertFalse(findings)

    def test_reference_effects(self):
        cases = [
            ("function fill(&$x){$x=$_GET['x'];} $a=''; fill($a); unserialize($a);", True),
            ("function fill($x){$x=$_GET['x'];} $a=''; fill($a); unserialize($a);", False),
            ("function fill(&$x,$v){$x=$v;} $a=''; fill($a,$_POST['x']); unserialize($a);", True),
            ("function fill(&$x,$v){$x=$v;} $a=''; fill(v:$_POST['x'],x:$a); unserialize($a);", True),
            ("function fill(&$x){$x=$_GET['x'];} $a=''; unserialize($a); fill($a);", False),
            ("function fill(&$x){$x=$_GET['x'];} $a=''; fill($a); $a='safe'; unserialize($a);", False),
            ("function fill(&$x){$x=$_GET['x'];} function wrap(&$p){fill($p);} $a=''; wrap($a); unserialize($a);", True),
            ("function fill(&$x){$x=$_GET['x'];} $a=''; $b=&$a; fill($b); unserialize($a);", True),
            ("function fill(&$x){return; $x=$_GET['x'];} $a=''; fill($a); unserialize($a);", False),
            ("function fill(&$x){$x['a']=$_GET['x'];} $a=[]; fill($a); unserialize($a['b']);", False),
            ("function fill(&$x){$x['a']=$_GET['x'];} $a=[]; fill($a); unserialize($a['a']);", True),
            ("function fill(&$x){$x=$_GET['x'];} $a=''; while($_GET['flag']){fill($a);} unserialize($a);", True),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                findings, _ = analyze(code)
                self.assertEqual(bool(findings), expected)
