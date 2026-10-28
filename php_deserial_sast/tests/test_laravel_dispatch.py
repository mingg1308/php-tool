import tempfile
import unittest
from pathlib import Path

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.scanner import PHPDeserializationScanner


ENCRYPTER = '''<?php
namespace Illuminate\\Encryption;
class Encrypter {
  public function decrypt($payload, $unserialize = true) {
    if ($unserialize) { unserialize($payload); }
  }
}
'''
COOKIE = '''<?php
namespace Illuminate\\Cookie\\Middleware;
use Symfony\\Component\\HttpFoundation\\Request;
class EncryptCookies {
  protected $encrypter;
  protected function decrypt(Request $request) {
    foreach ($request->cookies as $cookie) { $this->decryptCookie($cookie); }
  }
  protected function decryptCookie($cookie) { $this->encrypter->decrypt($cookie); }
}
'''
CSRF = '''<?php
namespace Illuminate\\Foundation\\Http\\Middleware;
class VerifyCsrfToken {
  protected $encrypter;
  protected function getTokenFromRequest($request) {
    $token = $request->input('_token') ?: $request->header('X-CSRF-TOKEN');
    if (! $token && $header = $request->header('X-XSRF-TOKEN')) {
      $this->encrypter->decrypt($header);
    }
  }
}
'''


class LaravelDispatchTests(unittest.TestCase):
    def scan(self, files, framework_models=True):
        with tempfile.TemporaryDirectory() as directory:
            for name, code in files.items():
                Path(directory, name).write_text(code, encoding='utf-8')
            result = PHPDeserializationScanner(ScannerConfig(
                target_path=directory, enable_rules=False, enable_gadgets=False,
                framework_models=framework_models, php_version='7.2')).scan()
            self.assertFalse(result.errors)
            return [f for f in result.findings if f.metadata.get('sink_name') == 'unserialize']

    def test_cookie_and_xsrf_routes_are_conditional(self):
        findings = self.scan({'Encrypter.php': ENCRYPTER, 'EncryptCookies.php': COOKIE,
                              'VerifyCsrfToken.php': CSRF})
        self.assertTrue(findings)
        self.assertTrue(any(f.metadata['source_assumption'] == 'modeled_framework_request'
                            for f in findings))
        self.assertTrue(any('APP_KEY' in text for f in findings
                            for text in f.metadata['framework_dispatch_assumptions']))
        descriptions = {step.description for f in findings for route in f.flow_evidence
                        for step in route.trace}
        self.assertTrue(any('Request cookies' in text for text in descriptions))
        self.assertTrue(any('X-XSRF-TOKEN' in text for text in descriptions))
        self.assertTrue(all(f.assessment.exploitability_verified is False for f in findings))

    def test_framework_dispatch_can_be_disabled(self):
        self.assertFalse(self.scan({'Encrypter.php': ENCRYPTER,
                                    'EncryptCookies.php': COOKIE}, framework_models=False))

    def test_explicit_false_unserialize_flag_blocks_modeled_route(self):
        for replacement in ('decrypt($cookie, false);',
                            'decrypt(payload: $cookie, unserialize: false);'):
            with self.subTest(replacement=replacement):
                safe_cookie = COOKIE.replace('decrypt($cookie);', replacement)
                self.assertFalse(self.scan({'Encrypter.php': ENCRYPTER,
                                            'EncryptCookies.php': safe_cookie}))

    def test_dominating_false_flag_blocks_but_reassignment_keeps_route(self):
        safe_cookie = COOKIE.replace('$this->encrypter->decrypt($cookie);',
                                     '$flag = false; $this->encrypter->decrypt($cookie, $flag);')
        self.assertFalse(self.scan({'Encrypter.php': ENCRYPTER,
                                    'EncryptCookies.php': safe_cookie}))
        unsafe_cookie = COOKIE.replace('$this->encrypter->decrypt($cookie);',
                                       '$flag = false; if ($cookie) { $flag = true; } '
                                       '$this->encrypter->decrypt($cookie, $flag);')
        self.assertTrue(self.scan({'Encrypter.php': ENCRYPTER,
                                   'EncryptCookies.php': unsafe_cookie}))

    def test_conditional_assignment_reaches_true_branch_only(self):
        source = '''<?php
function test($flag) {
  if ($flag && $value = $_GET['x']) {
    unserialize($value);
  } else {
    unserialize($value);
  }
}
'''
        findings = self.scan({'case.php': source})
        self.assertEqual([f.location.start_line for f in findings], [4])
