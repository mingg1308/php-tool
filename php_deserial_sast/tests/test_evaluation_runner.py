"""Check that the case-study runner records process completion and resource limits."""

import sys
import tempfile
import unittest
from pathlib import Path

from scripts.retest_case_studies import run_scanned


class EvaluationRunnerTests(unittest.TestCase):
    def test_completed_child_has_exit_code_and_log(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory, 'child.log')
            status, exit_code, peak = run_scanned(
                [sys.executable, '-c', 'print("ready")'], log, timeout=10)
            self.assertEqual((status, exit_code), ('finished', 0))
            self.assertIn(b'ready', log.read_bytes())
            if sys.platform == 'win32' or sys.platform.startswith('linux'):
                self.assertIsNotNone(peak)
                self.assertGreater(peak, 0)

    def test_timeout_kills_child_and_keeps_partial_log(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory, 'child.log')
            status, exit_code, _ = run_scanned(
                [sys.executable, '-u', '-c', 'import time; print("started"); time.sleep(10)'],
                log, timeout=1)
            self.assertEqual((status, exit_code), ('timeout', None))
            self.assertIn(b'started', log.read_bytes())
