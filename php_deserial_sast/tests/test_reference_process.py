import subprocess
import sys
import unittest
from scripts.reference_process import run_bounded

class ReferenceProcessTests(unittest.TestCase):
    def run_child(self, code, **options):
        return run_bounded([sys.executable, "-c", code], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, **options)

    def test_completed_exit_code_preserved(self):
        self.assertEqual(self.run_child("raise SystemExit(3)", timeout=10, stop=lambda: None), ("finished", 3))

    def test_real_deadline_stops_running_process(self):
        stopped = []
        self.assertEqual(self.run_child("import time; time.sleep(10)", timeout=0.2,
                         stop=lambda: stopped.append(True)), ("timeout", None))
        self.assertEqual(stopped, [True])

    def test_resume_clock_jump_stops_without_long_wait(self):
        stopped = []
        ticks = iter([0, 3600])
        self.assertEqual(self.run_child("import time; time.sleep(10)", timeout=900,
                         stop=lambda: stopped.append(True), clock=lambda: next(ticks)), ("timeout", None))
        self.assertEqual(stopped, [True])
