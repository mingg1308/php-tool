"""Periodic stack samples for diagnosing a slow full scan without a debugger."""
import faulthandler
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from php_deserial_sast.cli import main

faulthandler.dump_traceback_later(30, repeat=True)
main()
