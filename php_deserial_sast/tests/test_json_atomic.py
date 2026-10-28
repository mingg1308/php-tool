import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from php_deserial_sast.models import ScanResult, ScanSummary
from php_deserial_sast.reporters.json_reporter import JSONReporter


class AtomicJSONTests(unittest.TestCase):
    def test_round_trip(self):
        result = ScanResult(target_path="fixture.php", summary=ScanSummary(), findings=[],
                            analysis={"note": "Unicode: tiếng Việt"})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "scan.json")
            JSONReporter().save_to_file(result, str(path))
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), result.model_dump(mode="json"))
            self.assertEqual(list(Path(folder).glob("*.tmp")), [])

    def test_failed_write_preserves_previous_report(self):
        result = ScanResult(target_path="fixture.php", summary=ScanSummary(), findings=[])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "scan.json")
            path.write_text('{"previous":true}', encoding="utf-8")
            with patch("php_deserial_sast.reporters.json_reporter.json.dump", side_effect=OSError("disk failure")):
                with self.assertRaises(OSError):
                    JSONReporter().save_to_file(result, str(path))
            self.assertEqual(json.loads(path.read_text()), {"previous": True})
            self.assertEqual(list(Path(folder).glob("*.tmp")), [])
