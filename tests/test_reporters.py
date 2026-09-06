"""
Unit tests for SARIF, HTML, and JSON reporters.
"""

import os
import json
import pytest
from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.scanner import PHPDeserializationScanner
from php_deserial_sast.reporters.sarif import SarifReporter
from php_deserial_sast.reporters.html_report import HTMLReporter
from php_deserial_sast.reporters.json_reporter import JSONReporter


def test_full_scan_and_reports(tmp_path):
    target_dir = os.path.join(os.path.dirname(__file__), "..", "test_samples")
    config = ScannerConfig(target_path=target_dir)
    scanner = PHPDeserializationScanner(config)
    result = scanner.scan()

    assert result.summary.total_files_scanned > 0
    assert result.summary.total_findings > 0
    assert result.summary.gadget_chains_found > 0

    # Test SARIF export
    sarif_path = tmp_path / "report.sarif"
    sarif_rep = SarifReporter()
    sarif_rep.save_to_file(result, str(sarif_path))
    assert os.path.exists(sarif_path)
    with open(sarif_path, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)
        assert sarif_data["version"] == "2.1.0"
        assert len(sarif_data["runs"][0]["results"]) > 0

    # Test HTML export
    html_path = tmp_path / "report.html"
    html_rep = HTMLReporter()
    html_rep.save_to_file(result, str(html_path))
    assert os.path.exists(html_path)
    with open(html_path, "r", encoding="utf-8") as f:
        html_data = f.read()
        assert "<!DOCTYPE html>" in html_data
        assert "PHP Insecure Deserialization SAST Report" in html_data

    # Test JSON export
    json_path = tmp_path / "report.json"
    json_rep = JSONReporter()
    json_rep.save_to_file(result, str(json_path))
    assert os.path.exists(json_path)
