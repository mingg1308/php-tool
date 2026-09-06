"""
Unit tests for new enhancements:
1. Non-overlapping finding deduplication and correlation
2. Dynamic Phar concatenation & wrapper detection
3. Namespace & use alias resolution
4. Inter-procedural taint analysis
"""

import os
import pytest
from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.scanner import PHPDeserializationScanner
from php_deserial_sast.core.parser import PHPParser
from php_deserial_sast.core.symbol_table import ProjectSymbolTable
from php_deserial_sast.core.ast_visitor import ASTVisitor
from php_deserial_sast.core.taint_engine import TaintEngine
from php_deserial_sast.models import Severity, VulnerabilityType


def test_deduplication_vuln_post():
    """Verify that vuln_post.php produces exactly 1 high-precision CRITICAL finding."""
    target = os.path.join(os.path.dirname(__file__), "..", "test_samples", "direct_unserialize", "vuln_post.php")
    config = ScannerConfig(target_path=target)
    scanner = PHPDeserializationScanner(config)
    result = scanner.scan()

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.vuln_type == VulnerabilityType.DIRECT_UNSERIALIZE
    assert f.location.start_line == 12


def test_deduplication_test1():
    """Verify that test1.php produces exactly 2 distinct findings (1 POP Chain + 1 Direct Unserialize)."""
    target = os.path.join(os.path.dirname(__file__), "..", "test_samples", "my testcase", "test1.php")
    config = ScannerConfig(target_path=target)
    scanner = PHPDeserializationScanner(config)
    result = scanner.scan()

    assert len(result.findings) == 2
    types = {f.vuln_type for f in result.findings}
    assert VulnerabilityType.POP_GADGET_CHAIN in types
    assert VulnerabilityType.DIRECT_UNSERIALIZE in types


def test_dynamic_phar_concatenation():
    """Verify dynamic phar concatenation with 'phar://' is detected and boosted to CRITICAL."""
    code = b"""<?php
    $user_file = $_GET['file'];
    $phar_path = "phar://" . $user_file;
    file_exists($phar_path);
    """
    parser = PHPParser()
    root, source_bytes = parser.parse_source(code)

    taint_engine = TaintEngine("dynamic_phar.php", source_bytes, root)
    findings = taint_engine.analyze()

    assert len(findings) >= 1
    phar_f = [f for f in findings if f.vuln_type == VulnerabilityType.PHAR_DESERIALIZATION]
    assert len(phar_f) >= 1
    assert phar_f[0].severity == Severity.CRITICAL
    assert "Explicit Wrapper Detected" in phar_f[0].title


def test_namespace_use_alias_resolution():
    """Verify use declarations and aliases are properly parsed and mapped."""
    code = br"""<?php
    namespace App\Controllers;
    use App\Services\StorageService as Storage;
    use App\Utils\Logger;

    class HomeController extends Storage {
        public function run() {
            Logger::log("hello");
        }
    }
    """
    parser = PHPParser()
    root, source_bytes = parser.parse_source(code)

    st = ProjectSymbolTable()
    visitor = ASTVisitor(st, "home.php", source_bytes)
    visitor.extract_all(root)

    cls = st.get_class("HomeController")
    assert cls is not None
    assert cls.use_map.get("Storage") == "App\\Services\\StorageService"
    assert cls.use_map.get("Logger") == "App\\Utils\\Logger"
    assert cls.resolved_parent == "App\\Services\\StorageService"


def test_interprocedural_taint_propagation(tmp_path):
    """Verify inter-procedural taint propagation across helper functions."""
    helper_code = """<?php
    function get_untrusted_input() {
        return $_GET['payload'];
    }

    function dangerous_sink_wrapper($data) {
        unserialize($data);
    }
    """
    caller_code = """<?php
    $val = get_untrusted_input();
    dangerous_sink_wrapper($val);
    """
    f1 = tmp_path / "helpers.php"
    f1.write_text(helper_code, encoding="utf-8")
    f2 = tmp_path / "main.php"
    f2.write_text(caller_code, encoding="utf-8")

    config = ScannerConfig(target_path=str(tmp_path))
    scanner = PHPDeserializationScanner(config)
    result = scanner.scan()

    assert result.summary.total_findings >= 1
    interproc = [f for f in result.findings if "dangerous_sink_wrapper" in f.title or "unserialize" in f.description]
    assert len(interproc) >= 1
