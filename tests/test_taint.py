"""
Unit tests for Taint Analysis and Source-to-Sink tracking.
"""

import pytest
from php_deserial_sast.core.parser import PHPParser
from php_deserial_sast.core.taint_engine import TaintEngine
from php_deserial_sast.models import Severity, VulnerabilityType


def test_taint_direct_unserialize():
    code = b"""<?php
    $cookie = $_COOKIE['session'];
    $decoded = base64_decode($cookie);
    $obj = unserialize($decoded);
    """
    parser = PHPParser()
    root, source_bytes = parser.parse_source(code)
    
    taint_engine = TaintEngine("sample.php", source_bytes, root)
    findings = taint_engine.analyze()

    assert len(findings) >= 1
    unserialize_findings = [f for f in findings if f.vuln_type == VulnerabilityType.DIRECT_UNSERIALIZE]
    assert len(unserialize_findings) >= 1
    f = unserialize_findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.dataflow_trace is not None
    assert len(f.dataflow_trace) >= 2


def test_taint_safe_allowed_classes():
    code = b"""<?php
    $cookie = $_COOKIE['session'];
    $obj = unserialize($cookie, ['allowed_classes' => false]);
    """
    parser = PHPParser()
    root, source_bytes = parser.parse_source(code)
    
    taint_engine = TaintEngine("safe.php", source_bytes, root)
    findings = taint_engine.analyze()

    # Should not flag direct insecure deserialization because of allowed_classes => false
    assert len(findings) == 0


def test_taint_phar_deserialization():
    code = b"""<?php
    $path = $_GET['file_url'];
    if (file_exists($path)) {
        echo "File exists";
    }
    """
    parser = PHPParser()
    root, source_bytes = parser.parse_source(code)
    
    taint_engine = TaintEngine("phar_test.php", source_bytes, root)
    findings = taint_engine.analyze()

    phar_findings = [f for f in findings if f.vuln_type == VulnerabilityType.PHAR_DESERIALIZATION]
    assert len(phar_findings) >= 1
    assert phar_findings[0].severity == Severity.HIGH
