"""
Unit tests for Semgrep-like YAML Rule Engine.
"""

import os
import pytest
from php_deserial_sast.core.parser import PHPParser
from php_deserial_sast.rules.engine import RuleEngine
from php_deserial_sast.config import DEFAULT_BUILTIN_RULES_DIR


def test_rule_engine_loading():
    engine = RuleEngine(DEFAULT_BUILTIN_RULES_DIR)
    assert len(engine.rules) > 0
    rule_ids = [r.id for r in engine.rules]
    assert "php-insecure-unserialize-direct" in rule_ids
    assert "php-phar-filesystem-deserialization" in rule_ids


def test_rule_engine_evaluation():
    engine = RuleEngine(DEFAULT_BUILTIN_RULES_DIR)
    code = b"""<?php
    $data = unserialize($_POST['exploit']);
    """
    parser = PHPParser()
    root, source_bytes = parser.parse_source(code)
    
    findings = engine.evaluate_file("vuln.php", source_bytes, root)
    assert len(findings) >= 1
    direct_match = [f for f in findings if f.rule_id == "php-insecure-unserialize-direct"]
    assert len(direct_match) >= 1
