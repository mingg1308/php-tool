"""
Unit tests for PHP Tree-sitter Parser and AST Visitor.
"""

import os
import pytest
from php_deserial_sast.core.parser import PHPParser, get_node_text, find_nodes_by_type
from php_deserial_sast.core.symbol_table import ProjectSymbolTable
from php_deserial_sast.core.ast_visitor import ASTVisitor


SAMPLE_CODE = b"""<?php
namespace App\\Testing;

class TargetClass extends BaseClass {
    public $handler;
    private $logFile = '/tmp/log';

    public function __destruct() {
        if ($this->handler) {
            $this->handler->close();
        }
    }

    public function __toString() {
        return (string)$this->handler;
    }

    public function doWork() {
        eval($this->handler);
    }
}
"""


def test_parser_basic():
    parser = PHPParser()
    root, source_bytes = parser.parse_source(SAMPLE_CODE)
    assert root is not None
    assert root.type == "program"


def test_ast_visitor_extraction():
    parser = PHPParser()
    root, source_bytes = parser.parse_source(SAMPLE_CODE)
    
    st = ProjectSymbolTable()
    visitor = ASTVisitor(st, "test.php", source_bytes)
    visitor.extract_all(root)

    cls = st.get_class("TargetClass")
    assert cls is not None
    assert cls.namespace == "App\\Testing"
    assert cls.parent_class == "BaseClass"
    assert "handler" in cls.properties
    assert "logFile" in cls.properties

    # Check magic methods
    magic_methods = cls.get_magic_methods()
    assert "__destruct" in magic_methods
    assert "__toString" in magic_methods
    assert "doWork" in cls.methods

    # Check doWork has eval sink
    do_work = cls.methods["doWork"]
    sinks = [c for c in do_work.calls if c.is_sink]
    assert len(sinks) >= 1
    assert sinks[0].callee_name == "eval"
    assert sinks[0].sink_category == "RCE"
