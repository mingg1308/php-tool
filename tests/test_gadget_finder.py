"""
Unit tests for POP Gadget Chain Finder and Call Graph.
"""

import pytest
from php_deserial_sast.core.parser import PHPParser
from php_deserial_sast.core.symbol_table import ProjectSymbolTable
from php_deserial_sast.core.ast_visitor import ASTVisitor
from php_deserial_sast.core.call_graph import CallGraph
from php_deserial_sast.core.gadget_finder import GadgetFinder
from php_deserial_sast.models import Severity


CHAIN_SAMPLE = b"""<?php
namespace App\\Testing;

class EntryClass {
    public $logger;
    public function __destruct() {
        if ($this->logger) {
            $this->logger->close();
        }
    }
}

class SinkClass {
    public function close() {
        eval($this->payload);
    }
}
"""


def test_pop_gadget_chain_discovery():
    parser = PHPParser()
    root, source_bytes = parser.parse_source(CHAIN_SAMPLE)
    
    st = ProjectSymbolTable()
    visitor = ASTVisitor(st, "chain_test.php", source_bytes)
    visitor.extract_all(root)

    cg = CallGraph(st)
    finder = GadgetFinder(st, cg)
    chains = finder.find_all_gadget_chains()

    assert len(chains) >= 1
    chain = chains[0]
    assert chain.entry_class == "EntryClass"
    assert chain.entry_method == "__destruct"
    assert chain.sink_class == "SinkClass"
    assert chain.sink_method == "close"
    assert chain.sink_function == "eval"
    assert chain.severity == Severity.CRITICAL
    assert len(chain.steps) == 3  # Entry -> Hop to SinkClass::close -> Sink eval
