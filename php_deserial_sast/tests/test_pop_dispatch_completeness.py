import unittest
from php_deserial_sast.core.parser import PHPParser
from php_deserial_sast.core.ast_visitor import ASTVisitor
from php_deserial_sast.core.symbol_table import ProjectSymbolTable
from php_deserial_sast.core.call_graph import CallGraph
from php_deserial_sast.core.gadget_finder import GadgetFinder

class POPDispatchCompletenessTests(unittest.TestCase):
    def graph(self, code):
        root, source = PHPParser().parse_source("<?php " + code)
        symbols = ProjectSymbolTable()
        ASTVisitor(symbols, "fixture.php", source).extract_all(root)
        return CallGraph(symbols)

    def test_more_than_twelve_overrides_are_retained(self):
        code = "class Base {function run(){$this->go();} function go(){}}"
        code += " ".join("class Child%d extends Base {function go(){system($this->cmd);}}" % i for i in range(18))
        graph = self.graph(code)
        targets = {e.callee_class for e in graph.edges if e.edge_type == "VIRTUAL_OVERRIDE" and e.caller_class == "Base"}
        self.assertEqual(len(targets), 18)
        self.assertEqual(graph.dispatch_candidates_truncated, 0)

    def test_more_than_four_property_targets_are_retained(self):
        code = "class Caller {function __destruct(){$this->object->go();}}"
        code += " ".join("class Receiver%d {function go(){system($this->cmd);}}" % i for i in range(8))
        graph = self.graph(code)
        targets = {e.callee_class for e in graph.edges if e.edge_type == "SERIALIZED_PROPERTY_DISPATCH" and e.caller_class == "Caller"}
        self.assertEqual(len(targets), 8)
        self.assertEqual(graph.dispatch_candidates_truncated, 0)

    def test_inherited_method_keeps_concrete_receiver_across_calls(self):
        code = (
            'class Base { function __destruct(){$this->go();} '
            'function go(){$this->finish();} function finish(){} } '
            'class Safe extends Base { function finish(){} } '
            'class Dangerous extends Base { function finish(){system("x");} }'
        )
        graph = self.graph(code)
        chains = GadgetFinder(graph.symbol_table, graph).find_all_gadget_chains()
        self.assertFalse(any(chain.entry_class == 'Safe' for chain in chains))
        self.assertTrue(any(chain.entry_class == 'Dangerous'
                            and chain.sink_function == 'system' for chain in chains))
