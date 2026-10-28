"""Constructor properties must follow helper summaries and escaping writes."""
import unittest
from php_deserial_sast.core.parser import PHPParser
from php_deserial_sast.core.ast_visitor import ASTVisitor
from php_deserial_sast.core.symbol_table import ProjectSymbolTable
from php_deserial_sast.core.dataflow import FlowProject
from php_deserial_sast.core.taint_engine import TaintEngine


def library_analyze(code, demand=True, library=True):
    root, source = PHPParser().parse_source('<?php ' + code)
    assert not root.has_error
    symbols = ProjectSymbolTable()
    ASTVisitor(symbols, 'fixture.php', source).extract_all(root)
    project = FlowProject({'fixture.php': (root, source)}, symbols, library_mode=library,
                          experimental_demand_summaries=demand)
    project.build()
    findings = TaintEngine('fixture.php', source, root, project=project, php_version='8.1').analyze()
    return findings, project


LIBRARY_CASES = {
    'direct': ('class Box {function __construct($x){$this->payload=$x;} function run(){unserialize($this->payload);}}', True),
    'helper': ('function identity($x){return $x;} class Box {function __construct($x){$this->payload=identity($x);} function run(){unserialize($this->payload);}}', True),
    'safe_helper': ("function fixed($x){return 'a:0:{}';} class Box {function __construct($x){$this->payload=fixed($x);} function run(){unserialize($this->payload);}}", False),
    'overwrite': ("class Box {function __construct($x){$this->payload=$x; $this->payload='safe';} function run(){unserialize($this->payload);}}", False),
    'conditional_overwrite': ("class Box {function __construct($x){$this->payload=$x; if(rand())$this->payload='safe';} function run(){unserialize($this->payload);}}", True),
    'unreachable': ('class Box {function __construct($x){return; $this->payload=$x;} function run(){unserialize($this->payload);}}', False),
    'throwing_constructor': ('class Box {function __construct($x){$this->payload=$x; throw new Exception();} function run(){unserialize($this->payload);}}', False),
    'early_return': ('class Box {function __construct($x){$this->payload=$x; return;} function run(){unserialize($this->payload);}}', True),
    'different_case': ('class Box {function __construct($x){$this->Payload=$x;} function run(){unserialize($this->payload);}}', False),
    'matching_case': ('class Box {function __construct($x){$this->Payload=$x;} function run(){unserialize($this->Payload);}}', True),
    'private_constructor': ('class Box {private function __construct($x){$this->payload=$x;} function run(){unserialize($this->payload);}}', False),
    'inherited_property': ('class Base {function __construct($x){$this->payload=$x;}} class Box extends Base {function run(){unserialize($this->payload);}}', True),
}


class LibraryPropertyFlowTests(unittest.TestCase):
    def test_labeled_cases_in_both_summary_modes(self):
        for demand in (False, True):
            for name, (code, expected) in LIBRARY_CASES.items():
                with self.subTest(demand=demand, case=name):
                    findings, project = library_analyze(code, demand)
                    self.assertTrue(project.converged)
                    self.assertEqual(bool(findings), expected)
                    for finding in findings:
                        self.assertEqual(finding.metadata['source_assumption'], 'library_public_api_parameter')
                        self.assertFalse(finding.metadata['exploitability_verified'])

    def test_constructor_helpers_refresh_method_return_summaries(self):
        code = '''function helper($x){return $x;}
        class Box {function __construct($x){$this->payload=helper($x);}
                   function value(){return $this->payload;}}
        function endpoint(Box $box){unserialize($box->value());}'''
        for demand in (False, True):
            findings, project = library_analyze(code, demand)
            self.assertTrue(project.converged)
            self.assertTrue(findings)
            self.assertGreaterEqual(project.library_property_rounds, 2)
            demands = set(project.return_demands)
            for engine in project.files.values():
                TaintEngine(engine.path, engine.source, engine.root, project=project).analyze()
            self.assertEqual(demands, project.return_demands)

    def test_application_mode_does_not_assume_constructor_control(self):
        findings, project = library_analyze(LIBRARY_CASES['helper'][0], library=False)
        self.assertFalse(findings)
        self.assertFalse(project.library_properties)

    def test_rebuilding_is_stable(self):
        findings, project = library_analyze(LIBRARY_CASES['helper'][0])
        before = project._signature(project.returns, project.sinks)
        project.build()
        self.assertTrue(project.converged)
        self.assertEqual(before, project._signature(project.returns, project.sinks))
