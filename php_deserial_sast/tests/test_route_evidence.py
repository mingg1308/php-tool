"""A route has an inspectable identity and does not overstate gadget proof."""
import tempfile
import unittest
from pathlib import Path

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.models import ScanResult
from php_deserial_sast.reporters.sarif import SarifReporter
from php_deserial_sast.scanner import PHPDeserializationScanner


class RouteEvidenceTests(unittest.TestCase):
    def scan(self, sources, *, gadgets=False):
        with tempfile.TemporaryDirectory() as directory:
            for name, code in sources.items():
                path = Path(directory, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('<?php\n' + code, encoding='utf-8')
            result = PHPDeserializationScanner(ScannerConfig(
                target_path=directory, enable_gadgets=gadgets,
                php_version='8.1')).scan()
            return result

    def test_direct_source_and_guarded_route_are_distinct(self):
        result = self.scan({
            'sink.php': 'function decode($value) { unserialize($value); }',
            'a.php': "decode($_GET['x']);",
            'b.php': "if (check($_POST['y'])) { decode($_POST['y']); }",
        })
        self.assertFalse(result.errors)
        routes = [route for route in result.routes
                  if route.route_kind == 'source_to_sink']
        self.assertEqual(len(routes), 2)
        self.assertEqual({route.status for route in routes}, {'conditional'})
        self.assertEqual(len({route.route_id for route in routes}), 2)
        self.assertTrue(any('guard_feasibility' in route.missing_edges for route in routes))
        self.assertTrue(any('guard_feasibility' not in route.missing_edges for route in routes))
        self.assertEqual(len(ScanResult.model_validate_json(result.model_dump_json()).routes), 2)

    def test_unknown_propagation_is_not_proven(self):
        result = self.scan({'a.php': "unserialize(unknown_decode($_GET['x']));"})
        route = next(route for route in result.routes
                     if route.route_kind == 'source_to_sink')
        self.assertEqual(route.status, 'unknown')
        self.assertIn('unresolved_data_propagation', route.missing_edges)
        self.assertFalse(route.runtime_verified)

    def test_direct_request_has_static_route_and_sarif_reference(self):
        result = self.scan({'a.php': "unserialize($_POST['payload']);"})
        route = next(route for route in result.routes
                     if route.route_kind == 'source_to_sink')
        self.assertEqual(route.status, 'proven')
        self.assertFalse(route.runtime_verified)
        sarif = SarifReporter().generate_sarif(result)
        matches = [item for item in sarif['runs'][0]['results']
                   if any(row['route_id'] == route.route_id
                          for row in item['properties']['routes'])]
        self.assertEqual(len(matches), 1)

    def test_candidate_gadget_does_not_claim_runtime_proof(self):
        code = ('class Payload { public $cmd; function __wakeup() {'
                'system($this->cmd); } } unserialize($_POST["data"]);')
        result = self.scan({'a.php': code}, gadgets=True)
        self.assertFalse(result.errors)
        candidates = [route for route in result.routes
                      if route.route_kind == 'candidate_gadget']
        self.assertTrue(candidates)
        self.assertTrue(all(route.status == 'conditional' and not route.runtime_verified
                            and route.gadget_chain_id for route in candidates))

    def test_duplicate_test_class_cannot_link_production_gadget(self):
        result = self.scan({
            'app.php': ('class Payload { public $cmd; function __wakeup() {'
                        'system($this->cmd); } } unserialize($_POST["data"]);'),
            'tests/test.php': ('class Payload { function __wakeup() {} } '
                               'unserialize($_POST["data"]);'),
        }, gadgets=True)
        candidates = [route for route in result.routes
                      if route.route_kind == 'candidate_gadget']
        self.assertTrue(candidates)
        self.assertTrue(all(route.sink.file_path.endswith('app.php')
                            for route in candidates))


if __name__ == '__main__':
    unittest.main()
