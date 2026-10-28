"""Regression checks for traits and conditional Drupal dispatch."""
import unittest
from php_deserial_sast.tests.test_dataflow_regression import analyze

class TraitResolutionTests(unittest.TestCase):
    def test_trait_sink(self):
        findings, _ = analyze("trait Decode {function load($v){unserialize($v);}} class Box {use Decode;} $b=new Box(); $b->load($_GET['x']);")
        self.assertTrue(findings)

    def test_nested_trait(self):
        findings, _ = analyze("trait Decode {function load($v){unserialize($v);}} trait Nested {use Decode;} class Box {use Nested;} $b=new Box(); $b->load($_GET['x']);")
        self.assertTrue(findings)

    def test_class_overrides_trait(self):
        findings, _ = analyze("trait Decode {function load($v){unserialize($v);}} class Box {use Decode; function load($v){return 1;}} $b=new Box(); $b->load($_GET['x']);")
        self.assertFalse(findings)

    def test_trait_overrides_parent(self):
        findings, _ = analyze("class ParentBox {function load($v){return 1;}} trait Decode {function load($v){unserialize($v);}} class Box extends ParentBox {use Decode;} $b=new Box(); $b->load($_GET['x']);")
        self.assertTrue(findings)

    def test_constant_argument(self):
        findings, _ = analyze("trait Decode {function load($v){unserialize($v);}} class Box {use Decode;} $b=new Box(); $b->load('constant');")
        self.assertFalse(findings)

    def test_adaptation_is_not_guessed(self):
        findings, _ = analyze("trait A {function load($v){unserialize($v);}} trait B {function load($v){return 1;}} class Box {use A,B {B::load insteadof A;}} $b=new Box(); $b->load($_GET['x']);")
        self.assertFalse(findings)

class FrameworkDispatchTests(unittest.TestCase):
    def test_field_candidates_exclude_test_modules_when_production_exists(self):
        from php_deserial_sast.core.framework_dispatch import FIELD_BASE, _field_candidates
        from php_deserial_sast.core.symbol_table import ClassSymbol, ProjectSymbolTable

        symbols = ProjectSymbolTable()
        symbols.add_class(ClassSymbol(name='FieldItemBase', full_name=FIELD_BASE,
                                      is_abstract=True, file_path='core/lib/FieldItemBase.php'))
        symbols.add_class(ClassSymbol(name='RealItem', full_name='Drupal\\Field\\RealItem',
                                      resolved_parent=FIELD_BASE,
                                      file_path='core/modules/field/src/RealItem.php'))
        symbols.add_class(ClassSymbol(name='TestObjectItem', full_name='Drupal\\field_test\\TestObjectItem',
                                      resolved_parent=FIELD_BASE,
                                      file_path='core/modules/field/tests/modules/field_test/src/TestObjectItem.php'))
        self.assertEqual(_field_candidates(symbols), ['Drupal\\Field\\RealItem'])

    def test_field_candidates_preserve_isolated_test_scan(self):
        from php_deserial_sast.core.framework_dispatch import FIELD_BASE, _field_candidates
        from php_deserial_sast.core.symbol_table import ClassSymbol, ProjectSymbolTable

        symbols = ProjectSymbolTable()
        symbols.add_class(ClassSymbol(name='FieldItemBase', full_name=FIELD_BASE,
                                      is_abstract=True, file_path='lib/FieldItemBase.php'))
        symbols.add_class(ClassSymbol(name='TestObjectItem', full_name='Drupal\\field_test\\TestObjectItem',
                                      resolved_parent=FIELD_BASE, file_path='tests/TestObjectItem.php'))
        self.assertEqual(_field_candidates(symbols), ['Drupal\\field_test\\TestObjectItem'])

    def test_production_dispatch_does_not_reach_test_only_field_sink(self):
        from php_deserial_sast.tests.test_evidence_upgrade import EvidenceUpgradeTests

        result = EvidenceUpgradeTests().scan({
            'src/Base.php': r'namespace Drupal\Core\Field; abstract class FieldItemBase {}',
            'src/Real.php': (r'namespace Drupal\Core\Field; '
                             r'class RealItem extends FieldItemBase {function setValue($data){return $data;}}'),
            'tests/TestObjectItem.php': (r'namespace Drupal\field_test; '
                                         r'class TestObjectItem extends \Drupal\Core\Field\FieldItemBase '
                                         r'{function setValue($data){unserialize($data);}}'),
            'src/Normalizer.php': (r'namespace Drupal\serialization\Normalizer; '
                                   r'class FieldItemNormalizer {function denormalize($data,$class,$format=null,'
                                   r'array $context=[]) {$field=$context["target_instance"]; '
                                   r'$field->setValue($data);}}'),
            'entry.php': (r'$n=new \Drupal\serialization\Normalizer\FieldItemNormalizer(); '
                          r'$n->denormalize($_POST["x"],"RealItem",null,[]);'),
        })
        self.assertFalse(result.errors)
        self.assertFalse(any(f.metadata.get('engine') == 'taint'
                             and f.location.file_path.endswith('TestObjectItem.php')
                             for f in result.findings))

    def test_drupal_decode_only_propagates_request_body(self):
        template = r"""
namespace Drupal\rest {
  class RequestHandler {
    function deserialize($body, $format) {
      $decoded = $this->serializer->decode(BODY, FORMAT, ['request_method' => 'post']);
      unserialize($decoded);
    }
  }
}
"""
        format_only = template.replace("BODY", "'safe'").replace("FORMAT", "$_GET['format']")
        body_only = template.replace("BODY", "$_POST['body']").replace("FORMAT", "'json'")
        self.assertFalse(analyze(format_only)[0])
        findings, _ = analyze(body_only)
        self.assertTrue(findings)
        self.assertTrue(any("decoder and format require runtime review" in step.description
                            for finding in findings for step in finding.dataflow_trace))

    def check_dispatch(self, argument="$_POST['x']", context="target_instance", namespace="Drupal", restriction=""):
        code = r"""
namespace Drupal\Core\Field {abstract class FieldItemBase {} class Demo extends FieldItemBase {function setValue($data){unserialize($data RESTRICTION);}}}
namespace Drupal\serialization\Normalizer {class FieldItemNormalizer {function denormalize($data,$class,$format=null,array $context=[]) {$field=$context['CONTEXT']; $field->setValue($data);}}}
namespace { $n=new \Drupal\serialization\Normalizer\FieldItemNormalizer(); $n->denormalize(ARGUMENT,'Demo',null,[]); }
""".replace("RESTRICTION", restriction).replace("CONTEXT", context).replace("ARGUMENT", argument).replace("Drupal", namespace)
        return analyze(code)

    def test_context_dispatch(self):
        findings, project = self.check_dispatch()
        self.assertTrue(findings)
        self.assertTrue(any("Framework dispatch model:" in step.description for f in findings for step in f.dataflow_trace))
        self.assertEqual(project.framework_dispatch.statistics()["modeled_calls"], 1)

    def test_safe_argument(self):
        self.assertFalse(self.check_dispatch(argument="'constant'")[0])

    def test_unrelated_namespace(self):
        self.assertFalse(self.check_dispatch(namespace="Application")[0])

    def test_wrong_context_key(self):
        self.assertFalse(self.check_dispatch(context="other")[0])

    def test_object_reconstruction_disabled(self):
        self.assertFalse(self.check_dispatch(restriction=", ['allowed_classes'=>false]")[0])

class CrossFileInventoryTests(unittest.TestCase):
    def test_caller_reconciles_inventory(self):
        from php_deserial_sast.tests.test_evidence_upgrade import EvidenceUpgradeTests
        result = EvidenceUpgradeTests().scan({
            "callee.php": "function restore($value){unserialize($value);}",
            "caller.php": "restore($_POST['data']);",
        })
        self.assertEqual(len(result.sink_inventory), 1)
        self.assertEqual(result.sink_inventory[0].disposition, "interprocedural_source_to_sink_review")
        self.assertTrue(result.sink_inventory[0].evidence)

    def test_framework_can_be_disabled(self):
        _, project = FrameworkDispatchTests().check_dispatch()
        project.framework_dispatch.enabled = False
        project.framework_dispatch.cache.clear()
        project.framework_dispatch.reasons.clear()
        project.resolutions.clear()
        for engine in project.files.values():
            for nodes in engine.nodes.values():
                for node in nodes:
                    self.assertFalse(project.framework_dispatch.targets(engine, node))
