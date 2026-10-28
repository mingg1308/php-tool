"""Evidence preservation and explicit rejection of unsupported rule semantics."""
import tempfile
import unittest
from pathlib import Path

from php_deserial_sast.config import ScannerConfig, DEFAULT_BUILTIN_RULES_DIR
from php_deserial_sast.scanner import PHPDeserializationScanner
from php_deserial_sast.rules.engine import Rule, RuleEngine
from php_deserial_sast.models import Finding
from php_deserial_sast.reporters.sarif import SarifReporter


class EvidenceUpgradeTests(unittest.TestCase):
    def scan(self, files, **options):
        with tempfile.TemporaryDirectory() as directory:
            for name, code in files.items():
                path = Path(directory, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("<?php\n" + code, encoding="utf-8")
            return PHPDeserializationScanner(ScannerConfig(
                target_path=directory, enable_gadgets=False, php_version="8.1", **options
            )).scan()

    def test_two_callers_preserve_guard_and_source(self):
        result = self.scan({
            "decode.php": "function decode($x){unserialize($x);}",
            "a.php": "if (custom_guard($_GET['a'])) {decode($_GET['a']);}",
            "b.php": "decode($_POST['b']);",
        })
        flows = [f for f in result.findings if f.metadata.get("engine") == "taint"]
        self.assertFalse(result.errors)
        self.assertEqual(len(flows), 1)
        finding = flows[0]
        self.assertTrue(any(r.review_conditions for r in finding.flow_evidence))
        self.assertTrue(any(not r.review_conditions for r in finding.flow_evidence))
        self.assertGreater(finding.metadata['route_totals']['with_guard'], 0)
        self.assertGreater(finding.metadata['route_totals']['without_guard'], 0)
        self.assertEqual(sum(row['routes'] for row in finding.metadata['route_callers']),
                         finding.metadata['alternative_flow_count'])
        self.assertEqual(finding.assessment.evidence_level, "observed_source_flow")
        self.assertIn("guard_not_proven", finding.assessment.limitations)
        self.assertEqual(finding.assessment.detection_level, "conditional_path")
        restored = Finding.model_validate_json(finding.model_dump_json())
        self.assertEqual(restored.flow_evidence, finding.flow_evidence)
        self.assertFalse(restored.assessment.exploitability_verified)
        sarif = SarifReporter().generate_sarif(result)
        entry = next(item for item in sarif["runs"][0]["results"]
                     if item["ruleId"] == finding.rule_id)
        self.assertEqual(len(entry["properties"]["flow_evidence"]), len(finding.flow_evidence))
        self.assertEqual(entry["properties"]["assessment"]["evidence_level"], "observed_source_flow")

    def test_verified_string_guard_is_accounted_without_hiding_other_caller(self):
        helper = ("function is_serialized_string($data){"
                  "if(!is_string($data)){return false;} $data=trim($data);"
                  "if(strlen($data)<4){return false;}"
                  "elseif('s'!==$data[0]){return false;}else{return true;}}")
        files = {
            'decode.php': helper + 'function decode($s){unserialize($s);}',
            'guarded.php': "if(is_serialized_string($_GET['x'])){decode($_GET['x']);}",
        }
        guarded = self.scan(files)
        self.assertFalse(any(f.metadata.get('engine') == 'taint' for f in guarded.findings))
        self.assertGreater(guarded.analysis['object_payload_exclusion']['distinct_routes'], 0)

        files['unguarded.php'] = "decode($_POST['y']);"
        mixed = self.scan(files)
        finding = next(f for f in mixed.findings if f.metadata.get('engine') == 'taint')
        self.assertEqual(finding.severity.value, 'CRITICAL')
        self.assertGreater(finding.metadata['object_excluded_route_count'], 0)
        self.assertEqual(finding.metadata['route_totals']['without_guard'], 1)
        self.assertEqual(finding.assessment.detection_level, "direct_untrusted_deserialization",
                         finding.assessment.model_dump())

    def test_direct_request_to_unserialize_has_static_detection_evidence(self):
        result = self.scan({"direct.php": "unserialize($_POST['payload']);"})
        finding = next(f for f in result.findings if f.metadata.get("engine") == "taint")
        self.assertEqual(finding.assessment.detection_level, "direct_untrusted_deserialization")
        self.assertFalse(finding.assessment.exploitability_verified)

    def test_syntactic_sink_is_review_candidate(self):
        result = self.scan({"review.php": "function decode($value) { unserialize($value); }"})
        finding = next(f for f in result.findings if f.rule_id == "php-unserialize-review")
        self.assertEqual(finding.assessment.detection_level, "review_candidate")

    def test_igbinary_direct_request_is_detected_as_object_deserialization(self):
        result = self.scan({"direct.php": "use function igbinary_unserialize; igbinary_unserialize($_POST['payload']);"})
        finding = next(f for f in result.findings if f.rule_id == "php-igbinary-unserialize-tainted-input")
        self.assertEqual(finding.assessment.detection_level, "direct_untrusted_deserialization",
                         finding.assessment.model_dump())
        self.assertEqual(finding.metadata["sink_name"], "igbinary_unserialize")
        self.assertTrue(any("igbinary extension" in item for item in finding.metadata["prerequisites"]))

    def test_igbinary_without_observed_source_is_review_only(self):
        result = self.scan({"review.php": "function decode($value) { return igbinary_unserialize($value); }"})
        finding = next(f for f in result.findings if f.rule_id == "php-igbinary-unserialize-review")
        self.assertEqual(finding.assessment.detection_level, "review_candidate")

    def test_namespaced_user_function_does_not_become_igbinary_sink(self):
        result = self.scan({"shadow.php": (
            "namespace Demo; function igbinary_unserialize($value) { return $value; } "
            "igbinary_unserialize($_POST['payload']);"
        )})
        self.assertFalse(any("igbinary" in finding.rule_id for finding in result.findings),
                         [(finding.rule_id, finding.metadata.get("engine")) for finding in result.findings])

    def test_different_guards_survive_summary(self):
        result = self.scan({"a.php": """
            function decode($x) { unserialize($x); }
            function route($x) {
                if (check_one($x)) { decode($x); }
                if (check_two($x)) { decode($x); }
            }
            route($_GET['x']);
        """})
        finding = next(f for f in result.findings if f.metadata.get("engine") == "taint")
        guards = [" ".join(r.review_conditions) for r in finding.flow_evidence]
        self.assertTrue(any("check_one" in g for g in guards))
        self.assertTrue(any("check_two" in g for g in guards))

    def test_unresolved_flow_is_not_observed_evidence(self):
        result = self.scan({"a.php": "unserialize(unknown_decode($_GET['x']));"})
        finding = next(f for f in result.findings if f.metadata.get("engine") == "taint")
        self.assertEqual(finding.assessment.evidence_level, "unresolved_flow")
        self.assertEqual(finding.assessment.analysis_completeness, "limited")

    def test_unsupported_semantics_rejected(self):
        for fields in [
            {"mode": "taint"}, {"pattern-sources": [{"pattern": "$_GET[...]"}]},
            {"patterns": [{"pattern": "unserialize(...)"}]},
            {"pattern-either": [{"pattern-either": [{"pattern": "unserialize(...)"}]}]},
            {"pattern": {"pattern-regex": "unserialize"}},
            {"pattern": None}, {"languages": ["python"]},
        ]:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                rule = {"id": "bad", "pattern": "unserialize(...)"}
                if "pattern-either" in fields:
                    rule.pop("pattern")
                Rule({**rule, **fields})

    def test_bad_rule_does_not_hide_valid_neighbor_and_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "rules.yml").write_text('''rules:
  - id: bad
    mode: taint
    pattern: unserialize(...)
  - id: good
    severity: WARNING
    pattern: unserialize(...)
''', encoding="utf-8")
            rules = RuleEngine(directory)
            self.assertEqual([r.id for r in rules.rules], ["good"])
            self.assertEqual(len(rules.load_errors), 1)
            result = self.scan({"a.php": "unserialize($_GET['x']);"}, rules_dir=directory)
            self.assertTrue(any(e.phase == "rule_load" for e in result.errors))
            self.assertTrue(all(f.assessment.analysis_completeness == "limited" for f in result.findings))

    def test_builtin_rules_remain_loadable(self):
        rules = RuleEngine(DEFAULT_BUILTIN_RULES_DIR)
        self.assertFalse(rules.load_errors)
        self.assertTrue(rules.rules)

    def test_report_trace_budget_does_not_remove_sink(self):
        code = "function decode($x){unserialize($x);}" + "\n".join(
            "decode($_GET['x%d']);" % index for index in range(50))
        result = self.scan({"a.php": code})
        finding = next(f for f in result.findings if f.metadata.get("engine") == "taint")
        self.assertEqual(len(finding.flow_evidence), 32)
        self.assertTrue(finding.metadata["flow_evidence_truncated"])
        self.assertGreaterEqual(finding.metadata["alternative_flow_count"], 50)
        self.assertEqual(finding.metadata['route_totals']['request'],
                         finding.metadata['alternative_flow_count'])
        self.assertTrue(finding.metadata['route_callers_truncated'])
        self.assertIn("displayed_flow_evidence_truncated", finding.assessment.limitations)

    def test_trace_budget_keeps_different_guard_group_across_files(self):
        result = self.scan({
            "decode.php": "function decode($x){unserialize($x);}",
            "a.php": "\n".join("decode($_GET['x%d']);" % i for i in range(40)),
            "b.php": "if (custom_guard($_POST['b'])) {decode($_POST['b']);}",
        })
        finding = next(f for f in result.findings if f.metadata.get("engine") == "taint")
        self.assertLessEqual(len(finding.flow_evidence), 32)
        self.assertTrue(any(route.review_conditions for route in finding.flow_evidence))
        self.assertTrue(any(not route.review_conditions for route in finding.flow_evidence))
