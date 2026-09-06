"""
OASIS SARIF v2.1.0 JSON Reporter for CI/CD and GitHub Security integration.
"""

import json
from typing import Dict, Any, List
from php_deserial_sast.models import ScanResult, Severity


SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


class SarifReporter:
    """Generates standard SARIF v2.1.0 JSON reports."""

    def __init__(self, scanner_name: str = "PHP-Deserial-SAST", version: str = "1.0.0"):
        self.scanner_name = scanner_name
        self.version = version

    def generate_sarif(self, result: ScanResult) -> Dict[str, Any]:
        """Convert ScanResult to SARIF 2.1.0 dictionary."""
        rules_map: Dict[str, Dict[str, Any]] = {}
        sarif_results: List[Dict[str, Any]] = []

        for finding in result.findings:
            # Register rule
            if finding.rule_id not in rules_map:
                rules_map[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning")
                    },
                    "help": {
                        "text": finding.remediation or finding.description,
                        "markdown": f"### Remediation\n{finding.remediation}" if finding.remediation else finding.description
                    },
                    "properties": {
                        "tags": ["security", "cwe-502", "insecure-deserialization", "php"],
                        "security-severity": "9.8" if finding.severity == Severity.CRITICAL else "7.5"
                    }
                }

            # Build result item
            res_item: Dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": finding.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location.file_path.replace("\\", "/")
                        },
                        "region": {
                            "startLine": finding.location.start_line,
                            "startColumn": finding.location.start_col,
                            "endLine": finding.location.end_line,
                            "endColumn": finding.location.end_col
                        }
                    }
                }]
            }

            # CodeFlows for dataflow / gadget chain
            thread_flow_locations = []
            if finding.dataflow_trace:
                for step in finding.dataflow_trace:
                    thread_flow_locations.append({
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": step.location.file_path.replace("\\", "/")},
                                "region": {"startLine": step.location.start_line, "startColumn": step.location.start_col}
                            },
                            "message": {"text": step.description}
                        }
                    })

            if thread_flow_locations:
                res_item["codeFlows"] = [{
                    "threadFlows": [{
                        "locations": thread_flow_locations
                    }]
                }]

            sarif_results.append(res_item)

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.scanner_name,
                            "version": self.version,
                            "informationUri": "https://github.com/ambionics/phpggc",
                            "rules": list(rules_map.values())
                        }
                    },
                    "results": sarif_results
                }
            ]
        }
        return sarif_doc

    def save_to_file(self, result: ScanResult, output_path: str):
        sarif_data = self.generate_sarif(result)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)
