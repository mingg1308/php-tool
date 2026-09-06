"""
JSON Reporter for machine-readable output.
"""

import json
from php_deserial_sast.models import ScanResult


class JSONReporter:
    """Exports ScanResult to formatted JSON."""

    def generate_json(self, result: ScanResult) -> str:
        return result.model_dump_json(indent=2)

    def save_to_file(self, result: ScanResult, output_path: str):
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(self.generate_json(result))
