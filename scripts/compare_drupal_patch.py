"""Compare focused taint findings in the affected and fixed Drupal releases."""
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.models import Severity
from php_deserial_sast.scanner import PHPDeserializationScanner


def main():
    rows = []
    for release in ("8.6.9", "8.6.10"):
        target = ROOT / "testcase" / f"drupal-{release}"
        if not target.is_dir():
            raise SystemExit(f"Missing source tree: {target}")
        start = time.perf_counter()
        report = PHPDeserializationScanner(ScannerConfig(
            target_path=str(target), php_version="7.4", min_severity=Severity.INFO,
            enable_gadgets=False, enable_rules=False,
            experimental_side_effects=False,
        )).scan()
        rows.append({
            "release": release,
            "seconds": round(time.perf_counter() - start, 3),
            "errors": [error.model_dump() for error in report.errors],
            "findings": [{"file": str(Path(f.location.file_path).relative_to(target)),
                          "line": f.location.start_line, "severity": f.severity.value,
                          "sink": f.metadata.get("sink_name")}
                         for f in report.findings],
        })
        print(json.dumps(rows[-1], ensure_ascii=False), flush=True)
    output = ROOT / "reports/evaluation/retest-2026-10-30-rss/drupal-patch-comparison.json"
    if "--no-save" not in sys.argv:
        output.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
