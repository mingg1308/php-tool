"""Re-export saved evidence without rescanning; provenance is recorded explicitly."""
import argparse
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from php_deserial_sast.models import ScanResult
from php_deserial_sast.core.evidence import compact_flow_evidence, assess_finding
from php_deserial_sast.reporters.json_reporter import JSONReporter


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        raise ValueError("Use a separate output to preserve the scan artifact")
    raw = args.source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    result = ScanResult.model_validate_json(raw)
    del raw
    before = [(f.id, f.severity, f.location) for f in result.findings]
    for finding in result.findings:
        original = len(finding.flow_evidence)
        finding.flow_evidence, _ = compact_flow_evidence(finding.flow_evidence)
        if original > len(finding.flow_evidence):
            finding.metadata["flow_evidence_truncated"] = True
            finding.metadata["flow_evidence_limit"] = 32
            finding.metadata["alternative_flow_count"] = max(original, finding.metadata.get("alternative_flow_count", 0))
        assess_finding(finding, result.errors)
    result.analysis["report_processing"] = {
        "operation": "evidence_compaction_only_not_a_rescan", "source": str(args.source), "source_sha256": digest}
    JSONReporter().save_to_file(result, str(args.output))
    restored = ScanResult.model_validate_json(args.output.read_bytes())
    assert before == [(f.id, f.severity, f.location) for f in restored.findings]
    print(f"Preserved {len(before)} findings; bytes {args.source.stat().st_size} -> {args.output.stat().st_size}")


if __name__ == "__main__":
    main()
