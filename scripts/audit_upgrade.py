"""Validate full-scan artifacts and retain coverage limits separately from failures."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from php_deserial_sast.models import ScanResult


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("label")
    parser.add_argument("--supplement", nargs="*", default=[])
    args = parser.parse_args()
    folder = ROOT / "reports/evaluation" / args.label
    runs = json.loads((folder / "runs.json").read_text(encoding="utf-8"))
    locations = {run["project"]: folder for run in runs}
    for supplement in args.supplement:
        other = ROOT / "reports/evaluation" / supplement
        first_manifest = json.loads((folder / "source_manifest.json").read_text(encoding="utf-8"))
        other_manifest = json.loads((other / "source_manifest.json").read_text(encoding="utf-8"))
        if first_manifest != other_manifest:
            raise ValueError("Cannot combine different scanner snapshots")
        additional = json.loads((other / "runs.json").read_text(encoding="utf-8"))
        replaced = {run["project"] for run in additional}
        runs = [run for run in runs if run["project"] not in replaced] + additional
        locations.update({run["project"]: other for run in additional})
    expected = {p.name for p in (ROOT / "testcase").iterdir() if p.is_dir()}
    rows, failures = [], []
    for run in runs:
        project = run["project"]
        path = locations[project] / (project + ".json")
        if run["status"] != "finished" or not path.exists():
            failures.append({"project": project, "reason": "missing_or_unfinished_report"})
            continue
        try:
            result = ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            failures.append({"project": project, "reason": "invalid_report", "detail": str(exc)})
            continue
        if result.summary.total_findings != len(result.findings):
            raise ValueError("Finding count mismatch: " + project)
        operational = [e.model_dump() for e in result.errors if e.phase not in {"call_graph_limit", "gadget_limit"}]
        if operational:
            failures.append({"project": project, "errors": operational})
        if any(f.assessment is None for f in result.findings):
            failures.append({"project": project, "reason": "missing_evidence_assessment"})
        rows.append({"project": project, "files": result.summary.total_files_scanned,
                     "report": path.relative_to(ROOT).as_posix(),
                     "findings": len(result.findings), "seconds": run["seconds"],
                     "by_evidence": dict(Counter(f.assessment.evidence_level if f.assessment else "missing" for f in result.findings)),
                     "by_status": dict(Counter(f.metadata.get("analysis_status", "unknown") for f in result.findings)),
                     "control_flow": result.analysis.get("control_flow"),
                     "errors": [e.model_dump() for e in result.errors],
                     "operational_errors": operational})
    missing = sorted(expected - {row["project"] for row in rows})
    if missing:
        failures.append({"missing_projects": missing})
    manifest = json.loads((folder / "source_manifest.json").read_text(encoding="utf-8"))
    current_manifest = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in (ROOT / "php_deserial_sast").rglob("*")
                        if p.suffix in {".py", ".yaml"}}
    changed = sorted(name for name in manifest.keys() | current_manifest.keys()
                     if manifest.get(name) != current_manifest.get(name))
    snapshot_errors = [name for name, digest in manifest.items()
                       if not (folder / "source" / name).exists()
                       or hashlib.sha256((folder / "source" / name).read_bytes()).hexdigest() != digest]
    output = {"label": args.label, "expected_projects": len(expected), "validated_reports": len(rows),
              "operational_failures": failures, "source_changed_since_snapshot": changed,
              "snapshot_integrity_errors": snapshot_errors, "projects": rows,
              "note": "Operational success is not complete PHP coverage or proof of exploitability. POP caps and CFG fallback remain explicit."}
    (folder / "audit.json").write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"reports": len(rows), "failures": failures, "changed_source_files": len(changed)}))
    return int(bool(failures or snapshot_errors))


if __name__ == "__main__":
    raise SystemExit(main())
