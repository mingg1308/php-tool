"""Normalize sink locations, preserving incomplete scans and separate evidence types."""
import argparse
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
BASE = ROOT / "reports/evaluation"


def read(path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return default


def site(path, line, project):
    path = path.replace("\\", "/")
    for prefix in ("/tmp/target/", "testcase/" + project + "/"):
        if prefix in path:
            path = path.split(prefix, 1)[1]
            break
    return path + ":" + str(line)


def reference(tool, project, labels):
    selected = None
    for label in labels:
        runs = read(BASE / label / (tool + "-runs.json"), [])
        for run in runs:
            if run["project"] == project:
                selected = (label, run)
    if selected is None:
        return {"status": "not_run", "sites": None}
    label, run = selected
    data = read(BASE / label / tool / project / "result.json")
    status = run["status"]
    sites = None
    if tool == "psalm" and isinstance(data, list):
        sites = sorted({site(f["file_path"], f["line_from"], project)
                        for f in data if f.get("type") == "TaintedUnserialize"})
        status = "report_with_diagnostics" if any(not f.get("is_security") for f in data) else "report"
    elif tool == "progpilot" and isinstance(data, dict):
        sites = sorted({site(f["sink_file"], f["sink_line"], project)
                        for f in data.get("results", []) if f.get("sink_name") == "unserialize"})
        status = "partial_error" if data.get("error") or run.get("exit_code") != 0 else "report"
    elif status == "finished":
        status = "failed_no_report"
    if run["status"] == "timeout":
        status = "timeout_partial" if sites is not None else "timeout"
    fixture_names = ([Path(p).stem for p in read(BASE / label / tool / project / 'files.json', [])]
                     if project == 'fixtures' else None)
    return {"status": status, "sites": sites, "seconds": run["seconds"], "fixture_names": fixture_names,
            "exit_code": run.get("exit_code"), "label": label,
            "evidence": str((BASE / label / tool / project).relative_to(ROOT))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="optimized")
    parser.add_argument("--references", nargs="+", default=["external-final", "external-retry"])
    args = parser.parse_args()
    runs = read(BASE / args.label / "runs.json", [])
    before = {r["project"]: r for r in read(BASE / "before/runs.json", [])}
    rows = []
    details = {}
    for run in runs:
        project = run["project"]
        data = read(BASE / args.label / (project + ".json"))
        own = {"status": run["status"], "seconds": run["seconds"], "sites": None}
        if data is not None:
            groups = {}
            for finding in data.get("findings", []):
                meta = finding.get("metadata", {})
                group = ("taint_" + meta.get("source_assumption", "unknown")
                         if meta.get("engine") == "taint" and meta.get("sink_name") == "unserialize"
                         else "other_findings")
                loc = finding["location"]
                groups.setdefault(group, set()).add(site(loc["file_path"], loc["start_line"], project))
            own.update(status="incomplete" if data.get("errors") else "report",
                       sites=sorted(groups.get("taint_observed_request", set())),
                       groups={k: sorted(v) for k, v in groups.items()},
                       errors=data.get("errors", []), total_findings=len(data.get("findings", [])))
        refs = {tool: reference(tool, project, args.references) for tool in ("progpilot", "psalm")}
        comparisons = {}
        for tool, ref in refs.items():
            if own["sites"] is not None and ref["sites"] is not None:
                a, b = set(own["sites"]), set(ref["sites"])
                comparisons[tool] = {"common": sorted(a & b), "own_only": sorted(a - b),
                                     "reference_only": sorted(b - a),
                                     "note": "Location agreement, not vulnerability ground truth; inspect scan status."}
        details[project] = {"own": own, **refs, "comparisons": comparisons}
        row = {"project": project, "before_seconds": before.get(project, {}).get("seconds"),
               "before_status": before.get(project, {}).get("status"),
               "own_seconds": own["seconds"], "own_status": own["status"],
               "own_request_unserialize_sites": None if own["sites"] is None else len(own["sites"]),
               "own_total_findings": own.get("total_findings")}
        for tool, ref in refs.items():
            row[tool + "_status"] = ref["status"]
            row[tool + "_sites"] = None if ref["sites"] is None else len(ref["sites"])
        rows.append(row)
    output = BASE / "comparison"
    output.mkdir(exist_ok=True)
    (output / "sites.json").write_text(json.dumps(details, ensure_ascii=False, indent=2), encoding="utf-8")
    from php_deserial_sast.tests.test_dataflow_regression import CASES, analyze
    from php_deserial_sast.tests.test_small_cases import CASES as SMALL_CASES
    CASES = {**CASES, **SMALL_CASES}
    fixtures = {tool: reference(tool, "fixtures", args.references) for tool in ("progpilot", "psalm")}
    fixture_rows = []
    for name, (code, expected) in CASES.items():
        findings, project = analyze(code)
        row = {"case": name, "expected_by_scanner_model": expected,
               "own": bool(findings), "converged": project.converged}
        for tool, ref in fixtures.items():
            row[tool] = (None if ref["sites"] is None or name not in (ref.get('fixture_names') or [])
                         else any(s.startswith(name + ".php:") for s in ref["sites"]))
        fixture_rows.append(row)
    (output / "fixtures.json").write_text(json.dumps(fixture_rows, indent=2), encoding="utf-8")
    if rows:
        with (output / "summary.csv").open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
