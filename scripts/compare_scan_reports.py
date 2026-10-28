"""Compare finding multisets; differences are not ground-truth accuracy scores."""
import argparse
from collections import Counter
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports" / "evaluation"


def folder(label):
    resolved = (REPORTS / label).resolve()
    if resolved.parent != REPORTS.resolve():
        raise ValueError("Use a single report folder name")
    return resolved


def load_runs(label):
    directory = folder(label)
    runs = json.loads((directory / "runs.json").read_text(encoding="utf-8"))
    return {run["project"]: (directory, run) for run in runs}


def findings(directory, project):
    data = json.loads((directory / (project + ".json")).read_text(encoding="utf-8"))
    result = Counter()
    for finding in data["findings"]:
        location = finding["location"]
        result[(finding["rule_id"], location["file_path"], location["start_line"],
                location["start_col"], finding["severity"])] += 1
    return result


def rows(counter):
    return [dict(rule_id=key[0], file=key[1], line=key[2], column=key[3],
                 severity=key[4], count=count) for key, count in sorted(counter.items())]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("current")
    parser.add_argument("--baseline", nargs="+", required=True)
    args = parser.parse_args()
    baseline = {}
    for label in args.baseline:
        loaded = load_runs(label)
        duplicate = baseline.keys() & loaded.keys()
        if duplicate:
            raise ValueError("Ambiguous baseline projects: " + ", ".join(sorted(duplicate)))
        baseline.update(loaded)
    results = []
    for project, (directory, run) in load_runs(args.current).items():
        result = {"project": project, "current_status": run["status"],
                  "current_errors": run.get("errors", [])}
        if project not in baseline:
            result["comparison_status"] = "missing_baseline"
        else:
            previous, old_run = baseline[project]
            result["baseline_folder"] = previous.name
            if run["status"] != "finished" or old_run["status"] != "finished":
                result["comparison_status"] = "unfinished_scan"
            else:
                before, after = findings(previous, project), findings(directory, project)
                result.update(comparison_status="compared", baseline_count=before.total(),
                              current_count=after.total(), added=rows(after - before),
                              removed=rows(before - after))
        results.append(result)
    output = folder(args.current) / "comparison.json"
    output.write_text(json.dumps({"baseline_labels": args.baseline,
        "interpretation": "Finding differences only; no precision/recall or exploitability claim.",
        "projects": results}, indent=2, ensure_ascii=False), encoding="utf-8")
    for row in results:
        print(json.dumps({"project": row["project"], "status": row["comparison_status"],
            "added": sum(item["count"] for item in row.get("added", [])),
            "removed": sum(item["count"] for item in row.get("removed", []))}))


if __name__ == "__main__":
    main()
