"""Summarize reproducible PHP deserialization scans at matching target sites."""

import argparse
import collections
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SITES = {
    "xvwa": ("vulnerabilities/php_object_injection/home.php", 38),
    "saloon-3.0.0": ("src/Http/Auth/AccessTokenAuthenticator.php", 105),
    "laravel-5.6.29": ("src/Illuminate/Encryption/Encrypter.php", 149),
    "wordpress-5.8.2": ("wp-admin/includes/upgrade.php", 1616),
    "drupal-8.6.9": ("core/lib/Drupal/Core/Field/Plugin/Field/FieldType/MapItem.php", 67),
    "pokemon": ("save-load.php", 30),
    "workshop-level1": ("src/save-load.php", 27),
    "workshop-level2": ("src/save-load.php", 27),
    "workshop-level3": ("src/safe-save-load.php", 26),
    "workshop-level4": ("src/save-load.php", 27),
}


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def site_matches(path, line, site):
    if not site:
        return False
    expected_path, expected_line = site
    return str(path).replace("\\", "/").lower().endswith(expected_path.lower()) and line == expected_line


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--own", type=Path, default=ROOT / "reports/evaluation/retest-2026-10-30-all-levels")
    parser.add_argument("--semgrep", type=Path, default=ROOT / "reports/evaluation/semgrep-docker-all-2026-10-30")
    parser.add_argument("--semgrep-extra", type=Path, default=ROOT / "reports/evaluation/semgrep-docker-labs-2026-10-30")
    parser.add_argument("--output", type=Path, default=ROOT / "reports/evaluation/reference-comparison-2026-10-30.json")
    args = parser.parse_args()
    own_runs = {x["case"]: x for x in read(args.own / "runs.json")}
    semgrep_dirs = (args.semgrep, args.semgrep_extra)
    semgrep_runs = {x["project"]: (x, folder)
                    for folder in semgrep_dirs if (folder / "runs.json").exists()
                    for x in read(folder / "runs.json")["runs"]}
    rows = []
    for name, own_run in own_runs.items():
        own = read(args.own / f"{name}.json")
        semgrep_run, semgrep_dir = semgrep_runs.get(name, (None, None))
        semgrep = read(semgrep_dir / f"{name}.json") if semgrep_dir and (semgrep_dir / f"{name}.json").exists() else None
        site = SITES.get(name)
        own_site = [f for f in own["findings"] if site_matches(f["location"]["file_path"], f["location"]["start_line"], site)]
        semgrep_site = [f for f in semgrep["results"] if site_matches(f["path"], f["start"]["line"], site)] if semgrep else []
        sink_rows = [s for s in own["sink_inventory"] if s["sink_name"] == "unserialize"]
        semgrep_counts = collections.Counter(f["check_id"] for f in semgrep["results"]) if semgrep else {}
        rows.append({
            "case": name,
            "reference_site": f"{site[0]}:{site[1]}" if site else None,
            "own": {
                "status": own_run["status"],
                "seconds": own_run["seconds"],
                "scanned_files": own["summary"]["total_files_scanned"],
                "errors": len(own["errors"]),
                "findings": len(own["findings"]),
                "unserialize_sinks": len(sink_rows),
                "observed_request_unserialize_sinks": sum(s["disposition"] == "observed_request" for s in sink_rows),
                "site_findings": [{"rule": f["rule_id"], "severity": f["severity"], "engine": f.get("metadata", {}).get("engine"), "source_assumption": f.get("metadata", {}).get("source_assumption")} for f in own_site],
            },
            "semgrep": {
                "status": semgrep_run["status"],
                "seconds": semgrep_run["seconds"],
                "scanned_files": semgrep_run["scanned_files"],
                "errors": semgrep_run["errors"],
                "findings": semgrep_run["results"],
                "by_rule": dict(semgrep_counts),
                "site_findings": [{"rule": f["check_id"], "severity": f["extra"]["severity"]} for f in semgrep_site],
            } if semgrep else None,
        })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
    for row in rows:
        other = row["semgrep"] or {}
        print(row["case"], row["own"]["findings"], other.get("findings"), row["own"]["site_findings"], other.get("site_findings"))


if __name__ == "__main__":
    main()
