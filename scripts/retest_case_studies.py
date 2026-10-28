"""Re-run the case-study projects with explicit, reproducible scan settings."""

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CASES = (
    ("xvwa", "testcase/xvwa", "7.4", False, ()),
    ("saloon-3.0.0", "testcase/saloon-3.0.0", "8.1", True, ()),
    ("monolog", "testcase/monolog", "8.1", False,
     ("--max-gadget-paths", "100000", "--max-gadget-expansions", "500000")),
    ("monolog-1.23.0", "testcase/monolog-1.23.0", "5.6", True, ()),
    ("monolog-1.23.0-src-deep", "testcase/monolog-1.23.0/src/Monolog", "5.6", True,
     ("--max-depth", "10", "--max-gadget-paths", "100000", "--max-gadget-expansions", "500000")),
    ("tcpdf-6.2.22", "testcase/tcpdf-6.2.22", "7.2", False, ()),
    ("laravel-5.6.29", "testcase/laravel-5.6.29", "7.2", True, ()),
    ("wordpress-5.8.2", "testcase/wordpress-5.8.2", "7.3", False, ()),
    ("drupal-8.6.9", "testcase/drupal-8.6.9", "7.4", True, ()),
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path,
                        default=ROOT / "reports/evaluation/retest-2026-10-24")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--only", choices=[case[0] for case in CASES])
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest = {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (ROOT / "php_deserial_sast").rglob("*")
        if path.suffix in {".py", ".yaml"}
    }
    manifest_path = output / "source_manifest.json"
    if args.resume and manifest_path.is_file():
        previous = json.loads(manifest_path.read_text(encoding="utf-8"))
        if previous != manifest:
            parser.error("Engine source changed; choose a new output directory for this run.")
    manifest_path.write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    runs_path = output / "runs.json"
    runs = json.loads(runs_path.read_text(encoding="utf-8")) if args.resume and runs_path.is_file() else []
    for name, relative_target, version, effects, extra in CASES:
        if args.only and name != args.only:
            continue
        if args.resume and not args.only and any(
            row.get("case") == name and row.get("status") == "finished"
            and row.get("summary") and not row.get("errors") for row in runs
        ):
            continue
        runs = [row for row in runs if row["case"] != name]
        target = ROOT / relative_target
        if not target.is_dir():
            runs.append({"case": name, "status": "missing_target", "target": str(target)})
            continue
        report = output / f"{name}.json"
        log = output / f"{name}.log"
        command = [sys.executable, "-m", "php_deserial_sast.cli", "scan", str(target),
                   "--php-version", version, "--severity", "INFO", "--format", "json",
                   "--output", str(report), *extra]
        if effects:
            command.append("--experimental-side-effects")
        print("START", name, flush=True)
        started = time.perf_counter()
        try:
            with log.open("wb") as stream:
                completed = subprocess.run(command, cwd=ROOT, stdout=stream,
                                           stderr=subprocess.STDOUT, timeout=args.timeout)
            status = "finished"
            exit_code = completed.returncode
        except subprocess.TimeoutExpired:
            status = "timeout"
            exit_code = None
        row = {"case": name, "target": str(target), "php_version": version,
               "experimental_side_effects": effects, "command": command,
               "status": status, "exit_code": exit_code,
               "seconds": round(time.perf_counter() - started, 3),
               "report": str(report), "log": str(log)}
        if report.is_file():
            try:
                data = json.loads(report.read_text(encoding="utf-8"))
                row["summary"] = data.get("summary")
                row["errors"] = data.get("errors")
                row["analysis"] = data.get("analysis")
            except (OSError, ValueError) as exc:
                row["report_error"] = f"{type(exc).__name__}: {exc}"
        runs.append(row)
        runs_path.write_text(
            json.dumps(runs, indent=2, ensure_ascii=False), encoding="utf-8")
        print("END", name, status, exit_code, row["seconds"], flush=True)
    return 0 if all(row["status"] == "finished" and "summary" in row
                    and not row.get("errors") for row in runs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
