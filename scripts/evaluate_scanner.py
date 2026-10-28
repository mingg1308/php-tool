"""Isolated full-project scans; preserve failures, timeouts and raw output."""
import argparse
import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = {"saloon-3.0.0": "8.1", "monolog": "8.1"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("label")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--snapshot", action="store_true")
    parser.add_argument("--source-snapshot", type=Path, help="Use an existing source directory as the scan baseline.")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--projects", nargs="*")
    parser.add_argument("--library-mode", action="store_true")
    parser.add_argument("--experimental-foreach-cfg", action="store_true")
    parser.add_argument("--experimental-side-effects", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--experimental-demand-summaries", action="store_true")
    mode.add_argument("--eager-summaries", action="store_true")
    parser.add_argument("--max-depth", type=int, default=6)
    parser.add_argument("--max-gadget-paths", type=int, default=10000)
    parser.add_argument("--max-gadget-expansions", type=int, default=250000)
    args = parser.parse_args()
    source_root = args.source_snapshot.resolve() if args.source_snapshot else ROOT
    if not (source_root / "php_deserial_sast" / "cli.py").is_file():
        parser.error("Source directory must contain php_deserial_sast/cli.py")
    output = ROOT / "reports" / "evaluation" / args.label
    output.mkdir(parents=True, exist_ok=True)
    if args.resume and (output / "source_manifest.json").exists():
        previous_manifest = json.loads((output / "source_manifest.json").read_text(encoding="utf-8"))
        current_manifest = {p.relative_to(source_root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in (source_root / "php_deserial_sast").rglob("*") if p.suffix in {".py", ".yaml"}}
        if current_manifest != previous_manifest:
            raise SystemExit("Source changed since snapshot; use a new label instead of mixing scan versions.")
    cwd = source_root
    if args.snapshot:
        cwd = output / "source"
        if not args.resume or not (cwd / "php_deserial_sast").exists():
            shutil.copytree(source_root / "php_deserial_sast", cwd / "php_deserial_sast",
                            ignore=shutil.ignore_patterns("__pycache__"), dirs_exist_ok=True)
    manifest = {p.relative_to(cwd).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (cwd / "php_deserial_sast").rglob("*") if p.suffix in {".py", ".yaml"}}
    (output / "source_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    runs = json.loads((output / "runs.json").read_text(encoding="utf-8")) if args.resume and (output / "runs.json").exists() else []
    for target in sorted((ROOT / "testcase").iterdir()):
        if not target.is_dir() or args.projects and target.name not in args.projects:
            continue
        if args.resume and any(r["project"] == target.name and r.get("summary") and not r.get("report_error") for r in runs):
            continue
        runs = [r for r in runs if r["project"] != target.name]
        report = output / (target.name + ".json")
        report.unlink(missing_ok=True)
        command = [sys.executable, "-m", "php_deserial_sast.cli", "scan", str(target),
                   "--php-version", VERSIONS.get(target.name, "7.4"), "--severity", "info",
                   "--format", "json", "--output", str(report),
                   "--max-depth", str(args.max_depth),
                   "--max-gadget-paths", str(args.max_gadget_paths),
                   "--max-gadget-expansions", str(args.max_gadget_expansions)]
        if args.library_mode:
            command.append("--library-mode")
        if args.experimental_foreach_cfg:
            command.append("--experimental-foreach-cfg")
        if args.experimental_side_effects:
            command.append("--experimental-side-effects")
        if args.experimental_demand_summaries:
            command.append("--experimental-demand-summaries")
        if args.eager_summaries:
            command.append("--eager-summaries")
        print("START", args.label, target.name, flush=True)
        start = time.perf_counter()
        with (output / (target.name + ".log")).open("wb") as log:
            try:
                result = subprocess.run(command, cwd=cwd, stdout=log, stderr=log, timeout=args.timeout)
                status, code = "finished", result.returncode
            except subprocess.TimeoutExpired:
                status, code = "timeout", None
        run = {"project": target.name, "command": command, "status": status,
               "exit_code": code, "seconds": round(time.perf_counter() - start, 3)}
        if report.exists():
            try:
                data = json.loads(report.read_text(encoding="utf-8"))
                run.update(summary=data.get("summary"), errors=data.get("errors"), analysis=data.get("analysis"))
            except (ValueError, OSError) as exc:
                run["report_error"] = f"{type(exc).__name__}: {exc}"
        runs.append(run)
        (output / "runs.json").write_text(json.dumps(runs, indent=2, ensure_ascii=False), encoding="utf-8")
        print("END", target.name, status, code, run["seconds"], flush=True)


if __name__ == "__main__":
    main()
