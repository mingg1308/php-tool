"""Re-run the case-study projects with explicit, reproducible scan settings."""

import argparse
from collections import Counter
import hashlib
from importlib.metadata import PackageNotFoundError, version
import json
import os
import platform
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
    ("laravel-5.6.30", "testcase/laravel-5.6.30", "7.2", True, ()),
    ("wordpress-5.8.2", "testcase/wordpress-5.8.2", "7.3", False, ()),
    ("drupal-8.6.9", "testcase/drupal-8.6.9", "7.4", True, ()),
    ("drupal-8.6.10", "testcase/drupal-8.6.10", "7.4", False, ()),
    ("pokemon", r"D:\Học viện\cyberjutsu\php_object_injection\lJCBG1NQbW43d6D2IiFA_php_deserialization\pokemon", "7.3", False, ()),
    ("workshop-level1", r"D:\Học viện\cyberjutsu\php_object_injection\lJCBG1NQbW43d6D2IiFA_php_deserialization\php_deserialization_workshop\php_deserialization_workshop_level1", "7.3", False, ()),
    ("workshop-level2", r"D:\Học viện\cyberjutsu\php_object_injection\lJCBG1NQbW43d6D2IiFA_php_deserialization\php_deserialization_workshop\php_deserialization_workshop_level2", "7.3", False, ()),
)
PACKAGES = ('tree-sitter', 'tree-sitter-php', 'pyyaml', 'rich', 'pydantic',
            'click', 'jinja2', 'networkx', 'httpx')


def runtime_manifest() -> dict:
    packages = {}
    for name in PACKAGES:
        try:
            packages[name] = version(name)
        except PackageNotFoundError:
            packages[name] = None
    return {'python': platform.python_version(),
            'implementation': platform.python_implementation(),
            'platform': platform.platform(), 'packages': packages}


def peak_resident_bytes(pid: int) -> int | None:
    """Read the child process's resident high-water mark when supported."""
    if sys.platform == 'win32':
        import ctypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [('cb', ctypes.c_ulong), ('PageFaultCount', ctypes.c_ulong),
                        ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
                        ('QuotaPeakPagedPoolUsage', ctypes.c_size_t), ('QuotaPagedPoolUsage', ctypes.c_size_t),
                        ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t), ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                        ('PagefileUsage', ctypes.c_size_t), ('PeakPagefileUsage', ctypes.c_size_t)]

        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        psapi = ctypes.WinDLL('psapi', use_last_error=True)
        kernel.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
        psapi.GetProcessMemoryInfo.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong)
        handle = kernel.OpenProcess(0x0400 | 0x0010, 0, pid)
        if not handle:
            return None
        try:
            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return int(counters.PeakWorkingSetSize)
        finally:
            kernel.CloseHandle(handle)
        return None
    if sys.platform.startswith('linux'):
        try:
            for line in Path(f'/proc/{pid}/status').read_text().splitlines():
                if line.startswith('VmHWM:'):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            pass
    return None


def run_scanned(command: list[str], log: Path, timeout: int) -> tuple[str, int | None, int | None]:
    peak = None
    with log.open('wb') as stream, subprocess.Popen(
            command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT) as process:
        deadline = time.monotonic() + timeout
        while True:
            resident = peak_resident_bytes(process.pid)
            if resident is not None:
                peak = max(peak or 0, resident)
            exit_code = process.poll()
            if exit_code is not None:
                return 'finished', exit_code, peak
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                return 'timeout', None, peak
            try:
                process.wait(timeout=min(0.25, remaining))
            except subprocess.TimeoutExpired:
                pass


def target_tree_hash(target: Path) -> tuple[str, int]:
    """Hash relative names and bytes so resume cannot hide target changes."""
    digest = hashlib.sha256()
    count = 0
    for path in sorted((path for path in target.rglob('*') if path.is_file()),
                       key=lambda path: path.relative_to(target).as_posix()):
        relative = path.relative_to(target).as_posix().encode('utf-8')
        digest.update(len(relative).to_bytes(8, 'big'))
        digest.update(relative)
        digest.update(path.stat().st_size.to_bytes(8, 'big'))
        with path.open('rb') as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        count += 1
    return digest.hexdigest(), count


def compare_reports(output: Path, baseline: Path, names: list[str]) -> list[dict]:
    """Compare exact finding locations without treating counts as accuracy."""
    def signature(finding):
        location = finding['location']
        return (os.path.normcase(os.path.normpath(location['file_path'])),
                location['start_line'], location['start_col'],
                finding['rule_id'], finding['severity'])

    rows = []
    for name in names:
        previous, current = baseline / f'{name}.json', output / f'{name}.json'
        if not previous.is_file() or not current.is_file():
            rows.append({'case': name, 'status': 'missing_report'})
            continue
        old = json.loads(previous.read_text(encoding='utf-8'))
        new = json.loads(current.read_text(encoding='utf-8'))
        before = Counter(signature(finding) for finding in old['findings'])
        after = Counter(signature(finding) for finding in new['findings'])
        missing, added = before - after, after - before
        rows.append({'case': name, 'status': 'same' if not missing and not added else 'changed',
                     'missing': sum(missing.values()), 'added': sum(added.values()),
                     'missing_examples': list(missing.elements())[:20],
                     'added_examples': list(added.elements())[:20]})
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path,
                        default=ROOT / "reports/evaluation/retest-2026-10-24")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--only", choices=[case[0] for case in CASES])
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--compare", type=Path, help="Baseline report directory for exact finding-signature comparison.")
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
    runtime = runtime_manifest()
    for name, relative_target, version, effects, extra in CASES:
        if args.only and name != args.only:
            continue
        target = ROOT / relative_target
        if not target.is_dir():
            runs = [row for row in runs if row['case'] != name]
            runs.append({"case": name, "status": "missing_target", "target": str(target)})
            continue
        target_digest, target_files = target_tree_hash(target)
        report = output / f"{name}.json"
        log = output / f"{name}.log"
        command = [sys.executable, "-m", "php_deserial_sast.cli", "scan", str(target),
                   "--php-version", version, "--severity", "INFO", "--format", "json",
                   "--output", str(report), *extra]
        if effects:
            command.append("--experimental-side-effects")
        if args.resume and not args.only and any(
            row.get("case") == name and row.get("status") == "finished"
            and row.get("summary") and not row.get("errors")
            and row.get("target_sha256") == target_digest
            and row.get("command") == command
            and row.get("runtime") == runtime for row in runs
        ):
            continue
        runs = [row for row in runs if row["case"] != name]
        print("START", name, flush=True)
        started = time.perf_counter()
        status, exit_code, peak_rss = run_scanned(command, log, args.timeout)
        row = {"case": name, "target": str(target), "php_version": version,
               "target_sha256": target_digest, "target_files": target_files,
               "runtime": runtime,
               "experimental_side_effects": effects, "command": command,
               "status": status, "exit_code": exit_code,
               "seconds": round(time.perf_counter() - started, 3),
               "peak_rss_bytes": peak_rss,
               "peak_rss_mib": round(peak_rss / (1024 * 1024), 2) if peak_rss is not None else None,
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
    comparison_ok = True
    if args.compare:
        comparison = compare_reports(output, args.compare.resolve(),
                                     [name for name, *_ in CASES if not args.only or name == args.only])
        (output / 'comparison.json').write_text(
            json.dumps(comparison, ensure_ascii=False, indent=2), encoding='utf-8')
        comparison_ok = all(row['status'] == 'same' for row in comparison)
        print('COMPARISON', 'same' if comparison_ok else 'changed_or_missing', flush=True)
    return 0 if comparison_ok and all(row["status"] == "finished" and "summary" in row
                    and not row.get("errors") for row in runs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
