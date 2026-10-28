"""Run the local Semgrep rules against the same case-study directories."""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'reports/evaluation/semgrep-reference-2026-10-26'
CONFIG = ROOT / 'semgrep_php_deserialization.yml'
CASES = (
    ('xvwa', 'testcase/xvwa'),
    ('saloon-3.0.0', 'testcase/saloon-3.0.0'),
    ('monolog', 'testcase/monolog'),
    ('monolog-1.23.0', 'testcase/monolog-1.23.0'),
    ('monolog-1.23.0-src-deep', 'testcase/monolog-1.23.0/src/Monolog'),
    ('tcpdf-6.2.22', 'testcase/tcpdf-6.2.22'),
    ('laravel-5.6.29', 'testcase/laravel-5.6.29'),
    ('wordpress-5.8.2', 'testcase/wordpress-5.8.2'),
    ('drupal-8.6.9', 'testcase/drupal-8.6.9'),
)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--only', choices=[name for name, _ in CASES])
    parser.add_argument('--timeout', type=int, default=900)
    parser.add_argument('--all-files', action='store_true',
                        help='Disable Semgrep ignore files for closer source coverage.')
    args = parser.parse_args()
    output = (ROOT / 'reports/evaluation/semgrep-full-2026-10-26') if args.all_files else OUTPUT
    output.mkdir(parents=True, exist_ok=True)
    runs = []
    for name, relative in CASES:
        if args.only and name != args.only:
            continue
        report = output / (name + '.json')
        command = [
            'pysemgrep', 'scan', '--config', str(CONFIG), '--metrics=off',
            '--no-git-ignore', '--max-target-bytes', '0', '--timeout', '60',
            '--jobs', '2', '--json', '--output', str(report), str(ROOT / relative),
        ]
        if args.all_files:
            command.insert(command.index('--max-target-bytes'), '--x-ignore-semgrepignore-files')
        print('START', name, flush=True)
        started = time.perf_counter()
        environment = os.environ.copy()
        environment['PYTHONUTF8'] = '1'
        try:
            completed = subprocess.run(command, cwd=ROOT, capture_output=True,
                                       timeout=args.timeout, env=environment)
            status, exit_code = 'finished', completed.returncode
            stdout, stderr = completed.stdout, completed.stderr
        except subprocess.TimeoutExpired as exc:
            status, exit_code = 'timeout', None
            stdout, stderr = exc.stdout or b'', exc.stderr or b''
        (output / (name + '.stdout.log')).write_bytes(stdout)
        (output / (name + '.stderr.log')).write_bytes(stderr)
        data = None
        if report.exists():
            try:
                data = json.loads(report.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                pass
        row = {
            'project': name, 'target': relative, 'status': status,
            'exit_code': exit_code, 'seconds': round(time.perf_counter() - started, 3),
            'report': str(report.relative_to(ROOT)), 'command': command,
            'results': len(data['results']) if data else None,
            'errors': len(data['errors']) if data else None,
            'scanned_files': len(data.get('paths', {}).get('scanned', [])) if data else None,
        }
        runs.append(row)
        (output / 'runs.json').write_text(json.dumps({
            'semgrep_version': '1.180.0',
            'rules_sha256': hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
            'runs': runs,
        }, indent=2, ensure_ascii=False), encoding='utf-8')
        print('END', name, status, exit_code, row['seconds'], row['results'], flush=True)
    return 0 if all(r['status'] == 'finished' and r['exit_code'] == 0
                    and r['errors'] == 0 for r in runs) else 1


if __name__ == '__main__':
    sys.exit(main())
