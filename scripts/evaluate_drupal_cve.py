"""Sequential, reproducible Drupal CVE-2019-6340 reference runs."""
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'reports/evaluation/drupal-cve-2019-6340-assessment'
OUT.mkdir(parents=True, exist_ok=True)
rows = []

def run(name, command, timeout=None):
    print('START', name, flush=True)
    start = time.perf_counter()
    with (OUT / (name + '.stdout.log')).open('wb') as stdout, (OUT / (name + '.stderr.log')).open('wb') as stderr:
        try:
            result = subprocess.run(command, cwd=ROOT, stdout=stdout, stderr=stderr, timeout=timeout)
            status, code = 'finished', result.returncode
        except subprocess.TimeoutExpired:
            status, code = 'timeout', None
    row = {'name': name, 'command': command, 'status': status, 'exit_code': code,
           'seconds': round(time.perf_counter()-start, 3)}
    rows.append(row)
    (OUT / 'sequence.json').write_text(json.dumps(rows, indent=2), encoding='utf8')
    print('END', name, status, code, row['seconds'], flush=True)
    return row

# Keep tools sequential, including the already launched experimental scan.
prior = ROOT / 'reports/evaluation/drupal-cve-2019-6340-upgraded/runs.json'
start = time.monotonic()
while not prior.exists():
    if time.monotonic()-start > 180:
        raise SystemExit('Previous scan has not recorded completion; refusing concurrent timing.')
    time.sleep(1)
run('own-default', [sys.executable, 'scripts/evaluate_scanner.py', 'drupal-cve-2019-6340-default',
    '--snapshot', '--projects', 'drupal-8.6.9', '--timeout', '900', '--max-depth', '10',
    '--max-gadget-paths', '20000', '--max-gadget-expansions', '500000'])
for tool in ('psalm', 'progpilot'):
    run(tool, [sys.executable, 'scripts/evaluate_external.py', '--tool', tool,
        '--skip-fixtures', '--projects', 'drupal-8.6.9', '--timeout', '900',
        '--image', 'php-sast-references:local', '--label', 'drupal-cve-2019-6340-references'])
codeql = str(ROOT / 'codeql/codeql.exe')
run('codeql-version', [codeql, 'version', '--format=json'], 120)
run('codeql-languages', [codeql, 'resolve', 'languages', '--format=json'], 120)
run('codeql-php-extractor', [codeql, 'resolve', 'extractor', '--language=php'], 120)
