"""Run local Psalm/Progpilot sources in Docker, without executing testcase apps.

Requires composer:2 and dependencies installed in each tool's vendor directory.
Raw outputs, commands, runtime versions and errors are retained, including timeouts.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tarfile
import time
from xml.sax.saxutils import quoteattr

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.reference_process import run_bounded
from php_deserial_sast.scanner import PHP_EXTENSIONS
from php_deserial_sast.tests.test_dataflow_regression import CASES
from php_deserial_sast.tests.test_small_cases import CASES as SMALL_CASES

CASES = {**CASES, **SMALL_CASES}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--fixtures-only', action='store_true')
    parser.add_argument('--skip-fixtures', action='store_true', help='Only scan explicitly selected real projects.')
    parser.add_argument('--tool', choices=['psalm', 'progpilot'])
    parser.add_argument('--label', default='external')
    parser.add_argument('--projects', nargs='*')
    parser.add_argument('--target', type=Path, help='Additional explicitly selected fixture/source directory.')
    parser.add_argument('--image', default='composer:2')
    parser.add_argument('--dependency-dir', type=Path, help='Additional dependency definitions for Psalm, mounted read-only.')
    parser.add_argument('--local-progpilot-source', action='store_true', help='Mount locally patched Progpilot sources over the reference image.')
    parser.add_argument('--memory-mb', type=int, default=3072, help='Container memory limit in MiB; PHP uses 80 percent.')
    args = parser.parse_args()
    if args.memory_mb < 256:
        parser.error('--memory-mb must be at least 256')
    if args.dependency_dir and not args.dependency_dir.is_dir():
        parser.error('--dependency-dir must exist')
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    output = ROOT / 'reports/evaluation' / args.label
    output.mkdir(parents=True, exist_ok=True)
    fixtures = output / 'fixtures'
    fixtures.mkdir(exist_ok=True)
    for name, (code, _) in CASES.items():
        # Unique helpers avoid collisions without depending on namespace support.
        code = re.sub(r'\b(decode|identity)\b', lambda m: m[0] + '_' + name, code)
        code = re.sub(r'\b(A|B)\b', lambda m: m[0] + '_' + name, code)
        (fixtures / (name + '.php')).write_text('<?php\n' + code + '\n', encoding='utf-8')
    if args.fixtures_only and args.skip_fixtures:
        parser.error('--fixtures-only and --skip-fixtures cannot be combined')
    targets = [] if args.skip_fixtures else [('fixtures', fixtures, '8.1')]
    if not args.fixtures_only:
        dirs = sorted((ROOT / 'testcase').iterdir(), key=lambda p: (p.name not in {'xvwa','saloon-3.0.0','monolog-1.23.0','monolog'}, p.name))
        targets += [(p.name, p, '8.1' if p.name in {'saloon-3.0.0', 'monolog'} else '7.4') for p in dirs if p.is_dir() and (not args.projects or p.name in args.projects)]
    if args.target:
        target = args.target.resolve()
        if not target.is_dir():
            parser.error('--target must be a directory')
        targets.append((target.name, target, '7.4'))
    metadata = {}
    for tool in ['codeql', 'psalm', 'progpilot']:
        p = subprocess.run(['git', '-C', str(ROOT / tool), 'rev-parse', 'HEAD'], capture_output=True, text=True)
        top = subprocess.run(['git', '-C', str(ROOT / tool), 'rev-parse', '--show-toplevel'], capture_output=True, text=True)
        own_repository = top.returncode == 0 and Path(top.stdout.strip()).resolve() == (ROOT / tool).resolve()
        metadata[tool] = {'commit': p.stdout.strip() if own_repository and p.returncode == 0 else None,
                          'status': 'not_evaluated_by_this_runner' if tool == 'codeql' else 'scheduled',
                          'version_source': 'tool_git_repository' if own_repository else 'not_a_separate_git_repository'}
    metadata['image'] = subprocess.run(['docker', 'image', 'inspect', args.image, '--format', '{{.Id}} {{json .RepoDigests}}'], capture_output=True, text=True).stdout.strip()
    (output / 'environment.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')

    def run_tool(tool):
        runs = []
        for name, target, version in targets:
            work = output / tool / name
            work.mkdir(parents=True, exist_ok=True)
            (work / 'result.json').unlink(missing_ok=True)
            (work / 'dependencies.tar').unlink(missing_ok=True)
            files = []
            for current, dirs, names in os.walk(target):
                dirs[:] = [d for d in dirs if d not in {'.git', '.svn', '.hg', 'vendor_disabled'}]
                files.extend('/tmp/target/' + (Path(current) / f).relative_to(target).as_posix()
                             for f in names if any(f.lower().endswith(ext) for ext in PHP_EXTENSIONS))
            with tarfile.open(work / 'target.tar', 'w') as archive:
                for file in sorted(files):
                    relative = file.removeprefix('/tmp/target/')
                    archive.add(target / relative, arcname=relative, recursive=False)
            (work / 'files.json').write_text(json.dumps(sorted(files)), encoding='utf-8')
            container = 'sast-eval-' + args.label + '-' + tool + '-' + name.replace('.', '-')
            common = ['docker', 'run', '--rm', '--name', container, '--network', 'none',
                      '--memory', str(args.memory_mb) + 'm', '--cpus', '2', '--entrypoint', 'sh',
                      '-v', str(ROOT / 'scripts') + ':/scripts:ro',
                      '-v', str(work) + ':/out', '-w', '/out']
            if tool == 'psalm' and args.dependency_dir:
                with tarfile.open(work / 'dependencies.tar', 'w') as archive:
                    dependency_root = args.dependency_dir.resolve()
                    for dependency in sorted(dependency_root.rglob('*.php')):
                        archive.add(dependency, arcname=dependency.relative_to(dependency_root).as_posix(), recursive=False)
            if tool == 'progpilot' and args.local_progpilot_source:
                common += ['-v', str(ROOT / 'progpilot/package/src') + ':/tools/progpilot/package/src:ro']
            if args.image == 'composer:2':
                common += ['-v', str(ROOT / tool) + ':/tools/' + tool + ':ro']
            common += [args.image, '/scripts/reference_entrypoint.sh', '-d', 'memory_limit=' + str(args.memory_mb * 4 // 5) + 'M']
            if tool == 'progpilot':
                command = common + ['/scripts/progpilot_scan.php', '/out/files.json', '/out/result.json', version]
            else:
                extensions = ''.join('<extension name=' + quoteattr(ext.lstrip('.')) + ' />' for ext in sorted(PHP_EXTENSIONS) if ext != '.class.php')
                config = ('<?xml version="1.0"?><psalm xmlns="https://getpsalm.org/schema/config" '
                          'errorLevel="8" resolveFromConfigFile="true" findUnusedCode="false" '
                          'cacheDirectory="/tmp/psalm-cache"><projectFiles><directory name="/tmp/target" />'
                          '</projectFiles>' + ('<extraFiles><directory name="/deps" /></extraFiles>' if args.dependency_dir else '') + '<fileExtensions>' + extensions + '</fileExtensions>'
                          '<enableExtensions><extension name="soap" /></enableExtensions></psalm>')
                (work / 'psalm.xml').write_text(config, encoding='utf-8')
                command = common + ['/tools/psalm/psalm', '--config=/out/psalm.xml', '--taint-analysis',
                                    '--no-cache', '--no-progress', '--threads=1', '--output-format=json',
                                    '--php-version=' + version]
            print('START', tool, name, flush=True)
            start = time.perf_counter()
            with (work / 'stdout.log').open('wb') as stdout, (work / 'stderr.log').open('wb') as stderr:
                def stop_container():
                    try:
                        subprocess.run(['docker', 'rm', '-f', container], capture_output=True, timeout=15)
                    except (subprocess.TimeoutExpired, OSError):
                        pass
                status, code = run_bounded(command, stdout=stdout, stderr=stderr,
                                           timeout=args.timeout, stop=stop_container)
            run = {'project': name, 'tool': tool, 'status': status, 'exit_code': code,
                   'seconds': round(time.perf_counter()-start, 3), 'input_files': len(files), 'command': command}
            if tool == 'psalm':
                try:
                    data = json.loads((work / 'stdout.log').read_text(encoding='utf-8'))
                    (work / 'result.json').write_text(json.dumps(data, indent=2), encoding='utf-8')
                except (ValueError, UnicodeError):
                    run['output_error'] = 'stdout was not a JSON report; inspect logs'
            # Process completion is not proof of complete analysis.
            try:
                report = json.loads((work / 'result.json').read_text(encoding='utf-8'))
                if tool == 'progpilot':
                    run['analysis_status'] = ('completed_without_reported_limits'
                        if status == 'finished' and code == 0 and report.get('coverage_complete') is True
                        else 'incomplete_or_unverified')
                    run['analysis_warning_count'] = report.get('analysis_warning_count')
                else:
                    run['analysis_status'] = ('json_report_available'
                        if status == 'finished' and code in (0, 2) and isinstance(report, list)
                        else 'incomplete_or_unverified')
            except (OSError, ValueError, UnicodeError):
                run['analysis_status'] = 'no_valid_report'
            runs.append(run)
            (output / (tool + '-runs.json')).write_text(json.dumps(runs, indent=2), encoding='utf-8')
            print('END', tool, name, status, code, run['seconds'], flush=True)
        return runs

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(run_tool, [args.tool] if args.tool else ['progpilot', 'psalm']))


if __name__ == '__main__':
    main()
