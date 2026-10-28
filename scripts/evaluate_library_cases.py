"""Export labeled constructor/library API cases in both summary modes."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.models import Severity
from php_deserial_sast.scanner import PHPDeserializationScanner
from php_deserial_sast.tests.test_library_property_flow import LIBRARY_CASES


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    for demand in (False, True):
        mode = 'demand' if demand else 'eager'
        for name, (code, expected) in LIBRARY_CASES.items():
            fixture = output / (mode + '-' + name + '.php')
            fixture.write_text('<?php\n' + code, encoding='utf-8')
            result = PHPDeserializationScanner(ScannerConfig(
                target_path=str(fixture), library_mode=True, php_version='8.1',
                min_severity=Severity.INFO, experimental_demand_summaries=demand)).scan()
            fixture.with_suffix('.json').write_text(result.model_dump_json(indent=2), encoding='utf-8')
            flows = [finding for finding in result.findings if finding.metadata.get('engine') == 'taint']
            rows.append({'case': name, 'mode': mode, 'expected_api_exposure': expected,
                         'observed_api_exposure': bool(flows),
                         'passed': bool(flows) == expected and not result.errors,
                         'summary_converged': result.analysis.get('summary_converged'),
                         'errors': [error.model_dump() for error in result.errors]})
    summary = {'total': len(rows), 'passed': sum(row['passed'] for row in rows), 'cases': rows,
               'scope': 'Assumed public constructor input; not observed request control or exploitability.'}
    manifest = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (ROOT / 'php_deserial_sast').rglob('*') if p.suffix in {'.py', '.yaml'}}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    (output / 'source_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps({'total': summary['total'], 'passed': summary['passed'],
                      'failures': [r for r in rows if not r['passed']]}))
    return int(summary['passed'] != summary['total'])


if __name__ == '__main__':
    raise SystemExit(main())
