"""Isolated full-pipeline scans of the small PHP cases; save reproducible evidence."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.models import Severity
from php_deserial_sast.scanner import PHPDeserializationScanner
from php_deserial_sast.tests.test_dataflow_regression import CASES
from php_deserial_sast.tests.test_small_cases import CASES as EXTRA
from php_deserial_sast.tests.test_upgrade_models import UPGRADE_CASES
from php_deserial_sast.tests.test_object_global_effects import CASES as OBJECT_GLOBAL_CASES
from scripts.compare_results import reference


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'reports/evaluation/small-expanded/own')
    parser.add_argument('--experimental-foreach-cfg', action='store_true')
    parser.add_argument('--experimental-side-effects', action='store_true')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--experimental-demand-summaries', action='store_true')
    mode.add_argument('--eager-summaries', action='store_true')
    parser.add_argument('--include-upgrade-cases', action='store_true')
    parser.add_argument('--include-object-global-cases', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    refs = {t: reference(t, 'fixtures', ['small-expanded']) for t in ('progpilot', 'psalm')}
    rows = []
    cases = {name: (code, expected, args.experimental_side_effects)
             for name, (code, expected) in {**CASES, **EXTRA}.items()}
    if args.include_upgrade_cases:
        cases.update(UPGRADE_CASES)
    if args.include_object_global_cases:
        cases.update({"effects_" + name: (code, expected, True)
                      for name, (code, expected) in OBJECT_GLOBAL_CASES.items()})
    for name, (code, expected, effects) in cases.items():
        fixture = output / (name + '.php')
        fixture.write_text('<?php\n' + code + '\n', encoding='utf-8')
        result = PHPDeserializationScanner(ScannerConfig(
            target_path=str(fixture), php_version='8.1', min_severity=Severity.INFO,
            experimental_foreach_cfg=args.experimental_foreach_cfg,
            experimental_side_effects=effects,
            experimental_demand_summaries=not args.eager_summaries
        )).scan()
        (output / (name + '.json')).write_text(result.model_dump_json(indent=2), encoding='utf-8')
        taint = [f for f in result.findings if f.metadata.get('engine') == 'taint'
                 and f.metadata.get('sink_name') == 'unserialize']
        row = {'case': name, 'expected_taint_under_model': expected, 'observed_taint': bool(taint),
               'experimental_side_effects': effects,
               'passed': bool(taint) == expected and not result.errors,
               'errors': [e.model_dump() for e in result.errors],
               'statuses': [f.metadata['analysis_status'] for f in taint],
               'all_findings': len(result.findings)}
        for tool, ref in refs.items():
            row[tool] = None if ref['sites'] is None or name in UPGRADE_CASES or name.startswith('effects_') else any(s.startswith(name + '.php:') for s in ref['sites'])
        rows.append(row)
    manifest = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (ROOT / 'php_deserial_sast').rglob('*') if p.suffix in {'.py', '.yaml'}}
    summary = {'total': len(rows), 'passed': sum(r['passed'] for r in rows),
               'experimental_demand_summaries': not args.eager_summaries,
               'upgrade_cases_included': args.include_upgrade_cases,
               'object_global_cases_included': args.include_object_global_cases,
               'experimental_foreach_cfg': args.experimental_foreach_cfg,
               'experimental_side_effects': args.experimental_side_effects,
               'expected_positive': sum(r['expected_taint_under_model'] for r in rows),
               'references': refs, 'cases': rows,
               'scope': 'Modeled taint to unrestricted unserialize, not exploitability or general precision/recall.'}
    tp = sum(r['expected_taint_under_model'] and r['observed_taint'] for r in rows)
    fp = sum(not r['expected_taint_under_model'] and r['observed_taint'] for r in rows)
    fn = sum(r['expected_taint_under_model'] and not r['observed_taint'] for r in rows)
    tn = sum(not r['expected_taint_under_model'] and not r['observed_taint'] for r in rows)
    summary['labeled_suite_metrics'] = {'true_positive': tp, 'false_positive': fp,
        'false_negative': fn, 'true_negative': tn,
        'precision': tp / (tp + fp) if tp + fp else None,
        'recall': tp / (tp + fn) if tp + fn else None,
        'cases_with_scan_errors': sum(bool(r['errors']) for r in rows),
        'generalizes_to_real_projects': False}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    (output / 'source_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps({k: summary[k] for k in ('total', 'passed', 'expected_positive')}))
    print(json.dumps([r for r in rows if not r['passed']], indent=2))
    return 0 if summary['passed'] == summary['total'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
