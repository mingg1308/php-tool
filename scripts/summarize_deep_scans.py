"""Validate and summarize application/library scans without conflating evidence."""
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from php_deserial_sast.models import ScanResult


def main():
    base = ROOT / 'reports/evaluation'
    output = {'created_utc': datetime.now(timezone.utc).isoformat(),
              'notes': ['Findings are review candidates, not confirmed exploitable vulnerabilities.',
                        'Library-mode public parameters are assumed external sources.',
                        'Reported analysis errors and candidate limits mean coverage is incomplete.',
                        'Concurrent runs: durations are not a controlled performance benchmark.'],
              'runs': []}
    for label in ('deep-current', 'deep-library'):
        runfile = base / label / 'runs.json'
        if not runfile.exists():
            continue
        for run in json.loads(runfile.read_text(encoding='utf-8')):
            path = base / label / (run['project'] + '.json')
            item = {'project': run['project'], 'mode': 'library' if label == 'deep-library' else 'application',
                    'seconds': run['seconds'], 'process_status': run['status'],
                    'exit_code': run['exit_code'], 'command': run['command'],
                    'report': path.relative_to(ROOT).as_posix(), 'valid_json_report': False}
            if path.exists():
                raw = json.loads(path.read_text(encoding='utf-8'))
                result = ScanResult.model_validate(raw)
                if result.summary.total_findings != len(result.findings):
                    raise ValueError(f'Finding count mismatch: {path}')
                item.update(valid_json_report=True,
                            coverage_status='incomplete' if result.errors else 'no_reported_errors',
                            summary=raw['summary'], analysis=raw['analysis'], errors=raw['errors'],
                            by_rule=dict(Counter(f.rule_id for f in result.findings)),
                            by_analysis_status=dict(Counter(f.metadata.get('analysis_status', 'unspecified') for f in result.findings)),
                            by_source_assumption=dict(Counter(f.metadata.get('source_assumption', 'not_applicable') for f in result.findings)),
                            unserialize_taint_sites=[{'location': f.location.model_dump(),
                                                     'severity': f.severity.value,
                                                     'confidence': f.confidence.value,
                                                     'metadata': f.metadata}
                                                    for f in result.findings
                                                    if f.metadata.get('engine') == 'taint'
                                                    and f.metadata.get('sink_name') == 'unserialize'])
                if label == 'deep-current':
                    old_path = base / 'optimized' / path.name
                    if old_path.exists():
                        old = json.loads(old_path.read_text(encoding='utf-8'))
                        item['previous_snapshot_comparison'] = {
                            'previous_total_findings': old['summary']['total_findings'],
                            'current_total_findings': raw['summary']['total_findings'],
                            'previous_errors': old.get('errors', []),
                            'note': 'Configuration differs: POP depth and budgets increased; this is not a one-variable comparison.'}
            else:
                item['coverage_status'] = 'no_report'
            output['runs'].append(item)
    output['completed_reports'] = sum(r['valid_json_report'] for r in output['runs'])
    output['expected_reports'] = 13
    target = base / 'deep-current' / 'evaluation_summary.json'
    target.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps({'completed_reports': output['completed_reports'], 'expected_reports': 13,
                      'runs': [{k: r.get(k) for k in ('project', 'mode', 'seconds', 'coverage_status')}
                               for r in output['runs']]}, indent=2))
    return 0 if output['completed_reports'] == 13 else 1


if __name__ == '__main__':
    raise SystemExit(main())
