"""Compare the three real projects against the same deep-scan configuration."""
import json
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'reports/evaluation'


def describe(label, name):
    data = json.loads((BASE / label / (name + '.json')).read_text(encoding='utf-8'))
    from php_deserial_sast.models import ScanResult
    ScanResult.model_validate(data)
    return {
        'summary': data['summary'], 'errors': data['errors'],
        'statuses': dict(Counter(f.get('metadata', {}).get('analysis_status', 'other') for f in data['findings'])),
        'taint_sites': [{'file': f['location']['file_path'], 'line': f['location']['start_line'],
                        'sink': f['metadata'].get('sink_name'), 'severity': f['severity'],
                        'confidence': f['confidence'], 'metadata': f['metadata']}
                       for f in data['findings'] if f.get('metadata', {}).get('engine') == 'taint'],
    }


def main():
    import sys
    sys.path.insert(0, str(ROOT))
    result = {
        'baseline': 'deep-current', 'current': 'fixes-validated',
        'note': 'No exploitation performed. Candidate call-graph limits remain explicit. Constant defaults are assumptions, not runtime configuration proof.',
        'projects': {name: {'before': describe('deep-current', name),
                            'after': describe('fixes-validated', name)}
                     for name in ('xvwa', 'tcpdf-6.2.22', 'wordpress-5.8.2')},
    }
    path = BASE / 'fixes-validated' / 'comparison.json'
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    for name, row in result['projects'].items():
        print(name, 'findings', row['before']['summary']['total_findings'], '->', row['after']['summary']['total_findings'],
              'taint', len(row['before']['taint_sites']), '->', len(row['after']['taint_sites']))


if __name__ == '__main__':
    main()
