"""Compare site agreement, coverage and errors for the local Semgrep rules."""

import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEMGREP = ROOT / 'reports/evaluation/semgrep-reference-2026-10-26'
OWN = ROOT / 'reports/evaluation/project-by-project-scope-2026-10-26'


def relative_site(path, line, target):
    normalized = path.replace('\\', '/')
    marker = '/' + target.strip('/') + '/'
    if marker in normalized:
        normalized = normalized.rsplit(marker, 1)[1]
    return f'{normalized}:{line}'


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--all-files', action='store_true')
    args = parser.parse_args()
    semgrep = ROOT / 'reports/evaluation/semgrep-full-2026-10-26' if args.all_files else SEMGREP
    runs = json.loads((semgrep / 'runs.json').read_text(encoding='utf-8'))['runs']
    rows = []
    for run in runs:
        name, target = run['project'], run['target']
        own = json.loads((OWN / (name + '.json')).read_text(encoding='utf-8'))
        external = json.loads((semgrep / (name + '.json')).read_text(encoding='utf-8'))
        by_rule = {}
        for finding in external['results']:
            by_rule.setdefault(finding['check_id'], set()).add(
                relative_site(finding['path'], finding['start']['line'], target))
        own_inventory = {relative_site(s['location']['file_path'], s['location']['start_line'], target)
                         for s in own['sink_inventory'] if s['sink_name'] == 'unserialize'}
        own_observed = {relative_site(f['location']['file_path'], f['location']['start_line'], target)
                        for f in own['findings'] if f['metadata'].get('engine') == 'taint'
                        and f['metadata'].get('sink_name') == 'unserialize'
                        and f['metadata'].get('source_assumption') == 'observed_request'}
        own_framework = {relative_site(f['location']['file_path'], f['location']['start_line'], target)
                         for f in own['findings'] if f['metadata'].get('engine') == 'taint'
                         and f['metadata'].get('sink_name') == 'unserialize'
                         and f['metadata'].get('source_assumption') == 'modeled_framework_request'}
        ext_review = by_rule.get('php-unserialize-review', set())
        ext_taint = by_rule.get('php-request-to-unserialize', set())
        scanned_paths = {path.replace('\\', '/').lower() for path in external.get('paths', {}).get('scanned', [])}
        own_inventory_scanned = {site for site in own_inventory
                                 if any(path.endswith('/' + site.rsplit(':', 1)[0].lower())
                                        for path in scanned_paths)}
        row = {
            'project': name, 'target': target,
            'own_scanned_files': own['summary']['total_files_scanned'],
            'semgrep_scanned_files': run['scanned_files'],
            'own_errors': len(own['errors']), 'semgrep_errors': len(external['errors']),
            'semgrep_error_files': sorted({e.get('path') for e in external['errors'] if e.get('path')}),
            'own_findings_all_categories': len(own['findings']),
            'semgrep_findings_all_four_rules': len(external['results']),
            'semgrep_rule_counts': dict(sorted(Counter(r['check_id'] for r in external['results']).items())),
            'unserialize_inventory': {
                'own_sites': len(own_inventory), 'semgrep_review_sites': len(ext_review),
                'own_sites_in_semgrep_scanned_files': len(own_inventory_scanned),
                'common_in_scanned_files': len(own_inventory_scanned & ext_review),
                'own_only_in_scanned_files': sorted(own_inventory_scanned - ext_review),
                'common': sorted(own_inventory & ext_review),
                'own_only': sorted(own_inventory - ext_review),
                'semgrep_only': sorted(ext_review - own_inventory),
            },
            'request_to_unserialize': {
                'own_observed_sites': sorted(own_observed),
                'own_modeled_framework_sites': sorted(own_framework),
                'semgrep_observed_sites': sorted(ext_taint),
                'common_observed': sorted(own_observed & ext_taint),
                'own_only_observed': sorted(own_observed - ext_taint),
                'semgrep_only_observed': sorted(ext_taint - own_observed),
            },
        }
        rows.append(row)
    (semgrep / 'comparison.json').write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding='utf-8')
    for row in rows:
        print(row['project'], 'files', row['own_scanned_files'], row['semgrep_scanned_files'],
              'all', row['own_findings_all_categories'], row['semgrep_findings_all_four_rules'],
              'taint', len(row['request_to_unserialize']['own_observed_sites']),
              len(row['request_to_unserialize']['semgrep_observed_sites']),
              'errors', row['own_errors'], row['semgrep_errors'])


if __name__ == '__main__':
    main()
