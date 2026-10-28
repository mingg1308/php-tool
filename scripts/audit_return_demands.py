"""Check whether reporting introduces return demands absent at summary fixpoint."""
import argparse
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.core.dataflow import FlowProject
from php_deserial_sast.scanner import PHPDeserializationScanner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    snapshots = []
    original = FlowProject.build
    def build(project, *positional, **keywords):
        original(project, *positional, **keywords)
        snapshots.append((project, set(project.return_demands)))
    with patch.object(FlowProject, 'build', build):
        result = PHPDeserializationScanner(ScannerConfig(
            target_path=str(Path(args.target).resolve()), php_version='7.4',
            enable_rules=False, enable_gadgets=False,
            experimental_demand_summaries=True)).scan()
    late = sorted({key for project, before in snapshots for key in project.return_demands - before})
    data = {'target': args.target, 'late_return_demands': late,
            'summary_converged': all(p.converged for p, _ in snapshots),
            'summary_builds': len(snapshots), 'scan_errors': [e.model_dump() for e in result.errors],
            'taint_findings': len(result.findings), 'seconds': result.summary.scan_duration_seconds,
            'scope': 'Taint-only scan; verifies demand closure, not exploitability.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(data, ensure_ascii=True))
    return int(bool(late) or not data['summary_converged'] or not snapshots)


if __name__ == '__main__':
    raise SystemExit(main())
