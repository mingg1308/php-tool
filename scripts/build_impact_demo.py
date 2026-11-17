"""Write JSON and HTML from one isolated scanner run for review."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.models import Severity
from php_deserial_sast.reporters.html_report import HTMLReporter
from php_deserial_sast.reporters.json_reporter import JSONReporter
from php_deserial_sast.scanner import PHPDeserializationScanner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target', type=Path)
    parser.add_argument('--php-version', default='7.3')
    parser.add_argument('--output', type=Path, default=Path('evaluation/pokemon'))
    args = parser.parse_args()
    result = PHPDeserializationScanner(ScannerConfig(
        target_path=str(args.target.resolve()), php_version=args.php_version,
        enable_llm=False, min_severity=Severity.INFO,
    )).scan()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    JSONReporter().save_to_file(result, str(args.output.with_suffix('.json')))
    HTMLReporter().save_to_file(result, str(args.output.with_suffix('.html')))
    print(f'findings={len(result.findings)} routes={len(result.routes)} '
          f'impact_candidates={sum(f.rule_id == "php-deserialization-rce-impact-candidate" for f in result.findings)} '
          f'errors={len(result.errors)}')
    return 2 if result.errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
