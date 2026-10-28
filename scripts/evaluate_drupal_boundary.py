"""Boundary calibration only; never substitutes for a complete Drupal scan."""
from pathlib import Path
import json
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
OUT=ROOT/'reports/evaluation/drupal-cve-2019-6340-assessment'
start=time.monotonic()
while True:
    p=OUT/'sequence.json'
    try:
        finished=any(r['name']=='codeql-php-extractor' for r in json.loads(p.read_text(encoding='utf8')))
    except (OSError,ValueError):
        finished=False
    if finished: break
    if time.monotonic()-start>1800: raise SystemExit('Full-project reference sequence has not finished')
    time.sleep(2)
from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.scanner import PHPDeserializationScanner
from php_deserial_sast.models import Severity
cases=OUT/'boundary-cases'
labels=json.loads((cases/'labels.json').read_text(encoding='utf8'))
rows=[]
for case in labels:
    fixture=cases/(case['case']+'.php')
    result=PHPDeserializationScanner(ScannerConfig(target_path=str(fixture),php_version='7.4',
        min_severity=Severity.INFO,enable_gadgets=False,experimental_side_effects=True)).scan()
    (cases/(case['case']+'.own.json')).write_text(result.model_dump_json(indent=2),encoding='utf8')
    taints=[f for f in result.findings if f.metadata.get('engine')=='taint' and f.metadata.get('sink_name')=='unserialize']
    rows.append({'case':case['case'],'expected':case['expected_untrusted_unserialize'],'observed':bool(taints),
        'passed':bool(taints)==case['expected_untrusted_unserialize'] and not result.errors})
(cases/'own-summary.json').write_text(json.dumps(rows,indent=2),encoding='utf8')
print('OWN_BOUNDARY',json.dumps(rows),flush=True)
for tool in ('psalm','progpilot'):
    command=[sys.executable,'scripts/evaluate_external.py','--tool',tool,'--skip-fixtures',
        '--projects','__no_full_projects__','--target',str(cases),'--timeout','180',
        '--image','php-sast-references:local','--label','drupal-cve-2019-6340-boundary-references']
    with (OUT/(tool+'-boundary.runner.log')).open('wb') as log:
        result=subprocess.run(command,cwd=ROOT,stdout=log,stderr=log)
    print('END_BOUNDARY',tool,result.returncode,flush=True)
