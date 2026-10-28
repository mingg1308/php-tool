"""Run only isolated setter fixtures with a harmless object restoration marker."""
import json
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'reports/evaluation/drupal-cve-2019-6340-assessment'
rows=[]
for case in json.loads((OUT/'boundary-cases/labels.json').read_text(encoding='utf8')):
    command=['docker','run','--rm','--network','none','--memory','256m','--cpus','1',
        '--entrypoint','php','-v',str(OUT)+':/evidence:ro','php-sast-references:local',
        '-d','error_reporting=0','-d','auto_prepend_file=/evidence/probe_runtime.php',
        '/evidence/boundary-cases/'+case['case']+'.php']
    result=subprocess.run(command,capture_output=True,text=True,timeout=30)
    observed='BENIGN_OBJECT_RESTORED' in result.stdout
    rows.append({'case':case['case'],'exit_code':result.returncode,
        'benign_object_restored':observed,'expected':case['expected_untrusted_unserialize'],
        'passed':result.returncode==0 and observed==case['expected_untrusted_unserialize'],
        'stdout':result.stdout,'stderr':result.stderr,'command':command})
(OUT/'boundary-runtime.json').write_text(json.dumps({'scope':'Only isolated original setter bodies; not a deployed Drupal exploit or REST/HAL verification.',
    'runtime':'PHP in pinned php-sast-references:local image; differs from target PHP 7.4 static setting',
    'cases':rows},indent=2),encoding='utf8')
print(json.dumps(rows))
