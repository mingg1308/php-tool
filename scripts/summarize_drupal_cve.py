"""Compare CVE sink localization separately from end-to-end taint evidence."""
from pathlib import Path
from collections import Counter
import hashlib
import json
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'reports/evaluation'
OUT=BASE/'drupal-cve-2019-6340-assessment'
PROJECT='drupal-8.6.9'
SITES={'link':('core/modules/link/src/Plugin/Field/FieldType/LinkItem.php',194),
       'map':('core/lib/Drupal/Core/Field/Plugin/Field/FieldType/MapItem.php',67)}
def read(path,default=None):
    try:return json.loads(path.read_text(encoding='utf8'))
    except (OSError,ValueError):return default

def matches(path,line,site):
    return path.replace('\\','/').endswith(site[0]) and line==site[1]

def own(label):
    folder=BASE/label; runs=read(folder/'runs.json',[])
    run=next((r for r in runs if r['project']==PROJECT),{})
    data=read(folder/(PROJECT+'.json'))
    result={'label':label,'status':run.get('status','not_run'),'exit_code':run.get('exit_code'),
        'wall_seconds':run.get('seconds'),'report_available':data is not None,'sites':None}
    if data is None:return result
    result.update(summary=data['summary'],errors=data['errors'],analysis=data['analysis'],
        rule_counts=dict(Counter(f['rule_id'] for f in data['findings'])),
        evidence_counts=dict(Counter(f['assessment']['evidence_level'] for f in data['findings'])))
    result['sites']={}
    for key,site in SITES.items():
        findings=[f for f in data['findings'] if matches(f['location']['file_path'],f['location']['start_line'],site)]
        inventory=[s for s in data['sink_inventory'] if matches(s['location']['file_path'],s['location']['start_line'],site)]
        result['sites'][key]={'localized':bool(findings),'taint_flow_found':any(f.get('flow_evidence') for f in findings),
                              'findings':findings,'inventory':inventory}
    return result

def external(tool,label,project):
    folder=BASE/label/tool/project
    run=next((r for r in read(BASE/label/(tool+'-runs.json'),[]) if r['project']==project),{})
    data=read(folder/'result.json')
    result={'status':run.get('status','not_run'),'exit_code':run.get('exit_code'),'seconds':run.get('seconds'),
            'input_files':run.get('input_files'),'report_available':data is not None,'unserialize_findings':None}
    if tool=='psalm' and isinstance(data,list):
        findings=[f for f in data if f.get('type')=='TaintedUnserialize']
        result.update(unserialize_findings=findings,total_diagnostics=len(data))
    elif tool=='progpilot' and isinstance(data,dict):
        findings=[f for f in data.get('results',[]) if f.get('sink_name')=='unserialize']
        result.update(unserialize_findings=findings,total_findings=len(data.get('results',[])),
            enumerated_files=data.get('enumerated_files'),error=data.get('error'))
    log=folder/'stderr.log'
    if log.exists():
        text=log.read_text(encoding='utf8',errors='replace')
        result['stderr_excerpt']=text[:1800]
    result['usable_complete_reference']=(data is not None and run.get('status')=='finished'
        and run.get('exit_code') in ([0,2] if tool=='psalm' else [0]) and not result.get('error'))
    return result

comparison={'cve':'CVE-2019-6340','scope':read(OUT/'cve_scope.json'),
    'own_default':own('drupal-cve-2019-6340-default'),
    'own_side_effects':own('drupal-cve-2019-6340-upgraded'),
    'references':{tool:external(tool,'drupal-cve-2019-6340-references',PROJECT) for tool in ('psalm','progpilot')},
    'boundary_calibration':{'scope':'Original setter bodies with explicit caller source and inert parent stub; not a full Drupal CVE proof.',
        'labels':read(OUT/'boundary-cases/labels.json'), 'own':read(OUT/'boundary-cases/own-summary.json'),
        'references':{tool:external(tool,'drupal-cve-2019-6340-boundary-references','boundary-cases') for tool in ('psalm','progpilot')}}}
sequence=read(OUT/'sequence.json',[])
comparison['codeql']={'runs':[r for r in sequence if r['name'].startswith('codeql-')],
    'version':read(OUT/'codeql-version.stdout.log'),
    'languages':read(OUT/'codeql-languages.stdout.log'),
    'php_extractor_stdout':(OUT/'codeql-php-extractor.stdout.log').read_text(encoding='utf8',errors='replace') if (OUT/'codeql-php-extractor.stdout.log').exists() else None,
    'php_extractor_stderr':(OUT/'codeql-php-extractor.stderr.log').read_text(encoding='utf8',errors='replace') if (OUT/'codeql-php-extractor.stderr.log').exists() else None}
comparison['codeql']['ascii_retries']=read(OUT/'codeql-ascii-runs.json',[])
comparison['codeql']['local_extractors']=[p.parent.name for p in (ROOT/'codeql').glob('*/codeql-extractor.yml')]
comparison['codeql']['php_extractor_installed']='php' in comparison['codeql']['local_extractors']
comparison['codeql']['usable_php_reference']=False
comparison['codeql']['limitations']=['CLI Java initialization failed; see raw logs', 'No PHP extractor in installed distribution; PHP absent from official supported language list']
manifest=read(BASE/'drupal-cve-2019-6340-default/source_manifest.json',{})
current={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'php_deserial_sast').rglob('*') if p.suffix in {'.py','.yaml'}}
comparison['scanner_source_unchanged']=manifest==current
comparison['boundary_calibration']['runtime']=read(OUT/'boundary-runtime.json')
comparison['progpilot_direct_control']=external('progpilot','drupal-cve-2019-6340-control-reference','reference-control')
comparison['reference_environment']=read(BASE/'drupal-cve-2019-6340-references/environment.json')
comparison['reference_environment_note']='CodeQL commit in legacy runner metadata may be inherited from parent repository; use the CLI version/language probe instead. Reference execution is pinned by Docker image ID.'
original=read(OUT/'target_manifest.json',{})
target=ROOT/'testcase'/PROJECT
comparison['target_source_unchanged']=all((target/name).is_file() and hashlib.sha256((target/name).read_bytes()).hexdigest()==digest for name,digest in original.items())
comparison['reference_input_parity']={}
for tool in ('psalm','progpilot'):
    files=read(BASE/'drupal-cve-2019-6340-references'/tool/PROJECT/'files.json',[])
    actual={name.removeprefix('/tmp/target/') for name in files}
    comparison['reference_input_parity'][tool]={'files':len(actual),'same_paths_as_manifest':actual==set(original)}

comparison['accuracy_metrics']={'precision':None,'recall':None,
    'reason':'No independent exhaustive labels; failed/unsupported reference scans are not negative results.'}
(OUT/'comparison.json').write_text(json.dumps(comparison,indent=2,ensure_ascii=False),encoding='utf8')
print(json.dumps({'scanner_source_unchanged':comparison['scanner_source_unchanged'],
    'references':{k:{a:v.get(a) for a in ('status','seconds','report_available','usable_complete_reference')} for k,v in comparison['references'].items()}}))
