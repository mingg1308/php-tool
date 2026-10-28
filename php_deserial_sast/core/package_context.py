"""Conservative Composer package identity and offline advisory context.

Advisories describe affected components, not a proven application exploit.
The short built-in catalog is intentionally explicit and independently
auditable; unknown packages never inherit a benchmark-specific label.
"""

import json
import re
from pathlib import Path


ADVISORIES = (
    {
        'package': 'saloonphp/saloon',
        'id': 'CVE-2026-33942',
        'url': 'https://github.com/saloonphp/saloon/security/advisories/GHSA-rf88-776r-rcq9',
        'affected_before': (4, 0, 0),
        'sink_suffix': 'src/http/auth/accesstokenauthenticator.php',
        'sink_rule': 'php-unserialize-allows-all-classes',
        'advisory_severity': 'HIGH',
    },
    {
        'package': 'tecnickcom/tcpdf',
        'id': 'CVE-2018-17057',
        'url': 'https://github.com/advisories/GHSA-5hw4-m7f3-hhx8',
        'affected_before': (6, 2, 22),
        'sink_suffix': None,
        'sink_rule': None,
        'advisory_severity': 'CRITICAL',
    },
)

GADGET_REFERENCES = (
    {
        'package': 'monolog/monolog',
        'id': 'PHPGGC Monolog/RCE7',
        'url': 'https://github.com/ambionics/phpggc/tree/master/gadgetchains/Monolog/RCE/7',
        'minimum_version': (1, 10, 0),
        'before_version': (3, 0, 0),
        'entry_suffix': 'FingersCrossedHandler',
        'sink_function': 'call_user_func',
        'candidate_property': 'processors',
    },
)


def package_context(target_path):
    target = Path(target_path).resolve()
    root = target if target.is_dir() else target.parent
    context = {'name': None, 'type': None, 'version': None,
               'version_source': None, 'library_auto_detected': False,
               'advisories': [], 'gadget_references': []}
    composer = root / 'composer.json'
    if not composer.is_file():
        return context
    try:
        data = json.loads(composer.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, ValueError):
        return context
    if not isinstance(data, dict):
        return context
    name = data.get('name')
    if not isinstance(name, str):
        return context
    context['name'] = name.lower()
    context['type'] = data.get('type') if isinstance(data.get('type'), str) else None
    context['library_auto_detected'] = context['type'] == 'library'
    version = data.get('version')
    if isinstance(version, str) and re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?', version):
        context['version'], context['version_source'] = version, 'composer.json'
    else:
        short_name = name.rsplit('/', 1)[-1]
        match = re.fullmatch(re.escape(short_name) + r'-(\d+\.\d+\.\d+)', root.name, re.I)
        if match:
            context['version'], context['version_source'] = match[1], 'directory_name_unverified'
    core = re.match(r'^(\d+)\.(\d+)\.(\d+)', context['version'] or '')
    version_tuple = tuple(int(part) for part in core.groups()) if core else None
    for advisory in ADVISORIES:
        if context['name'] != advisory['package']:
            continue
        status = ('unknown_version' if version_tuple is None else
                  'affected_version' if version_tuple < advisory['affected_before'] else
                  'outside_affected_range')
        context['advisories'].append({
            'id': advisory['id'], 'url': advisory['url'], 'status': status,
            'advisory_severity': advisory['advisory_severity'],
            'version_source': context['version_source'],
            'sink_suffix': advisory['sink_suffix'],
            'sink_rule': advisory['sink_rule'],
            'exploitability_verified': False,
        })
    for reference in GADGET_REFERENCES:
        if context['name'] != reference['package']:
            continue
        status = ('unknown_version' if version_tuple is None else
                  'version_in_reference_range' if reference['minimum_version'] <= version_tuple < reference['before_version']
                  else 'outside_reference_range')
        context['gadget_references'].append({
            'id': reference['id'], 'url': reference['url'], 'status': status,
            'version_source': context['version_source'],
            'entry_suffix': reference['entry_suffix'],
            'sink_function': reference['sink_function'],
            'candidate_property': reference['candidate_property'],
            'exploitability_verified': False,
        })
    return context


def annotate_advisories(findings, context):
    for finding in findings:
        path = finding.location.file_path.replace('\\', '/').lower()
        for advisory in context['advisories']:
            if (advisory['status'] == 'affected_version'
                    and advisory['sink_suffix'] and path.endswith(advisory['sink_suffix'])
                    and finding.rule_id == advisory['sink_rule']):
                finding.metadata['known_advisory'] = {
                    key: value for key, value in advisory.items()
                    if key not in {'sink_suffix', 'sink_rule'}
                }
        chain = finding.gadget_chain
        if chain:
            for reference in context['gadget_references']:
                if (reference['status'] == 'version_in_reference_range'
                        and chain.entry_class.endswith(reference['entry_suffix'])
                        and chain.sink_function == reference['sink_function']
                        and reference['candidate_property'] in chain.candidate_serialized_properties):
                    finding.metadata['published_gadget_reference'] = {
                        key: value for key, value in reference.items()
                        if key not in {'entry_suffix', 'sink_function', 'candidate_property'}
                    }
