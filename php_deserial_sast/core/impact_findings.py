"""Surface conditional RCE impacts already linked to an observed deserialize site.

These findings summarize retained routes. They do not claim that a serialized
object, its properties, or a later request were exercised at runtime.
"""

from collections import defaultdict
import hashlib
import json

from php_deserial_sast.core.review_priority import score_review_priority
from php_deserial_sast.models import (
    Confidence, EvidenceAssessment, Finding, Severity, VulnerabilityType,
)


def _identity(parts):
    encoded = json.dumps(parts, ensure_ascii=False, sort_keys=True, default=str).encode('utf-8')
    return 'IMPACT-' + hashlib.sha256(encoded).hexdigest()[:12]


def build_rce_impact_findings(routes, findings):
    """Return one review finding per source, candidate class and RCE sink.

    Multiple possible triggers to the same impact are grouped so a game with
    several maps does not produce repeated warnings for one eval() site.
    Only a direct RCE sink is promoted. A dynamic call target or file write is
    not automatically an RCE finding.
    """
    sources = {finding.id: finding for finding in findings}
    groups = defaultdict(list)
    for route in routes:
        if (route.route_kind not in {'candidate_session_dispatch', 'candidate_gadget'}
                or route.status != 'conditional' or route.impact is None
                or route.impact_category != 'RCE' or not route.impact_function):
            continue
        source = sources.get(route.source_finding_id)
        if (source is None or source.metadata.get('sink_type') != 'DIRECT_UNSERIALIZE'
                or not any(flow.source_kind == 'request' and not flow.uncertain
                           for flow in source.flow_evidence)):
            continue
        impact = route.impact
        key = (source.id, route.route_kind, route.entry_class,
               impact.file_path, impact.start_line, impact.start_col,
               route.impact_function)
        groups[key].append(route)

    emitted = []
    for key, linked in sorted(groups.items(), key=lambda pair: repr(pair[0])):
        source_id, kind, entry_class, _, _, _, sink_function = key
        source = sources[source_id]
        impact = linked[0].impact
        missing_edges = sorted({edge for route in linked for edge in route.missing_edges})
        trigger_sites = sorted({(route.trigger.file_path, route.trigger.start_line)
                                for route in linked if route.trigger})
        trigger_note = (f'{len(trigger_sites)} possible later trigger site(s) were retained.'
                        if kind == 'candidate_session_dispatch' else
                        'A candidate magic-method gadget path was retained.')
        candidate = entry_class or 'unknown class'
        finding = Finding(
            id=_identity(key),
            rule_id='php-deserialization-rce-impact-candidate',
            vuln_type=VulnerabilityType.CUSTOM_RULE_MATCH,
            title=f'Conditional RCE impact: {candidate} -> {sink_function}()',
            description=(
                f'An observed request-to-deserialization finding has a candidate '
                f'{kind.replace("_", " ")} route to {sink_function}() through {candidate}. '
                f'{trigger_note} '
                'The object class, serialized properties, and runtime execution are not proven.'
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            location=impact,
            code_snippet='',
            cwe=('CWE-78: Improper Neutralization of Special Elements used in an OS Command'
                 if sink_function.lower() in {'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open'}
                 else 'CWE-94: Improper Control of Generation of Code'),
            remediation=(
                'Do not deserialize untrusted PHP objects. Use a data-only format, '
                'and do not execute code or commands from object properties.'
            ),
            metadata={
                'engine': 'impact_candidate',
                'analysis_status': 'conditional_deserialization_impact',
                'source_finding_id': source_id,
                'source_location': source.location.model_dump(),
                'route_kind': kind,
                'route_ids': sorted(route.route_id for route in linked),
                'candidate_class': entry_class,
                'impact_function': sink_function,
                'trigger_sites': [{'file_path': path, 'start_line': line}
                                  for path, line in trigger_sites],
                'missing_edges': missing_edges,
                'class_loading': sorted({route.class_loading or 'unknown' for route in linked}),
                'source_scope': source.metadata.get('source_scope', 'production'),
                'exploitability_verified': False,
            },
        )
        finding.assessment = EvidenceAssessment(
            potential_impact=Severity.CRITICAL,
            evidence_level='candidate_call_chain',
            detection_level='review_candidate',
            analysis_completeness='limited',
            limitations=missing_edges,
            exploitability_verified=False,
            review_priority=score_review_priority(
                finding, 'candidate_call_chain', 'review_candidate', missing_edges),
        )
        emitted.append(finding)
    return emitted
