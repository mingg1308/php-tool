"""Typed review of explicit SPL container deserialization methods.

Only exact built-in receiver types are reported. An arbitrary user-defined
``unserialize`` method is not assumed to parse PHP's object format.
"""

from php_deserial_sast.core.dataflow import arguments, expression
from php_deserial_sast.core.parser import get_node_location
from php_deserial_sast.models import Finding, VulnerabilityType, Severity, Confidence


SPL_DESERIALIZERS = {
    'splobjectstorage', 'arrayobject', 'arrayiterator',
    'spldoublylinkedlist', 'splstack', 'splqueue',
}


def explicit_spl_deserialization_reviews(engine):
    findings = []
    project = engine.project
    for scope, nodes in engine.nodes.items():
        for call in nodes:
            if (call.type not in {'member_call_expression', 'nullsafe_member_call_expression'}
                    or engine.call_name(call) != 'unserialize'
                    or not engine.reachable(call, scope)):
                continue
            args = arguments(call)
            if not args or expression(args[0]) is None:
                continue
            project.resolve(engine, call)
            receiver = project.receiver_classes.get((engine.path, call.id), '').lstrip('\\').lower()
            if receiver not in SPL_DESERIALIZERS:
                continue
            location = get_node_location(call, engine.path)
            findings.append(Finding(
                id=f'SPL-DESERIALIZE-{engine.path}-{call.start_byte}',
                rule_id='php-spl-explicit-unserialize-review',
                vuln_type=VulnerabilityType.CUSTOM_RULE_MATCH,
                title='Review SPL container deserialization',
                description=(
                    f'{receiver}::unserialize() restores a serialized container. '
                    'Determine whether its input is attacker-controlled and can reconstruct objects; '
                    'this call alone does not prove object injection or gadget reachability.'
                ),
                severity=Severity.MEDIUM, confidence=Confidence.LOW,
                location=location, code_snippet=engine.text(call),
                remediation='Do not pass untrusted serialized data to SPL container unserialize methods.',
                metadata={
                    'engine': 'typed_rule', 'analysis_status': 'conditional_spl_deserialization_review',
                    'receiver_class': receiver, 'exploitability_verified': False,
                    'prerequisites': [
                        'The serialized container input is attacker-controlled.',
                        'Object reconstruction and a compatible gadget are possible at runtime.',
                    ],
                    'documentation': 'https://www.php.net/manual/en/splobjectstorage.unserialize.php',
                },
            ))
    return findings
