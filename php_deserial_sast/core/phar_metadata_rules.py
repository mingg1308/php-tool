"""Typed review of explicit Phar metadata deserialization.

PHP 8 removed implicit metadata deserialization on archive opening, but
Phar::getMetadata and PharFileInfo::getMetadata still deserialize metadata.
This reports the operation, not attacker control of the archive or a gadget.
"""

from php_deserial_sast.core.dataflow import arguments, expression
from php_deserial_sast.core.parser import get_node_location
from php_deserial_sast.models import Finding, VulnerabilityType, Severity, Confidence


PHAR_METADATA_CLASSES = {'phar', 'pharfileinfo'}


def explicit_phar_metadata_reviews(engine, php_version):
    project = engine.project
    php8_or_newer = bool(php_version and tuple(map(int, php_version.split('.')[:2])) >= (8, 0))
    findings = []
    for scope, nodes in engine.nodes.items():
        for call in nodes:
            if (call.type not in {'member_call_expression', 'nullsafe_member_call_expression'}
                    or engine.call_name(call) != 'getmetadata'
                    or not engine.reachable(call, scope)):
                continue
            project.resolve(engine, call)
            receiver = project.receiver_classes.get((engine.path, call.id), '').lstrip('\\').lower()
            if receiver not in PHAR_METADATA_CLASSES:
                continue
            args = arguments(call)
            option = expression(args[0]) if args else None
            allowed = engine._array_field(option, 'allowed_classes')
            restricted = bool(allowed is not None and
                              (engine.text(allowed).lower() == 'false' or
                               allowed.type == 'array_creation_expression' and not allowed.named_children))
            if php8_or_newer and restricted:
                continue
            location = get_node_location(call, engine.path)
            findings.append(Finding(
                id=f'PHAR-METADATA-{engine.path}-{call.start_byte}',
                rule_id='php-phar-explicit-metadata-review',
                vuln_type=VulnerabilityType.CUSTOM_RULE_MATCH,
                title='Review explicit Phar metadata deserialization',
                description=(
                    f'{receiver}::getMetadata() deserializes archive metadata. '
                    'Whether the archive is attacker-controlled, contains an object, and can reach a gadget requires review.'
                ),
                severity=Severity.MEDIUM, confidence=Confidence.LOW,
                location=location, code_snippet=engine.text(call),
                remediation='Do not load metadata from untrusted Phar archives; on PHP 8+, restrict allowed_classes when objects are unnecessary.',
                metadata={
                    'engine': 'typed_rule', 'analysis_status': 'conditional_metadata_deserialization',
                    'receiver_class': receiver, 'target_php_version': php_version or 'unknown',
                    'class_policy': 'unknown' if option is not None else 'allow_objects',
                    'runtime_configuration_verified': False, 'exploitability_verified': False,
                    'prerequisites': [
                        'The Phar archive must be attacker-controlled or its metadata untrusted.',
                        'Metadata must reconstruct an object and a compatible gadget must be loaded.',
                    ],
                },
            ))
    return findings
