"""Review direct side effects in Serializable::unserialize callbacks."""

from php_deserial_sast.models import Finding, VulnerabilityType, Severity, Confidence


def serializable_callback_reviews(symbol_table):
    findings = []
    for cls in symbol_table.get_all_unique_classes():
        interfaces = {name.lstrip('\\').lower() for name in
                      [*cls.resolved_interfaces, *cls.interfaces]}
        if 'serializable' not in interfaces:
            continue
        method = next((method for name, method in cls.methods.items()
                       if name.lower() == 'unserialize'), None)
        if method is None or method.location is None:
            continue
        dangerous = sorted({call.callee_name for call in method.calls if call.is_sink})
        if not dangerous:
            continue
        location = method.location
        findings.append(Finding(
            id=f'SERIALIZABLE-CALLBACK-{cls.full_name or cls.name}-{location.start_line}',
            rule_id='php-serializable-unserialize-side-effect-review',
            vuln_type=VulnerabilityType.CUSTOM_RULE_MATCH,
            title='Review Serializable::unserialize side effect',
            description=(
                f'{cls.full_name or cls.name} implements Serializable and its unserialize() '
                f'callback directly calls {", ".join(dangerous)}. A compatible legacy-format '
                'serialized object and a reachable untrusted deserialization entry are required.'
            ),
            severity=Severity.MEDIUM, confidence=Confidence.LOW,
            location=location, code_snippet=method.body_text[:800],
            cwe=None, owasp=None,
            remediation='Avoid dangerous side effects in Serializable::unserialize(); validate restored data and remove unsafe object deserialization entry points.',
            metadata={
                'engine': 'typed_rule', 'analysis_status': 'serializable_callback_review',
                'class_name': cls.full_name or cls.name,
                'direct_sinks': dangerous,
                'exploitability_verified': False,
                'prerequisites': [
                    'A compatible serialized object of this class reaches an untrusted deserialization entry.',
                    'The class is loaded and the direct side effect is reachable with controlled state.',
                ],
                'documentation': 'https://www.php.net/manual/en/class.serializable.php',
            },
        ))
    return findings
