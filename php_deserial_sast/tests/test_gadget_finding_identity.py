"""A shared inherited magic-method location must not hide distinct POP paths."""

import unittest

from php_deserial_sast.models import (
    CodeLocation, Confidence, Finding, GadgetChain, GadgetStep, Severity,
    VulnerabilityType,
)
from php_deserial_sast.scanner import PHPDeserializationScanner


class GadgetFindingIdentityTests(unittest.TestCase):
    def test_distinct_chains_at_same_entry_location_are_retained(self):
        location = CodeLocation(file_path='AbstractHandler.php', start_line=42,
                                start_col=5, end_line=42, end_col=25)

        def finding(chain_id, receiver):
            chain = GadgetChain(
                chain_id=chain_id, entry_class=receiver,
                entry_method='__destruct', sink_class='Sink',
                sink_method='run', sink_function='system', sink_type='RCE',
                steps=[GadgetStep(
                    step_number=1, class_name=receiver,
                    method_name='__destruct', step_type='ENTRY_MAGIC_METHOD',
                    location=location, code_snippet='function __destruct() {}',
                    description='Inherited destructor'),
                    GadgetStep(
                        step_number=2, class_name='Sink', method_name='run',
                        step_type='SINK_CALL', location=location,
                        code_snippet='system($cmd)', description='Impact')],
                length=2,
            )
            return Finding(
                id=f'POP-{chain_id}', rule_id='php-pop-gadget-chain',
                vuln_type=VulnerabilityType.POP_GADGET_CHAIN,
                title='Candidate POP chain', description='Candidate',
                severity=Severity.LOW, confidence=Confidence.LOW,
                location=location, code_snippet='function __destruct() {}',
                gadget_chain=chain,
            )

        scanner = object.__new__(PHPDeserializationScanner)
        retained = scanner._deduplicate_findings([
            finding('first', 'FingersCrossedHandler'),
            finding('second', 'SyslogUdpHandler'),
            finding('first', 'FingersCrossedHandler'),
        ])
        self.assertEqual({f.gadget_chain.chain_id for f in retained},
                         {'first', 'second'})
        self.assertEqual(len(retained), 2)

    def test_same_entry_and_impact_are_clustered_with_alternatives(self):
        location = CodeLocation(file_path='Handler.php', start_line=7,
                                start_col=3, end_line=7, end_col=25)
        def candidate(chain_id):
            step = GadgetStep(step_number=1, class_name='Handler',
                              method_name='__destruct', step_type='ENTRY_MAGIC_METHOD',
                              location=location, code_snippet='__destruct()', description='Entry')
            chain = GadgetChain(chain_id=chain_id, entry_class='Handler',
                                entry_method='__destruct', sink_class='Handler',
                                sink_method='run', sink_function='system',
                                sink_type='RCE', steps=[step], length=1)
            return Finding(id='POP-' + chain_id, rule_id='php-pop-gadget-chain',
                           vuln_type=VulnerabilityType.POP_GADGET_CHAIN,
                           title='Candidate', description='Candidate',
                           severity=Severity.LOW, confidence=Confidence.LOW,
                           location=location, code_snippet='__destruct()',
                           gadget_chain=chain)

        retained = object.__new__(PHPDeserializationScanner)._deduplicate_findings(
            [candidate('route-a'), candidate('route-b')])
        self.assertEqual(len(retained), 1)
        self.assertEqual(len(retained[0].metadata['alternative_gadget_chain_ids']), 1)


if __name__ == '__main__':
    unittest.main()
