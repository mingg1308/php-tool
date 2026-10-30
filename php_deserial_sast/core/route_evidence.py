"""Project-level, stable identifiers for evidence already produced by engines.

This module does not infer new reachability. In particular a compatible gadget
remains conditional even when a static source-to-sink route is proven.
"""

import hashlib
import json

from php_deserial_sast.models import CodeLocation, RouteEvidence


def _identity(parts):
    encoded = json.dumps(parts, ensure_ascii=False, sort_keys=True,
                         separators=(',', ':'), default=str).encode('utf-8')
    return 'ROUTE-' + hashlib.sha256(encoded).hexdigest()[:16]


def build_route_evidence(findings):
    routes = {}
    for finding in findings:
        if finding.metadata.get('engine') != 'taint':
            continue
        assessment = finding.assessment
        for flow in finding.flow_evidence:
            persistent_read = next((row for row in finding.metadata.get(
                'persistent_store_read_evidence', ())
                if flow.source_kind == 'persistent_data' and flow.source_fields
                and row.get('column') == flow.source_fields[-1]), None)
            missing = []
            if flow.uncertain:
                missing.append('unresolved_data_propagation')
            if flow.source_kind == 'library_parameter':
                missing.append('external_caller')
            elif flow.source_kind == 'persistent_data':
                missing.append('attacker_controlled_store_write')
            elif flow.source_kind == 'framework_request':
                missing.append('framework_runtime_binding')
            if flow.review_conditions:
                missing.append('guard_feasibility')
            if flow.path_assumptions:
                missing.append('runtime_path_configuration')
            global_limitations = (limitation for limitation in (assessment.limitations if assessment else ())
                                  if limitation.startswith(('scan_error:', 'summary_', 'cfg_',
                                                            'dependency_', 'unresolved_call',
                                                            'exception_', 'php_runtime_',
                                                            'legacy_wddx_')))
            if assessment and any(global_limitations):
                missing.append('analysis_coverage')
            status = ('unknown' if flow.uncertain else
                      'conditional' if missing or flow.source_kind != 'request' else
                      'proven')
            identity = [finding.id, finding.location.model_dump(), flow.source_kind,
                        flow.source_origin, flow.source_parameter, flow.source_fields,
                        flow.review_conditions, flow.path_assumptions, flow.uncertain]
            route = RouteEvidence(
                route_id=_identity(identity), route_kind='source_to_sink',
                status=status, source_finding_id=finding.id,
                source_kind=flow.source_kind, source_origin=flow.source_origin,
                sink=finding.location, review_conditions=list(flow.review_conditions),
                path_assumptions=list(flow.path_assumptions),
                persistent_table=persistent_read.get('table') if persistent_read else None,
                persistent_column=persistent_read.get('column') if persistent_read else None,
                missing_edges=missing,
            )
            routes[route.route_id] = route

            if persistent_read:
                for candidate in finding.metadata.get('persistent_store_write_candidates', ()):
                    if (candidate.get('table') != persistent_read.get('table')
                            or candidate.get('column') != persistent_read.get('column')
                            or candidate.get('read_location') != persistent_read.get('read_location')
                            or not candidate.get('location')):
                        continue
                    identity = [finding.id, flow.source_origin, candidate['location'],
                                candidate['read_location'], candidate['table'], candidate['column'],
                                candidate.get('source_origin')]
                    candidate_route = RouteEvidence(
                        route_id=_identity(identity), route_kind='candidate_persistent_store',
                        status='conditional', source_finding_id=finding.id,
                        source_kind=candidate.get('source_kind', 'unknown'),
                        source_origin=candidate.get('source_origin', 'unknown'), sink=finding.location,
                        store=CodeLocation.model_validate(candidate['location']),
                        trigger=CodeLocation.model_validate(candidate['read_location']),
                        persistent_table=candidate['table'],
                        persistent_column=candidate['column'],
                        missing_edges=['write_read_identity_and_order',
                                       'write_authorization', 'runtime_path_configuration'],
                    )
                    routes[candidate_route.route_id] = candidate_route

        for link in finding.metadata.get('candidate_exploit_paths', ()):
            chain_id = link.get('gadget_chain_id')
            impact = link.get('impact_site')
            if not chain_id or not impact:
                continue
            identity = [finding.id, finding.location.model_dump(), chain_id,
                        link.get('entry_class'), impact]
            missing = list(link.get('runtime_conditions_unverified', ()))
            route = RouteEvidence(
                route_id=_identity(identity), route_kind='candidate_gadget',
                status='conditional', source_finding_id=finding.id,
                source_kind='request', source_origin='linked_source_finding',
                sink=finding.location, gadget_chain_id=chain_id,
                entry_class=link.get('entry_class'),
                impact=CodeLocation.model_validate(impact),
                missing_edges=missing,
            )
            routes[route.route_id] = route
        dispatch = finding.metadata.get('deserialized_session_dispatch', {})
        for group, trigger_key in (('calls', 'call_location'),
                                   ('render_sites', 'render_location')):
            for row in dispatch.get(group, ()):
                store = row.get('store_location')
                trigger = row.get(trigger_key)
                if not store or not trigger:
                    continue
                for candidate in row.get('candidate_classes', ()):
                    loading = candidate.get('class_loading', 'unknown')
                    for impact in candidate.get('dangerous_sinks', ()):
                        impact_location = impact.get('location')
                        if not impact_location:
                            continue
                        identity = [finding.id, row.get('session_key'), store,
                                    trigger, candidate.get('class'), impact_location,
                                    impact.get('function')]
                        missing = ['session_identity_and_request_order',
                                   'object_class_and_properties',
                                   'runtime_trigger_and_effect']
                        if loading != 'included':
                            missing.append('class_loading_unverified')
                        if row.get('candidate_classes_truncated'):
                            missing.append('dispatch_candidates_unexamined')
                        if candidate.get('sink_search_truncated'):
                            missing.append('dispatch_sink_search_truncated')
                        route = RouteEvidence(
                            route_id=_identity(identity),
                            route_kind='candidate_session_dispatch',
                            status='conditional', source_finding_id=finding.id,
                            source_kind='request',
                            source_origin='linked_source_finding',
                            sink=finding.location,
                            entry_class=candidate.get('class'),
                            impact=CodeLocation.model_validate(impact_location),
                            store=CodeLocation.model_validate(store),
                            trigger=CodeLocation.model_validate(trigger),
                            session_key=str(row.get('session_key')),
                            class_loading=loading,
                            bootstrap_entrypoints=list(row.get('bootstrap_entrypoints', ())),
                            session_start_on_both_routes=row.get(
                                'session_bootstrap', {}).get('session_start_on_both_routes'),
                            missing_edges=missing,
                        )
                        routes[route.route_id] = route
    return sorted(routes.values(), key=lambda route: (route.sink.file_path,
                  route.sink.start_line, route.route_kind, route.route_id))
