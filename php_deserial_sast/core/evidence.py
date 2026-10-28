"""Assess static evidence independently of the potential impact rating."""
from php_deserial_sast.models import EvidenceAssessment


def compact_flow_evidence(routes, limit=32):
    unique = {route.model_dump_json(): route for route in routes}
    selected, remaining, groups = [], [], set()
    for route in unique.values():
        group = (route.source_kind, route.uncertain, tuple(route.review_conditions), tuple(route.path_assumptions))
        if group not in groups:
            groups.add(group)
            selected.append(route)
        else:
            remaining.append(route)
    return (selected + remaining)[:limit], len(unique)


def assess_finding(finding, errors):
    status = finding.metadata.get("analysis_status")
    routes = finding.flow_evidence
    if routes:
        kinds = {route.source_kind for route in routes if not route.uncertain}
        level = ("observed_source_flow" if "request" in kinds else
                 "modeled_source_flow" if "framework_request" in kinds else
                 "assumed_persistent_flow" if any(route.source_kind == "persistent_data" for route in routes) else
                 "assumed_api_flow" if "library_parameter" in kinds else "unresolved_flow")
    else:
        level = "candidate_call_chain" if status == "candidate_call_chain" else "syntactic_review"
    # Errors in other files can affect dependencies. Until coverage is tracked
    # per dependency, report them conservatively on all retained findings.
    coverage = finding.metadata.get('dependency_coverage')
    dependencies = set(coverage['files']) if coverage else None
    local_phases = {'taint', 'rules', 'loop_fixed_point'}
    pop_phases = {'call_graph_limit', 'gadget_limit'}
    limitations = {f"scan_error:{error.phase}" for error in errors
                   if error.phase != 'llm'
                   and (error.phase not in pop_phases or status == 'candidate_call_chain')
                   and (error.phase not in local_phases or dependencies is None
                        or error.file_path in dependencies)}
    if finding.metadata.get("summary_converged") is False:
        limitations.add("summary_not_converged")
    if finding.metadata.get("cfg_fallback_scopes_in_project"):
        limitations.add("cfg_partial_project_coverage")
    if coverage and coverage['fallback_scopes']:
        limitations.add('cfg_dependency_scope_fallback')
    if coverage and coverage['missing_files']:
        limitations.add('dependency_files_not_analyzed')
    if coverage and coverage.get('unresolved_call_count', 0):
        limitations.add('dependency_calls_unresolved')
    if finding.metadata.get('exception_flow_approximation'):
        limitations.add('exception_types_and_finally_completions_approximated')
    if finding.metadata.get("flow_evidence_truncated"):
        limitations.add("displayed_flow_evidence_truncated")
    if finding.metadata.get("summary_evidence_truncated"):
        limitations.add("summary_guard_alternatives_truncated")
    if any(route.uncertain for route in routes):
        limitations.add("unresolved_propagation")
    if any(route.review_conditions for route in routes):
        limitations.add("guard_not_proven")
    if any(route.path_assumptions for route in routes):
        limitations.add("runtime_path_configuration_assumed")
    if any(route.source_kind == "library_parameter" for route in routes):
        limitations.add("external_caller_assumed")
    if any(route.source_kind == "framework_request" for route in routes):
        limitations.add("framework_source_modeled")
    if any(route.source_kind == "persistent_data" for route in routes):
        limitations.add("persistent_store_write_provenance_unverified")
    if finding.metadata.get("sink_type") == "PHAR_DESERIALIZATION" and finding.metadata.get("target_php_version") == "unknown":
        limitations.add("php_runtime_version_unknown")
    if status == "candidate_call_chain":
        limitations.add("property_control_and_deserialization_entry_not_proven")
    completeness = "limited" if limitations else "within_model"
    if (finding.metadata.get("sink_type") == "DIRECT_UNSERIALIZE"
            and level == "observed_source_flow" and completeness == "within_model"
            and any(route.source_kind == "request" and not route.uncertain
                    and not route.review_conditions and not route.path_assumptions
                    for route in routes)):
        detection_level = "direct_untrusted_deserialization"
    elif routes:
        detection_level = "conditional_path"
    else:
        detection_level = "review_candidate"
    finding.assessment = EvidenceAssessment(
        potential_impact=finding.severity, evidence_level=level,
        detection_level=detection_level, analysis_completeness=completeness,
        limitations=sorted(limitations),
    )
