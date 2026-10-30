"""Explainable static review priority, independent of vulnerability severity.

The numeric scale orders manual review; it is neither CVSS nor a probability of
exploitation. Only evidence already retained in a finding can change the score.
"""

from php_deserial_sast.models import Confidence, ReviewPriority, Severity


IMPACT = {
    Severity.CRITICAL: 35, Severity.HIGH: 28, Severity.MEDIUM: 20,
    Severity.LOW: 10, Severity.INFO: 4,
}
EVIDENCE = {
    "observed_source_flow": 30,
    "modeled_source_flow": 22,
    "assumed_persistent_flow": 12,
    "assumed_api_flow": 10,
    "unresolved_flow": 14,
    "candidate_call_chain": 5,
    "syntactic_review": 2,
}
CONFIDENCE = {Confidence.HIGH: 15, Confidence.MEDIUM: 9, Confidence.LOW: 3}
DETECTION = {
    "direct_untrusted_deserialization": 20,
    "conditional_path": 8,
    "review_candidate": 0,
}
LIMITATION_COST = {
    "guard_not_proven": 12,
    "unresolved_propagation": 10,
    "runtime_path_configuration_assumed": 10,
    "external_caller_assumed": 5,
    "framework_source_modeled": 4,
    "persistent_store_write_provenance_unverified": 8,
    "php_runtime_version_unknown": 8,
    "legacy_wddx_runtime_unverified": 8,
    "property_control_and_deserialization_entry_not_proven": 8,
    "dependency_files_not_analyzed": 8,
    "dependency_calls_unresolved": 4,
    "summary_not_converged": 8,
    "summary_guard_alternatives_truncated": 4,
    "displayed_flow_evidence_truncated": 2,
    "cfg_dependency_scope_fallback": 3,
    "cfg_partial_project_coverage": 3,
    "exception_types_and_finally_completions_approximated": 2,
}
SCOPE_COST = {"tests": 12, "vendor": 8, "examples": 8, "external": 8}


def score_review_priority(finding, evidence_level, detection_level, limitations):
    """Return a deterministic score and its complete arithmetic breakdown."""
    factors = {
        f"impact:{finding.severity.value}": IMPACT[finding.severity],
        f"evidence:{evidence_level}": EVIDENCE[evidence_level],
        f"confidence:{finding.confidence.value}": CONFIDENCE[finding.confidence],
        f"detection:{detection_level}": DETECTION[detection_level],
    }
    if limitations:
        factors["analysis:limited"] = -5
    for limitation in sorted(limitations):
        if limitation in LIMITATION_COST:
            factors[f"limitation:{limitation}"] = -LIMITATION_COST[limitation]
        elif limitation.startswith("scan_error:"):
            factors[f"limitation:{limitation}"] = -8
    limitation_total = sum(value for key, value in factors.items()
                           if key.startswith("limitation:"))
    if limitation_total < -18:
        factors["cap:combined_limitations"] = -18 - limitation_total
    scope = finding.metadata.get("source_scope", "production")
    if scope in SCOPE_COST:
        factors[f"scope:{scope}"] = -SCOPE_COST[scope]

    raw = sum(factors.values())
    score = max(0, min(100, raw))
    if raw < 0:
        factors["floor:zero"] = -raw
    elif raw > 100:
        factors["cap:maximum"] = 100 - raw
    if evidence_level == "candidate_call_chain" and score < 10:
        factors["floor:reviewable_chain"] = 10 - score
        score = 10
    elif detection_level == "review_candidate" and score < 5:
        factors["floor:reviewable_site"] = 5 - score
        score = 5
    caps = []
    if detection_level == "review_candidate" or evidence_level == "candidate_call_chain":
        caps.append((29, "candidate_only"))
    if evidence_level in {"assumed_api_flow", "assumed_persistent_flow", "unresolved_flow"}:
        caps.append((49, "assumed_or_unresolved_flow"))
    if detection_level == "conditional_path":
        caps.append((79, "conditional_path"))
    if scope in SCOPE_COST:
        caps.append((59, "nonproduction_scope"))
    for cap, reason in caps:
        if score > cap:
            factors[f"cap:{reason}"] = cap - score
            score = cap

    band = ("URGENT" if score >= 80 else "HIGH" if score >= 60
            else "MEDIUM" if score >= 30 else "LOW")
    return ReviewPriority(score=score, band=band, factors=factors)
