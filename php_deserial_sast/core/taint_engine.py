"""Report deserialization dependencies from the project dataflow analysis."""

import hashlib
from php_deserial_sast.core.dataflow import FlowProject, PATH_ARGUMENTS, DESERIALIZATION_FUNCTIONS, arguments, expression, FieldKind
from php_deserial_sast.core.parser import get_node_location
from php_deserial_sast.core.framework_dispatch import LARAVEL_DEFAULT_SERIALIZATION_NOTE
from php_deserial_sast.models import Finding, VulnerabilityType, Severity, Confidence, SinkInventoryEntry, FlowEvidence

PHAR_RUNTIME_NOTE = (
    "Automatic Phar metadata deserialization on filesystem access applies before PHP 8.0. "
    "PHP 8.0+ no longer does this on archive opening; explicit getMetadata() calls require separate analysis."
)

FLOW_EVIDENCE_LIMIT = 32


def representative_routes(routes):
    """Bound presentation only; detection still considers all input routes."""
    selected, remaining, groups = [], [], set()
    for route in routes:
        group = (route.flow.kind, route.flow.uncertain, route.review_conditions, route.path_assumptions)
        if group not in groups:
            groups.add(group)
            selected.append(route)
        else:
            remaining.append(route)
    return (selected + remaining)[:FLOW_EVIDENCE_LIMIT]


def route_records(routes):
    """Identify caller/source/guard combinations without relying on trace order."""
    records = {}
    for route in routes:
        binding = next((step for step in reversed(route.flow.steps)
                        if step.description.startswith("Argument bound to ")), None)
        location = binding.location if binding else route.flow.steps[0].location if route.flow.steps else route.location
        identity = (route.flow.kind, route.flow.origin, route.flow.index,
                    route.flow.fields, route.flow.uncertain, route.review_conditions,
                    route.path_assumptions, location.file_path,
                    location.start_line, location.start_col)
        route_id = hashlib.sha256(repr(identity).encode()).hexdigest()[:16]
        records[route_id] = {
            "id": route_id, "source_kind": route.flow.kind,
            "source_origin": route.flow.origin,
            "source_parameter": route.flow.index,
            "source_fields": ["<array-key>" if field is FieldKind.ARRAY_KEY else field
                              for field in route.flow.fields],
            "uncertain": route.flow.uncertain,
            "review_conditions": list(route.review_conditions),
            "path_assumptions": list(route.path_assumptions),
            "caller_file": location.file_path,
            "caller_line": location.start_line,
            "caller_column": location.start_col,
        }
    return records


def route_summary(records, limit=32):
    """Summarize all distinct route records, including undisplayed traces."""
    callers = {}
    totals = {"with_guard": 0, "without_guard": 0, "uncertain": 0,
              "request": 0, "framework_request": 0, "library_parameter": 0,
              "persistent_data": 0}
    for route in records.values():
        guarded = bool(route["review_conditions"])
        totals["with_guard" if guarded else "without_guard"] += 1
        totals["uncertain"] += bool(route["uncertain"])
        if route["source_kind"] in totals:
            totals[route["source_kind"]] += 1
        key = (route["caller_file"], route["caller_line"], route["caller_column"])
        row = callers.setdefault(key, {"file": key[0], "line": key[1], "column": key[2],
                                       "routes": 0, "with_guard": 0, "without_guard": 0,
                                       "uncertain": 0})
        row["routes"] += 1
        row["with_guard" if guarded else "without_guard"] += 1
        row["uncertain"] += bool(route["uncertain"])
    ranked = sorted(callers.values(), key=lambda row: (-row["routes"], row["file"], row["line"], row["column"]))
    return totals, ranked[:limit], len(ranked) > limit


class TaintEngine:
    def __init__(self, file_path, source_bytes, root_node, symbol_table=None,
                 library_mode=False, project=None, php_version=None):
        self.file_path = file_path
        self.project = project or FlowProject(
            {file_path: (root_node, source_bytes)}, symbol_table, library_mode,
            php_version=php_version
        )
        self.owns_project = project is None
        self.php_version = php_version
        self.checked_sites = set()
        self.sink_inventory = []
        self.object_excluded_routes = {}

    def collect_function_summaries(self):
        self.project.build()

    def analyze(self):
        if self.owns_project and not self.project.returns:
            self.project.build()
        engine = self.project.files[self.file_path]
        candidates = []
        implicit_phar = self.php_version is None or tuple(map(int, self.php_version.split('.')[:2])) < (8, 0)
        wddx_available = self.php_version is None or tuple(map(int, self.php_version.split('.')[:2])) < (7, 4)
        checked_call_names = PATH_ARGUMENTS.keys() | DESERIALIZATION_FUNCTIONS
        for scope, nodes in engine.nodes.items():
            candidates.extend(engine.direct_sinks(scope, False))
            candidates.extend(engine.forwarded_sinks(scope, False))
            for node in nodes:
                if node.type == "function_call_expression" and engine.call_name(node) in checked_call_names:
                    self.checked_sites.add((self.file_path, node.start_point[0] + 1, node.start_point[1] + 1))
        if not wddx_available:
            candidates = [sink for sink in candidates if sink.name != "wddx_deserialize"]
        self.sink_inventory = self._build_sink_inventory(engine, candidates, implicit_phar)
        groups = {}
        for sink in candidates:
            if sink.name not in DESERIALIZATION_FUNCTIONS and not sink.phar_possible:
                continue
            if sink.name not in DESERIALIZATION_FUNCTIONS and not implicit_phar:
                continue
            key = (sink.location.file_path, sink.location.start_line, sink.location.start_col, sink.argument, sink.name)
            groups.setdefault(key, []).append(sink)
        findings = []
        for key, routes in groups.items():
            excluded = [sink for sink in routes if sink.object_payload_excluded]
            if excluded:
                self.object_excluded_routes[key] = route_records(excluded)
            excluded_count = len(excluded)
            routes = [sink for sink in routes if not sink.object_payload_excluded]
            if not routes:
                continue
            routes.sort(key=lambda s: ({"request": 0, "framework_request": 1,
                                       "persistent_data": 2, "library_parameter": 3}.get(s.flow.kind, 4),
                                       bool(s.path_assumptions), bool(s.review_conditions), s.flow.uncertain, len(s.flow.steps)))
            records = route_records(routes)
            route_totals, route_callers, callers_truncated = route_summary(records)
            sink, flow = routes[0], routes[0].flow
            assumed = flow.kind == "library_parameter"
            modeled = flow.kind == "framework_request"
            persistent = flow.kind == "persistent_data"
            phar = sink.name not in DESERIALIZATION_FUNCTIONS
            guarded = bool(sink.review_conditions)
            if assumed:
                kind = VulnerabilityType.LIBRARY_API_EXPOSURE
                severity, confidence = Severity.MEDIUM, Confidence.LOW
                title = f"Conditional API exposure to {sink.name}()"
                description = (
                    "A public API parameter can reach this sink under the library-mode assumption. "
                    "No request-controlled caller is established by this finding. "
                    "Known constant callers do not make the public API itself private or unreachable. "
                )
            elif persistent:
                kind = VulnerabilityType.PHAR_DESERIALIZATION if phar else VulnerabilityType.DIRECT_UNSERIALIZE
                severity, confidence = Severity.MEDIUM, Confidence.LOW
                title = f"Conditional persisted-data flow to {sink.name}()"
                description = ("Data read from a persistent store reaches this sink. "
                               "An attacker-controlled write to the same record and runtime trigger are not established. ")
            else:
                kind = VulnerabilityType.PHAR_DESERIALIZATION if phar else VulnerabilityType.DIRECT_UNSERIALIZE
                severity = Severity.HIGH if phar or modeled or flow.uncertain else Severity.CRITICAL
                confidence = Confidence.LOW if flow.uncertain else Confidence.MEDIUM if modeled else Confidence.HIGH
                title = f"Potential {'Phar metadata ' if phar else ''}deserialization via {sink.name}()"
                description = ("Data from a modeled framework request API reaches the sink; verify how that request is created. "
                               if modeled else "Request-derived data reaches the sink. ")
                if flow.uncertain:
                    description += "Part of the return-value propagation is unresolved and needs review. "
            if guarded:
                description += "Relevant branch or early-return predicates require manual validation; this trace does not establish that object payloads pass these checks. "
            if sink.path_assumptions:
                severity, confidence = Severity.MEDIUM, Confidence.LOW
                description += "Project constant definitions give a local path prefix; a Phar route would require a different runtime constant configuration. Verify bootstrap order and external overrides. "
            default_disabled = bool(routes) and all(
                LARAVEL_DEFAULT_SERIALIZATION_NOTE in route.review_conditions for route in routes)
            if default_disabled:
                severity, confidence = Severity.MEDIUM, Confidence.LOW
                description += "The scanned middleware disables cookie deserialization by default; a runtime override remains possible. "
            if phar:
                description += PHAR_RUNTIME_NOTE
            else:
                description += "Object injection additionally requires object reconstruction and available gadget classes."
            if sink.name == "wddx_deserialize" and self.php_version is None:
                severity, confidence = Severity.MEDIUM, Confidence.LOW
                description += " WDDX was removed in PHP 7.4; the target PHP version and extension availability are unknown."
            digest = hashlib.sha256(repr(key).encode()).hexdigest()[:12]
            trace = []
            for step in flow.steps:
                if not trace or step != trace[-1]:
                    trace.append(step)
            findings.append(Finding(
                id=f"FLOW-{digest}",
                rule_id="php-library-api-exposure" if assumed else "php-phar-insecure-deserialization" if phar else "php-igbinary-unserialize-tainted-input" if sink.name == "igbinary_unserialize" else "php-wddx-deserialize-tainted-input" if sink.name == "wddx_deserialize" else "php-unserialize-tainted-input",
                vuln_type=kind, title=title, description=description,
                severity=severity, confidence=confidence,
                location=sink.location, code_snippet=sink.code, dataflow_trace=trace,
                flow_evidence=[FlowEvidence(
                    source_kind=route.flow.kind, source_origin=route.flow.origin,
                    source_parameter=route.flow.index,
                    source_fields=['<array-key>' if f is FieldKind.ARRAY_KEY else f for f in route.flow.fields],
                    uncertain=route.flow.uncertain,
                    guard_status="unrecognized_guard" if route.review_conditions else "no_guard",
                    review_conditions=list(route.review_conditions),
                    path_assumptions=list(route.path_assumptions), trace=list(route.flow.steps),
                ) for route in representative_routes(routes)],
                remediation=(
                    "Verify the API caller and allow only intended local paths. Reject phar:// explicitly when accepting untrusted paths. "
                    "stream_is_local() and phar.readonly do not establish that Phar metadata is safe."
                    if phar else f"Avoid {sink.name}() on untrusted data; use a data-only format such as JSON."
                ),
                metadata={
                    "engine": "taint", "source_assumption": "library_public_api_parameter" if assumed else "persistent_store_read_unverified" if persistent else "modeled_framework_request" if modeled else "observed_request",
                    "analysis_kind": "source_to_sink_candidate",
                    "methodology_reference": "S5135" if not phar else None,
                    "analysis_status": "default_serialization_disabled_review" if default_disabled else "configured_local_path_review" if sink.path_assumptions else "conditional_api_exposure" if assumed else "conditional_persistent_data_flow" if persistent else "conditional_runtime_sink" if sink.name == "wddx_deserialize" and self.php_version is None else "guarded_flow_review" if guarded else "unresolved_return_flow" if flow.uncertain else "modeled_source_to_sink" if modeled else "source_to_sink",
                    "path_prefix_assumptions": list(sink.path_assumptions),
                    "review_conditions": list(sink.review_conditions),
                    "framework_dispatch_assumptions": list(dict.fromkeys(step.description for route in routes for step in route.flow.steps if step.description.startswith("Framework dispatch model:"))),
                    "runtime_configuration_verified": False,
                    "exploitability_verified": False,
                    "sink_type": "PHAR_DESERIALIZATION" if phar else "DIRECT_UNSERIALIZE",
                    "sink_argument": sink.argument, "sink_name": sink.name,
                    "target_php_version": self.php_version or "unknown",
                    "automatic_phar_metadata_requires": "PHP < 8.0" if phar else None,
                    "alternative_flow_count": len(routes), "summary_converged": self.project.converged,
                    "object_excluded_route_count": excluded_count,
                    "distinct_route_count": len(records),
                    "route_records": records,
                    "route_totals": route_totals,
                    "route_callers": route_callers,
                    "route_callers_truncated": callers_truncated,
                    "flow_evidence_limit": FLOW_EVIDENCE_LIMIT,
                    "flow_evidence_truncated": len(routes) > FLOW_EVIDENCE_LIMIT,
                    "prerequisites": (["An application caller passes attacker-controlled input."] if assumed else []) +
                                     (["An attacker can write the same persisted record before this read and the code path is triggered."] if persistent else []) +
                                     (["A reachable Phar archive and a PHP runtime with automatic metadata deserialization."] if phar else []) +
                                     (["The igbinary extension must be installed at runtime."] if sink.name == "igbinary_unserialize" else []) +
                                     (["PHP must be older than 7.4 and the WDDX extension available."] if sink.name == "wddx_deserialize" else []) +
                                     ["Applicable object classes/gadgets must be loaded; exploitability is not established by taint alone."],
                },
            ))
        return findings

    def _build_sink_inventory(self, engine, candidates, implicit_phar):
        """Account for each deserialization-related sink and its observed source status."""
        routes = {}
        for sink in candidates:
            key = (
                sink.location.file_path,
                sink.location.start_line,
                sink.location.start_col,
                sink.argument,
                sink.name,
            )
            routes.setdefault(key, []).append(sink.flow)

        entries = []
        for scope, nodes in engine.nodes.items():
            for node in nodes:
                if node.type != "function_call_expression":
                    continue
                name = engine.call_name(node)
                if name not in DESERIALIZATION_FUNCTIONS and name not in PATH_ARGUMENTS:
                    continue
                if (name == "wddx_deserialize" and self.php_version is not None
                        and tuple(map(int, self.php_version.split('.')[:2])) >= (7, 4)):
                    continue
                if self.project.resolve(engine, node):
                    continue
                location = get_node_location(node, self.file_path)
                arg_indexes = (0,) if name in DESERIALIZATION_FUNCTIONS else PATH_ARGUMENTS[name]
                for arg_index in arg_indexes:
                    arg = engine.builtin_argument(node, arg_index)
                    if arg is None:
                        continue
                    key = (self.file_path, location.start_line, location.start_col, arg_index, name)
                    flows = routes.get(key, ())
                    evidence = []
                    source_assumption = None
                    phar_prefix_excluded = (
                        name not in DESERIALIZATION_FUNCTIONS
                        and not engine.phar_path_may_resolve_to_wrapper(arg)
                    )
                    if not engine.reachable(node, scope):
                        disposition = "unreachable_in_scope_cfg"
                        note = "No control-flow path from this lexical scope entry reaches the call in the supported statement CFG."
                    elif phar_prefix_excluded:
                        if flows:
                            flow = min(flows, key=lambda item: (item.uncertain, len(item.steps)))
                            source_assumption = (
                                "observed_request" if flow.kind == "request"
                                else "library_public_api_parameter" if flow.kind == "library_parameter"
                                else flow.kind
                            )
                            evidence = flow.steps
                        disposition = "fixed_non_phar_path"
                        note = "A fixed path prefix is incompatible with the phar:// wrapper, even when the suffix is request-controlled."
                    elif flows:
                        flow = min(
                            flows,
                            key=lambda item: (
                                0 if item.kind == "request" else 1,
                                item.uncertain,
                                len(item.steps),
                            ),
                        )
                        source_assumption = (
                            "observed_request" if flow.kind == "request"
                            else "library_public_api_parameter" if flow.kind == "library_parameter"
                            else flow.kind
                        )
                        evidence = flow.steps
                        if flow.kind == "framework_request":
                            source_assumption = "modeled_framework_request"
                            disposition = "modeled_framework_request"
                            note = "A typed framework request API reaches the sink; verify its runtime origin."
                        elif flow.kind == "request":
                            disposition = "observed_request_unresolved" if flow.uncertain else "observed_request"
                            note = "Tracked request data reaches this sink; verify remaining runtime and exploitability prerequisites."
                        else:
                            disposition = "conditional_library_api"
                            note = "A public API parameter can reach this sink; an untrusted application caller is not established."
                    elif name == "unserialize" and engine.unserialize_safe(node):
                        disposition = "restricted_unserialize"
                        note = "allowed_classes is false, preventing PHP object reconstruction at this call."
                    elif name not in DESERIALIZATION_FUNCTIONS and not implicit_phar:
                        disposition = "php8_phar_implicit_deserialization_inactive"
                        note = "Implicit Phar metadata deserialization does not apply to the configured PHP 8.0+ runtime."
                    else:
                        prefix = engine.fixed_prefix(arg)
                        if name not in DESERIALIZATION_FUNCTIONS and prefix and prefix.lower().startswith("phar://"):
                            disposition = "fixed_phar_path"
                            note = "The path has a statically identified phar:// prefix; determine whether the archive is attacker-controlled."
                        elif name not in DESERIALIZATION_FUNCTIONS and prefix is not None:
                            disposition = "fixed_non_phar_path"
                            note = "The path prefix is statically fixed and does not identify a phar:// archive."
                        else:
                            disposition = "no_tracked_source"
                            note = "No supported untrusted source was traced to this sink in this scan."
                    entries.append(SinkInventoryEntry(
                        location=location,
                        sink_name=name,
                        sink_argument=arg_index,
                        disposition=disposition,
                        source_assumption=source_assumption,
                        evidence=evidence,
                        note=note,
                    ))
        return entries
