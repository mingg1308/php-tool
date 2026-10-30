"""
Scanner Orchestrator integrating AST Parsing, Taint Analysis, Rule Engine, POP Gadget Finder, and LLM Verification.
"""

import os
import time
from collections import Counter
from typing import List, Dict, Set, Tuple, Optional, Any
from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.models import (
    ScanResult,
    ScanSummary,
    ScanError,
    Finding,
    GadgetChain,
    Severity,
    Confidence,
    VulnerabilityType,
)
from php_deserial_sast.core.parser import PHPParser, find_nodes_by_type, ASTIndex
from php_deserial_sast.core.symbol_table import ProjectSymbolTable
from php_deserial_sast.core.ast_visitor import ASTVisitor
from php_deserial_sast.core.call_graph import CallGraph
from php_deserial_sast.core.gadget_finder import GadgetFinder
from php_deserial_sast.core.taint_engine import TaintEngine, FLOW_EVIDENCE_LIMIT, route_summary
from php_deserial_sast.core.dataflow import FlowProject, SideEffectBudgetExceeded, arguments, expression
from php_deserial_sast.core.evidence import assess_finding, compact_flow_evidence
from php_deserial_sast.core.route_evidence import build_route_evidence
from php_deserial_sast.core.control_flow import coverage as cfg_coverage
from php_deserial_sast.core.finding_coverage import FindingCoverage
from php_deserial_sast.core.pop_evidence import annotate_pop_candidates
from php_deserial_sast.core.deserialized_dispatch import annotate_session_dispatch
from php_deserial_sast.core.persistent_store import annotate_persistent_store_writes
from php_deserial_sast.core.finding_scope import source_scope
from php_deserial_sast.core.phar_metadata_rules import explicit_phar_metadata_reviews
from php_deserial_sast.core.spl_deserialization_rules import explicit_spl_deserialization_reviews
from php_deserial_sast.core.serializable_callback_rules import serializable_callback_reviews
from php_deserial_sast.core.package_context import package_context, annotate_advisories
from php_deserial_sast.rules.engine import RuleEngine
from php_deserial_sast.llm.verifier import LLMVerifier


PHP_EXTENSIONS = {
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".inc",
    ".phtml", ".module", ".install", ".theme", ".profile", ".engine",
    ".ctp", ".tpl", ".class.php",
}


class PHPDeserializationScanner:
    """Main SAST Scanner orchestrator for PHP Insecure Deserialization."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.package_context = package_context(config.target_path)
        if self.config.library_mode is None:
            self.config.library_mode = self.package_context['library_auto_detected']
        self.parser = PHPParser()
        self.symbol_table = ProjectSymbolTable()
        self.rule_engine = RuleEngine(self.config.rules_dir) if self.config.enable_rules else None
        self.llm_verifier: Optional[LLMVerifier] = None
        self._discovery_errors: List[ScanError] = []

        if self.config.enable_llm:
            self.llm_verifier = LLMVerifier(
                provider=self.config.llm_provider,
                model=self.config.llm_model,
                api_key=self.config.llm_api_key,
                symbol_table=self.symbol_table
            )

    def scan(self) -> ScanResult:
        """Run the complete multi-phase static analysis scan."""
        start_time = time.time()
        # A scanner instance may be reused. Reset project state so symbols and
        # taint summaries from a previous target cannot leak into this scan.
        self.symbol_table = ProjectSymbolTable()
        if self.llm_verifier:
            self.llm_verifier.slicer.symbol_table = self.symbol_table
        self._discovery_errors = []
        php_files = sorted(self._collect_php_files(self.config.target_path))
        
        parsed_files: Dict[str, Tuple[Any, bytes]] = {}
        node_indexes = {}
        streamed_findings = []
        sink_inventory = []
        streamed_files = 0
        scanned_files = 0
        scanned_bytes = 0
        largest_file_bytes = 0
        indexed_nodes = 0
        phase_times = {}
        phase_start = time.perf_counter()
        total_lines = 0
        errors: List[ScanError] = list(self._discovery_errors)
        if self.rule_engine:
            errors.extend(
                ScanError(file_path=path, phase="rule_load", message=message)
                for path, message in self.rule_engine.load_errors
            )

        # Phase 1: Parse all files and populate Symbol Table
        for file_path in php_files:
            try:
                if self.config.max_file_bytes and os.path.getsize(file_path) > self.config.max_file_bytes:
                    errors.append(ScanError(file_path=file_path, phase="resource_limit", message=f"File exceeds configured limit of {self.config.max_file_bytes} bytes; file was not scanned."))
                    continue
                root_node, source_bytes = self.parser.parse_file(file_path)
                if root_node.has_error:
                    parse_errors = list(find_nodes_by_type(root_node, "ERROR"))
                    first_error = next(
                        (node for node in parse_errors if node.start_byte != root_node.start_byte),
                        parse_errors[0] if parse_errors else root_node,
                    )
                    errors.append(ScanError(
                        file_path=file_path,
                        phase="parse",
                        message=(
                            f"Tree-sitter recovered from {len(parse_errors)} syntax error node(s); "
                            f"analysis may be incomplete near line {first_error.start_point[0] + 1}."
                        ),
                    ))
                try:
                    node_index = ASTIndex(root_node, self.config.max_ast_nodes)
                except ValueError as exc:
                    errors.append(ScanError(file_path=file_path, phase="resource_limit", message=str(exc)))
                    continue
                indexed_nodes += node_index.node_count
                visitor = ASTVisitor(self.symbol_table, file_path, source_bytes)
                visitor.extract_all(root_node, node_index)
                scanned_files += 1
                scanned_bytes += len(source_bytes)
                largest_file_bytes = max(largest_file_bytes, len(source_bytes))
                total_lines += len(source_bytes.splitlines())
                session_render_candidate = (b"$_SESSION" in source_bytes
                                            and bool(node_index.by_type.get("foreach_statement"))
                                            and bool(node_index.by_type.get("echo_statement")))
                if not node_index.needs_project_analysis and not session_render_candidate:
                    # No declarations/calls: evaluate custom rules now, then
                    # release large data-table trees before parsing the next file.
                    if self.rule_engine:
                        try:
                            streamed_findings.extend(self._filter_contextual_rule_findings(
                                self.rule_engine.evaluate_file(file_path, source_bytes, root_node, node_index)
                            ))
                        except Exception as exc:
                            errors.append(ScanError(file_path=file_path, phase="rules", message=str(exc)))
                    streamed_files += 1
                else:
                    parsed_files[file_path] = (root_node, source_bytes)
                    node_indexes[file_path] = node_index
                del visitor, node_index, root_node, source_bytes
            except Exception as e:
                errors.append(ScanError(file_path=file_path, phase="parse", message=str(e)))

        phase_times["parse_index_symbols_and_data_rules"] = time.perf_counter() - phase_start
        phase_start = time.perf_counter()

        # Phase 2: Build Call Graph & Collect Inter-procedural Taint Summaries
        call_graph = CallGraph(self.symbol_table) if self.config.enable_gadgets else None
        finder = None
        if call_graph and call_graph.dispatch_candidates_truncated:
            errors.append(ScanError(file_path=self.config.target_path, phase="call_graph_limit",
                                    message=f"Dynamic dispatch candidate caps omitted {call_graph.dispatch_candidates_truncated} candidate edges; POP coverage is incomplete."))

        flow_project = None
        side_effect_fallback = False
        side_effect_attempted_evaluations = 0
        side_effect_attempted_effect_demands = 0
        side_effect_attempted_bindings = 0
        if self.config.enable_taint:
            try:
                flow_options = dict(
                    experimental_foreach_cfg=self.config.experimental_foreach_cfg,
                    experimental_demand_summaries=self.config.experimental_demand_summaries,
                    framework_models=self.config.framework_models,
                    php_version=self.config.php_version,
                )
                flow_project = FlowProject(
                    parsed_files, self.symbol_table, self.config.library_mode,
                    experimental_side_effects=self.config.experimental_side_effects,
                    max_side_effect_seconds=self.config.max_side_effect_seconds,
                    max_side_effect_bindings=self.config.max_side_effect_bindings,
                    **flow_options,
                )
                try:
                    flow_project.build()
                except SideEffectBudgetExceeded as exc:
                    side_effect_fallback = True
                    side_effect_attempted_evaluations = flow_project.summary_evaluations
                    side_effect_attempted_effect_demands = len(flow_project.effect_demands)
                    side_effect_attempted_bindings = flow_project.effect_bindings
                    errors.append(ScanError(file_path=self.config.target_path, phase="side_effect_budget",
                                            message=f"{exc}; rescanned taint without experimental side effects. Reference/global/property effect coverage is incomplete."))
                    flow_project = FlowProject(
                        parsed_files, self.symbol_table, self.config.library_mode,
                        experimental_side_effects=False, **flow_options,
                    )
                    flow_project.build()
                if not flow_project.converged:
                    errors.append(ScanError(file_path=self.config.target_path, phase="taint_summary", message="Interprocedural summaries reached their iteration limit; coverage may be incomplete."))
            except Exception as e:
                errors.append(ScanError(file_path=self.config.target_path, phase="taint_summary", message=str(e)))

        phase_times["graph_and_summaries"] = time.perf_counter() - phase_start
        phase_start = time.perf_counter()
        all_findings: List[Finding] = streamed_findings

        if self.config.enable_rules:
            all_findings.extend(serializable_callback_reviews(self.symbol_table))
        gadget_chains: List[GadgetChain] = []

        # Phase 3.1: POP Gadget Chain Analysis
        if self.config.enable_gadgets:
            finder = GadgetFinder(self.symbol_table, call_graph, max_depth=self.config.max_chain_depth,
                                  max_paths=self.config.max_gadget_paths,
                                  max_expansions=self.config.max_gadget_expansions)
            gadget_chains = finder.find_all_gadget_chains()
            gadget_findings = finder.convert_to_findings(gadget_chains)
            all_findings.extend(gadget_findings)
            if finder.limit_reached:
                errors.append(ScanError(file_path=self.config.target_path, phase="gadget_limit", message=f"Gadget analysis budget reached after examining {finder.paths_examined} sink paths and {finder.expansions} graph edges; analysis is incomplete. Increase --max-gadget-paths/--max-gadget-expansions or disable gadget analysis explicitly."))

        # Phase 3.2: Taint Analysis & Rule Matching across all files
        object_excluded_routes = {}
        for file_path, (root_node, source_bytes) in parsed_files.items():
            checked_sites = set()
            if flow_project and self.config.enable_rules:
                all_findings.extend(explicit_phar_metadata_reviews(
                    flow_project.files[file_path], self.config.php_version))
                all_findings.extend(explicit_spl_deserialization_reviews(
                    flow_project.files[file_path]))
            # Taint Engine
            if self.config.enable_taint:
                try:
                    taint_engine = TaintEngine(
                        file_path,
                        source_bytes,
                        root_node,
                        self.symbol_table,
                        library_mode=self.config.library_mode,
                        project=flow_project,
                        php_version=self.config.php_version,
                    )
                    all_findings.extend(taint_engine.analyze())
                    for sink_key, records in taint_engine.object_excluded_routes.items():
                        object_excluded_routes.setdefault(sink_key, {}).update(records)
                    sink_inventory.extend(taint_engine.sink_inventory)
                    checked_sites = taint_engine.checked_sites
                except Exception as e:
                    errors.append(ScanError(file_path=file_path, phase="taint", message=str(e)))

            # Rule Engine
            if self.rule_engine:
                try:
                    syntactic = self.rule_engine.evaluate_file(
                        file_path, source_bytes, root_node, node_indexes[file_path],
                        flow_project.files[file_path] if flow_project else None)
                    builtin_flow_rules = {"php-phar-filesystem-deserialization", "php-insecure-unserialize-direct", "php-unserialize-without-allowed-classes", "php-unserialize-cookie-session"}
                    syntactic = self._filter_contextual_rule_findings(syntactic)
                    shadowed_igbinary_sites = set()
                    shadowed_extra_builtin_sites = set()
                    yaml_disabled_sites = set()
                    if flow_project and any(f.rule_id == "php-igbinary-unserialize-review"
                                            or f.rule_id.startswith(("php-wddx-deserialize-", "php-yaml-parse-"))
                                            for f in syntactic):
                        engine = flow_project.files[file_path]
                        for nodes in engine.nodes.values():
                            for call in nodes:
                                if call.type != "function_call_expression":
                                    continue
                                name = engine.call_name(call)
                                if name not in {"igbinary_unserialize", "wddx_deserialize",
                                                "yaml_parse", "yaml_parse_file", "yaml_parse_url"}:
                                    continue
                                if flow_project.resolve(engine, call):
                                    site = (call.start_point[0] + 1, call.start_point[1] + 1)
                                    if name == "igbinary_unserialize":
                                        shadowed_igbinary_sites.add(site)
                                    else:
                                        shadowed_extra_builtin_sites.add(site)
                    if (flow_project and any(f.rule_id == "php-yaml-parse-direct-request-review"
                                             for f in syntactic)):
                        engine = flow_project.files[file_path]
                        settings, yaml_calls = [], []
                        for scope, nodes in engine.nodes.items():
                            for call in nodes:
                                if call.type != "function_call_expression":
                                    continue
                                name = engine.call_name(call)
                                if name in {"yaml_parse", "yaml_parse_file", "yaml_parse_url"}:
                                    yaml_calls.append((scope, call))
                                elif name == "ini_set" and not flow_project.resolve(engine, call):
                                    args = arguments(call)
                                    if len(args) < 2:
                                        continue
                                    key = engine.text(expression(args[0])).strip("'\"").lower()
                                    if key == "yaml.decode_php":
                                        value = engine.text(expression(args[1])).strip("'\"").lower()
                                        settings.append((scope, call, value))
                        for scope, call in yaml_calls:
                            disabled = [setting for setting_scope, setting, value in settings
                                        if setting_scope == scope and value in {"0", "false", "off"}
                                        and setting.start_byte < call.start_byte
                                        and engine.dominates(setting, call)]
                            if not disabled:
                                continue
                            last_disable = max(disabled, key=lambda setting: setting.start_byte)
                            if not any(setting_scope == scope
                                       and last_disable.start_byte < setting.start_byte < call.start_byte
                                       for setting_scope, setting, _ in settings):
                                yaml_disabled_sites.add((call.start_point[0] + 1,
                                                         call.start_point[1] + 1))
                    all_findings.extend(f for f in syntactic if not (
                        f.rule_id in builtin_flow_rules and (file_path, f.location.start_line, f.location.start_col) in checked_sites
                    ) and not (
                        f.rule_id == "php-igbinary-unserialize-review"
                        and (f.location.start_line, f.location.start_col) in shadowed_igbinary_sites
                    ) and not (
                        f.rule_id.startswith(("php-wddx-deserialize-", "php-yaml-parse-"))
                        and (f.location.start_line, f.location.start_col) in shadowed_extra_builtin_sites
                    ) and not (
                        f.rule_id == "php-yaml-parse-direct-request-review"
                        and (f.location.start_line, f.location.start_col) in yaml_disabled_sites
                    ))
                except Exception as e:
                    errors.append(ScanError(file_path=file_path, phase="rules", message=str(e)))

        phase_times["findings"] = time.perf_counter() - phase_start
        phase_start = time.perf_counter()
        # Phase 4: Deduplicate and Filter
        # A caller in another file can establish a route to this lexical sink.
        # Reconcile after all files, independently of the severity filter.
        indexed_routes = {}
        for finding in all_findings:
            if finding.metadata.get("engine") != "taint":
                continue
            loc = finding.location
            key = (loc.file_path, loc.start_line, loc.start_col,
                   finding.metadata.get("sink_argument"), finding.metadata.get("sink_name"))
            indexed_routes.setdefault(key, finding)
        for entry in sink_inventory:
            loc = entry.location
            key = (loc.file_path, loc.start_line, loc.start_col, entry.sink_argument, entry.sink_name)
            finding = indexed_routes.get(key)
            if finding is not None and entry.disposition == "no_tracked_source":
                entry.disposition = "interprocedural_source_to_sink_review"
                entry.source_assumption = finding.metadata.get("source_assumption")
                entry.evidence = finding.dataflow_trace
                entry.note = "A caller in the project reaches this sink; inspect the finding's assumptions and validation conditions."
        unique_findings = self._deduplicate_findings(all_findings)
        for finding in unique_findings:
            if finding.metadata.get("engine") != "taint":
                continue
            loc = finding.location
            sink_key = (loc.file_path, loc.start_line, loc.start_col,
                        finding.metadata.get("sink_argument"), finding.metadata.get("sink_name"))
            records = object_excluded_routes.get(sink_key, {})
            if records:
                _, callers, truncated = route_summary(records)
                finding.metadata["object_excluded_route_count"] = len(records)
                finding.metadata["object_excluded_callers"] = callers
                finding.metadata["object_excluded_callers_truncated"] = truncated
        filtered_findings = [
            f for f in unique_findings
            if f.severity.rank >= self.config.min_severity.rank
        ]

        # Phase 5: LLM Verification (if enabled)
        if self.llm_verifier and filtered_findings:
            for finding in filtered_findings:
                # Verify CRITICAL and HIGH findings
                if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                    verdict = self.llm_verifier.verify_finding(finding)
                    if verdict:
                        finding.llm_verification = verdict
                    elif self.llm_verifier.last_error:
                        errors.append(ScanError(
                            file_path=finding.location.file_path,
                            phase="llm",
                            message=self.llm_verifier.last_error,
                        ))

        if flow_project:
            for path, engine in flow_project.files.items():
                if engine.loop_limit_reached:
                    errors.append(ScanError(file_path=path, phase="loop_fixed_point",
                                            message="Loop taint evaluation reached its iteration limit; results may be incomplete."))
        control_flow = cfg_coverage(flow_project)
        annotate_pop_candidates(filtered_findings, flow_project)
        annotate_session_dispatch(filtered_findings, flow_project, call_graph)
        annotate_persistent_store_writes(filtered_findings, flow_project)
        annotate_advisories(filtered_findings, self.package_context)
        finding_coverage = FindingCoverage(flow_project)
        for finding in filtered_findings:
            finding.metadata['source_scope'] = source_scope(self.config.target_path, finding.location.file_path)
            finding_coverage.annotate(finding)
            if flow_project and flow_project.summary_evidence_truncated:
                finding.metadata["summary_evidence_truncated"] = True
            assess_finding(finding, errors)

        routes = build_route_evidence(filtered_findings)
        phase_times["postprocess_and_evidence"] = time.perf_counter() - phase_start

        # Phase 6: Build Summary & Result
        duration = time.time() - start_time
        summary = self._create_summary(
            total_files=scanned_files,
            discovered_files=len(php_files),
            files_with_errors=len({error.file_path for error in errors}),
            total_lines=total_lines,
            findings=filtered_findings,
            chains_count=len(gadget_chains),
            duration=duration
        )

        all_class_names = [cls.full_name or cls.name for cls in self.symbol_table.get_all_unique_classes()]
        sink_inventory.sort(key=lambda item: (
            os.path.normcase(os.path.normpath(item.location.file_path)),
            item.location.start_line,
            item.location.start_col,
            item.sink_argument,
        ))
        sink_dispositions = Counter(item.disposition for item in sink_inventory)
        route_kinds = Counter(route.route_kind for route in routes)
        route_statuses = Counter(route.status for route in routes)
        excluded_sites = [
            {"file": key[0], "line": key[1], "column": key[2],
             "sink_argument": key[3], "sink_name": key[4],
             "distinct_routes": len(records)}
            for key, records in object_excluded_routes.items()
        ]
        excluded_sites.sort(key=lambda row: (row["file"], row["line"], row["column"]))
        scope_counts = Counter(f.metadata['source_scope'] for f in filtered_findings)

        return ScanResult(
            analysis={"library_mode": self.config.library_mode,
                      "package_context": self.package_context,
                      "finding_scope_counts": dict(sorted(scope_counts.items())),
                      "object_payload_exclusion": {
                          "distinct_routes": sum(len(records) for records in object_excluded_routes.values()),
                          "sites": excluded_sites[:32],
                          "sites_truncated": len(excluded_sites) > 32,
                      },
                      "framework_dispatch": flow_project.framework_dispatch.statistics() if flow_project else {"enabled": False}, "target_php_version": self.config.php_version or "unknown",
                      "sink_inventory": {"enabled": self.config.enable_taint,
                                         "total_sinks": len(sink_inventory),
                                         "by_disposition": dict(sorted(sink_dispositions.items()))},
                      "route_evidence": {
                          "retained_routes": len(routes),
                          "by_kind": dict(sorted(route_kinds.items())),
                          "by_status": dict(sorted(route_statuses.items())),
                          "findings_with_displayed_flows_truncated": sum(
                              bool(f.metadata.get("flow_evidence_truncated"))
                              for f in filtered_findings),
                          "runtime_verified": False,
                      },
                      "performance": {"scanned_bytes": scanned_bytes, "largest_file_bytes": largest_file_bytes,
                                      "indexed_ast_nodes": indexed_nodes, "streamed_data_files": streamed_files,
                                      "retained_project_files": len(parsed_files), "phase_seconds": phase_times},
                      "discovery": {"excluded_directories": sorted(self.config.exclude_dirs),
                                    "php_extensions": sorted(PHP_EXTENSIONS),
                                    "directory_errors": sum(error.phase == "discovery" for error in errors)},
                      "limits": {"max_file_bytes": self.config.max_file_bytes, "max_ast_nodes": self.config.max_ast_nodes, "max_gadget_paths": self.config.max_gadget_paths, "max_gadget_expansions": self.config.max_gadget_expansions,
                                 "max_side_effect_seconds": self.config.max_side_effect_seconds,
                                 "max_side_effect_bindings": self.config.max_side_effect_bindings},
                      "taint_enabled": self.config.enable_taint, "rules_enabled": self.config.enable_rules,
                      "gadgets_enabled": self.config.enable_gadgets, "gadget_paths_examined": getattr(finder, "paths_examined", 0),
                      "gadget_expansions": getattr(finder, "expansions", 0),
                      "gadget_limit_reached": getattr(finder, "limit_reached", False),
                      "call_graph": {"typed_dynamic_calls_resolved": getattr(call_graph, "dynamic_calls_resolved", 0),
                                     "typed_dynamic_calls_unresolved": getattr(call_graph, "dynamic_calls_unresolved", 0),
                                     "dispatch_candidates_truncated": getattr(call_graph, "dispatch_candidates_truncated", 0)},
                      "llm_enabled": self.config.enable_llm,
                      "dataflow": "use-site definitions with separate array fields; statement CFG pruning for supported scopes",
                      "interprocedural_side_effects": {"enabled": bool(flow_project and flow_project.experimental_side_effects),
                          "requested": self.config.experimental_side_effects,
                          "status": "budget_fallback" if side_effect_fallback else "experimental" if self.config.experimental_side_effects else "disabled",
                          "attempted_summary_evaluations": side_effect_attempted_evaluations if side_effect_fallback else None,
                          "attempted_effect_demands": side_effect_attempted_effect_demands if side_effect_fallback else None,
                          "attempted_bindings": side_effect_attempted_bindings if side_effect_fallback else getattr(flow_project, "effect_bindings", 0),
                          "models": ["reference_parameters", "literal_globals", "receiver_and_parameter_properties"] if flow_project and flow_project.experimental_side_effects else [],
                          "limitations": ["global_alias_and_heap_not_fully_modeled", "loop_carried_effects_incomplete"] if flow_project and flow_project.experimental_side_effects else ["reference_global_and_object_effects_not_modeled"]},
                      "control_flow": control_flow,
                      "field_depth_limit": 4, "field_paths_widened": getattr(flow_project, "field_paths_widened", False),
                      "summary_solver": "dependency_worklist",
                      "summary_guard_alternatives_limit": 16,
                      "summary_evidence_truncated": getattr(flow_project, "summary_evidence_truncated", False),
                      "summary_evaluations": getattr(flow_project, "summary_evaluations", 0),
                      "experimental_demand_summaries": self.config.experimental_demand_summaries,
                      "return_summary_mode": "demand" if self.config.experimental_demand_summaries else "eager",
                      "demanded_return_functions": len(getattr(flow_project, "return_demands", ())),
                      "demanded_effect_functions": len(getattr(flow_project, "effect_demands", ())),
                      "summary_rounds": getattr(flow_project, "rounds", 0), "summary_converged": getattr(flow_project, "converged", None)},
            target_path=self.config.target_path,
            summary=summary,
            findings=filtered_findings,
            sink_inventory=sink_inventory,
            routes=routes,
            gadget_chains=gadget_chains,
            all_classes=all_class_names,
            errors=errors
        )

    def _collect_php_files(self, target_path: str) -> List[str]:
        """Collect all PHP source files within target path."""
        if not os.path.exists(target_path):
            self._discovery_errors.append(ScanError(file_path=target_path, phase="discovery", message="Target path does not exist; no source was scanned."))
            return []
        if os.path.isfile(target_path):
            return [target_path] if self._is_php_file(target_path) else []

        php_files = []
        for root, dirs, files in os.walk(target_path, onerror=self._record_discovery_error):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in self.config.exclude_dirs]

            for file in files:
                if self._is_php_file(file):
                    full_path = os.path.normpath(os.path.join(root, file))
                    php_files.append(full_path)

        return php_files

    def _record_discovery_error(self, error: OSError) -> None:
        """Keep directory traversal failures visible as incomplete coverage."""
        failed_path = getattr(error, "filename", None) or self.config.target_path
        self._discovery_errors.append(ScanError(
            file_path=str(failed_path),
            phase="discovery",
            message=f"Could not enumerate this path: {error}",
        ))

    def _filter_contextual_rule_findings(self, findings: List[Finding]) -> List[Finding]:
        """Drop Phar path review hints that cannot apply to the declared input/runtime."""
        version = self.config.php_version
        php8_or_newer = False
        if version:
            parts = tuple(int(part) for part in version.split("."))
            php8_or_newer = parts >= (8, 0)

        filtered = []
        for finding in findings:
            if (finding.rule_id.startswith("php-wddx-deserialize-") and version
                    and tuple(int(part) for part in version.split(".")) >= (7, 4)):
                continue
            if finding.rule_id != "php-phar-path-api-review":
                filtered.append(finding)
                continue
            if php8_or_newer:
                # Filesystem access no longer implicitly deserializes Phar
                # metadata on PHP 8+; explicit metadata access is analyzed as
                # a separate sink.
                continue
            path = str(finding.metadata.get("bindings", {}).get("$PATH", "")).strip()
            if len(path) >= 2 and path[0] in "'\"" and path[-1] == path[0] and "phar://" not in path.lower():
                # Fixed literals such as php://temp or a fixture filename are
                # not attacker-selectable Phar wrapper paths.
                continue
            filtered.append(finding)
        return filtered

    def _is_php_file(self, filename: str) -> bool:
        lower = filename.lower()
        return any(lower.endswith(ext) for ext in PHP_EXTENSIONS)

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Deduplicate and correlate findings across Taint Engine, Rule Engine, and Gadget Finder:
        1. Taint Engine precedence: If Taint Engine detected an insecure deserialization or phar sink at (file, line),
           suppress lower-fidelity syntactic rule matches (e.g. php-insecure-unserialize-direct, php-unserialize-without-allowed-classes,
           php-phar-filesystem-deserialization) on the same line.
        2. POP Gadget Chain subsumption: If a POP Gadget Chain already covers Class::magicMethod -> sink,
           suppress simple pattern rules (php-magic-*-dangerous-sink) in that method.
        3. Multi-rule clustering: For multiple custom rules firing on the exact same token/location,
           keep only the most specific/highest severity finding.
        """
        # 1. Collect Taint Engine verified sink locations
        taint_deserial_lines: Set[Tuple[str, int]] = set()
        taint_phar_lines: Set[Tuple[str, int]] = set()
        for f in findings:
            norm_file = os.path.normpath(f.location.file_path)
            if f.vuln_type == VulnerabilityType.DIRECT_UNSERIALIZE:
                for ln in range(f.location.start_line, f.location.end_line + 1):
                    taint_deserial_lines.add((norm_file, ln))
            elif (f.vuln_type == VulnerabilityType.PHAR_DESERIALIZATION
                  or f.metadata.get("engine") == "taint"
                  and f.metadata.get("sink_type") == "PHAR_DESERIALIZATION"):
                for ln in range(f.location.start_line, f.location.end_line + 1):
                    taint_phar_lines.add((norm_file, ln))

        # 2. Collect POP Gadget Chain spans
        covered_magic_spans: Dict[str, List[Tuple[int, int]]] = {}
        unrestricted_unserialize_sites: Set[Tuple[str, int]] = set()
        direct_session_decode_sites: Set[Tuple[str, int, int]] = set()
        direct_wddx_sites: Set[Tuple[str, int, int]] = set()
        for f in findings:
            if f.rule_id == "php-unserialize-allows-all-classes":
                unrestricted_unserialize_sites.add((
                    os.path.normcase(os.path.normpath(f.location.file_path)),
                    f.location.start_line,
                ))
            if f.rule_id == "php-session-decode-direct-request-review":
                direct_session_decode_sites.add((
                    os.path.normcase(os.path.normpath(f.location.file_path)),
                    f.location.start_line, f.location.start_col,
                ))
            if f.rule_id == "php-wddx-deserialize-direct-request-review":
                direct_wddx_sites.add((
                    os.path.normcase(os.path.normpath(f.location.file_path)),
                    f.location.start_line, f.location.start_col,
                ))
            if f.vuln_type == VulnerabilityType.POP_GADGET_CHAIN and f.gadget_chain:
                first_step = f.gadget_chain.steps[0] if f.gadget_chain.steps else None
                if first_step:
                    norm_file = os.path.normpath(first_step.location.file_path)
                    covered_magic_spans.setdefault(norm_file, []).append((
                        first_step.location.start_line,
                        first_step.location.end_line,
                    ))

        # 3. Filter redundant findings based on cross-engine correlation
        correlated: List[Finding] = []
        for f in findings:
            norm_file = os.path.normpath(f.location.file_path)
            start_line = f.location.start_line

            if f.vuln_type == VulnerabilityType.CUSTOM_RULE_MATCH:
                rule_id = f.rule_id.lower()

                if (rule_id == "php-session-decode-review"
                        and (os.path.normcase(norm_file), start_line, f.location.start_col)
                        in direct_session_decode_sites):
                    continue
                if (rule_id == "php-wddx-deserialize-review"
                        and (os.path.normcase(norm_file), start_line, f.location.start_col)
                        in direct_wddx_sites):
                    continue

                # An explicit allowed_classes=true match is the more specific
                # finding; avoid retaining the generic review finding at the
                # same unserialize call.
                if (
                    rule_id == "php-unserialize-review"
                    and (os.path.normcase(norm_file), start_line) in unrestricted_unserialize_sites
                ):
                    continue

                # Check if covered by Taint Engine deserialization sink
                if any(k in rule_id for k in ("unserialize", "deserial")) and (norm_file, start_line) in taint_deserial_lines:
                    continue

                # Check if covered by Taint Engine Phar sink
                if "phar" in rule_id and (norm_file, start_line) in taint_phar_lines:
                    continue

                # Check if covered by a full POP Gadget Chain
                if any(m in rule_id for m in ("magic", "wakeup", "destruct", "tostring")):
                    is_subsumed = False
                    for span_start, span_end in covered_magic_spans.get(norm_file, ()):
                        if span_start <= start_line <= span_end + 3:
                            is_subsumed = True
                            break
                    if is_subsumed:
                        continue

            correlated.append(f)

        # 4. Deduplicate remaining findings by location and rule
        seen_keys = set()
        final_findings = []
        # Sort by severity rank descending so highest severity is kept if locations collide
        pop_sink_rank = {"RCE": 6, "DYNAMIC_INVOCATION": 5, "FILE_WRITE": 4,
                         "FILE_DELETE": 3, "FILE_READ_INCLUDE": 2}
        def pop_route_rank(finding):
            chain = finding.gadget_chain
            if not chain:
                return (0, 0, 0)
            speculative = sum(step.step_type in {"SERIALIZED_PROPERTY_DISPATCH", "VIRTUAL_OVERRIDE"}
                              for step in chain.steps)
            direct = sum(step.step_type == "DIRECT_METHOD_CALL" for step in chain.steps)
            return (-speculative, direct, -chain.length)

        correlated.sort(key=lambda x: (
            x.severity.rank,
            pop_sink_rank.get(x.gadget_chain.sink_type, 1) if x.gadget_chain else 0,
            bool(x.gadget_chain.candidate_serialized_properties) if x.gadget_chain else False,
            x.confidence.rank if hasattr(x.confidence, 'rank') else (1 if x.confidence == Confidence.HIGH else 0),
            pop_route_rank(x),
        ), reverse=True)

        retained_by_key = {}
        for f in correlated:
            pop = f.gadget_chain
            pop_endpoint = ((pop.entry_class, pop.entry_method, pop.sink_class,
                             pop.sink_method, pop.sink_function,
                             os.path.normcase(os.path.normpath(pop.steps[-1].location.file_path)),
                             pop.steps[-1].location.start_line, pop.steps[-1].location.start_col)
                            if pop else None)
            key = (os.path.normcase(os.path.normpath(f.location.file_path)),
                   f.location.start_line, f.location.start_col,
                   "taint" if f.metadata.get("engine") == "taint" else f.rule_id,
                   f.metadata.get("sink_name"), f.metadata.get("sink_argument"),
                   pop.sink_type if pop else None, pop_endpoint)
            if key not in seen_keys:
                seen_keys.add(key)
                final_findings.append(f)
                retained_by_key[key] = f
            elif f.vuln_type == VulnerabilityType.POP_GADGET_CHAIN and f.gadget_chain:
                retained = retained_by_key[key]
                alternatives = retained.metadata.setdefault("alternative_gadget_chain_ids", [])
                alternatives.append(f.gadget_chain.chain_id)
            elif f.flow_evidence:
                retained = retained_by_key[key]
                if f.metadata.get("engine") == "taint":
                    records = retained.metadata.setdefault("route_records", {})
                    records.update(f.metadata.get("route_records", {}))
                    totals, callers, truncated = route_summary(records)
                    retained.metadata["distinct_route_count"] = len(records)
                    retained.metadata["route_totals"] = totals
                    retained.metadata["route_callers"] = callers
                    retained.metadata["route_callers_truncated"] = truncated
                retained.flow_evidence, unique_count = compact_flow_evidence(
                    retained.flow_evidence + f.flow_evidence, FLOW_EVIDENCE_LIMIT)
                retained.metadata["flow_evidence_truncated"] = (
                    retained.metadata.get("flow_evidence_truncated", False)
                    or f.metadata.get("flow_evidence_truncated", False)
                    or unique_count > FLOW_EVIDENCE_LIMIT)
                retained.metadata["alternative_flow_count"] = max(
                    retained.metadata.get("alternative_flow_count", 0),
                    f.metadata.get("alternative_flow_count", 0), unique_count)
                retained.metadata["summary_converged"] = (
                    retained.metadata.get("summary_converged", True)
                    and f.metadata.get("summary_converged", True)
                )

        return sorted(
            final_findings,
            key=lambda f: (
                -f.severity.rank,
                os.path.normcase(os.path.normpath(f.location.file_path)),
                f.location.start_line,
                f.location.start_col,
                f.rule_id,
            ),
        )

    def _create_summary(
        self,
        total_files: int,
        discovered_files: int,
        files_with_errors: int,
        total_lines: int,
        findings: List[Finding],
        chains_count: int,
        duration: float
    ) -> ScanSummary:
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)
        info = sum(1 for f in findings if f.severity == Severity.INFO)

        classes = self.symbol_table.get_all_unique_classes()
        unique_classes = len(classes)
        total_methods = sum(len(c.methods) for c in classes)

        return ScanSummary(
            api_exposure_count=sum(f.vuln_type == VulnerabilityType.LIBRARY_API_EXPOSURE for f in findings),
            total_files_discovered=discovered_files,
            total_files_scanned=total_files,
            files_with_errors=files_with_errors,
            total_lines_scanned=total_lines,
            total_classes_found=unique_classes,
            total_methods_found=total_methods,
            total_findings=len(findings),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            info_count=info,
            gadget_chains_found=chains_count,
            scan_duration_seconds=duration
        )
