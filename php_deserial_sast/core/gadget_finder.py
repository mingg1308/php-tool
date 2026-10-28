"""
POP Gadget Chain Finder for PHP Insecure Deserialization.
Finds exploit paths from Magic Methods to Dangerous Sinks.
"""

from typing import Iterator, List, Set, Optional, Tuple
from collections import deque
import hashlib
import re
from php_deserial_sast.core.symbol_table import (
    ProjectSymbolTable,
    ClassSymbol,
    MethodSymbol,
    POP_ENTRY_MAGIC_METHODS,
)
from php_deserial_sast.core.call_graph import CallGraph, CallEdge
from php_deserial_sast.core.parser import get_code_snippet
from php_deserial_sast.models import (
    GadgetChain,
    GadgetStep,
    CodeLocation,
    Severity,
    Confidence,
    Finding,
    VulnerabilityType,
)


class GadgetFinder:
    """Discovers Property-Oriented Programming (POP) chains in the codebase."""

    def __init__(self, symbol_table: ProjectSymbolTable, call_graph: CallGraph, max_depth: int = 6, max_paths: int = 10000, max_expansions: int = 250000):
        self.symbol_table = symbol_table
        self.call_graph = call_graph
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.max_expansions = max_expansions
        self.paths_examined = 0
        self.expansions = 0
        self.limit_reached = False
        # Backward reachability excludes only nodes with no path to any sink.
        # This avoids spending the forward POP budget on irrelevant subgraphs.
        self._sink_distance = {node: 0 for node, data in call_graph.graph.nodes(data=True) if data.get("is_sink")}
        pending = deque(self._sink_distance)
        while pending:
            node = pending.popleft()
            for parent in call_graph.graph.predecessors(node):
                if parent not in self._sink_distance:
                    self._sink_distance[parent] = self._sink_distance[node] + 1
                    pending.append(parent)

    def find_all_gadget_chains(self) -> List[GadgetChain]:
        """Find all POP gadget chains starting from magic methods to dangerous sinks."""
        chains: List[GadgetChain] = []
        unique_classes = self.symbol_table.get_all_unique_classes()
        def entry_priority(cls):
            distances = [self._sink_distance.get(f"{owner.full_name or owner.name}::{name}", float("inf"))
                         for owner in self.symbol_table.resolve_inheritance(cls.full_name or cls.name)
                         for name in owner.get_pop_entry_methods()]
            # Spend bounded search on shortest known routes to sinks, without
            # a library-specific preference for method names such as close().
            return (min(distances, default=float("inf")), cls.full_name or cls.name)
        unique_classes.sort(key=entry_priority)

        for cls in unique_classes:
            if cls.is_abstract:
                continue
            # Serialized instances execute lifecycle methods inherited from
            # their parent classes too. Select the nearest implementation for
            # each allowed POP entry and start graph traversal at its owner.
            entry_methods = {}
            for owner in self.symbol_table.resolve_inheritance(cls.full_name or cls.name):
                for method_name, method_sym in owner.get_pop_entry_methods().items():
                    entry_methods.setdefault(method_name, (owner, method_sym))
            for method_name, (owner, method_sym) in entry_methods.items():
                owner_key = owner.full_name or owner.name
                start_node = f"{owner_key}::{method_name}"
                for path in self._search_paths_to_sinks(
                    start_node, depth=0, visited=set(), entry_receiver_class=cls
                ):
                    chain = self._build_gadget_chain(cls, method_sym, path)
                    if chain:
                        chains.append(chain)
                if self.limit_reached:
                    break
            if self.limit_reached:
                break

        # Deduplicate chains by signature
        return self._deduplicate_chains(chains)

    def _search_paths_to_sinks(
        self,
        current_node: str,
        depth: int,
        visited: Set[str],
        entry_receiver_class: Optional[ClassSymbol] = None,
    ) -> Iterator[List[Tuple[str, CallEdge]]]:
        """Yield sink paths lazily so large call graphs do not materialize every path."""
        if depth > self.max_depth:
            return []
        if self._sink_distance.get(current_node, float("inf")) > self.max_depth - depth + 1:
            return

        visited = visited | {current_node}

        successors = self.call_graph.get_successors(current_node)
        if entry_receiver_class is not None:
            # Calls on $this retain their runtime receiver after entering an
            # inherited method. A sibling override cannot run on that object.
            constrained = []
            for succ_node, edge in successors:
                call = edge.call_info
                if call.target_object == "$this":
                    expected = self.call_graph._method_owner(
                        entry_receiver_class, call.callee_name
                    )
                    if expected:
                        owner, method = expected
                        if (
                            edge.callee_class != (owner.full_name or owner.name)
                            or edge.callee_method != method.name
                        ):
                            continue
                constrained.append((succ_node, edge))
            successors = constrained

        for succ_node, edge in successors:
            if succ_node not in self._sink_distance:
                continue
            if self.limit_reached:
                return
            if self.expansions >= self.max_expansions:
                self.limit_reached = True
                return
            self.expansions += 1
            if succ_node.startswith("SINK::"):
                if self.paths_examined >= self.max_paths:
                    self.limit_reached = True
                    return
                self.paths_examined += 1
                yield [(succ_node, edge)]
            else:
                next_receiver = entry_receiver_class
                if edge.edge_type in {
                    "SERIALIZED_PROPERTY_DISPATCH", "DYNAMIC_DISPATCH",
                    "MAGIC_CALL", "MAGIC_TOSTRING", "MAGIC_GET", "MAGIC_INVOKE",
                }:
                    next_receiver = (self.symbol_table.get_class(edge.callee_class)
                                     if edge.callee_class else None)
                if succ_node in visited:
                    continue
                for sub_path in self._search_paths_to_sinks(
                    succ_node, depth + 1, visited, next_receiver
                ):
                    yield [(succ_node, edge)] + sub_path
                    if self.limit_reached:
                        return
                if self.limit_reached:
                    return

    def _build_gadget_chain(
        self,
        entry_cls: ClassSymbol,
        entry_method: MethodSymbol,
        path: List[Tuple[str, CallEdge]]
    ) -> Optional[GadgetChain]:
        """Convert path of edges into a structured GadgetChain model."""
        if not path:
            return None

        steps: List[GadgetStep] = []
        step_num = 1

        # Step 1: Entry Magic Method
        entry_loc = entry_method.location or CodeLocation(
            file_path=entry_cls.file_path,
            start_line=1,
            start_col=1,
            end_line=1,
            end_col=1
        )
        
        entry_step = GadgetStep(
            step_number=step_num,
            class_name=entry_cls.name,
            method_name=entry_method.name,
            step_type="ENTRY_MAGIC_METHOD",
            location=entry_loc,
            code_snippet=entry_method.body_text[:200] if entry_method.body_text else f"function {entry_method.name}()",
            description=f"Candidate magic-method entry `{entry_cls.name}::{entry_method.name}()`. A deserialization source and property control have not been established.",
            controllable_properties=[]
        )
        steps.append(entry_step)

        # Intermediate and Sink Steps
        sink_edge = path[-1][1]
        sink_fn = sink_edge.callee_method
        sink_category = sink_edge.call_info.sink_category or "RCE"
        candidate_properties = {
            edge.call_info.callback_property_source
            for _, edge in path if edge.call_info.callback_property_source
        }
        for _, edge in path:
            owner = self.symbol_table.get_class(edge.caller_class)
            if not owner:
                continue
            expressions = (edge.call_info.target_object or "", *edge.call_info.arguments)
            for expression_text in expressions:
                for property_name in re.findall(r'\$this->([A-Za-z_]\w*)', expression_text):
                    if property_name in owner.properties:
                        candidate_properties.add(property_name)
        candidate_properties = sorted(candidate_properties)
        sink_cls_name = path[-1][1].caller_class
        sink_method_name = path[-1][1].caller_method

        for i, (node_key, edge) in enumerate(path):
            step_num += 1
            is_last = (i == len(path) - 1)
            
            loc = edge.call_info.location or entry_loc
            snippet = ", ".join(edge.call_info.arguments) if edge.call_info.arguments else edge.edge_type

            if is_last:
                step_type = "SINK_CALL"
                desc = (
                    f"Execution reaches dangerous sink `{sink_fn}({', '.join(edge.call_info.arguments)})` "
                    f"in `{edge.caller_class}::{edge.caller_method}()` ({sink_category})."
                )
            else:
                step_type = edge.edge_type
                desc = (
                    f"From `{edge.caller_class}::{edge.caller_method}()`, invokes "
                    f"`{edge.callee_class}::{edge.callee_method}()` via {edge.edge_type.lower()}."
                )

            step = GadgetStep(
                step_number=step_num,
                class_name=edge.caller_class,
                method_name=edge.caller_method,
                step_type=step_type,
                target_class=edge.callee_class,
                target_method=edge.callee_method,
                location=loc,
                code_snippet=snippet,
                description=desc,
                controllable_properties=[]
            )
            steps.append(step)

        # Calculate severity and confidence
        # A call-graph path is only a hypothesis. It does not prove that
        # unserialized properties control the sink arguments or that the
        # runtime can reach this method, so do not assign vulnerability-level
        # severity here.
        severity = Severity.LOW
        minimum_edge_confidence = min(edge.confidence for _, edge in path)
        confidence = (
            Confidence.HIGH if minimum_edge_confidence >= 0.9
            else Confidence.MEDIUM if minimum_edge_confidence >= 0.7
            else Confidence.LOW
        )

        explanation = (
            f"Candidate call-graph path starting at `{entry_cls.name}::{entry_method.name}()` "
            f"traversing through {len(steps)-2} intermediate step(s) "
            f"and reaching dangerous sink `{sink_fn}()` in `{sink_cls_name}::{sink_method_name}()`. "
            "Confidence describes call resolution, not exploitability. Serialized property control, path constraints and a reachable deserialization entry need separate verification."
        )
        if candidate_properties:
            explanation += " Candidate serialized property references: " + ", ".join(candidate_properties) + "."

        blueprint = self._generate_payload_blueprint(steps)

        signature = "|".join(
            [entry_cls.full_name or entry_cls.name, entry_method.name]
            + [
                f"{edge.caller_class}::{edge.caller_method}>{node_key}:{edge.edge_type}:{edge.call_info.location}"
                for node_key, edge in path
            ]
        )
        return GadgetChain(
            chain_id=hashlib.sha256(signature.encode("utf-8")).hexdigest()[:12],
            entry_class=entry_cls.full_name or entry_cls.name,
            entry_method=entry_method.name,
            sink_class=sink_cls_name,
            sink_method=sink_method_name,
            sink_function=sink_fn,
            sink_type=sink_category,
            steps=steps,
            candidate_serialized_properties=candidate_properties,
            length=len(steps),
            confidence=confidence,
            severity=severity,
            explanation=explanation,
            payload_blueprint=blueprint
        )

    def _generate_payload_blueprint(self, steps: List[GadgetStep]) -> str:
        """Generate structured ASCII blueprint of the object graph needed for exploit."""
        lines = ["Gadget Object Structure:"]
        for s in steps:
            if s.step_type == "ENTRY_MAGIC_METHOD":
                lines.append(f"  [1] {s.class_name} (Entry: {s.method_name})")
            elif s.step_type == "SINK_CALL":
                lines.append(f"  └──> [{s.step_number}] {s.class_name}::{s.method_name} ===> SINK: {s.code_snippet}")
            else:
                lines.append(f"  └──> [{s.step_number}] {s.target_class}::{s.target_method} ({s.step_type})")
        return "\n".join(lines)

    def _deduplicate_chains(self, chains: List[GadgetChain]) -> List[GadgetChain]:
        """Keep bounded, distinct routes to each sink site.

        A sink function alone is too coarse: different handler methods and
        receiver paths may have very different payload requirements.
        """
        best = {}
        for c in chains:
            key = (
                c.entry_class,
                c.entry_method,
                c.sink_class,
                c.sink_method,
                c.sink_function,
            )
            routes = best.setdefault(key, {})
            signature = tuple((s.class_name, s.method_name, s.step_type,
                               s.target_class, s.target_method) for s in c.steps)
            current = routes.get(signature)
            if current is None or self._chain_quality(c) > self._chain_quality(current):
                routes[signature] = c
        retained = []
        for routes in best.values():
            retained.extend(sorted(routes.values(), key=self._chain_quality, reverse=True)[:2])
        return sorted(retained, key=self._chain_quality, reverse=True)

    def _chain_quality(self, chain: GadgetChain):
        """Prioritize concrete execution evidence over broad dispatch guesses."""
        speculative_edges = sum(
            step.step_type in ("SERIALIZED_PROPERTY_DISPATCH", "VIRTUAL_OVERRIDE")
            for step in chain.steps
        )
        return (
            {"RCE": 6, "DYNAMIC_INVOCATION": 5, "FILE_WRITE": 4,
             "FILE_DELETE": 3, "FILE_READ_INCLUDE": 2}.get(chain.sink_type, 1),
            bool(chain.candidate_serialized_properties),
            {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[chain.confidence.value],
            -speculative_edges,
            chain.sink_type == "RCE",
            -chain.length,
        )

    def convert_to_findings(self, chains: List[GadgetChain]) -> List[Finding]:
        """Convert gadget chains into SAST Finding objects."""
        findings = []
        for chain in chains:
            f = Finding(
                id=f"POP-{chain.chain_id}",
                rule_id="php-pop-gadget-chain",
                vuln_type=VulnerabilityType.POP_GADGET_CHAIN,
                title=f"Candidate POP chain: {chain.entry_class}::{chain.entry_method} -> {chain.sink_function}()",
                description=chain.explanation,
                severity=chain.severity,
                confidence=chain.confidence,
                location=chain.steps[0].location,
                code_snippet=chain.steps[0].code_snippet,
                gadget_chain=chain,
                cwe=None,
                owasp=None,
                remediation=(
                    "Verify that PHP invokes this method during or after object restoration, trace the relevant "
                    "properties from an untrusted serialized value, and confirm that the sink arguments are controllable."
                ),
                metadata={"analysis_status": "candidate_call_chain", "confidence_basis": "call_graph_reachability", "exploitability_verified": False},
            )
            findings.append(f)
        return findings
