"""
POP Gadget Chain Finder for PHP Insecure Deserialization.
Finds exploit paths from Magic Methods to Dangerous Sinks.
"""

from typing import List, Set, Optional, Tuple
import uuid
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

    def __init__(self, symbol_table: ProjectSymbolTable, call_graph: CallGraph, max_depth: int = 6):
        self.symbol_table = symbol_table
        self.call_graph = call_graph
        self.max_depth = max_depth

    def find_all_gadget_chains(self) -> List[GadgetChain]:
        """Find all POP gadget chains starting from magic methods to dangerous sinks."""
        chains: List[GadgetChain] = []
        unique_classes = self.symbol_table.get_all_unique_classes()

        for cls in unique_classes:
            entry_methods = cls.get_pop_entry_methods()
            for method_name, method_sym in entry_methods.items():
                start_node = f"{cls.name}::{method_name}"
                found_paths = self._search_paths_to_sinks(start_node, depth=0, visited=set())
                for path in found_paths:
                    chain = self._build_gadget_chain(cls, method_sym, path)
                    if chain:
                        chains.append(chain)

        # Deduplicate chains by signature
        return self._deduplicate_chains(chains)

    def _search_paths_to_sinks(
        self,
        current_node: str,
        depth: int,
        visited: Set[str]
    ) -> List[List[Tuple[str, CallEdge]]]:
        """Recursive DFS to find paths from current_node to SINK::* nodes."""
        if depth > self.max_depth:
            return []

        paths = []
        visited = visited | {current_node}

        for succ_node, edge in self.call_graph.get_successors(current_node):
            if succ_node.startswith("SINK::"):
                paths.append([(succ_node, edge)])
            elif succ_node not in visited:
                sub_paths = self._search_paths_to_sinks(succ_node, depth + 1, visited)
                for sp in sub_paths:
                    paths.append([(succ_node, edge)] + sp)

        return paths

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
            description=f"Entry point triggered upon deserialization/destruction via magic method `{entry_cls.name}::{entry_method.name}()`.",
            controllable_properties=list(entry_cls.properties.keys())
        )
        steps.append(entry_step)

        # Intermediate and Sink Steps
        sink_edge = path[-1][1]
        sink_fn = sink_edge.callee_method
        sink_category = sink_edge.call_info.sink_category or "RCE"
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
        severity = Severity.CRITICAL if sink_category in ("RCE", "DYNAMIC_INVOCATION", "FILE_WRITE") else Severity.HIGH
        confidence = Confidence.HIGH if len(steps) <= 3 else (Confidence.MEDIUM if len(steps) <= 5 else Confidence.LOW)

        explanation = (
            f"POP Gadget Chain found starting at `{entry_cls.name}::{entry_method.name}()` "
            f"traversing through {len(steps)-2} intermediate step(s) "
            f"and reaching dangerous sink `{sink_fn}()` in `{sink_cls_name}::{sink_method_name}()`."
        )

        blueprint = self._generate_payload_blueprint(steps)

        return GadgetChain(
            chain_id=str(uuid.uuid4())[:8],
            entry_class=entry_cls.name,
            entry_method=entry_method.name,
            sink_class=sink_cls_name,
            sink_method=sink_method_name,
            sink_function=sink_fn,
            sink_type=sink_category,
            steps=steps,
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
        """Deduplicate chains having identical entry, steps signature, and sink."""
        seen = set()
        unique = []
        for c in chains:
            sig = (c.entry_class, c.entry_method, c.sink_class, c.sink_method, c.sink_function, c.length)
            if sig not in seen:
                seen.add(sig)
                unique.append(c)
        return unique

    def convert_to_findings(self, chains: List[GadgetChain]) -> List[Finding]:
        """Convert gadget chains into SAST Finding objects."""
        findings = []
        for chain in chains:
            f = Finding(
                id=f"POP-{chain.chain_id}",
                rule_id="php-pop-gadget-chain",
                vuln_type=VulnerabilityType.POP_GADGET_CHAIN,
                title=f"POP Gadget Chain: {chain.entry_class}::{chain.entry_method} -> {chain.sink_function}()",
                description=chain.explanation,
                severity=chain.severity,
                confidence=chain.confidence,
                location=chain.steps[0].location,
                code_snippet=chain.steps[0].code_snippet,
                gadget_chain=chain,
                cwe="CWE-502: Deserialization of Untrusted Data",
                owasp="A08:2021-Software and Data Integrity Failures",
                remediation=(
                    "Refactor magic methods to avoid executing dynamic calls or filesystem operations "
                    "on unverified internal properties. Do not expose deserialization endpoints to untrusted input."
                )
            )
            findings.append(f)
        return findings
