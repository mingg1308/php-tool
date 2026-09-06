"""
Inter-procedural and Dynamic Call Graph builder for PHP codebase.
"""

from typing import List, Tuple, Optional
from dataclasses import dataclass
import networkx as nx
from php_deserial_sast.core.symbol_table import (
    ProjectSymbolTable,
    CallExpressionInfo,
)


@dataclass
class CallEdge:
    caller_class: str
    caller_method: str
    callee_class: Optional[str]
    callee_method: str
    edge_type: str  # "DIRECT_METHOD_CALL", "DYNAMIC_DISPATCH", "MAGIC_TOSTRING", "MAGIC_CALL", "MAGIC_GET", "MAGIC_INVOKE", "SINK"
    call_info: CallExpressionInfo
    confidence: float = 1.0


class CallGraph:
    """Represents the project-wide call graph supporting dynamic PHP dispatch."""

    def __init__(self, symbol_table: ProjectSymbolTable):
        self.symbol_table = symbol_table
        self.graph = nx.DiGraph()
        self.edges: List[CallEdge] = []
        self._build_graph()

    def _method_key(self, class_name: str, method_name: str) -> str:
        return f"{class_name}::{method_name}"

    def _build_graph(self):
        """Construct graph nodes and edges from all classes and methods."""
        unique_classes = self.symbol_table.get_all_unique_classes()

        # Add all methods as nodes
        for cls in unique_classes:
            for method_name, method_sym in cls.methods.items():
                node_key = self._method_key(cls.name, method_name)
                self.graph.add_node(
                    node_key,
                    class_name=cls.name,
                    method_name=method_name,
                    method_sym=method_sym,
                    is_magic=method_sym.is_magic
                )

        # Build edges based on method calls and potential dynamic dispatches
        for cls in unique_classes:
            for method_name, method_sym in cls.methods.items():
                caller_key = self._method_key(cls.name, method_name)

                # 1. Direct and dynamic method calls
                for call in method_sym.calls:
                    if call.call_type == "METHOD_CALL":
                        callee_name = call.callee_name
                        target_obj = call.target_object or ""

                        # If internal call: $this->cleanUp()
                        if target_obj == "$this":
                            if callee_name in cls.methods:
                                callee_key = self._method_key(cls.name, callee_name)
                                self._add_edge(cls.name, method_name, cls.name, callee_name, "DIRECT_METHOD_CALL", call, 1.0)
                            elif "__call" in cls.methods:
                                self._add_edge(cls.name, method_name, cls.name, "__call", "MAGIC_CALL", call, 0.9)
                        else:
                            # Dynamic dispatch on property object e.g. $this->handler->close()
                            # Potential targets: any class with method callee_name or with __call
                            matching_classes = self.symbol_table.find_classes_with_method(callee_name)
                            for target_cls in matching_classes:
                                self._add_edge(cls.name, method_name, target_cls.name, callee_name, "DYNAMIC_DISPATCH", call, 0.8)

                            # Also classes with __call
                            classes_with_magic_call = self.symbol_table.find_classes_with_method("__call")
                            for target_cls in classes_with_magic_call:
                                if target_cls.name != cls.name:
                                    self._add_edge(cls.name, method_name, target_cls.name, "__call", "MAGIC_CALL", call, 0.7)

                    elif call.call_type == "FUNCTION_CALL" and call.is_sink:
                        # Sink call edge
                        sink_node_key = f"SINK::{call.callee_name}"
                        if not self.graph.has_node(sink_node_key):
                            self.graph.add_node(sink_node_key, is_sink=True, sink_name=call.callee_name, category=call.sink_category)
                        self._add_edge(cls.name, method_name, None, call.callee_name, "SINK", call, 1.0)

                # 2. String conversion edges (kích hoạt __toString)
                if method_sym.string_conversions:
                    classes_with_tostring = self.symbol_table.find_classes_with_method("__toString")
                    for target_cls in classes_with_tostring:
                        if target_cls.name != cls.name:
                            dummy_call = CallExpressionInfo(
                                call_type="METHOD_CALL",
                                callee_name="__toString",
                                target_object=method_sym.string_conversions[0],
                                arguments=[],
                                location=method_sym.location
                            )
                            self._add_edge(cls.name, method_name, target_cls.name, "__toString", "MAGIC_TOSTRING", dummy_call, 0.75)

                # 3. Property access edges (kích hoạt __get)
                if method_sym.property_accesses:
                    classes_with_get = self.symbol_table.find_classes_with_method("__get")
                    for target_cls in classes_with_get:
                        if target_cls.name != cls.name:
                            dummy_call = CallExpressionInfo(
                                call_type="METHOD_CALL",
                                callee_name="__get",
                                target_object="$this->property",
                                arguments=[],
                                location=method_sym.location
                            )
                            self._add_edge(cls.name, method_name, target_cls.name, "__get", "MAGIC_GET", dummy_call, 0.6)

    def _add_edge(self, caller_cls: str, caller_m: str, callee_cls: Optional[str], callee_m: str,
                  edge_type: str, call_info: CallExpressionInfo, confidence: float):
        caller_node = self._method_key(caller_cls, caller_m)
        if edge_type == "SINK":
            callee_node = f"SINK::{callee_m}"
        else:
            callee_node = self._method_key(callee_cls, callee_m) if callee_cls else callee_m

        edge = CallEdge(
            caller_class=caller_cls,
            caller_method=caller_m,
            callee_class=callee_cls,
            callee_method=callee_m,
            edge_type=edge_type,
            call_info=call_info,
            confidence=confidence
        )
        self.edges.append(edge)
        self.graph.add_edge(caller_node, callee_node, edge_data=edge)

    def get_successors(self, node_key: str) -> List[Tuple[str, CallEdge]]:
        """Get list of (target_node_key, edge) for a given caller node."""
        if not self.graph.has_node(node_key):
            return []
        successors = []
        for succ in self.graph.successors(node_key):
            edge_data = self.graph.get_edge_data(node_key, succ).get("edge_data")
            if edge_data:
                successors.append((succ, edge_data))
        return successors
