"""
Inter-procedural and Dynamic Call Graph builder for PHP codebase.
"""

from typing import List, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict
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
        # Multiple call sites can connect the same pair of methods. A
        # MultiDiGraph preserves every edge instead of silently keeping only
        # the last one.
        self.graph = nx.MultiDiGraph()
        self.edges: List[CallEdge] = []
        self._classes_by_method = defaultdict(list)
        self._classes_by_namespace = defaultdict(list)
        self._descendants = defaultdict(list)
        self._implementers = defaultdict(list)
        self._owner_cache = {}
        self.dispatch_candidates_truncated = 0
        for cls in symbol_table.get_all_unique_classes():
            self._classes_by_namespace[cls.namespace].append(cls)
            hierarchy = symbol_table.resolve_inheritance(cls.full_name or cls.name)
            for parent in hierarchy[1:]:
                self._descendants[parent.full_name or parent.name].append(cls)
            for interface in {i for parent in hierarchy for i in parent.resolved_interfaces}:
                self._implementers[interface].append(cls)
        self.dynamic_calls_resolved = 0
        self.dynamic_calls_unresolved = 0
        self._build_graph()

    def _method_key(self, class_name: str, method_name: str) -> str:
        return f"{class_name}::{method_name}"

    def _method_owner(self, cls, method_name: str):
        """Find a method on a class, its parents, or its used traits."""
        key = (id(cls), method_name)
        if key in self._owner_cache:
            return self._owner_cache[key]
        for parent in self.symbol_table.resolve_inheritance(cls.full_name or cls.name):
            if method_name in parent.methods:
                self._owner_cache[key] = (parent, parent.methods[method_name])
                return self._owner_cache[key]
            for trait_name in parent.traits:
                trait = self.symbol_table.get_class(trait_name)
                if trait and method_name in trait.methods:
                    self._owner_cache[key] = (trait, trait.methods[method_name])
                    return self._owner_cache[key]
        self._owner_cache[key] = None
        return None

    def _classes_for_type(self, cls, type_name: str):
        """Resolve a declared receiver type; never guess from method-name coincidence."""
        type_name = (type_name or "").strip().lstrip("?").lstrip("\\")
        if not type_name or any(token in type_name for token in ("|", "&", "[", "callable")):
            return []
        resolved = self.symbol_table.resolve_class_name(
            type_name, cls.namespace, cls.file_path
        )
        declared = self.symbol_table.get_class(resolved)
        if declared:
            return [declared]

        # For interface/abstract declarations, use only classes that explicitly
        # declare the resolved interface or inherit from a known implementer.
        return self._implementers.get(resolved, [])

    def _receiver_type(self, cls, method_sym, target_object: str):
        """Infer receiver types only from declared parameter/property types."""
        target_object = (target_object or "").strip()
        if target_object.startswith("$this->"):
            prop_name = target_object[len("$this->"):].split("->", 1)[0].split("[", 1)[0]
            prop = cls.properties.get(prop_name)
            return prop.type_hint if prop else None
        return method_sym.parameter_types.get(target_object)

    def _add_typed_dispatch(self, caller_cls, caller_method, call):
        type_name = self._receiver_type(caller_cls, caller_cls.methods[caller_method], call.target_object)
        targets = self._classes_for_type(caller_cls, type_name) if type_name else []
        if not targets:
            self.dynamic_calls_unresolved += 1
            return

        edges_added = 0
        for target_cls in targets:
            owner = self._method_owner(target_cls, call.callee_name)
            edge_type = "DYNAMIC_DISPATCH"
            if owner is None:
                owner = self._method_owner(target_cls, "__call")
                edge_type = "MAGIC_CALL"
            if owner is None:
                continue
            owner_cls, owner_method = owner
            self._add_edge(
                caller_cls.full_name or caller_cls.name, caller_method,
                owner_cls.full_name or owner_cls.name, owner_method.name,
                edge_type, call, 0.9 if len(targets) == 1 else 0.7,
            )
            edges_added += 1
        if edges_added:
            self.dynamic_calls_resolved += 1
        else:
            self.dynamic_calls_unresolved += 1

    def _add_serialized_property_dispatch(self, caller_cls, caller_method, call):
        """Add low-confidence same-namespace targets for untyped object properties.

        PHP unserialization can replace an untyped object's property with another
        object, so declared constructor-time types are not a complete model of a
        POP chain. Restrict candidates to the caller namespace and preserve low
        edge confidence to keep this as gadget-review evidence.
        """
        if not (call.target_object or "").strip().startswith("$this->"):
            return 0

        targets = []
        for candidate in self._classes_by_namespace[caller_cls.namespace]:
            owner = self._method_owner(candidate, call.callee_name)
            if owner:
                targets.append(owner)

        # Several possible receiver classes can inherit the same implementation.
        unique_owners = {
            (owner_cls.full_name or owner_cls.name, method.name): (owner_cls, method)
            for owner_cls, method in targets
        }
        ranked_owners = sorted(
            unique_owners.values(),
            key=lambda pair: (
                not bool(pair[0].get_pop_entry_methods()),
                not any(call.is_sink for candidate_method in pair[0].methods.values()
                        for call in candidate_method.calls),
                pair[0].is_abstract,
                (pair[0].full_name or pair[0].name),
                pair[1].name,
            ),
        )
        # Preserve every indexed candidate. Search budgets are enforced by
        # the gadget finder and reported explicitly, not by deleting edges.
        for owner_cls, method in ranked_owners:
            self._add_edge(
                caller_cls.full_name or caller_cls.name, caller_method,
                owner_cls.full_name or owner_cls.name, method.name,
                "SERIALIZED_PROPERTY_DISPATCH", call, 0.4,
            )
        return len(unique_owners)

    def _add_virtual_overrides(self, caller_cls, caller_method, call, base_owner):
        """Model $this method overrides reachable on serialized subclasses."""
        base_cls, _ = base_owner
        base_name = base_cls.full_name or base_cls.name
        owners = {}
        for candidate in self._descendants.get(base_name, ()):
            owner = self._method_owner(candidate, call.callee_name)
            if not owner:
                continue
            owner_cls, method = owner
            owner_name = owner_cls.full_name or owner_cls.name
            if owner_name == base_name:
                continue
            owners[(owner_name, method.name)] = (owner_cls, method)

        def override_rank(pair):
            owner_cls, method = pair
            class_has_sink = any(
                call.is_sink
                for candidate_method in owner_cls.methods.values()
                for call in candidate_method.calls
            )
            return (
                not class_has_sink,
                not bool(method.property_accesses),
                owner_cls.full_name or owner_cls.name,
                method.name,
            )

        added = 0
        for owner_cls, method in sorted(owners.values(), key=override_rank):
            owner_name = owner_cls.full_name or owner_cls.name
            self._add_edge(
                caller_cls.full_name or caller_cls.name, caller_method,
                owner_name, method.name, "VIRTUAL_OVERRIDE", call, 0.55,
            )
            added += 1
        return added

    def _build_graph(self):
        """Construct graph nodes and edges from all classes and methods."""
        unique_classes = self.symbol_table.get_all_unique_classes()
        # Dynamic dispatch previously searched every class for every call
        # site. Build the reverse index once so graph construction scales with
        # the number of classes and call edges instead of their product.
        for cls in unique_classes:
            for method_name in cls.methods:
                self._classes_by_method[method_name].append(cls)

        # Add all methods as nodes
        for cls in unique_classes:
            class_key = cls.full_name or cls.name
            for method_name, method_sym in cls.methods.items():
                node_key = self._method_key(class_key, method_name)
                self.graph.add_node(
                    node_key,
                    class_name=class_key,
                    method_name=method_name,
                    method_sym=method_sym,
                    is_magic=method_sym.is_magic
                )

        # Build edges based on method calls and potential dynamic dispatches
        for cls in unique_classes:
            class_key = cls.full_name or cls.name
            for method_name, method_sym in cls.methods.items():
                caller_key = self._method_key(class_key, method_name)

                # 1. Direct and dynamic method calls
                for call in method_sym.calls:
                    if call.call_type == "METHOD_CALL":
                        callee_name = call.callee_name
                        target_obj = call.target_object or ""

                        # If internal call: $this->cleanUp()
                        if target_obj == "$this":
                            owner = self._method_owner(cls, callee_name)
                            edge_type = "DIRECT_METHOD_CALL"
                            if owner is None:
                                owner = self._method_owner(cls, "__call")
                                edge_type = "MAGIC_CALL"
                            if owner:
                                owner_cls, owner_method = owner
                                self._add_edge(class_key, method_name, owner_cls.full_name or owner_cls.name,
                                               owner_method.name, edge_type, call, 1.0 if edge_type == "DIRECT_METHOD_CALL" else 0.9)
                                if edge_type == "DIRECT_METHOD_CALL":
                                    self._add_virtual_overrides(
                                        cls, method_name, call, (owner_cls, owner_method)
                                    )
                            else:
                                # Abstract base methods often invoke an
                                # abstract method implemented only by children.
                                self._add_virtual_overrides(
                                    cls, method_name, call, (cls, None)
                                )
                        else:
                            before = self.dynamic_calls_unresolved
                            self._add_typed_dispatch(cls, method_name, call)
                            # With no declared receiver type, conservatively add
                            # same-namespace implementations: serialized object
                            # properties can replace their constructor-time type.
                            if self.dynamic_calls_unresolved > before:
                                self._add_serialized_property_dispatch(cls, method_name, call)

                    elif call.call_type == "FUNCTION_CALL" and call.is_sink:
                        # Sink call edge
                        sink_node_key = f"SINK::{call.callee_name}"
                        if not self.graph.has_node(sink_node_key):
                            self.graph.add_node(sink_node_key, is_sink=True, sink_name=call.callee_name, category=call.sink_category)
                        self._add_edge(class_key, method_name, None, call.callee_name, "SINK", call, 1.0)

                # 2. String conversion edges (kích hoạt __toString)
                if method_sym.string_conversions:
                    for expression in method_sym.string_conversions:
                        receiver_type = self._receiver_type(cls, method_sym, expression)
                        targets = self._classes_for_type(cls, receiver_type) if receiver_type else []
                        if not targets:
                            self.dynamic_calls_unresolved += 1
                        for target_cls in targets:
                            owner = self._method_owner(target_cls, "__toString")
                            if not owner:
                                continue
                            owner_cls, owner_method = owner
                            dummy_call = CallExpressionInfo(
                                call_type="METHOD_CALL",
                                callee_name="__toString",
                                target_object=expression,
                                arguments=[],
                                location=method_sym.location
                            )
                            self._add_edge(class_key, method_name, owner_cls.full_name or owner_cls.name,
                                           owner_method.name, "MAGIC_TOSTRING", dummy_call, 0.9 if len(targets) == 1 else 0.7)

                # 3. Property access edges (kích hoạt __get)
                if method_sym.property_accesses:
                    for property_name in method_sym.property_accesses:
                        prop = cls.properties.get(property_name)
                        targets = self._classes_for_type(cls, prop.type_hint) if prop and prop.type_hint else []
                        if not targets:
                            self.dynamic_calls_unresolved += 1
                        for target_cls in targets:
                            owner = self._method_owner(target_cls, "__get")
                            if not owner:
                                continue
                            owner_cls, owner_method = owner
                            dummy_call = CallExpressionInfo(
                                call_type="METHOD_CALL",
                                callee_name="__get",
                                target_object=f"$this->{property_name}",
                                arguments=[],
                                location=method_sym.location
                            )
                            self._add_edge(class_key, method_name, owner_cls.full_name or owner_cls.name,
                                           owner_method.name, "MAGIC_GET", dummy_call, 0.9 if len(targets) == 1 else 0.7)

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
        for _, succ, _, data in self.graph.out_edges(node_key, keys=True, data=True):
            edge_data = data.get("edge_data")
            if edge_data:
                successors.append((succ, edge_data))
        return successors
