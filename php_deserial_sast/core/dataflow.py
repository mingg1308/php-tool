"""Use-site, field-sensitive PHP dependencies shared by taint and summaries.

Definitions are resolved before a use, within its lexical scope. Conditional
writes are merged conservatively; a write on a sibling branch cannot reach a
use. Unknown dynamic dispatch remains an explicit analysis limitation.
"""

from dataclasses import dataclass, replace
from collections import defaultdict, deque
from typing import Optional
import re
import time
from php_deserial_sast.core.bindings import FieldKind, foreach_bindings

from php_deserial_sast.core.parser import get_node_text, get_node_location, iter_child_nodes, find_nodes_by_type
from php_deserial_sast.models import TaintStep
from php_deserial_sast.core.ast_visitor import PHAR_TRIGGER_SINKS
from php_deserial_sast.core.source_models import is_framework_request_source, is_wpdb_persistent_read
from php_deserial_sast.core.guard_models import proves_serialized_string_only
from php_deserial_sast.core.control_flow import ScopeCFG
from php_deserial_sast.core.framework_dispatch import FrameworkDispatch
from php_deserial_sast.core.object_effects import actual_property, property_owner, property_effects, receiver_class

SCOPES = {"function_definition", "method_declaration", "anonymous_function", "anonymous_function_creation_expression", "arrow_function"}
CALLS = {"function_call_expression", "member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression"}


class SideEffectBudgetExceeded(RuntimeError):
    """The optional side-effect solver exceeded its wall-time budget."""
BRANCHES = {"if_statement", "else_clause", "else_if_clause", "while_statement", "for_statement", "foreach_statement", "do_statement", "case_statement", "default_statement", "catch_clause", "conditional_expression"}
REQUESTS = {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$HTTP_RAW_POST_DATA"}
TRUSTED_SERVER = {"DOCUMENT_ROOT", "SERVER_SOFTWARE", "SERVER_ADDR", "SERVER_PORT", "SCRIPT_FILENAME"}
SCALAR_FUNCTIONS = {"intval", "floatval", "boolval", "strlen", "count", "sizeof", "strcmp", "strcasecmp", "strpos", "stripos", "strrpos", "is_numeric", "ctype_digit", "file_exists", "is_file", "is_dir", "is_readable", "is_writable", "stream_is_local", "in_array", "array_key_exists", "defined"}
TRANSFORMS = {"base64_decode", "urldecode", "rawurldecode", "gzuncompress", "gzinflate", "gzdecode", "stripslashes", "trim", "rtrim", "ltrim", "substr", "str_replace", "preg_replace", "sprintf", "vsprintf", "strtolower", "strtoupper", "dirname", "basename", "file_get_contents"}
SCALAR_FUNCTIONS.update({"is_array", "is_bool", "is_callable", "is_float", "is_int", "is_integer", "is_null", "is_object", "is_resource", "is_scalar", "is_string"})
TRANSFORMS.update({"fread", "fgets", "stream_get_contents"})
PATH_ARGUMENTS = {name: (0,) for name in PHAR_TRIGGER_SINKS}
PATH_ARGUMENTS.update({"hash_file": (1,), "hash_hmac_file": (1,), "copy": (0, 1), "rename": (0, 1), "unlink": (0,), "readfile": (0,), "file": (0,)})
DESERIALIZATION_FUNCTIONS = {"unserialize", "igbinary_unserialize", "wddx_deserialize"}
FIELD_DEPTH_LIMIT = 4
SUMMARY_GUARD_LIMIT = 16


def bounded_fields(fields):
    # A wildcard in the last retained position also covers deeper descendants.
    # This finite domain prevents recursive summaries from growing paths forever.
    return fields if len(fields) <= FIELD_DEPTH_LIMIT else fields[:FIELD_DEPTH_LIMIT - 1] + (None,)


def summary_components(dependencies):
    """Return strongly connected components in callee-before-caller order.

    Iterative Kosaraju traversal avoids Python recursion limits on large call
    graphs. All keys and edges must refer to functions in this project.
    """
    seen, finished = set(), []
    reverse = {key: [] for key in dependencies}
    for caller, callees in dependencies.items():
        for callee in callees:
            reverse[callee].append(caller)
    for start in dependencies:
        if start in seen:
            continue
        seen.add(start)
        stack = [(start, iter(dependencies[start]))]
        while stack:
            node, children = stack[-1]
            child = next(children, None)
            if child is None:
                finished.append(node)
                stack.pop()
            elif child not in seen:
                seen.add(child)
                stack.append((child, iter(dependencies[child])))
    seen.clear()
    components = []
    for start in reversed(finished):
        if start in seen:
            continue
        seen.add(start)
        component, stack = [], [start]
        while stack:
            node = stack.pop()
            component.append(node)
            for caller in reverse[node]:
                if caller not in seen:
                    seen.add(caller)
                    stack.append(caller)
        components.append(component)
    return list(reversed(components))


def arguments(node):
    args = node.child_by_field_name("arguments")
    if args is None:
        return []
    # Named arguments are kept as wrappers so callers can bind by their names.
    return [child for child in args.named_children if child.type == "argument"]


def expression(argument):
    children = [c for c in argument.named_children if c.type != "name"]
    return children[-1] if children else argument


def literal(node, source):
    if node is None:
        return None
    text = get_node_text(node, source)
    if node.type in ("string", "encapsed_string") and not any(
        c.type not in ("string_content", "escape_sequence") for c in node.named_children
    ):
        return text[1:-1]
    if node.type == "integer":
        return text
    return None


@dataclass(frozen=True)
class Flow:
    kind: str
    origin: str
    index: int = -1
    fields: tuple = ()
    steps: tuple = ()
    blocked_phar: bool = False
    uncertain: bool = False

    def key(self):
        return self.kind, self.origin, self.index, self.fields, self.blocked_phar, self.uncertain


def merge(*groups):
    return tuple(accumulate_flows({}, *groups).values())


def accumulate_flows(result, *groups):
    """Merge into an existing map without rescanning all accumulated flows."""
    for group in groups:
        for flow in group:
            old = result.get(flow.key())
            if old is None or len(flow.steps) < len(old.steps):
                result[flow.key()] = flow
    return result


def trace_steps(steps):
    # Keep the origin even when recursive summaries grow beyond the trace cap.
    return steps if len(steps) <= 32 else steps[:1] + steps[-31:]


@dataclass
class Function:
    key: tuple
    name: str
    class_name: str
    namespace: str
    node: object
    params: tuple
    public: bool
    engine: object


@dataclass(frozen=True)
class Sink:
    name: str
    location: object
    code: str
    flow: Flow
    argument: int = 0
    phar_possible: bool = True
    review_conditions: tuple = ()
    path_assumptions: tuple = ()
    object_payload_excluded: bool = False

    def key(self):
        return self.name, self.location.file_path, self.location.start_line, self.location.start_col, self.argument, self.flow.key(), self.phar_possible, tuple(sorted(set(self.review_conditions))), self.path_assumptions, self.object_payload_excluded


def compact_sink_summaries(sinks, limit=SUMMARY_GUARD_LIMIT):
    """Bound descriptive guard alternatives, never distinct taint identities.

    Guard annotations do not block propagation. Source/fields/blocking flags,
    sink coordinates and path assumptions remain separate groups. Empty guard
    evidence sorts first, so a direct unguarded route cannot be displaced.
    """
    groups = {}
    for sink in sinks:
        key = sink.key()
        variants = groups.setdefault(key[:7] + key[8:], {})
        guards = key[7]
        previous = variants.get(guards)
        if previous is None or len(sink.flow.steps) < len(previous.flow.steps):
            variants[guards] = sink
    kept, truncated = [], False
    for variants in groups.values():
        truncated |= len(variants) > limit
        kept.extend(variants[guards] for guards in sorted(variants, key=lambda g: (len(g), g))[:limit])
    return tuple(kept), truncated


class FileFlow:
    def __init__(self, project, path, root, source):
        self.project, self.path, self.root, self.source = project, path, root, source
        self.scope = {}
        self.nodes = defaultdict(list)
        self._call_nodes = {}
        self.writes = defaultdict(list)
        self.iteration_fields = {}
        self.aliases = defaultdict(list)
        self.alias_flat = {}
        self.heap_events = {}
        self.heap_cache = {}
        self.finally_escapes = {}
        self.global_declarations = defaultdict(list)
        self.functions = {}
        self.cache = {}
        self.effect_index = {}
        self.loop_results = {}
        self.active = set()
        self.guards = []
        self.context_cache = {}
        self.location_cache = {}
        self.review_condition_cache = {}
        self._runtime_reachability_cache = {}
        self._has_php_version_guard = b"PHP_VERSION" in source and b"version_compare" in source.lower()
        self._shadowed_php_version = self._has_php_version_guard and bool(re.search(
            rb"\bconst\s+PHP_VERSION\b|\buse\s+const\b[^;]*\bPHP_VERSION\b|\bdefine\s*\([^;]*\bPHP_VERSION\b",
            source,
        ))
        self.namespaces = {}
        self.function_imports = {}
        self._index(root, -1, "", "")
        self._prepare_aliases()
        self.cfgs = {-1: ScopeCFG(root, project.experimental_foreach_cfg)}
        for scope, function in self.functions.items():
            body = function.node.child_by_field_name("body")
            if body is not None:
                self.cfgs[scope] = ScopeCFG(body, project.experimental_foreach_cfg)
        self.loop_solver_enabled = any(cfg.supported and cfg.has_loops for cfg in self.cfgs.values())
        self.loop_solving = False
        self.loop_previous = {}
        self.loop_iterations = 0
        self.loop_limit_reached = False

    def reachable(self, node, scope=None):
        cfg = self.cfgs.get(self.scope.get(node.id, -1) if scope is None else scope)
        return (cfg is None or cfg.is_reachable(node)) and self._runtime_branch_reachable(node)

    def _runtime_branch_reachable(self, node):
        """Prune only PHP_VERSION branches proved impossible for the target runtime."""
        if not self.project.php_version or not self._has_php_version_guard:
            return True
        cached = self._runtime_reachability_cache.get(node.id)
        if cached is not None:
            return cached
        child, parent = node, node.parent
        while parent is not None and parent.type not in SCOPES:
            if parent.type == "if_statement":
                outcome = self._php_version_condition(parent.child_by_field_name("condition"))
                if outcome is not None:
                    if child == parent.child_by_field_name("body") and not outcome:
                        self._runtime_reachability_cache[node.id] = False
                        return False
                    if child == parent.child_by_field_name("alternative") and outcome:
                        self._runtime_reachability_cache[node.id] = False
                        return False
            child, parent = parent, parent.parent
        self._runtime_reachability_cache[node.id] = True
        return True

    def _php_version_condition(self, node):
        if self._shadowed_php_version:
            return None
        while node is not None and node.type == "parenthesized_expression" and len(node.named_children) == 1:
            node = node.named_children[0]
        if node is None or node.type != "function_call_expression" or self.call_name(node) != "version_compare":
            return None
        if self.project.resolve(self, node):
            return None
        args = arguments(node)
        if len(args) != 3:
            return None
        left, right, operator = (expression(arg) for arg in args)
        if left is None or right is None or operator is None or self.text(left) != "PHP_VERSION":
            return None
        version = literal(right, self.source)
        comparison = literal(operator, self.source)
        if not isinstance(version, str) or not re.fullmatch(r"\d+(?:\.\d+){1,2}", version):
            return None
        if comparison not in {">=", ">", "<=", "<", "==", "=", "!="}:
            return None
        try:
            target = tuple(map(int, self.project.php_version.split(".")))
        except ValueError:
            return None
        expected = tuple(map(int, version.split(".")))
        size = max(len(target), len(expected))
        target += (0,) * (size - len(target))
        expected += (0,) * (size - len(expected))
        return {">=": target >= expected, ">": target > expected,
                "<=": target <= expected, "<": target < expected,
                "==": target == expected, "=": target == expected,
                "!=": target != expected}[comparison]

    def calls_in_scope(self, scope):
        calls = self._call_nodes.get(scope)
        if calls is None:
            calls = self._call_nodes[scope] = tuple(
                node for node in self.nodes[scope] if node.type in CALLS)
        return calls

    def return_value_escapes(self, node):
        """A guaranteed abrupt finally overrides the pending return value."""
        child, parent = node, node.parent
        while parent is not None and parent.type not in SCOPES:
            if parent.type == 'try_statement' and child.type != 'finally_clause':
                final = next((c for c in parent.named_children if c.type == 'finally_clause'), None)
                if final is not None:
                    if final.id not in self.finally_escapes:
                        cfg = ScopeCFG(final.child_by_field_name('body'), self.project.experimental_foreach_cfg)
                        self.finally_escapes[final.id] = not cfg.supported or bool(cfg.normal_exits & cfg.reachable)
                    if not self.finally_escapes[final.id]:
                        return False
            child, parent = parent, parent.parent
        return True

    def _prepare_aliases(self):
        if self.project.experimental_side_effects:
            # Allocation identity is modeled only in straight-line scopes.
            # Branch joins, references and interprocedural heap mutation still
            # require a separate may-alias model.
            by_scope = defaultdict(list)
            for (scope, _), writes in self.writes.items():
                by_scope[scope].extend((a, target) for a, target in writes
                                       if len(target) == 1 and re.fullmatch(r'\$\w+', target[0]))
            for scope in self.nodes:
                body = self.root if scope == -1 else self.functions[scope].node.child_by_field_name('body')
                if body is None:
                    continue
                events = by_scope[scope]
                if self.aliases.get(scope) or any(a.parent is None or a.parent.type != 'expression_statement'
                                                or a.parent.parent != body for a, _ in events):
                    continue
                if any(n.type in BRANCHES | {'try_statement', 'unset_statement', 'global_declaration'}
                       for n in find_nodes_by_type(body, BRANCHES | {'try_statement', 'unset_statement', 'global_declaration'})):
                    continue
                if any(a.child_by_field_name('right') is not None and a.child_by_field_name('right').type == 'object_creation_expression'
                       for a, _ in events):
                    self.heap_events[scope] = sorted(events, key=lambda event: event[0].start_byte)
        for scope, aliases in self.aliases.items():
            body = self.root if scope == -1 else self.functions[scope].node.child_by_field_name('body')
            flat = all(a.parent is not None and a.parent.type == 'expression_statement'
                       and a.parent.parent == body for a, left, right in aliases)
            flat &= not any(n.type in {'unset_statement', 'global_declaration'}
                            for n in find_nodes_by_type(body, {'unset_statement', 'global_declaration'}))
            self.alias_flat[scope] = flat
        remapped = defaultdict(list)
        for (scope, _), writes in self.writes.items():
            for assignment, target in writes:
                mapped = self._canonical_access(target, assignment, scope)
                remapped[(scope, mapped[0])].append((assignment, mapped))
                if assignment.id in self.iteration_fields and mapped != target:
                    self.iteration_fields[assignment.id][mapped] = self.iteration_fields[assignment.id][target]
        self.writes = remapped
        self.scope_writes = defaultdict(list)
        for (scope, _), writes in self.writes.items():
            writes.sort(key=lambda pair: pair[0].start_byte)
            self.scope_writes[scope].extend(writes)

    def _canonical_access(self, access, node, scope=None):
        scope = self.scope.get(node.id, -1) if scope is None else scope
        if access[0].startswith("@global:") and self.global_visible(access[0][8:], node):
            access = (access[0][8:],) + access[1:]
        access = self._heap_access(access, node, scope)
        if not self.alias_flat.get(scope):
            return access
        cells = {}
        for assignment, left, right in self.aliases[scope]:
            if assignment.start_byte >= node.start_byte:
                break
            cells[left] = cells.get(right, right)
        return (cells.get(access[0], access[0]),) + access[1:]

    def _heap_access(self, access, node, scope):
        property_access = re.fullmatch(r'(\$\w+)->([A-Za-z_]\w*)', access[0])
        if not property_access or scope not in self.heap_events:
            return access
        key = (scope, node.start_byte)
        if key not in self.heap_cache:
            objects = {}
            for assignment, target in self.heap_events[scope]:
                if assignment.end_byte > node.start_byte:
                    break
                right = assignment.child_by_field_name('right')
                identity = None
                if assignment.type == 'assignment_expression' and right is not None:
                    if right.type == 'object_creation_expression':
                        identity = f'@heap:{scope}:{assignment.start_byte}'
                    elif right.type == 'variable_name':
                        identity = objects.get(self.text(right))
                objects[target[0]] = identity
            self.heap_cache[key] = objects
        identity = self.heap_cache[key].get(property_access[1])
        return (identity + '->' + property_access[2],) + access[1:] if identity else access

    def _alias_accesses(self, access, node):
        scope = self.scope.get(node.id, -1)
        if access[0].startswith("@global:") and self.global_visible(access[0][8:], node):
            access = (access[0][8:],) + access[1:]
        heap_access = self._heap_access(access, node, scope)
        if heap_access != access:
            return [heap_access], True  # Magic-property/interprocedural behavior is not proven.
        if self.alias_flat.get(scope):
            return [self._canonical_access(access, node)], False
        related = {access[0]}
        edges = [(left, right) for assignment, left, right in self.aliases.get(scope, ())
                 if assignment.start_byte < node.start_byte]
        changed = True
        while changed:
            before = len(related)
            for left, right in edges:
                if left in related or right in related:
                    related.update((left, right))
            changed = len(related) != before
        return [(name,) + access[1:] for name in sorted(related)], len(related) > 1

    def text(self, node):
        return get_node_text(node, self.source)

    def step(self, node, description, variable=None):
        location = self.location_cache.get(node.id)
        if location is None:
            location = self.location_cache[node.id] = get_node_location(node, self.path)
        return TaintStep(location=location, code_snippet=self.text(node), description=description, variable_name=variable)

    def _index(self, node, scope, namespace, class_name):
        stack = [[iter((node,)), scope, namespace, class_name]]
        while stack:
            frame = stack[-1]
            child = next(frame[0], None)
            if child is None:
                stack.pop()
                continue
            if child.type == "namespace_definition" and child.child_by_field_name("body") is None:
                frame[2] = self.text(child.child_by_field_name("name"))
            state = self._index_node(child, *frame[1:])
            if state is not None:
                stack.append([iter_child_nodes(child, named=True), *state])

    def _index_node(self, node, scope, namespace, class_name):
        if node.type in ("integer", "float", "boolean", "null", "string", "comment", "name", "qualified_name"):
            return
        if node.type == "namespace_definition":
            namespace = self.text(node.child_by_field_name("name"))
        if node.type == "namespace_use_declaration" and re.match(r"use\s+function\b", self.text(node)):
            prefix = next((self.text(c) for c in node.named_children if c.type == "namespace_name"), "")
            for clause in find_nodes_by_type(node, "namespace_use_clause"):
                target = next((c for c in clause.named_children if c.type in ("name", "qualified_name")), None)
                if target is not None:
                    full = (prefix + "\\" + self.text(target)).strip("\\")
                    alias = self.text(clause.child_by_field_name("alias")) or full.split("\\")[-1]
                    self.function_imports[(namespace.lower(), alias.lower())] = full.lower()
        if node.type in ("class_declaration", "trait_declaration"):
            name = self.text(node.child_by_field_name("name"))
            class_name = (namespace + "\\" + name).strip("\\")
        if node.type in SCOPES:
            scope = node.start_byte
            params = node.child_by_field_name("parameters")
            names = []
            if params:
                for p in params.named_children:
                    name = p.child_by_field_name("name")
                    if name:
                        names.append((self.text(name), p))
            visibility = next((self.text(c) for c in node.named_children if c.type == "visibility_modifier"), "public")
            name = self.text(node.child_by_field_name("name"))
            f = Function((self.path, scope), name, class_name if node.type == "method_declaration" else "", namespace, node, tuple(names), visibility == "public" and node.type in ("method_declaration", "function_definition"), self)
            self.functions[scope] = f
            self.nodes[scope]  # Keep even an empty function body in the index.
        if node.type in CALLS or node.type in ("variable_name", "subscript_expression", "member_access_expression", "nullsafe_member_access_expression", "assignment_expression", "reference_assignment_expression", "augmented_assignment_expression", "foreach_statement", "if_statement"):
            self.scope[node.id] = scope
        if node.type in CALLS:
            self.namespaces[node.id] = namespace
        if node.type == "global_declaration":
            for variable in node.named_children:
                if variable.type == "variable_name":
                    self.global_declarations[(scope, self.text(variable))].append(node)
        if node.type in CALLS or node.type in ("return_statement", "foreach_statement", "if_statement"):
            self.nodes[scope].append(node)
        if node.type in ("assignment_expression", "augmented_assignment_expression"):
            left = node.child_by_field_name("left")
            access = self.access(left)
            if access:
                self.writes[(scope, access[0])].append((node, access))
        if node.type == 'reference_assignment_expression':
            left, right = self.access(node.child_by_field_name('left')), self.access(node.child_by_field_name('right'))
            if left and right and len(left) == len(right) == 1 and all(re.fullmatch(r'\$\w+', a[0]) for a in (left, right)):
                self.aliases[scope].append((node, left[0], right[0]))
        if node.type == "foreach_statement":
            bindings = foreach_bindings(node)
            if bindings is not None:
                paths = {self.access(binding): fields for binding, fields in bindings}
                self.iteration_fields[node.id] = paths
                for access in paths:
                    self.writes[(scope, access[0])].append((node, access))
                return scope, namespace, class_name
            parts = [c for c in node.named_children if c.type != "comment"]
            binding = parts[1] if len(parts) > 1 else None
            if binding is not None and binding.type == 'pair':
                bindings = [c for c in binding.named_children if c.type != 'comment']
                key_access = self.access(bindings[0]) if bindings else None
                value_access = self.access(bindings[-1]) if bindings else None
                if key_access and key_access != value_access:
                    self.writes[(scope, key_access[0])].append((node, key_access))
            while binding is not None and binding.type in ("pair", "by_ref"):
                binding = binding.named_children[-1]
            access = self.access(binding)
            if access:
                self.writes[(scope, access[0])].append((node, access))
        return scope, namespace, class_name

    def access(self, node):
        if node is None:
            return None
        if node.type == "variable_name":
            return (self.text(node),)
        if node.type == "subscript_expression":
            parts = node.named_children
            base = self.access(parts[0]) if parts else None
            if base:
                field = literal(parts[1], self.source) if len(parts) > 1 else None
                if (self.project.experimental_side_effects and base == ("$GLOBALS",)
                        and isinstance(field, str) and re.fullmatch(r'[A-Za-z_]\w*', field)):
                    return ("@global:$" + field,)
                return base + (field,)
        if node.type in ("member_access_expression", "nullsafe_member_access_expression"):
            obj, name = node.child_by_field_name("object"), node.child_by_field_name("name")
            if obj is not None and obj.type == "variable_name" and name is not None and name.type == "name":
                return (self.text(obj) + "->" + self.text(name),)
            return (self.text(node),)
        return None

    def _contexts(self, node):
        if node.id in self.context_cache:
            return self.context_cache[node.id]
        result = {}
        child = node
        parent = node.parent
        while parent and parent.type not in SCOPES:
            if parent.type in {"case_statement", "default_statement"}:
                # A case contains a sequence of statements, not alternative
                # branches. Associate every statement with the same clause.
                if parent.parent is not None:
                    result[("switch", parent.parent.id)] = parent.id
            elif parent.type in BRANCHES:
                # Identify the selected body/alternative of the same decision.
                result[parent.id] = child.id
            elif parent.type == "binary_expression" and parent.child_by_field_name("right") == child:
                # The RHS may never execute. A write there cannot kill an
                # earlier definition at a use after the whole expression.
                if any(c.type.lower() in {"&&", "||", "and", "or", "??"} for c in parent.children):
                    result[parent.id] = child.id
            child, parent = parent, parent.parent
        self.context_cache[node.id] = result
        return result

    def _switch_fallthrough(self, definition, use):
        def clause(node):
            while node is not None and node.type not in SCOPES:
                if node.type in {"case_statement", "default_statement"}:
                    return node
                node = node.parent
            return None

        source, target = clause(definition), clause(use)
        if source is None or target is None or source.parent != target.parent:
            return False
        clauses = [node for node in source.parent.named_children
                   if node.type in {"case_statement", "default_statement"}]
        start, end = clauses.index(source), clauses.index(target)
        if start >= end:
            return False
        return not any(
            child.type in {"break_statement", "continue_statement", "return_statement", "throw_statement"}
            for current in clauses[start:end] for child in current.named_children
        )

    def _condition_assignment_body(self, definition, use):
        """An if/while condition is evaluated before its selected body."""
        if definition.type not in {"assignment_expression", "augmented_assignment_expression"}:
            return None
        current = definition.parent
        while current is not None and current.type not in SCOPES:
            if current.type in {"if_statement", "while_statement"}:
                condition = current.child_by_field_name("condition")
                body = current.child_by_field_name("body")
                if (condition is not None and body is not None
                        and condition.start_byte <= definition.start_byte < condition.end_byte
                        and body.start_byte <= use.start_byte < body.end_byte):
                    return current.id
            current = current.parent
        return None

    def compatible(self, definition, use):
        cfg = self.cfgs.get(self.scope.get(use.id, -1))
        if cfg and not cfg.may_reach(definition, use):
            return False
        a, b = self._contexts(definition), self._contexts(use)
        condition_to_body = self._condition_assignment_body(definition, use)
        return all(
            k == condition_to_body or k not in b or b[k] == v
            or isinstance(k, tuple) and k[0] == "switch"
            and (cfg is not None and cfg.supported or self._switch_fallthrough(definition, use))
            for k, v in a.items()
        )

    def dominates(self, definition, use):
        if definition.end_byte > use.start_byte:
            return False
        cfg = self.cfgs.get(self.scope.get(use.id, -1))
        if cfg:
            result = cfg.dominates(definition, use)
            if result is not None:
                return result
        a, b = self._contexts(definition), self._contexts(use)
        condition_to_body = self._condition_assignment_body(definition, use)
        return all(k == condition_to_body or b.get(k) == v for k, v in a.items())

    def _append(self, flows, node, description, variable=None, **flags):
        step = self.step(node, description, variable)
        return tuple(replace(f, steps=trace_steps(f.steps + (step,)), **flags) for f in flows)

    def read(self, access, use, symbolic=False):
        if self.project.experimental_side_effects:
            self.project.check_effect_budget()
        # Augmented assignments recursively read earlier definitions. Share the
        # expression cache lifecycle so summary updates invalidate these reads.
        key = ("read", access, use.id, symbolic)
        if key not in self.cache:
            if key in self.active:
                return self.loop_previous.get(key, ())
            self.active.add(key)
            try:
                self.cache[key] = merge(self._read(access, use, symbolic),
                                        self.call_effects(access, use, symbolic))
            finally:
                self.active.remove(key)
        return self.cache[key]

    def global_visible(self, name, node):
        if not self.project.experimental_side_effects:
            return False
        scope = self.scope.get(node.id, -1)
        return scope == -1 or any(
            declaration.end_byte <= node.start_byte
            for declaration in self.global_declarations.get((scope, name), ()))

    def effect_targets(self, call, include_hidden_globals=False):
        """Map reference-parameter effects to caller storage; no strong kills."""
        target = self.project.resolve(self, call)
        if target is None:
            return
        self.project.effect_demands.add(target.key)
        args = arguments(call)
        scope = self.scope.get(call.id, -1)
        for index, fields, flows in self.project.effects.get(target.key, ()):
            if isinstance(index, tuple):
                access = actual_property(self, target, call, index)
                if access:
                    yield access + fields, flows, target
                continue
            if isinstance(index, str):
                visible = self.global_visible(index, call)
                if include_hidden_globals or visible:
                    yield (index if visible else "@global:" + index,) + fields, flows, target
                continue
            name = target.params[index][0].lstrip("$")
            arg = next((a for a in args if self.text(a.child_by_field_name("name")) == name), None)
            if arg is None and index < len(args) and args[index].child_by_field_name("name") is None:
                arg = args[index]
            access = self.access(expression(arg)) if arg is not None else None
            if access:
                yield self._canonical_access(access, call, scope) + fields, flows, target

    def call_effects(self, access, use, symbolic):
        if not self.project.experimental_side_effects:
            return ()
        scope = self.scope.get(use.id, -1)
        found = {}
        cache_key = ("effect_index", scope)
        if cache_key not in self.effect_index:
            indexed = defaultdict(list)
            for call in self.calls_in_scope(scope):
                if self.reachable(call, scope):
                    for target_access, flows, target in self.effect_targets(call, include_hidden_globals=True):
                        indexed[target_access[0]].append((call, target_access, flows, target))
            self.effect_index[cache_key] = indexed
        for call, target_access, flows, target in self.effect_index[cache_key].get(access[0], ()):
            if call.end_byte > use.start_byte:
                continue
            if not self.compatible(call, use):
                continue
            if len(target_access) > len(access) or any(
                a != b and a is not None and b is not None
                for a, b in zip(target_access, access)
            ):
                continue
            # A later definite local overwrite supersedes this may-write.
            if any(call.end_byte < write.start_byte and written == access
                   and write.type == "assignment_expression" and self.dominates(write, use)
                   for write, written in self.writes.get((scope, access[0]), ())):
                continue
            bound = self.bind(flows, target, call, symbolic, access[len(target_access):])
            accumulate_flows(found, self._append(bound, call,
                "Possible reference, global or object-property write; callee paths are merged.",
                access[0], uncertain=True))
        return tuple(found.values())

    def reference_effects(self, function):
        """Conservative may-write summaries, including calls through wrappers."""
        if not self.project.experimental_side_effects:
            return ()
        scope = function.node.start_byte
        effects = {}
        exported = [(index, name) for index, (name, parameter) in enumerate(function.params)
                    if any(c.type == "reference_modifier" for c in parameter.named_children)]
        exported.extend((name, name) for owner, name in self.global_declarations if owner == scope)
        exported.extend((name[8:], name) for owner, name in self.writes
                        if owner == scope and name.startswith("@global:"))
        cfg = self.cfgs.get(scope)
        def escapes(node, access):
            return cfg is None or cfg.effect_can_escape(node, access, self.writes.get((scope, access[0]), ()))
        for index, name in exported:
            for write, access in self.writes.get((scope, name), ()):
                if write.type not in ("assignment_expression", "augmented_assignment_expression") or not self.reachable(write, scope):
                    continue
                if isinstance(index, str) and not name.startswith("@global:") and not self.global_visible(name, write):
                    continue
                if not escapes(write, access):
                    continue
                flows = self.evaluate(write.child_by_field_name("right"), symbolic=True)
                key = (index, bounded_fields(access[1:]))
                effects[key] = merge(effects.get(key, ()), flows)
            for call in self.calls_in_scope(scope):
                if not self.reachable(call, scope):
                    continue
                for access, flows, target in self.effect_targets(call):
                    if access[0] == name:
                        if not escapes(call, access):
                            continue
                        key = (index, bounded_fields(access[1:]))
                        effects[key] = merge(effects.get(key, ()),
                                             self.bind(flows, target, call, True))
        # A wrapper can modify a global through a call without declaring a
        # local binding to that global. Preserve that effect for its caller.
        for call in self.calls_in_scope(scope):
            if not self.reachable(call, scope):
                continue
            target = self.project.resolve(self, call)
            if target is None:
                continue
            self.project.effect_demands.add(target.key)
            for name, fields, flows in self.project.effects.get(target.key, ()):
                if not isinstance(name, str):
                    continue
                if self.global_visible(name, call) and not escapes(call, (name,) + fields):
                    continue
                key = (name, fields)
                effects[key] = merge(effects.get(key, ()), self.bind(flows, target, call, True))
        return tuple((index, fields, flows) for (index, fields), flows in effects.items() if flows) + property_effects(self, function)

    def _read(self, access, use, symbolic=False):
        if len(access) > FIELD_DEPTH_LIMIT + 1:
            self.project.field_paths_widened = True
            access = access[:1] + bounded_fields(access[1:])
        scope = self.scope.get(use.id, -1)
        found = ()
        writes = self.writes.get((scope, access[0]), [])
        cfg = self.cfgs.get(scope)
        reaching = None
        if cfg and len(access) == 1 and re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", access[0]):
            reaching = cfg.reaching_definitions(access[0], writes, use)
        for assign, target in reversed(writes):
            if reaching is not None and assign.id not in reaching:
                continue
            iteration = assign.type == "foreach_statement"
            body = assign.child_by_field_name("body") if iteration else None
            available_at = body.start_byte if body is not None else assign.end_byte
            if reaching is None and (available_at > use.start_byte or not self.compatible(assign, use)):
                continue
            # Exact fields and writes to ancestors affect this read. A sibling
            # field never contaminates the whole array or another field.
            if len(target) > len(access) and not (len(access) == FIELD_DEPTH_LIMIT + 1 and access[-1] is None):
                continue
            key_write = (access[-1] is FieldKind.ARRAY_KEY and len(target) == len(access)
                         and not iteration)
            compared = zip(target[:-1], access[:-1]) if key_write else zip(target, access)
            if any(a != b and a is not None and b is not None for a, b in compared):
                continue
            right = next(c for c in assign.named_children if c.type != "comment") if iteration else assign.child_by_field_name("right")
            element = None
            if iteration:
                parts = [c for c in assign.named_children if c.type != 'comment']
                binding = parts[1]
                if binding.type == 'pair':
                    pair = [c for c in binding.named_children if c.type != 'comment']
                    if self.access(pair[0]) == target and self.access(pair[-1]) != target:
                        element = FieldKind.ARRAY_KEY
            selected_fields = ((element,) if iteration else ()) + access[len(target):]
            if iteration and assign.id in self.iteration_fields:
                selected_fields = self.iteration_fields[assign.id][target] + access[len(target):]
            if key_write:
                left = assign.child_by_field_name('left')
                children = left.named_children if left is not None else []
                right = children[-1] if left is not None and left.type == 'subscript_expression' and len(children) > 1 else None
                selected_fields = ()
            value = self.evaluate(right, selected_fields, symbolic)
            if assign.type == "augmented_assignment_expression":
                value = merge(value, self.read(access, assign, symbolic))
            value = self._append(value, assign, "Foreach element reaches this use." if iteration else "Assignment reaching this use.", access[0])
            value = self._guard(value, access, use, assign)
            found = merge(found, value)
            definite = (body is not None and body.start_byte <= use.start_byte < body.end_byte) if iteration else self.dominates(assign, use)
            if reaching is None and None not in target and definite and not key_write:
                return found
        if reaching is not None and -1 not in reaching:
            return found
        # A foreach value is an element of its iterable. Properties accessed
        # on that value (for example $row->option_value) are represented as a
        # single lexical root by access(). Rebind them to the foreach element
        # only when that variable is an actual value binding in this scope.
        # A dominating write to the property has already returned above.
        member = re.fullmatch(r'(\$[A-Za-z_]\w*)->([A-Za-z_]\w*)', access[0])
        if member and not symbolic:
            base, field = member.groups()
            bindings = self.writes.get((scope, base), ())
            if any(assign.type == 'foreach_statement'
                   and self.iteration_fields.get(assign.id, {}).get((base,)) != (FieldKind.ARRAY_KEY,)
                   and target == (base,) and self.compatible(assign, use)
                   for assign, target in bindings):
                found = merge(found, self.read((base, field) + access[1:], use, symbolic))
        function = self.functions.get(scope)
        # In library mode, public constructors are potential external entry
        # points. Carry their parameter flows into properties read by methods
        # on the same class or a subclass.
        if self.project.library_mode and function and function.class_name and access[0].startswith("$this->"):
            hierarchy = [function.class_name]
            if self.project.symbols:
                hierarchy = [
                    item.full_name or item.name
                    for item in self.project.symbols.resolve_inheritance(function.class_name)
                ] or hierarchy
            for class_name in hierarchy:
                property_flows = self.project.library_properties.get((class_name.lower(), access[0]), ())
                if property_flows:
                    step = self.step(use, "Property initialized from a public constructor parameter.", access[0])
                    found = merge(found, tuple(replace(flow, steps=trace_steps(flow.steps + (step,))) for flow in property_flows))
        if function:
            if symbolic and self.project.experimental_side_effects:
                owner = property_owner(self, function, access, use)
                if owner is not None:
                    seed = (Flow("object_property", str(function.key), owner[1],
                        (owner[2],) + access[1:],
                        (self.step(use, "Symbolic object property bound at the caller.", access[0]),),
                        uncertain=True),)
                    found = merge(found, self._guard(seed, access, use))
            if symbolic and (self.global_visible(access[0], use) or access[0].startswith("@global:")):
                global_name = access[0][8:] if access[0].startswith("@global:") else access[0]
                seed = (Flow("global", global_name, fields=access[1:],
                    steps=(self.step(use, "Symbolic global value bound at the caller.", access[0]),)),)
                found = merge(found, self._guard(seed, access, use))
            for index, (name, parameter) in enumerate(function.params):
                if name == access[0] and (symbolic or self.project.library_mode and function.public):
                    kind = "parameter" if symbolic else "library_parameter"
                    step = self.step(parameter, "Symbolic function parameter." if symbolic else "Public API parameter: external control is an assumption, not an observed request source.", name)
                    seed = (Flow(kind, str(function.key), index, access[1:], (step,)),)
                    found = merge(found, self._guard(seed, access, use))
                    break
        return found

    def _guard(self, flows, access, use, definition=None):
        cfg = self.cfgs.get(self.scope.get(use.id, -1))
        if cfg and cfg.supported and cfg.has_exceptions:
            return flows  # Lexical guard order does not prove exception-path validation.
        if cfg and cfg.supported and cfg.has_loops:
            # Preserve guards only for loop-invariant variables, or a lone
            # foreach binding read inside its own body. The latter gets a new
            # value before each iteration's guards; it has no later writes.
            writes = self.writes.get((self.scope.get(use.id, -1), access[0]), ())
            stable_binding = False
            if len(writes) == 1 and writes[0][0].type == 'foreach_statement':
                body = writes[0][0].child_by_field_name('body')
                stable_binding = body is not None and body.start_byte <= use.start_byte < body.end_byte
            cyclic_write = False
            for assignment, _ in writes:
                current = assignment
                while current is not None and current.type not in SCOPES:
                    if current.type in {'while_statement', 'do_statement', 'for_statement', 'foreach_statement'}:
                        cyclic_write = True
                        break
                    current = current.parent
                if cyclic_write:
                    break
            # A write after a completed loop cannot be carried around its
            # backedge. Normal guard/definition ordering below still applies.
            if cyclic_write and not stable_binding:
                return flows
        definition_end = definition.end_byte if definition is not None else -1
        if definition is not None and definition.type == 'foreach_statement':
            body = definition.child_by_field_name('body')
            if body is not None:
                definition_end = body.start_byte  # iteration binding precedes its body
        child, parent = use, use.parent
        while parent is not None and parent.type not in SCOPES:
            if parent.type == "if_statement" and parent.child_by_field_name("body") == child:
                condition = parent.child_by_field_name("condition")
                while condition is not None and condition.type == "parenthesized_expression" and condition.named_children:
                    condition = condition.named_children[0]
                if (condition is not None and condition.type == "function_call_expression"
                        and self.call_name(condition) in {"ctype_digit", "is_numeric", "is_int", "is_integer", "is_float", "is_bool"}
                        and not self.project.resolve(self, condition)):
                    args = arguments(condition)
                    if (len(args) == 1 and self.access(expression(args[0])) == access
                            and definition_end < condition.start_byte
                            and access[0] not in self.source[condition.end_byte:use.start_byte].decode("utf-8", errors="replace")):
                        return ()
            child, parent = parent, parent.parent
        for guard, guarded in self.guards:
            if guarded != access or self.scope.get(guard.id, -1) != self.scope.get(use.id, -1) or not self.dominates(guard, use):
                continue
            if definition_end > guard.end_byte:
                continue
            # read() applies guards to each reaching definition separately.
            # A later unsafe write must not erase validation of the old value,
            # nor inherit that validation when the branches are merged.
            return tuple(replace(f, blocked_phar=True) for f in flows)
        return flows

    def evaluate(self, node, fields=(), symbolic=False):
        loop_scope = False
        if self.loop_solver_enabled and not self.loop_solving and not self.active and node is not None:
            current = node
            scope = -1
            while current is not None:
                if current.id in self.scope:
                    scope = self.scope[current.id]
                    break
                if current.type in SCOPES:
                    scope = current.start_byte
                    break
                current = current.parent
            cfg = self.cfgs.get(scope)
            loop_scope = bool(cfg and cfg.supported and cfg.has_loops)
        if loop_scope:
            query = (node.id, fields, symbolic)
            if query in self.loop_results:
                return self.loop_results[query]
            self.loop_solving = True
            try:
                previous = {}
                result = ()
                for _ in range(128):
                    self.loop_iterations += 1
                    self.cache.clear()
                    self.loop_previous = previous
                    result = self._evaluate_cached(node, fields, symbolic)
                    current = dict(self.cache)
                    signature = lambda values: {key: frozenset(f.key() for f in flows) for key, flows in values.items()}
                    if signature(current) == signature(previous):
                        self.loop_results[query] = result
                        return result
                    previous = current
                self.loop_limit_reached = True
                return tuple(replace(f, uncertain=True) for f in result)
            finally:
                self.loop_previous = {}
                self.loop_solving = False
        return self._evaluate_cached(node, fields, symbolic)

    def _evaluate_cached(self, node, fields=(), symbolic=False):
        if node is None:
            return ()
        if len(fields) > FIELD_DEPTH_LIMIT:
            self.project.field_paths_widened = True
            fields = bounded_fields(fields)
        # Font tables contain millions of scalar AST nodes. They have no taint;
        # retaining an empty cache entry for each costs more than parsing them.
        if node.type in ("integer", "float", "boolean", "null", "string", "name", "qualified_name", "string_content", "escape_sequence", "comment"):
            return ()
        key = (node.id, fields, symbolic)
        if key in self.cache:
            return self.cache[key]
        if key in self.active:
            return self.loop_previous.get(key, ())
        self.active.add(key)
        try:
            result = self._evaluate(node, fields, symbolic)
            self.cache[key] = result
            return result
        finally:
            self.active.remove(key)

    def _evaluate(self, node, fields, symbolic):
        if node.type == "argument":
            return self.evaluate(expression(node), fields, symbolic)
        access = self.access(node)
        if access:
            access += fields
            context = self.functions.get(self.scope.get(node.id, -1))
            if (access[0] == "$request->cookies" and context is not None
                    and context.class_name.lower() == "illuminate\\cookie\\middleware\\encryptcookies"
                    and context.name.lower() == "decrypt"):
                request_type = next((self.text(param.child_by_field_name("type")).lstrip("?\\")
                                     for name, param in context.params if name == "$request"), "")
                resolved_type = (self.project.symbols.resolve_class_name(
                    request_type, context.namespace, self.path) if request_type and self.project.symbols else request_type)
                if resolved_type.lower() == "symfony\\component\\httpfoundation\\request":
                    return (Flow("framework_request", self.path + ":" + str(node.start_byte),
                                 fields=bounded_fields(access[1:]),
                                 steps=(self.step(node, "Framework source model: Symfony Request cookies in Laravel middleware; verify runtime request origin."),)),)
            candidates, uncertain_alias = self._alias_accesses(access, node)
            result = ()
            for access in candidates:
                root = access[0]
                if root == "$_FILES" and len(access) >= 3 and access[2] in {"tmp_name", "size", "error"}:
                    continue
                request = root in REQUESTS or root == "$_SERVER" and (len(access) == 1 or access[1] not in TRUSTED_SERVER)
                if request:
                    flows = (Flow("request", self.path + ":" + str(node.start_byte), fields=bounded_fields(access[1:]), steps=(self.step(node, "Observed request source.", root),)),)
                    flows = self._guard(flows, access, node)
                else:
                    flows = self.read(access, node, symbolic)
                result = merge(result, flows)
            return tuple(replace(f, uncertain=True) for f in result) if uncertain_alias else result
        if node.type in ("integer", "float", "boolean", "null", "string", "name", "qualified_name"):
            return ()
        if node.type == "array_creation_expression":
            selected = []
            auto_index = 0
            for item in node.named_children:
                if item.type != "array_element_initializer":
                    continue
                parts = item.named_children
                if not parts:
                    continue
                if fields and fields[0] is FieldKind.ARRAY_KEY:
                    if len(parts) > 1:
                        selected.append(self.evaluate(parts[0], fields[1:], symbolic))
                    continue
                index = literal(parts[0], self.source) if len(parts) > 1 else str(auto_index)
                auto_index += 1
                if not fields or fields[0] is None or index is None or fields[0] == index:
                    selected.append(self.evaluate(parts[-1], fields[1:] if fields else (), symbolic))
            return merge(*selected)
        if node.type in ("assignment_expression", "augmented_assignment_expression"):
            return self.evaluate(node.child_by_field_name("right"), fields, symbolic)
        if node.type == "binary_expression":
            operator = self.text(node.child_by_field_name("operator"))
            if operator not in (".", "??"):
                return ()  # comparisons/numeric results cannot contain a path/payload
            return merge(self.evaluate(node.child_by_field_name("left"), fields, symbolic), self.evaluate(node.child_by_field_name("right"), fields, symbolic))
        if node.type == "cast_expression":
            cast = next((self.text(c).lower() for c in node.named_children if c.type == "cast_type"), "")
            if cast in ("int", "integer", "bool", "boolean", "float", "double", "real", "unset"):
                return ()
        if node.type in CALLS:
            return self._call_value(node, fields, symbolic)
        if node.type == "conditional_expression":
            body = node.child_by_field_name("body") or node.child_by_field_name("condition")
            return merge(self.evaluate(body, fields, symbolic), self.evaluate(node.child_by_field_name("alternative"), fields, symbolic))
        if node.type in SCOPES:
            return ()
        return merge(*(self.evaluate(c, fields, symbolic) for c in node.named_children))

    def call_name(self, node):
        raw = self.text(node.child_by_field_name("function") or node.child_by_field_name("name"))
        if node.type == "function_call_expression" and "\\" not in raw:
            imported = self.function_imports.get((self.namespaces.get(node.id, "").lower(), raw.lower()))
            if imported:
                return imported
        return raw.strip("\\").lower()

    def builtin_argument(self, node, index):
        """Bind PHP named arguments by declaration position, never textual order."""
        name = self.call_name(node)
        names = {"unserialize": ("data", "options"), "igbinary_unserialize": ("str",),
                 "explode": ("separator", "string", "limit"),
                 "hash_file": ("algo", "filename"),
                 "hash_hmac_file": ("algo", "filename", "key"), "copy": ("from", "to"),
                 "rename": ("from", "to"), "opendir": ("directory",), "scandir": ("directory",),
                 "openssl_decrypt": ("data", "cipher_algo", "passphrase", "options", "iv", "tag", "aad"),
                 "filter_input": ("type", "var_name", "filter", "options")}.get(name, ("filename",))
        args = arguments(node)
        if index < len(names):
            for arg in args:
                if self.text(arg.child_by_field_name("name")) == names[index]:
                    return expression(arg)
        if index < len(args) and args[index].child_by_field_name("name") is None:
            return expression(args[index])
        return None

    def uploaded_temp_path(self, node, depth=0):
        """Recognize PHP's upload handle, whose *contents* are request data.

        The tmp_name string itself is server generated and must not become a
        serialized-input source. Follow only a single dominating local copy.
        """
        if node is None or depth > 6:
            return False
        if node.type in ("argument", "parenthesized_expression", "error_suppression_expression"):
            return bool(node.named_children) and self.uploaded_temp_path(node.named_children[-1], depth + 1)
        access = self.access(node)
        if not access:
            return False
        if access[0] == "$_FILES":
            return len(access) == 3 and access[1] is not None and access[2] == "tmp_name"
        if len(access) != 1:
            return False
        writes = [assignment for assignment, target in self.writes.get((self.scope.get(node.id, -1), access[0]), ())
                  if target == access and assignment.end_byte <= node.start_byte
                  and self.compatible(assignment, node)]
        if len(writes) != 1 or writes[0].type != "assignment_expression" or not self.dominates(writes[0], node):
            return False
        return self.uploaded_temp_path(writes[0].child_by_field_name("right"), depth + 1)

    def _call_value(self, node, fields, symbolic):
        name = self.call_name(node)
        args = arguments(node)
        values = [expression(a) for a in args]
        context = self.functions.get(self.scope.get(node.id, -1))
        if (name == "header" and context is not None
                and context.class_name.lower() == "illuminate\\foundation\\http\\middleware\\verifycsrftoken"
                and context.name.lower() == "gettokenfromrequest"
                and self.access(node.child_by_field_name("object")) == ("$request",)
                and values and literal(values[0], self.source) == "X-XSRF-TOKEN"):
            return (Flow("framework_request", self.path + ":" + str(node.start_byte),
                         steps=(self.step(node, "Framework source model: Laravel X-XSRF-TOKEN request header; verify middleware registration."),)),)
        target = self.project.resolve(self, node)
        receiver = self.project.receiver_classes.get((self.path, node.id), "")
        if is_framework_request_source(receiver, name):
            return (Flow("framework_request", self.path + ":" + str(node.start_byte),
                         steps=(self.step(node, f"Framework source model: {receiver}::{name}; verify the runtime origin of this request."),)),)
        if (node.type in {"member_call_expression", "nullsafe_member_call_expression"}
                and is_wpdb_persistent_read(self.project.symbols,
                                            self.access(node.child_by_field_name("object")), name)):
            # get_results() returns a row collection. The collection itself
            # is not serialized input; model only values selected from a row.
            # This also avoids seeding every whole-result summary in large
            # WordPress projects.
            if symbolic or not fields:
                return ()
            return (Flow("persistent_data", self.path + ":" + str(node.start_byte),
                         fields=bounded_fields(fields), uncertain=True,
                         steps=(self.step(node,
                                          "WordPress database rows read by wpdb::get_results; attacker write provenance is unverified."),)),)
        targets = self.project.targets(self, node)
        if targets:
            result = ()
            for target in targets:
                self.project.return_demands.add(target.key)
                result = merge(result, self.bind(self.project.returns.get(target.key, ()), target, node, symbolic, fields))
            return self.project.framework_dispatch.annotate(self, node, result)
        # Drupal's REST handler passes the request body as the first input to
        # the serializer. The format and context select a decoder; they are
        # not serialized data. Keep the result uncertain because the selected
        # decoder and its runtime configuration are outside this call site.
        if (node.type in {"member_call_expression", "nullsafe_member_call_expression"}
                and name == "decode" and context is not None
                and context.class_name.lower() == "drupal\\rest\\requesthandler"
                and context.name.lower() == "deserialize"
                and self.access(node.child_by_field_name("object")) == ("$this->serializer",)):
            body = values[0] if values else None
            result = self.evaluate(body, fields, symbolic)
            return tuple(replace(flow, uncertain=True, blocked_phar=False) for flow in
                         self._append(result, node,
                                      "Drupal serializer decode derives its data from the request body; decoder and format require runtime review."))
        if node.type == "function_call_expression":
            if name == "file_get_contents" and self.uploaded_temp_path(self.builtin_argument(node, 0)):
                return (Flow("request", self.path + ":" + str(node.start_byte),
                             steps=(self.step(node, "Uploaded file contents read from PHP-managed temporary path."),)),)
            if name == "explode":
                # Only the string argument supplies element bytes. The
                # separator and limit affect splitting, not the content.
                if fields and fields[0] is FieldKind.ARRAY_KEY:
                    return ()
                source = self.builtin_argument(node, 1)
                flows = self.evaluate(source, (), symbolic) if source is not None else ()
                return self._append(flows, node, "Element of split string derives from input bytes.")
            if name == "openssl_decrypt":
                # Only the ciphertext supplies the output bytes. Key, cipher,
                # IV and tag affect whether decryption succeeds; taint in
                # those parameters alone is not a chosen plaintext source.
                ciphertext = self.builtin_argument(node, 0)
                flows = self.evaluate(ciphertext, fields, symbolic)
                if not flows:
                    return ()
                flows = self._append(flows, node,
                                     "Decrypted bytes depend on ciphertext; key and authentication prerequisites are unverified.")
                return tuple(replace(flow, uncertain=True, blocked_phar=False)
                             for flow in flows)
            if name == "tempnam":
                # Returns a generated local filename (or false), not an
                # arbitrary wrapper/payload supplied through its prefix.
                return ()
            hex_flag = {"md5": 1, "sha1": 1, "hash": 2, "hash_hmac": 3}.get(name)
            if hex_flag is not None and (len(values) <= hex_flag or self.text(values[hex_flag]).lower() == "false"):
                return ()  # Hex digest alphabet cannot encode a PHP object or phar://.
            if name in SCALAR_FUNCTIONS:
                return ()
            if name == "filter_input":
                input_type = self.text(self.builtin_argument(node, 0)).upper()
                filter_type = self.text(self.builtin_argument(node, 2)).upper()
                if input_type in {"INPUT_GET", "INPUT_POST", "INPUT_COOKIE", "INPUT_SERVER"}:
                    if filter_type in {"FILTER_VALIDATE_INT", "FILTER_VALIDATE_FLOAT", "FILTER_VALIDATE_BOOLEAN", "FILTER_VALIDATE_BOOL", "FILTER_SANITIZE_NUMBER_INT", "FILTER_SANITIZE_NUMBER_FLOAT"}:
                        return ()
                    return (Flow("request", self.path + ":" + str(node.start_byte),
                                 uncertain=filter_type not in {"", "FILTER_DEFAULT", "FILTER_UNSAFE_RAW"},
                                 steps=(self.step(node, "Observed filter_input request source."),)),)
            if name in ("getallheaders", "apache_request_headers") or name in ("file_get_contents", "fopen", "file") and literal(self.builtin_argument(node, 0), self.source) == "php://input":
                return (Flow("request", self.path + ":" + str(node.start_byte), steps=(self.step(node, "Observed request body/header read."),)),)
        if name in ("str_replace", "preg_replace"):
            values = values[2:3]
        elif name in ("substr", "trim", "rtrim", "ltrim", "dirname", "basename"):
            values = values[:1]
        result = merge(*(self.evaluate(a, fields, symbolic) for a in values))
        if not result:
            return ()
        preserves = name == "str_replace" and len(args) >= 3 and literal(expression(args[0]), self.source) == " " and literal(expression(args[1]), self.source) == "%20"
        result = self._append(result, node, "Value returned by transformation." if name in TRANSFORMS else "Return propagation is conservative: callee is unresolved.")
        result = tuple(replace(f, uncertain=f.uncertain or name not in TRANSFORMS) for f in result)
        return result if preserves else tuple(replace(f, blocked_phar=False) for f in result)

    def bind(self, flows, target, call, symbolic, fields=()):
        if self.project.experimental_side_effects and self.project._effects_building:
            self.project.effect_bindings += 1
            if (self.project.max_side_effect_bindings
                    and self.project.effect_bindings > self.project.max_side_effect_bindings):
                raise SideEffectBudgetExceeded(
                    f"Experimental side-effect analysis exceeded {self.project.max_side_effect_bindings} bindings")
        args = arguments(call)
        result = {}
        bound_groups = {}
        named_args = {self.text(a.child_by_field_name("name")): a for a in args
                      if a.child_by_field_name("name") is not None}
        parameters = {}
        for flow in flows:
            if flow.kind in {"object_property", "global"}:
                if flow.kind == "object_property":
                    if not flow.fields:
                        continue
                    access = actual_property(self, target, call, ("property", flow.index, flow.fields[0]))
                    if not access:
                        continue
                    bound = self.read(access + bounded_fields(flow.fields[1:] + fields), call, symbolic)
                    description, variable = "Object property bound at the caller.", access[0]
                elif self.global_visible(flow.origin, call):
                    bound = self.read((flow.origin,) + bounded_fields(flow.fields + fields), call, symbolic)
                    description, variable = "Global value bound at the caller.", flow.origin
                else:
                    hidden = self.call_effects(("@global:" + flow.origin,) + bounded_fields(flow.fields + fields), call, symbolic)
                    accumulate_flows(result, hidden)
                    if symbolic:
                        accumulate_flows(result, (replace(flow, fields=bounded_fields(flow.fields + fields), uncertain=True),))
                    continue
                # Compare semantic identity and retained trace length before
                # allocating traces. Many callee paths bind to the same source.
                step = None
                for value in bound:
                    blocked = value.blocked_phar or flow.blocked_phar
                    key = (value.kind, value.origin, value.index, value.fields, blocked, True)
                    length = min(32, len(value.steps) + 1 + len(flow.steps))
                    previous = result.get(key)
                    if previous is not None and len(previous.steps) <= length:
                        continue
                    if step is None:
                        step = self.step(call, description, variable)
                    # Preserve the existing two-stage trace truncation.
                    steps = trace_steps(trace_steps(value.steps + (step,)) + flow.steps)
                    result[key] = replace(value, blocked_phar=blocked, uncertain=True, steps=steps)
                continue
            if flow.kind != "parameter":
                accumulate_flows(result, (flow,))
                continue
            if flow.index >= len(target.params):
                continue
            parameter_name = target.params[flow.index][0].lstrip("$")
            if flow.index not in parameters:
                arg = named_args.get(parameter_name)
                if arg is None and flow.index < len(args) and args[flow.index].child_by_field_name("name") is None:
                    arg = args[flow.index]
                parameters[flow.index] = expression(arg) if arg is not None else None
            value_node = parameters[flow.index]
            if value_node is None:
                continue
            bound = self.evaluate(value_node, flow.fields + fields, symbolic)
            # Several callee field paths can evaluate to the same cached tuple.
            # Rebinding that tuple only changes its trace suffix. An earlier
            # suffix of equal/shorter length already wins every merge below.
            # Retain the tuple itself so object identities cannot be recycled.
            suffix_length = max(1, len(flow.steps))
            group_key = (id(bound), flow.blocked_phar, flow.uncertain)
            previous_group = bound_groups.get(group_key)
            if previous_group is not None and previous_group[1] <= suffix_length:
                continue
            bound_groups[group_key] = (bound, suffix_length)
            step = None
            for value in bound:
                blocked = value.blocked_phar or flow.blocked_phar
                uncertain = value.uncertain or flow.uncertain
                key = (value.kind, value.origin, value.index, value.fields, blocked, uncertain)
                length = min(32, len(value.steps) + suffix_length)
                previous = result.get(key)
                if previous is not None and len(previous.steps) <= length:
                    continue
                if step is None:
                    step = self.step(call, f"Argument bound to {target.name} parameter {parameter_name}{flow.fields}.", self.text(value_node))
                result[key] = Flow(value.kind, value.origin, value.index, value.fields,
                                   trace_steps(value.steps + (step,) + flow.steps[1:]),
                                   blocked, uncertain)
        return tuple(result.values())

    def _array_field(self, node, field):
        if node is None or node.type != "array_creation_expression":
            return None
        result = None
        for item in node.named_children:
            parts = item.named_children
            # PHP string keys from an unpack can override earlier options.
            if any(c.type == "variadic_unpacking" for c in parts) or item.type == "variadic_unpacking":
                result = None
                continue
            if item.type == "array_element_initializer" and len(parts) > 1 and literal(parts[0], self.source) is None:
                result = None
                continue
            if item.type == "array_element_initializer" and len(parts) > 1 and literal(parts[0], self.source) == field:
                result = parts[-1]
        return result

    def unserialize_safe(self, node):
        options = self.builtin_argument(node, 1)
        access = self.access(options)
        if access:
            # Only a dominating literal assignment with no intervening alias,
            # write or call mentioning this variable establishes constant options.
            for assign, target in reversed(self.writes.get((self.scope.get(options.id, -1), access[0]), [])):
                if assign.end_byte > options.start_byte or not self.compatible(assign, options):
                    continue
                if target != access or not self.dominates(assign, options) or assign.type != "assignment_expression":
                    return False
                if access[0] in self.source[assign.end_byte:node.start_byte].decode("utf-8", errors="replace"):
                    return False
                options = assign.child_by_field_name("right")
                break
        option = self._array_field(options, "allowed_classes")
        return option is not None and (self.text(option).lower() == "false" or option.type == "array_creation_expression" and not option.named_children)

    def fixed_prefix(self, node, depth=0):
        if node is None or depth > 8:
            return None
        text = literal(node, self.source)
        if text is not None:
            return text
        # __DIR__ and __FILE__ expand to fixed absolute local paths. A tainted
        # suffix cannot turn those paths into a phar:// wrapper URI.
        if node.type == "name" and self.text(node).upper() in {"__DIR__", "__FILE__"}:
            return "/"
        if node.type == "name":
            candidates = self.project.constant_definitions.get(self.text(node), ())
            if len(candidates) == 1:
                engine, definition, value = candidates[0]
                # Only a same-file, preceding, unconditional define proves the
                # runtime value here. Configurable bootstrap defaults do not.
                if (engine is self and self.scope.get(definition.id, -1) == -1
                        and definition.end_byte < node.start_byte and not self._contexts(definition)):
                    return engine.fixed_prefix(value, depth + 1)
        if node.type in ("argument", "parenthesized_expression", "error_suppression_expression") and node.named_children:
            return self.fixed_prefix(node.named_children[-1], depth + 1)
        if node.type == "binary_expression" and self.text(node.child_by_field_name("operator")) == ".":
            return self.fixed_prefix(node.child_by_field_name("left"), depth + 1)
        access = self.access(node)
        if access:
            for assign, target in reversed(self.writes.get((self.scope.get(node.id, -1), access[0]), [])):
                if assign.end_byte > node.start_byte or target != access or not self.compatible(assign, node):
                    continue
                if not self.dominates(assign, node) or assign.type == "augmented_assignment_expression":
                    return None
                return self.fixed_prefix(assign.child_by_field_name("right"), depth + 1)
        return None

    def phar_path_may_resolve_to_wrapper(self, node):
        """Return whether a dynamic suffix could make this path use phar://."""
        prefix = self.fixed_prefix(node)
        if prefix is None:
            return True
        prefix = prefix.lower()
        return prefix.startswith("phar://") or "phar://".startswith(prefix)

    def configured_local_prefix(self, node, depth=0):
        """Infer local defaults, never confuse configurable defaults with proof.

        Returned evidence is attached to a retained finding. A definition in a
        different file/function does not prove bootstrap order or exclude an
        external override. All discovered definitions must agree on localness.
        """
        if node is None or depth > 12:
            return False, ()
        prefix = self.fixed_prefix(node)
        if prefix is not None:
            return prefix.startswith('/') or bool(re.match(r'^[A-Za-z]:[\\/]', prefix)), ()
        if node.type == 'name':
            definitions = self.project.constant_definitions.get(self.text(node), ())
            evidence = []
            if not definitions:
                return False, ()
            for engine, call, value in definitions:
                local, assumptions = engine.configured_local_prefix(value, depth + 1)
                if not local:
                    return False, ()
                evidence.extend(assumptions)
                evidence.append(f'{engine.path}:{call.start_point[0]+1}: {engine.text(call)}')
            return True, tuple(dict.fromkeys(evidence))[:8]
        if node.type in ('argument', 'parenthesized_expression', 'error_suppression_expression') and node.named_children:
            return self.configured_local_prefix(node.named_children[-1], depth + 1)
        if node.type == 'binary_expression' and self.text(node.child_by_field_name('operator')) == '.':
            return self.configured_local_prefix(node.child_by_field_name('left'), depth + 1)
        if node.type == 'function_call_expression' and self.call_name(node) == 'dirname' and not self.project.resolve(self, node):
            args = arguments(node)
            if args:
                return self.configured_local_prefix(expression(args[0]), depth + 1)
        access = self.access(node)
        if access:
            for assign, target in reversed(self.writes.get((self.scope.get(node.id, -1), access[0]), ())):
                if assign.end_byte > node.start_byte or not self.compatible(assign, node):
                    continue
                if target != access or assign.type != 'assignment_expression' or not self.dominates(assign, node):
                    return False, ()
                return self.configured_local_prefix(assign.child_by_field_name('right'), depth + 1)
        return False, ()

    def direct_sinks(self, scope, symbolic):
        sinks = []
        for call in self.calls_in_scope(scope):
            if call.type != "function_call_expression" or not self.reachable(call, scope):
                continue
            name = self.call_name(call)
            if name not in DESERIALIZATION_FUNCTIONS and name not in PATH_ARGUMENTS:
                continue
            if self.project.resolve(self, call):
                continue  # A namespaced user function can shadow a PHP builtin.
            if name == "unserialize" and self.unserialize_safe(call):
                continue
            for index in ((0,) if name in DESERIALIZATION_FUNCTIONS else PATH_ARGUMENTS[name]):
                value = self.builtin_argument(call, index)
                if value is None:
                    continue
                phar_possible = name in DESERIALIZATION_FUNCTIONS or self.phar_path_may_resolve_to_wrapper(value)
                if name not in DESERIALIZATION_FUNCTIONS and not phar_possible and symbolic:
                    continue
                path_assumptions = self.configured_local_prefix(value)[1] if name not in DESERIALIZATION_FUNCTIONS and phar_possible else ()
                for flow in self.evaluate(value, symbolic=symbolic):
                    if name not in DESERIALIZATION_FUNCTIONS and flow.blocked_phar:
                        continue
                    flow = replace(flow, steps=flow.steps + (self.step(call, "Value reaches sink argument.", self.text(value)),))
                    sinks.append(Sink(name, get_node_location(call, self.path), self.text(call), flow, index, phar_possible,
                                      self.review_conditions(value, call), path_assumptions,
                                      name == "unserialize" and self.object_excluding_guard(value, call)))
        return sinks

    def review_conditions(self, value, use):
        # These predicates depend on immutable AST/write locations and static
        # call resolution, not on the current taint-summary iteration.
        key = (value.id, use.id)
        if key not in self.review_condition_cache:
            self.review_condition_cache[key] = self._review_conditions(value, use)
        return self.review_condition_cache[key]

    def object_excluding_guard(self, value, use):
        """Prove a positive serialized-string check on this exact argument."""
        if value.type in CALLS:
            args = arguments(value)
            value = expression(args[0]) if args else value
        access = self.access(value)
        if access is None:
            return False
        child, parent = use, use.parent
        while parent is not None and parent.type not in SCOPES:
            if parent.type == "if_statement" and parent.child_by_field_name("body") == child:
                body = parent.child_by_field_name("body")
                statements = [node for node in body.named_children if node.type != "comment"] if body else []
                if (len(statements) != 1 or statements[0].type != "expression_statement"
                        or not statements[0].start_byte <= use.start_byte
                        or use.end_byte > statements[0].end_byte):
                    child, parent = parent, parent.parent
                    continue
                condition = parent.child_by_field_name("condition")
                inner = condition.named_children[0] if condition is not None and condition.type == "parenthesized_expression" and len(condition.named_children) == 1 else condition
                if inner is not None and inner.type == "function_call_expression" and self.call_name(inner) == "is_serialized_string":
                    args = arguments(inner)
                    checked = self.access(expression(args[0])) if len(args) == 1 else None
                    if checked == access:
                        scope = self.scope.get(use.id, -1)
                        if any(condition.end_byte <= assign.start_byte
                               and assign.end_byte <= use.start_byte
                               and self.compatible(assign, use)
                               for assign, _ in self.writes.get((scope, access[0]), ())):
                            child, parent = parent, parent.parent
                            continue
                        target = self.project.resolve(self, inner)
                        if target is not None and proves_serialized_string_only(target):
                            return True
            child, parent = parent, parent.parent
        return False

    def _review_conditions(self, value, use):
        """Record relevant predicates, without treating signatures as sanitizers.

        Conditions are evidence requiring review, not a proof of reachability,
        integrity or an attacker-controlled signing key. Scope boundaries matter.
        """
        variables = {self.text(n) for n in find_nodes_by_type(value, "variable_name")}

        def accesses(root, variable):
            paths = set()
            for ref in find_nodes_by_type(root, "variable_name"):
                if self.text(ref) != variable:
                    continue
                outer = ref
                while (outer.parent is not None
                       and root.start_byte <= outer.parent.start_byte
                       and outer.parent.end_byte <= root.end_byte
                       and outer.parent.type == "subscript_expression"
                       and outer.parent.named_children
                       and outer.parent.named_children[0] == outer):
                    outer = outer.parent
                paths.add(self.access(outer) or (variable,))
            return paths

        def overlapping(left, right):
            return all(a is None or b is None or a == b
                       for a, b in zip(left, right))
        conditions = []
        child, parent = use, use.parent
        while parent is not None and parent.type not in SCOPES:
            if parent.type == "if_statement" and parent.child_by_field_name("body") == child:
                conditions.append(parent.child_by_field_name("condition"))
            child, parent = parent, parent.parent
        for guard in self.nodes.get(self.scope.get(use.id, -1), ()):
            if guard.type != "if_statement" or not self.dominates(guard, use):
                continue
            body = guard.child_by_field_name("body")
            statements = body.named_children if body is not None and body.type == "compound_statement" else [body]
            if statements and statements[-1] is not None and statements[-1].type in {"return_statement", "throw_expression", "throw_statement"}:
                conditions.append(guard.child_by_field_name("condition"))
        evidence = []
        for condition in conditions:
            if condition is None:
                continue
            refs = {self.text(n) for n in find_nodes_by_type(condition, "variable_name")}
            relevant = (variables & refs) - {"$this"}
            scope = self.scope.get(use.id, -1)
            for variable in tuple(relevant):
                if not any(overlapping(left, right)
                           for left in accesses(value, variable)
                           for right in accesses(condition, variable)):
                    relevant.discard(variable)
                    continue
                if any(condition.end_byte <= assign.start_byte
                       and assign.end_byte <= use.start_byte
                       and self.compatible(assign, use)
                       for assign, _ in self.writes.get((scope, variable), ())):
                    relevant.discard(variable)
            if not relevant:
                continue
            calls = [n for n in find_nodes_by_type(condition, CALLS)
                     if not (n.type == "function_call_expression" and self.call_name(n) in
                             {"isset", "empty", "is_string", "is_array", "is_object", "file_exists", "is_file", "is_dir"}
                             and not self.project.resolve(self, n))]
            if relevant and calls:
                evidence.append(f"{self.path}:{condition.start_point[0] + 1}: {self.text(condition)[:500]}")
        return tuple(dict.fromkeys(evidence))[:4]

    def forwarded_sinks(self, scope, symbolic):
        sinks = []
        for call in self.calls_in_scope(scope):
            if not self.reachable(call, scope):
                continue
            call_reviews = None
            validation_reviews = None
            excludes_objects = None
            for target in self.project.targets(self, call):
                for sink in self.project.sinks.get(target.key, ()):
                    bound = self.bind((sink.flow,), target, call, symbolic)
                    for flow in self.project.framework_dispatch.annotate(self, call, bound):
                        if sink.name not in DESERIALIZATION_FUNCTIONS and flow.blocked_phar:
                            continue
                        if call_reviews is None:
                            call_reviews = self.review_conditions(call, call)
                            validation_reviews = self.project.framework_dispatch.validation_reviews(self, call)
                        if sink.name == "unserialize" and excludes_objects is None:
                            excludes_objects = self.object_excluding_guard(call, call)
                        evidence = sink.review_conditions + call_reviews + validation_reviews
                        sinks.append(replace(
                            sink, flow=flow,
                            review_conditions=tuple(dict.fromkeys(evidence))[:4],
                            object_payload_excluded=(sink.object_payload_excluded or
                                                     sink.name == "unserialize" and excludes_objects),
                        ))
        return sinks

    def discover_guards(self):
        # Narrow structural recognizer: wrapper enumeration, an HTTP(S)-only
        # continue, and a terminating rejection. It is not a scope-wide regex.
        for scope, nodes in self.nodes.items():
            for loop in nodes:
                if loop.type != "foreach_statement":
                    continue
                text = re.sub(r"\s+", "", self.text(loop))
                text = re.sub(r"\((\$\w+==='(?:http|https)')\)", r"\1", text)
                match = re.fullmatch(r"foreach\((\$\w+)as(\$\w+)\)\{if\(\2==='http'\|\|\2==='https'\)\{continue;\}if\(stripos\((\$\w+),\2\.'://'\)===0\)\{(.+)\}\}", text)
                if not match:
                    continue
                wrappers, _, variable, _ = match.groups()
                definitions = [(a, target) for a, target in self.writes.get((scope, wrappers), []) if self.dominates(a, loop)]
                if not definitions or self.text(definitions[-1][0].child_by_field_name("right")).strip() != "stream_get_wrappers()":
                    continue
                wrapper_call = definitions[-1][0].child_by_field_name("right")
                if self.project.resolve(self, wrapper_call):
                    continue
                if any(self.project.resolve(self, call) for call in find_nodes_by_type(loop, "function_call_expression")):
                    continue
                rejection = [n for n in nodes if loop.start_byte < n.start_byte < loop.end_byte and n.type == "if_statement"]
                if rejection and self.terminates(rejection[-1].child_by_field_name("body"), set()):
                    guard = loop
                    body = loop.parent
                    outer = body.parent if body is not None else None
                    if outer is not None and outer.type == "if_statement":
                        condition = re.sub(r"\s+", "", self.text(outer.child_by_field_name("condition")))
                        expected = "(strpos(" + variable + ",'://')>0)"
                        statements = [n for n in body.named_children if n.type != "comment"]
                        if condition == expected and len(statements) == 2 and statements[-1] == loop:
                            condition_calls = list(find_nodes_by_type(outer.child_by_field_name("condition"), "function_call_expression"))
                            if all(not self.project.resolve(self, call) for call in condition_calls):
                                guard = outer
                    self.guards.append((guard, (variable,)))

    def terminates(self, node, seen):
        return "normal" not in self._outcomes(node, seen)

    def discover_validator_guards(self):
        for scope, nodes in self.nodes.items():
            for branch in nodes:
                if branch.type != 'if_statement':
                    continue
                condition = branch.child_by_field_name('condition')
                while condition is not None and condition.type == 'parenthesized_expression':
                    condition = condition.named_children[0]
                if condition is None or condition.type != 'unary_op_expression' or not self.text(condition).lstrip().startswith('!'):
                    continue
                call = condition.child_by_field_name('argument')
                if call is None or call.type not in {'function_call_expression', 'scoped_call_expression'}:
                    continue
                target = self.project.resolve(self, call)
                if target is None or target.key not in self.project.phar_validators:
                    continue
                if not self.terminates(branch.child_by_field_name('body'), set()):
                    continue
                index = self.project.phar_validators[target.key]
                args = arguments(call)
                parameter = target.params[index][0].lstrip('$')
                arg = next((a for a in args if self.text(a.child_by_field_name('name')) == parameter), None)
                if arg is None and index < len(args) and args[index].child_by_field_name('name') is None:
                    arg = args[index]
                access = self.access(expression(arg)) if arg is not None else None
                if access:
                    self.guards.append((branch, access))

    def _outcomes(self, node, seen):
        if node is None:
            return {"normal"}
        if node.type in ("throw_expression", "exit_statement"):
            return {"abort"}
        if node.type == "return_statement":
            return {"return"}
        if node.type == "if_statement":
            alternative = node.child_by_field_name("alternative")
            return self._outcomes(node.child_by_field_name("body"), seen) | self._outcomes(alternative, seen)
        if node.type in CALLS:
            if self.call_name(node) in ("exit", "die"):
                return {"abort"}
            target = self.project.resolve(self, node)
            if target and target.key not in seen:
                outcomes = target.engine._outcomes(target.node.child_by_field_name("body"), seen | {target.key})
                # Returning from Error() resumes the caller; throwing/exiting does not.
                return {"normal" if o == "return" else o for o in outcomes}
        if node.type in ("compound_statement", "expression_statement", "else_clause"):
            outcomes = {"normal"}
            for child in node.named_children:
                if "normal" in outcomes:
                    outcomes = (outcomes - {"normal"}) | self._outcomes(child, seen)
            return outcomes
        return {"normal"}


class FlowProject:
    def __init__(self, parsed_files, symbols=None, library_mode=False, experimental_foreach_cfg=False,
                 experimental_side_effects=False, experimental_demand_summaries=True, framework_models=True,
                 max_side_effect_seconds=0, php_version=None, max_side_effect_bindings=0):
        self.symbols, self.library_mode = symbols, library_mode
        self.php_version = php_version
        self.experimental_foreach_cfg = experimental_foreach_cfg
        self.experimental_side_effects = experimental_side_effects
        self.max_side_effect_seconds = max_side_effect_seconds
        self.max_side_effect_bindings = max_side_effect_bindings
        self.effect_bindings = 0
        self._effects_building = False
        self._effect_deadline = None
        self._effect_budget_checks = 0
        self.experimental_demand_summaries = experimental_demand_summaries
        self.return_demands = set()
        self.effect_demands = set()
        self.summary_evidence_truncated = False
        self.field_paths_widened = False
        self.files = {path: FileFlow(self, path, root, source) for path, (root, source) in parsed_files.items()}
        self.registry = defaultdict(list)
        self.functions = []
        for engine in self.files.values():
            for f in engine.functions.values():
                if f.name:
                    name = f.class_name + "::" + f.name if f.class_name else (f.namespace + "\\" + f.name).strip("\\")
                    self.registry[name.lower()].append(f)
                    self.functions.append(f)
        self.returns, self.sinks, self.effects = {}, {}, {}
        self.library_properties = defaultdict(tuple)
        self.library_property_rounds = 0
        self.resolutions = {}
        self.receiver_classes = {}
        self.framework_dispatch = FrameworkDispatch(self, framework_models)
        self.constant_definitions = defaultdict(list)
        for engine in self.files.values():
            for nodes in engine.nodes.values():
                for node in nodes:
                    if node.type == "function_call_expression" and engine.call_name(node) == "define" and not self.resolve(engine, node):
                        args = arguments(node)
                        if len(args) >= 2:
                            name = literal(expression(args[0]), engine.source)
                            if name:
                                self.constant_definitions[name].append((engine, node, expression(args[1])))
        self.converged = False
        for engine in self.files.values():
            engine.discover_guards()
        self.phar_validators = {}
        for function in self.functions:
            engine = function.engine
            body = function.node.child_by_field_name('body')
            if body is None:
                continue
            statements = [n for n in body.named_children if n.type != 'comment']
            for guard, access in engine.guards:
                if not statements or guard != statements[0]:
                    continue
                returns = list(find_nodes_by_type(guard, 'return_statement'))
                if not returns or any(engine.text(n).strip() != 'return false;' for n in returns):
                    continue
                if any(a.start_byte < guard.end_byte for a, _ in engine.writes.get((function.node.start_byte, access[0]), ())):
                    continue
                for index, (name, _) in enumerate(function.params):
                    if access == (name,):
                        self.phar_validators[function.key] = index
        for engine in self.files.values():
            engine.discover_validator_guards()
        if library_mode:
            self._index_library_properties()

    def _index_library_properties(self):
        """Recompute constructor properties using the current return summaries.

        Only may-writes that can escape the constructor are retained. Replace
        the previous map instead of accumulating stale taint after a kill.
        """
        updated = defaultdict(tuple)
        for function in self.functions:
            if function.name.lower() != "__construct" or not function.public or not function.class_name:
                continue
            engine = function.engine
            scope = function.node.start_byte
            cfg = engine.cfgs.get(scope)
            for (write_scope, _), writes in engine.writes.items():
                if write_scope != scope:
                    continue
                for assign, target in writes:
                    if len(target) != 1 or not target[0].startswith("$this->"):
                        continue
                    if not engine.reachable(assign, scope):
                        continue
                    if cfg and not cfg.effect_can_escape(assign, target, writes, normal_only=True):
                        continue
                    value = engine.evaluate(assign.child_by_field_name("right"), symbolic=False)
                    if not value:
                        continue
                    value = engine._append(value, assign, "Property assigned from a public constructor.", target[0])
                    # PHP property names are case-sensitive, unlike class names.
                    key = (function.class_name.lower(), target[0])
                    updated[key] = merge(updated[key], value)
        signature = lambda mapping: {key: frozenset(flow.key() for flow in flows)
                                     for key, flows in mapping.items() if flows}
        changed = signature(updated) != signature(self.library_properties)
        self.library_properties = updated
        self.library_property_rounds += 1
        return changed

    def targets(self, engine, call):
        target = self.resolve(engine, call)
        return (target,) if target else self.framework_dispatch.targets(engine, call)

    def method_candidates(self, class_name, method, visited=None):
        """Class implementation, then unadapted traits, then parent; ambiguity stays unresolved."""
        visited = set() if visited is None else visited
        key = class_name.strip("\\").lower()
        if key in visited or len(visited) >= 32:
            return []
        visited = visited | {key}
        direct = self.registry.get(key + "::" + method.lower(), [])
        if direct:
            return direct
        owner = self.symbols.get_class(class_name.strip("\\")) if self.symbols else None
        if owner is None or owner.trait_adaptations:
            return []
        traits = {}
        for trait in owner.traits:
            for function in self.method_candidates(trait, method, visited):
                traits[function.key] = function
        if traits:
            return list(traits.values())
        parent = owner.resolved_parent or owner.parent_class
        return self.method_candidates(parent, method, visited) if parent else []

    def resolve(self, engine, call):
        cache_key = engine.path, call.id
        if cache_key in self.resolutions:
            return self.resolutions[cache_key]
        name = engine.call_name(call)
        context = engine.functions.get(engine.scope.get(call.id, -1))
        namespace = engine.namespaces.get(call.id, "")
        cls = ""
        if call.type in ("member_call_expression", "nullsafe_member_call_expression"):
            obj = call.child_by_field_name("object")
            cls = receiver_class(engine, obj, call, namespace)
            if not cls:
                self.resolutions[cache_key] = None
                return None
        elif call.type == "scoped_call_expression":
            cls = engine.text(call.child_by_field_name("scope"))
            if cls.lower() in ("self", "static"):
                cls = context.class_name if context else ""
            elif cls.lower() == "parent" and context and self.symbols:
                parent = self.symbols.get_class(context.class_name)
                cls = parent.resolved_parent or parent.parent_class if parent else ""
            elif self.symbols:
                cls = self.symbols.resolve_class_name(cls, namespace, engine.path)
        candidates = []
        if cls:
            self.receiver_classes[cache_key] = cls
            candidates = self.method_candidates(cls, name)
        elif call.type == "function_call_expression":
            raw = engine.text(call.child_by_field_name("function"))
            imported = engine.function_imports.get((namespace.lower(), raw.lower()))
            if not raw.startswith("\\") and namespace and not imported:
                candidates = self.registry.get((namespace + "\\" + name).lower(), [])
            if not candidates:
                candidates = self.registry.get(name, [])
        local = [f for f in candidates if f.engine.path == engine.path]
        result = candidates[0] if len(candidates) == 1 else local[0] if not cls and len(local) == 1 else None
        self.resolutions[cache_key] = result
        return result

    def check_effect_budget(self, force=False):
        deadline = self._effect_deadline
        if deadline is None:
            return
        self._effect_budget_checks += 1
        if (force or self._effect_budget_checks % 256 == 0) and time.perf_counter() >= deadline:
            raise SideEffectBudgetExceeded(
                f"Experimental side-effect analysis exceeded {self.max_side_effect_seconds:g} seconds")

    def build(self, max_rounds=64):
        """Solve callee components before propagating summaries to callers.

        Only changed summaries reschedule callers inside a recursive component.
        The budget still bounds recursive growth and reports unfinished work.
        """
        self._effects_building = self.experimental_side_effects
        self.effect_bindings = 0
        self._effect_deadline = (time.perf_counter() + self.max_side_effect_seconds
                                 if self.experimental_side_effects and self.max_side_effect_seconds
                                 else None)
        self._effect_budget_checks = 0
        dependents = defaultdict(set)
        dependencies = {f.key: set() for f in self.functions}
        for f in self.functions:
            for node in f.engine.calls_in_scope(f.node.start_byte):
                for target in self.targets(f.engine, node):
                    dependents[target.key].add(f.key)
                    dependencies[f.key].add(target.key)
        functions = {f.key: f for f in self.functions}
        components = summary_components({key: sorted(value) for key, value in dependencies.items()})
        component_ids = {key: index for index, component in enumerate(components) for key in component}
        queue = deque()
        pending = set()
        next_component = 0
        self.summary_evaluations = 0
        known_returns = set(self.return_demands)
        known_effects = set(self.effect_demands)
        finished = False
        budget = max(10000, len(functions) * max_rounds)
        while self.summary_evaluations < budget:
            self.check_effect_budget(force=True)
            if not queue and next_component == len(components):
                if self.library_mode:
                    # Constructor expressions may use helper return summaries
                    # unavailable during indexing. Property changes must also
                    # invalidate methods that consumed the previous map.
                    for engine in self.files.values():
                        engine.cache.clear()
                        engine.effect_index.clear()
                        engine.loop_results.clear()
                    if self._index_library_properties():
                        queue.extend(sorted(functions, key=lambda key: component_ids[key]))
                        pending.update(queue)
                if self.experimental_demand_summaries:
                    # Top-level callers can introduce return dependencies only
                    # after their callees' sink summaries have become available.
                    for engine in self.files.values():
                        engine.cache.clear()
                        engine.effect_index.clear()
                        engine.loop_results.clear()
                        engine.direct_sinks(-1, True)
                        engine.forwarded_sinks(-1, True)
                    new_demands = (self.return_demands - known_returns) | (self.effect_demands - known_effects)
                    known_returns.update(self.return_demands)
                    known_effects.update(self.effect_demands)
                    queue.extend(sorted(new_demands - pending, key=lambda key: component_ids[key]))
                    pending.update(queue)
                if not queue:
                    finished = True
                    break
            if not queue:
                queue.extend(components[next_component])
                pending.update(queue)
                next_component += 1
            key = queue.popleft()
            pending.remove(key)
            f = functions[key]
            e, scope = f.engine, f.node.start_byte
            e.cache.clear()
            e.effect_index.clear()
            e.loop_results.clear()
            returns = merge(*(e.evaluate(n.named_children[0], symbolic=True) for n in e.nodes[scope]
                              if n.type == "return_statement" and n.named_children
                              and e.reachable(n, scope) and e.return_value_escapes(n))) if (
                                  not self.experimental_demand_summaries or key in self.return_demands) else ()
            sinks, truncated = compact_sink_summaries(e.direct_sinks(scope, True) + e.forwarded_sinks(scope, True))
            effects = e.reference_effects(f) if (
                not self.experimental_demand_summaries or key in self.effect_demands) else ()
            effect_signature = lambda items: {(i, fields, flow.key()) for i, fields, flows in items for flow in flows}
            self.summary_evidence_truncated |= truncated
            changed = ({v.key() for v in returns} != {v.key() for v in self.returns.get(key, ())}
                       or {v.key() for v in sinks} != {v.key() for v in self.sinks.get(key, ())}
                       or effect_signature(effects) != effect_signature(self.effects.get(key, ())))
            self.returns[key], self.sinks[key] = returns, sinks
            self.effects[key] = effects
            self.summary_evaluations += 1
            if self.experimental_demand_summaries:
                new_demands = (self.return_demands - known_returns) | (self.effect_demands - known_effects)
                known_returns.update(self.return_demands)
                known_effects.update(self.effect_demands)
                for demanded in sorted(new_demands, key=lambda item: component_ids[item]):
                    if component_ids[demanded] < next_component and demanded not in pending:
                        pending.add(demanded)
                        queue.append(demanded)
            if changed:
                for caller in sorted(dependents[key]):
                    reschedule = (component_ids[caller] < next_component if self.experimental_demand_summaries
                                  else component_ids[caller] == component_ids[key])
                    if reschedule and caller not in pending:
                        pending.add(caller)
                        queue.append(caller)
        self.converged = finished
        self.rounds = 0  # Legacy field: worklist evaluations are reported separately.
        for engine in self.files.values():
            engine.cache.clear()
            engine.effect_index.clear()
            engine.loop_results.clear()
        self._effects_building = False
        self._effect_deadline = None

    @staticmethod
    def _signature(returns, sinks):
        return ({k: frozenset(f.key() for f in v) for k, v in returns.items()}, {k: frozenset(s.key() for s in v) for k, v in sinks.items()})
