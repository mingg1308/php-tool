"""Locate coverage limitations along retained evidence and resolved callees."""
from collections import defaultdict
from php_deserial_sast.core.dataflow import CALLS, SCALAR_FUNCTIONS, TRANSFORMS, PATH_ARGUMENTS, DESERIALIZATION_FUNCTIONS
from php_deserial_sast.core.parser import get_node_location

MODELED_BUILTINS = SCALAR_FUNCTIONS | TRANSFORMS | set(PATH_ARGUMENTS) | DESERIALIZATION_FUNCTIONS | {"filter_input", "filter_input_array", "fopen", "isset", "empty", "unset", "eval", "exit", "die"}


class FindingCoverage:
    def __init__(self, project):
        self.project = project
        self.scopes = defaultdict(list)
        self.lookup_cache = {}
        self.callees = {}
        self.unresolved = {}
        if project is None:
            return
        for path, engine in project.files.items():
            for scope, function in engine.functions.items():
                node = function.node
                self.scopes[path].append((node.start_point, node.end_point, scope))
            self.scopes[path].sort(key=lambda row: row[0], reverse=True)

    def scope_at(self, location):
        key = (location.file_path, location.start_line, location.start_col)
        if key not in self.lookup_cache:
            point = (location.start_line - 1, location.start_col - 1)
            self.lookup_cache[key] = next((scope for start, end, scope in self.scopes[key[0]]
                                           if start <= point < end), -1)
        return self.lookup_cache[key]

    def annotate(self, finding):
        if self.project is None:
            return
        locations = [finding.location]
        locations.extend(step.location for step in finding.dataflow_trace or ())
        for route in finding.flow_evidence:
            locations.extend(step.location for step in route.trace)
        if finding.gadget_chain:
            locations.extend(step.location for step in finding.gadget_chain.steps)
        pending = [(loc.file_path, self.scope_at(loc)) for loc in locations]
        seen, fallbacks, exceptions, missing = set(), [], [], set()
        unresolved = []
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            path, scope = key
            engine = self.project.files.get(path)
            if engine is None:
                missing.add(path)
                continue
            cfg = engine.cfgs.get(scope)
            function = engine.functions.get(scope)
            row = {"file": path, "scope": function.name if function else "<top-level>",
                   "line": function.node.start_point[0] + 1 if function else 1}
            if cfg and not cfg.supported:
                fallbacks.append({**row, "reasons": sorted(cfg.unsupported)})
            if cfg and cfg.has_exceptions:
                exceptions.append(row)
            if key not in self.callees:
                targets = set()
                unknown = []
                for node in engine.nodes.get(scope, ()):
                    if node.type in CALLS and engine.reachable(node, scope):
                        resolved = self.project.targets(engine, node)
                        if resolved:
                            targets.update(target.key for target in resolved)
                        else:
                            callee = node.child_by_field_name("function")
                            static_function = (node.type == "function_call_expression" and callee is not None
                                               and callee.type in {"name", "qualified_name"})
                            if not static_function or engine.call_name(node) not in MODELED_BUILTINS:
                                unknown.append({"location": get_node_location(node, path).model_dump(),
                                    "call": engine.text(node)[:240],
                                    "kind": "external_or_missing_function" if static_function else "unresolved_dispatch"})
                self.callees[key] = targets
                self.unresolved[key] = unknown
            unresolved.extend(self.unresolved[key])
            pending.extend(self.callees[key] - seen)
        unresolved.sort(key=lambda row: (row['location']['file_path'], row['location']['start_line'], row['location']['start_col']))
        finding.metadata['dependency_coverage'] = {
            'basis': 'retained_evidence_and_resolved_callees',
            'complete_dependency_graph': False,
            'files': sorted({path for path, _ in seen}),
            'scopes': len(seen),
            'fallback_scopes': sorted(fallbacks, key=lambda r: (r['file'], r['line'])),
            'exception_scopes': sorted(exceptions, key=lambda r: (r['file'], r['line'])),
            'missing_files': sorted(missing),
            'unresolved_call_count': len(unresolved),
            'unresolved_calls': unresolved[:32],
            'unresolved_calls_truncated': len(unresolved) > 32,
            'limitations': ['dynamic_dispatch_and_omitted_trace_dependencies_not_exhaustive'],
        }
        finding.metadata['exception_flow_approximation'] = bool(exceptions)
