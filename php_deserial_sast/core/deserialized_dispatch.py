"""Bounded, conditional dispatch evidence for objects restored into PHP sessions.

This records possible methods on a serialized object across requests. It does
not claim that a particular class was supplied, loaded, or invoked at runtime.
"""

from collections import deque

from php_deserial_sast.core.class_loading import class_loading_status, session_bootstrap_evidence
from php_deserial_sast.core.dataflow import literal
from php_deserial_sast.core.parser import find_nodes_by_type, get_node_location


def _assignment_containing(call):
    current = call
    while current.parent is not None:
        parent = current.parent
        if parent.type == 'assignment_expression':
            right = parent.child_by_field_name('right')
            return parent if right and right.start_byte <= call.start_byte < right.end_byte else None
        if parent.type in {'function_definition', 'method_declaration', 'anonymous_function',
                           'anonymous_function_creation_expression', 'arrow_function'}:
            break
        current = parent
    return None


def _session_stores(engine, sink_call):
    source_assignment = _assignment_containing(sink_call)
    if source_assignment is None:
        return []
    source_access = engine.access(source_assignment.child_by_field_name('left'))
    stores = []
    assignments = sorted(find_nodes_by_type(engine.root, 'assignment_expression'),
                         key=lambda node: node.start_byte)

    def unchanged(access, start, end):
        return not any(
            start.end_byte < write.start_byte < end.start_byte
            and target == access and engine.compatible(write, end)
            for write, target in engine.writes.get((engine.scope.get(end.id, -1), access[0]), ())
        )

    for assignment in assignments:
        target = engine.access(assignment.child_by_field_name('left'))
        if not target or len(target) != 2 or target[0] != '$_SESSION' or target[1] is None:
            continue
        right = assignment.child_by_field_name('right')
        right_access = engine.access(right)
        if assignment == source_assignment:
            stores.append((target[1], get_node_location(assignment, engine.path)))
            continue
        if (not source_access or len(source_access) != 1
                or engine.scope.get(assignment.id, -1) != engine.scope.get(sink_call.id, -1)
                or assignment.start_byte <= source_assignment.end_byte
                or not engine.compatible(source_assignment, assignment)):
            continue
        if right_access == source_access and unchanged(source_access, source_assignment, assignment):
            stores.append((target[1], get_node_location(assignment, engine.path)))
            continue
        # An object can first be placed in an array element and the whole
        # array stored in the session, as in $items[$i]=$obj; $_SESSION['x']=$items.
        if not right_access or len(right_access) != 1:
            continue
        for element in assignments:
            if not (source_assignment.end_byte < element.start_byte < assignment.start_byte
                    and engine.scope.get(element.id, -1) == engine.scope.get(assignment.id, -1)
                    and engine.compatible(source_assignment, element)
                    and engine.compatible(element, assignment)):
                continue
            element_target = engine.access(element.child_by_field_name('left'))
            if (not element_target or len(element_target) < 2
                    or element_target[0] != right_access[0]
                    or engine.access(element.child_by_field_name('right')) != source_access):
                continue
            if (unchanged(source_access, source_assignment, element)
                    and unchanged(right_access, element, assignment)):
                stores.append((target[1], get_node_location(assignment, engine.path)))
                break
    return stores


def _method_owner(symbols, cls, name):
    name = name.lower()
    for owner in symbols.resolve_inheritance(cls.full_name or cls.name):
        for method in owner.methods.values():
            if method.name.lower() == name and method.visibility == 'public':
                return owner, method
    return None


def _session_key_replaced(engine, key, use):
    """Reject a later read after a definite local replacement of its key."""
    scope = engine.scope.get(use.id, -1)
    return any(target == ('$_SESSION', key)
               and write.type == 'assignment_expression'
               and write.end_byte <= use.start_byte
               and engine.dominates(write, use)
               and literal(write.child_by_field_name('right'), engine.source) is not None
               for write, target in engine.writes.get((scope, '$_SESSION'), ()))


def _reachable_sinks(graph, owner, method, max_depth=4, max_expansions=128):
    start = f'{owner.full_name or owner.name}::{method.name}'
    pending = deque([(start, 0)])
    seen = {start}
    sinks = []
    expansions = 0
    while pending and expansions < max_expansions and len(sinks) < 8:
        node, depth = pending.popleft()
        if depth >= max_depth:
            continue
        for successor, edge in sorted(graph.get_successors(node), key=lambda item: item[0]):
            expansions += 1
            if expansions > max_expansions:
                break
            if successor.startswith('SINK::'):
                category = edge.call_info.sink_category
                if category in {'RCE', 'DYNAMIC_INVOCATION', 'FILE_WRITE', 'FILE_DELETE', 'FILE_READ_INCLUDE'}:
                    candidate = {'function': edge.call_info.callee_name, 'category': category,
                                 'location': edge.call_info.location.model_dump() if edge.call_info.location else None}
                    if candidate not in sinks:
                        sinks.append(candidate)
            elif successor not in seen:
                seen.add(successor)
                pending.append((successor, depth + 1))
    return sinks


def annotate_session_dispatch(findings, project, graph):
    if project is None or graph is None or project.symbols is None:
        return
    observed = [finding for finding in findings
                if finding.metadata.get('sink_type') == 'DIRECT_UNSERIALIZE'
                and any(route.source_kind == 'request' and not route.uncertain
                        for route in finding.flow_evidence)]
    if not observed:
        return
    stores_by_finding = {}
    keys = set()
    for finding in observed:
        engine = project.files.get(finding.location.file_path)
        if engine is None:
            continue
        for nodes in engine.nodes.values():
            for call in nodes:
                if (call.type != 'function_call_expression' or engine.call_name(call) != 'unserialize'
                        or call.start_point[0] + 1 != finding.location.start_line
                        or call.start_point[1] + 1 != finding.location.start_col):
                    continue
                stores = _session_stores(engine, call)
                if stores:
                    stores_by_finding[finding.id] = stores
                    keys.update(key for key, _ in stores)
    if not keys:
        return
    calls_by_key = {key: {} for key in keys}
    for engine in project.files.values():
        for nodes in engine.nodes.values():
            for call in nodes:
                if call.type not in {'member_call_expression', 'nullsafe_member_call_expression'}:
                    continue
                access = engine.access(call.child_by_field_name('object'))
                if not access or len(access) != 2 or access[0] != '$_SESSION' or access[1] not in keys:
                    continue
                if _session_key_replaced(engine, access[1], call):
                    continue
                method = engine.call_name(call)
                if not method:
                    continue
                location = get_node_location(call, engine.path)
                identity = (engine.path, location.start_line, location.start_col, method)
                calls_by_key[access[1]][identity] = location
    renders_by_key = {key: {} for key in keys}
    for engine in project.files.values():
        for loop in find_nodes_by_type(engine.root, 'foreach_statement'):
            parts = [child for child in loop.named_children if child.type != 'comment']
            if len(parts) < 3:
                continue
            access = engine.access(parts[0])
            if not access or len(access) != 2 or access[0] != '$_SESSION' or access[1] not in keys:
                continue
            if _session_key_replaced(engine, access[1], loop):
                continue
            binding = parts[1]
            while binding.type in {'pair', 'by_ref'} and binding.named_children:
                binding = binding.named_children[-1]
            binding_access = engine.access(binding)
            if not binding_access or len(binding_access) != 1:
                continue
            for echo in find_nodes_by_type(loop, 'echo_statement'):
                if any(engine.access(variable) == binding_access
                       for variable in find_nodes_by_type(echo, 'variable_name')):
                    location = get_node_location(echo, engine.path)
                    renders_by_key[access[1]][(engine.path, location.start_line, location.start_col)] = location
    classes = sorted(project.symbols.get_all_unique_classes(), key=lambda cls: cls.full_name or cls.name)
    candidate_cache = {}
    loading_cache = {}
    bootstrap_cache = {}
    def bootstrap(sink_file, render_file):
        key = (sink_file, render_file)
        if key not in bootstrap_cache:
            bootstrap_cache[key] = session_bootstrap_evidence(project, sink_file, render_file)
        return bootstrap_cache[key]

    for finding in observed:
        stores = stores_by_finding.get(finding.id, ())
        if not stores:
            continue
        rows = []
        for key, store_location in stores[:16]:
            calls = calls_by_key.get(key, {})
            for (path, line, column, method_name), call_location in sorted(calls.items())[:32]:
                if method_name not in candidate_cache:
                    compatible = []
                    count = 0
                    for cls in classes:
                        resolved = _method_owner(project.symbols, cls, method_name)
                        if not resolved:
                            continue
                        count += 1
                        if len(compatible) >= 24:
                            continue
                        owner, method = resolved
                        parent = project.symbols.get_class(cls.resolved_parent or cls.parent_class) if (cls.resolved_parent or cls.parent_class) else None
                        compatible.append({
                            'class': cls.full_name or cls.name,
                            'method_owner': owner.full_name or owner.name,
                            'parent': cls.resolved_parent or cls.parent_class,
                            'overrides_parent_method': bool(parent and owner is cls
                                                            and _method_owner(project.symbols, parent, method_name)),
                            'dangerous_sinks': _reachable_sinks(graph, owner, method),
                        })
                    candidate_cache[method_name] = (compatible, count)
                compatible, count = candidate_cache[method_name]
                available = []
                excluded = []
                entrypoints = set()
                for candidate in compatible:
                    cls = project.symbols.get_class(candidate['class'])
                    if cls is None:
                        continue
                    loading_key = (finding.location.file_path, path, cls.file_path)
                    if loading_key not in loading_cache:
                        loading_cache[loading_key] = class_loading_status(
                            project, finding.location.file_path, path, cls.file_path)
                    loading, roots = loading_cache[loading_key]
                    entrypoints.update(roots)
                    row = dict(candidate, class_file=cls.file_path,
                               class_loading=loading)
                    if loading == 'excluded':
                        excluded.append(row)
                    else:
                        available.append(row)
                rows.append({
                    'session_key': key, 'store_location': store_location.model_dump(),
                    'call_location': call_location.model_dump(), 'method': method_name,
                    'candidate_classes': available, 'candidate_class_count': count - len(excluded),
                    'candidate_classes_truncated': count > len(compatible),
                    'excluded_candidates': excluded[:24],
                    'excluded_candidates_truncated': len(excluded) > 24,
                    'bootstrap_entrypoints': sorted(entrypoints),
                    'session_bootstrap': bootstrap(finding.location.file_path, path),
                    'cross_request_execution_unverified': True,
                })
        renders = []
        for key, store_location in stores[:16]:
            for location in list(renders_by_key.get(key, {}).values())[:16]:
                candidates = []
                excluded_candidates = []
                entrypoints = set()
                count = 0
                dangerous_count = 0
                for cls in classes:
                    resolved = _method_owner(project.symbols, cls, '__toString')
                    if not resolved:
                        continue
                    count += 1
                    owner, method = resolved
                    sinks = _reachable_sinks(graph, owner, method)
                    if sinks:
                        loading_key = (finding.location.file_path, location.file_path, cls.file_path)
                        if loading_key not in loading_cache:
                            loading_cache[loading_key] = class_loading_status(
                                project, finding.location.file_path, location.file_path, cls.file_path)
                        loading, roots = loading_cache[loading_key]
                        entrypoints.update(roots)
                        if loading == 'excluded':
                            excluded_candidates.append({
                                'class': cls.full_name or cls.name,
                                'class_file': cls.file_path,
                                'reason': 'excluded_by_observed_entrypoint_glob_guard',
                            })
                            continue
                        dangerous_count += 1
                        if len(candidates) < 24:
                            candidates.append({'class': cls.full_name or cls.name,
                                               'method_owner': owner.full_name or owner.name,
                                               'class_file': cls.file_path,
                                               'class_loading': loading,
                                               'dangerous_sinks': sinks})
                renders.append({'session_key': key, 'store_location': store_location.model_dump(),
                                'render_location': location.model_dump(),
                                'candidate_classes': candidates,
                                'candidate_class_count': dangerous_count,
                                'candidate_classes_truncated': dangerous_count > len(candidates),
                                'excluded_candidates': excluded_candidates[:24],
                                'excluded_candidates_truncated': len(excluded_candidates) > 24,
                                'bootstrap_entrypoints': sorted(entrypoints),
                                'session_bootstrap': bootstrap(finding.location.file_path, location.file_path),
                                'stringable_class_count': count,
                                'cross_request_execution_unverified': True})
        if not rows and not renders:
            continue
        finding.metadata['deserialized_session_dispatch'] = {
            'calls': rows[:32], 'calls_truncated': len(rows) > 32,
            'render_sites': renders[:16], 'render_sites_truncated': len(renders) > 16,
            'class_selection_unverified': True, 'runtime_class_loading_unverified': True,
            'exploitability_verified': False,
        }
