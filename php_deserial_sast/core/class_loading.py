"""Narrow, evidence-based class loading for a known PHP entrypoint.

Only a literal include shared by the deserialization and render files anchors
an entrypoint. A simple glob include may then prove that one local class file
is skipped by an exact path inequality. Other loading mechanisms stay unknown.
"""

import fnmatch
import os
from collections import defaultdict

from php_deserial_sast.core.dataflow import literal
from php_deserial_sast.core.parser import find_nodes_by_type


INCLUDES = ('include_expression', 'include_once_expression',
            'require_expression', 'require_once_expression')


def _unwrap(node):
    while node is not None and node.type in {'parenthesized_expression', 'argument'}:
        node = node.named_children[0] if node.named_children else None
    return node


def _literal_include(engine, node):
    value = literal(_unwrap(node.named_children[0]), engine.source) if node.named_children else None
    if not isinstance(value, str) or not value or '://' in value or os.path.isabs(value):
        return None
    return os.path.normcase(os.path.normpath(os.path.join(os.path.dirname(engine.path), value)))


def _common_entrypoints(project, sink_file, render_file):
    sink = os.path.normcase(os.path.normpath(sink_file))
    render = os.path.normcase(os.path.normpath(render_file))
    index = _entrypoint_index(project)
    readers = {engine.path for engine in index.get(render, ())}
    return [engine for engine in index.get(sink, ()) if engine.path in readers]


def _entrypoint_index(project):
    """Index literal includes once; dispatch may query many candidate classes."""
    index = getattr(project, '_class_loading_entrypoint_index', None)
    if index is None:
        index = defaultdict(list)
        for engine in project.files.values():
            targets = {_literal_include(engine, node)
                       for node in find_nodes_by_type(engine.root, INCLUDES)}
            for target in targets - {None}:
                index[target].append(engine)
        project._class_loading_entrypoint_index = index
    return index


def _entrypoints_for(project, file_path):
    target = os.path.normcase(os.path.normpath(file_path))
    return _entrypoint_index(project).get(target, ())


def session_bootstrap_evidence(project, sink_file, render_file):
    """Observe session_start on both explicit routes, without proving identity."""
    roots = _common_entrypoints(project, sink_file, render_file)
    if roots:
        pairs = [(root, root) for root in roots]
    else:
        pairs = [(writer, reader)
                 for writer in _entrypoints_for(project, sink_file)
                 for reader in _entrypoints_for(project, render_file)]
    def starts_session(engine):
        return any(engine.call_name(node) == 'session_start'
                   and not project.resolve(engine, node)
                   for node in find_nodes_by_type(engine.root, 'function_call_expression'))
    observed = [(writer.path, reader.path) for writer, reader in pairs
                if starts_session(writer) and starts_session(reader)]
    return {'session_start_on_both_routes': bool(observed),
            'entrypoint_pairs': [list(pair) for pair in observed[:16]],
            'session_identity_and_request_order_verified': False}


def _glob_matches(pattern, relative):
    pattern_parts = os.path.normcase(pattern.replace('\\', '/')).split('/')
    relative_parts = os.path.normcase(relative.replace('\\', '/')).split('/')
    return len(pattern_parts) == len(relative_parts) and all(
        fnmatch.fnmatchcase(part, mask) for part, mask in zip(relative_parts, pattern_parts)
    )


def _guard_status(engine, include, loop, binding, relative):
    current = include.parent
    while current is not None and current != loop:
        if current.type == 'if_statement':
            if any(child.type == 'else_clause' for child in current.named_children):
                return 'unknown'
            condition = _unwrap(current.child_by_field_name('condition'))
            if condition is None or condition.type != 'binary_expression':
                return 'unknown'
            left, right = condition.child_by_field_name('left'), condition.child_by_field_name('right')
            operator = condition.child_by_field_name('operator')
            if operator is None or left is None or right is None:
                return 'unknown'
            left_text, right_text = engine.text(left), engine.text(right)
            excluded = (literal(right, engine.source) if left_text == binding else
                        literal(left, engine.source) if right_text == binding else None)
            if not isinstance(excluded, str):
                return 'unknown'
            op = engine.text(operator)
            if op in {'!==', '!='}:
                return 'excluded' if os.path.normcase(excluded.replace('\\', '/')) == os.path.normcase(relative) else 'included'
            return 'unknown'
        current = current.parent
    return 'included' if current == loop else 'unknown'


def _status_in_entrypoint(engine, class_file):
    path = os.path.normcase(os.path.normpath(class_file))
    if path == os.path.normcase(os.path.normpath(engine.path)):
        return 'included'
    includes = list(find_nodes_by_type(engine.root, INCLUDES))
    if path in {_literal_include(engine, node) for node in includes}:
        return 'included'
    relative = os.path.relpath(class_file, os.path.dirname(engine.path)).replace('\\', '/')
    statuses = []
    recognized = set()
    for loop in find_nodes_by_type(engine.root, 'foreach_statement'):
        parts = [node for node in loop.named_children if node.type != 'comment']
        if len(parts) < 3 or parts[0].type != 'function_call_expression':
            continue
        glob = parts[0]
        if engine.call_name(glob) != 'glob':
            continue
        args = glob.child_by_field_name('arguments')
        pattern = literal(_unwrap(args.named_children[0]), engine.source) if args and args.named_children else None
        if not isinstance(pattern, str) or not _glob_matches(pattern, relative):
            continue
        binding = engine.text(parts[1])
        if not binding.startswith('$'):
            continue
        for include in find_nodes_by_type(loop, INCLUDES):
            if engine.text(_unwrap(include.named_children[0])) != binding:
                continue
            recognized.add(include.id)
            statuses.append(_guard_status(engine, include, loop, binding, relative))
    # An unrelated dynamic include may load the class by a route this narrow
    # model does not understand, so it prevents a definite exclusion.
    if any(node.id not in recognized and _literal_include(engine, node) is None
           for node in includes):
        return 'unknown'
    if 'included' in statuses:
        return 'included'
    if statuses and all(status == 'excluded' for status in statuses):
        return 'excluded'
    return 'unknown'


def class_loading_status(project, sink_file, render_file, class_file):
    """Return (status, entrypoints) for the observed source/render pair."""
    roots = _common_entrypoints(project, sink_file, render_file)
    if roots:
        statuses = [_status_in_entrypoint(engine, class_file) for engine in roots]
        entrypoints = [engine.path for engine in roots]
    else:
        # A restored session object may be written and read by different PHP
        # entrypoints. Both routes must explicitly include their respective
        # files; merely finding the same class somewhere in the tree is weak.
        writers = _entrypoints_for(project, sink_file)
        readers = _entrypoints_for(project, render_file)
        if not writers or not readers:
            return 'unknown', []
        statuses = []
        entrypoints = set()
        for writer in writers:
            for reader in readers:
                entrypoints.update((writer.path, reader.path))
                pair = (_status_in_entrypoint(writer, class_file),
                        _status_in_entrypoint(reader, class_file))
                statuses.append('included' if pair == ('included', 'included') else
                                'excluded' if 'excluded' in pair else 'unknown')
    if 'included' in statuses:
        status = 'included'
    elif all(item == 'excluded' for item in statuses):
        status = 'excluded'
    else:
        status = 'unknown'
    return status, sorted(entrypoints)
