"""Narrow, evidence-based class loading for a known PHP entrypoint.

Literal includes anchor entrypoints; their order and a narrow glob exclusion
constrain local class availability. A matching Composer PSR-4 declaration plus
an observed autoloader include is only a candidate, not runtime proof.
"""

import fnmatch
import json
import os
from collections import defaultdict

from php_deserial_sast.core.dataflow import literal
from php_deserial_sast.core.parser import find_nodes_by_type


INCLUDES = ('include_expression', 'include_once_expression',
            'require_expression', 'require_once_expression')
CONDITIONAL_CONTAINERS = {
    'if_statement', 'else_clause', 'switch_statement', 'case_statement',
    'while_statement', 'do_statement', 'for_statement', 'foreach_statement',
    'conditional_expression', 'match_expression', 'binary_expression',
    'try_statement', 'catch_clause', 'finally_clause', 'function_definition',
    'method_declaration', 'anonymous_function_creation_expression',
    'anonymous_function', 'arrow_function',
}


def _unwrap(node):
    while node is not None and node.type in {'parenthesized_expression', 'argument'}:
        node = node.named_children[0] if node.named_children else None
    return node


def _literal_include(engine, node):
    value, anchored = _constant_include_path(
        engine, node.named_children[0]) if node.named_children else (None, False)
    if (not isinstance(value, str) or not value or '://' in value
            or (os.path.isabs(value) and not anchored)):
        return None
    path = value if anchored else os.path.join(os.path.dirname(engine.path), value)
    return os.path.normcase(os.path.normpath(path))


def _constant_include_path(engine, node, depth=0):
    """Evaluate only fixed PHP include paths; never guess variable values."""
    node = _unwrap(node)
    if node is None or depth > 8:
        return None, False
    value = literal(node, engine.source)
    if isinstance(value, str):
        return value, False
    if node.type == 'name':
        magic = engine.text(node).upper()
        if magic == '__DIR__':
            return os.path.dirname(engine.path), True
        if magic == '__FILE__':
            return engine.path, True
    if node.type == 'binary_expression':
        operator = node.child_by_field_name('operator')
        if operator is None or engine.text(operator) != '.':
            return None, False
        left = node.child_by_field_name('left')
        right = node.child_by_field_name('right')
        first, first_anchored = _constant_include_path(engine, left, depth + 1)
        second, second_anchored = _constant_include_path(engine, right, depth + 1)
        if first is not None and second is not None:
            return first + second, first_anchored or second_anchored
    if (node.type == 'function_call_expression' and engine.call_name(node) == 'dirname'
            and not engine.project.resolve(engine, node)):
        args = node.child_by_field_name('arguments')
        if args is not None and len(args.named_children) == 1:
            value, anchored = _constant_include_path(engine, args.named_children[0], depth + 1)
            if anchored and value is not None:
                return os.path.dirname(value), True
    return None, False


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
    parents = _entrypoint_index(project).get(target, ())
    if parents:
        return parents
    # A PHP file that starts its own session can be the writer endpoint itself.
    # This establishes a candidate route, not web exposure or request order.
    cache = getattr(project, '_class_loading_self_entrypoints', None)
    if cache is None:
        cache = {}
        project._class_loading_self_entrypoints = cache
    if target not in cache:
        engine = project.files.get(file_path)
        cache[target] = (engine,) if engine and _starts_session(project, engine) else ()
    return cache[target]


def _starts_session(project, engine):
    """Recognize a top-level builtin session_start, excluding dormant methods."""
    for call in find_nodes_by_type(engine.root, 'function_call_expression'):
        if engine.call_name(call) != 'session_start' or project.resolve(engine, call):
            continue
        ancestor = call.parent
        while ancestor is not None and ancestor != engine.root:
            if ancestor.type in {'function_definition', 'method_declaration',
                                 'anonymous_function_creation_expression',
                                 'anonymous_function', 'arrow_function'}:
                break
            ancestor = ancestor.parent
        else:
            return True
    return False


def session_bootstrap_evidence(project, sink_file, render_file):
    """Observe session_start on both explicit routes, without proving identity."""
    roots = _common_entrypoints(project, sink_file, render_file)
    if roots:
        pairs = [(root, root) for root in roots]
    else:
        pairs = [(writer, reader)
                 for writer in _entrypoints_for(project, sink_file)
                 for reader in _entrypoints_for(project, render_file)]
    observed = [(writer.path, reader.path) for writer, reader in pairs
                if _starts_session(project, writer) and _starts_session(project, reader)]
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


def _status_in_entrypoint(project, engine, class_file, before_file=None):
    path = os.path.normcase(os.path.normpath(class_file))
    if path == os.path.normcase(os.path.normpath(engine.path)):
        return 'included'
    includes = list(find_nodes_by_type(engine.root, INCLUDES))
    cutoff = None
    if before_file and os.path.normcase(os.path.normpath(before_file)) != os.path.normcase(os.path.normpath(engine.path)):
        target = os.path.normcase(os.path.normpath(before_file))
        boundary = [node.start_byte for node in includes
                    if _literal_include(engine, node) == target]
        if boundary:
            cutoff = min(boundary)
    direct = [node for node in includes if _literal_include(engine, node) == path]
    if any(_unconditional_at_top_level(engine, node)
           and (cutoff is None or node.start_byte < cutoff) for node in direct):
        return 'included'
    relative = os.path.relpath(class_file, os.path.dirname(engine.path)).replace('\\', '/')
    statuses = []
    recognized = set()
    for loop in find_nodes_by_type(engine.root, 'foreach_statement'):
        if cutoff is not None and loop.start_byte >= cutoff:
            continue
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
    if _composer_autoload_candidate(project, engine, class_file, includes, cutoff):
        return 'composer_autoload_candidate'
    if direct:
        return 'unknown'
    if statuses and all(status == 'excluded' for status in statuses):
        return 'excluded'
    return 'unknown'


def _unconditional_at_top_level(engine, node):
    ancestor = node.parent
    while ancestor is not None and ancestor != engine.root:
        if ancestor.type in CONDITIONAL_CONTAINERS:
            return False
        ancestor = ancestor.parent
    return ancestor == engine.root


def _composer_autoload_files(project):
    """Match declared PSR-4 paths; this is configuration, not runtime proof."""
    cached = getattr(project, '_class_loading_composer_files', None)
    if cached is not None:
        return cached
    matched = set()
    project._class_loading_composer_files = matched
    if not project.files or project.symbols is None:
        return matched
    root = os.path.commonpath([os.path.abspath(path) for path in project.files])
    if not os.path.isdir(root):
        root = os.path.dirname(root)
    composer_path = os.path.join(root, 'composer.json')
    autoload_path = os.path.join(root, 'vendor', 'autoload.php')
    if not os.path.isfile(composer_path) or not os.path.isfile(autoload_path):
        return matched
    try:
        with open(composer_path, encoding='utf-8') as stream:
            config = json.load(stream)
        if not isinstance(config, dict) or not isinstance(config.get('autoload'), dict):
            return matched
        mappings = config['autoload'].get('psr-4', {})
        if not isinstance(mappings, dict):
            return matched
        for cls in project.symbols.get_all_unique_classes():
            name = (cls.full_name or cls.name).lstrip('\\')
            actual = os.path.normcase(os.path.abspath(cls.file_path))
            for prefix, directories in mappings.items():
                if (not isinstance(prefix, str) or prefix and not prefix.endswith('\\')
                        or not name.startswith(prefix)):
                    continue
                suffix = name[len(prefix):].replace('\\', os.sep) + '.php'
                for directory in ([directories] if isinstance(directories, str) else
                                  directories if isinstance(directories, list) else ()):
                    if not isinstance(directory, str):
                        continue
                    expected = os.path.normcase(os.path.abspath(os.path.join(root, directory, suffix)))
                    if expected == actual:
                        matched.add(actual)
                        break
    except (OSError, ValueError, TypeError):
        return matched
    return matched


def _composer_autoload_candidate(project, engine, class_file, includes, cutoff):
    if os.path.normcase(os.path.abspath(class_file)) not in _composer_autoload_files(project):
        return False
    root = os.path.commonpath([os.path.abspath(path) for path in project.files])
    if not os.path.isdir(root):
        root = os.path.dirname(root)
    loader = os.path.normcase(os.path.join(root, 'vendor', 'autoload.php'))
    for node in includes:
        target = _literal_include(engine, node)
        if (target and os.path.normcase(os.path.abspath(target)) == loader
                and _unconditional_at_top_level(engine, node)
                and (cutoff is None or node.start_byte < cutoff)):
            return True
    return False


def class_loading_status(project, sink_file, render_file, class_file):
    """Return (status, entrypoints) for the observed source/render pair."""
    roots = _common_entrypoints(project, sink_file, render_file)
    if roots:
        statuses = []
        for engine in roots:
            pair = (_status_in_entrypoint(project, engine, class_file, sink_file),
                    _status_in_entrypoint(project, engine, class_file, render_file))
            statuses.append('included' if pair == ('included', 'included') else
                            'composer_autoload_candidate' if all(item in {
                                'included', 'composer_autoload_candidate'} for item in pair) else
                            'excluded' if 'excluded' in pair else 'unknown')
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
                pair = (_status_in_entrypoint(project, writer, class_file, sink_file),
                        _status_in_entrypoint(project, reader, class_file, render_file))
                statuses.append('included' if pair == ('included', 'included') else
                                'composer_autoload_candidate' if all(item in {
                                    'included', 'composer_autoload_candidate'} for item in pair) else
                                'excluded' if 'excluded' in pair else 'unknown')
    if 'included' in statuses:
        status = 'included'
    elif 'composer_autoload_candidate' in statuses:
        status = 'composer_autoload_candidate'
    elif all(item == 'excluded' for item in statuses):
        status = 'excluded'
    else:
        status = 'unknown'
    return status, sorted(entrypoints)
