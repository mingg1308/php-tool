"""Bounded static evidence connecting a request write to a DB read.

Only explicit wpdb::insert calls and literal SELECT queries are matched.
This is a may-flow across executions, not proof of permissions or ordering.
"""

import re

from php_deserial_sast.core.dataflow import arguments, expression, literal
from php_deserial_sast.core.parser import get_node_location


SELECT = re.compile(r'\bselect\s+([A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)\s+'
                    r'from\s+([A-Za-z_][\w]*)\b', re.I)


def _wpdb_call(engine, node, name):
    return (node.type in {'member_call_expression', 'nullsafe_member_call_expression'}
            and engine.call_name(node) == name
            and engine.access(node.child_by_field_name('object')) == ('$wpdb',))


def _literal_select(engine, node, field):
    args = arguments(node)
    if not args:
        return None
    query = literal(expression(args[0]), engine.source)
    match = SELECT.search(query) if isinstance(query, str) else None
    if match and field.lower() in {part.strip().lower() for part in match[1].split(',')}:
        return match[2].lower()
    return None


def _wpdb_calls(project):
    writes = {}
    reads = {}
    for engine in project.files.values():
        for nodes in engine.nodes.values():
            for call in nodes:
                if _wpdb_call(engine, call, 'get_results'):
                    reads[(engine.path, call.start_byte)] = (engine, call)
                if not _wpdb_call(engine, call, 'insert'):
                    continue
                args = arguments(call)
                if len(args) < 2:
                    continue
                table = literal(expression(args[0]), engine.source)
                data = expression(args[1])
                if not isinstance(table, str) or data is None or data.type != 'array_creation_expression':
                    continue
                for item in data.named_children:
                    if item.type != 'array_element_initializer' or len(item.named_children) < 2:
                        continue
                    column = literal(item.named_children[0], engine.source)
                    if not isinstance(column, str):
                        continue
                    value = item.named_children[-1]
                    flows = engine.evaluate(value)
                    if any(flow.kind == 'request' and not flow.uncertain for flow in flows):
                        writes.setdefault((table.lower(), column.lower()), []).append({
                            'location': get_node_location(call, engine.path).model_dump(),
                            'source_kind': 'request', 'write_api': 'wpdb::insert',
                        })
    return writes, reads


def annotate_persistent_store_writes(findings, project):
    if project is None or not any(
            route.source_kind == 'persistent_data'
            for finding in findings for route in finding.flow_evidence):
        return
    writes, reads = _wpdb_calls(project)
    if not writes:
        return
    for finding in findings:
        matches = []
        for route in finding.flow_evidence:
            if (route.source_kind != 'persistent_data' or not route.source_fields
                    or not isinstance(route.source_fields[-1], str)
                    or any(part is not None for part in route.source_fields[:-1])):
                continue
            path, _, byte = route.source_origin.rpartition(':')
            if not byte.isdigit():
                continue
            read = reads.get((path, int(byte)))
            if read is None:
                continue
            engine, call = read
            column = route.source_fields[-1]
            table = _literal_select(engine, call, column)
            if table:
                for write in writes.get((table, column.lower()), ())[:16]:
                    matches.append({'table': table, 'column': column,
                                    'read_location': get_node_location(call, engine.path).model_dump(),
                                    **write})
        if matches:
            finding.metadata['persistent_store_write_candidates'] = matches[:16]
            finding.metadata['persistent_store_write_candidates_truncated'] = len(matches) > 16
            finding.metadata['persistent_store_write_provenance'] = 'static_table_column_and_request_match'
            finding.metadata['persistent_store_runtime_order_unverified'] = True
