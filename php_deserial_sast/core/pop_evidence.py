"""Correlate POP candidates with observed deserialization constraints.

Compatibility is a prerequisite, never proof of runtime reachability or of
attacker control over the properties used by the candidate chain.
"""
from collections import Counter
import re
from php_deserial_sast.core.dataflow import literal
from php_deserial_sast.core.parser import get_node_location, find_nodes_by_type


def class_policy(engine, call):
    if engine.unserialize_safe(call):
        return 'deny_objects', ()
    options = engine.builtin_argument(call, 1)
    if options is None:
        args = call.child_by_field_name('arguments')
        if args is not None and '...' in engine.text(args):
            return 'unknown', ()
        return 'allow_objects', ()
    if options.type != 'array_creation_expression':
        return 'unknown', ()
    allowed = engine._array_field(options, 'allowed_classes')
    if allowed is None:
        return 'unknown', ()
    if engine.text(allowed).lower() == 'true':
        return 'allow_objects', ()
    if allowed.type != 'array_creation_expression':
        return 'unknown', ()
    classes = []
    for item in allowed.named_children:
        if item.type == 'comment':
            continue
        if item.type != 'array_element_initializer' or len(item.named_children) != 1:
            return 'unknown', ()
        name = literal(item.named_children[0], engine.source)
        if name is None or item.named_children[0].type not in {'string', 'encapsed_string'}:
            return 'unknown', ()
        if item.named_children[0].type == 'string':
            # PHP single-quoted strings decode only escaped slash and quote.
            name = re.sub(r"\\([\\'])", lambda match: match[1], name)
        elif '\\' in name:
            return 'unknown', ()  # Other PHP string escapes require decoding.
        if name.startswith('\\'):
            return 'unknown', ()  # Do not assume runtime normalization of this option.
        classes.append(name.lower())
    return 'allowlist', tuple(classes)


def annotate_pop_candidates(findings, project):
    candidates = [finding for finding in findings if finding.gadget_chain]
    if project is None or not candidates:
        return
    observed = {(f.location.file_path, f.location.start_line, f.location.start_col): f
                for f in findings if f.metadata.get('sink_name') == 'unserialize'
                and any(route.source_kind == 'request' and not route.uncertain
                        for route in f.flow_evidence)}
    observed_by_id = {f.id: f for f in observed.values()}
    class_index = {(cls.full_name or cls.name).lower().lstrip('\\'): cls
                   for cls in project.symbols.get_all_unique_classes()} if project.symbols else {}
    sites = []
    for engine in project.files.values():
        for scope, nodes in engine.nodes.items():
            for call in nodes:
                if (call.type != 'function_call_expression' or engine.call_name(call) != 'unserialize'
                        or project.resolve(engine, call) or not engine.reachable(call, scope)):
                    continue
                location = get_node_location(call, engine.path)
                policy, classes = class_policy(engine, call)
                sites.append((location, policy, classes))
    for finding in candidates:
        entry = finding.gadget_chain.entry_class.lower().lstrip('\\')
        rows, counts = [], Counter()
        candidate_sources = []
        for location, policy, classes in sites:
            compatible = ('excluded' if policy == 'deny_objects' or policy == 'allowlist' and entry not in classes
                          else 'unknown' if policy == 'unknown' else 'compatible')
            counts[compatible] += 1
            source = observed.get((location.file_path, location.start_line, location.start_col))
            if source is not None and compatible == 'compatible':
                candidate_sources.append({'finding_id': source.id, 'location': location.model_dump(),
                                          'evidence': 'observed_request_and_object_class_policy_compatible',
                                          'runtime_class_loading_unverified': True})
                source.metadata.setdefault('candidate_gadget_links', []).append({
                    'gadget_finding_id': finding.id, 'entry_class': finding.gadget_chain.entry_class,
                    'entry_method': finding.gadget_chain.entry_method,
                    'link_level': 'compatible_deserialization_site',
                    'runtime_class_loading_unverified': True, 'exploitability_verified': False,
                })
            rows.append({'location': location.model_dump(), 'class_policy': policy,
                         'entry_class_compatibility': compatible,
                         'source_flow_observed': (location.file_path, location.start_line, location.start_col) in observed})
        rows.sort(key=lambda row: (not row['source_flow_observed'], row['entry_class_compatibility'] != 'compatible',
                                   row['location']['file_path'], row['location']['start_line']))
        # A top-level class defined before a same-file sink has direct static
        # loading evidence. A public property mentioned at the final sink can
        # be supplied by serialized object data. Neither fact proves that a
        # branch in the magic method is feasible at runtime.
        cls = class_index.get(entry)
        linked = []
        if cls and finding.gadget_chain.entry_method.lower() in {'__wakeup', '__unserialize'}:
            engine = project.files.get(cls.file_path)
            top_level = bool(engine and any(
                node.parent.type == 'program' and node.start_point[0] + 1 == cls.location.start_line
                for node in find_nodes_by_type(engine.root, 'class_declaration')))
            for location, policy, allowed in sites:
                key = (location.file_path, location.start_line, location.start_col)
                source = observed.get(key)
                if (not top_level or source is None or location.file_path != cls.file_path
                        or (cls.location.end_line, cls.location.end_col)
                           >= (location.start_line, location.start_col)
                        or policy == 'deny_objects'
                        or policy == 'allowlist' and entry not in allowed
                        or policy == 'unknown'):
                    continue
                linked.append({'finding_id': source.id, 'location': location.model_dump(),
                               'evidence': 'top_level_class_declared_before_observed_same_file_sink'})
                source.metadata.setdefault('candidate_gadget_links', []).append({
                    'gadget_finding_id': finding.id, 'entry_class': finding.gadget_chain.entry_class,
                    'entry_method': finding.gadget_chain.entry_method,
                    'class_loading': 'top_level_class_declared_before_sink',
                    'exploitability_verified': False})
        public_properties = []
        if linked and cls:
            sink_code = finding.gadget_chain.steps[-1].code_snippet
            public_properties = sorted({name for name in re.findall(r'\$this->([A-Za-z_][A-Za-z_0-9]*)', sink_code)
                                        if name in cls.properties and cls.properties[name].visibility == 'public'})
        linked_paths = []
        for link in linked:
            source = observed_by_id[link['finding_id']]
            chain = finding.gadget_chain
            impact = chain.steps[-1]
            path = {
                'source_finding_id': source.id,
                'deserialization_site': link['location'],
                'gadget_finding_id': finding.id,
                'gadget_chain_id': chain.chain_id,
                'entry_class': chain.entry_class,
                'entry_method': chain.entry_method,
                'candidate_serialized_properties': public_properties,
                'impact_function': chain.sink_function,
                'impact_site': impact.location.model_dump(),
                'class_loading': 'top_level_class_declared_before_sink',
                'path_evidence': 'observed_source_and_static_magic_method_chain',
                'runtime_conditions_unverified': [
                    'attacker_supplies_a_valid_serialized_object_of_the_entry_class',
                    'serialized_properties_satisfy_method_predicates',
                    'sink_arguments_and_runtime_side_effects_not_executed',
                ],
                'exploitability_verified': False,
            }
            linked_paths.append(path)
            source.metadata.setdefault('candidate_exploit_paths', []).append(path)
        finding.metadata['deserialization_constraints'] = {
            'entry_class': finding.gadget_chain.entry_class,
            'observed_site_count': len(rows), 'compatibility_counts': dict(counts),
            'sites': rows[:32], 'sites_truncated': len(rows) > 32,
            'runtime_class_loading': 'top_level_class_declared_before_sink' if linked else 'unproven',
            'property_control': 'public_serialized_property_candidate' if public_properties else 'unproven',
            'candidate_properties': public_properties, 'linked_source_sinks': linked,
            'linked_candidate_paths': linked_paths,
            'candidate_source_sinks': candidate_sources[:32],
            'candidate_source_sinks_truncated': len(candidate_sources) > 32,
            'entry_to_chain_reachability': 'unproven', 'exploitability_verified': False,
            'external_deserialization_entries_may_exist': True,
        }
