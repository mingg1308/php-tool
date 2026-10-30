"""Bounded object-property summaries shared by the dataflow solver.

Only literal properties on a receiver or an unrebound parameter are exported.
Writes are may-effects: magic methods, branch aliases and runtime types remain
uncertain. In particular, an empty summary never proves a caller-side kill.
"""
import re


def property_owner(engine, function, access, use):
    match = re.fullmatch(r'(\$\w+)->([A-Za-z_]\w*)', access[0])
    if not match:
        return None
    base, prop = match.groups()
    if base == '$this' and function.class_name:
        return ('property', -1, prop)
    for index, (name, _) in enumerate(function.params):
        if name != base:
            continue
        # A conditional reassignment also invalidates a unique input identity.
        if any(write.start_byte < use.start_byte
               for write, _ in engine.writes.get((function.node.start_byte, base), ())):
            return None
        if engine.aliases.get(function.node.start_byte):
            return None
        return ('property', index, prop)
    return None


def actual_property(engine, target, call, owner):
    _, index, prop = owner
    if index == -1:
        obj = call.child_by_field_name('object')
    else:
        from php_deserial_sast.core.dataflow import arguments, expression
        args = arguments(call)
        name = target.params[index][0].lstrip('$')
        arg = next((a for a in args if engine.text(a.child_by_field_name('name')) == name), None)
        if arg is None and index < len(args) and args[index].child_by_field_name('name') is None:
            arg = args[index]
        obj = expression(arg) if arg is not None else None
    access = engine.access(obj)
    if access and len(access) == 1 and re.fullmatch(r'\$\w+', access[0]):
        return engine._canonical_access((access[0] + '->' + prop,), call)
    return None


def property_effects(engine, function):
    from php_deserial_sast.core.dataflow import bounded_fields, merge
    scope = function.node.start_byte
    cfg = engine.cfgs.get(scope)
    effects = {}

    def add(node, access, flows):
        owner = property_owner(engine, function, access, node)
        if owner is None or not engine.reachable(node, scope):
            return
        if cfg and not cfg.effect_can_escape(node, access, engine.writes.get((scope, access[0]), ())):
            return
        key = (owner, bounded_fields(access[1:]))
        effects[key] = merge(effects.get(key, ()), flows)

    for write, access in engine.scope_writes.get(scope, ()):
        engine.project.check_effect_budget()
        if property_owner(engine, function, access, write) is not None:
            add(write, access, engine.evaluate(write.child_by_field_name('right'), symbolic=True))
    for call in engine.calls_in_scope(scope):
        engine.project.check_effect_budget()
        if engine.reachable(call, scope):
            for access, flows, target in engine.effect_targets(call):
                if property_owner(engine, function, access, call) is not None:
                    add(call, access, engine.bind(flows, target, call, True))
    return tuple((owner, fields, flows) for (owner, fields), flows in effects.items() if flows)


def receiver_class(engine, obj, use, namespace, seen=None):
    """Resolve straight-line variable aliases without guessing a runtime type."""
    if obj is None:
        return ""
    seen = set() if seen is None else seen
    key = (obj.id, use.id)
    if key in seen or len(seen) >= 32:
        return ""
    seen.add(key)
    scope = engine.scope.get(use.id, -1)
    context = engine.functions.get(scope)
    if engine.text(obj) == "$this" and context:
        return context.class_name
    if obj.type == "object_creation_expression":
        name = next((engine.text(c) for c in obj.named_children if c.type in {"name", "qualified_name"}), "")
        if not name:
            return ""
        if engine.project.symbols:
            return engine.project.symbols.resolve_class_name(name, namespace, engine.path)
        return (namespace + "\\" + name).strip("\\") if namespace and not name.startswith("\\") else name
    access = engine.access(obj)
    if not access or len(access) != 1:
        return ""
    for assignment, target in reversed(engine.writes.get((scope, access[0]), ())):
        if target != access or assignment.start_byte >= use.start_byte or not engine.compatible(assignment, use):
            continue
        if not engine.dominates(assignment, use):
            return ""  # Multiple possible types require a dispatch set.
        return receiver_class(engine, assignment.child_by_field_name("right"), assignment, namespace, seen)
    if context:
        for name, parameter in context.params:
            if name == access[0]:
                type_name = engine.text(parameter.child_by_field_name("type")).lstrip("?")
                if re.fullmatch(r"\\?[A-Za-z_][A-Za-z0-9_\\]*", type_name) and type_name.lower() not in {
                    "mixed", "object", "string", "int", "bool", "float", "array", "callable", "iterable"}:
                    return engine.project.symbols.resolve_class_name(type_name, namespace, engine.path) if engine.project.symbols else type_name
    return ""
