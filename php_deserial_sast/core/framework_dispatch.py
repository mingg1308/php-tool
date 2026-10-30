"""Explicit, conditional serializer dispatch contracts.

Edges are emitted only between methods actually present in the project. They
never create a source or a sink. Runtime field selection remains an assumption.
"""

import re

from php_deserial_sast.core.finding_scope import is_test_source_path

SER = "Drupal\\serialization\\Normalizer\\"
HAL = "Drupal\\hal\\Normalizer\\"
REQUEST = "Drupal\\rest\\RequestHandler"
FIELD_BASE = "Drupal\\Core\\Field\\FieldItemBase"
LARAVEL_ENCRYPTER = "Illuminate\\Encryption\\Encrypter"
LARAVEL_COOKIE = "Illuminate\\Cookie\\Middleware\\EncryptCookies"
LARAVEL_CSRF = "Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken"
PREFIX = "Framework dispatch model: "
LARAVEL_DEFAULT_SERIALIZATION_NOTE = (
    "Laravel cookie serialization defaults to false in the scanned class; "
    "a subclass or runtime override may re-enable it."
)


def _field_candidates(symbols):
    """Prefer deployable field types when a whole project includes test modules."""
    production, tests = [], []
    for cls in symbols.get_all_unique_classes():
        if cls.is_abstract or not any(
                (base.full_name or base.name).lower() == FIELD_BASE.lower()
                for base in symbols.resolve_inheritance(cls.full_name or cls.name)):
            continue
        name = cls.full_name or cls.name
        (tests if is_test_source_path(cls.file_path) else production).append(name)
    return production or tests


def _proven_false(engine, value, call):
    while value is not None and value.type in {'parenthesized_expression', 'argument'}:
        value = value.named_children[-1] if value.named_children else None
    if value is None:
        return False
    if engine.text(value).lower() == 'false':
        return True
    access = engine.access(value)
    if not access or len(access) != 1 or not re.fullmatch(r'\$[A-Za-z_]\w*', access[0]):
        return False
    scope = engine.scope.get(call.id, -1)
    reaching = [(write, target) for write, target in engine.writes.get((scope, access[0]), ())
                if write.end_byte <= call.start_byte and engine.compatible(write, call)]
    if not reaching:
        return False
    last, target = max(reaching, key=lambda item: item[0].start_byte)
    return (target == access and last.type == 'assignment_expression'
            and engine.dominates(last, call)
            and engine.text(last.child_by_field_name('right')).lower() == 'false')


def _decrypt_disables_unserialize(engine, call):
    arguments = call.child_by_field_name("arguments")
    args = [child for child in arguments.named_children if child.type == "argument"] if arguments else []
    positional = []
    for arg in args:
        name = arg.child_by_field_name("name")
        value = arg.named_children[-1] if arg.named_children else None
        if name is not None:
            if engine.text(name) == "unserialize":
                return _proven_false(engine, value, call)
        else:
            positional.append(value)
    return len(positional) >= 2 and _proven_false(engine, positional[1], call)


def _default_false_return(engine, value, depth=0):
    """Recognize a constant false default returned through resolved static helpers."""
    if value is None or depth > 3 or value.type != "scoped_call_expression":
        return False
    target = engine.project.resolve(engine, value)
    if target is None or not target.class_name:
        return False
    body = target.node.child_by_field_name("body")
    statements = [n for n in body.named_children if n.type != "comment"] if body else []
    if len(statements) != 1 or statements[0].type != "return_statement" or len(statements[0].named_children) != 1:
        return False
    result = statements[0].named_children[0]
    if result.type == "scoped_call_expression":
        return _default_false_return(target.engine, result, depth + 1)
    if result.type != "scoped_property_access_expression":
        return False
    if target.engine.text(result.child_by_field_name("scope")).lower() not in {"self", "static"}:
        return False
    name = target.engine.text(result.child_by_field_name("name")).lstrip("$")
    owner = engine.project.symbols.get_class(target.class_name) if engine.project.symbols else None
    prop = owner.properties.get(name) if owner else None
    if not prop or not prop.default_value or prop.default_value.lower() != "false":
        return False
    # A known subclass can replace the late-bound static method or property.
    owner_name = (owner.full_name or owner.name).lower()
    for cls in engine.project.symbols.get_all_unique_classes():
        if cls is owner:
            continue
        bases = engine.project.symbols.resolve_inheritance(cls.full_name or cls.name)[1:]
        if not any((base.full_name or base.name).lower() == owner_name for base in bases):
            continue
        override = cls.properties.get(name)
        if override and (override.default_value or "").lower() != "false":
            return False
        if target.name.lower() in cls.methods:
            return False
    return True


def _decrypt_uses_default_false(engine, call):
    arguments = call.child_by_field_name("arguments")
    args = [child for child in arguments.named_children if child.type == "argument"] if arguments else []
    positional = []
    for arg in args:
        name = arg.child_by_field_name("name")
        value = arg.named_children[-1] if arg.named_children else None
        if name is not None and engine.text(name) == "unserialize":
            return _default_false_return(engine, value)
        if name is None:
            positional.append(value)
    return len(positional) >= 2 and _default_false_return(engine, positional[1])


class FrameworkDispatch:
    def __init__(self, project, enabled=True):
        self.project, self.enabled = project, enabled
        self.cache, self.reasons = {}, {}
        self._fields = None

    def targets(self, engine, call):
        key = (engine.path, call.id)
        if key in self.cache:
            return self.cache[key]
        result, reason = [], None
        context = engine.functions.get(engine.scope.get(call.id, -1))
        if not self.enabled or context is None or call.type not in {"member_call_expression", "nullsafe_member_call_expression"}:
            self.cache[key] = ()
            return ()
        owner, method = context.class_name.lower(), context.name.lower()
        name = engine.call_name(call)
        obj = engine.access(call.child_by_field_name("object"))
        classes = []
        if name == "denormalize" and obj == ("$this->serializer",):
            if owner == REQUEST.lower() and method == "deserialize":
                classes = [HAL + "ContentEntityNormalizer", SER + "ContentEntityNormalizer"]
            elif owner == (SER + "FieldableEntityNormalizerTrait").lower() and method == "denormalizefielddata":
                classes = [HAL + "FieldNormalizer", SER + "FieldNormalizer"]
            elif owner in {(SER + "FieldNormalizer").lower(), (HAL + "FieldNormalizer").lower()} and method == "denormalize":
                classes = [HAL + "FieldItemNormalizer", SER + "FieldItemNormalizer"]
            if classes:
                reason = "Drupal serializer selects an available normalizer for the runtime entity/field type and format."
        elif (name == "setvalue" and method == "denormalize"
              and owner in {(SER + "FieldItemNormalizer").lower(), (HAL + "FieldItemNormalizer").lower()}):
            # Require a receiver loaded from this method's context, not merely
            # a method named setValue in a similarly named application class.
            scope = context.node.start_byte
            context_name = context.params[3][0] if len(context.params) >= 4 else None
            if obj and len(obj) == 1 and context_name and any(
                access == obj and engine.access(write.child_by_field_name("right")) == (context_name, "target_instance")
                and engine.dominates(write, call) for write, access in engine.writes.get((scope, obj[0]), ())):
                if self._fields is None:
                    self._fields = (_field_candidates(self.project.symbols)
                                    if self.project.symbols else [])
                classes = self._fields
                reason = "Drupal target_instance may select this field class; verify enabled modules and field schema."
        elif (name == "decrypt" and obj == ("$this->encrypter",)
              and (owner == LARAVEL_COOKIE.lower() and method in {"decryptcookie", "decryptarray"}
                   or owner == LARAVEL_CSRF.lower() and method == "gettokenfromrequest")):
            # The middleware constructor receives the encryption contract.
            # The concrete service binding may differ in a deployed app.
            if not _decrypt_disables_unserialize(engine, call):
                classes = [LARAVEL_ENCRYPTER]
                reason = "Laravel encryption contract may resolve to Encrypter; verify service binding, APP_KEY and MAC validation."
                if _decrypt_uses_default_false(engine, call):
                    reason += " " + LARAVEL_DEFAULT_SERIALIZATION_NOTE
        for cls in classes:
            result.extend(self.project.method_candidates(cls, name))
        unique = {function.key: function for function in result}
        self.cache[key] = tuple(unique.values())
        if unique:
            self.reasons[key] = reason
        return self.cache[key]

    def annotate(self, engine, call, flows):
        reason = self.reasons.get((engine.path, call.id))
        return engine._append(flows, call, PREFIX + reason, uncertain=True) if reason else flows

    def validation_reviews(self, engine, call):
        # Preserve unmodeled validation instead of claiming an exploit through
        # an unknown rejection routine. A name alone is never a sanitizer.
        reason = self.reasons.get((engine.path, call.id))
        if reason is None:
            return ()
        if reason.startswith("Laravel "):
            methods = self.project.method_candidates(LARAVEL_ENCRYPTER, "getJsonPayload")
            if any("validMac(" in method.engine.text(method.node)
                   and "validPayload(" in method.engine.text(method.node)
                   and "throw " in method.engine.text(method.node) for method in methods):
                reviews = ("Laravel getJsonPayload checks payload structure and MAC before decryption; APP_KEY and successful validation are unverified.",)
            else:
                reviews = ()
            return reviews + ((LARAVEL_DEFAULT_SERIALIZATION_NOTE,) if LARAVEL_DEFAULT_SERIALIZATION_NOTE in reason else ())
        scope = engine.scope.get(call.id, -1)
        return tuple("Framework validation requires review: " + engine.text(node)
                     for node in engine.nodes.get(scope, ())
                     if engine.call_name(node) == "checkforserializedstrings"
                     and node.start_byte < call.start_byte and engine.reachable(node, scope))[:1]

    def statistics(self):
        contracts = []
        if any(reason.startswith("Drupal ") for reason in self.reasons.values()):
            contracts.append("drupal_serializer_field_dispatch")
        if any(reason.startswith("Laravel ") for reason in self.reasons.values()):
            contracts.append("laravel_encrypter_contract_dispatch")
        return {"enabled": self.enabled, "modeled_calls": len(self.reasons),
                "candidate_edges": sum(len(self.cache[key]) for key in self.reasons),
                "contracts": contracts if self.enabled else [],
                "runtime_configuration_verified": False}
