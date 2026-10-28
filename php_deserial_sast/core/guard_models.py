"""Small, source-verified predicates that exclude PHP object payloads."""

import re

from php_deserial_sast.core.parser import find_nodes_by_type


def _compact(text):
    return re.sub(r"\s+", "", text)


def _body(node):
    return node.child_by_field_name("body") or next(
        (child for child in reversed(node.named_children)
         if child.type == "compound_statement"), None)


def _only_return(engine, node, value):
    body = _body(node)
    statements = [child for child in body.named_children if child.type != "comment"] if body else []
    return (len(statements) == 1 and statements[0].type == "return_statement"
            and _compact(engine.text(statements[0])) == f"return{value};")


def proves_serialized_string_only(function):
    """Recognize a helper whose only true branch requires the leading s token.

    This intentionally accepts a narrow, auditable shape. A helper with an
    extra return, side effect or different branch structure remains unknown.
    """
    if (function.name.lower() != "is_serialized_string" or function.namespace
            or function.class_name or len(function.params) != 1):
        return False
    parameter = function.params[0][0]
    engine = function.engine
    body = _body(function.node)
    statements = [child for child in body.named_children if child.type != "comment"] if body else []
    if len(statements) != 3:
        return False
    type_guard, normalization, token_guard = statements
    if type_guard.type != "if_statement" or not _only_return(engine, type_guard, "false"):
        return False
    if _compact(engine.text(type_guard.child_by_field_name("condition"))) != f"(!is_string({parameter}))":
        return False
    if normalization.type != "expression_statement" or _compact(engine.text(normalization)) != f"{parameter}=trim({parameter});":
        return False
    if token_guard.type != "if_statement" or not _only_return(engine, token_guard, "false"):
        return False
    alternatives = [child for child in token_guard.named_children
                    if child.type in {"else_if_clause", "else_clause"}]
    if not alternatives or alternatives[-1].type != "else_clause":
        return False
    if not _only_return(engine, alternatives[-1], "true"):
        return False
    if any(not _only_return(engine, branch, "false")
           for branch in alternatives[:-1]):
        return False
    expected = {f"('s'!=={parameter}[0])", f'("s"!=={parameter}[0])'}
    if not any(_compact(engine.text(branch.child_by_field_name("condition"))) in expected
               for branch in alternatives[:-1]):
        return False
    for branch in (token_guard, *alternatives[:-1]):
        condition = branch.child_by_field_name("condition")
        if any(engine.call_name(call) not in {"strlen", "substr"}
               for call in find_nodes_by_type(condition, "function_call_expression")):
            return False
        if any(True for _ in find_nodes_by_type(
                condition, ("assignment_expression", "augmented_assignment_expression", "update_expression"))):
            return False
    return True
