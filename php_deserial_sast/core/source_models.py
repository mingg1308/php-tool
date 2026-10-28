"""Explicit framework input models; matching requires a resolved receiver type.

These models describe request APIs, not proof that an application constructed a
request from an attacker. Findings retain that assumption separately.
"""

REQUEST_METHODS = {
    "symfony\\component\\httpfoundation\\request": frozenset({"get", "getcontent", "getquerystring"}),
    "illuminate\\http\\request": frozenset({"get", "getcontent", "input", "query", "post", "cookie", "header", "all"}),
}


def is_framework_request_source(class_name, method):
    return method.lower() in REQUEST_METHODS.get(class_name.strip("\\").lower(), ())


def is_wpdb_persistent_read(symbols, receiver_access, method):
    """Recognize WordPress database rows without claiming an attacker write."""
    if method.lower() != "get_results" or receiver_access != ("$wpdb",) or symbols is None:
        return False
    wpdb = symbols.get_class("wpdb")
    return wpdb is not None and any(name.lower() == "get_results" for name in wpdb.methods)
