"""
AST and Code Pattern Matcher for Semgrep-like YAML rules.
"""

import re
from typing import Dict, List, Tuple
from tree_sitter import Node
from php_deserial_sast.core.parser import PHPParser, get_node_text

_METAVARIABLE_EXPRESSION = (
    r"(?:\$[A-Za-z_][A-Za-z0-9_]*(?:(?:->|::)[A-Za-z_][A-Za-z0-9_]*|"
    r"\[[^\]\r\n]*\])*(?:\([^()\r\n]*\))?|"
    r"['\"][^'\"]*['\"]|[A-Za-z_][A-Za-z0-9_\\]*)"
)


def pattern_to_regex(pattern_str: str) -> Tuple[re.Pattern, List[str]]:
    r"""
    Convert a Semgrep-like pattern into a regular expression with named metavariables.
    e.g., 'unserialize($X)' -> r'unserialize\s*\(\s*(?P<X>[^,\)]+)\s*\)'
          '$_COOKIE[...]' -> r'\$_COOKIE\s*\[.*?\]'
    """
    cleaned = pattern_str.strip()
    metavars = []

    # Escape special regex characters except for our syntax markers
    # Replace wildcard '...' with placeholder
    cleaned = cleaned.replace("...", "___ELLIPSIS___")

    # Find metavariables like $X, $INPUT, $VAR
    def replace_metavar(m):
        var_name = m.group(1)
        metavars.append(var_name)
        return f"___METAVAR_{var_name}___"

    cleaned = re.sub(r'\$([A-Z][A-Z0-9_]*)', replace_metavar, cleaned)

    # Escape regex specials
    escaped = re.escape(cleaned)

    # Restore ellipsis as non-greedy match
    escaped = escaped.replace("___ELLIPSIS___", r"[\s\S]*?")

    # Restore metavariables as capturing groups
    captured = set()
    def restore_metavar(match):
        var_name = match.group(1)
        if var_name in captured:
            return rf"(?P={var_name})"
        captured.add(var_name)
        return rf"(?P<{var_name}>{_METAVARIABLE_EXPRESSION})"
    escaped = re.sub(r"___METAVAR_([A-Z][A-Z0-9_]*)___", restore_metavar, escaped)

    # Allow flexible whitespace and parentheses
    escaped = escaped.replace(r"\ ", r"\s*")
    escaped = escaped.replace(r"\(", r"\s*\(\s*")
    escaped = escaped.replace(r"\)", r"\s*\)\s*")

    regex = re.compile(escaped, re.IGNORECASE)
    return regex, metavars


class PatternMatcher:
    """Matches PHP AST nodes against pattern specifications."""

    def __init__(self):
        self._compiled_cache: Dict[str, Tuple[re.Pattern, List[str]]] = {}
        self._ast_cache = {}
        self._parser = None

    def _expression_pattern(self, pattern):
        if pattern not in self._ast_cache:
            self._parser = self._parser or PHPParser()
            # Ellipsis occupies an argument slot and matches zero or more args.
            expanded = re.sub(r"""'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|\.\.\.""",
                              lambda m: "$__SAST_ELLIPSIS" if m.group() == "..." else m.group(),
                              pattern.strip().rstrip(";"))
            text = "<?php " + expanded + ";"
            root, source = self._parser.parse_source(text)
            statements = [n for n in root.named_children if n.type != "php_tag"]
            call = statements[0].named_children[0] if len(statements) == 1 and statements[0].named_children else None
            self._ast_cache[pattern] = (call, source) if not root.has_error and call is not None and call.type in {
                "function_call_expression", "member_call_expression", "nullsafe_member_call_expression",
                "scoped_call_expression", "assignment_expression", "augmented_assignment_expression",
                "subscript_expression", "member_access_expression", "nullsafe_member_access_expression",
                "binary_expression", "object_creation_expression"} else None
        return self._ast_cache[pattern]

    def _structural(self, pattern, node, pattern_source, source, bindings):
        text = get_node_text(pattern, pattern_source)
        if pattern.type == "variable_name" and text == "$__SAST_ELLIPSIS":
            return True  # Expression wildcard, e.g. $_GET[...] array index.
        if pattern.type == "variable_name" and re.fullmatch(r"\$[A-Z][A-Z0-9_]*", text):
            value = get_node_text(node, source)
            # Token identity ignores trivia but preserves variable/string case.
            def signature(n):
                children = [c for c in n.children if c.type != "comment"]
                return (n.type, tuple(signature(c) for c in children)) if children else (n.type, get_node_text(n, source))
            identity = signature(node)
            if text in bindings and bindings[text][1] != identity:
                return False
            bindings[text] = (value, identity)
            return True
        parent = pattern.parent
        literal_call_name = parent is not None and pattern.type in {"name", "qualified_name"} and (
            parent.type == "function_call_expression" and parent.child_by_field_name("function") == pattern
            or parent.type in {"member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression"}
            and (parent.child_by_field_name("name") == pattern or parent.child_by_field_name("scope") == pattern))
        if literal_call_name:
            return node.type in {"name", "qualified_name"} and text.strip("\\").lower() == get_node_text(node, source).strip("\\").lower()
        if pattern.type != node.type:
            return False
        left = [c for c in pattern.children if c.type != "comment"]
        right = [c for c in node.children if c.type != "comment"]
        if not left:
            actual = get_node_text(node, source)
            return text == actual
        if pattern.type == "arguments":
            left = [c for c in pattern.named_children if c.type != "comment"]
            right = [c for c in node.named_children if c.type != "comment"]
            def sequence(i, j, current):
                if i == len(left):
                    return current if j == len(right) else None
                if get_node_text(left[i], pattern_source) == "$__SAST_ELLIPSIS":
                    for end in range(j, len(right) + 1):
                        matched = sequence(i + 1, end, dict(current))
                        if matched is not None:
                            return matched
                    return None
                updated = dict(current)
                if j < len(right) and self._structural(left[i], right[j], pattern_source, source, updated):
                    return sequence(i + 1, j + 1, updated)
                return None
            matched = sequence(0, 0, bindings)
            if matched is None:
                return False
            bindings.update(matched)
            return True
        return len(left) == len(right) and all(
            self._structural(a, b, pattern_source, source, bindings) for a, b in zip(left, right))

    def get_compiled_pattern(self, pattern_str: str) -> Tuple[re.Pattern, List[str]]:
        if pattern_str not in self._compiled_cache:
            self._compiled_cache[pattern_str] = pattern_to_regex(pattern_str)
        return self._compiled_cache[pattern_str]

    def matches(self, pattern_str: str, code_snippet: str) -> Tuple[bool, Dict[str, str]]:
        """Check if code snippet matches pattern string and return captured metavariables."""
        regex, metavars = self.get_compiled_pattern(pattern_str)
        m = regex.search(code_snippet)
        if m:
            bindings = {}
            for v in metavars:
                try:
                    bindings[f"${v}"] = m.group(v).strip()
                except IndexError:
                    pass
            return True, bindings
        return False, {}

    def matches_ast_node(self, pattern_str: str, node: Node, source_bytes: bytes) -> Tuple[bool, Dict[str, str]]:
        """Match pattern against text of an AST node."""
        compiled = self._expression_pattern(pattern_str)
        if compiled is not None:
            while node.type in ("expression_statement", "error_suppression_expression", "parenthesized_expression") and len(node.named_children) == 1:
                node = node.named_children[0]
            pattern, pattern_source = compiled
            bindings = {}
            matched = self._structural(pattern, node, pattern_source, source_bytes, bindings)
            return matched, {key: value[0] for key, value in bindings.items()} if matched else {}
        function_pattern = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", pattern_str)
        if function_pattern:
            # A literal/comment containing PHP-looking text is not a call.
            while node.type in ("expression_statement", "error_suppression_expression", "parenthesized_expression") and len(node.named_children) == 1:
                node = node.named_children[0]
            if node.type != "function_call_expression":
                return False, {}
            name = get_node_text(node.child_by_field_name("function"), source_bytes).strip("\\").lower()
            if name != function_pattern.group(1).lower():
                return False, {}
            compiled = self._expression_pattern(pattern_str)
            if compiled is not None:
                pattern, pattern_source = compiled
                bindings = {}
                matched = self._structural(pattern, node, pattern_source, source_bytes, bindings)
                return matched, {key: value[0] for key, value in bindings.items()} if matched else {}
        node_text = get_node_text(node, source_bytes)
        return self.matches(pattern_str, node_text)
