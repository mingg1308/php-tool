"""
AST and Code Pattern Matcher for Semgrep-like YAML rules.
"""

import re
from typing import Dict, List, Tuple
from tree_sitter import Node
from php_deserial_sast.core.parser import get_node_text


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
    for var_name in metavars:
        escaped = escaped.replace(
            f"___METAVAR_{var_name}___",
            rf"(?P<{var_name}>\$[a-zA-Z_0-9]+|[\'\"][^\'\"]*[\'\"]|[a-zA-Z_0-9\(\)\->]+)"
        )

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
        node_text = get_node_text(node, source_bytes)
        return self.matches(pattern_str, node_text)
