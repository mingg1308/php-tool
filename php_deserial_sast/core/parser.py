"""
Tree-sitter based PHP Parser and AST traversal utilities.
"""

from typing import List, Optional, Generator, Tuple, Union
import tree_sitter_php
from tree_sitter import Language, Parser, Node
from php_deserial_sast.models import CodeLocation


class PHPParser:
    """Wrapper around tree-sitter-php for parsing and AST querying."""

    def __init__(self):
        self.language = Language(tree_sitter_php.language_php())
        self.parser = Parser(self.language)

    def parse_source(self, source_code: Union[str, bytes]) -> Tuple[Node, bytes]:
        """Parse source code string or bytes into a tree-sitter AST root node."""
        if isinstance(source_code, str):
            code_bytes = source_code.encode("utf-8", errors="replace")
        else:
            code_bytes = source_code
        tree = self.parser.parse(code_bytes)
        return tree.root_node, code_bytes

    def parse_file(self, file_path: str) -> Tuple[Node, bytes]:
        """Read a file and parse it into an AST."""
        with open(file_path, "rb") as f:
            code_bytes = f.read()
        tree = self.parser.parse(code_bytes)
        return tree.root_node, code_bytes


def get_node_text(node: Node, source_bytes: bytes) -> str:
    """Get the UTF-8 text representation of an AST node."""
    if node is None:
        return ""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def get_node_location(node: Node, file_path: str) -> CodeLocation:
    """Extract 1-indexed line and column location from an AST node."""
    return CodeLocation(
        file_path=file_path,
        start_line=node.start_point[0] + 1,
        start_col=node.start_point[1] + 1,
        end_line=node.end_point[0] + 1,
        end_col=node.end_point[1] + 1,
    )


def find_nodes_by_type(node: Node, types: Union[str, List[str], Tuple[str, ...]]) -> Generator[Node, None, None]:
    """Recursively find all descendant nodes matching specified type(s)."""
    if isinstance(types, str):
        types = (types,)
    else:
        types = tuple(types)

    if node.type in types:
        yield node

    for child in node.children:
        yield from find_nodes_by_type(child, types)


def find_child_by_type(node: Node, target_type: Union[str, List[str], Tuple[str, ...]]) -> Optional[Node]:
    """Find immediate child matching the given type or types."""
    types = (target_type,) if isinstance(target_type, str) else tuple(target_type)
    for child in node.children:
        if child.type in types:
            return child
    return None


def find_child_by_field(node: Node, field_name: str) -> Optional[Node]:
    """Find child node by its field name (e.g., 'name', 'body', 'function')."""
    return node.child_by_field_name(field_name)


def get_code_snippet(source_bytes: bytes, start_line: int, end_line: int, context_lines: int = 2) -> str:
    """Extract code snippet surrounding the given 1-indexed line numbers."""
    lines = source_bytes.decode("utf-8", errors="replace").splitlines()
    total_lines = len(lines)
    
    first_line = max(1, start_line - context_lines)
    last_line = min(total_lines, end_line + context_lines)
    
    snippet_lines = []
    for line_no in range(first_line, last_line + 1):
        idx = line_no - 1
        if 0 <= idx < total_lines:
            prefix = " > " if (start_line <= line_no <= end_line) else "   "
            snippet_lines.append(f"{prefix}{line_no:4d} | {lines[idx]}")
            
    return "\n".join(snippet_lines)
