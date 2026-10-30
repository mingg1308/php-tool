"""
Tree-sitter based PHP Parser and AST traversal utilities.
"""

from typing import List, Optional, Generator, Tuple, Union
import re
from collections import defaultdict
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
        parse_bytes = _normalize_string_nuls(code_bytes)
        tree = self.parser.parse(parse_bytes)
        if tree.root_node.has_error:
            normalized = _normalize_readonly_compatibility(parse_bytes, tree.root_node)
            if normalized != parse_bytes:
                parse_bytes = normalized
                tree = self.parser.parse(parse_bytes)
            normalized = _normalize_legacy_string_offsets(parse_bytes, tree.root_node)
            if normalized != parse_bytes:
                tree = self.parser.parse(normalized)
        return tree.root_node, code_bytes

    def parse_file(self, file_path: str) -> Tuple[Node, bytes]:
        """Read a file and parse it into an AST."""
        with open(file_path, "rb") as f:
            code_bytes = f.read()
        return self.parse_source(code_bytes)


def _normalize_readonly_compatibility(source, root):
    """Work around grammar restrictions without moving source coordinates.

    A legacy function named readonly is read using an equal-length placeholder.
    For promotion with readonly before visibility, hide only the readonly token;
    visibility, type and parameter spans retain their original source positions.
    Original bytes remain authoritative for symbol names and report snippets.
    """
    if not re.search(rb"\breadonly\b", source, re.I):
        return source
    protected = [(n.start_byte, n.end_byte) for n in find_nodes_by_type(
        root, ("string", "encapsed_string", "comment", "heredoc", "nowdoc", "text"))]
    result = bytearray(source)
    for match in re.finditer(rb"\breadonly\b(?=\s+(?:public|protected|private)\b|\s*\()", source, re.I):
        if any(start <= match.start() < end for start, end in protected):
            continue
        tail = source[match.end():].lstrip()
        result[match.start():match.end()] = b"rdonly__" if tail.startswith(b"(") else b"        "
    return bytes(result)


def _normalize_string_nuls(source: bytes) -> bytes:
    """Normalize NULs inside quoted PHP strings, preserving source byte offsets.

    The parser treats NUL as EOF. The caller still receives the original bytes.
    Heredoc lexing is deliberately not guessed by this narrow normalization.
    """
    if b"\x00" not in source or b"<<<" in source:
        return source
    result = bytearray(source)
    i, quote = 0, None
    while i < len(source):
        char = source[i]
        if quote is not None:
            if char == 0:
                result[i] = 63
            elif char == 92:
                if i + 1 < len(source) and source[i + 1] == 0:
                    result[i + 1] = 63
                i += 2
                continue
            elif char == quote:
                quote = None
        elif source[i:i+2] == b"/*":
            end = source.find(b"*/", i+2)
            i = len(source) if end < 0 else end + 2
            continue
        elif source[i:i+2] == b"//" or char == 35:
            end = source.find(b"\n", i+1)
            i = len(source) if end < 0 else end + 1
            continue
        elif char in (39, 34):
            quote = char
        i += 1
    return bytes(result)


_LEGACY_BRACE_OFFSET = re.compile(
    rb"(?P<base>\$[A-Za-z_][A-Za-z0-9_]*(?:->[A-Za-z_][A-Za-z0-9_]*)?(?:\[[^\]\r\n]+\])*)"
    rb"\{(?P<offset>[^{}\r\n]+)\}"
)


def _normalize_legacy_string_offsets(source: bytes, root_node=None) -> bytes:
    """Normalize PHP's removed ``$value{offset}`` syntax for Tree-sitter.

    PHP 7.4 deprecated and PHP 8 removed curly-brace string offsets, while
    legacy libraries such as TCPDF 6.2.19 still use them. Replacing only the
    two delimiter bytes keeps every AST byte offset aligned with the original
    source. Callers continue to receive the untouched source bytes for text,
    snippets, and diagnostics.
    """

    if not _LEGACY_BRACE_OFFSET.search(source):
        return source
    protected = []
    if root_node is not None:
        protected = [(n.start_byte, n.end_byte) for n in find_nodes_by_type(
            root_node, ("string", "encapsed_string", "comment", "heredoc", "nowdoc")
        )]
    def normalize(match):
        if any(start <= match.start() < end for start, end in protected):
            return match.group(0)
        return match.group("base") + b"[" + match.group("offset") + b"]"
    return _LEGACY_BRACE_OFFSET.sub(normalize, source)


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
    """Traverse without Python recursion or cached child lists on every node."""
    types = {types} if isinstance(types, str) else set(types)
    for current in walk_nodes(node):
        if current.type in types:
            yield current


def walk_nodes(node):
    """Preorder TreeCursor traversal; memory is independent of tree width."""
    cursor = node.walk()
    while True:
        yield cursor.node
        if cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return


def iter_child_nodes(node, named=False):
    cursor = node.walk()
    if cursor.goto_first_child():
        while True:
            child = cursor.node
            if not named or child.is_named:
                yield child
            if not cursor.goto_next_sibling():
                break


class ASTIndex:
    """One traversal shared by declaration extraction and rule matching."""
    TYPES = {
        "namespace_definition", "namespace_use_declaration", "class_declaration",
        "trait_declaration", "function_definition", "method_declaration",
        "anonymous_function", "anonymous_function_creation_expression", "arrow_function",
        "function_call_expression", "member_call_expression", "nullsafe_member_call_expression",
        "scoped_call_expression", "assignment_expression", "subscript_expression",
        "expression_statement", "augmented_assignment_expression", "binary_expression",
        "foreach_statement", "echo_statement",
        "member_access_expression", "nullsafe_member_access_expression", "object_creation_expression",
        "include_expression", "include_once_expression",
        "require_expression", "require_once_expression",
    }
    SEMANTIC = TYPES - {"namespace_definition", "namespace_use_declaration", "assignment_expression", "subscript_expression", "expression_statement", "foreach_statement", "echo_statement"}

    def __init__(self, root, max_nodes=0):
        self.by_type = defaultdict(list)
        self.node_count = 0
        for node in walk_nodes(root):
            self.node_count += 1
            if max_nodes and self.node_count > max_nodes:
                raise ValueError(f"AST node limit exceeded ({max_nodes}); file analysis is incomplete.")
            if node.type in self.TYPES:
                self.by_type[node.type].append(node)

    def find(self, types):
        types = (types,) if isinstance(types, str) else types
        if len(types) == 1:
            # The index is populated by a preorder traversal, so one node
            # type is already ordered by source position.
            return self.by_type.get(types[0], ())
        return sorted((n for t in types for n in self.by_type.get(t, ())), key=lambda n: n.start_byte)

    @property
    def needs_project_analysis(self):
        return any(self.by_type.get(t) for t in self.SEMANTIC)


def find_child_by_type(node: Node, target_type: Union[str, List[str], Tuple[str, ...]]) -> Optional[Node]:
    """Find immediate child matching the given type or types."""
    types = (target_type,) if isinstance(target_type, str) else tuple(target_type)
    for child in iter_child_nodes(node):
        if child.type in types:
            return child
    return None


def find_child_by_field(node: Node, field_name: str) -> Optional[Node]:
    """Find child node by its field name (e.g., 'name', 'body', 'function')."""
    return node.child_by_field_name(field_name)


def get_code_snippet(source_bytes: bytes, start_line: int, end_line: int, context_lines: int = 2, lines=None) -> str:
    """Extract code snippet surrounding the given 1-indexed line numbers."""
    if lines is None:
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
