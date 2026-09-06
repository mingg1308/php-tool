"""
AST Visitor for extracting classes, methods, properties, and call expressions from PHP AST.
"""

from typing import List, Optional, Tuple, Dict, Any
from tree_sitter import Node
from php_deserial_sast.core.parser import (
    get_node_text,
    get_node_location,
    find_nodes_by_type,
    find_child_by_type,
    find_child_by_field,
)
from php_deserial_sast.core.symbol_table import (
    ClassSymbol,
    MethodSymbol,
    PropertySymbol,
    FunctionSymbol,
    CallExpressionInfo,
    ProjectSymbolTable,
    MAGIC_METHODS,
)


RCE_SINKS = {
    "eval", "assert", "system", "exec", "passthru", "shell_exec",
    "popen", "proc_open", "pcntl_exec", "create_function"
}

DYNAMIC_INVOKE_SINKS = {
    "call_user_func", "call_user_func_array", "forward_static_call",
    "forward_static_call_array", "array_map", "array_filter",
    "array_walk", "usort", "uasort", "uksort"
}

FILE_WRITE_SINKS = {
    "file_put_contents", "fwrite", "fputs", "touch"
}

FILE_DELETE_SINKS = {
    "unlink", "rmdir"
}

FILE_READ_SINKS = {
    "file_get_contents", "readfile", "file", "fopen",
    "show_source", "highlight_file"
}

INCLUDE_SINKS = {
    "include", "include_once", "require", "require_once"
}

PHAR_TRIGGER_SINKS = {
    "file_exists", "is_file", "is_dir", "is_readable", "is_writable",
    "is_executable", "filectime", "filemtime", "fileatime", "filesize",
    "stat", "lstat", "exif_read_data", "exif_thumbnail", "exif_imagetype",
    "md5_file", "sha1_file", "hash_file", "hash_hmac_file", "getimagesize",
    "get_meta_tags", "simplexml_load_file", "copy", "rename"
}

ALL_DANGEROUS_SINKS = (
    RCE_SINKS | DYNAMIC_INVOKE_SINKS | FILE_WRITE_SINKS |
    FILE_DELETE_SINKS | FILE_READ_SINKS | INCLUDE_SINKS | {"unserialize"} | PHAR_TRIGGER_SINKS
)


def categorize_sink(func_name: str) -> Optional[str]:
    """Return category of dangerous sink."""
    if func_name in RCE_SINKS:
        return "RCE"
    if func_name in DYNAMIC_INVOKE_SINKS:
        return "DYNAMIC_INVOCATION"
    if func_name in FILE_WRITE_SINKS:
        return "FILE_WRITE"
    if func_name in FILE_DELETE_SINKS:
        return "FILE_DELETE"
    if func_name in FILE_READ_SINKS or func_name in INCLUDE_SINKS:
        return "FILE_READ_INCLUDE"
    if func_name == "unserialize":
        return "DESERIALIZATION"
    if func_name in PHAR_TRIGGER_SINKS:
        return "PHAR_TRIGGER"
    return None


class ASTVisitor:
    """Visits Tree-sitter PHP AST nodes to collect classes, methods, and expressions."""

    def __init__(self, symbol_table: ProjectSymbolTable, file_path: str, source_bytes: bytes):
        self.symbol_table = symbol_table
        self.file_path = file_path
        self.source_bytes = source_bytes
        self.current_namespace = ""
        self.current_use_map: Dict[str, str] = {}

    def extract_all(self, root_node: Node):
        """Extract all symbols from root node of a PHP file."""
        self.symbol_table.files_scanned.add(self.file_path)
        self._extract_namespace(root_node)
        self._extract_use_declarations(root_node)
        self.symbol_table.file_use_maps[self.file_path] = dict(self.current_use_map)
        self._extract_classes(root_node)
        self._extract_functions(root_node)

    def _extract_namespace(self, root_node: Node):
        """Find namespace definition in the file."""
        for ns_node in find_nodes_by_type(root_node, "namespace_definition"):
            name_node = find_child_by_field(ns_node, "name") or find_child_by_type(ns_node, "namespace_name")
            if name_node:
                self.current_namespace = get_node_text(name_node, self.source_bytes).strip("\\ ")
                break

    def _extract_use_declarations(self, root_node: Node):
        """Extract use imports (aliases) from namespace_use_declaration nodes."""
        for use_node in find_nodes_by_type(root_node, "namespace_use_declaration"):
            for clause in find_nodes_by_type(use_node, "namespace_use_clause"):
                target_node = None
                alias = None
                has_as = False

                for child in clause.children:
                    if child.type in ("qualified_name", "name") and not target_node:
                        target_node = child
                    elif child.type == "as":
                        has_as = True
                    elif child.type == "name" and has_as:
                        alias = get_node_text(child, self.source_bytes).strip()

                if target_node:
                    fqcn = get_node_text(target_node, self.source_bytes).strip("\\ ")
                    if not alias:
                        alias = fqcn.split("\\")[-1]
                    self.current_use_map[alias] = fqcn

    def _extract_classes(self, root_node: Node):
        """Extract all class declarations in the file."""
        for cls_node in find_nodes_by_type(root_node, ["class_declaration", "trait_declaration"]):
            name_node = find_child_by_field(cls_node, "name")
            if not name_node:
                continue

            class_name = get_node_text(name_node, self.source_bytes).strip()
            full_name = f"{self.current_namespace}\\{class_name}" if self.current_namespace else class_name

            # Parent class (extends)
            parent_class = None
            resolved_parent = None
            base_clause = find_child_by_type(cls_node, "base_clause")
            if base_clause:
                for child in base_clause.children:
                    if child.type in ("name", "qualified_name"):
                        parent_class = get_node_text(child, self.source_bytes).strip()
                        resolved_parent = self.symbol_table.resolve_class_name(parent_class, self.current_namespace, self.file_path)
                        break

            # Interfaces (implements)
            interfaces = []
            resolved_interfaces = []
            interface_clause = find_child_by_type(cls_node, "class_interface_clause")
            if interface_clause:
                for child in interface_clause.children:
                    if child.type in ("name", "qualified_name"):
                        raw_iface = get_node_text(child, self.source_bytes).strip()
                        interfaces.append(raw_iface)
                        resolved_interfaces.append(self.symbol_table.resolve_class_name(raw_iface, self.current_namespace, self.file_path))

            cls_symbol = ClassSymbol(
                name=class_name,
                namespace=self.current_namespace,
                full_name=full_name,
                parent_class=parent_class,
                resolved_parent=resolved_parent,
                interfaces=interfaces,
                resolved_interfaces=resolved_interfaces,
                use_map=dict(self.current_use_map),
                file_path=self.file_path,
                location=get_node_location(cls_node, self.file_path)
            )

            # Body declaration list
            body_node = find_child_by_type(cls_node, "declaration_list")
            if body_node:
                self._extract_properties(body_node, cls_symbol)
                self._extract_methods(body_node, cls_symbol)

            self.symbol_table.add_class(cls_symbol)

    def _extract_properties(self, body_node: Node, cls_symbol: ClassSymbol):
        """Extract class properties."""
        for prop_decl in find_nodes_by_type(body_node, "property_declaration"):
            visibility = "public"
            for child in prop_decl.children:
                if child.type == "visibility_modifier":
                    visibility = get_node_text(child, self.source_bytes)

            for prop_elem in find_nodes_by_type(prop_decl, "property_element"):
                var_node = find_child_by_field(prop_elem, "name") or find_child_by_type(prop_elem, "variable_name")
                if var_node:
                    prop_name = get_node_text(var_node, self.source_bytes).lstrip("$")
                    default_val = None
                    val_node = find_child_by_field(prop_elem, "default_value")
                    if val_node:
                        default_val = get_node_text(val_node, self.source_bytes)

                    prop_sym = PropertySymbol(
                        name=prop_name,
                        visibility=visibility,
                        default_value=default_val,
                        location=get_node_location(prop_elem, self.file_path)
                    )
                    cls_symbol.properties[prop_name] = prop_sym

    def _extract_methods(self, body_node: Node, cls_symbol: ClassSymbol):
        """Extract methods and analyze their internal calls, sinks, and property usages."""
        for method_node in find_nodes_by_type(body_node, "method_declaration"):
            name_node = find_child_by_field(method_node, "name")
            if not name_node:
                continue

            method_name = get_node_text(name_node, self.source_bytes).strip()
            visibility = "public"
            is_static = False
            for child in method_node.children:
                if child.type == "visibility_modifier":
                    visibility = get_node_text(child, self.source_bytes)
                elif child.type == "static_modifier":
                    is_static = True

            # Extract parameters
            params = []
            params_node = find_child_by_field(method_node, "parameters") or find_child_by_type(method_node, "formal_parameters")
            if params_node:
                for param in find_nodes_by_type(params_node, "simple_parameter"):
                    p_name = find_child_by_field(param, "name") or find_child_by_type(param, "variable_name")
                    if p_name:
                        params.append(get_node_text(p_name, self.source_bytes))

            # Method body
            body = find_child_by_field(method_node, "body") or find_child_by_type(method_node, "compound_statement")
            body_text = get_node_text(body, self.source_bytes) if body else ""

            method_sym = MethodSymbol(
                name=method_name,
                class_name=cls_symbol.name,
                visibility=visibility,
                is_static=is_static,
                parameters=params,
                is_magic=(method_name in MAGIC_METHODS),
                location=get_node_location(method_node, self.file_path),
                body_text=body_text,
                ast_node=method_node
            )

            if body:
                self._analyze_method_body(body, method_sym)

            cls_symbol.methods[method_name] = method_sym

    def _analyze_method_body(self, body_node: Node, method_sym: MethodSymbol):
        """Analyze calls, member calls, property accesses, and string conversions inside method body."""
        # 1. Function calls (e.g. eval($this->x), file_put_contents($this->f, $this->d))
        for call_node in find_nodes_by_type(body_node, "function_call_expression"):
            fn_node = find_child_by_field(call_node, "function")
            if fn_node:
                fn_name = get_node_text(fn_node, self.source_bytes).strip("\\ ")
                args = self._extract_arguments(call_node)
                category = categorize_sink(fn_name)
                is_sink = category is not None

                call_info = CallExpressionInfo(
                    call_type="FUNCTION_CALL",
                    callee_name=fn_name,
                    arguments=args,
                    location=get_node_location(call_node, self.file_path),
                    ast_node=call_node,
                    is_sink=is_sink,
                    sink_category=category
                )
                method_sym.calls.append(call_info)

        # 2. Member method calls (e.g. $this->handler->close(), $this->cleanUp())
        for mcall_node in find_nodes_by_type(body_node, ["member_call_expression", "nullsafe_member_call_expression"]):
            obj_node = find_child_by_field(mcall_node, "object")
            name_node = find_child_by_field(mcall_node, "name")
            if name_node:
                callee_name = get_node_text(name_node, self.source_bytes).strip()
                target_obj = get_node_text(obj_node, self.source_bytes).strip() if obj_node else None
                args = self._extract_arguments(mcall_node)
                category = categorize_sink(callee_name)

                call_info = CallExpressionInfo(
                    call_type="METHOD_CALL",
                    callee_name=callee_name,
                    target_object=target_obj,
                    arguments=args,
                    location=get_node_location(mcall_node, self.file_path),
                    ast_node=mcall_node,
                    is_sink=(category is not None),
                    sink_category=category
                )
                method_sym.calls.append(call_info)

        # 3. Dynamic method calls / property accesses (e.g. ($this->func)($arg), $this->$callback($data))
        for dcall_node in find_nodes_by_type(body_node, "dynamic_variable_name"):
            var_text = get_node_text(dcall_node, self.source_bytes)
            method_sym.property_accesses.add(var_text)

        # 4. Property accesses ($this->property_name)
        for mem_access in find_nodes_by_type(body_node, "member_access_expression"):
            obj_node = find_child_by_field(mem_access, "object")
            prop_node = find_child_by_field(mem_access, "name")
            if obj_node and prop_node:
                obj_text = get_node_text(obj_node, self.source_bytes)
                prop_text = get_node_text(prop_node, self.source_bytes)
                if "$this" in obj_text:
                    method_sym.property_accesses.add(prop_text)

        # 5. String conversions (e.g. (string)$this->handler or string concatenation with property)
        for cast_node in find_nodes_by_type(body_node, "cast_expression"):
            type_node = find_child_by_type(cast_node, "cast_type")
            if type_node and "string" in get_node_text(type_node, self.source_bytes).lower():
                val_node = find_child_by_field(cast_node, "value")
                if val_node:
                    val_text = get_node_text(val_node, self.source_bytes)
                    method_sym.string_conversions.append(val_text)

        # Binary string concatenation ($x . $this->prop or "$this->prop")
        for bin_expr in find_nodes_by_type(body_node, "binary_expression"):
            op_node = find_child_by_field(bin_expr, "operator") or find_child_by_type(bin_expr, ".")
            if op_node and get_node_text(op_node, self.source_bytes) == ".":
                left = find_child_by_field(bin_expr, "left")
                right = find_child_by_field(bin_expr, "right")
                for side in (left, right):
                    if side and "$this->" in get_node_text(side, self.source_bytes):
                        method_sym.string_conversions.append(get_node_text(side, self.source_bytes))

    def _extract_arguments(self, call_node: Node) -> List[str]:
        """Extract text of argument expressions."""
        args = []
        args_node = find_child_by_field(call_node, "arguments") or find_child_by_type(call_node, "arguments")
        if args_node:
            for arg_child in args_node.children:
                if arg_child.type in ("argument", "variable_name", "string", "member_access_expression", "binary_expression"):
                    args.append(get_node_text(arg_child, self.source_bytes))
        return args

    def _extract_functions(self, root_node: Node):
        """Extract standalone function definitions."""
        for fn_node in find_nodes_by_type(root_node, "function_definition"):
            name_node = find_child_by_field(fn_node, "name")
            if not name_node:
                continue

            fn_name = get_node_text(name_node, self.source_bytes).strip()
            full_name = f"{self.current_namespace}\\{fn_name}" if self.current_namespace else fn_name

            func_sym = FunctionSymbol(
                name=fn_name,
                namespace=self.current_namespace,
                full_name=full_name,
                location=get_node_location(fn_node, self.file_path),
                ast_node=fn_node,
                file_path=self.file_path
            )
            self.symbol_table.add_function(func_sym)
