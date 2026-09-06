"""
Symbol Table and AST Metadata extraction for PHP codebase analysis.
"""

from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from php_deserial_sast.models import CodeLocation


MAGIC_METHODS = {
    "__construct", "__destruct", "__call", "__callStatic",
    "__get", "__set", "__isset", "__unset", "__sleep",
    "__wakeup", "__serialize", "__unserialize", "__toString",
    "__invoke", "__set_state", "__clone", "__debugInfo"
}

POP_ENTRY_MAGIC_METHODS = {
    "__destruct", "__wakeup", "__toString", "__unserialize",
    "__call", "__callStatic", "__get", "__set", "__isset", "__unset", "__invoke"
}


@dataclass
class PropertySymbol:
    name: str
    visibility: str = "public"  # public, protected, private
    type_hint: Optional[str] = None
    default_value: Optional[str] = None
    location: Optional[CodeLocation] = None


@dataclass
class CallExpressionInfo:
    call_type: str  # "FUNCTION_CALL", "METHOD_CALL", "STATIC_CALL", "DYNAMIC_CALL"
    callee_name: str  # Function or method name (e.g. "eval", "system", "close")
    target_object: Optional[str] = None  # e.g., "$this->handler", "$this", "$logger"
    arguments: List[str] = field(default_factory=list)
    location: Optional[CodeLocation] = None
    ast_node: Optional[Any] = None
    is_sink: bool = False
    sink_category: Optional[str] = None  # "RCE", "FILE_WRITE", "FILE_READ", etc.


@dataclass
class MethodSymbol:
    name: str
    class_name: str
    visibility: str = "public"
    is_static: bool = False
    parameters: List[str] = field(default_factory=list)
    is_magic: bool = False
    location: Optional[CodeLocation] = None
    body_text: str = ""
    ast_node: Optional[Any] = None
    calls: List[CallExpressionInfo] = field(default_factory=list)
    property_accesses: Set[str] = field(default_factory=set)  # Properties accessed e.g. $this->handler
    string_conversions: List[str] = field(default_factory=list)  # Expression converted to string (e.g. (string)$this->x)


@dataclass
class ClassSymbol:
    name: str
    namespace: str = ""
    full_name: str = ""
    parent_class: Optional[str] = None
    resolved_parent: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)
    resolved_interfaces: List[str] = field(default_factory=list)
    traits: List[str] = field(default_factory=list)
    properties: Dict[str, PropertySymbol] = field(default_factory=dict)
    methods: Dict[str, MethodSymbol] = field(default_factory=dict)
    use_map: Dict[str, str] = field(default_factory=dict)
    is_abstract: bool = False
    file_path: str = ""
    location: Optional[CodeLocation] = None

    def get_magic_methods(self) -> Dict[str, MethodSymbol]:
        return {name: m for name, m in self.methods.items() if m.is_magic}

    def get_pop_entry_methods(self) -> Dict[str, MethodSymbol]:
        return {name: m for name, m in self.methods.items() if name in POP_ENTRY_MAGIC_METHODS}


@dataclass
class FunctionSymbol:
    name: str
    namespace: str = ""
    full_name: str = ""
    parameters: List[str] = field(default_factory=list)
    location: Optional[CodeLocation] = None
    ast_node: Optional[Any] = None
    calls: List[CallExpressionInfo] = field(default_factory=list)
    file_path: str = ""


class ProjectSymbolTable:
    """Stores and resolves classes, interfaces, traits, and functions across the project."""

    def __init__(self):
        self.classes: Dict[str, ClassSymbol] = {}  # Key: full_name and short_name
        self.functions: Dict[str, FunctionSymbol] = {}
        self.files_scanned: Set[str] = set()
        self.file_use_maps: Dict[str, Dict[str, str]] = {}  # file_path -> {alias: FQCN}
        # Inter-procedural taint metadata
        self.function_taint_sources: Dict[str, Tuple[bool, List[Any], str]] = {}  # func/method -> (is_tainted, steps, source_name)
        self.function_sink_params: Dict[str, List[Tuple[int, str, CodeLocation]]] = {}  # func/method -> list of (param_idx, sink_name, loc)

    def add_class(self, cls: ClassSymbol):
        self.classes[cls.name] = cls
        if cls.full_name and cls.full_name != cls.name:
            self.classes[cls.full_name] = cls

    def add_function(self, func: FunctionSymbol):
        self.functions[func.name] = func
        if func.full_name and func.full_name != func.name:
            self.functions[func.full_name] = func

    def get_class(self, name: str) -> Optional[ClassSymbol]:
        return self.classes.get(name)

    def resolve_class_name(self, name: str, current_namespace: str = "", file_path: str = "") -> str:
        """Resolve a PHP class name considering use imports, namespace, and symbol table."""
        if not name:
            return ""
        if name.startswith("\\"):
            return name.lstrip("\\")

        # 1. Check use imports for the file
        if file_path in self.file_use_maps:
            use_map = self.file_use_maps[file_path]
            if name in use_map:
                return use_map[name]
            parts = name.split("\\")
            if parts[0] in use_map:
                return f"{use_map[parts[0]]}\\{'\\'.join(parts[1:])}"

        # 2. Check current namespace
        if current_namespace:
            namespaced_name = f"{current_namespace}\\{name}"
            if namespaced_name in self.classes:
                return namespaced_name

        # 3. Direct match
        if name in self.classes:
            return self.classes[name].full_name or name

        return f"{current_namespace}\\{name}" if current_namespace else name

    def get_all_unique_classes(self) -> List[ClassSymbol]:
        """Return list of unique ClassSymbol objects."""
        seen = set()
        unique = []
        for cls in self.classes.values():
            key = (cls.file_path, cls.name, cls.namespace)
            if key not in seen:
                seen.add(key)
                unique.append(cls)
        return unique

    def find_classes_with_method(self, method_name: str) -> List[ClassSymbol]:
        """Find all classes that define a specific method."""
        return [cls for cls in self.get_all_unique_classes() if method_name in cls.methods]

    def resolve_inheritance(self, class_name: str) -> List[ClassSymbol]:
        """Return hierarchy chain of classes from child to root ancestor."""
        hierarchy = []
        curr_name = class_name
        visited = set()
        while curr_name and curr_name not in visited:
            visited.add(curr_name)
            cls = self.get_class(curr_name)
            if not cls:
                break
            hierarchy.append(cls)
            curr_name = cls.parent_class
        return hierarchy
