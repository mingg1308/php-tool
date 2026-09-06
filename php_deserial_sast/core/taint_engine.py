"""
Dataflow and Taint Analysis Engine for PHP Insecure Deserialization and Phar vulnerabilities.
"""

from typing import List, Dict, Set, Tuple, Optional, Any, TYPE_CHECKING
from tree_sitter import Node
from php_deserial_sast.core.parser import (
    get_node_text,
    get_node_location,
    find_nodes_by_type,
    find_child_by_field,
    find_child_by_type,
    get_code_snippet
)
from php_deserial_sast.core.ast_visitor import PHAR_TRIGGER_SINKS
from php_deserial_sast.models import (
    Finding,
    VulnerabilityType,
    Severity,
    Confidence,
    TaintStep,
)
if TYPE_CHECKING:
    from php_deserial_sast.core.symbol_table import ProjectSymbolTable


SOURCES_SUPERGLOBALS = {
    "$_GET", "$_POST", "$_COOKIE", "$_REQUEST", "$_SERVER",
    "$_FILES", "$HTTP_RAW_POST_DATA"
}

SOURCES_FUNCTIONS = {
    "file_get_contents('php://input')",
    "php://input",
    "getallheaders",
    "apache_request_headers",
}

TRANSFORMATION_FUNCTIONS = {
    "base64_decode", "urldecode", "rawurldecode", "gzuncompress",
    "gzinflate", "gzdecode", "stripslashes", "trim", "rtrim", "ltrim",
    "substr", "str_replace", "sprintf", "vsprintf"
}

SAFE_CASTS = {"(int)", "(integer)", "(float)", "(double)", "(bool)", "(boolean)"}
SAFE_FUNCTIONS = {"intval", "floatval", "boolval", "is_numeric", "ctype_digit"}


class TaintEngine:
    """Performs intra-procedural and inter-procedural taint analysis for deserialization sinks."""

    def __init__(self, file_path: str, source_bytes: bytes, root_node: Node, symbol_table: Optional[Any] = None):
        self.file_path = file_path
        self.source_bytes = source_bytes
        self.root_node = root_node
        self.symbol_table = symbol_table
        # Variable name -> List of TaintSteps
        self.tainted_vars: Dict[str, List[TaintStep]] = {}
        # Variables holding phar prefix
        self.phar_prefix_vars: Set[str] = set()

    def collect_function_summaries(self):
        """Extract function return taint sources and parameter sink paths for inter-procedural analysis."""
        if not self.symbol_table:
            return

        self._trace_variable_assignments(self.root_node)

        for func_node in find_nodes_by_type(self.root_node, ["function_definition", "method_declaration"]):
            name_node = find_child_by_field(func_node, "name")
            if not name_node:
                continue
            func_name = get_node_text(name_node, self.source_bytes).strip()

            # Parameters
            params = []
            params_node = find_child_by_field(func_node, "parameters") or find_child_by_type(func_node, "formal_parameters")
            if params_node:
                for p in params_node.children:
                    p_text = get_node_text(p, self.source_bytes).strip()
                    if p_text.startswith("$"):
                        params.append(p_text.split("=")[0].strip())

            body = find_child_by_field(func_node, "body") or find_child_by_type(func_node, "compound_statement")
            if not body:
                continue

            # 1. Check if returns tainted value
            for ret_node in find_nodes_by_type(body, "return_statement"):
                for child in ret_node.children:
                    if child.type not in ("return", ";"):
                        is_t, steps, src = self._is_tainted_expression(child)
                        if is_t:
                            self.symbol_table.function_taint_sources[func_name] = (True, steps, src)
                            break

            # 2. Check if parameter reaches a sink directly inside this function
            for idx, param_var in enumerate(params):
                for call_node in find_nodes_by_type(body, "function_call_expression"):
                    call_fn = find_child_by_field(call_node, "function")
                    if not call_fn:
                        continue
                    call_fn_name = get_node_text(call_fn, self.source_bytes).strip("\\ ")
                    call_text = get_node_text(call_node, self.source_bytes)
                    if call_fn_name == "unserialize" and not self._is_unserialize_safe(call_node):
                        if param_var in call_text:
                            loc = get_node_location(call_node, self.file_path)
                            if func_name not in self.symbol_table.function_sink_params:
                                self.symbol_table.function_sink_params[func_name] = []
                            self.symbol_table.function_sink_params[func_name].append((idx, "unserialize", loc))
                    elif call_fn_name in PHAR_TRIGGER_SINKS:
                        if param_var in call_text:
                            loc = get_node_location(call_node, self.file_path)
                            if func_name not in self.symbol_table.function_sink_params:
                                self.symbol_table.function_sink_params[func_name] = []
                            self.symbol_table.function_sink_params[func_name].append((idx, call_fn_name, loc))

    def analyze(self) -> List[Finding]:
        """Scan file AST for tainted data flows into unserialize and phar sinks."""
        findings: List[Finding] = []

        # Analyze sequentially through top-level and function bodies
        self._trace_variable_assignments(self.root_node)
        
        # Check direct unserialize sinks
        direct_findings = self._check_unserialize_sinks()
        findings.extend(direct_findings)

        # Check phar deserialization sinks
        phar_findings = self._check_phar_sinks()
        findings.extend(phar_findings)

        # Check inter-procedural calls forwarding tainted parameters to sinks
        if self.symbol_table and self.symbol_table.function_sink_params:
            interproc_findings = self._check_interprocedural_calls()
            findings.extend(interproc_findings)

        return findings

    def _check_interprocedural_calls(self) -> List[Finding]:
        """Check calls to helper functions where arguments reach deserialization/phar sinks."""
        findings = []
        if not self.symbol_table:
            return findings

        for call_node in find_nodes_by_type(self.root_node, ["function_call_expression", "member_call_expression"]):
            fn_node = find_child_by_field(call_node, "function") or find_child_by_field(call_node, "name")
            if not fn_node:
                continue

            fn_name = get_node_text(fn_node, self.source_bytes).strip("\\ ")
            if fn_name not in self.symbol_table.function_sink_params:
                continue

            sink_infos = self.symbol_table.function_sink_params[fn_name]
            args_node = find_child_by_field(call_node, "arguments") or find_child_by_type(call_node, "arguments")
            if not args_node:
                continue

            arg_list = [c for c in args_node.children if c.type not in ("(", ")", ",")]

            for param_idx, sink_type, sink_loc in sink_infos:
                if param_idx < len(arg_list):
                    passed_arg = arg_list[param_idx]
                    is_tainted, steps, source_name = self._is_tainted_expression(passed_arg)
                    if is_tainted:
                        call_loc = get_node_location(call_node, self.file_path)
                        snippet = get_code_snippet(self.source_bytes, call_loc.start_line, call_loc.end_line)
                        
                        forward_step = TaintStep(
                            location=call_loc,
                            code_snippet=get_node_text(call_node, self.source_bytes),
                            description=f"Tainted parameter passed into function `{fn_name}()` which passes it to `{sink_type}()` at {sink_loc}.",
                            variable_name=get_node_text(passed_arg, self.source_bytes)
                        )
                        trace = steps + [forward_step]

                        is_phar = sink_type in PHAR_TRIGGER_SINKS
                        vuln_t = VulnerabilityType.PHAR_DESERIALIZATION if is_phar else VulnerabilityType.DIRECT_UNSERIALIZE
                        sev = Severity.HIGH if is_phar else Severity.CRITICAL

                        finding = Finding(
                            id=f"INTERPROC-{call_loc.start_line}-{fn_name}",
                            rule_id=f"php-interprocedural-{sink_type}-taint",
                            vuln_type=vuln_t,
                            title=f"Inter-procedural Insecure Deserialization via `{fn_name}()` -> `{sink_type}()`",
                            description=(
                                f"Tainted input from `{source_name}` is passed into helper function `{fn_name}()` at line {call_loc.start_line}, "
                                f"which forwards it to sink `{sink_type}()` at {sink_loc.file_path}:{sink_loc.start_line}."
                            ),
                            severity=sev,
                            confidence=Confidence.HIGH,
                            location=call_loc,
                            code_snippet=snippet,
                            dataflow_trace=trace,
                            cwe="CWE-502: Deserialization of Untrusted Data",
                            owasp="A08:2021-Software and Data Integrity Failures",
                            remediation=f"Validate or sanitize inputs before passing to `{fn_name}()` or refactor the callee sink."
                        )
                        findings.append(finding)

        return findings

    def _is_tainted_expression(self, expr_node: Node) -> Tuple[bool, List[TaintStep], Optional[str]]:
        """Check if an AST expression is tainted by untrusted source or tainted variable."""
        expr_text = get_node_text(expr_node, self.source_bytes).strip()

        # 1. Direct superglobals (e.g. $_POST['data'])
        for sg in SOURCES_SUPERGLOBALS:
            if expr_text.startswith(sg):
                step = TaintStep(
                    location=get_node_location(expr_node, self.file_path),
                    code_snippet=expr_text,
                    description=f"Untrusted input source directly accessed via `{sg}`.",
                    variable_name=sg
                )
                return True, [step], sg

        # 2. php://input or input functions
        if "php://input" in expr_text:
            step = TaintStep(
                location=get_node_location(expr_node, self.file_path),
                code_snippet=expr_text,
                description="Untrusted input read from `php://input` stream.",
                variable_name="php://input"
            )
            return True, [step], "php://input"

        # 3. Request object access ($request->get('param'), $request->input(...))
        if any(req in expr_text for req in ("$request->", "$this->request->", "$_REQUEST")):
            step = TaintStep(
                location=get_node_location(expr_node, self.file_path),
                code_snippet=expr_text,
                description=f"Untrusted request parameter accessed: `{expr_text}`.",
                variable_name=expr_text
            )
            return True, [step], expr_text

        # 4. Check if single variable is already in tainted map
        if expr_node.type == "variable_name" or expr_text.startswith("$"):
            var_name = expr_text.split("[")[0].strip()
            if var_name in self.tainted_vars:
                prev_steps = self.tainted_vars[var_name]
                step = TaintStep(
                    location=get_node_location(expr_node, self.file_path),
                    code_snippet=expr_text,
                    description=f"Tainted variable `{var_name}` used.",
                    variable_name=var_name
                )
                return True, prev_steps + [step], var_name

        # 5. Check function call transformations or inter-procedural returns
        if expr_node.type == "function_call_expression":
            fn_node = find_child_by_field(expr_node, "function")
            if fn_node:
                fn_name = get_node_text(fn_node, self.source_bytes).strip("\\ ")
                if fn_name in SAFE_FUNCTIONS:
                    return False, [], None

                # Check sprintf / printf dynamic phar formatting
                if fn_name in ("sprintf", "printf"):
                    args_node = find_child_by_field(expr_node, "arguments") or find_child_by_type(expr_node, "arguments")
                    if args_node:
                        arg_children = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                        if len(arg_children) >= 2:
                            fmt_text = get_node_text(arg_children[0], self.source_bytes)
                            has_phar = "phar://" in fmt_text
                            for arg in arg_children[1:]:
                                is_t, steps, vname = self._is_tainted_expression(arg)
                                if is_t:
                                    desc = (
                                        "Untrusted input dynamically formatted into 'phar://' stream wrapper via sprintf()."
                                        if has_phar else f"Tainted data passed through transformation function `{fn_name}()`."
                                    )
                                    step = TaintStep(
                                        location=get_node_location(expr_node, self.file_path),
                                        code_snippet=expr_text,
                                        description=desc,
                                        variable_name=vname
                                    )
                                    return True, steps + [step], vname

                # Inter-procedural function return taint
                if self.symbol_table and fn_name in self.symbol_table.function_taint_sources:
                    is_t, ret_steps, ret_src = self.symbol_table.function_taint_sources[fn_name]
                    step = TaintStep(
                        location=get_node_location(expr_node, self.file_path),
                        code_snippet=expr_text,
                        description=f"Untrusted input received from user function `{fn_name}()` return value.",
                        variable_name=ret_src
                    )
                    return True, ret_steps + [step], ret_src

                args_node = find_child_by_field(expr_node, "arguments") or find_child_by_type(expr_node, "arguments")
                if args_node:
                    for arg in args_node.children:
                        is_t, steps, vname = self._is_tainted_expression(arg)
                        if is_t:
                            step = TaintStep(
                                location=get_node_location(expr_node, self.file_path),
                                code_snippet=expr_text,
                                description=f"Tainted data passed through transformation function `{fn_name}()`.",
                                variable_name=vname
                            )
                            return True, steps + [step], vname

        # 6. Check binary concatenation with dynamic Phar detection
        if expr_node.type == "binary_expression":
            left = find_child_by_field(expr_node, "left")
            right = find_child_by_field(expr_node, "right")
            left_text = get_node_text(left, self.source_bytes).strip() if left else ""
            right_text = get_node_text(right, self.source_bytes).strip() if right else ""

            left_t, left_steps, left_src = self._is_tainted_expression(left) if left else (False, [], None)
            right_t, right_steps, right_src = self._is_tainted_expression(right) if right else (False, [], None)

            if left_t:
                if "phar://" in right_text or right_text in self.phar_prefix_vars:
                    step = TaintStep(
                        location=get_node_location(expr_node, self.file_path),
                        code_snippet=expr_text,
                        description="Untrusted input dynamically concatenated with 'phar://' stream wrapper protocol.",
                        variable_name=left_src
                    )
                    return True, left_steps + [step], left_src
                return True, left_steps, left_src

            if right_t:
                if "phar://" in left_text or left_text in self.phar_prefix_vars:
                    step = TaintStep(
                        location=get_node_location(expr_node, self.file_path),
                        code_snippet=expr_text,
                        description="Untrusted input dynamically concatenated with 'phar://' stream wrapper protocol.",
                        variable_name=right_src
                    )
                    return True, right_steps + [step], right_src
                return True, right_steps, right_src

        # 7. Check string interpolation (encapsed_string)
        if expr_node.type == "encapsed_string":
            if "phar://" in expr_text:
                for child in expr_node.children:
                    c_t, c_steps, c_src = self._is_tainted_expression(child)
                    if c_t:
                        step = TaintStep(
                            location=get_node_location(expr_node, self.file_path),
                            code_snippet=expr_text,
                            description="Untrusted input dynamically embedded inside 'phar://' string interpolation.",
                            variable_name=c_src
                        )
                        return True, c_steps + [step], c_src

        # 8. Check sub-nodes recursively
        for child in expr_node.children:
            if child.type in ("variable_name", "subscript_expression", "function_call_expression", "binary_expression"):
                is_t, steps, vname = self._is_tainted_expression(child)
                if is_t:
                    return True, steps, vname

        return False, [], None

    def _trace_variable_assignments(self, scope_node: Node):
        """Track variable assignments and propagate taint status."""
        for assign_node in find_nodes_by_type(scope_node, ["assignment_expression", "augmented_assignment_expression"]):
            left_node = find_child_by_field(assign_node, "left")
            right_node = find_child_by_field(assign_node, "right")

            if not left_node or not right_node:
                continue

            left_text = get_node_text(left_node, self.source_bytes).strip()
            right_text = get_node_text(right_node, self.source_bytes).strip()

            var_name = left_text.split("[")[0].strip()

            # Record variables holding phar:// prefix
            if "phar://" in right_text:
                self.phar_prefix_vars.add(var_name)

            # Check if right hand side is tainted
            is_tainted, steps, source_name = self._is_tainted_expression(right_node)

            if is_tainted:
                assign_step = TaintStep(
                    location=get_node_location(assign_node, self.file_path),
                    code_snippet=f"{left_text} = {right_text}",
                    description=f"Variable `{var_name}` assigned tainted value from `{source_name}`.",
                    variable_name=var_name
                )
                self.tainted_vars[var_name] = steps + [assign_step]
            else:
                # If variable was reassigned a safe constant/sanitized value, untaint it
                if var_name in self.tainted_vars and not any(sg in right_text for sg in SOURCES_SUPERGLOBALS):
                    if var_name not in right_text:
                        del self.tainted_vars[var_name]

    def _is_unserialize_safe(self, call_node: Node) -> bool:
        """Check if unserialize has allowed_classes => false or safe whitelist."""
        call_text = get_node_text(call_node, self.source_bytes)
        if "allowed_classes" in call_text:
            if "false" in call_text.lower() or "[]" in call_text or "array()" in call_text:
                return True
        return False

    def _check_unserialize_sinks(self) -> List[Finding]:
        """Find calls to unserialize() taking tainted inputs."""
        findings = []
        for call_node in find_nodes_by_type(self.root_node, "function_call_expression"):
            fn_node = find_child_by_field(call_node, "function")
            if not fn_node:
                continue

            fn_name = get_node_text(fn_node, self.source_bytes).strip("\\ ")
            if fn_name != "unserialize":
                continue

            # Check if safe options provided
            if self._is_unserialize_safe(call_node):
                continue

            # Get first argument
            args_node = find_child_by_field(call_node, "arguments") or find_child_by_type(call_node, "arguments")
            if not args_node or not args_node.children:
                continue

            first_arg = None
            for child in args_node.children:
                if child.type in ("argument", "variable_name", "subscript_expression", "function_call_expression", "binary_expression"):
                    first_arg = child
                    break

            if not first_arg:
                continue

            is_tainted, steps, source_name = self._is_tainted_expression(first_arg)
            loc = get_node_location(call_node, self.file_path)
            snippet = get_code_snippet(self.source_bytes, loc.start_line, loc.end_line)

            if is_tainted:
                sink_step = TaintStep(
                    location=loc,
                    code_snippet=get_node_text(call_node, self.source_bytes),
                    description="Tainted data passed into `unserialize()` sink without `allowed_classes => false`.",
                    variable_name=get_node_text(first_arg, self.source_bytes)
                )
                trace = steps + [sink_step]

                finding = Finding(
                    id=f"DESERIAL-DIRECT-{loc.start_line}",
                    rule_id="php-insecure-unserialize-tainted",
                    vuln_type=VulnerabilityType.DIRECT_UNSERIALIZE,
                    title="Direct Insecure Deserialization via unserialize()",
                    description=(
                        f"Unsanitized user-controlled input from `{source_name}` reaches the "
                        f"`unserialize()` sink at line {loc.start_line}. An attacker can supply a malicious serialized "
                        f"object payload to trigger arbitrary Object Injection or POP Gadget Chains leading to RCE."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    location=loc,
                    code_snippet=snippet,
                    dataflow_trace=trace,
                    cwe="CWE-502: Deserialization of Untrusted Data",
                    owasp="A08:2021-Software and Data Integrity Failures",
                    remediation=(
                        "1. Avoid passing untrusted user input into `unserialize()`.\n"
                        "2. Use safe data interchange formats such as JSON (`json_decode()` / `json_encode()`).\n"
                        "3. If object deserialization is strictly necessary, pass `['allowed_classes' => false]` "
                        "or specify an explicit whitelist of safe classes."
                    )
                )
                findings.append(finding)
            else:
                arg_text = get_node_text(first_arg, self.source_bytes).strip()
                if arg_text.startswith("$"):
                    finding = Finding(
                        id=f"DESERIAL-SUSPICIOUS-{loc.start_line}",
                        rule_id="php-unserialize-potential-taint",
                        vuln_type=VulnerabilityType.DIRECT_UNSERIALIZE,
                        title="Potential Insecure Deserialization via unserialize()",
                        description=(
                            f"Call to `unserialize({arg_text})` without `allowed_classes => false` detected. "
                            f"If variable `{arg_text}` can be influenced by an external user, it poses an Object Injection risk."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        location=loc,
                        code_snippet=snippet,
                        cwe="CWE-502: Deserialization of Untrusted Data",
                        owasp="A08:2021-Software and Data Integrity Failures",
                        remediation="Use `json_decode()` instead or add `['allowed_classes' => false]`."
                    )
                    findings.append(finding)

        return findings

    def _check_phar_sinks(self) -> List[Finding]:
        """Find filesystem function calls taking tainted input where 'phar://' stream wrapper may trigger deserialization."""
        findings = []
        for call_node in find_nodes_by_type(self.root_node, "function_call_expression"):
            fn_node = find_child_by_field(call_node, "function")
            if not fn_node:
                continue

            fn_name = get_node_text(fn_node, self.source_bytes).strip("\\ ")
            if fn_name not in PHAR_TRIGGER_SINKS:
                continue

            args_node = find_child_by_field(call_node, "arguments") or find_child_by_type(call_node, "arguments")
            if not args_node or not args_node.children:
                continue

            # First argument is typically the file path
            first_arg = None
            for child in args_node.children:
                if child.type in ("argument", "variable_name", "subscript_expression", "function_call_expression", "binary_expression"):
                    first_arg = child
                    break

            if not first_arg:
                continue

            is_tainted, steps, source_name = self._is_tainted_expression(first_arg)
            if is_tainted:
                loc = get_node_location(call_node, self.file_path)
                snippet = get_code_snippet(self.source_bytes, loc.start_line, loc.end_line)
                
                sink_step = TaintStep(
                    location=loc,
                    code_snippet=get_node_text(call_node, self.source_bytes),
                    description=f"Tainted file path passed into filesystem sink `{fn_name}()` which triggers Phar deserialization.",
                    variable_name=get_node_text(first_arg, self.source_bytes)
                )
                trace = steps + [sink_step]

                # Check if explicit phar wrapper was detected
                has_explicit_phar = any("phar://" in s.description or "phar://" in s.code_snippet for s in steps) or "phar://" in get_node_text(call_node, self.source_bytes)
                if has_explicit_phar:
                    title = f"Critical Phar Insecure Deserialization via `{fn_name}()` [Explicit Wrapper Detected]"
                    sev = Severity.CRITICAL
                    desc = (
                        f"Filesystem function `{fn_name}()` receives dynamically constructed `phar://` URL from `{source_name}` at line {loc.start_line}. "
                        f"The code dynamically prepends or constructs a `phar://` stream wrapper with untrusted user input. "
                        f"When PHP filesystem functions encounter a `phar://` wrapper, PHP automatically deserializes Phar archive metadata, "
                        f"allowing attackers to execute POP gadget chains without direct `unserialize()` calls."
                    )
                else:
                    title = f"Potential Phar Insecure Deserialization via `{fn_name}()`"
                    sev = Severity.HIGH
                    desc = (
                        f"Filesystem function `{fn_name}()` receives tainted input from `{source_name}` at line {loc.start_line}. "
                        f"In PHP, filesystem functions automatically deserialize Phar metadata when provided a `phar://` URL wrapper, "
                        f"allowing attackers to execute POP gadget chains without direct `unserialize()` calls."
                    )

                finding = Finding(
                    id=f"PHAR-DESERIAL-{loc.start_line}",
                    rule_id="php-phar-insecure-deserialization",
                    vuln_type=VulnerabilityType.PHAR_DESERIALIZATION,
                    title=title,
                    description=desc,
                    severity=sev,
                    confidence=Confidence.HIGH,
                    location=loc,
                    code_snippet=snippet,
                    dataflow_trace=trace,
                    cwe="CWE-502: Deserialization of Untrusted Data",
                    owasp="A08:2021-Software and Data Integrity Failures",
                    remediation=(
                        "1. Validate and sanitize file paths against `phar://` stream wrappers before passing to filesystem functions.\n"
                        "2. Ensure user-supplied paths do not begin with protocols (`phar://`, `zip://`, `compress.bzip2://`).\n"
                        "3. Use `basename()` or strict path whitelisting.\n"
                        "4. In PHP 8.0+, disable `phar.readonly` or avoid unvalidated filesystem calls."
                    )
                )
                findings.append(finding)

        return findings
