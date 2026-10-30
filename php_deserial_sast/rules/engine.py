"""
Semgrep-like Rule Engine for loading and executing YAML detection rules.
"""

import os
import glob
import re
from typing import List, Dict, Any, Optional, Tuple
import yaml
from tree_sitter import Node
from php_deserial_sast.rules.matcher import PatternMatcher
from php_deserial_sast.core.parser import (
    get_node_text,
    get_node_location,
    find_nodes_by_type,
    find_child_by_field,
    get_code_snippet,
)
from php_deserial_sast.models import (
    Finding,
    VulnerabilityType,
    Severity,
    Confidence,
)


def _normalize_pattern_item(item: Any) -> Optional[str]:
    if item is None:
        return None
    if isinstance(item, str):
        if item.strip():
            return item
    if isinstance(item, dict) and set(item) == {"pattern"}:
        return _normalize_pattern_item(item["pattern"])
    raise ValueError("Expected a non-empty pattern string or {pattern: string}; nested operators and pattern-regex are unsupported")


def _normalize_pattern_list(raw_list: Any) -> List[str]:
    if not raw_list:
        return []
    if isinstance(raw_list, str):
        return [raw_list]
    result = []
    if isinstance(raw_list, list):
        for item in raw_list:
            norm = _normalize_pattern_item(item)
            if norm is None:
                raise ValueError("Null pattern is unsupported")
            result.append(norm)
    else:
        raise ValueError("Expected a pattern list or string")
    return result


class Rule:
    def __init__(self, raw_dict: Dict[str, Any]):
        if not isinstance(raw_dict, dict):
            raise ValueError("Rule must be a mapping")
        allowed = {"id", "message", "severity", "confidence", "cwe", "owasp", "remediation",
                   "pattern", "pattern-either", "pattern-not", "pattern-inside", "mode", "languages", "metadata"}
        unknown = set(raw_dict) - allowed
        if unknown:
            raise ValueError("Unsupported rule fields: " + ", ".join(sorted(unknown)))
        if raw_dict.get("mode", "search") != "search":
            raise ValueError("Only search rules are supported; YAML taint rules are not executed by this matcher")
        if "languages" in raw_dict and raw_dict["languages"] != ["php"]:
            raise ValueError("Only languages: [php] is supported")
        if not isinstance(raw_dict.get("id"), str) or not raw_dict["id"].strip():
            raise ValueError("A non-empty rule id is required")
        if ("pattern" in raw_dict) == ("pattern-either" in raw_dict):
            raise ValueError("Specify exactly one of pattern or pattern-either")
        self.id = raw_dict.get("id", "unknown-rule")
        self.message = raw_dict.get("message", "")
        severity = raw_dict.get("severity", "MEDIUM").upper()
        self.severity = Severity({"ERROR": "HIGH", "WARNING": "MEDIUM"}.get(severity, severity))
        self.confidence = Confidence(raw_dict.get("confidence", "HIGH").upper())
        self.cwe = raw_dict.get("cwe", "CWE-502: Deserialization of Untrusted Data")
        self.owasp = raw_dict.get("owasp", "A08:2021-Software and Data Integrity Failures")
        self.remediation = raw_dict.get("remediation", "")
        
        self.pattern = _normalize_pattern_item(raw_dict.get("pattern"))
        self.pattern_either = _normalize_pattern_list(raw_dict.get("pattern-either", []))
        self.pattern_not = _normalize_pattern_list(raw_dict.get("pattern-not", []))
        self.pattern_inside = _normalize_pattern_item(raw_dict.get("pattern-inside"))
        if not self.pattern and not self.pattern_either:
            raise ValueError("Rule requires at least one non-empty pattern")
        self.metadata = raw_dict.get("metadata", {})
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a mapping")


class RuleEngine:
    """Manages rule loading and AST matching against YAML rules."""

    def __init__(self, rules_dir: Optional[str] = None):
        self.matcher = PatternMatcher()
        self.rules: List[Rule] = []
        self.load_errors: List[Tuple[str, str]] = []
        if rules_dir and os.path.exists(rules_dir):
            self.load_rules_from_dir(rules_dir)

    def load_rules_from_dir(self, directory: str):
        """Load all YAML rules from a directory recursively."""
        pattern = os.path.join(directory, "**", "*.y*ml")
        for file_path in glob.glob(pattern, recursive=True):
            self.load_rule_file(file_path)

    def load_rule_file(self, file_path: str):
        """Load rules from a single YAML file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if not data:
                    return
                rules_list = data.get("rules", [])
                if not isinstance(rules_list, list) or not rules_list:
                    raise ValueError("rules must be a non-empty list")
                for r_data in rules_list:
                    try:
                        rule = Rule(r_data)
                        if any(existing.id == rule.id for existing in self.rules):
                            raise ValueError("Duplicate rule id: " + rule.id)
                        self.rules.append(rule)
                    except Exception as exc:
                        rule_id = r_data.get("id", "<unknown>") if isinstance(r_data, dict) else "<invalid>"
                        self.load_errors.append((file_path, f"Rule {rule_id}: {type(exc).__name__}: {exc}"))
        except Exception as e:
            self.load_errors.append((file_path, f"{type(e).__name__}: {e}"))

    def evaluate_file(self, file_path: str, source_bytes: bytes, root_node: Node, node_index=None,
                      file_flow=None) -> List[Finding]:
        """Evaluate all loaded rules against a file's AST with AST subsumption filtering."""
        findings: List[Finding] = []
        file_text = None
        source_lines = None
        content_lower = source_bytes.lower()
        candidate_cache = {}
        function_call_index = None

        for rule in self.rules:
            # Determine appropriate AST candidate types based on rule target
            patterns = [rule.pattern] if rule.pattern else rule.pattern_either
            # A named function scope cannot match without its name in the file.
            # Skip unrelated files before iterating their AST call candidates.
            if rule.pattern_inside:
                scoped_function = re.search(
                    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)", rule.pattern_inside
                )
                if (scoped_function and scoped_function.group(1).lower().encode()
                        not in content_lower):
                    continue
            # A required literal function identifier must occur in the file.
            # Unknown/custom pattern shapes always fall through to matching.
            identifiers = [re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", p) for p in patterns if p]
            if identifiers and all(identifiers) and not any(m.group(1).lower().encode() in content_lower for m in identifiers):
                continue
            is_class_rule = any("class " in p for p in patterns if p)
            is_func_rule = any("function " in p for p in patterns if p)

            if is_class_rule:
                candidate_types = ["class_declaration", "trait_declaration"]
            elif is_func_rule:
                candidate_types = ["method_declaration", "function_definition"]
            else:
                candidate_types = [
                    "function_call_expression",
                    "member_call_expression",
                    "nullsafe_member_call_expression",
                    "scoped_call_expression",
                    "assignment_expression",
                    "subscript_expression",
                    "expression_statement",
                ]

            if not is_class_rule and not is_func_rule:
                for pattern in patterns:
                    compiled = self.matcher._expression_pattern(pattern) if pattern else None
                    if compiled is not None and compiled[0].type not in candidate_types:
                        candidate_types.append(compiled[0].type)
            candidate_key = tuple(candidate_types)
            # Every direct literal function pattern can only match a call
            # with that exact callee. Index once instead of trying every rule
            # against every call/statement in a large project file.
            literal_functions = []
            literal_patterns = {}
            for pattern in patterns:
                compiled = self.matcher._expression_pattern(pattern) if pattern else None
                if compiled is None or compiled[0].type != 'function_call_expression':
                    literal_functions = []
                    literal_patterns = {}
                    break
                callee = compiled[0].child_by_field_name('function')
                if callee is None or callee.type not in {'name', 'qualified_name'}:
                    literal_functions = []
                    literal_patterns = {}
                    break
                name = get_node_text(callee, compiled[1]).strip('\\').lower()
                literal_functions.append(name)
                literal_patterns.setdefault(name, []).append(pattern)
            if literal_functions:
                if function_call_index is None:
                    function_call_index = {}
                    calls = (node_index.by_type.get('function_call_expression', ())
                             if node_index is not None else
                             find_nodes_by_type(root_node, 'function_call_expression'))
                    for call in calls:
                        callee = call.child_by_field_name('function')
                        if callee is None:
                            continue
                        name = get_node_text(callee, source_bytes).strip('\\').lower()
                        function_call_index.setdefault(name, []).append(call)
                candidate_nodes = sorted(
                    (node for name in set(literal_functions)
                     for node in function_call_index.get(name, ())),
                    key=lambda node: node.start_byte,
                )
            else:
                if candidate_key not in candidate_cache:
                    candidate_cache[candidate_key] = (node_index.find(candidate_types)
                                                      if node_index is not None else
                                                      list(find_nodes_by_type(root_node, candidate_types)))
                candidate_nodes = candidate_cache[candidate_key]
            # Collect all matches for this rule in the file
            matched_nodes: List[Tuple[Node, Dict[str, str]]] = []
            for node in candidate_nodes:
                matching_patterns = None
                if literal_patterns:
                    callee = node.child_by_field_name('function')
                    name = get_node_text(callee, source_bytes).strip('\\').lower()
                    matching_patterns = literal_patterns[name]
                matched, bindings = self._check_node_matches_rule(
                    node, rule, source_bytes, matching_patterns)
                if matched:
                    if file_flow is not None and not file_flow._runtime_branch_reachable(node):
                        continue
                    if (file_flow is not None and node.type == "function_call_expression"
                            and rule.id in {"php-insecure-unserialize-direct",
                                            "php-unserialize-without-allowed-classes",
                                            "php-unserialize-allows-all-classes",
                                            "php-unserialize-review",
                                            "php-unserialize-cookie-session"}
                            and file_flow.call_name(node) == "unserialize"
                            and file_flow.unserialize_safe(node)):
                        continue
                    matched_nodes.append((node, bindings))

            # Innermost Subsumption: If an inner child node matched, discard ancestor container matches
            minimum_end = float("inf")
            for node, bindings in sorted(matched_nodes, key=lambda item: (-item[0].start_byte, item[0].end_byte)):
                has_child_match = minimum_end <= node.end_byte
                minimum_end = min(minimum_end, node.end_byte)
                if has_child_match:
                    continue

                loc = get_node_location(node, file_path)
                if source_lines is None:
                    if file_text is None:
                        file_text = source_bytes.decode("utf-8", errors="replace")
                    source_lines = file_text.splitlines()
                snippet = get_code_snippet(source_bytes, loc.start_line, loc.end_line, lines=source_lines)
                
                # Format message with captured bindings if available
                msg = rule.message
                for k, v in bindings.items():
                    msg = msg.replace(k, v)

                finding = Finding(
                    id=f"{rule.id}-{file_path}-{loc.start_line}-{loc.start_col}",
                    rule_id=rule.id,
                    vuln_type=VulnerabilityType.CUSTOM_RULE_MATCH,
                    title=rule.id.replace("-", " ").title(),
                    description=msg,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    location=loc,
                    code_snippet=snippet,
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    remediation=rule.remediation,
                    metadata={"rule_metadata": rule.metadata, "bindings": bindings, "analysis_status": "syntactic_rule_match", "exploitability_verified": False}
                )
                findings.append(finding)

        return findings

    def _check_node_matches_rule(
        self,
        node: Node,
        rule: Rule,
        source_bytes: bytes,
        candidate_patterns=None,
    ) -> Tuple[bool, Dict[str, str]]:
        # Reject unrelated nodes before walking or rendering their ancestors.
        all_bindings: Dict[str, str] = {}
        matched = False
        patterns = candidate_patterns if candidate_patterns is not None else (
            [rule.pattern] if rule.pattern else rule.pattern_either)
        for pattern in patterns:
            matched, bindings = self.matcher.matches_ast_node(pattern, node, source_bytes)
            if matched:
                all_bindings.update(bindings)
                break
        if not matched:
            return False, {}

        # 1. Check pattern-inside if specified: ensure an enclosing ancestor AST node matches
        if rule.pattern_inside:
            curr = node.parent
            inside_matched = False
            is_fn_pattern = "function " in rule.pattern_inside
            expected_fn = None
            generic_fn_scope = False
            if is_fn_pattern:
                fn_match = re.search(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)", rule.pattern_inside)
                expected_fn = fn_match.group(1).lower() if fn_match else None
                # This canonical scope pattern constrains the method name only.
                # A return type or parameter type must not hide a valid match.
                generic_fn_scope = bool(re.fullmatch(
                    r"function\s+[A-Za-z_]\w*\s*\(\s*\.\.\.\s*\)\s*\{\s*\.\.\.\s*\}",
                    rule.pattern_inside.strip(),
                ))

            while curr and curr.type != "program":
                # Error-recovery nodes can span most or all of a file. Matching
                # a function pattern against one of those nodes associates
                # unrelated methods with the function named in the pattern.
                if curr.type == "ERROR" or curr.is_error:
                    return False, {}

                if is_fn_pattern:
                    if curr.type in ("anonymous_function", "anonymous_function_creation_expression", "arrow_function"):
                        return False, {}
                    if curr.type in ("method_declaration", "function_definition"):
                        name_node = find_child_by_field(curr, "name")
                        actual_fn = (
                            get_node_text(name_node, source_bytes).strip().lower()
                            if name_node else ""
                        )
                        if expected_fn and actual_fn == expected_fn:
                            m_in = generic_fn_scope
                            if not m_in:
                                m_in, _ = self.matcher.matches(
                                    rule.pattern_inside,
                                    get_node_text(curr, source_bytes),
                                )
                            if m_in:
                                inside_matched = True
                                break
                    elif curr.type in ("class_declaration", "trait_declaration"):
                        break
                else:
                    curr_text = get_node_text(curr, source_bytes)
                    m_in, _ = self.matcher.matches(rule.pattern_inside, curr_text)
                    if m_in:
                        inside_matched = True
                        break
                curr = curr.parent
            if not inside_matched:
                return False, {}

        # 3. Check pattern-not exclusions
        for pat_not in rule.pattern_not:
            m_not, _ = self.matcher.matches_ast_node(pat_not, node, source_bytes)
            if m_not:
                return False, {}

        return True, all_bindings
