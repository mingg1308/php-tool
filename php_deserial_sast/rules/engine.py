"""
Semgrep-like Rule Engine for loading and executing YAML detection rules.
"""

import os
import glob
from typing import List, Dict, Any, Optional, Tuple
import yaml
from tree_sitter import Node
from php_deserial_sast.rules.matcher import PatternMatcher
from php_deserial_sast.core.parser import (
    get_node_text,
    get_node_location,
    find_nodes_by_type,
    get_code_snippet,
)
from php_deserial_sast.models import (
    Finding,
    VulnerabilityType,
    Severity,
    Confidence,
)


def _normalize_pattern_item(item: Any) -> Optional[str]:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        if "pattern" in item:
            return str(item["pattern"])
        if "pattern-regex" in item:
            return str(item["pattern-regex"])
    return None


def _normalize_pattern_list(raw_list: Any) -> List[str]:
    if not raw_list:
        return []
    if isinstance(raw_list, str):
        return [raw_list]
    result = []
    if isinstance(raw_list, list):
        for item in raw_list:
            norm = _normalize_pattern_item(item)
            if norm:
                result.append(norm)
    return result


class Rule:
    def __init__(self, raw_dict: Dict[str, Any]):
        self.id = raw_dict.get("id", "unknown-rule")
        self.message = raw_dict.get("message", "")
        self.severity = Severity(raw_dict.get("severity", "MEDIUM").upper())
        self.confidence = Confidence(raw_dict.get("confidence", "HIGH").upper())
        self.cwe = raw_dict.get("cwe", "CWE-502: Deserialization of Untrusted Data")
        self.owasp = raw_dict.get("owasp", "A08:2021-Software and Data Integrity Failures")
        self.remediation = raw_dict.get("remediation", "")
        
        self.pattern = _normalize_pattern_item(raw_dict.get("pattern"))
        self.pattern_either = _normalize_pattern_list(raw_dict.get("pattern-either", []))
        self.pattern_not = _normalize_pattern_list(raw_dict.get("pattern-not", []))
        self.pattern_inside = _normalize_pattern_item(raw_dict.get("pattern-inside"))
        self.pattern_sources = _normalize_pattern_list(raw_dict.get("pattern-sources", []))
        self.pattern_sinks = _normalize_pattern_list(raw_dict.get("pattern-sinks", []))
        self.pattern_sanitizers = _normalize_pattern_list(raw_dict.get("pattern-sanitizers", []))


class RuleEngine:
    """Manages rule loading and AST matching against YAML rules."""

    def __init__(self, rules_dir: Optional[str] = None):
        self.matcher = PatternMatcher()
        self.rules: List[Rule] = []
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
                for r_data in rules_list:
                    rule = Rule(r_data)
                    self.rules.append(rule)
        except Exception as e:
            print(f"[-] Error loading rule file {file_path}: {e}")

    def evaluate_file(self, file_path: str, source_bytes: bytes, root_node: Node) -> List[Finding]:
        """Evaluate all loaded rules against a file's AST with AST subsumption filtering."""
        findings: List[Finding] = []
        file_text = source_bytes.decode("utf-8", errors="replace")

        for rule in self.rules:
            # Determine appropriate AST candidate types based on rule target
            patterns = [rule.pattern] if rule.pattern else rule.pattern_either
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
                    "scoped_call_expression",
                    "assignment_expression",
                    "subscript_expression",
                    "expression_statement",
                ]

            candidate_nodes = list(find_nodes_by_type(root_node, candidate_types))

            # Collect all matches for this rule in the file
            matched_nodes: List[Tuple[Node, Dict[str, str]]] = []
            for node in candidate_nodes:
                matched, bindings = self._check_node_matches_rule(node, rule, source_bytes, file_text)
                if matched:
                    matched_nodes.append((node, bindings))

            # Innermost Subsumption: If an inner child node matched, discard ancestor container matches
            for node, bindings in matched_nodes:
                has_child_match = any(
                    other != node and
                    node.start_byte <= other.start_byte and
                    other.end_byte <= node.end_byte
                    for other, _ in matched_nodes
                )
                if has_child_match:
                    continue

                loc = get_node_location(node, file_path)
                snippet = get_code_snippet(source_bytes, loc.start_line, loc.end_line)
                
                # Format message with captured bindings if available
                msg = rule.message
                for k, v in bindings.items():
                    msg = msg.replace(k, v)

                finding = Finding(
                    id=f"{rule.id}-{loc.start_line}",
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
                    metadata={"bindings": bindings}
                )
                findings.append(finding)

        return findings

    def _check_node_matches_rule(
        self,
        node: Node,
        rule: Rule,
        source_bytes: bytes,
        file_text: str
    ) -> Tuple[bool, Dict[str, str]]:
        node_text = get_node_text(node, source_bytes)

        # 1. Check pattern-inside if specified: ensure an enclosing ancestor AST node matches
        if rule.pattern_inside:
            curr = node.parent
            inside_matched = False
            is_fn_pattern = "function " in rule.pattern_inside

            while curr and curr.type != "program":
                # If searching for an enclosing function, do not match against outer class containers
                if is_fn_pattern and curr.type in ("class_declaration", "trait_declaration"):
                    break
                curr_text = get_node_text(curr, source_bytes)
                m_in, _ = self.matcher.matches(rule.pattern_inside, curr_text)
                if m_in:
                    inside_matched = True
                    break
                curr = curr.parent
            if not inside_matched:
                return False, {}

        # 2. Check pattern / pattern-either
        all_bindings: Dict[str, str] = {}
        matched = False

        if rule.pattern:
            matched, bindings = self.matcher.matches_ast_node(rule.pattern, node, source_bytes)
            if matched:
                all_bindings.update(bindings)
        elif rule.pattern_either:
            for pat in rule.pattern_either:
                m_e, bindings = self.matcher.matches_ast_node(pat, node, source_bytes)
                if m_e:
                    matched = True
                    all_bindings.update(bindings)
                    break
        else:
            return False, {}

        if not matched:
            return False, {}

        # 3. Check pattern-not exclusions
        for pat_not in rule.pattern_not:
            m_not, _ = self.matcher.matches_ast_node(pat_not, node, source_bytes)
            if m_not:
                return False, {}

        # 4. Check sanitizers
        for sanitizer in rule.pattern_sanitizers:
            m_san, _ = self.matcher.matches(sanitizer, node_text)
            if m_san:
                return False, {}

        return True, all_bindings
