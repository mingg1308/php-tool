"""
Code Context Slicer for LLM verification.
Extracts only relevant AST and code slices to minimize prompt token count.
"""

from typing import Optional
import json
from php_deserial_sast.models import Finding
from php_deserial_sast.core.symbol_table import ProjectSymbolTable


class CodeSlicer:
    """Extracts focused code slices relevant to a finding or gadget chain."""

    def __init__(self, symbol_table: Optional[ProjectSymbolTable] = None):
        self.symbol_table = symbol_table

    def slice_finding(self, finding: Finding, max_lines: int = 120) -> str:
        """Create a concise code slice containing the vulnerability and its dataflow."""
        sections = []
        sections.append('// Analysis assumptions: ' + json.dumps(finding.metadata, ensure_ascii=False))

        # 1. Location and basic snippet
        sections.append(f"// File: {finding.location.file_path} (Lines {finding.location.start_line}-{finding.location.end_line})")
        sections.append(finding.code_snippet)

        # 2. If dataflow trace is present
        if finding.dataflow_trace:
            sections.append("\n// --- Dataflow Taint Trace ---")
            for i, step in enumerate(finding.dataflow_trace, 1):
                sections.append(f"// Step {i} ({step.location.file_path}:{step.location.start_line}): {step.description}")
                sections.append(f"   {step.code_snippet}")

        # 3. If gadget chain is present, include the participating class bodies
        if finding.gadget_chain and self.symbol_table:
            sections.append("\n// --- Participating Classes in POP Gadget Chain ---")
            for step in finding.gadget_chain.steps:
                cls_sym = self.symbol_table.get_class(step.class_name)
                if cls_sym:
                    method_sym = cls_sym.methods.get(step.method_name)
                    if method_sym:
                        sections.append(f"\n// {cls_sym.full_name or cls_sym.name}::{method_sym.name} at {method_sym.location}")
                        # Do not fabricate public properties/signatures or let a
                        # large property list consume the entire context budget.
                        body_lines = method_sym.body_text.splitlines()
                        budget = max(12, max_lines // max(1, len(finding.gadget_chain.steps)) - 5)
                        if len(body_lines) > budget:
                            sink_call = next((c for c in method_sym.calls if c.is_sink and c.location), None)
                            body_node = method_sym.ast_node.child_by_field_name("body")
                            center = sink_call.location.start_line - body_node.start_point[0] - 1 if sink_call and body_node else 0
                            start = max(0, min(center - budget // 2, len(body_lines) - budget))
                            sections.append(f"// Partial method body, omitted lines before: {start}; after: {len(body_lines)-start-budget}")
                            body_lines = body_lines[start:start + budget]
                        sections.extend(body_lines)

        full_slice = "\n".join(sections)
        lines = full_slice.splitlines()
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + "\n// ... [truncated for brevity]"
        return full_slice
