"""
Code Context Slicer for LLM verification.
Extracts only relevant AST and code slices to minimize prompt token count.
"""

from typing import Optional
from php_deserial_sast.models import Finding
from php_deserial_sast.core.symbol_table import ProjectSymbolTable


class CodeSlicer:
    """Extracts focused code slices relevant to a finding or gadget chain."""

    def __init__(self, symbol_table: Optional[ProjectSymbolTable] = None):
        self.symbol_table = symbol_table

    def slice_finding(self, finding: Finding, max_lines: int = 120) -> str:
        """Create a concise code slice containing the vulnerability and its dataflow."""
        sections = []

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
                        sections.append(f"\nclass {cls_sym.name} {{")
                        for p in cls_sym.properties.values():
                            sections.append(f"    public ${p.name};")
                        sections.append(f"    public function {method_sym.name}() {{")
                        sections.append(f"        {method_sym.body_text}")
                        sections.append("    }")
                        sections.append("}")

        full_slice = "\n".join(sections)
        lines = full_slice.splitlines()
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + "\n// ... [truncated for brevity]"
        return full_slice
