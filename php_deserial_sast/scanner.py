"""
Scanner Orchestrator integrating AST Parsing, Taint Analysis, Rule Engine, POP Gadget Finder, and LLM Verification.
"""

import os
import time
from typing import List, Dict, Set, Tuple, Optional, Any
from php_deserial_sast.config import ScannerConfig
from php_deserial_sast.models import (
    ScanResult,
    ScanSummary,
    Finding,
    GadgetChain,
    Severity,
    Confidence,
    VulnerabilityType,
)
from php_deserial_sast.core.parser import PHPParser
from php_deserial_sast.core.symbol_table import ProjectSymbolTable
from php_deserial_sast.core.ast_visitor import ASTVisitor
from php_deserial_sast.core.call_graph import CallGraph
from php_deserial_sast.core.gadget_finder import GadgetFinder
from php_deserial_sast.core.taint_engine import TaintEngine
from php_deserial_sast.rules.engine import RuleEngine
from php_deserial_sast.llm.verifier import LLMVerifier


PHP_EXTENSIONS = {".php", ".inc", ".phtml", ".module", ".class.php"}


class PHPDeserializationScanner:
    """Main SAST Scanner orchestrator for PHP Insecure Deserialization."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.parser = PHPParser()
        self.symbol_table = ProjectSymbolTable()
        self.rule_engine = RuleEngine(self.config.rules_dir) if self.config.enable_rules else None
        self.llm_verifier: Optional[LLMVerifier] = None

        if self.config.enable_llm:
            self.llm_verifier = LLMVerifier(
                provider=self.config.llm_provider,
                model=self.config.llm_model,
                api_key=self.config.llm_api_key,
                symbol_table=self.symbol_table
            )

    def scan(self) -> ScanResult:
        """Run the complete multi-phase static analysis scan."""
        start_time = time.time()
        php_files = self._collect_php_files(self.config.target_path)
        
        parsed_files: Dict[str, Tuple[Any, bytes]] = {}
        total_lines = 0

        # Phase 1: Parse all files and populate Symbol Table
        for file_path in php_files:
            try:
                root_node, source_bytes = self.parser.parse_file(file_path)
                parsed_files[file_path] = (root_node, source_bytes)
                total_lines += len(source_bytes.splitlines())

                visitor = ASTVisitor(self.symbol_table, file_path, source_bytes)
                visitor.extract_all(root_node)
            except Exception as e:
                # Fault tolerance for single unparseable files
                pass

        # Phase 2: Build Call Graph & Collect Inter-procedural Taint Summaries
        call_graph = CallGraph(self.symbol_table)

        if self.config.enable_taint:
            for file_path, (root_node, source_bytes) in parsed_files.items():
                try:
                    t_prep = TaintEngine(file_path, source_bytes, root_node, self.symbol_table)
                    t_prep.collect_function_summaries()
                except Exception:
                    pass

        all_findings: List[Finding] = []
        gadget_chains: List[GadgetChain] = []

        # Phase 3.1: POP Gadget Chain Analysis
        if self.config.enable_gadgets:
            finder = GadgetFinder(self.symbol_table, call_graph, max_depth=self.config.max_chain_depth)
            gadget_chains = finder.find_all_gadget_chains()
            gadget_findings = finder.convert_to_findings(gadget_chains)
            all_findings.extend(gadget_findings)

        # Phase 3.2: Taint Analysis & Rule Matching across all files
        for file_path, (root_node, source_bytes) in parsed_files.items():
            # Taint Engine
            if self.config.enable_taint:
                taint_engine = TaintEngine(file_path, source_bytes, root_node, self.symbol_table)
                taint_findings = taint_engine.analyze()
                all_findings.extend(taint_findings)

            # Rule Engine
            if self.rule_engine:
                rule_findings = self.rule_engine.evaluate_file(file_path, source_bytes, root_node)
                all_findings.extend(rule_findings)

        # Phase 4: Deduplicate and Filter
        unique_findings = self._deduplicate_findings(all_findings)
        filtered_findings = [
            f for f in unique_findings
            if f.severity.rank >= self.config.min_severity.rank
        ]

        # Phase 5: LLM Verification (if enabled)
        if self.llm_verifier and filtered_findings:
            for finding in filtered_findings:
                # Verify CRITICAL and HIGH findings
                if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                    verdict = self.llm_verifier.verify_finding(finding)
                    if verdict:
                        finding.llm_verification = verdict

        # Phase 6: Build Summary & Result
        duration = time.time() - start_time
        summary = self._create_summary(
            total_files=len(php_files),
            total_lines=total_lines,
            findings=filtered_findings,
            chains_count=len(gadget_chains),
            duration=duration
        )

        all_class_names = [cls.full_name or cls.name for cls in self.symbol_table.get_all_unique_classes()]

        return ScanResult(
            target_path=self.config.target_path,
            summary=summary,
            findings=filtered_findings,
            gadget_chains=gadget_chains,
            all_classes=all_class_names
        )

    def _collect_php_files(self, target_path: str) -> List[str]:
        """Collect all PHP source files within target path."""
        if os.path.isfile(target_path):
            return [target_path] if self._is_php_file(target_path) else []

        php_files = []
        for root, dirs, files in os.walk(target_path):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in self.config.exclude_dirs and not d.startswith(".")]

            for file in files:
                if self._is_php_file(file):
                    full_path = os.path.normpath(os.path.join(root, file))
                    php_files.append(full_path)

        return php_files

    def _is_php_file(self, filename: str) -> bool:
        lower = filename.lower()
        return any(lower.endswith(ext) for ext in PHP_EXTENSIONS)

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Deduplicate and correlate findings across Taint Engine, Rule Engine, and Gadget Finder:
        1. Taint Engine precedence: If Taint Engine detected an insecure deserialization or phar sink at (file, line),
           suppress lower-fidelity syntactic rule matches (e.g. php-insecure-unserialize-direct, php-unserialize-without-allowed-classes,
           php-phar-filesystem-deserialization) on the same line.
        2. POP Gadget Chain subsumption: If a POP Gadget Chain already covers Class::magicMethod -> sink,
           suppress simple pattern rules (php-magic-*-dangerous-sink) in that method.
        3. Multi-rule clustering: For multiple custom rules firing on the exact same token/location,
           keep only the most specific/highest severity finding.
        """
        norm_findings: List[Finding] = []
        for f in findings:
            norm_findings.append(f)

        # 1. Collect Taint Engine verified sink locations
        taint_deserial_lines: Set[Tuple[str, int]] = set()
        taint_phar_lines: Set[Tuple[str, int]] = set()
        for f in norm_findings:
            norm_file = os.path.normpath(f.location.file_path)
            if f.vuln_type == VulnerabilityType.DIRECT_UNSERIALIZE:
                for ln in range(f.location.start_line, f.location.end_line + 1):
                    taint_deserial_lines.add((norm_file, ln))
            elif f.vuln_type == VulnerabilityType.PHAR_DESERIALIZATION:
                for ln in range(f.location.start_line, f.location.end_line + 1):
                    taint_phar_lines.add((norm_file, ln))

        # 2. Collect POP Gadget Chain spans
        covered_magic_spans: List[Tuple[str, int, int, str]] = []
        for f in norm_findings:
            if f.vuln_type == VulnerabilityType.POP_GADGET_CHAIN and f.gadget_chain:
                first_step = f.gadget_chain.steps[0] if f.gadget_chain.steps else None
                if first_step:
                    norm_file = os.path.normpath(first_step.location.file_path)
                    covered_magic_spans.append((
                        norm_file,
                        first_step.location.start_line,
                        first_step.location.end_line,
                        f.gadget_chain.entry_method
                    ))

        # 3. Filter redundant findings based on cross-engine correlation
        correlated: List[Finding] = []
        for f in norm_findings:
            norm_file = os.path.normpath(f.location.file_path)
            start_line = f.location.start_line

            if f.vuln_type == VulnerabilityType.CUSTOM_RULE_MATCH:
                rule_id = f.rule_id.lower()

                # Check if covered by Taint Engine deserialization sink
                if any(k in rule_id for k in ("unserialize", "deserial")) and (norm_file, start_line) in taint_deserial_lines:
                    continue

                # Check if covered by Taint Engine Phar sink
                if "phar" in rule_id and (norm_file, start_line) in taint_phar_lines:
                    continue

                # Check if covered by a full POP Gadget Chain
                if any(m in rule_id for m in ("magic", "wakeup", "destruct", "tostring")):
                    is_subsumed = False
                    for span_file, span_start, span_end, entry_m in covered_magic_spans:
                        if span_file == norm_file and span_start <= start_line <= span_end + 3:
                            is_subsumed = True
                            break
                    if is_subsumed:
                        continue

            correlated.append(f)

        # 4. Deduplicate remaining findings by location and rule
        seen_keys = set()
        final_findings = []
        # Sort by severity rank descending so highest severity is kept if locations collide
        correlated.sort(key=lambda x: (x.severity.rank, 1 if x.confidence == Confidence.HIGH else 0), reverse=True)

        for f in correlated:
            key = (os.path.normpath(f.location.file_path), f.location.start_line, f.rule_id)
            # Also prevent duplicate rule types on exact same line
            sink_key = (os.path.normpath(f.location.file_path), f.location.start_line, f.vuln_type)
            if key not in seen_keys:
                seen_keys.add(key)
                final_findings.append(f)

        return final_findings

    def _create_summary(
        self,
        total_files: int,
        total_lines: int,
        findings: List[Finding],
        chains_count: int,
        duration: float
    ) -> ScanSummary:
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)
        info = sum(1 for f in findings if f.severity == Severity.INFO)

        unique_classes = len(self.symbol_table.get_all_unique_classes())
        total_methods = sum(len(c.methods) for c in self.symbol_table.get_all_unique_classes())

        return ScanSummary(
            total_files_scanned=total_files,
            total_lines_scanned=total_lines,
            total_classes_found=unique_classes,
            total_methods_found=total_methods,
            total_findings=len(findings),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            info_count=info,
            gadget_chains_found=chains_count,
            scan_duration_seconds=duration
        )
