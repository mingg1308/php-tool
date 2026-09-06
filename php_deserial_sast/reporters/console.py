"""
Rich Console Reporter for PHP Deserialization SAST Scanner.
"""

from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.tree import Tree
from rich.text import Text
from php_deserial_sast.models import ScanResult, Severity, Finding


class ConsoleReporter:
    """Renders scan results to terminal using Rich."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console(legacy_windows=False)

    def print_banner(self):
        banner_text = Text()
        banner_text.append("╔════════════════════════════════════════════════════════════════╗\n", style="bold cyan")
        banner_text.append("║    PHP INSECURE DESERIALIZATION & POP GADGET SAST SCANNER      ║\n", style="bold white")
        banner_text.append("║       Automated AST Analysis • Taint Flow • POP Gadget Chain   ║\n", style="cyan")
        banner_text.append("╚════════════════════════════════════════════════════════════════╝", style="bold cyan")
        self.console.print(Panel(banner_text, border_style="cyan", padding=(0, 1)))

    def render_results(self, result: ScanResult):
        """Render complete scan summary and findings."""
        self.print_banner()

        # Summary Statistics Table
        self._print_summary_table(result)

        if not result.findings:
            self.console.print(Panel("[bold green]✔ No Insecure Deserialization vulnerabilities detected![/bold green]", border_style="green"))
            return

        # Sort findings by severity
        sorted_findings = sorted(result.findings, key=lambda f: f.severity.rank, reverse=True)

        self.console.print(f"\n[bold underline]Detailed Vulnerability Findings ({len(sorted_findings)})[/bold underline]\n")

        for idx, finding in enumerate(sorted_findings, 1):
            self._render_single_finding(idx, finding)

    def _print_summary_table(self, result: ScanResult):
        table = Table(title="📊 Scan Summary & Metrics", border_style="cyan", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold white", justify="right")

        table.add_row("Target Directory", result.target_path)
        table.add_row("Files Scanned", str(result.summary.total_files_scanned))
        table.add_row("Lines of Code", str(result.summary.total_lines_scanned))
        table.add_row("Classes Analyzed", str(result.summary.total_classes_found))
        table.add_row("Methods Analyzed", str(result.summary.total_methods_found))
        table.add_row("POP Gadget Chains", f"[bold magenta]{result.summary.gadget_chains_found}[/bold magenta]")
        table.add_row("Total Findings", f"[bold yellow]{result.summary.total_findings}[/bold yellow]")
        table.add_row("  - CRITICAL", f"[bold red]{result.summary.critical_count}[/bold red]")
        table.add_row("  - HIGH", f"[bold orange3]{result.summary.high_count}[/bold orange3]")
        table.add_row("  - MEDIUM", f"[bold yellow]{result.summary.medium_count}[/bold yellow]")
        table.add_row("  - LOW / INFO", f"[bold blue]{result.summary.low_count + result.summary.info_count}[/bold blue]")
        table.add_row("Scan Duration", f"{result.summary.scan_duration_seconds:.2f}s")

        self.console.print(table)

    def _render_single_finding(self, index: int, finding: Finding):
        # Color based on severity
        color_map = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "bold orange3",
            Severity.MEDIUM: "bold yellow",
            Severity.LOW: "bold cyan",
            Severity.INFO: "bold blue"
        }
        sev_color = color_map.get(finding.severity, "white")

        title_text = Text()
        title_text.append(f"[{index}] [{finding.severity.value}] ", style=sev_color)
        title_text.append(f"{finding.title} ", style="bold white")
        title_text.append(f"({finding.rule_id})", style="dim")

        content_lines = []
        content_lines.append(f"[bold]Location:[/bold] [underline cyan]{finding.location}[/underline cyan]")
        content_lines.append(f"[bold]Confidence:[/bold] {finding.confidence.value}")
        content_lines.append(f"[bold]Description:[/bold] {finding.description}")

        if finding.cwe:
            content_lines.append(f"[bold]CWE:[/bold] {finding.cwe}")
        if finding.owasp:
            content_lines.append(f"[bold]OWASP:[/bold] {finding.owasp}")

        panel_content = "\n".join(content_lines)
        self.console.print(Panel(panel_content, title=title_text, border_style=sev_color, padding=(0, 1)))

        # Code snippet
        if finding.code_snippet:
            self.console.print("  [dim]Code Snippet:[/dim]")
            syntax = Syntax(finding.code_snippet, "php", theme="monokai", line_numbers=False)
            self.console.print(syntax)

        # Dataflow Taint Trace if available
        if finding.dataflow_trace:
            self.console.print("\n  [bold cyan]⚡ Dataflow Taint Propagation Trace:[/bold cyan]")
            tree = Tree("🔥 Untrusted Input Flow")
            for step_idx, step in enumerate(finding.dataflow_trace, 1):
                node_label = (
                    f"[bold yellow]Step {step_idx}:[/bold yellow] {step.description}\n"
                    f"  [dim cyan]Location:[/dim cyan] {step.location}\n"
                    f"  [dim]Code:[/dim] [bold white]{step.code_snippet}[/bold white]"
                )
                tree.add(node_label)
            self.console.print(tree)

        # POP Gadget Chain Tree if available
        if finding.gadget_chain:
            self.console.print("\n  [bold magenta]⛓ POP Gadget Chain Call Graph:[/bold magenta]")
            gtree = Tree(f"🎯 Entry Point: [bold yellow]{finding.gadget_chain.entry_class}::{finding.gadget_chain.entry_method}()[/bold yellow]")
            for step in finding.gadget_chain.steps:
                if step.step_type == "ENTRY_MAGIC_METHOD":
                    continue
                elif step.step_type == "SINK_CALL":
                    node_label = f"💥 [bold red]SINK ({finding.gadget_chain.sink_type}):[/bold red] {step.description}"
                else:
                    node_label = f"↳ [bold green]{step.target_class}::{step.target_method}()[/bold green] ([dim]{step.step_type}[/dim])"
                gtree.add(node_label)
            self.console.print(gtree)

            if finding.gadget_chain.payload_blueprint:
                self.console.print("\n  [dim]Object Payload Blueprint:[/dim]")
                self.console.print(Syntax(finding.gadget_chain.payload_blueprint, "text", theme="ansi_dark"))

        # LLM Verification Insight if available
        if finding.llm_verification:
            llm = finding.llm_verification
            status_style = "bold green" if llm.is_vulnerable else "bold yellow"
            status_text = "CONFIRMED TRUE POSITIVE" if llm.is_vulnerable else "LIKELY FALSE POSITIVE"
            llm_text = (
                f"[{status_style}]🤖 LLM Verification: {status_text}[/{status_style}] "
                f"(Confidence: {llm.confidence_score*100:.0f}%)\n"
                f"[bold]Assessment:[/bold] {llm.exploitability_assessment}\n"
                f"[bold]Reasoning:[/bold] {llm.reasoning}"
            )
            if llm.suggested_poc:
                llm_text += f"\n[bold]Suggested PoC / Object Graph:[/bold] {llm.suggested_poc}"
            self.console.print(Panel(llm_text, title="🤖 AI Security Analyst Verdict", border_style="magenta"))

        # Remediation
        if finding.remediation:
            self.console.print(f"\n  [bold green]💡 Remediation Suggestion:[/bold green]\n  {finding.remediation.replace(chr(10), chr(10)+'  ')}\n")

        self.console.print("─" * 80)
