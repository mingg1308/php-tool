"""
Command Line Interface (CLI) for PHP Insecure Deserialization SAST Scanner.
"""

import sys
import os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import click
# pyrefly: ignore [missing-import]
from rich.console import Console
# pyrefly: ignore [missing-import]
from rich.table import Table

from php_deserial_sast.config import ScannerConfig, DEFAULT_BUILTIN_RULES_DIR
from php_deserial_sast.models import Severity
from php_deserial_sast.scanner import PHPDeserializationScanner
from php_deserial_sast.reporters.console import ConsoleReporter
from php_deserial_sast.reporters.sarif import SarifReporter
from php_deserial_sast.reporters.html_report import HTMLReporter
from php_deserial_sast.reporters.json_reporter import JSONReporter
from php_deserial_sast.rules.engine import RuleEngine


console = Console(legacy_windows=False)


@click.group()
@click.version_option("1.0.0", prog_name="php-deserial-sast")
def main():
    """Automated PHP Insecure Deserialization and POP Gadget Chain SAST Scanner."""
    pass


@main.command(name="scan")
@click.argument("target", type=click.Path(exists=True), default=".")
@click.option("--rules-dir", "-r", type=click.Path(exists=True), default=DEFAULT_BUILTIN_RULES_DIR, help="Path to custom YAML rules directory.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path.")
@click.option("--format", "-f", "output_format", type=click.Choice(["console", "json", "sarif", "html"], case_sensitive=False), default="console", help="Report format.")
@click.option("--severity", "-s", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False), default="LOW", help="Minimum severity threshold.")
@click.option("--taint/--no-taint", default=True, help="Enable/disable Source-to-Sink Taint Analysis.")
@click.option("--gadgets/--no-gadgets", default=True, help="Enable/disable POP Gadget Chain Finder.")
@click.option("--rules/--no-rules", default=True, help="Enable/disable Semgrep-like YAML Rule Engine.")
@click.option("--llm/--no-llm", default=False, help="Enable LLM verification for False Positive filtering.")
@click.option("--llm-provider", type=click.Choice(["openai", "gemini", "ollama"], case_sensitive=False), default="openai", help="LLM Provider.")
@click.option("--llm-model", type=str, default=None, help="Model name for LLM verification.")
@click.option("--max-depth", type=int, default=6, help="Maximum POP chain graph search depth.")
def scan_cmd(
    target,
    rules_dir,
    output,
    output_format,
    severity,
    taint,
    gadgets,
    rules,
    llm,
    llm_provider,
    llm_model,
    max_depth
):
    """Scan a PHP codebase or file for Deserialization vulnerabilities and POP chains."""
    config = ScannerConfig(
        target_path=os.path.abspath(target),
        rules_dir=rules_dir,
        enable_taint=taint,
        enable_gadgets=gadgets,
        enable_rules=rules,
        enable_llm=llm,
        llm_provider=llm_provider,
        llm_model=llm_model,
        min_severity=Severity(severity.upper()),
        max_chain_depth=max_depth,
        output_format=output_format.lower(),
        output_file=output
    )

    scanner = PHPDeserializationScanner(config)
    
    if output_format.lower() == "console" or not output:
        with console.status("[bold cyan]Scanning PHP codebase for Insecure Deserialization & POP Gadgets...[/bold cyan]", spinner="dots"):
            result = scanner.scan()
    else:
        result = scanner.scan()

    # Always render to console if requested or if no output file specified
    if output_format.lower() == "console" or not output:
        reporter = ConsoleReporter(console)
        reporter.render_results(result)

    # Save to file if output specified
    if output:
        fmt = output_format.lower()
        if fmt == "sarif" or output.endswith(".sarif"):
            sarif_rep = SarifReporter()
            sarif_rep.save_to_file(result, output)
            console.print(f"[bold green]✔ SARIF report saved to:[/bold green] {output}")
        elif fmt == "html" or output.endswith(".html"):
            html_rep = HTMLReporter()
            html_rep.save_to_file(result, output)
            console.print(f"[bold green]✔ Interactive HTML report saved to:[/bold green] {output}")
        elif fmt == "json" or output.endswith(".json"):
            json_rep = JSONReporter()
            json_rep.save_to_file(result, output)
            console.print(f"[bold green]✔ JSON report saved to:[/bold green] {output}")
        else:
            json_rep = JSONReporter()
            json_rep.save_to_file(result, output)
            console.print(f"[bold green]✔ Report saved to:[/bold green] {output}")

    # Exit code: 1 if critical/high findings, else 0
    if result.summary.critical_count > 0 or result.summary.high_count > 0:
        sys.exit(1)
    sys.exit(0)


@main.command(name="find-gadgets")
@click.argument("target", type=click.Path(exists=True), default=".")
@click.option("--max-depth", type=int, default=6, help="Maximum POP chain graph search depth.")
def find_gadgets_cmd(target, max_depth):
    """Search exclusively for POP Gadget Chains in target directory."""
    config = ScannerConfig(
        target_path=os.path.abspath(target),
        enable_taint=False,
        enable_rules=False,
        enable_gadgets=True,
        max_chain_depth=max_depth
    )
    scanner = PHPDeserializationScanner(config)
    with console.status("[bold magenta]Traversing Call Graph for POP Gadget Chains...[/bold magenta]", spinner="aesthetic"):
        result = scanner.scan()

    reporter = ConsoleReporter(console)
    reporter.render_results(result)


@main.command(name="verify-rules")
@click.argument("rules_dir", type=click.Path(exists=True), default=DEFAULT_BUILTIN_RULES_DIR)
def verify_rules_cmd(rules_dir):
    """Validate YAML detection rules syntax and patterns."""
    engine = RuleEngine(rules_dir)
    table = Table(title=f"Loaded YAML Rules from {rules_dir}", border_style="cyan")
    table.add_column("Rule ID", style="bold white")
    table.add_column("Severity", style="bold yellow")
    table.add_column("Confidence", style="cyan")
    table.add_column("Message", style="dim")

    for r in engine.rules:
        table.add_row(r.id, r.severity.value, r.confidence.value, r.message[:60] + "...")

    console.print(table)
    console.print(f"[bold green]✔ Successfully verified {len(engine.rules)} YAML rule(s).[/bold green]")


if __name__ == "__main__":
    main()
