# Gliard Enterprise Security
# Copyright (c) 2026 Gliard Security Solutions. All rights reserved.
# This software and its associated documentation are proprietary and confidential.

import os
import yaml
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich.panel import Panel
from engine.scanners import *
from engine.reporter import Reporter
from engine.base import Severity, ScannerRegistry

console = Console()

def load_config():
    # 1. Try local root config (for development/running in source directory)
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
            
    # 2. Try package-level config (installed inside engine/ package)
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engine", "config.yaml")
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
            
    return {}

def calculate_score(findings):
    if not findings:
        return 100
    
    # Group findings by category to avoid over-penalizing the same type
    categories = {}
    for f in findings:
        categories.setdefault(f.category, []).append(f)
    
    total_deduction = 0
    for cat, cat_findings in categories.items():
        # Max deduction per category is 25 (reduced from 50)
        cat_deduction = sum(f.score for f in cat_findings)
        total_deduction += min(cat_deduction, 25)
    
    # Max total deduction is 80 — score never drops below 20
    total_deduction = min(total_deduction, 80)
    
    return max(20, 100 - total_deduction)

@click.command()
@click.argument('path', type=click.Path(exists=True, file_okay=False, dir_okay=True), required=False)
@click.option('--output', '-o', default='audit_report', help='Base name for output files')
def main(path, output):
    """Gliard: A professional security and reliability auditor for AI Agents."""
    if not path:
        from engine.cli_ui import GliardInterface
        root = os.path.dirname(os.path.abspath(__file__))
        ui = GliardInterface(root)
        ui.display_main_menu()
        return
    
    config = load_config()
    edition = config.get('edition', 'core').lower()
    
    console.print(f"[bold blue]Gliard v1.0.0[/bold blue] [{edition.upper()} EDITION] - Advanced AI Agent Security Scanner")
    console.print(f"Target: [green]{os.path.abspath(path)}[/green]\n")

    # Run scanners
    scanners = ScannerRegistry.get_scanners(config, path)
    raw_findings = []
    
    raw_findings = []
    
    # Separate scanners into interactive and static
    static_scanners = [s for s in scanners if s.__class__.__name__ != "AdversaryScanner"]
    interactive_scanners = [s for s in scanners if s.__class__.__name__ == "AdversaryScanner"]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("[green]Auditing Agent Intelligence...", total=len(static_scanners))
        for scanner in static_scanners:
            name = scanner.__class__.__name__
            progress.update(task, description=f"[bold green]Scanning[/bold green] [blue]{name}...[/blue]")
            findings = scanner.scan()
            raw_findings.extend(findings)
            progress.advance(task)
            
    # Run interactive scanners (Sentinel) separately to allow terminal input
    for scanner in interactive_scanners:
        findings = scanner.scan()
        raw_findings.extend(findings)
            
    # Group findings (Problem 1)
    grouped = {}
    for f in raw_findings:
        key = (f.category, f.title)
        if key not in grouped:
            grouped[key] = f
            f.locations = []
        
        if f.file_path:
            loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
            if loc not in grouped[key].locations:
                grouped[key].locations.append(loc)

    all_findings = []
    for f in grouped.values():
        if len(f.locations) > 1:
            f.description = f"{f.description}\n\nDetected in {len(f.locations)} locations."
            # We keep file_path as a representative location for the summary
            f.line_number = None
            f.snippet = None
        all_findings.append(f)
            
    # Calculate score
    score = calculate_score(all_findings)

    # Severity Breakdown
    severity_counts = {sev: 0 for sev in Severity}
    for f in all_findings:
        severity_counts[f.severity] += 1

    # Risk Level logic
    score_color = "green"
    risk_level = "LOW"
    if score < 30 or severity_counts[Severity.CRITICAL] > 0:
        score_color = "red"
        risk_level = "CRITICAL"
    elif score < 55 or severity_counts[Severity.HIGH] > 0:
        score_color = "yellow"
        risk_level = "HIGH"
    elif score < 75:
        score_color = "blue"
        risk_level = "MEDIUM"

    breakdown_text = "\n".join([f" • {sev.value}: {count}" for sev, count in severity_counts.items() if count > 0])
    
    console.print(Panel(
        f"[bold {score_color}]Risk Level: {risk_level}[/bold {score_color}]\n"
        f"Security Score: {score}/100\n\n"
        f"[bold]Findings Breakdown:[/bold]\n{breakdown_text}",
        title="Assessment Summary",
        expand=False
    ))

    if not all_findings:
        console.print("[bold green]Success![/bold green] No issues found. Your agent looks clean.")
        return

    # Sort findings by severity
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4
    }
    all_findings.sort(key=lambda x: severity_order.get(x.severity, 99))

    # Display findings in a table
    table = Table(title="Agent Audit Findings")
    table.add_column("Severity", justify="center")
    table.add_column("Category")
    table.add_column("Title")
    table.add_column("Location")

    for finding in all_findings:
        color = "white"
        if finding.severity == Severity.CRITICAL: color = "bold red"
        elif finding.severity == Severity.HIGH: color = "red"
        elif finding.severity == Severity.MEDIUM: color = "yellow"
        elif finding.severity == Severity.INFO: color = "blue"
        loc = finding.file_path or "-"
        if finding.line_number: loc += f":{finding.line_number}"
        table.add_row(f"[{color}]{finding.severity.value}[/{color}]", finding.category, finding.title, loc)

    console.print(table)

    # Generate reports
    reporter = Reporter(all_findings, path, edition=edition)
    reporter.score = score
    
    console.print(f"\n[bold]Generating {edition.upper()} reports...[/bold]")
    reporter.generate_all(output)
    
    console.print(f" [blue]SUCCESS:[/blue] Reports generated in project root.")
    if edition == "core":
        console.print(f" [yellow]INFO:[/yellow] Upgrade to [bold]Guard[/bold] or [bold]Sentinel[/bold] for PDF reports and more scanners.")

    console.print(Panel(
        f"[bold blue]Audit Complete![/bold blue]\nFound {len(all_findings)} items across {len(scanners)} scanners.",
        title="Status",
        border_style="blue"
    ))

if __name__ == '__main__':
    main()
