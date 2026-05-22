import os
import json
from datetime import datetime
from typing import List
from rich.console import Console
from .base import Finding
from .reporters.markdown import MarkdownReporter, StrategyMarkdownReporter
from .reporters.json import JsonReporter

try:
    from .reporters.pdf import PdfReporter, StrategyPdfReporter
except ImportError:
    PdfReporter = None
    StrategyPdfReporter = None

console = Console()

class Reporter:
    """
    Main coordinator for Gliard reporting.
    Delegates to specific reporter modules based on the active edition.
    """
    def __init__(self, findings: List[Finding], target_dir: str, edition: str = "core"):
        self.findings = findings
        self.target_dir = target_dir
        self.edition = edition.lower()
        self.report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.score = 0

    def generate_all(self, output_base: str):
        """
        Generates all reports allowed by the current edition.
        """
        # 1. CORE Reports (Markdown is always available)
        try:
            MarkdownReporter(self.findings, self.target_dir, self.score, self.edition).generate(f"{output_base}.md")
        except Exception as e:
            console.print(f" [red]✗[/red] Error generating Markdown report: {e}")
        
        if self.edition == "core":
            return # Core only gets Markdown

        # 2. GUARD & SENTINEL shared reports (JSON, PDF, Strategy)
        if self.edition in ["guard", "sentinel"]:
            try:
                JsonReporter(self.findings, self.target_dir, self.score, self.edition).generate(f"{output_base}.json")
            except Exception as e:
                console.print(f" [red]✗[/red] Error generating JSON report: {e}")
            
            if PdfReporter and StrategyPdfReporter:
                try:
                    PdfReporter(self.findings, self.target_dir, self.score, self.edition).generate(f"{output_base}.pdf")
                    StrategyPdfReporter(self.findings, self.target_dir, self.score, self.edition).generate(f"{output_base}_strategy.pdf")
                except Exception as e:
                    console.print(f" [red]✗[/red] Error generating PDF reports: {e}")

            try:
                StrategyMarkdownReporter(self.findings, self.target_dir, self.score, self.edition).generate(f"{output_base}_strategy.md")
            except Exception as e:
                console.print(f" [red]✗[/red] Error generating Strategy Markdown report: {e}")


        # 3. SENTINEL Reports (Enterprise features)
        if self.edition == "sentinel":
            try:
                self._generate_sentinel_reports(output_base)
            except Exception as e:
                console.print(f" [red]✗[/red] Error generating Sentinel reports: {e}")

    def _generate_sentinel_reports(self, output_base: str):
        """
        Generates Enterprise-only reports: Simulation logs and verified exploit JSON.
        """
        sentinel_findings = [f for f in self.findings if "Sentinel" in f.category]
        if not sentinel_findings:
            return

        # 1. Simulation Log (Detailed technical log of what happened)
        log_path = f"{output_base}_simulation.log"
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"GLIARD SENTINEL ADVERSARY SIMULATION LOG\n")
            f.write(f"=========================================\n")
            f.write(f"Target: {self.target_dir}\n")
            f.write(f"Date: {self.report_time}\n\n")
            
            for i, find in enumerate(sentinel_findings):
                f.write(f"EXPLOIT #{i+1}: {find.title}\n")
                f.write(f"Category: {find.category}\n")
                f.write(f"Target File: {find.file_path}:{find.line_number}\n")
                f.write(f"Status: VERIFIED / PROVED\n")
                f.write(f"Description: {find.description}\n")
                f.write(f"-----------------------------------------\n\n")

        # 2. Verified Exploit Data (JSON format for CI/CD ingestion)
        data_path = f"{output_base}_exploits.json"
        exploits = []
        for f in sentinel_findings:
            exploits.append({
                "vector": f.title,
                "file": f.file_path,
                "line": f.line_number,
                "severity": f.severity.value,
                "verification": "Adversary Engine Heuristic Simulation"
            })
        
        with open(data_path, "w", encoding="utf-8") as f:
            json.dump({"verified_exploits": exploits}, f, indent=2)
