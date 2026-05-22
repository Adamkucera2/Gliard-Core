import os
from .base import BaseReporter

class MarkdownReporter(BaseReporter):
    def generate(self, output_path: str):
        with open(output_path, 'w', encoding='utf-8') as out_f:
            out_f.write(f'<p align="center"><img src="gliard_logomark.svg" width="300"></p>\n\n')
            out_f.write(f"# Gliard Security Audit: {os.path.basename(self.target_dir)}\n")
            
            risk_level = self.get_risk_level()
            out_f.write(f"**Date:** {self.report_time} | **Risk Level:** {risk_level} | **Security Score:** {self.score}/100\n\n")
            
            out_f.write("## 1. Executive Summary\n")
            out_f.write(f"This assessment identifies security, efficiency, and logic vulnerabilities. The overall posture is currently rated as **{risk_level}**. ")
            out_f.write("Mapping provided to OWASP Top 10 for LLMs.\n\n")
            
            # Dynamic Strengths Detection
            strengths = []
            if os.path.exists(os.path.join(self.target_dir, "requirements.txt")):
                strengths.append("- **Dependency Management**: Standard package management is in place.")
            if os.path.exists(os.path.join(self.target_dir, "README.md")):
                strengths.append("- **Documentation**: Project contains helpful setup and usage documentation.")
            
            if strengths:
                out_f.write("## 2. Identified Strengths (Positive Findings)\n")
                for s in strengths:
                    out_f.write(f"{s}\n")
                out_f.write("\n")
 
            if self.edition == "core":
                out_f.write("## 3. Findings Overview\n")
                # Group by category
                cat_map = {}
                for find in self.findings:
                    if find.category not in cat_map:
                        cat_map[find.category] = []
                    cat_map[find.category].append(find)
                
                for cat, items in cat_map.items():
                    total_instances = sum(len(f.locations) if f.locations else 1 for f in items)
                    unique_files = set()
                    for f in items:
                        if f.locations:
                            for loc in f.locations:
                                unique_files.add(loc.split(':')[0])
                        elif f.file_path:
                            unique_files.add(f.file_path)
                    
                    file_count = len(unique_files)
                    out_f.write(f"**{cat.upper()}** {' ' * (25 - len(cat))} {total_instances} instances across {file_count} files  \n")
                    first = items[0]
                    fname = os.path.basename(first.file_path) if first.file_path else "multiple files"
                    out_f.write(f"&nbsp;&nbsp;e.g. {first.title} in {fname}\n\n")
                
                out_f.write("\n> [!TIP]\n")
                out_f.write("> **Upgrade to Guard** for exact line numbers, OWASP mapping, EU AI Act compliance, and full remediation guidance.\n\n")
            else:
                out_f.write("## 3. Findings Summary\n")
                out_f.write("| Severity | Category | OWASP | Title | Location |\n")
                out_f.write("| --- | --- | --- | --- | --- |\n")
                for finding in self.findings:
                    loc = finding.file_path if finding.file_path else "-"
                    if finding.line_number: loc += f":{finding.line_number}"
                    owasp = f"{finding.owasp_id}" if finding.owasp_id else "-"
                    out_f.write(f"| {finding.severity.value} | {finding.category} | {owasp} | {finding.title} | {loc} |\n")
                out_f.write("\n---\n")

                out_f.write("## 4. EU AI Act Alignment\n")
                eu_findings = [f for f in self.findings if f.category == "EU AI Act"]
                if not eu_findings:
                    out_f.write("✅ **Compliant**: No major EU AI Act violations detected based on current scanners.\n")
                else:
                    out_f.write("⚠️ **Non-Compliant**: The following EU AI Act requirements were not met:\n")
                    for f_eu in eu_findings:
                        out_f.write(f"- **{f_eu.title}**: {f_eu.description}\n")
                out_f.write("\n---\n")
                
                out_f.write("## Findings\n")
                for i, finding in enumerate(self.findings):
                    out_f.write(f"### {i+1}. [{finding.severity.value}] {finding.title}\n")
                    out_f.write(f"**Category:** {finding.category}  \n")
                    if finding.file_path:
                        loc = f"{finding.file_path}"
                        if finding.line_number: loc += f":{finding.line_number}"
                        out_f.write(f"**Location:** `{loc}`  \n")
                    out_f.write(f"**Description:** {finding.description}  \n")
                    if finding.snippet:
                        out_f.write(f"**Snippet:**\n```python\n{finding.snippet}\n```\n")
                    out_f.write(f"**Recommendation:** {finding.recommendation}\n\n")
                    out_f.write("---\n\n")

            out_f.write("\n\n---\n")
            out_f.write("*Gliard is an automated security analysis tool. Findings are based on pattern matching and heuristic analysis of source code. "
                    "This report does not replace a manual security audit conducted by a certified professional. EU AI Act compliance status indicated "
                    "herein reflects automated checks only and does not constitute official regulatory certification. Gliard and its authors "
                    "accept no liability for decisions made based on this report.*\n")


class StrategyMarkdownReporter(BaseReporter):
    def generate(self, output_path: str):
        from .base import REMEDIATION_GUIDE
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f'<p align="center"><img src="gliard_logomark.svg" width="250"></p>\n\n')
            f.write(f"# Remediation Strategy: {os.path.basename(self.target_dir)}\n")
            f.write(f"**Audit ID:** AUD-{os.path.basename(self.target_dir)}-STRAT\n\n")
            
            f.write("## 1. Executive Remediation Summary\n")
            f.write("This guide provides technical steps to resolve the identified security risks. Implementation of these changes will significantly improve the agent's security posture.\n\n")
            
            categories = sorted(list(set(f.category for f in self.findings)))
            for cat in categories:
                f.write(f"### Category: {cat}\n")
                guide = REMEDIATION_GUIDE.get(cat, {})
                if guide:
                    f.write(f"- **Impact:** {guide['impact']}\n")
                    f.write(f"- **Technical Fix:** {guide['fix']}\n")
                    f.write("- **Safe Implementation Example:**\n")
                    f.write(f"  ```python\n  {guide['example']}\n  ```\n")
                
                cat_findings = [find for find in self.findings if find.category == cat]
                affected_files = set(find.file_path for find in cat_findings if find.file_path)
                f.write(f"- **Affected Files:** {', '.join(affected_files) if affected_files else 'Project-wide configuration'}\n\n")
                f.write("---\n")
            
            f.write("\n\n---\n")
            f.write("*Gliard is an automated security analysis tool. Findings are based on pattern matching and heuristic analysis of source code. "
                    "This report does not replace a manual security audit conducted by a certified professional. EU AI Act compliance status indicated "
                    "herein reflects automated checks only and does not constitute official regulatory certification. Gliard and its authors "
                    "accept no liability for decisions made based on this report.*\n")
