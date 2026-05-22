import json
import os
from .base import BaseReporter

class JsonReporter(BaseReporter):
    def generate(self, output_path: str):
        report = {
            "gliard_version": "1.2.0",
            "audit_id": f"AUD-{os.path.basename(self.target_dir)}-JSON",
            "timestamp": self.report_time,
            "target": os.path.basename(self.target_dir.rstrip('/\\')),
            "score": self.score,
            "eu_ai_act_compliant": not any(f.category == "EU AI Act" for f in self.findings),
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity.value == "CRITICAL"),
                "high": sum(1 for f in self.findings if f.severity.value == "HIGH"),
                "medium": sum(1 for f in self.findings if f.severity.value == "MEDIUM"),
                "low": sum(1 for f in self.findings if f.severity.value == "LOW"),
                "info": sum(1 for f in self.findings if f.severity.value == "INFO"),
            },
            "findings": [
                {
                    "severity": f.severity.value,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "recommendation": f.recommendation,
                    "owasp_id": f.owasp_id,
                    "owasp_category": f.owasp_category,
                }
                for f in self.findings
            ],
            "disclaimer": "Gliard is an automated security analysis tool. Findings are based on pattern matching and heuristic analysis of source code. This report does not replace a manual security audit conducted by a certified professional. EU AI Act compliance status indicated herein reflects automated checks only and does not constitute official regulatory certification. Gliard and its authors accept no liability for decisions made based on this report."
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
