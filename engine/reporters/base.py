import os
from datetime import datetime
from typing import List
from ..base import Finding, Severity

REMEDIATION_GUIDE = {
    "Secrets": {
        "impact": "Exposed credentials allow unauthorized access to LLM providers, databases, or cloud infrastructure.",
        "fix": "Use environment variables (.env files) or secret managers like AWS Secrets Manager or HashiCorp Vault. Never commit secrets to version control.",
        "example": "BAD: api_key = 'sk-123...'\nGOOD: api_key = os.getenv('OPENAI_API_KEY')"
    },
    "Prompts": {
        "impact": "Unprotected prompts are vulnerable to injection attacks, causing the agent to ignore guardrails or leak data.",
        "fix": "Implement strict input validation and use delimiter-based prompt structures. Use system-level constraints that are harder to override.",
        "example": "Use XML tags or clear markers: '### User Input: {input} ###'"
    },
    "Tools/Capabilities": {
        "impact": "Dangerous system calls (os.system, exec) can lead to Remote Code Execution (RCE) or data destruction.",
        "fix": "Avoid shell=True. Use subprocess.run() with a predefined list of allowed arguments. Implement a 'whitelist' of permitted commands.",
        "example": "BAD: os.system(f'rm {file}')\nGOOD: if file in ALLOWED_FILES: os.remove(file)"
    },
    "Error Handling": {
        "impact": "Silent error suppression (pass/except) hides vulnerabilities and makes auditing impossible.",
        "fix": "Always log exceptions. Use specific exception types instead of a catch-all 'Exception'.",
        "example": "BAD: except: pass\nGOOD: except FileNotFoundError as e: logger.error(f'Audit fail: {e}')"
    },
    "Logic/Loops": {
        "impact": "Infinite loops or logical flaws can lead to Denial of Service (DoS) and excessive API costs.",
        "fix": "Implement maximum iteration counters for all autonomous loops. Use timeout decorators.",
        "example": "MAX_ITERATIONS = 10\nfor i in range(MAX_ITERATIONS): ..."
    },
    "Efficiency": {
        "impact": "Uncontrolled API usage can lead to massive financial costs and Denial of Service.",
        "fix": "Implement token usage tracking and hard caps in the configuration. Use a global budget manager.",
        "example": "if current_spend > DAILY_BUDGET: stop_agent()"
    },
    "Privacy": {
        "impact": "Sending PII to external LLMs violates GDPR and compromises user trust.",
        "fix": "Use a regex-based scrubber or libraries like Presidio to anonymize data before it leaves your environment.",
        "example": "clean_text = scrub_pii(user_input)"
    },
    "Memory": {
        "impact": "Sensitive data (tokens, API keys, PII) stored in plain text in databases can be exfiltrated if the storage layer is compromised.",
        "fix": "Encrypt sensitive fields before storage. Use a dedicated secret vault (e.g. Keysmith, HashiCorp Vault) instead of raw database inserts.",
        "example": "BAD: db.execute('INSERT INTO sessions VALUES (?)', (api_key,))\nGOOD: db.execute('INSERT INTO sessions VALUES (?)', (encrypt(api_key),))"
    },
    "Transparency": {
        "impact": "Users unaware they are interacting with an AI may be misled, violating trust and EU AI Act Article 13 disclosure requirements.",
        "fix": "Implement Chain-of-Thought logging and explicit AI disclosure in the system prompt or onboarding UI.",
        "example": "system_prompt = 'You are an AI assistant. Always explain your reasoning step by step.'"
    },
    "Data Flow": {
        "impact": "Sending sensitive data to external cloud LLM providers creates privacy risks and potential GDPR violations if PII leaves the EU.",
        "fix": "Audit which data is sent to external providers. Consider local/self-hosted models for sensitive workloads.",
        "example": "# For sensitive data, prefer local models:\n# ollama.chat(model='llama3', messages=[...])"
    },
    "EU AI Act": {
        "impact": "Non-compliance with the EU AI Act (Articles 9, 10, 13, 14, 17) can lead to significant fines (up to 7% of global turnover) and market withdrawal.",
        "fix": "Implement mandatory transparency disclosures, human oversight mechanisms, and documented risk management as required by your system's risk tier.",
        "example": "system_prompt = 'You are an AI assistant. [EU AI Act Disclosure] ...'"
    },
    "MCP Configuration": {
        "impact": "Misconfigured MCP servers can grant AI agents unrestricted filesystem access, execute untrusted third-party code, or expose API credentials to malicious servers.",
        "fix": "Audit every MCP server in your configuration. Use only trusted publishers, restrict filesystem permissions, and never embed secrets directly in args.",
        "example": "BAD: args: ['@unknown-org/server', '--allow-write', '/']\nGOOD: args: ['@modelcontextprotocol/server-filesystem', '--allow-write', '/tmp/sandbox']"
    },
    "Infrastructure": {
        "impact": "Containers running as root grant attackers full system access if the container is compromised.",
        "fix": "Always specify a non-root USER in your Dockerfile for production deployments.",
        "example": "RUN adduser --disabled-password appuser\nUSER appuser"
    }
}

class BaseReporter:
    def __init__(self, findings: List[Finding], target_dir: str, score: int = 0, edition: str = "core"):
        self.findings = findings
        self.target_dir = target_dir
        self.report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.score = score
        self.edition = edition.lower()

    def get_risk_level(self):
        if self.score < 40: return "CRITICAL"
        elif self.score < 70: return "HIGH"
        elif self.score < 90: return "MEDIUM"
        return "LOW"
