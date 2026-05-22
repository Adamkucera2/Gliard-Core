import os
import re
import ast
import json
import requests
from typing import List, Tuple, Optional
from ..base import Scanner, Finding, Severity, ScannerRegistry, Edition


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_test_file(filename: str) -> bool:
    """Return True for test files — lower severity across the board."""
    return filename.startswith("test_") or filename.endswith("_test.py")


def _downgrade_if_test(severity: Severity, filename: str) -> Severity:
    if _is_test_file(filename):
        return Severity.INFO
    return severity


# Structural patterns that look like secrets but are safe:
#   Ethereum/EVM addresses, Solana base58 addresses, Fernet tokens, placeholders
_SAFE_VALUE_PATTERNS: List[re.Pattern] = [
    re.compile(r"^0x[0-9a-fA-F]{40}$"),            # EVM address
    re.compile(r"^0x[0-9a-fA-F]{64}$"),            # EVM tx hash / event topic
    re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$"),  # Solana base58 pubkey
    re.compile(r"^gAAAAA"),                          # Fernet-encrypted value
    re.compile(r"^1{32}$"),                          # Solana system program
    re.compile(r"^(YOUR_|your_|<YOUR|PASTE_|INSERT_|ADD_YOUR|example|placeholder|xxx|000000)", re.IGNORECASE),
]

# Key names that indicate a blockchain context rather than a secret
_BLOCKCHAIN_CONTEXT_KEYS = {
    "mint", "usdc", "usdt", "sol", "dai", "token_program_id",
    "associated_token_program_id", "system_program_id", "contract",
    "program_id", "address", "wallet",
}

# Key names that justify flagging a bare hash/token as a secret
_SECRET_KEY_RE = re.compile(
    r'(?i)(?:api[_\-]?key|secret|password|token|access[_\-]?key|auth)',
)


def _is_safe_value(line: str, value: str) -> bool:
    """
    Return True when the matched value is a known-safe non-secret:
    blockchain address, Fernet blob, placeholder string, etc.
    """
    v = value.strip().strip("'\"")

    for pat in _SAFE_VALUE_PATTERNS:
        if pat.match(v):
            return True

    # Check surrounding key name for blockchain context
    key_match = re.search(r'["\']?([\w]+)["\']?\s*[:=]', line)
    if key_match and key_match.group(1).lower() in _BLOCKCHAIN_CONTEXT_KEYS:
        return True

    return False


# ---------------------------------------------------------------------------
# Scanners
# ---------------------------------------------------------------------------

@ScannerRegistry.register("SecretScanner")
class SecretScanner(Scanner):
    min_edition = Edition.CORE
    """
    Detects hardcoded secrets with context-aware false-positive filtering.

    Key improvements over the naive version:
    - Mistral / Cohere patterns now require a secret-sounding key name on
      the same line — this eliminates Solana/EVM address false positives.
    - Fernet-encrypted values (gAAAAA…) are skipped — they are already safe.
    - Blockchain contract/program addresses are whitelisted by structure and
      by surrounding key name.
    - Test files are downgraded to INFO.
    - Placeholder values (YOUR_KEY, <REPLACE>) are skipped.
    """

    # Patterns that are self-identifying (no extra context needed)
    _SELF_IDENTIFYING = {
        "OpenAI API Key":       r"sk-[a-zA-Z0-9]{48}",
        "Anthropic API Key":    r"sk-ant-api03-[a-zA-Z0-9\-_]{93}",
        "Google Cloud API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "Generic Secret":       r'(?i)(?:api_key|secret|password|token|access_key)\s*[:=]\s*[\'"][a-zA-Z0-9\-_]{16,}[\'"]',
    }

    # Patterns that require a secret-sounding key name on the same line
    _CONTEXT_REQUIRED = {
        "Mistral API Key": r"[a-zA-Z0-9]{32}",
        "Cohere API Key":  r"[a-zA-Z0-9]{40}",
    }

    def scan(self) -> List[Finding]:
        findings = []

        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if not self._should_exclude_dir(d, root)]
            for file in files:
                path = os.path.join(root, file)
                # Skip compiled, minified, or bundled JS files — high false positive rate
                if file.endswith('.js'):
                    # Skip obviously minified or bundled files
                    if any(marker in file for marker in ['.min.', '-CFZ', '.bundle.', '.chunk.']):
                        continue
                    # Skip if file is very large (>500KB) — likely compiled/bundled
                    try:
                        if os.path.getsize(path) > 500_000:
                            continue
                    except OSError:
                        pass

                if file in self.exclude_files or any(file.endswith(ext) for ext in self.exclude_extensions):
                    continue
                if not file.endswith(('.py', '.js', '.ts', '.tsx', '.env', '.yaml', '.yml', '.json', '.dockerfile', 'Dockerfile')):
                    continue

                path = os.path.join(root, file)
                rel_path = os.path.relpath(path, self.root_dir)

                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                except Exception:
                    continue

                for i, line in enumerate(lines):
                    matched = False

                    # Skip if the line contains an ignore tag
                    if "gliard:ignore" in line:
                        continue

                    # Self-identifying patterns
                    for title, pattern in self._SELF_IDENTIFYING.items():
                        m = re.search(pattern, line)
                        if not m:
                            continue
                        if _is_safe_value(line, m.group(0)):
                            continue
                        findings.append(self._make_finding(
                            title, rel_path, i + 1, line.strip(), file
                        ))
                        matched = True
                        break

                    if matched:
                        continue

                    # Context-required patterns
                    for title, pattern in self._CONTEXT_REQUIRED.items():
                        m = re.search(pattern, line)
                        if not m:
                            continue
                        if _is_safe_value(line, m.group(0)):
                            continue
                        # Only flag when a secret-sounding key name is present
                        if not _SECRET_KEY_RE.search(line):
                            continue
                        # Skip if the line contains an ignore tag
                        if "gliard:ignore" in line:
                            continue
                        findings.append(self._make_finding(
                            title, rel_path, i + 1, line.strip(), file
                        ))
                        break

        return findings

    def _make_finding(self, title: str, rel_path: str, lineno: int,
                      snippet: str, filename: str) -> Finding:
        return Finding(
            category="Secrets",
            title=f"Potential {title} found",
            description=f"Detected a string matching the pattern for {title}.",
            severity=_downgrade_if_test(Severity.CRITICAL, filename),
            file_path=rel_path,
            line_number=lineno,
            snippet=snippet,
            recommendation="Move secrets to environment variables and ensure they are not committed to version control.",
            owasp_id="LLM06",
            owasp_category="Sensitive Information Disclosure",
        )


@ScannerRegistry.register("PromptScanner")
class PromptScanner(Scanner):
    min_edition = Edition.CORE
    """
    Detects missing or weak prompt injection protection.
    """

    def scan(self) -> List[Finding]:
        findings = []
        # Modern regex for injection protection detection
        protection_regex = r"(?i)(do not follow|refuse to|you must not|never|always ignore|override)\s.{0,40}(instruction|prompt|user|input)"
        
        # Guardrail library indicators
        guardrail_indicators = [
            r"import guardrails",
            r"from llm_guard",
            r"import rebuff"
        ]

        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if not self._should_exclude_dir(d, root)]
            for file in files:
                if not file.endswith(('.py', '.txt', '.md')):
                    continue
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except Exception:
                    continue

                rel_path = os.path.relpath(path, self.root_dir)

                # Check for system prompt indicators
                is_system_prompt = re.search(r"(?i)(you are an? (assistant|agent|ai|bot)|system_prompt\s*=)", content)
                
                if is_system_prompt:
                    # Check for protection patterns
                    has_regex_protection = re.search(protection_regex, content)
                    has_guardrail_lib = any(re.search(p, content) for p in guardrail_indicators)

                    if not (has_regex_protection or has_guardrail_lib):
                        findings.append(Finding(
                            category="Prompts",
                            title="Missing Injection Protection",
                            description="System prompt found but no explicit override resistance or guardrail libraries detected.",
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            recommendation="Add explicit instructions to the system prompt to ignore user attempts to override core behavior, or implement a guardrail library like rebuff or guardrails.",
                            owasp_id="LLM01",
                            owasp_category="Prompt Injection",
                        ))
        return findings


@ScannerRegistry.register("ToolScanner")
class ToolScanner(Scanner):
    min_edition = Edition.CORE
    """
    Detects dangerous system calls.

    subprocess.* calls are expected in CLI tooling and build scripts —
    these are downgraded to MEDIUM rather than HIGH to reduce noise for
    legitimate orchestration code.  The real CRITICAL/HIGH risk is when
    an agent can invoke these autonomously inside core/ or tools/.
    """

    _DANGEROUS_CALLS = {
        "os.system":        Severity.CRITICAL,
        "os.popen":         Severity.CRITICAL,
        "subprocess.run":   Severity.HIGH,
        "subprocess.Popen": Severity.HIGH,
        "subprocess.call":  Severity.HIGH,
        "shutil.rmtree":    Severity.CRITICAL,
        "eval":             Severity.CRITICAL,
        "exec":             Severity.CRITICAL,
    }

    # Directories where subprocess is expected — downgrade to MEDIUM
    _EXPECTED_SUBPROCESS_DIRS = {"cli", "scripts", "scratch", "build"}

    def scan(self) -> List[Finding]:
        findings = []

        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if not self._should_exclude_dir(d, root)]
            for file in files:
                if not file.endswith('.py'):
                    continue

                path = os.path.join(root, file)
                rel_path = os.path.relpath(path, self.root_dir)
                rel_parts = set(rel_path.split(os.sep))

                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "gliard:ignore-file" in content:
                            continue
                    
                    tree = ast.parse(content)
                    lines = content.splitlines()
                    for node in ast.walk(tree):
                        if not isinstance(node, ast.Call):
                            continue

                        func_name = ""
                        if isinstance(node.func, ast.Attribute):
                            if isinstance(node.func.value, ast.Name):
                                func_name = f"{node.func.value.id}.{node.func.attr}"
                        elif isinstance(node.func, ast.Name):
                            func_name = node.func.id

                        if func_name not in self._DANGEROUS_CALLS:
                            continue

                        # Skip if the line contains an ignore tag
                        if node.lineno <= len(lines) and "gliard:ignore" in lines[node.lineno - 1]:
                            continue

                        severity = self._DANGEROUS_CALLS[func_name]

                        # Check for shell=True in subprocess calls (Critical vulnerability)
                        is_shell_true = False
                        if func_name.startswith("subprocess."):
                            for kw in node.keywords:
                                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    is_shell_true = True
                                    severity = Severity.CRITICAL
                                    break

                        # Downgrade subprocess in known utility directories
                        if func_name.startswith("subprocess."):
                            if any(d in rel_parts for d in self._EXPECTED_SUBPROCESS_DIRS):
                                severity = Severity.MEDIUM

                        # Downgrade everything in test files
                        severity = _downgrade_if_test(severity, file)

                        findings.append(Finding(
                            category="Tools/Capabilities",
                            title=f"Dangerous Call Detected: {func_name}",
                            description=f"The agent code explicitly calls {func_name}, which can perform destructive or unverified system actions.",
                            severity=severity,
                            file_path=rel_path,
                            line_number=node.lineno,
                            recommendation="Implement a strict sandbox or require manual human approval for this specific system capability." if not is_shell_true else "Remove 'shell=True' and pass arguments as a list to prevent OS command injection.",
                            owasp_id="LLM08",
                            owasp_category="Excessive Agency",
                        ))
                except Exception:
                    continue

        return findings


@ScannerRegistry.register("SensitiveLoggingScanner")
class SensitiveLoggingScanner(Scanner):
    min_edition = Edition.CORE
    """
    Detects logging or printing of sensitive variables (API keys, tokens, etc.).
    Basic hygiene check for AI agents.
    """
    _SENSITIVE_VAR_NAMES = {"token", "api_key", "password", "secret", "credentials", "auth", "private_key", "key"}
    _LOG_FUNCTIONS = {"print", "info", "debug", "warning", "error", "critical", "log", "write"}

    def scan(self) -> List[Finding]:
        findings = []
        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if not self._should_exclude_dir(d, root)]
            for file in files:
                if not file.endswith('.py'):
                    continue
                path = os.path.join(root, file)
                rel_path = os.path.relpath(path, self.root_dir)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    if "gliard:ignore-file" in content:
                        continue
                    
                    tree = ast.parse(content)
                    lines = content.splitlines()
                    for node in ast.walk(tree):
                        if not isinstance(node, ast.Call):
                            continue
                        
                        # Get function name
                        func_name = ""
                        if isinstance(node.func, ast.Attribute):
                            func_name = node.func.attr
                        elif isinstance(node.func, ast.Name):
                            func_name = node.func.id
                        
                        if func_name in self._LOG_FUNCTIONS:
                            # Check arguments for sensitive variables
                            for arg in node.args + [kw.value for kw in node.keywords]:
                                for subnode in ast.walk(arg):
                                    if isinstance(subnode, ast.Name) and any(s in subnode.id.lower() for s in self._SENSITIVE_VAR_NAMES):
                                        if node.lineno <= len(lines) and "gliard:ignore" in lines[node.lineno - 1]:
                                            continue
                                        
                                        findings.append(Finding(
                                            category="Privacy",
                                            title="Potential Sensitive Data Leak in Logs",
                                            description=f"The variable '{subnode.id}' appears to be passed to a logging/output function '{func_name}()'. This may leak sensitive data into logs or console.",
                                            severity=Severity.HIGH,
                                            file_path=rel_path,
                                            line_number=node.lineno,
                                            recommendation="Never log raw secrets or PII. Use a scrubber or anonymizer before logging.",
                                            owasp_id="LLM06",
                                            owasp_category="Sensitive Information Disclosure"
                                        ))
                                        break
                except Exception:
                    continue
        return findings

