import os
import re
import ast
from typing import List
from ..base import Scanner, Finding, Severity, ScannerRegistry, Edition
from .security import _is_test_file, _downgrade_if_test



@ScannerRegistry.register("HallucinationScanner")
class HallucinationScanner(Scanner):
    min_edition = Edition.CORE
    def scan(self) -> List[Finding]:
        findings = []
        safety_patterns = [
            r"don't know", r"not sure", r"unsure", r"cannot answer",
            r"neviem", r"if you are unsure",
            r"(?i)(based only on|only use the (provided|following)|do not use (external|outside|your) knowledge)"
        ]
        prompt_var_names = {"system_prompt", "system_message", "SYSTEM_PROMPT", "SYSTEM_MESSAGE", "prompt_template"}
        found_safety = False

        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if not self._should_exclude_dir(d, root)]
            for file in files:
                # Skip .md and .txt as requested
                if not file.endswith(('.py', '.yaml', '.json')):
                    continue
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # 1. Check AST for prompt variables in Python files (preferred)
                    if file.endswith('.py'):
                        try:
                            tree = ast.parse(content)
                            for node in ast.walk(tree):
                                if isinstance(node, ast.Assign):
                                    for target in node.targets:
                                        if isinstance(target, ast.Name) and target.id in prompt_var_names:
                                            # Strictly check inside string literals assigned to these variables
                                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                                if any(re.search(p, node.value.value, re.IGNORECASE) for p in safety_patterns):
                                                    found_safety = True
                                                    break
                                    if found_safety: break
                        except SyntaxError:
                            pass
                    
                    # 2. For non-python files (yaml, json), check content directly as they are often config/prompt files
                    else:
                        if any(re.search(p, content, re.IGNORECASE) for p in safety_patterns):
                            found_safety = True
                            break
                            
                except Exception:
                    continue
            if found_safety:
                break

        if not found_safety:
            findings.append(Finding(
                category="Prompts",
                title="Missing Hallucination Guardrails",
                description="System prompts do not explicitly instruct the agent to admit uncertainty or stick to context.",
                severity=Severity.MEDIUM, # Lowered from HIGH to MEDIUM
                recommendation="Add 'If you don't know the answer, say you don't know' or 'Answer based only on provided context' to your system prompts.",
                owasp_id="LLM09",
                owasp_category="Overreliance",
            ))
        return findings


@ScannerRegistry.register("LogicScanner")
class LogicScanner(Scanner):
    min_edition = Edition.CORE
    """
    Detects logic issues: infinite loops and silent error suppression.

    Improvements over the naive version:
    - `while True` is only flagged when there is NO `break` or `return`
      anywhere in the loop body — genuine event loops always have an exit.
    - `try/except/pass` is only flagged for broad catches (`Exception`,
      bare `except`) — specific catches like `except KeyboardInterrupt: pass`
      are intentional and are skipped.
    - Test files are downgraded to INFO.
    """

    # Specific exception types that are acceptable to silence
    _ACCEPTABLE_SILENT_EXCEPTIONS = {
        "KeyboardInterrupt", "SystemExit", "StopIteration",
        "StopAsyncIteration", "GeneratorExit",
        "CancelledError", "ConnectionResetError", "ConnectionAbortedError",
        "TimeoutError", "FileNotFoundError", "UnicodeDecodeError",
    }

    def scan(self) -> List[Finding]:
        scanner_config = self.get_scanner_config()
        max_comp = scanner_config.get('max_complexity', 10)
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

                        # ---- Infinite loop check ----
                        if isinstance(node, ast.While):
                            is_true = (
                                isinstance(node.test, ast.Constant) and node.test.value is True
                            ) or (
                                isinstance(node.test, ast.Name) and node.test.id == "True"
                            )
                            if not is_true:
                                continue

                            # Only flag when the loop body has no break / return
                            has_exit = any(
                                isinstance(n, (ast.Break, ast.Return))
                                for n in ast.walk(node)
                                if n is not node
                            )
                            if has_exit:
                                continue

                            # Skip if the line contains an ignore tag
                            if node.lineno <= len(lines) and "gliard:ignore" in lines[node.lineno - 1]:
                                continue

                            findings.append(Finding(
                                category="Logic/Loops",
                                title="Potential Infinite Loop",
                                description="A 'while True' loop with no break or return was detected. This can cause the agent to hang or consume excessive tokens.",
                                severity=_downgrade_if_test(Severity.MEDIUM, file),
                                file_path=rel_path,
                                line_number=node.lineno,
                                recommendation="Add a maximum iteration counter or a robust exit condition to the loop.",
                                owasp_id="LLM04",
                                owasp_category="Model Denial of Service",
                            ))

                        # ---- Silent error suppression check ----
                        if isinstance(node, ast.Try):
                            for handler in node.handlers:
                                # Must be a pure `pass` body
                                if not (len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass)):
                                    continue

                                # Skip acceptable specific exceptions
                                if handler.type is not None:
                                    exc_name = (
                                        handler.type.id
                                        if isinstance(handler.type, ast.Name)
                                        else None
                                    )
                                    if exc_name in self._ACCEPTABLE_SILENT_EXCEPTIONS:
                                        continue
                                    # Named specific exception that isn't in our
                                    # acceptable list — still flag, but as MEDIUM
                                    severity = Severity.MEDIUM
                                else:
                                    # Bare `except: pass` — worst case
                                    severity = Severity.HIGH

                                # Skip if the line contains an ignore tag
                                if handler.lineno <= len(lines) and "gliard:ignore" in lines[handler.lineno - 1]:
                                    continue

                                findings.append(Finding(
                                    category="Error Handling",
                                    title="Silent Error Suppression",
                                    description="Detected a try/except/pass block. This hides errors and makes debugging agent failures difficult.",
                                    severity=_downgrade_if_test(severity, file),
                                    file_path=rel_path,
                                    line_number=handler.lineno,
                                    recommendation="Always log exceptions even if they are expected, to maintain an audit trail.",
                                    owasp_id="LLM09",
                                    owasp_category="Overreliance",
                                ))
                except Exception:
                    continue

        return findings
