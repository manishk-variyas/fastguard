from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Dict, List, Optional, Set

from fastguard.depcheck import scan_dependencies
from fastguard.models import FINDING_RE, Confidence, FileGroup, Finding, Severity
from fastguard.vulndb import run_static_analysis

PROMPT_TEMPLATE = """You are a senior application security engineer auditing a Python FastAPI backend.

Analyze the following code thoroughly for security vulnerabilities.
Look for but do not limit yourself to:

- SQL Injection
- Hardcoded secrets, API keys, passwords
- Insecure CORS configuration
- Missing or broken authentication on routes
- Missing input validation (no Pydantic models)
- Insecure direct object references (IDOR)
- Sensitive data exposed in logs or API responses
- Insecure JWT handling (weak algorithms, no expiry, no signature check)
- Debug mode or dev config left enabled
- Dependency vulnerabilities in requirements.txt or pyproject.toml
- Mass assignment vulnerabilities
- Unhandled exceptions leaking stack traces
- Insecure file upload handling
- Open redirects
- Rate limiting missing on sensitive endpoints
- Insecure deserialization

For each issue found, respond using EXACTLY this format and nothing else:

---FINDING---
SEVERITY: critical | high | medium | low | informational
VULNERABILITY: <name of the vulnerability>
CATEGORY: <OWASP Top 10 category, e.g. A03:2021 -- Injection>
FILE: <filename>
LINE: <line number or range>
AFFECTED_CODE: <the exact vulnerable code snippet>
DESCRIPTION: <clear explanation of what the issue is and why it is dangerous>
IMPACT: <what an attacker could realistically do if this is exploited>
FIX_EXPLANATION: <explain why the fix resolves the vulnerability>
FIX_CODE: <the corrected replacement code snippet>
REFERENCES: <OWASP link, CVE, CWE where applicable>
CONFIDENCE: high | medium | low
---END---

If no vulnerabilities are found, respond with exactly: NO_FINDINGS

Code to audit:
{code}
"""

NO_FINDINGS_PATTERN = re.compile(r"NO_FINDINGS", re.IGNORECASE)


def _find_opencode() -> Optional[str]:
    candidates = [
        "opencode",
        "npx opencode",
        "opencode-cli",
    ]
    for cmd in candidates:
        try:
            subprocess.run(
                [cmd.split()[0], "--version" if len(cmd.split()) == 1 else "version"],
                capture_output=True,
                timeout=5,
            )
            return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            continue

    extra_paths = [
        "/usr/local/bin/opencode",
        "/opt/homebrew/bin/opencode",
        f"{__import__('os').path.expanduser('~')}/.local/bin/opencode",
    ]
    for p in extra_paths:
        if __import__("os").path.exists(p):
            return p

    return None


def _call_opencode(code_block: str, target_dir: str = "") -> str:
    cmd = _find_opencode()
    if cmd is None:
        return "NO_FINDINGS"

    prompt = PROMPT_TEMPLATE.format(code=code_block)

    args = [cmd, "run", prompt]
    if target_dir:
        args.extend(["--dir", target_dir])

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=300,
        )
        output = result.stdout or ""
        return output.strip()
    except subprocess.TimeoutExpired:
        return "NO_FINDINGS"
    except Exception:
        return "NO_FINDINGS"


def _parse_findings(raw_response: str, file_group: FileGroup) -> list[Finding]:
    if not raw_response or "NO_FINDINGS" in raw_response.upper():
        return []
    if raw_response.startswith("Error"):
        return []

    findings: list[Finding] = []
    for match in FINDING_RE.finditer(raw_response):
        try:
            finding = Finding(
                severity=Severity(match.group(1).strip().lower()),
                vulnerability=match.group(2).strip(),
                category=match.group(3).strip(),
                file=match.group(4).strip(),
                line=match.group(5).strip(),
                affected_code=match.group(6).strip(),
                description=match.group(7).strip(),
                impact=match.group(8).strip(),
                fix_explanation=match.group(9).strip(),
                fix_code=match.group(10).strip(),
                references=match.group(11).strip(),
                confidence=Confidence(match.group(12).strip().lower()),
                file_group=file_group,
            )
            findings.append(finding)
        except (ValueError, IndexError):
            continue

    return findings


def analyze_code(
    code: str,
    target_dir: str = "",
    severity_filter: Optional[set[str]] = None,
) -> list[Finding]:
    if not code.strip():
        return []

    raw = _call_opencode(code, target_dir=target_dir)
    findings = _parse_findings(raw, FileGroup.OTHER)

    if severity_filter:
        findings = [f for f in findings if f.severity.value in severity_filter]

    return findings


def analyze_group(
    group: FileGroup,
    code_block: str,
    severity_filter: Optional[set[str]] = None,
    target_dir: str = "",
) -> list[Finding]:
    return analyze_code(code_block, target_dir=target_dir, severity_filter=severity_filter)


def run_all_analyses(
    files: List[str],
    target_dir: str = "",
    severity_filter: Optional[Set[str]] = None,
    enable_opencode: bool = True,
) -> List[Finding]:
    """Run all analysis engines: static rules + dependency check + OpenCode AI."""
    all_findings: List[Finding] = []
    seen_keys: Set[str] = set()

    # 1. Static analysis (deterministic rules) on all .py files
    for filepath in files:
        if filepath.endswith(".py"):
            findings = run_static_analysis(filepath)
            for f in findings:
                if f.dedup_key not in seen_keys:
                    seen_keys.add(f.dedup_key)
                    all_findings.append(f)

    # 2. Dependency vulnerability scan (real CVE data from OSV.dev)
    dep_findings = scan_dependencies(target_dir)
    for f in dep_findings:
        if f.dedup_key not in seen_keys:
            seen_keys.add(f.dedup_key)
            all_findings.append(f)

    # 3. OpenCode AI analysis (deep reasoning)
    if enable_opencode:
        combined_code = ""
        for filepath in sorted(files):
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                combined_code += f"# --- File: {filepath} ---\n{content}\n\n"
            except Exception:
                pass

        if combined_code.strip():
            ai_findings = analyze_code(
                combined_code, target_dir=target_dir, severity_filter=severity_filter
            )
            for f in ai_findings:
                if f.dedup_key not in seen_keys:
                    seen_keys.add(f.dedup_key)
                    all_findings.append(f)

    return all_findings
