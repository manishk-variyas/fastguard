from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Pattern

from fastguard.models import Confidence, Finding, Severity


class Rule:
    """A single static analysis detection rule."""

    def __init__(
        self,
        id: str,
        name: str,
        category: str,
        severity: Severity,
        confidence: Confidence,
        description: str,
        impact: str,
        fix_explanation: str,
        fix_code: str,
        references: str,
        pattern: Pattern,
        file_pattern: Optional[Pattern] = None,
        line_range: Optional[tuple[int, int]] = None,
    ):
        self.id = id
        self.name = name
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.description = description
        self.impact = impact
        self.fix_explanation = fix_explanation
        self.fix_code = fix_code
        self.references = references
        self.pattern = pattern
        self.file_pattern = file_pattern
        self.line_range = line_range

    def match(self, line: str, filepath: str = "") -> Optional[re.Match]:
        if self.file_pattern and not self.file_pattern.search(filepath):
            return None
        return self.pattern.search(line)


# -- Rules definitions --

RULES: List[Rule] = [
    Rule(
        id="SEC001",
        name="Hardcoded Secret / API Key",
        category="A05:2021 – Security Misconfiguration",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="A hardcoded secret, API key, or credential detected in source code.",
        impact="Anyone with repo access can extract secrets and compromise production systems.",
        fix_explanation="Load secrets from environment variables or a secrets manager.",
        fix_code='import os\nSECRET_KEY = os.environ.get("SECRET_KEY")\nif not SECRET_KEY:\n    raise RuntimeError("SECRET_KEY not set")',
        references="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        pattern=re.compile(
            r'(?:SECRET_KEY|API_KEY|PASSWORD|PASSWD|TOKEN|CREDENTIALS|PRIVATE_KEY)\s*=\s*["\'][A-Za-z0-9_\-\.]{8,}["\']',
            re.IGNORECASE,
        ),
        file_pattern=re.compile(r"\.(py|env|cfg|ini|yml|yaml|json|toml)$"),
    ),
    Rule(
        id="SEC002",
        name="SQL Injection (String Formatting)",
        category="A03:2021 – Injection",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="SQL query built using string formatting or concatenation with user-controlled variables.",
        impact="An attacker can read, modify, or delete database contents, bypass auth, or execute commands.",
        fix_explanation="Use parameterized queries (cursor.execute with ? placeholders) to separate SQL from data.",
        fix_code='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        references="https://owasp.org/www-community/attacks/SQL_Injection",
        pattern=re.compile(
            r'(?:cursor\.execute|\.execute_sql|\.raw_sql|connection\.execute)\s*\(\s*f["\']',
            re.IGNORECASE,
        ),
        file_pattern=re.compile(r"\.py$"),
    ),
    Rule(
        id="SEC003",
        name="SQL Injection (Concat in Query)",
        category="A03:2021 – Injection",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="SQL query constructed via string concatenation with dynamic values.",
        impact="An attacker can inject arbitrary SQL commands.",
        fix_explanation="Replace string concatenation with parameterized queries.",
        fix_code='query = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, (user_id,))',
        references="https://owasp.org/www-community/attacks/SQL_Injection",
        pattern=re.compile(
            r"""['"](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b.*?['"]\s*[%+]""",
            re.IGNORECASE,
        ),
        file_pattern=re.compile(r"\.py$"),
    ),
    Rule(
        id="SEC004",
        name="JWT Algorithm 'none'",
        category="A02:2021 – Cryptographic Failures",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="JWT is created or accepted with algorithm='none', allowing unsigned token forgery.",
        impact="Anyone can forge arbitrary JWT tokens and impersonate any user.",
        fix_explanation="Always use a strong algorithm like HS256 or RS256 with proper key management.",
        fix_code='jwt.encode(payload, SECRET_KEY, algorithm="HS256")',
        references="https://cwe.mitre.org/data/definitions/347.html",
        pattern=re.compile(
            r"""algorithm\s*=\s*["']none["']""",
            re.IGNORECASE,
        ),
        file_pattern=re.compile(r"\.py$"),
    ),
    Rule(
        id="SEC005",
        name="JWT Signature Verification Disabled",
        category="A02:2021 – Cryptographic Failures",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="JWT decode called with verify_signature=False, accepting arbitrary forged tokens.",
        impact="Complete authentication bypass — anyone can forge tokens.",
        fix_explanation="Always verify signatures. Remove options that disable verification.",
        fix_code='jwt.decode(token, SECRET_KEY, algorithms=["HS256"])',
        references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
        pattern=re.compile(
            r"""verify_signature\s*=\s*False""",
            re.IGNORECASE,
        ),
        file_pattern=re.compile(r"\.py$"),
    ),
    Rule(
        id="SEC006",
        name="Debug Mode Enabled in Production",
        category="A05:2021 – Security Misconfiguration",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="FastAPI app created with debug=True or DEBUG variable set to True.",
        impact="Stack traces and internal details leak to end users on errors, aiding attackers.",
        fix_explanation="Set debug=False in production. Control via environment variable.",
        fix_code='app = FastAPI(debug=False)\n# or\nDEBUG = os.environ.get("DEBUG", "false").lower() == "true"',
        references="https://fastapi.tiangolo.com/tutorial/debugging/",
        pattern=re.compile(
            r"""debug\s*=\s*True""",
            re.IGNORECASE,
        ),
        file_pattern=re.compile(r"\.py$"),
    ),
    Rule(
        id="SEC007",
        name="Insecure CORS (Wildcard + Credentials)",
        category="A05:2021 – Security Misconfiguration",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="CORS configured with wildcard origin '*' and allow_credentials=True. Invalid combination that exposes sessions.",
        impact="Any website can make authenticated cross-origin requests, leading to data theft.",
        fix_explanation="Use explicit allowed origins from a whitelist, or disable credentials with wildcard.",
        fix_code='app.add_middleware(CORSMiddleware, allow_origins=["https://trusted.example.com"], allow_credentials=True)',
        references="https://portswigger.net/web-security/cors",
        pattern=re.compile(
            r"""allow_origins\s*=\s*\[?\s*["']\*["']""",
            re.IGNORECASE,
        ),
        file_pattern=re.compile(r"\.py$"),
    ),
    Rule(
        id="SEC008",
        name="Sensitive Data Logged",
        category="A04:2021 – Insecure Design",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Sensitive keywords (password, secret, token) appear inside logging calls.",
        impact="Credentials leak to log files, which may be retained, shipped, or accessed by unauthorized parties.",
        fix_explanation="Never log sensitive data. Log only non-sensitive metadata.",
        fix_code='logging.info(f"Login attempt for user: {username}")',
        references="https://owasp.org/Top10/A04_2021-Insecure_Design/",
        pattern=re.compile(
            r"""logging\.(?:info|debug|warning|error|exception)\s*\([^)]*(?:password|secret|token|credential)""",
            re.IGNORECASE,
        ),
        file_pattern=re.compile(r"\.py$"),
    ),
    Rule(
        id="SEC009",
        name="Hardcoded Database URL with Credentials",
        category="A05:2021 – Security Misconfiguration",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Database connection URL with embedded username and password found in source.",
        impact="Anyone with source access can connect directly to the database.",
        fix_explanation="Use environment variables for database URLs.",
        fix_code='DATABASE_URL = os.environ.get("DATABASE_URL")',
        references="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        pattern=re.compile(
            r"""(?:postgresql|mysql|mongodb|redis|psql)://[^/:@]+:[^/:@]+@""",
            re.IGNORECASE,
        ),
    ),
    Rule(
        id="SEC010",
        name="Insecure Deserialization (pickle)",
        category="A08:2021 – Software and Data Integrity Failures",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Unsafe use of pickle.loads() on untrusted data can lead to arbitrary code execution.",
        impact="An attacker can achieve remote code execution by sending a crafted pickle payload.",
        fix_explanation="Avoid pickle with untrusted data. Use JSON or other safe serialization formats.",
        fix_code="import json\ndata = json.loads(untrusted_input)",
        references="https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
        pattern=re.compile(
            r"""pickle\.loads?\s*\(""",
            re.IGNORECASE,
        ),
        file_pattern=re.compile(r"\.py$"),
    ),
    Rule(
        id="SEC011",
        name="YAML Load Unsafe",
        category="A08:2021 – Software and Data Integrity Failures",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Using yaml.load() without SafeLoader can execute arbitrary code.",
        impact="An attacker can execute arbitrary Python code via crafted YAML input.",
        fix_explanation="Always use yaml.safe_load() instead of yaml.load().",
        fix_code="import yaml\ndata = yaml.safe_load(user_input)",
        references="https://cwe.mitre.org/data/definitions/502.html",
        pattern=re.compile(
            r"""yaml\.load\s*\((?!.*SafeLoader)""",
        ),
        file_pattern=re.compile(r"\.py$"),
    ),
    Rule(
        id="SEC012",
        name="eval() / exec() Used",
        category="A03:2021 – Injection",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Use of eval() or exec() on dynamic input allows arbitrary code execution.",
        impact="An attacker can execute arbitrary Python code on the server.",
        fix_explanation="Avoid eval/exec entirely. Use safer alternatives like ast.literal_eval().",
        fix_code="import ast\nresult = ast.literal_eval(input_str)",
        references="https://owasp.org/www-community/attacks/Code_Injection",
        pattern=re.compile(
            r"""\b(?:eval|exec)\s*\(""",
        ),
        file_pattern=re.compile(r"\.py$"),
    ),
    Rule(
        id="SEC013",
        name="Open Redirect (return Redirect)",
        category="A01:2021 – Broken Access Control",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description="URL redirect using user-controlled input without validation.",
        impact="Phishing attacks — attacker can redirect users to malicious sites.",
        fix_explanation="Validate redirect URLs against an allowlist of trusted domains.",
        fix_code='allowed_domains = ["example.com"]\nif any(d in url for d in allowed_domains):\n    return RedirectResponse(url)',
        references="https://owasp.org/www-community/attacks/Open_redirect",
        pattern=re.compile(
            r"""RedirectResponse\s*\(\s*[^"']*(?:request|args|params|query|form)""",
            re.IGNORECASE,
        ),
        file_pattern=re.compile(r"\.py$"),
    ),
    Rule(
        id="SEC014",
        name="File Upload Without Validation",
        category="A05:2021 – Security Misconfiguration",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="File upload endpoint without file type or size validation.",
        impact="Attackers can upload malicious files (web shells, malware) to the server.",
        fix_explanation="Validate file extension, content type, and size before saving.",
        fix_code="ALLOWED_EXTENSIONS = {'.jpg', '.png'}\nif not filename.endswith(tuple(ALLOWED_EXTENSIONS)):\n    raise HTTPException(400)",
        references="https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
        pattern=re.compile(
            r"""UploadFile\b.*(?:def |async def ).*?(?!\.filename|\.content_type|\.size)""",
            re.IGNORECASE | re.DOTALL,
        ),
        file_pattern=re.compile(r"\.py$"),
    ),
]


def run_static_analysis(filepath: str, content: Optional[str] = None) -> List[Finding]:
    """Run static analysis rules on a single file."""
    if content is None:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return []

    findings: List[Finding] = []
    matched_rules: set[str] = set()
    lines = content.split("\n")

    for rule in RULES:
        if not rule.file_pattern or rule.file_pattern.search(filepath):
            for lineno, line in enumerate(lines, 1):
                m = rule.match(line, filepath)
                if m:
                    if rule.id in matched_rules:
                        continue
                    matched_rules.add(rule.id)
                    findings.append(Finding(
                        severity=rule.severity,
                        vulnerability=rule.name,
                        category=rule.category,
                        file=filepath,
                        line=str(lineno),
                        affected_code=line.strip(),
                        description=rule.description,
                        impact=rule.impact,
                        fix_explanation=rule.fix_explanation,
                        fix_code=rule.fix_code,
                        references=rule.references,
                        confidence=rule.confidence,
                    ))
    return findings
