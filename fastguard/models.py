from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    def __str__(self) -> str:
        return self.value

    def rank(self) -> int:
        ranking = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "informational": 1,
        }
        return ranking.get(self.value, 0)


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    def __str__(self) -> str:
        return self.value

    def rank(self) -> int:
        ranking = {"high": 3, "medium": 2, "low": 1}
        return ranking.get(self.value, 0)


class FileGroup(str, Enum):
    ROUTES = "routes / endpoints"
    MODELS = "models / schemas"
    CONFIG = "config / settings"
    MIDDLEWARE = "middleware"
    AUTH = "dependencies / auth"
    MAIN = "main entry point"
    OTHER = "other"

    def __str__(self) -> str:
        return self.value


@dataclass
class Finding:
    severity: Severity
    vulnerability: str
    category: str
    file: str
    line: str
    affected_code: str
    description: str
    impact: str
    fix_explanation: str
    fix_code: str
    references: str
    confidence: Confidence
    file_group: FileGroup = FileGroup.OTHER
    dedup_key: str = ""

    def __post_init__(self):
        self.dedup_key = self._make_dedup_key()

    def _make_dedup_key(self) -> str:
        vuln = self.vulnerability.strip().lower()
        file_stem = self.file.strip().lower()
        return f"{vuln}||{file_stem}"

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "vulnerability": self.vulnerability,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "affected_code": self.affected_code,
            "description": self.description,
            "impact": self.impact,
            "fix_explanation": self.fix_explanation,
            "fix_code": self.fix_code,
            "references": self.references,
            "confidence": self.confidence.value,
            "file_group": self.file_group.value,
        }


@dataclass
class ScanReport:
    target: str
    scanned_files: int
    duration_seconds: float
    date: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        if not self.findings:
            return 0
        weighted = 0
        for f in self.findings:
            base = f.severity.rank() * 10
            conf_mult = {"high": 1.0, "medium": 0.7, "low": 0.4}
            weighted += base * conf_mult.get(f.confidence.value, 0.5)
        max_possible = len(self.findings) * 50 * 1.0
        ratio = min(weighted / max_possible, 1.0) if max_possible > 0 else 0
        return round(ratio * 100)

    @property
    def risk_label(self) -> str:
        score = self.risk_score
        if score >= 70:
            return "HIGH RISK"
        elif score >= 40:
            return "MEDIUM RISK"
        elif score >= 20:
            return "LOW RISK"
        return "INFO"

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for s in Severity:
            counts[s.value] = 0
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def total_findings(self) -> int:
        return len(self.findings)


FINDING_RE = re.compile(
    r"---FINDING---\s*"
    r"SEVERITY:\s*(critical|high|medium|low|informational)\s*"
    r"VULNERABILITY:\s*(.*?)\s*"
    r"CATEGORY:\s*(.*?)\s*"
    r"FILE:\s*(.*?)\s*"
    r"LINE:\s*(.*?)\s*"
    r"AFFECTED_CODE:\s*(.*?)\s*"
    r"DESCRIPTION:\s*(.*?)\s*"
    r"IMPACT:\s*(.*?)\s*"
    r"FIX_EXPLANATION:\s*(.*?)\s*"
    r"FIX_CODE:\s*(.*?)\s*"
    r"REFERENCES:\s*(.*?)\s*"
    r"CONFIDENCE:\s*(high|medium|low)\s*"
    r"---END---",
    re.DOTALL,
)
