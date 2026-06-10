from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fastguard.models import Confidence, Finding, Severity


OSV_API_URL = "https://api.osv.dev/v1/query"
PURL_PREFIX = "pkg:pypi/"

# Requirements line regex: package_name (with optional version specifiers)
REQ_LINE_RE = re.compile(
    r"^\s*([a-zA-Z0-9_\-\.]+)\s*([><=!~]+\s*[\d\.\*]+(?:\s*,\s*[><=!]+\s*[\d\.\*]+)*)?\s*(?:#.*)?$"
)
VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)")


def _parse_requirements(filepath: str) -> Dict[str, str]:
    """Parse requirements.txt and return {package: version}."""
    packages: Dict[str, str] = {}
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = REQ_LINE_RE.match(line)
                if m:
                    pkg = m.group(1).lower()
                    spec = m.group(2)
                    version = ""
                    if spec:
                        vm = VERSION_RE.search(spec)
                        if vm:
                            version = vm.group(1)
                    packages[pkg] = version
    except Exception:
        pass
    return packages


def _parse_pyproject_toml(filepath: str) -> Dict[str, str]:
    """Parse pyproject.toml for [project] dependencies."""
    packages: Dict[str, str] = {}
    try:
        in_deps = False
        with open(filepath, "r") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("[project]"):
                    in_deps = True
                    continue
                if in_deps and stripped.startswith("["):
                    in_deps = False
                    continue
                if in_deps and ("dependencies" in stripped or stripped.startswith('"')):
                    # Handle dependencies = [...] or inline strings
                    m = REQ_LINE_RE.match(stripped.lstrip('"\' '))
                    if m:
                        pkg = m.group(1).lower()
                        spec = m.group(2)
                        version = ""
                        if spec:
                            vm = VERSION_RE.search(spec)
                            if vm:
                                version = vm.group(1)
                        packages[pkg] = version
    except Exception:
        pass
    return packages


def _query_osv(package: str, version: str) -> List[dict]:
    """Query OSV.dev API for vulnerabilities in a package@version."""
    query: dict = {
        "package": {"purl": f"{PURL_PREFIX}{package}"},
    }
    if version:
        query["version"] = version

    try:
        data = json.dumps(query).encode()
        req = urllib.request.Request(
            OSV_API_URL,
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())

        vulns = result.get("vulns", [])
        return vulns
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return []


def _osv_to_findings(
    vulns: list[dict],
    package: str,
    filepath: str,
) -> List[Finding]:
    """Convert OSV.dev vulnerability results to Finding objects."""
    findings: List[Finding] = []
    seen_ids: set[str] = set()

    for vuln in vulns:
        vuln_id = vuln.get("id", "UNKNOWN")
        if vuln_id in seen_ids:
            continue
        seen_ids.add(vuln_id)

        aliases = vuln.get("aliases", [])
        cve_ids = [a for a in aliases if a.startswith("CVE-")]
        cve_str = ", ".join(cve_ids) if cve_ids else vuln_id

        summary = vuln.get("summary", "") or vuln.get("details", "No description available")
        severity_summary = vuln.get("severity", [])
        cvss_scores = [
            s.get("score", "")
            for s in severity_summary
            if s.get("type") == "CVSS"
        ]
        cvss_str = f" (CVSS: {cvss_scores[0]})" if cvss_scores else ""

        # Map severity based on CVSS
        if cvss_scores:
            try:
                score = float(cvss_scores[0])
                if score >= 9.0:
                    sev = Severity.CRITICAL
                elif score >= 7.0:
                    sev = Severity.HIGH
                elif score >= 4.0:
                    sev = Severity.MEDIUM
                else:
                    sev = Severity.LOW
            except ValueError:
                sev = Severity.MEDIUM
        else:
            sev = Severity.MEDIUM

        references = vuln.get("references", [])
        ref_links = [r.get("url", "") for r in references if r.get("url")]
        ref_str = "; ".join(ref_links[:3]) if ref_links else f"https://osv.dev/vulnerability/{vuln_id}"

        fix_versions = []
        for affected in vuln.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        fix_versions.append(event["fixed"])

        fix_explanation = (
            f"Upgrade {package} to version {' or '.join(fix_versions)}"
            if fix_versions
            else f"Upgrade {package} to the latest version"
        )

        fix_code = f"{package}>={' || '.join(fix_versions) if fix_versions else 'latest'}"

        findings.append(Finding(
            severity=sev,
            vulnerability=f"Known Vulnerability in {package}: {cve_str}",
            category="A06:2021 – Vulnerable and Outdated Components",
            file=filepath,
            line="dependency",
            affected_code=f"{package} (current version: {vuln.get('version', 'unknown')})",
            description=summary[:500],
            impact=f"Attackers can exploit {cve_str} to compromise the application{cvss_str}",
            fix_explanation=fix_explanation,
            fix_code=fix_code,
            references=ref_str,
            confidence=Confidence.HIGH,
        ))

    return findings


def scan_dependencies(target_dir: str) -> List[Finding]:
    """Scan project dependencies against OSV.dev CVE database."""
    findings: List[Finding] = []
    target = Path(target_dir).expanduser().resolve()

    dep_files: List[str] = []
    for fname in ["requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock"]:
        fp = target / fname
        if fp.exists():
            dep_files.append(str(fp))
    # Also check subdirectories
    for f in target.rglob("requirements.txt"):
        if str(f) not in dep_files:
            dep_files.append(str(f))
    for f in target.rglob("pyproject.toml"):
        if str(f) not in dep_files:
            dep_files.append(str(f))

    if not dep_files:
        return findings

    scanned_packages: set[str] = set()

    for filepath in dep_files:
        fname = Path(filepath).name
        packages: Dict[str, str] = {}
        if fname == "requirements.txt":
            packages = _parse_requirements(filepath)
        elif fname == "pyproject.toml":
            packages = _parse_pyproject_toml(filepath)

        for pkg, version in packages.items():
            if pkg in scanned_packages:
                continue
            scanned_packages.add(pkg)
            vulns = _query_osv(pkg, version)
            if vulns:
                findings.extend(_osv_to_findings(vulns, pkg, filepath))

    return findings
