from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from fastguard.analyzer import run_all_analyses
from fastguard.collector import (
    classify_file,
    collect_files,
    group_to_code_blocks,
    read_file_content,
)
from fastguard.models import Confidence, FileGroup, Finding, ScanReport, Severity

console = Console()
CACHE_DIR = Path.home() / ".cache" / "fastguard"


def _cache_key(target_dir: str) -> str:
    raw = os.path.abspath(target_dir)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _load_raw_findings(target_dir: str) -> Optional[list[dict]]:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_file = CACHE_DIR / f"{_cache_key(target_dir)}.json"
        if cache_file.exists():
            with open(cache_file) as f:
                data = json.load(f)
            return data.get("raw_findings")
    except Exception:
        return None
    return None


def _save_raw_findings(target_dir: str, raw_findings: list[dict]):
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_file = CACHE_DIR / f"{_cache_key(target_dir)}.json"
        with open(cache_file, "w") as f:
            json.dump(
                {"target": os.path.abspath(target_dir), "raw_findings": raw_findings},
                f,
            )
    except Exception:
        pass


def _dict_to_finding(d: dict) -> Finding:
    return Finding(
        severity=Severity(d["severity"]),
        vulnerability=d["vulnerability"],
        category=d["category"],
        file=d["file"],
        line=d["line"],
        affected_code=d["affected_code"],
        description=d["description"],
        impact=d["impact"],
        fix_explanation=d["fix_explanation"],
        fix_code=d["fix_code"],
        references=d["references"],
        confidence=Confidence(d["confidence"]),
        file_group=FileGroup(d.get("file_group", "other")),
    )


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        if f.dedup_key not in seen:
            seen.add(f.dedup_key)
            unique.append(f)
    return unique


def _rank_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (f.severity.rank(), f.confidence.rank()),
        reverse=True,
    )


def run_scan(
    target_dir: str,
    severity_filter: Optional[List[str]] = None,
    details: bool = False,
) -> ScanReport:
    start = time.time()

    severity_set: Optional[set[str]] = None
    if severity_filter:
        severity_set = {s.lower().strip() for s in severity_filter}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting files...", total=None)

        groups = collect_files(target_dir)
        total_files = sum(len(files) for files in groups.values())

        all_file_paths = [f for files in groups.values() for f in files]

        all_findings: list[Finding] = []

        if all_file_paths:
            cached = _load_raw_findings(target_dir)
            if cached is not None:
                progress.update(task, description="Loading cached analysis...")
                all_findings = [_dict_to_finding(d) for d in cached]
            else:
                progress.update(
                    task,
                    description="Static analysis + CVE lookup + AI audit...",
                )

                all_findings = run_all_analyses(
                    files=all_file_paths,
                    target_dir=target_dir,
                    severity_filter=severity_set,
                    enable_opencode=True,
                )

                _save_raw_findings(target_dir, [f.to_dict() for f in all_findings])

            # Tag with file groups
            for finding in all_findings:
                finding.file_group = classify_file(finding.file)

        if severity_set:
            all_findings = [f for f in all_findings if f.severity.value in severity_set]

        progress.update(task, description="Done!")

    all_findings = _rank_findings(_deduplicate(all_findings))

    elapsed = time.time() - start
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return ScanReport(
        target=target_dir,
        scanned_files=total_files,
        duration_seconds=round(elapsed, 1),
        date=date_str,
        findings=all_findings,
    )
