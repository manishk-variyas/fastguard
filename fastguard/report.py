from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from fastguard.models import Finding, ScanReport

console = Console()


def _risk_color(score: int) -> str:
    if score >= 70:
        return "red"
    elif score >= 40:
        return "yellow"
    elif score >= 20:
        return "blue"
    return "green"


def _severity_style(severity: str) -> str:
    styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "informational": "white",
    }
    return styles.get(severity, "white")


def _severity_tag(severity: str) -> str:
    symbols = {
        "critical": "●",
        "high": "●",
        "medium": "●",
        "low": "●",
        "informational": "●",
    }
    return symbols.get(severity, "●")


def print_terminal_report(report: ScanReport, details: bool = False):
    color = _risk_color(report.risk_score)

    summary = (
        f"Target  : {report.target}\n"
        f"Scanned : {report.scanned_files} files     "
        f"Duration: {report.duration_seconds}s     "
        f"Date: {report.date}"
    )
    console.print()
    console.print(Panel(summary, title="FastGuard Security Report", border_style=color))
    console.print()

    risk_text = Text()
    risk_text.append(f"Risk Score : {report.risk_score} / 100   ", style="bold")
    risk_text.append(f"{report.risk_label}", style=f"bold {color}")
    console.print(risk_text)
    console.print()

    count_table = Table.grid(padding=(0, 2))
    count_table.add_column()
    for s in ["critical", "high", "medium", "low", "informational"]:
        count = report.severity_counts.get(s, 0)
        count_table.add_row(
            f"  {_severity_tag(s)} {s.capitalize():15s} {count}",
            style=_severity_style(s),
        )
    count_table.add_row("─" * 25, style="dim")
    count_table.add_row(f"  Total         {report.total_findings} findings", style="bold")
    console.print(count_table)
    console.print()

    if report.findings:
        table = Table(show_header=True, header_style="bold")
        table.add_column("#", style="dim", width=3)
        table.add_column("Severity", width=12)
        table.add_column("Vulnerability", width=30)
        table.add_column("File", width=35)
        table.add_column("Line", width=8)
        table.add_column("Confidence", width=10)

        for i, f in enumerate(report.findings, 1):
            table.add_row(
                str(i),
                Text(f.severity.value.upper(), style=_severity_style(f.severity.value)),
                f.vulnerability[:28],
                f.file[:33],
                f.line[:6],
                Text(f.confidence.value.capitalize(), style="bold"),
            )
        console.print(table)
        console.print()

        if details:
            for i, f in enumerate(report.findings, 1):
                console.print()
                console.print(
                    Panel(
                        f"[bold]Description:[/bold] {f.description}\n\n"
                        f"[bold]Impact:[/bold] {f.impact}\n\n"
                        f"[bold]Fix:[/bold] {f.fix_explanation}\n\n"
                        f"[bold]Affected Code:[/bold]\n{f.affected_code}\n\n"
                        f"[bold]Fixed Code:[/bold]\n{f.fix_code}\n\n"
                        f"[bold]References:[/bold] {f.references}",
                        title=f"#{i} {f.severity.value.upper()} - {f.vulnerability}",
                        border_style=_severity_style(f.severity.value),
                    )
                )
    else:
        console.print("[bold green]No findings detected. Your code looks clean![/bold green]")
        console.print()


def generate_json_report(report: ScanReport, output_path: str):
    data = {
        "tool": "FastGuard",
        "version": "1.0.0",
        "target": report.target,
        "scanned_files": report.scanned_files,
        "duration_seconds": report.duration_seconds,
        "date": report.date,
        "risk_score": report.risk_score,
        "risk_label": report.risk_label,
        "severity_counts": report.severity_counts,
        "total_findings": report.total_findings,
        "findings": [f.to_dict() for f in report.findings],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    console.print(f"[green]JSON report saved to {output_path}[/green]")


def generate_markdown_report(report: ScanReport, output_path: str):
    lines: list[str] = []
    lines.append("# FastGuard Security Report")
    lines.append("")
    lines.append(f"- **Target:** {report.target}")
    lines.append(f"- **Files Scanned:** {report.scanned_files}")
    lines.append(f"- **Duration:** {report.duration_seconds}s")
    lines.append(f"- **Date:** {report.date}")
    lines.append(f"- **Risk Score:** {report.risk_score}/100 ({report.risk_label})")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for s in ["critical", "high", "medium", "low", "informational"]:
        count = report.severity_counts.get(s, 0)
        lines.append(f"| {s.capitalize()} | {count} |")
    lines.append(f"| **Total** | **{report.total_findings}** |")
    lines.append("")

    if report.findings:
        lines.append("## Findings")
        lines.append("")
        lines.append(
            "| # | Severity | Vulnerability | File | Line | Confidence |"
        )
        lines.append("|---|---|---|---|---|---|")
        for i, f in enumerate(report.findings, 1):
            lines.append(
                f"| {i} | {f.severity.value.upper()} | {f.vulnerability} | "
                f"{f.file} | {f.line} | {f.confidence.value.capitalize()} |"
            )
        lines.append("")

        lines.append("## Detailed Findings")
        lines.append("")
        for i, f in enumerate(report.findings, 1):
            lines.append(f"### {i}. {f.severity.value.upper()} - {f.vulnerability}")
            lines.append("")
            lines.append(f"- **Category:** {f.category}")
            lines.append(f"- **File:** {f.file}")
            lines.append(f"- **Line:** {f.line}")
            lines.append(f"- **Confidence:** {f.confidence.value.capitalize()}")
            lines.append("")
            lines.append("**Description:**")
            lines.append("")
            lines.append(f"{f.description}")
            lines.append("")
            lines.append("**Impact:**")
            lines.append("")
            lines.append(f"{f.impact}")
            lines.append("")
            lines.append("**Fix Explanation:**")
            lines.append("")
            lines.append(f"{f.fix_explanation}")
            lines.append("")
            lines.append("**Affected Code:**")
            lines.append("")
            lines.append(f"```python")
            lines.append(f"{f.affected_code}")
            lines.append(f"```")
            lines.append("")
            lines.append("**Fixed Code:**")
            lines.append("")
            lines.append(f"```python")
            lines.append(f"{f.fix_code}")
            lines.append(f"```")
            lines.append("")
            lines.append("**References:**")
            lines.append("")
            lines.append(f"{f.references}")
            lines.append("")
            lines.append("---")
            lines.append("")
    else:
        lines.append("No findings detected. Your code looks clean!")
        lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    console.print(f"[green]Markdown report saved to {output_path}[/green]")


def generate_html_report(report: ScanReport, output_path: str):
    findings_rows = ""
    for i, f in enumerate(report.findings, 1):
        sev_class = f.severity.value
        findings_rows += f"""
        <tr class="finding-row" data-severity="{sev_class}">
          <td>{i}</td>
          <td><span class="severity-badge {sev_class}">{f.severity.value.upper()}</span></td>
          <td>{f.vulnerability}</td>
          <td>{f.file}</td>
          <td>{f.line}</td>
          <td>{f.confidence.value.capitalize()}</td>
        </tr>
        """

    details_section = ""
    for i, f in enumerate(report.findings, 1):
        sev_class = f.severity.value
        details_section += f"""
        <div class="finding-detail {sev_class}" id="detail-{i}">
          <h3>#{i} {f.severity.value.upper()} - {f.vulnerability}</h3>
          <p><strong>Category:</strong> {f.category}</p>
          <p><strong>File:</strong> {f.file} <strong>Line:</strong> {f.line}</p>
          <p><strong>Confidence:</strong> {f.confidence.value.capitalize()}</p>
          <h4>Description</h4>
          <p>{f.description}</p>
          <h4>Impact</h4>
          <p>{f.impact}</p>
          <h4>Fix Explanation</h4>
          <p>{f.fix_explanation}</p>
          <h4>Affected Code</h4>
          <pre><code class="python">{f.affected_code}</code></pre>
          <h4>Fixed Code</h4>
          <pre><code class="python">{f.fix_code}</code></pre>
          <h4>References</h4>
          <p>{f.references}</p>
        </div>
        """

    sev_counts = report.severity_counts
    color = "red" if report.risk_score >= 70 else "orange" if report.risk_score >= 40 else "blue"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FastGuard Security Report - {report.target}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 40px 20px; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .header {{ text-align: center; padding: 40px 0; border-bottom: 1px solid #30363d; margin-bottom: 40px; }}
  .header h1 {{ font-size: 2.5em; color: #58a6ff; }}
  .header h1 span {{ color: #f0883e; }}
  .header .meta {{ color: #8b949e; margin-top: 10px; }}
  .risk-score {{ text-align: center; padding: 30px; margin: 20px 0; border-radius: 12px; background: #161b22; border: 1px solid #30363d; }}
  .risk-score .score {{ font-size: 4em; font-weight: 800; color: {color}; }}
  .risk-score .label {{ font-size: 1.5em; color: {color}; margin-top: 5px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 30px 0; }}
  .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }}
  .stat-card .num {{ font-size: 2em; font-weight: bold; }}
  .stat-card .label {{ color: #8b949e; font-size: 0.9em; margin-top: 4px; }}
  .stat-card.critical .num {{ color: #f85149; }}
  .stat-card.high .num {{ color: #d29922; }}
  .stat-card.medium .num {{ color: #58a6ff; }}
  .stat-card.low .num {{ color: #3fb950; }}
  .stat-card.info .num {{ color: #8b949e; }}
  table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
  th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #30363d; }}
  th {{ background: #161b22; color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 0.85em; letter-spacing: 0.5px; }}
  tr:hover {{ background: #1c2128; }}
  .severity-badge {{ padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }}
  .severity-badge.critical {{ background: #f851491a; color: #f85149; border: 1px solid #f85149; }}
  .severity-badge.high {{ background: #d299221a; color: #d29922; border: 1px solid #d29922; }}
  .severity-badge.medium {{ background: #58a6ff1a; color: #58a6ff; border: 1px solid #58a6ff; }}
  .severity-badge.low {{ background: #3fb9501a; color: #3fb950; border: 1px solid #3fb950; }}
  .severity-badge.informational {{ background: #8b949e1a; color: #8b949e; border: 1px solid #8b949e; }}
  .finding-detail {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin: 20px 0; }}
  .finding-detail h3 {{ margin-bottom: 16px; }}
  .finding-detail h4 {{ color: #58a6ff; margin: 20px 0 8px; }}
  .finding-detail pre {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 16px; overflow-x: auto; font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 0.85em; }}
  .finding-detail code {{ font-family: 'SF Mono', Monaco, Consolas, monospace; }}
  .finding-detail.critical {{ border-left: 4px solid #f85149; }}
  .finding-detail.high {{ border-left: 4px solid #d29922; }}
  .finding-detail.medium {{ border-left: 4px solid #58a6ff; }}
  .finding-detail.low {{ border-left: 4px solid #3fb950; }}
  .finding-detail.informational {{ border-left: 4px solid #8b949e; }}
  .footer {{ text-align: center; color: #8b949e; margin-top: 60px; padding-top: 20px; border-top: 1px solid #30363d; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>⚡ Fast<span>Guard</span></h1>
    <p class="meta">Security Report | {report.date} | {report.scanned_files} files scanned in {report.duration_seconds}s</p>
  </div>

  <div class="risk-score">
    <div class="score">{report.risk_score}/100</div>
    <div class="label">{report.risk_label}</div>
  </div>

  <div class="stats-grid">
    <div class="stat-card critical">
      <div class="num">{sev_counts.get('critical', 0)}</div>
      <div class="label">Critical</div>
    </div>
    <div class="stat-card high">
      <div class="num">{sev_counts.get('high', 0)}</div>
      <div class="label">High</div>
    </div>
    <div class="stat-card medium">
      <div class="num">{sev_counts.get('medium', 0)}</div>
      <div class="label">Medium</div>
    </div>
    <div class="stat-card low">
      <div class="num">{sev_counts.get('low', 0)}</div>
      <div class="label">Low</div>
    </div>
    <div class="stat-card info">
      <div class="num">{sev_counts.get('informational', 0)}</div>
      <div class="label">Info</div>
    </div>
  </div>

  <h2>Findings ({report.total_findings})</h2>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Severity</th>
        <th>Vulnerability</th>
        <th>File</th>
        <th>Line</th>
        <th>Confidence</th>
      </tr>
    </thead>
    <tbody>
      {findings_rows}
    </tbody>
  </table>

  <h2>Detailed Findings</h2>
  {details_section}

  <div class="footer">
    <p>Generated by FastGuard v1.0.0 | Powered by OpenCode</p>
  </div>
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    console.print(f"[green]HTML report saved to {output_path}[/green]")


def write_report(
    report: ScanReport,
    output_format: Optional[str] = None,
    output_path: Optional[str] = None,
    details: bool = False,
):
    print_terminal_report(report, details=details)

    if output_format == "json" and output_path:
        generate_json_report(report, output_path)
    elif output_format == "markdown" and output_path:
        generate_markdown_report(report, output_path)
    elif output_format == "html" and output_path:
        generate_html_report(report, output_path)
