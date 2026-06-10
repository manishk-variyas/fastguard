from __future__ import annotations

from typing import Optional

import typer
from rich import print as rprint

from fastguard import __version__
from fastguard.report import write_report
from fastguard.scanner import run_scan

app = typer.Typer(
    name="fastguard",
    help="FastGuard - AI-powered security scanner for Python FastAPI backends",
    no_args_is_help=True,
)


def _version_callback(value: bool):
    if value:
        rprint(f"[bold blue]FastGuard[/bold blue] v{__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit",
        callback=_version_callback,
        is_eager=True,
    ),
):
    pass


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Target FastAPI project directory",
        exists=False,
    ),
    output: Optional[str] = typer.Option(
        "html",
        "--output",
        "-o",
        help="Report output format (html, markdown, json)",
    ),
    report: Optional[str] = typer.Option(
        None,
        "--report",
        "-r",
        help="Path for the generated report file",
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity levels (comma-separated): critical,high,medium,low,informational",
    ),
    details: bool = typer.Option(
        True,
        "--details",
        "-d",
        help="Show detailed findings in terminal output",
    ),
):
    """Scan a FastAPI project for security vulnerabilities."""
    severity_filter: Optional[list[str]] = None
    if severity:
        severity_filter = [s.strip().lower() for s in severity.split(",")]
        valid = {"critical", "high", "medium", "low", "informational"}
        for s in severity_filter:
            if s not in valid:
                rprint(f"[red]Invalid severity: '{s}'. Choose from: {', '.join(valid)}[/red]")
                raise typer.Exit(code=1)

    if output and output not in ("html", "markdown", "json"):
        rprint(f"[red]Invalid output format: '{output}'. Choose from: html, markdown, json[/red]")
        raise typer.Exit(code=1)

    if output and not report:
        safe_name = target.rstrip("/").replace("/", "-").replace("\\", "-").replace(" ", "_")
        report = f"fastguard_report_{safe_name}.html"

    rprint("[bold blue]⚡ FastGuard[/bold blue] - Scanning for vulnerabilities...\n")

    try:
        scan_report = run_scan(
            target_dir=target,
            severity_filter=severity_filter,
            details=details,
        )
    except (FileNotFoundError, NotADirectoryError) as e:
        rprint(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        rprint(f"[red]Scan failed: {e}[/red]")
        raise typer.Exit(code=1)

    write_report(scan_report, output_format=output, output_path=report, details=details)
