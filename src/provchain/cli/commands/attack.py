"""Supply chain attack detection command"""

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from provchain.core.package import parse_package_spec
from provchain.data.cache import Cache
from provchain.data.db import Database
from provchain.data.models import AttackHistory, RiskLevel
from provchain.integrations.pypi import PyPIClient
from provchain.interrogator.analyzers.attack import AttackAnalyzer
from provchain.interrogator.engine import InterrogatorEngine

app = typer.Typer(name="attack", help="Supply chain attack detection")
console = Console()


@app.command()
def detect(
    package: str = typer.Argument(..., help="Package specifier (e.g., 'requests' or 'requests==2.31.0')"),
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Show detailed attack information"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json"),
) -> None:
    """Detect supply chain attacks for a package"""
    # Initialize database and cache
    db = Database()
    cache = Cache(db)

    # Parse package spec
    spec = parse_package_spec(package)

    # Initialize analyzer
    analyzer = AttackAnalyzer(cache=cache, db=db)

    # Get package metadata and analyze
    with PyPIClient(cache=cache) as pypi:
        try:
            if spec.version:
                # Use specified version
                package_metadata = pypi.get_package_info(spec.name, spec.version)
            else:
                # Resolve latest version (get_package_info without version returns latest)
                package_metadata = pypi.get_package_info(spec.name)
            result = analyzer.analyze(package_metadata)
        except ValueError as e:
            # Package not found or invalid version
            error_msg = str(e)
            if "not found" in error_msg.lower():
                console.print(f"[red]Error: Package or version not found: {error_msg}[/red]")
                console.print("[yellow]Tip: Verify the package name and version are correct[/yellow]")
            else:
                console.print(f"[red]Error: Invalid package specification: {error_msg}[/red]")
            raise typer.Exit(1)
        except Exception as e:
            # Network or other errors
            error_type = type(e).__name__
            if "HTTP" in error_type or "Connection" in error_type or "Timeout" in error_type:
                console.print(f"[red]Error: Network error while fetching package information[/red]")
                console.print(f"[yellow]Details: {str(e)}[/yellow]")
                console.print("[yellow]Tip: Check your internet connection and try again[/yellow]")
            else:
                console.print(f"[red]Error: Could not analyze package: {str(e)}[/red]")
                console.print("[yellow]Tip: If this persists, please report the issue[/yellow]")
            raise typer.Exit(1)

    # Display results
    if format == "table":
        _display_attack_table(result, detailed)
    elif format == "json":
        import json
        output_str = json.dumps(result.model_dump(), indent=2, default=str)
        console.print(output_str)
    else:
        _display_attack_table(result, detailed)

    # Exit with non-zero if attacks detected
    if result.findings:
        critical_count = sum(1 for f in result.findings if f.severity == RiskLevel.CRITICAL)
        high_count = sum(1 for f in result.findings if f.severity == RiskLevel.HIGH)
        if critical_count > 0 or high_count > 0:
            sys.exit(1)


@app.command()
def history(
    package: str = typer.Argument(..., help="Package name"),
    limit: int = typer.Option(10, "--limit", "-n", help="Number of history records to show"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json"),
) -> None:
    """Show attack history for a package"""
    # Initialize database
    db = Database()

    # Get attack history
    try:
        attacks = db.get_attack_history("pypi", package, limit=limit)
    except ValueError as e:
        console.print(f"[red]Error: Invalid package name: {str(e)}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        error_type = type(e).__name__
        if "HTTP" in error_type or "Connection" in error_type:
            console.print(f"[red]Error: Network error while retrieving attack history[/red]")
            console.print(f"[yellow]Details: {str(e)}[/yellow]")
        else:
            console.print(f"[red]Error: Could not retrieve attack history: {str(e)}[/red]")
        raise typer.Exit(1)

    if not attacks:
        console.print(f"[green]No attack history found for package '{package}'[/green]")
        return

    # Display results
    if format == "table":
        _display_attack_history_table(attacks)
    elif format == "json":
        import json
        output_str = json.dumps([a.model_dump() for a in attacks], indent=2, default=str)
        console.print(output_str)
    else:
        _display_attack_history_table(attacks)


def _display_attack_table(result, detailed: bool = False) -> None:
    """Display attack detection results in a table format"""
    console.print(f"\n[bold]Attack Detection Results[/bold]")
    console.print(f"Risk Score: {result.risk_score:.1f}/10")
    console.print(f"Confidence: {result.confidence*100:.0f}%")
    console.print(f"Attacks Detected: {len(result.findings)}\n")

    if not result.findings:
        console.print("[green]No attacks detected[/green]")
        return

    # Summary table
    summary_table = Table(title="Attack Summary")
    summary_table.add_column("Attack Type", style="cyan")
    summary_table.add_column("Severity", justify="center")
    summary_table.add_column("Count", justify="right")

    attack_types = {}
    for finding in result.findings:
        attack_type = finding.id.split("_")[0] if "_" in finding.id else "unknown"
        if attack_type not in attack_types:
            attack_types[attack_type] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        attack_types[attack_type][finding.severity.value] = (
            attack_types[attack_type].get(finding.severity.value, 0) + 1
        )

    for attack_type, counts in attack_types.items():
        total = sum(counts.values())
        max_severity = max(
            (s for s, c in counts.items() if c > 0),
            key=lambda s: ["low", "medium", "high", "critical"].index(s) if s in ["low", "medium", "high", "critical"] else -1,
            default="low",
        )
        severity_color = {
            "critical": "red",
            "high": "yellow",
            "medium": "blue",
            "low": "green",
        }.get(max_severity, "white")

        summary_table.add_row(
            attack_type,
            f"[{severity_color}]{max_severity.upper()}[/{severity_color}]",
            str(total),
        )

    console.print(summary_table)

    # Detailed findings
    if detailed:
        console.print("\n[bold]Detailed Findings:[/bold]\n")
        for finding in result.findings:
            severity_color = {
                RiskLevel.CRITICAL: "red",
                RiskLevel.HIGH: "yellow",
                RiskLevel.MEDIUM: "blue",
                RiskLevel.LOW: "green",
            }.get(finding.severity, "white")

            console.print(f"  [{severity_color}]{finding.severity.value.upper()}[/{severity_color}] {finding.title}")
            console.print(f"    {finding.description}")
            if finding.evidence:
                console.print(f"    Evidence: {', '.join(finding.evidence[:3])}")
            if finding.remediation:
                console.print(f"    Remediation: {finding.remediation}")
            console.print()


def _display_attack_history_table(attacks: list[AttackHistory]) -> None:
    """Display attack history in a table format"""
    table = Table(title="Attack History")
    table.add_column("Date", style="cyan")
    table.add_column("Attack Type", style="yellow")
    table.add_column("Severity", justify="center")
    table.add_column("Description", style="white")
    table.add_column("Resolved", justify="center")

    for attack in attacks:
        severity_color = {
            RiskLevel.CRITICAL: "red",
            RiskLevel.HIGH: "yellow",
            RiskLevel.MEDIUM: "blue",
            RiskLevel.LOW: "green",
        }.get(attack.severity, "white")

        resolved_str = "[green]Yes[/green]" if attack.resolved else "[red]No[/red]"

        table.add_row(
            attack.detected_at.strftime("%Y-%m-%d %H:%M:%S"),
            attack.attack_type,
            f"[{severity_color}]{attack.severity.value.upper()}[/{severity_color}]",
            attack.description[:50] + "..." if len(attack.description) > 50 else attack.description,
            resolved_str,
        )

    console.print(table)

