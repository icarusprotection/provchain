"""Vulnerability detection command"""

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from provchain.core.package import parse_package_spec, parse_requirements_file
from provchain.data.cache import Cache
from provchain.data.db import Database
from provchain.data.models import RiskLevel, VulnerabilityResult
from provchain.integrations.osv import OSVClient
from provchain.integrations.pypi import PyPIClient
from provchain.interrogator.analyzers.vulnerability import VulnerabilityAnalyzer
from provchain.cli.formatters import format_report

app = typer.Typer(name="vuln", help="Vulnerability detection and scanning")
console = Console()


@app.command()
def scan(
    requirements: str = typer.Option(None, "-r", "--requirements", help="Requirements file path"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, sarif, markdown"),
    output: str = typer.Option(None, "-o", "--output", help="Output file path"),
    severity: str = typer.Option(None, "--severity", help="Filter by severity: critical, high, medium, low"),
    cve_db: str = typer.Option("osv", "--cve-db", help="CVE database: osv, nvd (default: osv)"),
) -> None:
    """Scan requirements file for vulnerabilities"""
    if not requirements:
        console.print("[red]Error: --requirements (-r) is required[/red]")
        raise typer.Exit(1)

    if not Path(requirements).exists():
        console.print(f"[red]Error: Requirements file not found: {requirements}[/red]")
        raise typer.Exit(1)

    # Initialize database and cache
    db = Database()
    cache = Cache(db)

    # Parse requirements
    specs = parse_requirements_file(requirements)
    if not specs:
        console.print("[yellow]No packages found in requirements file[/yellow]")
        raise typer.Exit(0)

    # Initialize analyzer
    analyzer = VulnerabilityAnalyzer(cache=cache, db=db)

    # Process each package
    results = []
    with PyPIClient(cache=cache) as pypi:
        for spec in specs:
            if spec.version:
                pkg_id = spec.to_identifier()
            else:
                # Resolve latest version
                try:
                    pkg_metadata = pypi.get_package_info(spec.name)
                    pkg_id = pkg_metadata.identifier
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not resolve version for {spec.name}: {e}[/yellow]")
                    continue

            # Get package metadata
            try:
                package_metadata = pypi.get_package_info(pkg_id.name, pkg_id.version)
                vuln_result = analyzer.get_vulnerability_result(package_metadata)
                results.append(vuln_result)
            except Exception as e:
                console.print(f"[yellow]Warning: Error analyzing {pkg_id.name}: {e}[/yellow]")
                continue

    # Filter by severity if specified
    if severity:
        severity_level = RiskLevel(severity.lower())
        filtered_results = []
        for result in results:
            filtered_vulns = [
                v for v in result.vulnerabilities if v.severity == severity_level
            ]
            if filtered_vulns:
                result.vulnerabilities = filtered_vulns
                result.total_count = len(filtered_vulns)
                filtered_results.append(result)
        results = filtered_results

    # Display results
    if format == "table":
        _display_vulnerability_table(results)
    elif format == "json":
        import json
        output_data = [r.model_dump() for r in results]
        output_str = json.dumps(output_data, indent=2, default=str)
        if output:
            Path(output).write_text(output_str)
        else:
            console.print(output_str)
    elif format in ("sarif", "markdown"):
        # SARIF and Markdown formats are not yet supported for vulnerability results
        # Fall back to table format
        _display_vulnerability_table(results)
    else:
        # Unknown format, default to table
        _display_vulnerability_table(results)

    # Exit with non-zero if critical vulnerabilities found
    total_critical = sum(r.critical_count for r in results)
    if total_critical > 0:
        console.print(f"\n[red]Found {total_critical} critical vulnerabilities![/red]")
        sys.exit(1)


@app.command()
def check(
    package: str = typer.Argument(..., help="Package specifier (e.g., 'requests' or 'requests==2.31.0')"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json"),
    severity: str = typer.Option(None, "--severity", help="Filter by severity: critical, high, medium, low"),
    cve_db: str = typer.Option("osv", "--cve-db", help="CVE database: osv, nvd (default: osv)"),
) -> None:
    """Check specific package for vulnerabilities"""
    # Initialize database and cache
    db = Database()
    cache = Cache(db)

    # Parse package spec
    spec = parse_package_spec(package)
    
    # Initialize analyzer
    analyzer = VulnerabilityAnalyzer(cache=cache, db=db)

    # Get package metadata and analyze
    with PyPIClient(cache=cache) as pypi:
        try:
            if spec.version:
                # Use specified version
                package_metadata = pypi.get_package_info(spec.name, spec.version)
            else:
                # Resolve latest version (get_package_info without version returns latest)
                package_metadata = pypi.get_package_info(spec.name)
            vuln_result = analyzer.get_vulnerability_result(package_metadata)
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

    # Filter by severity if specified
    if severity:
        severity_level = RiskLevel(severity.lower())
        vuln_result.vulnerabilities = [
            v for v in vuln_result.vulnerabilities if v.severity == severity_level
        ]
        vuln_result.total_count = len(vuln_result.vulnerabilities)

    # Display results
    if format == "table":
        _display_vulnerability_table([vuln_result])
    elif format == "json":
        import json
        output_str = json.dumps(vuln_result.model_dump(), indent=2, default=str)
        console.print(output_str)
    else:
        _display_vulnerability_table([vuln_result])

    # Exit with non-zero if vulnerabilities found
    if vuln_result.total_count > 0:
        sys.exit(1)


@app.command()
def prioritize(
    requirements: str = typer.Option(None, "-r", "--requirements", help="Requirements file path"),
    severity: str = typer.Option("critical", "--severity", help="Minimum severity: critical, high, medium, low"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json"),
) -> None:
    """Prioritize vulnerabilities by severity"""
    if not requirements:
        console.print("[red]Error: --requirements (-r) is required[/red]")
        raise typer.Exit(1)

    # Use scan command with severity filter
    scan(requirements=requirements, format=format, severity=severity)


def _display_vulnerability_table(results: list[VulnerabilityResult]) -> None:
    """Display vulnerability results in a table format"""
    if not results:
        console.print("[green]No vulnerabilities found[/green]")
        return

    # Summary table
    summary_table = Table(title="Vulnerability Summary")
    summary_table.add_column("Package", style="cyan")
    summary_table.add_column("Total", justify="right")
    summary_table.add_column("Critical", justify="right", style="red")
    summary_table.add_column("High", justify="right", style="yellow")
    summary_table.add_column("Medium", justify="right", style="blue")
    summary_table.add_column("Low", justify="right")
    summary_table.add_column("Risk Score", justify="right")

    for result in results:
        summary_table.add_row(
            f"{result.package.name}=={result.package.version}",
            str(result.total_count),
            str(result.critical_count),
            str(result.high_count),
            str(result.medium_count),
            str(result.low_count),
            f"{result.risk_score:.1f}",
        )

    console.print(summary_table)

    # Detailed vulnerabilities
    console.print("\n[bold]Detailed Vulnerabilities:[/bold]\n")
    for result in results:
        if not result.vulnerabilities:
            continue

        console.print(f"[bold cyan]{result.package.name}=={result.package.version}[/bold cyan]")
        for vuln in result.vulnerabilities:
            severity_color = {
                RiskLevel.CRITICAL: "red",
                RiskLevel.HIGH: "yellow",
                RiskLevel.MEDIUM: "blue",
                RiskLevel.LOW: "green",
            }.get(vuln.severity, "white")

            console.print(f"  [{severity_color}]{vuln.severity.value.upper()}[/{severity_color}] {vuln.id}: {vuln.summary}")
            if vuln.cvss_score:
                console.print(f"    CVSS: {vuln.cvss_score.base_score:.1f} ({vuln.cvss_score.vector})")
            if vuln.fixed_versions:
                console.print(f"    Fixed in: {', '.join(vuln.fixed_versions)}")
            if vuln.exploit_available:
                console.print(f"    [red]⚠ EXPLOIT AVAILABLE[/red]")
            if vuln.references:
                console.print(f"    References: {vuln.references[0]}")
            console.print()

