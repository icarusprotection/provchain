"""Vet command: Pre-install analysis"""

import concurrent.futures
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from provchain.core.package import parse_package_spec, parse_requirements_file
from provchain.data.cache import Cache
from provchain.data.db import Database
from provchain.interrogator.engine import InterrogatorEngine
from provchain.cli.formatters import format_report

app = typer.Typer(name="vet", help="Analyze package before installation")
console = Console()


@app.command()
def vet(
    package: str = typer.Argument(..., help="Package specifier (e.g., 'requests' or 'requests==2.31.0')"),
    requirements: str = typer.Option(None, "-r", "--requirements", help="Requirements file path"),
    deep: bool = typer.Option(False, "--deep", help="Include behavioral analysis (requires Docker)"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, sarif, markdown"),
    ci: bool = typer.Option(False, "--ci", help="CI mode: exit with non-zero code if risk exceeds threshold"),
    threshold: str = typer.Option("medium", "--threshold", help="Risk threshold: low, medium, high, critical"),
    parallel: int = typer.Option(1, "--parallel", "-j", "--jobs", help="Number of parallel jobs for analyzing multiple packages"),
) -> None:
    """Analyze package for security risks before installation"""
    # Initialize database and cache
    db = Database()
    cache = Cache(db)

    # Initialize database and cache for engine
    engine_db = Database()
    engine_cache = Cache(engine_db)

    # Initialize engine
    engine = InterrogatorEngine(enable_behavior=deep, cache=engine_cache, db=engine_db)

    # Parse packages
    packages_to_analyze = []

    if requirements:
        # Parse requirements file
        specs = parse_requirements_file(requirements)
        for spec in specs:
            if spec.version:
                packages_to_analyze.append(spec.to_identifier())
            else:
                # Need to resolve version - for MVP, use latest
                packages_to_analyze.append(spec.to_identifier())
    else:
        # Parse single package
        spec = parse_package_spec(package)
        packages_to_analyze.append(spec.to_identifier())

    # Analyze packages
    reports = []
    
    def analyze_single_package(pkg_id):
        """Analyze a single package"""
        try:
            # Check cache first
            cached_report = db.get_analysis(pkg_id.ecosystem, pkg_id.name, pkg_id.version)
            if cached_report:
                return cached_report
            else:
                report = engine.analyze_package(pkg_id)
                db.store_analysis(report)
                return report
        except ValueError as e:
            # Package not found or invalid version
            error_msg = str(e)
            console.print(f"[red]Error analyzing {pkg_id.name}: {error_msg}[/red]")
            from provchain.data.models import VetReport, RiskLevel
            return VetReport(
                package=pkg_id,
                overall_risk=RiskLevel.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                results=[],
                recommendations=[f"Package or version not found: {error_msg}"],
            )
        except Exception as e:
            # Network or other errors
            error_type = type(e).__name__
            if "HTTP" in error_type or "Connection" in error_type or "Timeout" in error_type:
                console.print(f"[red]Error analyzing {pkg_id.name}: Network error[/red]")
                console.print(f"[yellow]Details: {str(e)}[/yellow]")
            else:
                console.print(f"[red]Error analyzing {pkg_id.name}: {str(e)}[/red]")
            # Return a minimal error report
            from provchain.data.models import VetReport, RiskLevel
            return VetReport(
                package=pkg_id,
                overall_risk=RiskLevel.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                results=[],
                recommendations=[f"Analysis failed: {str(e)}"],
            )
    
    # Use parallel execution if multiple packages and parallel > 1
    if len(packages_to_analyze) > 1 and parallel > 1:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Analyzing {len(packages_to_analyze)} packages...", total=len(packages_to_analyze))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
                futures = {executor.submit(analyze_single_package, pkg_id): pkg_id for pkg_id in packages_to_analyze}
                
                for future in concurrent.futures.as_completed(futures):
                    pkg_id = futures[future]
                    try:
                        report = future.result()
                        reports.append(report)
                        progress.update(task, advance=1, description=f"Analyzed {pkg_id.name}")
                    except Exception as e:
                        console.print(f"[red]Failed to analyze {pkg_id.name}: {e}[/red]")
                        progress.update(task, advance=1)
    else:
        # Sequential execution for single package or parallel=1
        for pkg_id in packages_to_analyze:
            report = analyze_single_package(pkg_id)
            reports.append(report)

    # Format and display reports
    for report in reports:
        format_report(report, format, console)

    # CI mode: check threshold and exit
    if ci:
        threshold_map = {"low": 2.0, "medium": 4.0, "high": 6.0, "critical": 8.0}
        threshold_value = threshold_map.get(threshold.lower(), 4.0)

        for report in reports:
            if report.risk_score >= threshold_value:
                sys.exit(1)

        sys.exit(0)

