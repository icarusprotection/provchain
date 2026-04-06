"""Vet command: local and enterprise-backed package analysis."""

import concurrent.futures
import json
import sys
from typing import Any

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from provchain.cli.formatters import format_report
from provchain.config import Config
from provchain.core.package import parse_package_spec, parse_requirements_file
from provchain.data.cache import Cache
from provchain.data.db import Database
from provchain.enterprise.client import (
    EnterpriseClient,
    enterprise_enabled,
    remote_vet_response_to_report,
)
from provchain.interrogator.engine import InterrogatorEngine

app = typer.Typer(name="vet", help="Analyze package before installation")
console = Console()


def _ci_exit_for_reports(reports: list[Any], threshold: str, blocked: bool = False) -> None:
    if blocked:
        sys.exit(1)

    threshold_map = {"low": 2.0, "medium": 4.0, "high": 6.0, "critical": 8.0}
    threshold_value = threshold_map.get(threshold.lower(), 4.0)

    for report in reports:
        if report.risk_score >= threshold_value:
            sys.exit(1)

    sys.exit(0)


def _print_dependency_analysis(analysis: dict[str, Any], format_type: str) -> None:
    if format_type == "json":
        print(json.dumps(analysis, indent=2))
        return

    console.print("\n[bold]ProvChain Enterprise Dependency Analysis[/bold]")
    console.print(
        "Root: "
        f"{analysis.get('root_package_name')} @ {analysis.get('root_package_version') or 'unknown'}"
    )
    console.print(
        "Status: "
        f"{analysis.get('status')} | Total packages: {analysis.get('total_packages', 0)} | "
        f"Blocked: {analysis.get('blocked_packages', 0)}"
    )
    if analysis.get("truncated"):
        console.print(f"[yellow]{analysis.get('truncated_reason', 'Graph was truncated')}[/yellow]")

    table = Table(title="Dependency Graph Nodes")
    table.add_column("Package", style="cyan")
    table.add_column("Depth", justify="right")
    table.add_column("Risk", justify="right")
    table.add_column("Blocked", justify="center")

    for node in analysis.get("nodes", []):
        blocked = "yes" if node.get("blocked") else "no"
        table.add_row(
            f"{node.get('package_name')}=={node.get('package_version')}",
            str(node.get("depth", 0)),
            f"{float(node.get('risk_score', 0.0)):.1f}",
            blocked,
        )

    console.print(table)
    console.print()


@app.command()
def vet(
    package: str = typer.Argument(
        None,
        help="Package specifier (e.g., 'requests' or 'requests==2.31.0')",
    ),
    requirements: str = typer.Option(None, "-r", "--requirements", help="Requirements file path"),
    deep: bool = typer.Option(
        False, "--deep", help="Include behavioral analysis (requires Docker)"
    ),
    transitive: bool = typer.Option(
        False,
        "--transitive",
        help="Use enterprise dependency graph analysis for a single root package",
    ),
    max_depth: int = typer.Option(
        4,
        "--max-depth",
        help="Maximum dependency depth for enterprise transitive analysis",
    ),
    max_nodes: int = typer.Option(
        50,
        "--max-nodes",
        help="Maximum dependency nodes for enterprise transitive analysis",
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, sarif, markdown"
    ),
    ci: bool = typer.Option(
        False, "--ci", help="CI mode: exit with non-zero code if risk exceeds threshold"
    ),
    threshold: str = typer.Option(
        "medium", "--threshold", help="Risk threshold: low, medium, high, critical"
    ),
    parallel: int = typer.Option(
        1,
        "--parallel",
        "-j",
        "--jobs",
        help="Number of parallel jobs for analyzing multiple packages",
    ),
) -> None:
    """Analyze packages locally or through ProvChain Enterprise."""
    if not package and not requirements:
        console.print("[red]Error:[/red] Provide a PACKAGE argument or use -r/--requirements")
        raise typer.Exit(1)

    config = Config()
    use_enterprise = enterprise_enabled(config)

    if transitive and requirements:
        console.print("[red]Error:[/red] --transitive cannot be used with --requirements")
        raise typer.Exit(1)

    if transitive and not use_enterprise:
        console.print(
            "[red]Error:[/red] --transitive requires enterprise login. "
            "Run `provchain login --api-key ... --url ...` first."
        )
        raise typer.Exit(1)

    if use_enterprise:
        client = EnterpriseClient.from_config(config)

        if transitive:
            spec = parse_package_spec(package)
            version = spec.version
            if spec.specifier and not version:
                version = None
            try:
                analysis = client.analyze_dependencies(
                    package_name=spec.name,
                    version=version,
                    deep=deep,
                    max_depth=max_depth,
                    max_nodes=max_nodes,
                )
            except RuntimeError as exc:
                console.print(f"[red]Enterprise dependency analysis failed:[/red] {exc}")
                raise typer.Exit(1)

            _print_dependency_analysis(analysis, format)
            if ci and int(analysis.get("blocked_packages", 0)) > 0:
                sys.exit(1)
            return

        specs = parse_requirements_file(requirements) if requirements else [parse_package_spec(package)]

        def analyze_single_remote(spec):
            remote_version = spec.version if spec.version else None
            response = client.vet_package(spec.name, version=remote_version, deep=deep)
            return response, remote_vet_response_to_report(response)

        responses: list[dict[str, Any]] = []
        reports = []

        try:
            if len(specs) > 1 and parallel > 1:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                ) as progress:
                    task = progress.add_task(
                        f"Analyzing {len(specs)} packages via enterprise backend...",
                        total=len(specs),
                    )
                    with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
                        futures = {executor.submit(analyze_single_remote, spec): spec for spec in specs}
                        for future in concurrent.futures.as_completed(futures):
                            response, report = future.result()
                            responses.append(response)
                            reports.append(report)
                            progress.update(
                                task,
                                advance=1,
                                description=f"Analyzed {report.package.name}",
                            )
            else:
                for spec in specs:
                    response, report = analyze_single_remote(spec)
                    responses.append(response)
                    reports.append(report)
        except RuntimeError as exc:
            console.print(f"[red]Enterprise vet failed:[/red] {exc}")
            raise typer.Exit(1)

        for report in reports:
            format_report(report, format, console)

        if ci:
            any_blocked = any(bool(response.get("blocked")) for response in responses)
            _ci_exit_for_reports(reports, threshold, blocked=any_blocked)
        return

    # Local mode
    db = Database()
    engine_db = Database()
    engine_cache = Cache(engine_db)
    engine = InterrogatorEngine(enable_behavior=deep, cache=engine_cache, db=engine_db)

    packages_to_analyze = []
    if requirements:
        specs = parse_requirements_file(requirements)
        for spec in specs:
            packages_to_analyze.append(spec.to_identifier())
    else:
        try:
            spec = parse_package_spec(package)
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1)
        packages_to_analyze.append(spec.to_identifier())

    reports = []

    def analyze_single_package(pkg_id):
        """Analyze a single package."""
        try:
            cached_report = db.get_analysis(pkg_id.ecosystem, pkg_id.name, pkg_id.version)
            if cached_report:
                # Ensure cached result covers all enabled analyzers
                cached_analyzers = {r.analyzer for r in cached_report.results}
                expected_analyzers = set(engine.analyzers_enabled)
                if expected_analyzers <= cached_analyzers:
                    return cached_report
            report = engine.analyze_package(pkg_id)
            db.store_analysis(report)
            return report
        except ValueError as exc:
            error_msg = str(exc)
            console.print(f"[red]Error analyzing {pkg_id.name}: {error_msg}[/red]")
            from provchain.data.models import RiskLevel, VetReport

            return VetReport(
                package=pkg_id,
                overall_risk=RiskLevel.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                results=[],
                recommendations=[f"Package or version not found: {error_msg}"],
            )
        except Exception as exc:
            error_type = type(exc).__name__
            error_str = str(exc)
            if "HTTP" in error_type and "404" in error_str:
                console.print(f"[red]Error analyzing {pkg_id.name}: Package not found on PyPI[/red]")
            elif "HTTP" in error_type or "Connection" in error_type or "Timeout" in error_type:
                console.print(f"[red]Error analyzing {pkg_id.name}: Network error[/red]")
                console.print(f"[yellow]Details: {error_str}[/yellow]")
            else:
                console.print(f"[red]Error analyzing {pkg_id.name}: {str(exc)}[/red]")
            from provchain.data.models import RiskLevel, VetReport

            return VetReport(
                package=pkg_id,
                overall_risk=RiskLevel.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                results=[],
                recommendations=[f"Analysis failed: {str(exc)}"],
            )

    if len(packages_to_analyze) > 1 and parallel > 1:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"Analyzing {len(packages_to_analyze)} packages...",
                total=len(packages_to_analyze),
            )

            with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
                futures = {
                    executor.submit(analyze_single_package, pkg_id): pkg_id
                    for pkg_id in packages_to_analyze
                }

                for future in concurrent.futures.as_completed(futures):
                    pkg_id = futures[future]
                    try:
                        report = future.result()
                        reports.append(report)
                        progress.update(task, advance=1, description=f"Analyzed {pkg_id.name}")
                    except Exception as exc:
                        console.print(f"[red]Failed to analyze {pkg_id.name}: {exc}[/red]")
                        progress.update(task, advance=1)
    else:
        for pkg_id in packages_to_analyze:
            reports.append(analyze_single_package(pkg_id))

    for report in reports:
        format_report(report, format, console)

    if ci:
        _ci_exit_for_reports(reports, threshold)
