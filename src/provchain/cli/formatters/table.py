"""Table formatter using Rich"""

from rich.console import Console
from rich.table import Table

from provchain.data.models import VetReport


def format_table(report: VetReport, console: Console) -> None:
    """Format report as Rich table"""
    # Header
    console.print("\n[bold]ProvChain Analysis Report[/bold]")
    console.print(f"Package: {report.package.name} @ {report.package.version}")
    console.print(
        f"Overall Risk: {report.overall_risk.value.upper()} (Score: {report.risk_score:.1f}/10, Confidence: {report.confidence * 100:.0f}%)"
    )

    # Analyzer results table
    table = Table(title="Analysis Results")
    table.add_column("Analyzer", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Summary", style="green")

    for result in report.results:
        # Create summary from findings
        if result.findings:
            summary = result.findings[0].title
        else:
            summary = "No issues found"

        table.add_row(
            result.analyzer,
            f"{result.risk_score:.1f}",
            summary,
        )

    console.print(table)

    # Recommendations
    if report.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in report.recommendations:
            console.print(f"  • {rec}")

    console.print()
