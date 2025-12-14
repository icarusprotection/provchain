"""Watch command: Continuous monitoring"""

import asyncio
from pathlib import Path

import typer
from rich.console import Console

from provchain.core.sbom import load_sbom_from_file
from provchain.data.db import Database
from provchain.watchdog.engine import WatchdogEngine

app = typer.Typer(name="watch", help="Continuous monitoring")
console = Console()


@app.command()
def watch(
    sbom: str = typer.Option(None, "--sbom", help="SBOM file path"),
    daemon: bool = typer.Option(False, "--daemon", help="Run as background daemon"),
) -> None:
    """Start monitoring packages in SBOM"""
    if not sbom:
        console.print("[red]Error:[/red] SBOM file required (--sbom)")
        return

    sbom_path = Path(sbom)
    if not sbom_path.exists():
        console.print(f"[red]Error:[/red] SBOM file not found: {sbom}")
        return

    # Load SBOM
    sbom_data = load_sbom_from_file(sbom_path)

    # Initialize watchdog
    db = Database()
    engine = WatchdogEngine(db)

    if daemon:
        console.print(f"[green]Starting watchdog daemon for SBOM: {sbom}[/green]")
        asyncio.run(engine.run_daemon(sbom_data))
    else:
        console.print(f"[green]Checking SBOM: {sbom}[/green]")
        alerts = asyncio.run(engine.check_sbom(sbom_data))
        if alerts:
            console.print(f"[yellow]Found {len(alerts)} alert(s)[/yellow]")
            for alert in alerts:
                console.print(f"  - {alert.title}: {alert.description}")
        else:
            console.print("[green]No alerts[/green]")


@app.command()
def status() -> None:
    """Check monitoring status"""
    db = Database()
    alerts = db.get_unresolved_alerts()
    console.print(f"Unresolved alerts: {len(alerts)}")
    for alert in alerts:
        console.print(f"  - {alert.title} ({alert.severity.value})")

