"""SBOM command: SBOM management"""

from pathlib import Path

import typer
from rich.console import Console

from provchain.core.sbom import (
    generate_sbom_from_requirements,
    load_sbom_from_file,
    save_sbom_to_file,
)
from provchain.data.db import Database

app = typer.Typer(name="sbom", help="SBOM management")
console = Console()


@app.command()
def generate(
    requirements: str = typer.Option(None, "-r", "--requirements", help="Requirements file path"),
    output: str = typer.Option("sbom.json", "-o", "--output", help="Output file path"),
    name: str = typer.Option("project", "--name", help="Project name"),
) -> None:
    """Generate SBOM from requirements file or current environment"""
    if requirements:
        sbom = generate_sbom_from_requirements(requirements, name)
    else:
        # For MVP, require requirements file
        console.print("[red]Error:[/red] Requirements file required (-r)")
        return

    # Save SBOM
    save_sbom_to_file(sbom, output)
    console.print(f"[green]SBOM generated: {output}[/green]")

    # Store in database
    db = Database()
    db.store_sbom(sbom, requirements)


@app.command()
def import_sbom(
    file: str = typer.Argument(..., help="SBOM file path"),
) -> None:
    """Import existing SBOM"""
    sbom_path = Path(file)
    if not sbom_path.exists():
        console.print(f"[red]Error:[/red] SBOM file not found: {file}")
        return

    sbom = load_sbom_from_file(sbom_path)
    console.print(f"[green]Imported SBOM: {sbom.name} with {len(sbom.packages)} packages[/green]")

    # Store in database
    db = Database()
    db.store_sbom(sbom, str(sbom_path))
