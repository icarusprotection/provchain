"""Verify command: Provenance checking"""

from pathlib import Path

import typer
from rich.console import Console

from provchain.core.package import parse_package_spec
from provchain.verifier.engine import VerifierEngine

app = typer.Typer(name="verify", help="Verify package provenance")
console = Console()


@app.command()
def verify(
    artifact: str = typer.Argument(..., help="Artifact path or package specifier"),
) -> None:
    """Verify package artifact provenance"""
    engine = VerifierEngine()

    artifact_path = Path(artifact)
    if artifact_path.exists():
        # Verify local artifact
        result = engine.verify_artifact(artifact_path)
        console.print(f"Verification result: {result}")
    else:
        # Try to parse as package specifier
        try:
            spec = parse_package_spec(artifact)
            result = engine.verify_package(spec.to_identifier())
            console.print(f"Verification result: {result}")
        except ValueError:
            console.print(f"[red]Error:[/red] Invalid artifact path or package specifier: {artifact}")

