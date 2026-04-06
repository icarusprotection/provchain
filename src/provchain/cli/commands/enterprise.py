"""Enterprise CLI commands."""

from pathlib import Path

import typer
from rich.console import Console

from provchain.config import Config
from provchain.enterprise.client import EnterpriseClient, enterprise_enabled

app = typer.Typer(name="enterprise", help="Enterprise backend integration")
console = Console()


def _config_path() -> Path:
    return Path.home() / ".provchain" / "config.toml"


def login(
    api_key: str = typer.Option(..., "--api-key", help="ProvChain Enterprise API key"),
    url: str = typer.Option(
        "http://localhost:8000",
        "--url",
        help="ProvChain Enterprise backend base URL",
    ),
) -> None:
    """Persist enterprise backend credentials for the CLI."""
    config = Config(config_path=_config_path())
    config.set("enterprise", "enabled", True)
    config.set("enterprise", "api_key", api_key)
    config.set("enterprise", "api_url", url.rstrip("/"))
    config.save()
    console.print("[green]ProvChain Enterprise login saved.[/green]")
    console.print(f"Backend: {url.rstrip('/')}")


def logout() -> None:
    """Clear enterprise backend credentials."""
    config = Config(config_path=_config_path())
    config.set("enterprise", "enabled", False)
    config.set("enterprise", "api_key", "")
    config.save()
    console.print("[green]ProvChain Enterprise login cleared.[/green]")


@app.command()
def status() -> None:
    """Show current enterprise backend configuration."""
    config = Config(config_path=_config_path())
    if not enterprise_enabled(config):
        console.print("[yellow]Enterprise backend is not configured.[/yellow]")
        return

    client = EnterpriseClient.from_config(config)
    health_note = "unverified"
    try:
        health = client.health()
        health_note = health.get("status", "reachable")
    except RuntimeError:
        health_note = "configured"

    masked_key = str(config.get("enterprise", "api_key", ""))
    if len(masked_key) > 8:
        masked_key = f"{masked_key[:8]}..."

    console.print("[green]Enterprise backend configured.[/green]")
    console.print(f"URL: {config.get('enterprise', 'api_url')}")
    console.print(f"API key: {masked_key}")
    console.print(f"Health: {health_note}")
