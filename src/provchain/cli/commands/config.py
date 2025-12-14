"""Config command: Configuration management"""

import json
from pathlib import Path

import typer
from rich.console import Console

from provchain.config import Config

app = typer.Typer(name="config", help="Configuration management")
console = Console()


@app.command()
def init() -> None:
    """Initialize configuration file"""
    config_path = Path.home() / ".provchain" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)

    if config_path.exists():
        console.print(f"[yellow]Config file already exists: {config_path}[/yellow]")
        return

    # Create default config
    config_content = """[general]
threshold = "medium"
analyzers = ["typosquat", "maintainer", "metadata", "install_hooks", "behavior"]
cache_ttl = 24

[behavior]
enabled = true
timeout = 60
network_policy = "monitor"

[watchdog]
check_interval = 60

[output]
format = "table"
verbosity = "normal"
color = true

[integrations]
github_token = ""
pypi_token = ""
"""

    config_path.write_text(config_content)
    console.print(f"[green]Configuration file created: {config_path}[/green]")


@app.command()
def set(
    key: str = typer.Argument(..., help="Configuration key in format 'section.key'"),
    value: str = typer.Argument(..., help="Configuration value"),
) -> None:
    """Set configuration value"""
    # Parse key format: section.key
    if "." not in key:
        console.print("[red]Error: Key must be in format 'section.key' (e.g., 'general.threshold')[/red]")
        raise typer.Exit(1)

    section, config_key = key.split(".", 1)

    # Validate section exists in default config
    if section not in Config.DEFAULT_CONFIG:
        console.print(f"[red]Error: Invalid section '{section}'. Valid sections: {', '.join(Config.DEFAULT_CONFIG.keys())}[/red]")
        raise typer.Exit(1)

    # Get the config instance
    config_path = Path.home() / ".provchain" / "config.toml"
    # Ensure directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config = Config(config_path=config_path)

    # Get the expected type from default config
    default_section = Config.DEFAULT_CONFIG[section]
    if config_key not in default_section:
        console.print(f"[red]Error: Invalid key '{config_key}' in section '{section}'. Valid keys: {', '.join(default_section.keys())}[/red]")
        raise typer.Exit(1)

    expected_type = type(default_section[config_key])

    # Convert value to appropriate type
    try:
        if expected_type is bool:
            # Handle boolean strings
            if value.lower() in ("true", "1", "yes", "on"):
                converted_value = True
            elif value.lower() in ("false", "0", "no", "off"):
                converted_value = False
            else:
                console.print(f"[red]Error: Invalid boolean value '{value}'. Use 'true' or 'false'[/red]")
                raise typer.Exit(1)
        elif expected_type is int:
            converted_value = int(value)
        elif expected_type is list:
            # Try to parse as JSON list
            try:
                converted_value = json.loads(value)
                if not isinstance(converted_value, list):
                    raise ValueError("Not a list")
            except (json.JSONDecodeError, ValueError):
                # Fallback: comma-separated values
                # Also handle PowerShell-style quoting where quotes might be included
                value_cleaned = value.strip().strip('"').strip("'")
                if value_cleaned.startswith("[") and value_cleaned.endswith("]"):
                    # Try parsing again after cleaning quotes
                    try:
                        converted_value = json.loads(value_cleaned)
                        if not isinstance(converted_value, list):
                            raise ValueError("Not a list")
                    except (json.JSONDecodeError, ValueError):
                        # Final fallback: comma-separated values
                        converted_value = [v.strip().strip('"').strip("'") for v in value_cleaned.strip("[]").split(",") if v.strip()]
                else:
                    # Comma-separated values
                    converted_value = [v.strip().strip('"').strip("'") for v in value.split(",") if v.strip()]
        else:
            # String type
            converted_value = value

        # Validate specific values before setting
        if section == "general" and config_key == "threshold":
            valid_thresholds = ["low", "medium", "high", "critical"]
            if converted_value not in valid_thresholds:
                console.print(f"[red]Error: Invalid threshold value '{converted_value}'. Must be one of: {', '.join(valid_thresholds)}[/red]")
                raise typer.Exit(1)
        
        if section == "behavior" and config_key == "network_policy":
            valid_policies = ["allow", "deny", "monitor"]
            if converted_value not in valid_policies:
                console.print(f"[red]Error: Invalid network_policy value '{converted_value}'. Must be one of: {', '.join(valid_policies)}[/red]")
                raise typer.Exit(1)
        
        if section == "output" and config_key == "format":
            valid_formats = ["table", "json", "sarif", "markdown"]
            if converted_value not in valid_formats:
                console.print(f"[red]Error: Invalid format value '{converted_value}'. Must be one of: {', '.join(valid_formats)}[/red]")
                raise typer.Exit(1)
        
        if section == "output" and config_key == "verbosity":
            valid_verbosities = ["quiet", "normal", "verbose"]
            if converted_value not in valid_verbosities:
                console.print(f"[red]Error: Invalid verbosity value '{converted_value}'. Must be one of: {', '.join(valid_verbosities)}[/red]")
                raise typer.Exit(1)

        # Set the value
        config.set(section, config_key, converted_value)

        # Save to file
        try:
            config.save()
            console.print(f"[green]Configuration updated: {key} = {converted_value}[/green]")
        except RuntimeError as e:
            console.print(f"[red]Error saving configuration: {e}[/red]")
            raise typer.Exit(1)

    except ValueError:
        console.print(f"[red]Error: Invalid value type. Expected {expected_type.__name__}, got '{value}'[/red]")
        raise typer.Exit(1)


@app.command()
def show() -> None:
    """Show current configuration"""
    config_path = Path.home() / ".provchain" / "config.toml"
    if config_path.exists():
        console.print(f"[green]Configuration file: {config_path}[/green]")
        console.print(config_path.read_text())
    else:
        console.print("[yellow]No configuration file found. Run 'provchain config init' to create one.[/yellow]")


@app.command()
def validate() -> None:
    """Validate configuration file"""
    config_path = Path.home() / ".provchain" / "config.toml"
    config = Config(config_path=config_path)
    
    try:
        config.validate()
        console.print("[green]Configuration is valid![/green]")
    except ValueError as e:
        console.print(f"[red]Configuration validation failed:[/red]")
        console.print(str(e))
        raise typer.Exit(1)

