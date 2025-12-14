"""Main CLI entry point"""

import sys
import typer
from rich.console import Console

from provchain import __version__
from provchain.cli.commands import attack, config, sbom, vet, verify, vuln, watch

console = Console()

_app = typer.Typer(
    name="provchain",
    help="ProvChain: Supply Chain Security Suite",
    add_completion=False,
    no_args_is_help=True,
)


@_app.callback()
def main_callback() -> None:
    """ProvChain: Supply Chain Security Suite"""
    pass

# Add command groups
# Note: vet is a direct command function, not a group, so we register it directly
_app.command(name="vet", help="Analyze package before installation")(vet.vet)
_app.add_typer(verify.app, name="verify")
_app.add_typer(watch.app, name="watch")
_app.add_typer(sbom.app, name="sbom")
_app.add_typer(config.app, name="config")
_app.add_typer(vuln.app, name="vuln")
_app.add_typer(attack.app, name="attack")


def main() -> None:
    """Main entry point - wrapper to handle --version"""
    # Check for --version flag before invoking Typer
    if len(sys.argv) > 1 and (sys.argv[1] == "--version" or sys.argv[1] == "-v"):
        console.print(f"provchain version {__version__}")
        sys.exit(0)
    _app()


# Keep app as alias for backward compatibility
app = _app


if __name__ == "__main__":
    main()

