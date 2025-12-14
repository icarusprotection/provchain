"""Output formatters"""

from provchain.cli.formatters.json import format_json
from provchain.cli.formatters.markdown import format_markdown
from provchain.cli.formatters.sarif import format_sarif
from provchain.cli.formatters.table import format_table


def format_report(report, format_type: str, console) -> None:
    """Format and display report"""
    if format_type == "json":
        format_json(report, console)
    elif format_type == "sarif":
        format_sarif(report, console)
    elif format_type == "markdown":
        format_markdown(report, console)
    else:
        format_table(report, console)

