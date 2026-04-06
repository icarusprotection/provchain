"""JSON formatter"""

import json

from rich.console import Console

from provchain.data.models import VetReport


def format_json(report: VetReport, console: Console) -> None:
    """Format report as JSON"""
    output = report.model_dump(mode="json")
    # Use print() directly so Rich doesn't interpret escape sequences or wrap lines
    print(json.dumps(output, indent=2, default=str))
