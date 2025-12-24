"""SARIF formatter for GitHub Actions"""

import json

from rich.console import Console

from provchain.data.models import VetReport


def format_sarif(report: VetReport, console: Console) -> None:
    """Format report as SARIF"""
    # SARIF format for GitHub Actions
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ProvChain",
                        "version": "1.0.0",
                    }
                },
                "results": [],
            }
        ],
    }

    # Convert findings to SARIF results
    for result in report.results:
        for finding in result.findings:
            sarif["runs"][0]["results"].append(
                {
                    "ruleId": finding.id,
                    "level": finding.severity.value,
                    "message": {
                        "text": finding.description,
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": str(report.package),
                                }
                            }
                        }
                    ],
                }
            )

    console.print(json.dumps(sarif, indent=2))
