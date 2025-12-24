"""Markdown formatter"""

from rich.console import Console

from provchain.data.models import VetReport


def format_markdown(report: VetReport, console: Console) -> None:
    """Format report as Markdown"""
    output = f"""# ProvChain Analysis Report

## Package: {report.package.name} @ {report.package.version}

**Overall Risk:** {report.overall_risk.value.upper()} (Score: {report.risk_score:.1f}/10, Confidence: {report.confidence * 100:.0f}%)

## Analysis Results

"""

    for result in report.results:
        output += f"### {result.analyzer}\n\n"
        output += f"- **Risk Score:** {result.risk_score:.1f}/10\n"
        output += f"- **Confidence:** {result.confidence * 100:.0f}%\n\n"

        if result.findings:
            output += "**Findings:**\n\n"
            for finding in result.findings:
                output += f"- **{finding.title}** ({finding.severity.value})\n"
                output += f"  - {finding.description}\n"
                if finding.remediation:
                    output += f"  - Remediation: {finding.remediation}\n"
                output += "\n"

    if report.recommendations:
        output += "## Recommendations\n\n"
        for rec in report.recommendations:
            output += f"- {rec}\n"

    console.print(output)
