"""CVE monitor"""

import uuid
from datetime import timedelta

from provchain.data.db import Database
from provchain.data.models import SBOM, Alert, RiskLevel
from provchain.utils.network import HTTPClient


class CVEMonitor:
    """Monitors vulnerability databases for new disclosures"""

    CHECK_INTERVAL = timedelta(minutes=15)
    OSV_API_URL = "https://api.osv.dev/v1/query"

    def __init__(self, db: Database):
        self.db = db

    async def check(self, sbom: SBOM) -> list[Alert]:
        """Check for CVEs affecting packages in SBOM"""
        alerts = []

        # Query OSV API for each package
        for package in sbom.packages:
            if package.ecosystem != "pypi":
                continue  # Only support PyPI for now

            try:
                # Query OSV API
                query = {
                    "package": {
                        "name": package.name,
                        "ecosystem": "PyPI",
                    },
                    "version": package.version,
                }

                # Query OSV API
                with HTTPClient(base_url="https://api.osv.dev") as client:
                    response = client.post("/v1/query", json=query)
                    if response.status_code == 200:
                        data = response.json()
                        vulns = data.get("vulns", [])

                        for vuln in vulns:
                            vuln_id = vuln.get("id", "unknown")
                            summary = vuln.get("summary", "No summary available")
                            severity = vuln.get("database_specific", {}).get("severity", "UNKNOWN")

                            # Map severity to RiskLevel
                            severity_map = {
                                "CRITICAL": RiskLevel.CRITICAL,
                                "HIGH": RiskLevel.HIGH,
                                "MEDIUM": RiskLevel.MEDIUM,
                                "LOW": RiskLevel.LOW,
                            }
                            risk_level = severity_map.get(severity.upper(), RiskLevel.MEDIUM)

                            alerts.append(
                                Alert(
                                    id=str(uuid.uuid4()),
                                    package=package,
                                    alert_type="cve",
                                    severity=risk_level,
                                    title=f"CVE found: {vuln_id}",
                                    description=f"Vulnerability {vuln_id} affects {package.name} {package.version}: {summary}",
                                    evidence={
                                        "vuln_id": vuln_id,
                                        "summary": summary,
                                        "severity": severity,
                                        "details": vuln.get("details", ""),
                                    },
                                    recommended_action=f"Update {package.name} to a patched version",
                                )
                            )
            except Exception:
                # Query failed, continue with next package
                continue

        return alerts
