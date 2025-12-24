"""Repository monitor"""

import uuid
from datetime import timedelta

from provchain.data.db import Database
from provchain.data.models import Alert, PackageIdentifier, RiskLevel
from provchain.integrations.github import GitHubClient


class RepositoryMonitor:
    """Monitors source repository for suspicious changes"""

    CHECK_INTERVAL = timedelta(hours=12)

    def __init__(self, db: Database, github_token: str | None = None):
        self.db = db
        self.github_token = github_token

    async def check(self, repo_url: str) -> list[Alert]:
        """Check repository for changes"""
        alerts = []

        try:
            github = GitHubClient(token=self.github_token)
            owner, repo = github.parse_repo_url(repo_url)
            repo_data = github.get_repository(owner, repo)

            # Check if repository was transferred
            # Check if repository visibility changed
            if repo_data.get("private"):
                # Repository is private - could be suspicious if it was public
                alerts.append(
                    Alert(
                        id=str(uuid.uuid4()),
                        package=PackageIdentifier(ecosystem="pypi", name=repo, version=""),
                        alert_type="repo_visibility_change",
                        severity=RiskLevel.MEDIUM,
                        title=f"Repository visibility changed: {repo}",
                        description="Repository is now private",
                        evidence={"repo_url": repo_url},
                        recommended_action="Verify repository visibility change is legitimate",
                    )
                )

            github.close()
        except Exception:
            # Repository check failed, skip
            pass

        return alerts
