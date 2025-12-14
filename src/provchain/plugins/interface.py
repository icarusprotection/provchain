"""Plugin interfaces"""

from abc import ABC, abstractmethod
from typing import Any

from provchain.data.models import AnalysisResult, PackageMetadata


class AnalyzerPlugin(ABC):
    """Base class for analyzer plugins"""

    name: str = ""

    @abstractmethod
    def analyze(self, package_metadata: PackageMetadata) -> AnalysisResult:
        """Analyze package and return results"""
        pass


class ReporterPlugin(ABC):
    """Base class for reporter plugins"""

    name: str = ""

    @abstractmethod
    def report(self, report: Any) -> None:
        """Generate report"""
        pass

