"""Base analyzer interface"""

from abc import ABC, abstractmethod

from provchain.data.models import AnalysisResult, PackageMetadata


class BaseAnalyzer(ABC):
    """Base class for all analyzers"""

    name: str = "base"

    @abstractmethod
    def analyze(self, package_metadata: PackageMetadata) -> AnalysisResult:
        """Analyze a package and return results"""
        pass

    def get_confidence(self, findings: list) -> float:
        """Calculate confidence score based on findings"""
        if not findings:
            return 0.5  # Medium confidence if no findings

        # Higher confidence with more findings
        confidence = min(0.5 + (len(findings) * 0.1), 1.0)
        return confidence
