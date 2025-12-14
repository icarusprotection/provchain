"""Analysis modules"""

from provchain.interrogator.analyzers.attack import AttackAnalyzer
from provchain.interrogator.analyzers.base import BaseAnalyzer
from provchain.interrogator.analyzers.behavior import BehaviorAnalyzer
from provchain.interrogator.analyzers.install_hooks import InstallHookAnalyzer
from provchain.interrogator.analyzers.maintainer import MaintainerAnalyzer
from provchain.interrogator.analyzers.metadata import MetadataAnalyzer
from provchain.interrogator.analyzers.typosquat import TyposquatAnalyzer
from provchain.interrogator.analyzers.vulnerability import VulnerabilityAnalyzer

__all__ = [
    "AttackAnalyzer",
    "BaseAnalyzer",
    "BehaviorAnalyzer",
    "InstallHookAnalyzer",
    "MaintainerAnalyzer",
    "MetadataAnalyzer",
    "TyposquatAnalyzer",
    "VulnerabilityAnalyzer",
]
