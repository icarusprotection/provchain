"""Core data models for ProvChain"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk level enumeration"""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PackageIdentifier(BaseModel):
    """Unique identifier for a package version"""

    ecosystem: str = "pypi"
    name: str
    version: str

    @property
    def purl(self) -> str:
        """Package URL (PURL) format"""
        return f"pkg:{self.ecosystem}/{self.name}@{self.version}"

    def __str__(self) -> str:
        return f"{self.name}=={self.version}"


class MaintainerInfo(BaseModel):
    """Information about a package maintainer"""

    username: str
    email: str | None = None
    profile_url: str | None = None
    account_created: datetime | None = None
    package_count: int | None = None


class PackageMetadata(BaseModel):
    """Core package metadata from registry"""

    identifier: PackageIdentifier
    description: str | None = None
    homepage: str | None = None
    repository: str | None = None
    license: str | None = None
    maintainers: list[MaintainerInfo] = []
    dependencies: list[str] = []
    first_release: datetime | None = None
    latest_release: datetime | None = None
    download_count: int | None = None


class Finding(BaseModel):
    """Individual finding from analysis"""

    id: str
    title: str
    description: str
    severity: RiskLevel
    evidence: list[str] = []
    references: list[str] = []
    remediation: str | None = None


class AnalysisResult(BaseModel):
    """Result from a single analyzer"""

    analyzer: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    risk_score: float = Field(ge=0.0, le=10.0)
    confidence: float = Field(ge=0.0, le=1.0)
    findings: list[Finding] = []
    raw_data: dict[str, Any] = {}


class VetReport(BaseModel):
    """Complete report from interrogator"""

    package: PackageIdentifier
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    overall_risk: RiskLevel
    risk_score: float
    confidence: float
    results: list[AnalysisResult] = []
    recommendations: list[str] = []


class SBOM(BaseModel):
    """Software Bill of Materials"""

    name: str
    version: str = "1.0.0"
    created: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    packages: list[PackageIdentifier] = []
    source: str | None = None  # e.g., "requirements.txt", "poetry.lock"


class Alert(BaseModel):
    """Watchdog alert"""

    id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    package: PackageIdentifier
    alert_type: str
    severity: RiskLevel
    title: str
    description: str
    evidence: dict[str, Any] = {}
    recommended_action: str | None = None


class CVSSScore(BaseModel):
    """CVSS v3.1 scoring data"""

    vector: str  # CVSS vector string
    base_score: float = Field(ge=0.0, le=10.0)
    temporal_score: float | None = Field(None, ge=0.0, le=10.0)
    environmental_score: float | None = Field(None, ge=0.0, le=10.0)
    severity: RiskLevel  # Derived from base score
    attack_vector: str | None = None  # NETWORK, ADJACENT, LOCAL, PHYSICAL
    attack_complexity: str | None = None  # LOW, HIGH
    privileges_required: str | None = None  # NONE, LOW, HIGH
    user_interaction: str | None = None  # NONE, REQUIRED
    scope: str | None = None  # UNCHANGED, CHANGED
    confidentiality_impact: str | None = None  # NONE, LOW, HIGH
    integrity_impact: str | None = None  # NONE, LOW, HIGH
    availability_impact: str | None = None  # NONE, LOW, HIGH


class Vulnerability(BaseModel):
    """CVE/vulnerability information"""

    id: str  # CVE ID or OSV ID
    summary: str
    details: str | None = None
    severity: RiskLevel
    cvss_score: CVSSScore | None = None
    affected_versions: list[str] = []  # Version ranges affected
    fixed_versions: list[str] = []  # Versions with fixes
    published: datetime | None = None
    modified: datetime | None = None
    references: list[str] = []
    database: str = "osv"  # osv, nvd, etc.
    exploit_available: bool = False
    patch_available: bool = False


class VulnerabilityResult(BaseModel):
    """Vulnerability analysis result"""

    package: PackageIdentifier
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    vulnerabilities: list[Vulnerability] = []
    total_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    risk_score: float = Field(ge=0.0, le=10.0)
    confidence: float = Field(ge=0.0, le=1.0)
    raw_data: dict[str, Any] = {}


class VulnerabilityReport(BaseModel):
    """Complete vulnerability report"""

    packages: list[VulnerabilityResult] = []
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AttackPattern(BaseModel):
    """Attack pattern definition"""

    id: str
    name: str
    description: str
    attack_type: str  # typosquat, account_takeover, dependency_confusion, malicious_update
    severity: RiskLevel
    indicators: list[str] = []  # Indicators of this attack pattern
    examples: list[str] = []  # Known examples
    detection_rules: dict[str, Any] = {}  # Rules for detection


class AttackHistory(BaseModel):
    """Historical attack record"""

    id: str
    package: PackageIdentifier
    attack_type: str
    detected_at: datetime
    pattern_id: str | None = None
    severity: RiskLevel
    description: str
    evidence: dict[str, Any] = {}
    source: str = "provchain"  # provchain, osv, github, etc.
    resolved: bool = False
    resolved_at: datetime | None = None


class AttackResult(BaseModel):
    """Attack detection result"""

    package: PackageIdentifier
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    attacks_detected: list[AttackHistory] = []
    risk_score: float = Field(ge=0.0, le=10.0)
    confidence: float = Field(ge=0.0, le=1.0)
    findings: list[Finding] = []
    raw_data: dict[str, Any] = {}


class AttackReport(BaseModel):
    """Complete attack analysis report"""

    package: PackageIdentifier
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    overall_risk: RiskLevel
    risk_score: float
    confidence: float
    attack_results: list[AttackResult] = []
    historical_attacks: list[AttackHistory] = []
    recommendations: list[str] = []
