"""Database layer for ProvChain"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

from provchain.data.models import (
    SBOM,
    Alert,
    AttackHistory,
    AttackPattern,
    PackageIdentifier,
    RiskLevel,
    VetReport,
)

Base = declarative_base()


class PackageAnalysis(Base):
    """Package analysis cache table"""

    __tablename__ = "package_analyses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ecosystem = Column(String, nullable=False)
    name = Column(String, nullable=False)
    version = Column(String, nullable=False)
    analyzed_at = Column(DateTime, nullable=False)
    risk_score = Column(String, nullable=False)  # Store as string for precision
    risk_level = Column(String, nullable=False)
    report_json = Column(Text, nullable=False)

    __table_args__ = (
        Index("idx_package_analyses_lookup", "ecosystem", "name", "version"),
        {"sqlite_autoincrement": True},
    )


class SBOMRecord(Base):
    """SBOM tracking table"""

    __tablename__ = "sboms"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    source_path = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    sbom_json = Column(Text, nullable=False)

    packages = relationship("SBOMPackage", back_populates="sbom", cascade="all, delete-orphan")


class SBOMPackage(Base):
    """SBOM packages table for efficient querying"""

    __tablename__ = "sbom_packages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sbom_id = Column(Integer, ForeignKey("sboms.id", ondelete="CASCADE"), nullable=False)
    ecosystem = Column(String, nullable=False)
    name = Column(String, nullable=False)
    version = Column(String, nullable=False)

    sbom = relationship("SBOMRecord", back_populates="packages")

    __table_args__ = (Index("idx_sbom_packages_lookup", "ecosystem", "name"),)


class AlertRecord(Base):
    """Watchdog alerts table"""

    __tablename__ = "alerts"

    id = Column(String, primary_key=True)
    created_at = Column(DateTime, nullable=False)
    ecosystem = Column(String, nullable=False)
    package_name = Column(String, nullable=False)
    package_version = Column(String, nullable=True)
    alert_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    evidence_json = Column(Text, nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    __table_args__ = (Index("idx_alerts_unresolved", "resolved_at"),)


class MaintainerSnapshot(Base):
    """Maintainer history for change detection"""

    __tablename__ = "maintainer_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ecosystem = Column(String, nullable=False)
    package_name = Column(String, nullable=False)
    snapshot_at = Column(DateTime, nullable=False)
    maintainers_json = Column(Text, nullable=False)

    __table_args__ = (
        Index("idx_maintainer_snapshots_lookup", "ecosystem", "package_name", "snapshot_at"),
    )


class ConfigRecord(Base):
    """Configuration table"""

    __tablename__ = "config"

    key = Column(String, primary_key=True)
    value_json = Column(Text, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class AttackPatternRecord(Base):
    """Attack pattern definitions table"""

    __tablename__ = "attack_patterns"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    attack_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    indicators_json = Column(Text, nullable=True)
    examples_json = Column(Text, nullable=True)
    detection_rules_json = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)

    __table_args__ = (Index("idx_attack_patterns_type", "attack_type"),)


class AttackHistoryRecord(Base):
    """Attack history records table"""

    __tablename__ = "attack_history"

    id = Column(String, primary_key=True)
    ecosystem = Column(String, nullable=False)
    package_name = Column(String, nullable=False)
    package_version = Column(String, nullable=True)
    attack_type = Column(String, nullable=False)
    detected_at = Column(DateTime, nullable=False)
    pattern_id = Column(String, nullable=True)
    severity = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    evidence_json = Column(Text, nullable=True)
    source = Column(String, nullable=False, default="provchain")
    resolved = Column(String, nullable=False, default="false")  # Store as string for SQLite
    resolved_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("idx_attack_history_lookup", "ecosystem", "package_name", "detected_at"),
        Index("idx_attack_history_type", "attack_type"),
        Index("idx_attack_history_resolved", "resolved"),
    )


class Database:
    """Database manager for ProvChain"""

    def __init__(self, db_path: Path | str | None = None):
        if db_path is None:
            db_path = Path.home() / ".provchain" / "provchain.db"
        else:
            db_path = Path(db_path)

        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self.engine = create_engine(f"sqlite:///{db_path}", echo=False)
        self.Session = sessionmaker(bind=self.engine)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema"""
        Base.metadata.create_all(self.engine)

    def store_analysis(self, report: VetReport) -> None:
        """Store package analysis result"""
        session = self.Session()
        try:
            # Check if analysis exists
            existing = (
                session.query(PackageAnalysis)
                .filter_by(
                    ecosystem=report.package.ecosystem,
                    name=report.package.name,
                    version=report.package.version,
                )
                .first()
            )

            analysis_data = {
                "ecosystem": report.package.ecosystem,
                "name": report.package.name,
                "version": report.package.version,
                "analyzed_at": report.timestamp,
                "risk_score": str(report.risk_score),
                "risk_level": report.overall_risk.value,
                "report_json": report.model_dump_json(),
            }

            if existing:
                for key, value in analysis_data.items():
                    setattr(existing, key, value)
            else:
                session.add(PackageAnalysis(**analysis_data))

            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_analysis(self, ecosystem: str, name: str, version: str) -> VetReport | None:
        """Retrieve package analysis result"""
        session = self.Session()
        try:
            analysis = (
                session.query(PackageAnalysis)
                .filter_by(ecosystem=ecosystem, name=name, version=version)
                .first()
            )

            if analysis:
                return VetReport.model_validate_json(analysis.report_json)
            return None
        finally:
            session.close()

    def store_sbom(self, sbom: SBOM, source_path: str | None = None) -> int:
        """Store SBOM and return its ID"""
        session = self.Session()
        try:
            sbom_record = SBOMRecord(
                name=sbom.name,
                source_path=source_path,
                created_at=sbom.created,
                updated_at=datetime.now(timezone.utc),
                sbom_json=sbom.model_dump_json(),
            )
            session.add(sbom_record)
            session.flush()

            # Store packages
            for package in sbom.packages:
                session.add(
                    SBOMPackage(
                        sbom_id=sbom_record.id,
                        ecosystem=package.ecosystem,
                        name=package.name,
                        version=package.version,
                    )
                )

            session.commit()
            return sbom_record.id
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_sbom(self, sbom_id: int) -> SBOM | None:
        """Retrieve SBOM by ID"""
        session = self.Session()
        try:
            sbom_record = session.query(SBOMRecord).filter_by(id=sbom_id).first()
            if sbom_record:
                return SBOM.model_validate_json(sbom_record.sbom_json)
            return None
        finally:
            session.close()

    def store_alert(self, alert: Alert) -> None:
        """Store watchdog alert"""
        session = self.Session()
        try:
            alert_data = {
                "id": alert.id,
                "created_at": alert.timestamp,
                "ecosystem": alert.package.ecosystem,
                "package_name": alert.package.name,
                "package_version": alert.package.version,
                "alert_type": alert.alert_type,
                "severity": alert.severity.value,
                "title": alert.title,
                "description": alert.description,
                "evidence_json": json.dumps(alert.evidence) if alert.evidence else None,
            }

            existing = session.query(AlertRecord).filter_by(id=alert.id).first()
            if existing:
                for key, value in alert_data.items():
                    setattr(existing, key, value)
            else:
                session.add(AlertRecord(**alert_data))

            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_unresolved_alerts(self) -> list[Alert]:
        """Get all unresolved alerts"""
        session = self.Session()
        try:
            alerts = session.query(AlertRecord).filter_by(resolved_at=None).all()
            result = []
            for alert_record in alerts:
                alert_dict = {
                    "id": alert_record.id,
                    "timestamp": alert_record.created_at,
                    "package": PackageIdentifier(
                        ecosystem=alert_record.ecosystem,
                        name=alert_record.package_name,
                        version=alert_record.package_version or "",
                    ),
                    "alert_type": alert_record.alert_type,
                    "severity": alert_record.severity,
                    "title": alert_record.title,
                    "description": alert_record.description,
                    "evidence": (
                        json.loads(alert_record.evidence_json) if alert_record.evidence_json else {}
                    ),
                }
                result.append(Alert(**alert_dict))
            return result
        finally:
            session.close()

    def store_maintainer_snapshot(
        self, ecosystem: str, package_name: str, maintainers: list[dict[str, Any]]
    ) -> None:
        """Store maintainer snapshot"""
        session = self.Session()
        try:
            snapshot = MaintainerSnapshot(
                ecosystem=ecosystem,
                package_name=package_name,
                snapshot_at=datetime.now(timezone.utc),
                maintainers_json=json.dumps(maintainers),
            )
            session.add(snapshot)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_latest_maintainer_snapshot(
        self, ecosystem: str, package_name: str
    ) -> list[dict[str, Any]] | None:
        """Get latest maintainer snapshot"""
        session = self.Session()
        try:
            snapshot = (
                session.query(MaintainerSnapshot)
                .filter_by(ecosystem=ecosystem, package_name=package_name)
                .order_by(MaintainerSnapshot.snapshot_at.desc())
                .first()
            )

            if snapshot:
                return json.loads(snapshot.maintainers_json)
            return None
        finally:
            session.close()

    def store_attack_pattern(self, pattern: AttackPattern) -> None:
        """Store attack pattern definition"""
        session = self.Session()
        try:
            pattern_data = {
                "id": pattern.id,
                "name": pattern.name,
                "description": pattern.description,
                "attack_type": pattern.attack_type,
                "severity": pattern.severity.value,
                "indicators_json": json.dumps(pattern.indicators) if pattern.indicators else None,
                "examples_json": json.dumps(pattern.examples) if pattern.examples else None,
                "detection_rules_json": json.dumps(pattern.detection_rules)
                if pattern.detection_rules
                else None,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            }

            existing = session.query(AttackPatternRecord).filter_by(id=pattern.id).first()
            if existing:
                for key, value in pattern_data.items():
                    if key not in ["created_at"]:  # Don't update created_at
                        setattr(existing, key, value)
                existing.updated_at = datetime.now(timezone.utc)
            else:
                session.add(AttackPatternRecord(**pattern_data))

            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_attack_pattern(self, pattern_id: str) -> AttackPattern | None:
        """Get attack pattern by ID"""
        session = self.Session()
        try:
            pattern_record = session.query(AttackPatternRecord).filter_by(id=pattern_id).first()
            if pattern_record:
                return AttackPattern(
                    id=pattern_record.id,
                    name=pattern_record.name,
                    description=pattern_record.description,
                    attack_type=pattern_record.attack_type,
                    severity=RiskLevel(pattern_record.severity),
                    indicators=json.loads(pattern_record.indicators_json)
                    if pattern_record.indicators_json
                    else [],
                    examples=json.loads(pattern_record.examples_json)
                    if pattern_record.examples_json
                    else [],
                    detection_rules=json.loads(pattern_record.detection_rules_json)
                    if pattern_record.detection_rules_json
                    else {},
                )
            return None
        finally:
            session.close()

    def get_attack_patterns_by_type(self, attack_type: str) -> list[AttackPattern]:
        """Get all attack patterns of a specific type"""
        session = self.Session()
        try:
            pattern_records = (
                session.query(AttackPatternRecord).filter_by(attack_type=attack_type).all()
            )
            patterns = []
            for record in pattern_records:
                patterns.append(
                    AttackPattern(
                        id=record.id,
                        name=record.name,
                        description=record.description,
                        attack_type=record.attack_type,
                        severity=RiskLevel(record.severity),
                        indicators=json.loads(record.indicators_json)
                        if record.indicators_json
                        else [],
                        examples=json.loads(record.examples_json) if record.examples_json else [],
                        detection_rules=json.loads(record.detection_rules_json)
                        if record.detection_rules_json
                        else {},
                    )
                )
            return patterns
        finally:
            session.close()

    def store_attack_history(self, attack: AttackHistory) -> None:
        """Store attack history record"""
        session = self.Session()
        try:
            attack_data = {
                "id": attack.id,
                "ecosystem": attack.package.ecosystem,
                "package_name": attack.package.name,
                "package_version": attack.package.version,
                "attack_type": attack.attack_type,
                "detected_at": attack.detected_at,
                "pattern_id": attack.pattern_id,
                "severity": attack.severity.value,
                "description": attack.description,
                "evidence_json": json.dumps(attack.evidence) if attack.evidence else None,
                "source": attack.source,
                "resolved": "true" if attack.resolved else "false",
                "resolved_at": attack.resolved_at,
            }

            existing = session.query(AttackHistoryRecord).filter_by(id=attack.id).first()
            if existing:
                for key, value in attack_data.items():
                    setattr(existing, key, value)
            else:
                session.add(AttackHistoryRecord(**attack_data))

            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_attack_history(
        self, ecosystem: str, package_name: str, limit: int = 100
    ) -> list[AttackHistory]:
        """Get attack history for a package"""
        session = self.Session()
        try:
            attack_records = (
                session.query(AttackHistoryRecord)
                .filter_by(ecosystem=ecosystem, package_name=package_name)
                .order_by(AttackHistoryRecord.detected_at.desc())
                .limit(limit)
                .all()
            )

            attacks = []
            for record in attack_records:
                attacks.append(
                    AttackHistory(
                        id=record.id,
                        package=PackageIdentifier(
                            ecosystem=record.ecosystem,
                            name=record.package_name,
                            version=record.package_version or "",
                        ),
                        attack_type=record.attack_type,
                        detected_at=record.detected_at,
                        pattern_id=record.pattern_id,
                        severity=RiskLevel(record.severity),
                        description=record.description,
                        evidence=json.loads(record.evidence_json) if record.evidence_json else {},
                        source=record.source,
                        resolved=record.resolved == "true",
                        resolved_at=record.resolved_at,
                    )
                )
            return attacks
        finally:
            session.close()

    def check_attack_pattern(
        self, attack_type: str, package_name: str, evidence: dict[str, Any]
    ) -> AttackPattern | None:
        """Check if evidence matches any known attack pattern"""
        patterns = self.get_attack_patterns_by_type(attack_type)
        for pattern in patterns:
            # Simple matching - check if evidence contains pattern indicators
            if pattern.indicators:
                for indicator in pattern.indicators:
                    if indicator.lower() in str(evidence).lower():
                        return pattern
        return None
