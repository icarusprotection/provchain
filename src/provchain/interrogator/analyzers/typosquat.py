"""Typosquatting detection analyzer"""

import difflib
import unicodedata
from typing import Any

from provchain.data.models import AnalysisResult, Finding, PackageMetadata, RiskLevel
from provchain.interrogator.analyzers.base import BaseAnalyzer


class TyposquatAnalyzer(BaseAnalyzer):
    """Detects potential typosquatting attempts"""

    name = "typosquat"

    # Popular packages list (would be populated from PyPI stats in production)
    POPULAR_PACKAGES = [
        "requests",
        "numpy",
        "pandas",
        "flask",
        "django",
        "setuptools",
        "pip",
        "wheel",
        "urllib3",
        "certifi",
        "charset-normalizer",
        "idna",
        "python-dateutil",
        "pytz",
        "six",
        "pyyaml",
        "jinja2",
        "markupsafe",
        "click",
        "itsdangerous",
        "werkzeug",
        "gunicorn",
        "sqlalchemy",
        "psycopg2",
        "pillow",
        "matplotlib",
        "scipy",
        "scikit-learn",
        "tensorflow",
        "torch",
    ]

    POPULAR_PACKAGES_THRESHOLD = 10_000  # Weekly downloads

    def __init__(self, popular_packages: list[str] | None = None):
        """Initialize typosquat analyzer

        Args:
            popular_packages: Optional list of popular package names to check against.
                            If None, uses default list.
        """
        if popular_packages:
            self.popular_packages = set(popular_packages)
        else:
            self.popular_packages = set(self.POPULAR_PACKAGES)

    def levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def keyboard_proximity(self, char1: str, char2: str) -> bool:
        """Check if two characters are adjacent on QWERTY keyboard"""
        qwerty_layout = [
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
        ]

        pos1 = None
        pos2 = None

        for row_idx, row in enumerate(qwerty_layout):
            if char1.lower() in row:
                col_idx = row.index(char1.lower())
                pos1 = (row_idx, col_idx)
            if char2.lower() in row:
                col_idx = row.index(char2.lower())
                pos2 = (row_idx, col_idx)

        if pos1 and pos2:
            row_diff = abs(pos1[0] - pos2[0])
            col_diff = abs(pos1[1] - pos2[1])
            return row_diff <= 1 and col_diff <= 1

        return False

    def check_character_substitution(self, name: str, popular: str) -> bool:
        """Check for character substitution attacks (0/o, 1/l, rn/m)"""
        substitutions = {
            "0": "o",
            "o": "0",
            "1": "l",
            "l": "1",
            "rn": "m",
            "m": "rn",
        }

        # Check if name is popular name with substitutions
        test_name = name.lower()
        test_popular = popular.lower()

        for old, new in substitutions.items():
            if old in test_name and new in test_popular:
                # Check if they're similar after substitution
                modified_name = test_name.replace(old, new)
                if modified_name == test_popular:
                    return True

        return False

    def normalize_unicode(self, text: str) -> str:
        """Normalize Unicode to detect homoglyphs"""
        # Normalize to NFKD (decomposed form) to separate base characters from combining marks
        normalized = unicodedata.normalize("NFKD", text)
        # Remove combining marks (diacritics)
        ascii_text = "".join(c for c in normalized if unicodedata.category(c) != "Mn")
        return ascii_text.lower()

    def check_homoglyph(self, name: str, popular: str) -> bool:
        """Check for homoglyph attacks (Cyrillic а vs Latin a)"""
        # Normalize both strings to detect homoglyphs
        name_normalized = self.normalize_unicode(name)
        popular_normalized = self.normalize_unicode(popular)

        # Check if normalized versions are similar
        if name_normalized == popular_normalized and name != popular:
            # Same after normalization but different before - likely homoglyph attack
            return True

        # Also check visual similarity
        if len(name) == len(popular):
            similarity = difflib.SequenceMatcher(None, name.lower(), popular.lower()).ratio()
            if similarity > 0.85:
                # Check if they differ only in visually similar characters
                differences = sum(1 for c1, c2 in zip(name.lower(), popular.lower()) if c1 != c2)
                if differences <= 2:
                    return True
        return False

    def analyze(self, package_metadata: PackageMetadata) -> AnalysisResult:
        """Analyze package for typosquatting"""
        package_name = package_metadata.identifier.name.lower()
        findings = []
        risk_score = 0.0

        # Check against popular packages
        for popular in self.popular_packages:
            popular_lower = popular.lower()

            # Skip if it's the same package
            if package_name == popular_lower:
                continue

            # Levenshtein distance check
            distance = self.levenshtein_distance(package_name, popular_lower)
            if distance <= 2:
                risk_score = max(risk_score, 8.0 - (distance * 2))
                findings.append(
                    Finding(
                        id="typosquat_levenshtein",
                        title=f"Similar to popular package '{popular}'",
                        description=f"Package name '{package_metadata.identifier.name}' is very similar to popular package '{popular}' (Levenshtein distance: {distance})",
                        severity=RiskLevel.HIGH if distance == 1 else RiskLevel.MEDIUM,
                        evidence=[f"Levenshtein distance: {distance}", f"Popular package: {popular}"],
                        remediation="Verify this is the intended package and not a typosquatting attack",
                    )
                )

            # Keyboard proximity check
            if len(package_name) == len(popular_lower):
                differences = sum(
                    1 for i, (c1, c2) in enumerate(zip(package_name, popular_lower)) if c1 != c2
                )
                if differences <= 2:
                    # Check if differences are keyboard-adjacent
                    keyboard_adjacent = all(
                        self.keyboard_proximity(c1, c2)
                        for c1, c2 in zip(package_name, popular_lower)
                        if c1 != c2
                    )
                    if keyboard_adjacent:
                        risk_score = max(risk_score, 7.0)
                        findings.append(
                            Finding(
                                id="typosquat_keyboard",
                                title=f"Keyboard-adjacent to popular package '{popular}'",
                                description=f"Package name differs from '{popular}' by keyboard-adjacent characters",
                                severity=RiskLevel.HIGH,
                                evidence=[f"Popular package: {popular}"],
                                remediation="Verify this is the intended package",
                            )
                        )

            # Character substitution check
            if self.check_character_substitution(package_name, popular_lower):
                risk_score = max(risk_score, 9.0)
                findings.append(
                    Finding(
                        id="typosquat_substitution",
                        title=f"Character substitution attack on '{popular}'",
                        description=f"Package name appears to use character substitution to mimic '{popular}'",
                        severity=RiskLevel.CRITICAL,
                        evidence=[f"Popular package: {popular}"],
                        remediation="DO NOT INSTALL - This is likely a typosquatting attack",
                    )
                )

            # Homoglyph check (improved)
            if self.check_homoglyph(package_name, popular_lower):
                # Check if it's a known homoglyph pattern
                name_normalized = self.normalize_unicode(package_name)
                popular_normalized = self.normalize_unicode(popular_lower)
                if name_normalized == popular_normalized:
                    # Exact match after normalization - critical homoglyph attack
                    risk_score = max(risk_score, 9.5)
                    findings.append(
                        Finding(
                            id="typosquat_homoglyph_critical",
                            title=f"Critical homoglyph attack on '{popular}'",
                            description=f"Package name uses Unicode homoglyphs to exactly mimic '{popular}' after normalization",
                            severity=RiskLevel.CRITICAL,
                            evidence=[
                                f"Popular package: {popular}",
                                f"Normalized name: {name_normalized}",
                                f"Normalized popular: {popular_normalized}",
                            ],
                            remediation="DO NOT INSTALL - This is a homoglyph attack",
                        )
                    )
                else:
                    # Similar but not exact - high risk
                    risk_score = max(risk_score, 8.5)
                    findings.append(
                        Finding(
                            id="typosquat_homoglyph",
                            title=f"Homoglyph attack on '{popular}'",
                            description=f"Package name uses visually similar characters to '{popular}'",
                            severity=RiskLevel.HIGH,
                            evidence=[f"Popular package: {popular}"],
                            remediation="Verify character encoding and intended package",
                        )
                    )

            # Prefix/suffix additions
            if package_name.startswith(popular_lower) or package_name.endswith(popular_lower):
                if len(package_name) > len(popular_lower):
                    risk_score = max(risk_score, 6.0)
                    findings.append(
                        Finding(
                            id="typosquat_prefix_suffix",
                            title=f"Prefix/suffix addition to '{popular}'",
                            description=f"Package name adds prefix or suffix to popular package '{popular}'",
                            severity=RiskLevel.MEDIUM,
                            evidence=[f"Popular package: {popular}"],
                            remediation="Verify this is a legitimate fork or extension",
                        )
                    )

        confidence = self.get_confidence(findings)

        return AnalysisResult(
            analyzer=self.name,
            risk_score=min(risk_score, 10.0),
            confidence=confidence,
            findings=findings,
            raw_data={"checked_against": len(self.popular_packages)},
        )

