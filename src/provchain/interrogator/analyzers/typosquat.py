"""Typosquatting detection analyzer"""

import difflib
import json
import logging
import time
import unicodedata
from pathlib import Path

from provchain.data.models import AnalysisResult, Finding, PackageMetadata, RiskLevel
from provchain.interrogator.analyzers.base import BaseAnalyzer

logger = logging.getLogger(__name__)


class TyposquatAnalyzer(BaseAnalyzer):
    """Detects potential typosquatting attempts"""

    name = "typosquat"

    # Top ~250 most downloaded PyPI packages - reliable offline fallback
    POPULAR_PACKAGES = [
        # Core / packaging
        "pip",
        "setuptools",
        "wheel",
        "packaging",
        "build",
        "flit-core",
        "hatchling",
        "editables",
        "pathspec",
        "trove-classifiers",
        "calver",
        "hatch-vcs",
        "setuptools-scm",
        "cython",
        "poetry",
        "pipenv",
        # Networking / HTTP
        "requests",
        "urllib3",
        "certifi",
        "charset-normalizer",
        "idna",
        "httpx",
        "httpcore",
        "aiohttp",
        "aiosignal",
        "frozenlist",
        "multidict",
        "yarl",
        "async-timeout",
        "h11",
        "httptools",
        "requests-toolchain",
        # Data science / ML
        "numpy",
        "pandas",
        "pyarrow",
        "scipy",
        "scikit-learn",
        "matplotlib",
        "seaborn",
        "statsmodels",
        "plotly",
        "dash",
        "bokeh",
        "altair",
        "scikit-image",
        "opencv-python",
        "imageio",
        # Deep learning
        "tensorflow",
        "torch",
        "keras",
        "tensorboard",
        "absl-py",
        "grpcio-status",
        "markdown",
        "wrapt",
        "termcolor",
        "astunparse",
        "flatbuffers",
        "gast",
        "opt-einsum",
        "ml-dtypes",
        "jax",
        "jaxlib",
        "triton",
        "nvidia-cuda-runtime-cu12",
        "nvidia-cublas-cu12",
        "nvidia-cudnn-cu12",
        # NLP / Hugging Face
        "transformers",
        "tokenizers",
        "huggingface-hub",
        "safetensors",
        "datasets",
        "accelerate",
        "evaluate",
        "sentencepiece",
        "regex",
        # Web frameworks
        "flask",
        "django",
        "fastapi",
        "uvicorn",
        "starlette",
        "gunicorn",
        "uvloop",
        "watchfiles",
        "websockets",
        # Pydantic / validation
        "pydantic",
        "email-validator",
        # Templating / markup
        "jinja2",
        "markupsafe",
        "pygments",
        "docutils",
        "bleach",
        "webencodings",
        # CLI / terminal
        "click",
        "itsdangerous",
        "werkzeug",
        "colorama",
        "tqdm",
        "rich",
        # Serialization / parsing
        "pyyaml",
        "orjson",
        "lxml",
        "beautifulsoup4",
        "soupsieve",
        "html5lib",
        # Date / time
        "python-dateutil",
        "pytz",
        # Utilities
        "six",
        "decorator",
        "attrs",
        "more-itertools",
        "typing-extensions",
        "zipp",
        "importlib-metadata",
        "jaraco-classes",
        "filelock",
        "platformdirs",
        "distlib",
        "tomli",
        "exceptiongroup",
        "iniconfig",
        # Crypto / security
        "cryptography",
        "paramiko",
        "pycparser",
        "cffi",
        "pyasn1",
        "rsa",
        "oauthlib",
        "requests-oauthlib",
        # JSON / schema
        "jsonschema",
        "pyrsistent",
        "pyparsing",
        # Testing
        "pluggy",
        "pytest",
        "coverage",
        "tox",
        "nox",
        # Virtualenv
        "virtualenv",
        # Publishing
        "keyring",
        "pkginfo",
        "readme-renderer",
        "twine",
        # AWS
        "boto3",
        "botocore",
        "s3transfer",
        "awscli",
        # Google Cloud
        "grpcio",
        "protobuf",
        "googleapis-common-protos",
        "google-auth",
        "google-api-core",
        "google-cloud-core",
        "google-cloud-storage",
        "google-resumable-media",
        "google-crc32c",
        "proto-plus",
        "pyasn1-modules",
        "cachetools",
        "google-auth-oauthlib",
        # Databases
        "sqlalchemy",
        "psycopg2",
        "psycopg2-binary",
        "mysqlclient",
        "aiomysql",
        "asyncpg",
        "databases",
        "sqlmodel",
        "alembic",
        "mako",
        "greenlet",
        "redis",
        "pymongo",
        "motor",
        # Task queues
        "celery",
        "kombu",
        "billiard",
        "amqp",
        "vine",
        # Async
        "anyio",
        "sniffio",
        # Image
        "pillow",
        # Web scraping
        "scrapy",
        "selenium",
        "playwright",
        "pyppeteer",
        # Code quality
        "black",
        "isort",
        "flake8",
        "mypy",
        "pylint",
        "bandit",
        "pre-commit",
        "autopep8",
        "yapf",
        "rope",
        # Documentation
        "sphinx",
        "mkdocs",
        "pdoc",
        # DevOps / infra
        "invoke",
        "fabric",
        "ansible",
        "salt",
        "docker",
        "kubernetes",
        # Orchestration / data pipelines
        "airflow",
        "luigi",
        "prefect",
        "dagster",
        "dbt-core",
        "great-expectations",
        # Dashboards / apps
        "streamlit",
        "gradio",
        "panel",
        "voila",
        # Jupyter ecosystem
        "jupyter",
        "notebook",
        "jupyterlab",
        "ipython",
        "ipykernel",
        "nbconvert",
        "nbformat",
        "traitlets",
        "tornado",
        "pyzmq",
        # Math
        "networkx",
        "sympy",
        "mpmath",
        # Multipart / forms
        "python-multipart",
        # Pandas profiling
        "pandas-profiling",
    ]

    POPULAR_PACKAGES_THRESHOLD = 10_000  # Weekly downloads

    _CACHE_DIR = Path.home() / ".provchain"
    _CACHE_FILE = _CACHE_DIR / "popular_packages.json"
    _CACHE_MAX_AGE_SECONDS = 7 * 24 * 60 * 60  # 7 days
    _TOP_PACKAGES_URL = (
        "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
    )
    _MAX_PACKAGES = 5000

    def __init__(self, popular_packages: list[str] | None = None):
        """Initialize typosquat analyzer

        Args:
            popular_packages: Optional list of popular package names to check against.
                            If None, fetches top packages dynamically (with fallback
                            to the hardcoded list).
        """
        if popular_packages:
            self.popular_packages = set(popular_packages)
        else:
            fetched = self._fetch_popular_packages()
            if fetched:
                self.popular_packages = set(fetched)
            else:
                self.popular_packages = set(self.POPULAR_PACKAGES)

    @classmethod
    def _fetch_popular_packages(cls) -> list[str] | None:
        """Fetch top PyPI packages, using a disk cache to avoid repeated requests.

        Returns:
            List of package names or None on failure.
        """
        # Try reading from cache first
        try:
            if cls._CACHE_FILE.exists():
                raw = cls._CACHE_FILE.read_text(encoding="utf-8")
                cached = json.loads(raw)
                timestamp = cached.get("timestamp", 0)
                if time.time() - timestamp < cls._CACHE_MAX_AGE_SECONDS:
                    packages = cached.get("packages", [])
                    if packages:
                        logger.debug(
                            "Using cached popular packages list (%d packages)",
                            len(packages),
                        )
                        return list(packages)
        except Exception:
            logger.debug("Could not read popular-packages cache, will re-fetch")

        # Fetch from remote
        try:
            import urllib.request

            logger.info("Fetching top PyPI packages from %s", cls._TOP_PACKAGES_URL)
            req = urllib.request.Request(
                cls._TOP_PACKAGES_URL,
                headers={"User-Agent": "provchain"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            rows = data.get("rows", [])
            packages = [row["project"] for row in rows[: cls._MAX_PACKAGES] if "project" in row]

            if not packages:
                logger.warning("Fetched top-packages JSON but found no rows")
                return None

            # Write cache
            try:
                cls._CACHE_DIR.mkdir(parents=True, exist_ok=True)
                cls._CACHE_FILE.write_text(
                    json.dumps({"timestamp": time.time(), "packages": packages}),
                    encoding="utf-8",
                )
            except OSError as exc:
                logger.warning("Could not write popular-packages cache: %s", exc)

            logger.info("Loaded %d popular packages from PyPI stats", len(packages))
            return packages

        except Exception as exc:
            logger.warning(
                "Failed to fetch popular packages, falling back to hardcoded list: %s",
                exc,
            )
            return None

    def levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row: list[int] = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = list(current_row)

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
                        evidence=[
                            f"Levenshtein distance: {distance}",
                            f"Popular package: {popular}",
                        ],
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
