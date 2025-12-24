"""Install hook analyzer for setup.py/pyproject.toml"""

import ast
import re
from pathlib import Path

from provchain.data.models import AnalysisResult, Finding, PackageMetadata, RiskLevel
from provchain.interrogator.analyzers.base import BaseAnalyzer


class InstallHookAnalyzer(BaseAnalyzer):
    """Static analysis of setup.py, setup.cfg, and pyproject.toml"""

    name = "install_hooks"

    DANGEROUS_PATTERNS = [
        (r"exec\s*\(", "exec() call"),
        (r"eval\s*\(", "eval() call"),
        (r"__import__\s*\(", "__import__() call"),
        (r"subprocess\.", "subprocess usage"),
        (r"os\.system", "os.system() call"),
        (r"os\.popen", "os.popen() call"),
        (r"socket\.", "socket usage"),
        (r"urllib\.request", "urllib.request usage"),
        (r"requests\.", "requests usage"),
        (r"http\.client", "http.client usage"),
        (r"base64\.", "base64 encoding/decoding"),
        (r"pickle\.", "pickle usage"),
        (r"marshal\.", "marshal usage"),
    ]

    DANGEROUS_IMPORTS = [
        "socket",
        "urllib",
        "urllib2",
        "httplib",
        "http.client",
        "requests",
        "subprocess",
        "os.system",
        "os.popen",
        "shutil",
        "tempfile",
    ]

    def analyze_python_file(self, file_path: Path) -> list[Finding]:
        """Analyze Python file for dangerous patterns"""
        findings = []

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            # Pattern-based detection
            for pattern, description in self.DANGEROUS_PATTERNS:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[: match.start()].count("\n") + 1
                    # Create safe ID from pattern (extract replace operations outside f-string)
                    pattern_id = pattern.replace(r"\s*\(", "").replace(".", "_")
                    findings.append(
                        Finding(
                            id=f"install_hook_{pattern_id}",
                            title=f"Suspicious code: {description}",
                            description=f"Found {description} in {file_path.name} at line {line_num}",
                            severity=RiskLevel.HIGH,
                            evidence=[
                                f"File: {file_path.name}",
                                f"Line: {line_num}",
                                f"Pattern: {pattern}",
                            ],
                            remediation="Review install hooks for malicious code",
                        )
                    )

            # AST-based analysis for imports
            try:
                tree = ast.parse(content, filename=str(file_path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if any(dangerous in alias.name for dangerous in self.DANGEROUS_IMPORTS):
                                findings.append(
                                    Finding(
                                        id=f"install_hook_import_{alias.name}",
                                        title=f"Suspicious import: {alias.name}",
                                        description=f"Import of potentially dangerous module: {alias.name}",
                                        severity=RiskLevel.MEDIUM,
                                        evidence=[
                                            f"File: {file_path.name}",
                                            f"Import: {alias.name}",
                                        ],
                                        remediation="Verify that network/system access is necessary",
                                    )
                                )
                    elif isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            if node.func.id in ["exec", "eval", "__import__"]:
                                findings.append(
                                    Finding(
                                        id=f"install_hook_call_{node.func.id}",
                                        title=f"Dangerous function call: {node.func.id}",
                                        description=f"Call to dangerous function {node.func.id}()",
                                        severity=RiskLevel.CRITICAL,
                                        evidence=[f"File: {file_path.name}"],
                                        remediation="DO NOT INSTALL - Contains code execution",
                                    )
                                )
            except SyntaxError:
                # File has syntax errors, skip AST analysis
                pass

        except Exception:
            # File read failed, skip
            pass

        return findings

    def analyze_pyproject_toml(self, file_path: Path) -> list[Finding]:
        """Analyze pyproject.toml for suspicious build hooks"""
        findings = []

        try:
            import tomli

            with open(file_path, "rb") as f:
                data = tomli.load(f)

            # Check for custom build scripts or setup sections
            # These sections indicate custom build processes that may be suspicious
            # Note: "build-system" is a standard section (parsed as "build-system" key)
            # but "build" (without "-system") and "setup" are suspicious custom sections
            if "build" in data or "setup" in data:
                findings.append(
                    Finding(
                        id="install_hook_custom_build",
                        title="Custom build configuration",
                        description="pyproject.toml contains custom build or setup configuration",
                        severity=RiskLevel.LOW,
                        evidence=[f"File: {file_path.name}"],
                    )
                )

        except ImportError:
            # tomli not available, skip
            pass
        except Exception:
            # File read failed, skip
            pass

        return findings

    def analyze(self, package_metadata: PackageMetadata) -> AnalysisResult:
        """Analyze install hooks"""
        findings = []
        risk_score = 0.0
        package_name = package_metadata.identifier.name
        version = package_metadata.identifier.version

        # Fetch source distribution from PyPI
        try:
            import tarfile
            import tempfile
            import zipfile

            from provchain.integrations.pypi import PyPIClient
            from provchain.utils.network import HTTPClient

            with PyPIClient() as pypi:
                metadata = pypi.get_package_metadata(package_name, version)
                releases = metadata.get("releases", {}).get(version, [])

                # Find source distribution
                sdist = None
                for file_info in releases:
                    filename = file_info.get("filename", "")
                    if filename.endswith(".tar.gz") or filename.endswith(".zip"):
                        sdist = file_info
                        break

                if not sdist:
                    return AnalysisResult(
                        analyzer=self.name,
                        risk_score=0.0,
                        confidence=0.1,
                        findings=[],
                        raw_data={"note": "No source distribution available for analysis"},
                    )

                # Download and extract source distribution
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmp_path = Path(tmpdir)
                    sdist_url = sdist.get("url")

                    if not sdist_url:
                        return AnalysisResult(
                            analyzer=self.name,
                            risk_score=0.0,
                            confidence=0.1,
                            findings=[],
                            raw_data={"note": "Source distribution URL not available"},
                        )

                    # Download
                    with HTTPClient() as client:
                        response = client.get(sdist_url)
                        sdist_file = tmp_path / sdist["filename"]
                        sdist_file.write_bytes(response.content)

                    # Extract
                    extract_dir = tmp_path / "extracted"
                    extract_dir.mkdir()

                    if sdist_file.suffix == ".gz":
                        import tarfile

                        with tarfile.open(sdist_file, "r:gz") as tar:
                            # Validate tar members to prevent path traversal attacks
                            def safe_members(tar_file):
                                extract_path = Path(extract_dir).resolve()
                                for member in tar_file.getmembers():
                                    # Normalize path and check for directory traversal
                                    member_path = Path(member.name)
                                    # Check for absolute paths or parent directory references
                                    if member_path.is_absolute() or ".." in member_path.parts:
                                        continue
                                    # Resolve to ensure it's within extract directory
                                    resolved = (extract_path / member_path).resolve()
                                    try:
                                        resolved.relative_to(extract_path)
                                    except ValueError:
                                        # Path outside extract directory, skip
                                        continue
                                    yield member

                            tar.extractall(extract_dir, members=safe_members(tar))
                    elif sdist_file.suffix == ".zip":
                        import zipfile

                        with zipfile.ZipFile(sdist_file) as zipf:
                            # Validate zip members to prevent path traversal attacks
                            extract_path = Path(extract_dir).resolve()
                            for member in zipf.namelist():
                                # Normalize path and check for directory traversal
                                member_path = Path(member)
                                # Check for absolute paths or parent directory references
                                if member_path.is_absolute() or ".." in member_path.parts:
                                    continue
                                # Resolve to ensure it's within extract directory
                                resolved = (extract_path / member_path).resolve()
                                try:
                                    resolved.relative_to(extract_path)
                                except ValueError:
                                    # Path outside extract directory, skip
                                    continue
                                zipf.extract(member, extract_dir)

                    # Find extracted package directory
                    extracted_dirs = [d for d in extract_dir.iterdir() if d.is_dir()]
                    if not extracted_dirs:
                        return AnalysisResult(
                            analyzer=self.name,
                            risk_score=0.0,
                            confidence=0.1,
                            findings=[],
                            raw_data={"note": "Could not extract source distribution"},
                        )

                    package_dir = extracted_dirs[0]

                    # Analyze setup.py
                    setup_py = package_dir / "setup.py"
                    if setup_py.exists():
                        file_findings = self.analyze_python_file(setup_py)
                        findings.extend(file_findings)
                        risk_score += sum(
                            2.0
                            if f.severity == RiskLevel.CRITICAL
                            else 1.0
                            if f.severity == RiskLevel.HIGH
                            else 0.5
                            for f in file_findings
                        )

                    # Analyze pyproject.toml
                    pyproject_toml = package_dir / "pyproject.toml"
                    if pyproject_toml.exists():
                        toml_findings = self.analyze_pyproject_toml(pyproject_toml)
                        findings.extend(toml_findings)
                        risk_score += sum(0.5 for f in toml_findings)

                    # Analyze setup.cfg
                    setup_cfg = package_dir / "setup.cfg"
                    if setup_cfg.exists():
                        # Basic check for setup.cfg (could be enhanced)
                        pass

                    confidence = 0.8 if findings else 0.9

        except Exception as e:
            # Analysis failed, return low confidence result
            findings.append(
                Finding(
                    id="install_hooks_analysis_failed",
                    title="Install hooks analysis failed",
                    description=f"Could not analyze install hooks: {e}",
                    severity=RiskLevel.UNKNOWN,
                    evidence=[str(e)],
                )
            )
            confidence = 0.2

        return AnalysisResult(
            analyzer=self.name,
            risk_score=min(risk_score, 10.0),
            confidence=confidence,
            findings=findings,
            raw_data={"analyzed": len(findings) > 0},
        )
