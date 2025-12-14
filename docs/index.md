# ProvChain Documentation

Welcome to ProvChain, the supply chain security platform for Python packages.

## Overview

ProvChain provides behavioral analysis, provenance verification, and continuous monitoring of software dependencies. Unlike tools that focus solely on known CVEs, ProvChain answers: "Should I trust this package at all?"

## Quick Start

```bash
# Install
pip install ProvChain

# Analyze a package
ProvChain vet requests

# Verify an artifact
ProvChain verify ./dist/mypackage.whl

# Generate SBOM
ProvChain sbom generate -r requirements.txt
```

## Features

- **Pre-Install Analysis**: Behavioral analysis, typosquatting detection, maintainer trust signals, vulnerability detection, and supply chain attack detection
- **Provenance Verification**: Hash verification, signature checking, reproducible builds
- **Continuous Monitoring**: Maintainer changes, repository monitoring, CVE alerts
- **Advanced Vulnerability Detection**: OSV.dev integration, CVSS v3.1 scoring, vulnerability prioritization
- **Supply Chain Attack Detection**: Account takeover detection, dependency confusion detection, malicious update detection

## Documentation

- [CLI Reference](cli-reference.md)
- [Configuration Guide](configuration.md)
- [Architecture Overview](architecture.md)
- [Vulnerability Detection](vulnerability-detection.md)
- [Attack Detection](attack-detection.md)
- [CI/CD Integration](ci-cd.md)

