# ProvChain

[![CI](https://github.com/ipf/provchain/workflows/CI/badge.svg)](https://github.com/ipf/provchain/actions/workflows/ci.yml)
[![Security](https://github.com/ipf/provchain/workflows/Security/badge.svg)](https://github.com/ipf/provchain/actions/workflows/security.yml)

**ProvChain** is an open-source Python supply chain security platform created by Icarus Protection that provides behavioral analysis, provenance verification, and continuous monitoring of software dependencies. Unlike existing tools that focus solely on known CVEs, ProvChain answers the harder question: "Should I trust this package at all?"

## Core Value Proposition

Trust verification across the entire dependency lifecycle before install, during build, and continuously after deployment.

## Features

- **Pre-Install Analysis (Interrogator)**: Behavioral analysis, typosquatting detection, maintainer trust signals, metadata quality checks, vulnerability detection, and supply chain attack detection
- **Provenance Verification (Verifier)**: Hash verification, Sigstore signatures, GPG signatures, and reproducible build checking
- **Continuous Monitoring (Watchdog)**: Maintainer change detection, repository monitoring, release analysis, and CVE alerts
- **Advanced Vulnerability Detection**: OSV.dev integration, CVSS v3.1 scoring, vulnerability prioritization, and patch availability detection
- **Supply Chain Attack Detection**: Account takeover detection, dependency confusion detection, malicious update detection, and historical attack pattern analysis

## Installation

```bash
pip install provchain
```

For behavioral analysis support (requires Docker):

```bash
pip install "provchain[behavioral]"
```

## Quick Start

### Check Version

```bash
# Check installed version
provchain --version
# or
provchain -v
```

### Basic Vetting

```bash
# Vet a single package
provchain vet requests

# Vet a specific version
provchain vet requests==2.31.0

# Vet all dependencies from requirements.txt
provchain vet -r requirements.txt

# Deep analysis (includes behavioral sandbox)
provchain vet --deep flask
```

### Verification

```bash
# Verify a local artifact
provchain verify ./dist/mypackage.whl

# Verify an installed package
provchain verify requests==2.31.0
```

### SBOM Management

```bash
# Generate SBOM from current environment
provchain sbom generate

# Generate from requirements.txt
provchain sbom generate -r requirements.txt -o sbom.json

# Import existing SBOM
provchain sbom import sbom.json
```

### Vulnerability Detection

```bash
# Scan requirements file for vulnerabilities
provchain vuln scan -r requirements.txt

# Check specific package for vulnerabilities
provchain vuln check requests==2.31.0

# Prioritize by severity (critical/high/medium/low)
provchain vuln prioritize -r requirements.txt --severity critical

# Output in JSON format
provchain vuln scan -r requirements.txt --format json
```

### Supply Chain Attack Detection

```bash
# Detect attacks for a package
provchain attack detect requests

# Show detailed attack information
provchain attack detect requests --detailed

# View attack history for a package
provchain attack history requests

# View attack history with custom limit
provchain attack history requests --limit 20
```

### Continuous Monitoring

```bash
# Start monitoring an SBOM
provchain watch --sbom sbom.json

# Run as background daemon
provchain watch --daemon

# Check monitoring status
provchain watch status
```

## Output Formats

ProvChain supports multiple output formats for CI/CD integration:

```bash
# JSON output
provchain vet requests --format json

# SARIF for GitHub Actions
provchain vet requests --format sarif

# Markdown report
provchain vet requests --format markdown
```

## CI/CD Integration

ProvChain is designed for CI/CD pipelines with exit codes and structured output:

```bash
# Exit with non-zero code if risk exceeds threshold
provchain vet -r requirements.txt --ci

# Custom threshold
provchain vet --ci --threshold medium
```

## Configuration

### Initialize Configuration

```bash
# Create default configuration file
provchain config init
```

### Set Configuration Values

```bash
# Set a string value
provchain config set general.threshold high

# Set a list value (JSON array format)
provchain config set general.analyzers '["typosquat", "maintainer"]'

# Set a boolean value
provchain config set behavior.enabled true

# Set an integer value
provchain config set general.cache_ttl 48
```

### View Configuration

```bash
# Show current configuration
provchain config show

# Validate configuration
provchain config validate
```

### Configuration File

The configuration file is located at `~/.provchain/config.toml`:

```toml
[general]
threshold = "medium"
analyzers = ["typosquat", "maintainer", "metadata", "install_hooks", "behavior"]
cache_ttl = 24

[behavior]
enabled = true
timeout = 60
network_policy = "monitor"

[watchdog]
check_interval = 60

[output]
format = "table"
verbosity = "normal"
color = true
```

## Requirements

- Python 3.10+
- 512MB RAM (minimum)
- 100MB disk space
- Docker (optional, for behavioral analysis)

## Design Principles

- **Offline-First**: Core functionality works without network; cloud features are additive
- **Zero Config Start**: `pip install provchain && provchain vet flask` works immediately
- **Privacy by Default**: No telemetry without opt-in; local analysis preferred
- **Extensible**: Plugin system for custom analyzers, reporters, and integrations
- **CI/CD Native**: Exit codes, JSON output, and SARIF support for automation

## License

Apache 2.0

## Contributing

Contributions are welcome! Please see our contributing guidelines for more information.

## Documentation

For detailed documentation, see:
- [CLI Reference](docs/cli-reference.md)
- [Vulnerability Detection](docs/vulnerability-detection.md)
- [Attack Detection](docs/attack-detection.md)
- [Configuration Guide](docs/configuration.md)
- [Architecture Overview](docs/architecture.md)
- [CI/CD Integration](docs/ci-cd.md)

## Links

<<<<<<< HEAD
- [Documentation](https://icarusprotection.com)
=======
- [Documentation](https://provchain.readthedocs.io)
>>>>>>> 57fa40531f7dcb3ef8807efc6a0fd8f581bca595
- [GitHub Repository](https://github.com/icarusprotection/provchain)
- [Issue Tracker](https://github.com/icarusprotection/provchain/issues)

