# Architecture Overview

## Components

### Interrogator

Pre-install analysis engine that evaluates packages before installation.

**Analyzers:**
- Typosquatting detection (enhanced with Unicode normalization and homoglyph detection)
- Maintainer trust analysis
- Metadata quality checks
- Install hook analysis
- Vulnerability detection (OSV.dev integration, CVSS scoring)
- Supply chain attack detection (account takeover, dependency confusion, malicious updates)
- Behavioral sandbox (optional)

### Verifier

Provenance verification engine that verifies package authenticity.

**Methods:**
- Hash verification
- Sigstore signatures
- GPG signatures
- Reproducible builds

### Watchdog

Continuous monitoring engine that tracks packages over time.

**Monitors:**
- Maintainer changes
- Repository changes
- New releases
- CVE alerts

## Data Flow

1. Package specification → Interrogator → Analysis results (including vulnerability and attack detection)
2. Artifact → Verifier → Verification results
3. SBOM → Watchdog → Alerts
4. Package → Vulnerability Scanner (OSV.dev) → Vulnerability report
5. Package → Attack Detector → Attack history and patterns

## Storage

- SQLite database for local storage
  - Package analysis cache
  - Attack history and patterns
  - Vulnerability data cache
  - Maintainer snapshots
- Caching layer for API responses (OSV.dev, PyPI, GitHub)
- Configuration file for settings

