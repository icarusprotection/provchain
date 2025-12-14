# Supply Chain Attack Detection

ProvChain provides comprehensive supply chain attack detection to identify malicious packages and suspicious patterns.

## Overview

The attack detection system analyzes packages for various supply chain attack patterns including account takeovers, dependency confusion, malicious updates, and enhanced typosquatting detection.

## Features

- **Account Takeover Detection**: Identifies unexpected maintainer changes
- **Dependency Confusion Detection**: Detects public packages mimicking private package names
- **Malicious Update Detection**: Identifies suspicious version jumps and unusual changes
- **Enhanced Typosquatting**: Unicode normalization and homoglyph detection
- **Historical Pattern Matching**: Compares against known attack patterns
- **Attack History Tracking**: Maintains database of detected attacks

## Usage

### Detect Attacks

```bash
# Detect attacks for a package
provchain attack detect requests

# Show detailed attack information
provchain attack detect requests --detailed

# Output in JSON format
provchain attack detect requests --format json
```

### View Attack History

```bash
# View attack history for a package
provchain attack history requests

# View more history records
provchain attack history requests --limit 20

# Output in JSON format
provchain attack history requests --format json
```

## Attack Types

### Account Takeover

Detects when package maintainers change unexpectedly, which may indicate account compromise.

**Indicators:**
- Maintainer username changes
- Maintainer email changes
- Sudden changes without announcement
- New maintainers with suspicious profiles

**Example:**
```bash
provchain attack detect mypackage
# Detects: Maintainer change detected
# Previous maintainers: original_user
# Current maintainers: suspicious_user
```

### Dependency Confusion

Detects public packages that may be attempting to mimic private/internal package names.

**Indicators:**
- Package name suggests private/internal use
- Low download count
- Recently created package
- Name matches common private package patterns

**Example:**
```bash
provchain attack detect internal-corp-package
# Detects: Potential dependency confusion attack
# Evidence: Low download count, recently created, name suggests private package
```

### Malicious Update

Detects unusual version jumps or suspicious changes that may indicate malicious updates.

**Indicators:**
- Large version jumps (e.g., 1.0.0 → 2.0.0)
- Breaking changes without proper versioning
- Suspicious code changes
- Unusual release patterns

**Example:**
```bash
provchain attack detect mypackage==2.0.0
# Detects: Unusual version jump detected
# Previous version: 1.0.0
# Current version: 2.0.0
# Major jump: 1
```

### Enhanced Typosquatting

Improved typosquatting detection with Unicode normalization and homoglyph detection.

**Enhancements:**
- Unicode normalization to detect homoglyphs (Cyrillic а vs Latin a)
- Improved similarity algorithms
- Keyboard proximity detection
- Character substitution detection (0/o, 1/l, rn/m)

## Integration with Vet Command

Attack detection is automatically included when running `provchain vet`:

```bash
# Attack analysis is included in vet results
provchain vet requests

# The attack analyzer runs alongside other analyzers
provchain vet -r requirements.txt
```

## Attack History Database

Detected attacks are stored in a local SQLite database:

- **Location**: `~/.provchain/provchain.db`
- **Tables**: `attack_patterns`, `attack_history`
- **Retention**: Indefinite (can be cleared manually)

Attack history includes:
- Attack type
- Detection timestamp
- Severity level
- Evidence and indicators
- Resolution status

## Output Format

### Table Format (Default)

```
Attack Detection Results
Risk Score: 8.5/10
Confidence: 85%
Attacks Detected: 2

Attack Summary
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┓
┃ Attack Type     ┃ Severity ┃ Count   ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━┩
│ account_takeover│   HIGH   │    1    │
│ typosquat       │ CRITICAL │    1    │
└─────────────────┴──────────┴─────────┘

Detailed Findings:
  CRITICAL typosquat_homoglyph_critical: Critical homoglyph attack on 'requests'
    Package name uses Unicode homoglyphs to exactly mimic 'requests' after normalization
    Evidence: Normalized name: requests, Normalized popular: requests
    Remediation: DO NOT INSTALL - This is a homoglyph attack
```

## Configuration

Attack detection is enabled by default when `attack` is included in `general.analyzers`:

```toml
[general]
analyzers = ["typosquat", "maintainer", "metadata", "vulnerability", "attack"]
```

## Exit Codes

The `attack detect` command exits with:
- `0`: No attacks detected, or all attacks are resolved
- `1`: Critical or high severity attacks detected

This makes it suitable for CI/CD integration:

```bash
# Fail CI if attacks detected
provchain attack detect requests
```

