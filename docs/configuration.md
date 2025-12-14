# Configuration Guide

ProvChain can be configured via a TOML configuration file at `~/.provchain/config.toml` or using the `config` command.

## Configuration File

```toml
[general]
threshold = "medium"
analyzers = ["typosquat", "maintainer", "metadata", "install_hooks", "vulnerability", "attack", "behavior"]
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

[integrations]
github_token = ""
pypi_token = ""
```

## Options

### general.threshold

Risk threshold for CI failures: `low`, `medium`, `high`, `critical`

### general.analyzers

List of analyzers to enable: `typosquat`, `maintainer`, `metadata`, `install_hooks`, `vulnerability`, `attack`, `behavior`

- `vulnerability`: Enable vulnerability detection using OSV.dev
- `attack`: Enable supply chain attack detection

### behavior.enabled

Enable Docker-based behavioral analysis (requires Docker)

### watchdog.check_interval

Check interval in minutes for continuous monitoring

## Using the Config Command

### Initialize Configuration

```bash
provchain config init
```

This creates a default configuration file at `~/.provchain/config.toml`.

### Set Configuration Values

You can update configuration values using the `config set` command:

```bash
# Set threshold
provchain config set general.threshold high

# Set analyzers list (JSON array format)
provchain config set general.analyzers '["typosquat", "maintainer"]'

# Set boolean values
provchain config set behavior.enabled true

# Set integer values
provchain config set general.cache_ttl 48
```

**List Values:** When setting list values, use JSON array format:
- PowerShell: `provchain config set general.analyzers '["typosquat", "maintainer"]'`
- Bash: `provchain config set general.analyzers "[\"typosquat\", \"maintainer\"]"`

**Validation:** The `config set` command validates values before saving:
- `general.threshold` must be one of: `low`, `medium`, `high`, `critical`
- `behavior.network_policy` must be one of: `allow`, `deny`, `monitor`
- `output.format` must be one of: `table`, `json`, `sarif`, `markdown`
- `output.verbosity` must be one of: `quiet`, `normal`, `verbose`

### View Configuration

```bash
# Show all configuration
provchain config show

# Validate configuration
provchain config validate
```

## Environment Variables

- `PROVCHAIN_GITHUB_TOKEN`: GitHub API token for increased rate limits

## Vulnerability Detection Settings

Vulnerability detection uses OSV.dev by default. The analyzer is automatically enabled when included in `general.analyzers`.

**Features:**
- Automatic CVE database queries via OSV.dev API
- CVSS v3.1 scoring and severity classification
- Patch availability detection
- Exploit availability indicators

## Attack Detection Settings

Attack detection analyzes packages for supply chain attack patterns. The analyzer is automatically enabled when included in `general.analyzers`.

**Detection Capabilities:**
- Account takeover detection (maintainer changes)
- Dependency confusion detection
- Malicious update detection (version jumps)
- Historical attack pattern matching
- Enhanced typosquatting detection

Attack history is stored in the local database and can be queried using `provchain attack history <package>`.

