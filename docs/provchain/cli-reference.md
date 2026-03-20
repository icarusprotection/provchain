# CLI Reference

## Global Options

### --version, -v

Display version information and exit.

```bash
provchain --version
provchain -v
```

## Commands

### vet

Analyze package for security risks before installation.

```bash
ProvChain vet <package>
ProvChain vet -r requirements.txt
ProvChain vet --deep flask
ProvChain vet --format json requests
ProvChain vet --ci --threshold medium
```

### verify

Verify package artifact provenance.

```bash
ProvChain verify ./dist/mypackage.whl
ProvChain verify requests==2.31.0
```

### watch

Continuous monitoring of packages.

```bash
ProvChain watch --sbom sbom.json
ProvChain watch --daemon
ProvChain watch status
```

### vuln

Vulnerability detection and scanning using OSV.dev integration and CVSS v3.1 scoring.

#### scan

Scan a requirements file for vulnerabilities.

```bash
# Basic scan
provchain vuln scan -r requirements.txt

# Output to JSON file
provchain vuln scan -r requirements.txt --format json -o vulns.json

# Filter by severity
provchain vuln scan -r requirements.txt --severity critical

# Use different CVE database (future: NVD support)
provchain vuln scan -r requirements.txt --cve-db osv
```

**Options:**
- `-r, --requirements`: Requirements file path (required)
- `-f, --format`: Output format: `table`, `json`, `sarif`, `markdown` (default: `table`)
- `-o, --output`: Output file path (optional)
- `--severity`: Filter by severity: `critical`, `high`, `medium`, `low` (optional)
- `--cve-db`: CVE database: `osv`, `nvd` (default: `osv`)

**Exit Codes:**
- `0`: No critical vulnerabilities found
- `1`: Critical vulnerabilities detected

#### check

Check a specific package for vulnerabilities.

```bash
# Check specific version
provchain vuln check requests==2.31.0

# Check latest version
provchain vuln check requests

# JSON output
provchain vuln check requests --format json

# Filter by severity
provchain vuln check requests --severity high
```

**Options:**
- `-f, --format`: Output format: `table`, `json` (default: `table`)
- `--severity`: Filter by severity: `critical`, `high`, `medium`, `low` (optional)
- `--cve-db`: CVE database: `osv`, `nvd` (default: `osv`)

**Exit Codes:**
- `0`: No vulnerabilities found
- `1`: Vulnerabilities detected

#### prioritize

Prioritize vulnerabilities by severity level.

```bash
# Show only critical vulnerabilities
provchain vuln prioritize -r requirements.txt --severity critical

# Show high and critical
provchain vuln prioritize -r requirements.txt --severity high

# JSON output
provchain vuln prioritize -r requirements.txt --severity critical --format json
```

**Options:**
- `-r, --requirements`: Requirements file path (required)
- `--severity`: Minimum severity: `critical`, `high`, `medium`, `low` (default: `critical`)
- `-f, --format`: Output format: `table`, `json` (default: `table`)

### attack

Supply chain attack detection including account takeover, dependency confusion, malicious updates, and enhanced typosquatting.

#### detect

Detect supply chain attacks for a package.

```bash
# Basic detection
provchain attack detect requests

# Show detailed information
provchain attack detect requests --detailed

# JSON output
provchain attack detect requests --format json

# Check specific version
provchain attack detect requests==2.31.0 --detailed
```

**Options:**
- `-d, --detailed`: Show detailed attack information including evidence and remediation
- `-f, --format`: Output format: `table`, `json` (default: `table`)

**Detected Attack Types:**
- `typosquat`: Typosquatting attacks (enhanced with Unicode normalization)
- `account_takeover`: Unexpected maintainer changes
- `dependency_confusion`: Public packages mimicking private names
- `malicious_update`: Suspicious version jumps or changes

**Exit Codes:**
- `0`: No attacks detected
- `1`: Critical or high severity attacks detected

#### history

View attack history for a package.

```bash
# View recent attack history
provchain attack history requests

# View more records
provchain attack history requests --limit 20

# JSON output
provchain attack history requests --format json
```

**Options:**
- `-n, --limit`: Number of history records to show (default: `10`)
- `-f, --format`: Output format: `table`, `json` (default: `table`)

**History Information:**
- Detection timestamp
- Attack type
- Severity level
- Description and evidence
- Resolution status

### sbom

SBOM management.

```bash
ProvChain sbom generate -r requirements.txt -o sbom.json
ProvChain sbom import sbom.json
```

## Additional Resources

For more detailed information on specific features:

- [Vulnerability Detection Guide](vulnerability-detection.md) - Comprehensive guide to vulnerability scanning
- [Attack Detection Guide](attack-detection.md) - Detailed information on supply chain attack detection
- [Configuration Guide](configuration.md) - Complete configuration options
- [Architecture Overview](architecture.md) - System architecture and data flow

### config

Configuration management.

#### init

Initialize default configuration file.

```bash
provchain config init
```

#### set

Set a configuration value. Supports string, integer, boolean, and list types.

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

**Note:** For list values, use JSON array format. In PowerShell, use single quotes: `'["item1", "item2"]'`. In bash, use double quotes: `"[\"item1\", \"item2\"]"`.

#### show

Display current configuration.

```bash
provchain config show
```

#### validate

Validate the current configuration file.

```bash
provchain config validate
```

