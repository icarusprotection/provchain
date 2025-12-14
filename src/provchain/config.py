"""Configuration management"""

import copy
from pathlib import Path
from typing import Any

try:
    import tomli
except ImportError:
    try:
        import tomli as tomllib  # Python 3.11+
        tomli = tomllib
    except ImportError:
        tomli = None

try:
    import tomli_w
except ImportError:
    tomli_w = None


class Config:
    """Configuration manager"""

    DEFAULT_CONFIG = {
        "general": {
            "threshold": "medium",
            "analyzers": ["typosquat", "maintainer", "metadata", "install_hooks", "behavior"],
            "cache_ttl": 24,
        },
        "behavior": {
            "enabled": True,
            "timeout": 60,
            "network_policy": "monitor",
        },
        "watchdog": {
            "check_interval": 60,
        },
        "output": {
            "format": "table",
            "verbosity": "normal",
            "color": True,
        },
        "integrations": {
            "github_token": "",
            "pypi_token": "",
        },
    }

    def __init__(self, config_path: Path | None = None):
        if config_path is None:
            config_path = Path.home() / ".provchain" / "config.toml"
        self.config_path = config_path
        self.config: dict[str, Any] = copy.deepcopy(self.DEFAULT_CONFIG)
        self.load()

    def load(self) -> None:
        """Load configuration from file"""
        if self.config_path.exists():
            if tomli is None:
                # Fallback: can't load TOML, use defaults
                return

            try:
                with open(self.config_path, "rb") as f:
                    file_config = tomli.load(f)
                    # Merge with defaults
                    self._merge_config(self.config, file_config)
            except Exception:
                # File read failed, use defaults
                pass

        # Also check environment variables
        import os

        if os.getenv("PROVCHAIN_GITHUB_TOKEN"):
            self.config["integrations"]["github_token"] = os.getenv("PROVCHAIN_GITHUB_TOKEN")

    def _merge_config(self, base: dict[str, Any], override: dict[str, Any]) -> None:
        """Recursively merge configuration"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(section, {}).get(key, default)

    def set(self, section: str, key: str, value: Any) -> None:
        """Set configuration value"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value

    def save(self) -> None:
        """Save configuration to file"""
        if tomli_w is None:
            raise RuntimeError("tomli-w is required to save configuration files")

        # Validate before saving
        self.validate()

        # Ensure directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        # Write config to file
        with open(self.config_path, "wb") as f:
            tomli_w.dump(self.config, f)

    def validate(self) -> None:
        """Validate configuration values"""
        errors = []

        # Validate general.threshold
        threshold = self.config.get("general", {}).get("threshold", "medium")
        if threshold not in ["low", "medium", "high", "critical"]:
            errors.append(f"Invalid threshold value: {threshold}. Must be one of: low, medium, high, critical")

        # Validate general.analyzers
        analyzers = self.config.get("general", {}).get("analyzers", [])
        valid_analyzers = ["typosquat", "maintainer", "metadata", "install_hooks", "behavior"]
        if not isinstance(analyzers, list):
            errors.append("general.analyzers must be a list")
        else:
            for analyzer in analyzers:
                if analyzer not in valid_analyzers:
                    errors.append(f"Invalid analyzer: {analyzer}. Must be one of: {', '.join(valid_analyzers)}")

        # Validate general.cache_ttl
        cache_ttl = self.config.get("general", {}).get("cache_ttl", 24)
        if not isinstance(cache_ttl, int) or cache_ttl < 0:
            errors.append("general.cache_ttl must be a non-negative integer")

        # Validate behavior.enabled
        behavior_enabled = self.config.get("behavior", {}).get("enabled", True)
        if not isinstance(behavior_enabled, bool):
            errors.append("behavior.enabled must be a boolean")

        # Validate behavior.timeout
        behavior_timeout = self.config.get("behavior", {}).get("timeout", 60)
        if not isinstance(behavior_timeout, int) or behavior_timeout <= 0:
            errors.append("behavior.timeout must be a positive integer")

        # Validate behavior.network_policy
        network_policy = self.config.get("behavior", {}).get("network_policy", "monitor")
        if network_policy not in ["allow", "deny", "monitor"]:
            errors.append(f"Invalid network_policy: {network_policy}. Must be one of: allow, deny, monitor")

        # Validate watchdog.check_interval
        check_interval = self.config.get("watchdog", {}).get("check_interval", 60)
        if not isinstance(check_interval, int) or check_interval <= 0:
            errors.append("watchdog.check_interval must be a positive integer")

        # Validate output.format
        output_format = self.config.get("output", {}).get("format", "table")
        if output_format not in ["table", "json", "sarif", "markdown"]:
            errors.append(f"Invalid output format: {output_format}. Must be one of: table, json, sarif, markdown")

        # Validate output.verbosity
        verbosity = self.config.get("output", {}).get("verbosity", "normal")
        if verbosity not in ["quiet", "normal", "verbose"]:
            errors.append(f"Invalid verbosity: {verbosity}. Must be one of: quiet, normal, verbose")

        # Validate output.color
        color = self.config.get("output", {}).get("color", True)
        if not isinstance(color, bool):
            errors.append("output.color must be a boolean")

        if errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
            raise ValueError(error_msg)

