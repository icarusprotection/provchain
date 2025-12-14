"""Plugin loader and discovery"""

import importlib
import importlib.util
import inspect
from pathlib import Path
from typing import Any

from provchain.plugins.interface import AnalyzerPlugin, ReporterPlugin


class PluginLoader:
    """Plugin discovery and loading"""

    def __init__(self, plugin_dirs: list[Path] | None = None):
        self.plugin_dirs = plugin_dirs or []
        self.analyzers: dict[str, AnalyzerPlugin] = {}
        self.reporters: dict[str, ReporterPlugin] = {}

    def discover_plugins(self) -> None:
        """Discover plugins in plugin directories"""
        for plugin_dir in self.plugin_dirs:
            if not plugin_dir.exists():
                continue

            # Look for Python files
            for file_path in plugin_dir.glob("*.py"):
                try:
                    module_name = file_path.stem
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)

                        # Find plugin classes
                        for name, obj in inspect.getmembers(module):
                            if inspect.isclass(obj):
                                if issubclass(obj, AnalyzerPlugin) and obj != AnalyzerPlugin:
                                    plugin = obj()
                                    self.analyzers[plugin.name] = plugin
                                elif issubclass(obj, ReporterPlugin) and obj != ReporterPlugin:
                                    plugin = obj()
                                    self.reporters[plugin.name] = plugin
                except Exception:
                    # Plugin load failed, skip
                    pass

    def get_analyzer(self, name: str) -> AnalyzerPlugin | None:
        """Get analyzer plugin by name"""
        return self.analyzers.get(name)

    def get_reporter(self, name: str) -> ReporterPlugin | None:
        """Get reporter plugin by name"""
        return self.reporters.get(name)

