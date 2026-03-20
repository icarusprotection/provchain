"""Plugin loader and discovery"""

import importlib
import importlib.util
import inspect
import logging
from pathlib import Path

from provchain.plugins.interface import AnalyzerPlugin, ReporterPlugin

logger = logging.getLogger(__name__)


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
                                    analyzer_plugin = obj()
                                    self.analyzers[analyzer_plugin.name] = analyzer_plugin
                                elif issubclass(obj, ReporterPlugin) and obj != ReporterPlugin:
                                    reporter_plugin = obj()
                                    self.reporters[reporter_plugin.name] = reporter_plugin
                except Exception:
                    logger.warning("Failed to load plugin from %s", file_path, exc_info=True)

    def get_analyzer(self, name: str) -> AnalyzerPlugin | None:
        """Get analyzer plugin by name"""
        return self.analyzers.get(name)

    def get_reporter(self, name: str) -> ReporterPlugin | None:
        """Get reporter plugin by name"""
        return self.reporters.get(name)
