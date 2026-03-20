"""Plugin registry — discovery and DAG node construction.

``discover_plugins`` walks the vxis.plugins package tree and collects
every concrete BasePlugin subclass.  ``build_dag_from_plugins`` turns the
resulting registry into a dict of TaskNode objects ready for DAGExecutor.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from types import ModuleType
from typing import TYPE_CHECKING

from vxis.plugins.base import BasePlugin
from vxis.core.engine import TaskNode

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Plugin discovery
# ---------------------------------------------------------------------------


def discover_plugins(
    package_path: str = "vxis.plugins",
) -> dict[str, BasePlugin]:
    """Walk all submodules of *package_path* and collect BasePlugin subclasses.

    The function:
    1. Imports the top-level package.
    2. Recursively iterates over every sub-package and module using
       ``pkgutil.walk_packages``.
    3. Inspects every class in each module; keeps those that:
       - Are a subclass of ``BasePlugin``.
       - Are **not** ``BasePlugin`` itself (avoids registering the ABC).
       - Are **not** abstract (``inspect.isabstract`` check).
    4. Instantiates each concrete class and registers it by ``meta.name``.

    Duplicate names (last-found wins) are logged as warnings.

    Args:
        package_path: Dotted import path of the plugin package to scan.
                      Defaults to ``"vxis.plugins"``.

    Returns:
        Mapping of plugin name to instantiated plugin.
    """
    registry: dict[str, BasePlugin] = {}

    try:
        package: ModuleType = importlib.import_module(package_path)
    except ImportError:
        logger.warning(
            "Could not import plugin package '%s'. Registry will be empty.",
            package_path,
        )
        return registry

    package_root = getattr(package, "__path__", None)
    if package_root is None:
        logger.warning(
            "'%s' is not a package (no __path__). Registry will be empty.",
            package_path,
        )
        return registry

    for module_info in pkgutil.walk_packages(
        path=package_root,
        prefix=package_path + ".",
        onerror=lambda name: logger.warning("Error walking module '%s'.", name),
    ):
        try:
            module = importlib.import_module(module_info.name)
        except Exception:  # noqa: BLE001
            logger.warning(
                "Skipping module '%s': failed to import.",
                module_info.name,
                exc_info=True,
            )
            continue

        for _class_name, cls in inspect.getmembers(module, inspect.isclass):
            # Must be a proper subclass of BasePlugin (not BasePlugin itself).
            if cls is BasePlugin:
                continue
            if not issubclass(cls, BasePlugin):
                continue
            # Skip abstract classes that are not fully implemented yet.
            if inspect.isabstract(cls):
                continue

            try:
                instance: BasePlugin = cls()
                plugin_name = instance.meta.name
            except Exception:  # noqa: BLE001
                logger.warning(
                    "Could not instantiate plugin class '%s' from '%s'.",
                    cls.__name__,
                    module_info.name,
                    exc_info=True,
                )
                continue

            if plugin_name in registry:
                logger.warning(
                    "Duplicate plugin name '%s' (new: %s, existing: %s). "
                    "Overwriting with the most recently discovered class.",
                    plugin_name,
                    cls.__name__,
                    type(registry[plugin_name]).__name__,
                )

            registry[plugin_name] = instance
            logger.debug(
                "Registered plugin '%s' from '%s'.",
                plugin_name,
                module_info.name,
            )

    return registry


# ---------------------------------------------------------------------------
# DAG node construction
# ---------------------------------------------------------------------------


def build_dag_from_plugins(
    registry: dict[str, BasePlugin],
) -> dict[str, TaskNode]:
    """Build a dict of TaskNode objects from a plugin registry.

    Each node's ``depends_on``, ``optional_depends``, and ``timeout_seconds``
    are sourced directly from the plugin's ``PluginMeta``.

    Args:
        registry: Mapping returned by ``discover_plugins`` (or constructed
                  manually in tests).

    Returns:
        Mapping of plugin name to ``TaskNode``, ready for ``DAGExecutor``.
    """
    dag: dict[str, TaskNode] = {}

    for name, plugin in registry.items():
        meta = plugin.meta
        dag[name] = TaskNode(
            plugin_name=meta.name,
            depends_on=list(meta.depends_on),
            optional_depends=list(meta.optional_depends),
            timeout_seconds=meta.timeout_seconds,
        )

    return dag
