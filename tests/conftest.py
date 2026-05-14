"""Shared pytest helpers.

Tests in this package load individual modules from
``src/azure_functions_agents/`` in **isolation** via :mod:`importlib`
rather than importing the package itself.  Reason: the package
``__init__.py`` eagerly imports the whole API surface (``app``,
``runner``, ``sandbox``, …) which in turn pulls in heavy third-party
dependencies (``azure.functions``, ``copilot``, ``hyperlight_sandbox``,
``pydantic``, …).  Loading a single module in isolation lets the test
suite run with nothing more than ``pip install pytest`` — no project
install required, no venv with the full dependency closure.

When a future test legitimately needs the assembled package, switch
that test to a normal ``import azure_functions_agents.X`` and rely on
``pip install -e .[dev]`` to provide the deps.  The fixtures below stay
useful either way.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PKG_DIR = _REPO_ROOT / "src" / "azure_functions_agents"


def load_module_in_isolation(module_name: str, file_name: str) -> ModuleType:
    """Load ``src/azure_functions_agents/<file_name>`` as a standalone module.

    The loaded module is registered under ``module_name`` in
    ``sys.modules`` so internal references (logging name, etc.) work
    correctly, but it is NOT placed inside the ``azure_functions_agents``
    namespace — the package ``__init__.py`` is never executed.
    """
    path = _PKG_DIR / file_name
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"Could not build import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def load_package_in_isolation(
    package_name: str, subpackage_dir: str
) -> ModuleType:
    """Load ``src/azure_functions_agents/<subpackage_dir>/`` as a standalone package.

    Like :func:`load_module_in_isolation` but for subpackages (directories
    with an ``__init__.py``).  The package is registered under
    ``package_name`` in ``sys.modules`` and given a
    ``submodule_search_locations`` entry pointing at its own directory so
    ``from package_name import submodule`` works inside the loaded code
    without triggering the parent ``azure_functions_agents/__init__.py``.

    The parent ``azure_functions_agents/__init__.py`` pulls in heavy deps
    (``copilot``, ``hyperlight_sandbox``, …); subpackages that limit
    themselves to the stdlib (e.g. ``credentials/``) can be tested
    without paying that import cost.
    """
    pkg_path = _PKG_DIR / subpackage_dir
    init_py = pkg_path / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        package_name,
        init_py,
        submodule_search_locations=[str(pkg_path)],
    )
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"Could not build import spec for {init_py}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[package_name] = module
    spec.loader.exec_module(module)
    return module
