"""Pytest fixtures for fork-owned Python (no package install required for argv_utils)."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Headless Qt for pytest-qt / PySide6 on Linux CI.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def pytest_configure(config: pytest.Config) -> None:
    gui = ROOT / "xyberpix-gui"
    if gui.is_dir() and str(gui) not in sys.path:
        sys.path.insert(0, str(gui))


@pytest.fixture
def ngit_path() -> Path:
    return ROOT / "ngit" / "ngit"


@pytest.fixture
def ngit_mod(ngit_path: Path):
    """Load the ngit CLI script as a module (extensionless file; stdlib only at import)."""
    path = str(ngit_path.resolve())
    loader = importlib.machinery.SourceFileLoader("ngit_under_test", path)
    spec = importlib.util.spec_from_loader("ngit_under_test", loader)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
