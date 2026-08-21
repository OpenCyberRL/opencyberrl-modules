"""Shared cybergym test helpers: path constants and registration import."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_DIR = Path(__file__).resolve().parents[1]
TASK_PY = MODULE_DIR / "tasks" / "task.py"


def load_registration():
    """Import the registration file the way discover() does (by path)."""
    if "cybergym_registration" not in sys.modules:
        spec = importlib.util.spec_from_file_location("cybergym_registration", TASK_PY)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return sys.modules["cybergym_registration"]


@pytest.fixture
def registration():
    """The imported registration module (task.py exec'd by path)."""
    return load_registration()


@pytest.fixture
def module_dir() -> Path:
    """The cybergym module directory."""
    return MODULE_DIR
