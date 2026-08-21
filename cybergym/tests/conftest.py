"""Shared cybergym test helpers: path bootstrap, constants, fixtures."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_DIR = Path(__file__).resolve().parents[1]
MODULE_ROOT = Path(__file__).resolve().parents[2]   # .../opencyberrl-modules
TASK_PY = MODULE_DIR / "tasks" / "task.py"
TESTDATA = MODULE_DIR / "testdata"

# The module lives in its own checkout while its tests run against the opencrl
# package from the core checkout, so make this repo's root importable no matter
# which directory pytest was invoked from.
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))


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


@pytest.fixture(scope="session")
def testdata() -> Path:
    """Directory of real CyberGym artifacts (error.txt, patch.diff, ...)."""
    return TESTDATA
