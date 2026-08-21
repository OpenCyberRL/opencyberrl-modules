"""Registration tests: synthetic index entries prove the family registers."""
from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

from opencrl import ScriptedModel, Task, rollout
import pytest
from opencrl.task import discover, get_task, list_tasks
MODULE_DIR = Path(__file__).resolve().parents[1]
TASK_PY = MODULE_DIR / "tasks" / "task.py"


def _registration():
    """Import the registration file the way discover() does (by path)."""
    if "cybergym_registration" not in sys.modules:
        spec = importlib.util.spec_from_file_location("cybergym_registration", TASK_PY)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return sys.modules["cybergym_registration"]


def _synthetic_index(task_id: str) -> str:
    return f"""
tasks:
  - id: {task_id}
    source: arvo
    project: synthproj
    language: python
    levels: [0, 1, 2, 3]
    provenance:
      repo: https://example.com/synthproj
      commit: deadbeef
"""


def test_synthetic_entry_registers_four_variants(tmp_path):
    reg = _registration()
    index = tmp_path / "index.yaml"
    index.write_text(_synthetic_index("synth-four"))

    names = reg.register_index(index)
    assert names == [f"cybergym_arvo_synth-four_l{n}" for n in range(4)]

    for name in names:
        assert name in list_tasks()
        t = get_task(name)
        assert isinstance(t, Task)
        assert t.name == name
        assert t.backend == "mock"
        assert t.dir == str(TASK_PY.parent)


def test_registered_variant_rolls_out_on_mock_backend(tmp_path):
    reg = _registration()
    index = tmp_path / "index.yaml"
    index.write_text(_synthetic_index("synth-roll"))

    reg.register_index(index)
    task = get_task("cybergym_arvo_synth-roll_l2")
    result = rollout(task, ScriptedModel([
        {"role": "assistant", "content": "no exploit found", "tool_calls": None},
    ]))
    assert result.reward == 0.0  # placeholder reward until modules#3 lands


def test_placeholder_reward_is_documented_zero(tmp_path):
    reg = _registration()
    index = tmp_path / "index.yaml"
    index.write_text(_synthetic_index("synth-reward"))

    reg.register_index(index)
    task = get_task("cybergym_arvo_synth-reward_l3")
    assert "placeholder" in task.goal.lower()
    assert callable(task.reward)


@pytest.mark.parametrize("text", ["", "tasks: []", "tasks:\n"])
def test_empty_index_registers_zero_tasks(tmp_path, text):
    reg = _registration()
    index = tmp_path / "index.yaml"
    index.write_text(text)
    assert reg.register_index(index) == []


def test_real_module_with_empty_index_imports_cleanly():
    reg = _registration()  # imports task.py against the real (empty) index
    assert reg.register_index(reg.INDEX_PATH) == []


def test_discover_imports_real_module_cleanly():
    discover(MODULE_DIR)  # empty shipped index: no error, nothing registered


def test_discover_end_to_end_with_synthetic_index(tmp_path):
    """A copied module dir with a synthetic index registers via discover()."""
    module = tmp_path / "cybergym"
    shutil.copytree(MODULE_DIR, module,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (module / "index.yaml").write_text(_synthetic_index("disc-synth"))

    discover(module)

    expected = [f"cybergym_arvo_disc-synth_l{n}" for n in range(4)]
    for name in expected:
        assert name in list_tasks()
        assert get_task(name).backend == "mock"


def test_entry_with_partial_levels_registers_only_those(tmp_path):
    reg = _registration()
    index = tmp_path / "index.yaml"
    index.write_text(f"""
tasks:
  - id: synth-partial
    source: oss-fuzz
    project: synthproj
    language: c
    levels: [1, 3]
    provenance: {{repo: https://example.com/synthproj}}
""")

    assert reg.register_index(index) == [
        "cybergym_oss-fuzz_synth-partial_l1", "cybergym_oss-fuzz_synth-partial_l3"]
