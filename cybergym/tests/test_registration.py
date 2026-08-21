"""Registration tests: synthetic index entries prove the family registers."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from opencrl import ScriptedModel, Task, rollout
from opencrl.task import discover, get_task, list_tasks


def _synthetic_index(task_id: str) -> str:
    """A one-entry index with all four levels onboarded."""
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


def test_synthetic_entry_registers_four_variants(registration, tmp_path):
    index = tmp_path / "index.yaml"
    index.write_text(_synthetic_index("synth-four"))

    names = registration.register_index(index)
    assert names == [f"cybergym_arvo_synth-four_l{n}" for n in range(4)]

    for name in names:
        assert name in list_tasks()
        t = get_task(name)
        assert isinstance(t, Task)
        assert t.name == name
        assert t.backend == "mock"
        assert t.dir == str(Path(registration.__file__).parent)


def test_registered_variant_rolls_out_on_mock_backend(registration, tmp_path):
    index = tmp_path / "index.yaml"
    index.write_text(_synthetic_index("synth-roll"))
    registration.register_index(index)
    task = get_task("cybergym_arvo_synth-roll_l2")
    result = rollout(task, ScriptedModel([
        {"role": "assistant", "content": "no exploit found", "tool_calls": None},
    ]))
    assert result.reward == 0.0  # placeholder reward until modules#3 lands


def test_placeholder_goal_and_reward_wiring(registration, tmp_path):
    index = tmp_path / "index.yaml"
    index.write_text(_synthetic_index("synth-reward"))

    registration.register_index(index)
    task = get_task("cybergym_arvo_synth-reward_l3")
    assert "placeholder" in task.goal.lower()
    assert callable(task.reward)
    assert task.reward(None) == 0.0


@pytest.mark.parametrize("text", ["", "tasks: []", "tasks:\n"])
def test_empty_index_registers_zero_tasks(registration, tmp_path, text):
    index = tmp_path / "index.yaml"
    index.write_text(text)
    assert registration.register_index(index) == []


def test_real_module_with_empty_index_imports_cleanly(registration):
    # registration fixture imported task.py against the real (empty) index
    assert registration.register_index(registration.INDEX_PATH) == []


def test_discover_imports_real_module_cleanly(module_dir):
    discover(module_dir)  # empty shipped index: no error, nothing registered


def test_discover_end_to_end_with_synthetic_index(module_dir, tmp_path):
    """A copied module dir with a synthetic index registers via discover()."""
    module = tmp_path / "cybergym"
    shutil.copytree(module_dir, module,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (module / "index.yaml").write_text(_synthetic_index("disc-synth"))

    discover(module)

    for n in range(4):
        name = f"cybergym_arvo_disc-synth_l{n}"
        assert name in list_tasks()
        assert get_task(name).backend == "mock"


def test_entry_with_partial_levels_registers_only_those(registration, tmp_path):
    index = tmp_path / "index.yaml"
    index.write_text("""
tasks:
  - id: synth-partial
    source: oss-fuzz
    project: synthproj
    language: c
    levels: [1, 3]
    provenance: {repo: https://example.com/synthproj}
""")

    assert registration.register_index(index) == [
        "cybergym_oss-fuzz_synth-partial_l1", "cybergym_oss-fuzz_synth-partial_l3"]
