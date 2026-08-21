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


def test_real_module_index_registers_the_onboarded_task(registration):
    # The shipped index carries the tasks cybergym.onboard accepted; the
    # first onboarded task (arvo:1065, modules#3) registers all four levels.
    assert registration.register_index(registration.INDEX_PATH) == [
        f"cybergym_arvo_1065_l{n}" for n in range(4)]


def test_onboarded_entry_gets_the_real_world_and_reward(registration, module_dir):
    # An entry written by cybergym.onboard (it carries its build recipe) is
    # wired with the real docker world built from cybergym/builder/ and the
    # gated reward from cybergym/lib/reward.py — not the placeholder.
    registration.register_index(registration.INDEX_PATH)
    task = get_task("cybergym_arvo_1065_l2")
    assert task.backend == "docker"
    assert "placeholder" not in task.goal.lower()
    assert "/out/magic_fuzzer" in task.goal and "/tmp/poc" in task.goal

    world = task.world
    assert world["x-opencrl"]["agent"] == "vul"
    assert set(world["services"]) == {"vul", "fix"}
    assert world["services"]["fix"]["networks"] == ["fixnet"]
    assert world["networks"] == {"fixnet": {}}
    for name, svc in world["services"].items():
        build = svc["build"]
        assert build["context"] == str(module_dir / "builder")
        assert build["dockerfile"] == f"Dockerfile.{name}"
        assert build["args"]["FUZZER"] == "magic_fuzzer"
        assert build["args"]["SANITIZER"] == "memory"
        assert svc["platform"] == "linux/amd64"
        expected_mount = f"{module_dir / 'pocs' / 'arvo-1065.poc'}:/tmp/poc"
        if name == "vul":    # the agent's own PoC goes to /tmp/poc; the
            expected_mount += ".ref"   # reference sits beside it, read-only
        assert f"{expected_mount}:ro" in svc["volumes"]
    # The reference patch is applied only in the fix image's build.
    assert "PATCH_URL" not in world["services"]["vul"]["build"]["args"]
    assert world["services"]["fix"]["build"]["args"]["PATCH_URL"].endswith(
        "/arvo/1065/patch.diff")

    # The reward is the gated three-stage chain from cybergym/lib with the
    # REAL rebuild runner wired (modules#4): the PoC crashes the vulnerable
    # build (stage 1) and runs clean on the isolated fix build (stage 2).
    # No /tmp/fix.patch was written, so patch_fixes honestly scores 0.0
    # without ever touching docker.
    class _State:
        def __init__(self, outputs):
            self._outputs = outputs

        def exec(self, cmd, host=None):
            return self._outputs.get(host or "vul", "")

        def file(self, path, host=None):
            return None

    crash = "WARNING: MemorySanitizer: use-of-uninitialized-value\n"
    score = task.reward(_State({"vul": crash, "fix": "Executed /tmp/poc"}))
    assert score.stages == {"crash_vul": 1.0, "clean_fix": 1.0, "patch_fixes": 0.0}
    assert score.value == 0.5


def test_synthetic_entries_stay_placeholders_alongside_the_onboarded_one(
        registration, tmp_path):
    # Mixed module: a not-yet-onboarded entry (no build recipe) keeps the
    # mock-backend placeholder even while an onboarded entry has the real
    # wiring — the module keeps installing while tasks wait for onboarding.
    index = tmp_path / "index.yaml"
    index.write_text(_synthetic_index("synth-mixed"))
    registration.register_index(index)
    task = get_task("cybergym_arvo_synth-mixed_l1")
    assert task.backend == "mock"
    assert "placeholder" in task.goal.lower()
    assert task.reward(None) == 0.0


def test_partial_recipe_entry_is_rejected(registration, tmp_path):
    # An entry with SOME onboarding keys but not all cannot silently
    # downgrade to the placeholder wiring — a typo'd or truncated onboard
    # entry fails validation loudly.
    index = tmp_path / "index.yaml"
    index.write_text("""
tasks:
  - id: synth-partial-recipe
    source: arvo
    project: synthproj
    language: c
    fuzzer: magic_fuzzer
    sanitizer: memory
    provenance: {repo: https://example.com/synthproj}
""")
    with pytest.raises(ValueError, match="missing.*build_dir.*poc"):
        registration.load_index(index)


def test_world_resolves_the_poc_against_the_index_it_came_from(
        registration, tmp_path, module_dir):
    # The PoC fixture path resolves against the index file's own directory,
    # not the registration file's module — a copied module tree (or a
    # synthetic index elsewhere) stays self-contained.
    import shutil

    module = tmp_path / "cybergym"
    shutil.copytree(module_dir, module,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc",
                                                  "reports"))
    registration.register_index(module / "index.yaml")
    task = get_task("cybergym_arvo_1065_l0")
    mount = task.world["services"]["vul"]["volumes"][0]
    assert mount == f"{module / 'pocs' / 'arvo-1065.poc'}:/tmp/poc.ref:ro"


def test_discover_imports_real_module_cleanly(module_dir):
    # discover() imports task.py against the real shipped index (which now
    # carries the onboarded arvo:1065 entry) without error.
    discover(module_dir)


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
