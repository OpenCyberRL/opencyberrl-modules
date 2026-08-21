"""Differential verdict helpers over mock exec maps."""
from __future__ import annotations

from cybergym.lib.verdict import Differential, differential

MSAN_CRASH = """==14==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x590726 in match /src/file/src/softmagic.c:365:9
DEDUP_TOKEN: match--file_softmagic--mget
SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/file/src/softmagic.c:365:9
"""

CLEAN_RUN = """INFO: Seed: 1
/out/magic_fuzzer: Running 1 inputs 1 time(s) each.
Running: /tmp/poc
Executed /tmp/poc in 3 ms
"""

VUL_CMD = "docker exec cybergym-vul /out/magic_fuzzer /tmp/poc"
FIX_CMD = "docker exec cybergym-fix /out/magic_fuzzer /tmp/poc"


def test_healthy_task_crashes_vul_and_runs_fix_clean() -> None:
    exec_map = {VUL_CMD: MSAN_CRASH, FIX_CMD: CLEAN_RUN}
    assert differential(exec_map, vul_cmd=VUL_CMD, fix_cmd=FIX_CMD) == Differential(
        crash_vul=True, clean_fix=True
    )


def test_regression_poc_crashes_both() -> None:
    exec_map = {VUL_CMD: MSAN_CRASH, FIX_CMD: MSAN_CRASH}
    assert differential(exec_map, vul_cmd=VUL_CMD, fix_cmd=FIX_CMD) == Differential(
        crash_vul=True, clean_fix=False
    )


def test_wrong_poc_crashes_neither() -> None:
    exec_map = {VUL_CMD: CLEAN_RUN, FIX_CMD: CLEAN_RUN}
    assert differential(exec_map, vul_cmd=VUL_CMD, fix_cmd=FIX_CMD) == Differential(
        crash_vul=False, clean_fix=True
    )


def test_missing_command_output_is_clean() -> None:
    # A command absent from the map contributes no output: no crash evidence.
    assert differential({}, vul_cmd=VUL_CMD, fix_cmd=FIX_CMD) == Differential(
        crash_vul=False, clean_fix=True
    )


def test_missing_fix_output_keeps_crash_vul_true() -> None:
    exec_map = {VUL_CMD: MSAN_CRASH}
    assert differential(exec_map, vul_cmd=VUL_CMD, fix_cmd=FIX_CMD) == Differential(
        crash_vul=True, clean_fix=True
    )


def test_failed_exec_is_not_a_clean_run() -> None:
    # The failed-exec-vs-clean ambiguity: an exec that timed out produces a
    # sentinel with no crash evidence — it must NOT read as a clean run.
    exec_map = {VUL_CMD: MSAN_CRASH,
                FIX_CMD: "[opencrl: command timed out after 120s]"}
    assert differential(exec_map, vul_cmd=VUL_CMD, fix_cmd=FIX_CMD) == Differential(
        crash_vul=True, clean_fix=False
    )


def test_failed_exec_is_no_crash_evidence() -> None:
    exec_map = {VUL_CMD: "[cybergym: rebuild failed: pipeline exited 4]"}
    assert differential(exec_map, vul_cmd=VUL_CMD, fix_cmd=FIX_CMD) == Differential(
        crash_vul=False, clean_fix=True
    )
