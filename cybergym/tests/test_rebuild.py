"""The Docker rebuild runner: pipeline decisions and cache, docker mocked.

The real apply -> rebuild -> PoC-run pipeline is exercised end-to-end by the
docker-marked contract test (tests/test_contract.py); here docker() is
stubbed so these cover the decision logic: failure sentinels (a failed
rebuild must never read as a clean run), PoC transport, and the
patch-hash-keyed cache.
"""
from __future__ import annotations

import base64
import subprocess
from dataclasses import dataclass, field

import pytest

import cybergym.lib.rebuild as rb
from cybergym.lib.rebuild import (
    REBUILD_FAILED,
    docker_rebuild_runner,
    poc_read_command,
)

MSAN_CRASH = """==14==WARNING: MemorySanitizer: use-of-uninitialized-value
SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/file/src/softmagic.c:365:9
"""

CLEAN_RUN = "INFO: Seed: 1\nExecuted /tmp/poc in 3 ms\n"

PATCH = "--- a/x\n+++ b/x\n"
POC_BYTES = b"\x00\x01crash!"
POC_CMD = poc_read_command("/tmp/poc")
IMAGE = "opencrl-build-deadbeefcafe"
CONTAINER = "abc123"

NOISE = "mesg: ttyname failed: Inappropriate ioctl for device"


def _marked(poc: bytes) -> str:
    """The marker-delimited base64 the real command yields, wrapped in the
    login-shell stderr noise that State.exec combines into one stream."""
    b64 = base64.b64encode(poc).decode()
    return (f"{NOISE}\ncybergym-poc-begin\n{b64}\ncybergym-poc-end\n{NOISE}")


@dataclass
class FakeWorld:
    project: str = "opencrl-test"
    compose_file: str = "/tmp/compose.yml"


@dataclass
class FakeState:
    """Duck-typed State: serves the PoC base64, holds a docker-backed world."""

    world: object = None
    outputs: dict = field(default_factory=lambda: {(POC_CMD, "vul"): _marked(POC_BYTES)})
    files: dict = field(default_factory=dict)

    def exec(self, command: str, host: str | None = None) -> str:
        return self.outputs[(command, host)]

    def file(self, path: str, host: str | None = None) -> str | None:
        return self.files.get(path)


def poc_state(poc: bytes = POC_BYTES) -> FakeState:
    return FakeState(world=FakeWorld(),
                     outputs={(POC_CMD, "vul"): _marked(poc)})


@pytest.fixture
def docker_calls(monkeypatch):
    """Stub docker(); records every call and returns canned results."""
    calls: list[list[str]] = []
    results: dict[str, subprocess.CompletedProcess] = {
        "compose": subprocess.CompletedProcess([], 0, stdout=CONTAINER, stderr=""),
        "inspect": subprocess.CompletedProcess([], 0, stdout=IMAGE, stderr=""),
        "run": subprocess.CompletedProcess([], 0, stdout=CLEAN_RUN, stderr=""),
    }

    def fake_docker(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
        calls.append(list(args))
        return results[args[0]]

    monkeypatch.setattr(rb, "docker", fake_docker)
    return calls, results


def runner(**kwargs):
    return docker_rebuild_runner(fuzzer="magic_fuzzer", platform="linux/amd64",
                                 cache={}, **kwargs)


def run_args(calls):
    return next(args for args in calls if args[0] == "run")


# --- the pipeline's result routing ---------------------------------------------


def test_clean_rebuild_returns_the_poc_run_output(docker_calls) -> None:
    calls, results = docker_calls
    out = runner()(PATCH, poc_state())
    assert out == CLEAN_RUN
    args = run_args(calls)
    assert args[:4] == ["run", "--rm", "--platform", "linux/amd64"]
    mounts = [args[i + 1] for i, a in enumerate(args) if a == "-v"]
    assert [m.split(":")[1:] for m in mounts] == [["/tmp/fix.patch", "ro"],
                                                  ["/tmp/poc", "ro"]]
    assert IMAGE in args
    script = args[-1]
    assert "git apply /tmp/fix.patch" in script
    assert "patch -p1 -N" in script
    assert "build-step.sh" in script
    assert "exec /out/magic_fuzzer -runs=1 /tmp/poc" in script


def test_crashing_rebuild_returns_output_verbatim(docker_calls) -> None:
    calls, results = docker_calls
    results["run"] = subprocess.CompletedProcess([], 1, stdout=MSAN_CRASH, stderr="")
    out = runner()(PATCH, poc_state())
    assert out == MSAN_CRASH          # the stage's crash oracle sees the report


def test_apply_failure_returns_sentinel(docker_calls) -> None:
    calls, results = docker_calls
    results["run"] = subprocess.CompletedProcess(
        [], 3, stdout="", stderr="error: patch failed: src/funcs.c:27\n")
    out = runner()(PATCH, poc_state())
    assert out.startswith(REBUILD_FAILED)
    assert "patch failed" in out


def test_nonzero_exit_without_crash_report_is_a_sentinel(docker_calls) -> None:
    # A run that died without a sanitizer report is a failed run, not a
    # clean one — the same ambiguity verdict.py warns about.
    calls, results = docker_calls
    results["run"] = subprocess.CompletedProcess([], 2, stdout="segfault", stderr="")
    out = runner()(PATCH, poc_state())
    assert out.startswith(REBUILD_FAILED)


def test_pipeline_timeout_returns_sentinel(monkeypatch) -> None:
    def hung_docker(*args: str, timeout: float = 120):
        raise RuntimeError(f"docker {' '.join(args)} timed out after {timeout}s")

    monkeypatch.setattr(rb, "docker", hung_docker)
    out = runner()(PATCH, poc_state())
    assert out.startswith(REBUILD_FAILED)


# --- PoC retrieval and image resolution ----------------------------------------


def test_missing_agent_poc_returns_sentinel_without_rebuilding(docker_calls) -> None:
    calls, _ = docker_calls
    state = FakeState(world=FakeWorld(),
                      outputs={(POC_CMD, "vul"):
                               f"{NOISE}\nbase64: /tmp/poc: No such file or directory"})
    out = runner()(PATCH, state)
    assert out.startswith(REBUILD_FAILED)
    assert not any(args[0] == "run" for args in calls)


def test_unresolvable_service_image_returns_sentinel(docker_calls) -> None:
    calls, results = docker_calls
    results["compose"] = subprocess.CompletedProcess([], 1, stdout="",
                                                     stderr="no such service")
    out = runner()(PATCH, poc_state())
    assert out.startswith(REBUILD_FAILED)
    assert not any(args[0] == "run" for args in calls)


# --- the cache ------------------------------------------------------------------


def test_identical_rebuilds_hit_the_cache(docker_calls) -> None:
    calls, _ = docker_calls
    run = runner()
    first = run(PATCH, poc_state())
    second = run(PATCH, poc_state(POC_BYTES))     # fresh state, same bytes
    assert first == second == CLEAN_RUN
    assert sum(1 for a in calls if a[0] == "run") == 1


def test_different_patch_or_poc_rebuilds(docker_calls) -> None:
    calls, _ = docker_calls
    run = runner()
    run(PATCH, poc_state())
    run("--- a/y\n+++ b/y\n", poc_state())
    run(PATCH, poc_state(b"\x00other"))
    assert sum(1 for a in calls if a[0] == "run") == 3


def test_different_image_rebuilds(docker_calls) -> None:
    calls, results = docker_calls
    run = runner()
    run(PATCH, poc_state())
    results["inspect"] = subprocess.CompletedProcess([], 0,
                                                     stdout="opencrl-build-other",
                                                     stderr="")
    run(PATCH, poc_state())
    assert sum(1 for a in calls if a[0] == "run") == 2
