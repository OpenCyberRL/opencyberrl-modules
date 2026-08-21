"""The Docker-backed rebuild runner for the patch_fixes reward stage.

The agent explores — and can tamper with — its live vulnerable container, so
its patch can never be verified in there. Instead this module spins a
DISPOSABLE container from the same vul image: its /src is pristine by
construction (straight from the image layers, not the agent's mutated
filesystem). The agent's patch and PoC are bind-mounted read-only, the patch
is applied (git apply — the tool Dockerfile.fix uses for the reference
patch — falling back to patch -p1), the image's own build-step.sh rebuilds
with sanitizers, and the agent's own PoC runs against the rebuilt fuzzer.
The run's combined output goes back to the reward stage, which scores it
with the usual crash oracle.

Failures are honest: a patch that does not apply, a build that breaks, or a
pipeline that times out returns a "[cybergym: rebuild failed ...]" sentinel
(via cybergym.lib.verdict.run_failed) — a failed rebuild never reads as a
clean run.

Identical rebuilds (same image, patch bytes, PoC bytes) are cached for the
life of the process, so re-scoring an episode — or a second episode with the
same patch — never pays the emulated rebuild twice.

Known accepted v1 limitation (modules#4): a patch that neuters the harness
(e.g. forcing an exit before the bug is reachable) runs "clean" and is not
yet detected.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import shlex
import tempfile
from collections.abc import Callable, MutableMapping
from pathlib import Path
from typing import TYPE_CHECKING

from cybergym.builder.topology import docker
from cybergym.lib.crash import poc_crashes
from cybergym.lib.verdict import CYBERGYM_FAILED

if TYPE_CHECKING:
    from opencrl.state import State

RebuildRunner = Callable[[str, "State"], str]

REBUILD_FAILED = CYBERGYM_FAILED + " rebuild failed"
"""Sentinel prefix every failed rebuild pipeline returns (see run_failed)."""

REBUILD_TIMEOUT = 1800.0
"""Whole-pipeline bound; emulated (Rosetta) rebuilds are slow, so be generous."""

_CACHE: dict[tuple[str, str, str], str] = {}
"""Process-wide rebuild cache: (image, patch sha256, poc sha256) -> output."""

_POC_MARK = "cybergym-poc"


def _container_script(fuzzer: str) -> str:
    """The apply -> rebuild -> run recipe executed inside the container.

    Exit codes: 3 the patch did not apply, 4 the rebuild failed, otherwise
    the fuzzer's own exit code (a crashing run exits nonzero — the caller
    tells a crash from a failure by the sanitizer report in the output, so
    a nonzero exit WITH a report is still the run's output, verbatim).
    """
    return "\n".join([
        "set -u",
        # Apply the agent's patch to the pristine tree. git apply first (the
        # same tool the fix image's build uses for the reference patch);
        # patch(1) -p1 as fallback for patches git rejects.
        "if ! (git apply /tmp/fix.patch || patch -p1 -N < /tmp/fix.patch); then",
        '    echo "patch did not apply" >&2; exit 3',
        "fi",
        # Rebuild with sanitizers exactly as the image was built. The build
        # log goes to a file and only its tail is printed on failure, so a
        # broken rebuild stays diagnosable without drowning the output.
        "if ! bash /usr/local/bin/build-step.sh > /tmp/rebuild.log 2>&1; then",
        "    tail -n 100 /tmp/rebuild.log >&2; exit 4",
        "fi",
        f"exec /out/{shlex.quote(fuzzer)} -runs=1 /tmp/poc",
    ])


def poc_read_command(poc_path: str) -> str:
    """The exec command that transports the agent's PoC out of the vul
    container: base64 between marker lines.

    State.exec returns combined stdout+stderr, and login shells on some
    images chatter on stderr ("mesg: ttyname failed: ...") — markers make
    the payload immune to that noise, wherever it interleaves.
    """
    return (f"echo {_POC_MARK}-begin; base64 -w0 {shlex.quote(poc_path)}; "
            f"echo; echo {_POC_MARK}-end")


def _read_agent_poc(state: "State", poc_path: str, vul_host: str) -> bytes | str:
    """The agent's PoC bytes from the vulnerable container.

    Crash inputs are binary and State.exec/read_file return text, so the
    bytes are base64'd inside the container before crossing the text
    boundary. Returns a failure sentinel when there is no readable PoC.
    """
    marked = state.exec(poc_read_command(poc_path), host=vul_host)
    match = re.search(rf"{_POC_MARK}-begin\n(.*?)\n{_POC_MARK}-end", marked, re.DOTALL)
    if not match:
        return (f"{REBUILD_FAILED}: no readable PoC at {poc_path} "
                f"in the {vul_host} container\n{marked}")
    try:
        return base64.b64decode(match.group(1).strip(), validate=True)
    except (binascii.Error, ValueError):
        return f"{REBUILD_FAILED}: corrupt PoC transport from {vul_host}\n{marked}"


def _service_image(world, service: str) -> str | None:
    """The image the compose service's running container was started from."""
    try:
        ps = docker("compose", "-p", world.project, "-f", world.compose_file,
                    "ps", "-q", service)
        container = ps.stdout.strip()
        if ps.returncode != 0 or not container:
            return None
        ins = docker("inspect", "-f", "{{.Config.Image}}", container)
    except (RuntimeError, OSError):    # CLI missing, wedged, timed out
        return None
    return ins.stdout.strip() or None


def _rebuild_and_run(image: str, patch: str, poc: bytes, *,
                     fuzzer: str, platform: str | None,
                     timeout: float) -> str:
    """One disposable apply -> rebuild -> PoC-run pipeline; its output."""
    with tempfile.TemporaryDirectory(prefix="cybergym-rebuild-") as tmp:
        patch_host = Path(tmp) / "fix.patch"
        patch_host.write_text(patch)
        poc_host = Path(tmp) / "poc"
        poc_host.write_bytes(poc)
        args = ["run", "--rm"]
        if platform:
            args += ["--platform", platform]
        args += ["-v", f"{patch_host}:/tmp/fix.patch:ro",
                 "-v", f"{poc_host}:/tmp/poc:ro",
                 image, "bash", "-c", _container_script(fuzzer)]
        try:
            result = docker(*args, timeout=timeout)
        except (RuntimeError, OSError) as exc:      # timed out / no docker CLI
            return f"{REBUILD_FAILED}: {exc}"
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0 and not poc_crashes(output):
        return f"{REBUILD_FAILED}: pipeline exited {result.returncode}\n{output}"
    return output


def docker_rebuild_runner(*, fuzzer: str, poc_path: str = "/tmp/poc",
                          vul_host: str = "vul", platform: str | None = None,
                          timeout: float = REBUILD_TIMEOUT,
                          cache: MutableMapping | None = None) -> RebuildRunner:
    """Build the real RebuildRunner (see cybergym.lib.reward) for one task.

    fuzzer, poc_path and vul_host mirror reward_stages' view of the world;
    platform must match the task's build platform (MSan images are
    linux/amd64-only). cache overrides the process-wide rebuild cache —
    tests inject a fresh mapping so cached results never leak between them.
    """
    cache = _CACHE if cache is None else cache

    def runner(patch: str, state: "State") -> str:
        poc = _read_agent_poc(state, poc_path, vul_host)
        if isinstance(poc, str):                    # a failure sentinel
            return poc
        image = _service_image(state.world, vul_host)
        if not image:
            return (f"{REBUILD_FAILED}: no running '{vul_host}' service "
                    f"container to rebuild from")
        key = (image, hashlib.sha256(patch.encode()).hexdigest(),
               hashlib.sha256(poc).hexdigest())
        if key not in cache:
            cache[key] = _rebuild_and_run(image, patch, poc, fuzzer=fuzzer,
                                          platform=platform, timeout=timeout)
        return cache[key]

    return runner
