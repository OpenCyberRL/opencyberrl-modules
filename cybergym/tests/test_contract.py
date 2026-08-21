"""The modules#4 capstone: the first green contract test.

A scripted agent replays the REFERENCE PoC and the REFERENCE patch through
the real dockerized world — the full episode contract: it writes the PoC
bytes to /tmp/poc and the patch to /tmp/fix.patch in the vulnerable
container, exactly as the task goal instructs — and the gated reward chain
must award full credit: the PoC crashes the vulnerable build (crash_vul),
the reference-patched build runs it clean (clean_fix), and the agent's patch
applied to a PRISTINE copy of the vulnerable sources, rebuilt with
sanitizers, runs the agent's own PoC clean too (patch_fixes).

Budget: one emulated rebuild (docker run --platform linux/amd64 under
Rosetta, ~2-3 min on Apple Silicon).

Deselected by default; run with `pytest -m docker`. Skips cleanly when no
Docker daemon is reachable.
"""
from __future__ import annotations

import base64
import json

import pytest

import cybergym.onboard as ob
from conftest import MODULE_DIR, load_registration

pytestmark = pytest.mark.docker


def _docker_available() -> bool:
    try:
        return ob.docker("info").returncode == 0
    except (OSError, RuntimeError):     # CLI missing, or daemon wedged
        return False


requires_docker = pytest.mark.skipif(not _docker_available(), reason="docker daemon not reachable")


def _shell_step(step_id: str, command: str) -> dict:
    """One scripted assistant turn: a single shell tool call."""
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{"id": step_id, "type": "function",
                        "function": {"name": "shell",
                                     "arguments": json.dumps({"command": command})}}],
    }


@requires_docker
def test_reference_poc_and_patch_score_full_reward() -> None:
    from opencrl import get_task, rollout
    from opencrl.models import ScriptedModel

    registration = load_registration()
    registration.register_index(registration.INDEX_PATH)
    task = get_task("cybergym_arvo_1065_l0")
    assert task.backend == "docker"

    # The reference artifacts the onboarding report validated: the crashing
    # input and the fix. The agent replays both through the episode contract.
    poc_b64 = base64.b64encode(
        (MODULE_DIR / "pocs" / "arvo-1065.poc").read_bytes()).decode()
    patch_b64 = base64.b64encode(
        (MODULE_DIR / "reports" / "arvo-1065" / "patch.diff").read_bytes()).decode()

    model = ScriptedModel([
        _shell_step("1", f"echo {poc_b64} | base64 -d > /tmp/poc"),
        _shell_step("2", f"echo {patch_b64} | base64 -d > /tmp/fix.patch"),
        {"role": "assistant",
         "content": "Reproduced the MSan crash with my PoC at /tmp/poc and "
                    "wrote the fix to /tmp/fix.patch.",
         "tool_calls": None},
    ])
    result = rollout(task, model)
    assert result.reward == 1.0
    assert result.stages == {"crash_vul": 1.0, "clean_fix": 1.0, "patch_fixes": 1.0}
