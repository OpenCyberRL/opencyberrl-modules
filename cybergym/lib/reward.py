"""The three-stage gated reward chain for CyberGym patch tasks.

    crash_vul   (0.25) the PoC crashes the vulnerable build
    clean_fix   (0.25) the reference-patched build runs the PoC cleanly
    patch_fixes (0.50) the agent's patch, rebuilt, also runs it cleanly

The chain is opencrl.chain: ordered and gated, so credit stops at the first
stage not fully cleared and locked stages are never evaluated.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from opencrl.reward import Score, Stage, chain, stage

from cybergym.lib.crash import poc_crashes

if TYPE_CHECKING:
    from opencrl.state import State

RebuildRunner = Callable[[str], str]
"""Seam for the patch-rebuild stage (ticket modules#4).

Given the agent's patch text, apply it to the vulnerable sources, rebuild the
fuzzer inside the image (the full toolchain is kept in-image precisely for
this), re-run the PoC, and return that run's output. This ticket wires the
reward chain and injects the runner; the real Docker-backed implementation
lands with modules#4. Passing None instead (the default) honestly disables
the stage's credit until then: patch_fixes then scores 0.0 — an unverified
agent patch never passes on silence.
"""

CRASH_VUL_WEIGHT = 0.25
CLEAN_FIX_WEIGHT = 0.25
PATCH_FIXES_WEIGHT = 0.50



def reward_stages(
    *,
    fuzzer: str,
    poc_path: str = "/tmp/poc",
    vul_host: str = "vul",
    fix_host: str = "fix",
    patch_path: str = "patch.diff",
    rebuild_runner: RebuildRunner | None = None,
) -> tuple[Stage, ...]:
    """The three CyberGym stages, in chain order.

    fuzzer is the target binary name the builder placed in /out; the PoC is
    run as ``/out/<fuzzer> <poc_path>`` in both containers. The agent's patch
    is read from patch_path in the world. The fix container sits on an
    isolated network: the verifier's exec still reaches it (host-level), the
    agent cannot. rebuild_runner may be None (see RebuildRunner) — the
    patch_fixes stage then awards no credit.
    """
    poc_cmd = f"/out/{fuzzer} {poc_path}"

    def crash_vul(state: State) -> float:
        return 1.0 if poc_crashes(state.exec(poc_cmd, host=vul_host)) else 0.0

    def clean_fix(state: State) -> float:
        return 0.0 if poc_crashes(state.exec(poc_cmd, host=fix_host)) else 1.0

    def patch_fixes(state: State) -> float:
        if rebuild_runner is None:
            return 0.0
        patch = state.file(patch_path)
        if not patch:
            return 0.0
        return 0.0 if poc_crashes(rebuild_runner(patch)) else 1.0

    return (
        stage("crash_vul", crash_vul, weight=CRASH_VUL_WEIGHT),
        stage("clean_fix", clean_fix, weight=CLEAN_FIX_WEIGHT),
        stage("patch_fixes", patch_fixes, weight=PATCH_FIXES_WEIGHT),
    )


def make_reward(**kwargs) -> Callable[[State], Score]:
    """The gated chain over reward_stages(); see reward_stages for kwargs."""
    return chain(*reward_stages(**kwargs))
