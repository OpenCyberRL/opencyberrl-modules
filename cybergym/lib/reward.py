"""The three-stage gated reward chain for CyberGym patch tasks.

    crash_vul   (0.25) the agent's PoC crashes the vulnerable build
    clean_fix   (0.25) the reference-patched build runs the PoC cleanly
    patch_fixes (0.50) the agent's patch, rebuilt, also runs it cleanly

The chain is opencrl.chain: ordered and gated, so credit stops at the first
stage not fully cleared and locked stages are never evaluated — the
expensive patch rebuild only ever runs when both PoC stages cleared.

The episode contract the agent is told about in the task goal: the PoC goes
to /tmp/poc in the vulnerable container (a reference crashing input is
mounted read-only at /tmp/poc.ref for reproduction), the patch to
/tmp/fix.patch. clean_fix always runs the REFERENCE PoC (the onboarded,
verified differential), not the agent's — it is the world's sanity baseline.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from opencrl.reward import Score, Stage, chain, stage

from cybergym.lib.crash import poc_crashes
from cybergym.lib.verdict import run_failed

if TYPE_CHECKING:
    from opencrl.state import State

RebuildRunner = Callable[[str, "State"], str]
"""Seam for the patch-rebuild stage; the real one lives in cybergym.lib.rebuild.

Given the agent's patch text and the finished episode's State, apply the
patch to a PRISTINE copy of the vulnerable sources (a fresh container from
the vul image — never the agent's live, mutated filesystem), rebuild with
sanitizers, run the agent's own PoC against the rebuilt fuzzer, and return
that run's output. The PoC is fetched from the vulnerable container through
State, so the runner needs no wiring-time knowledge of the episode. A
pipeline that fails before producing a run (patch did not apply, build
broke, run timed out) returns a "[cybergym: ..." failure sentinel — a failed
rebuild must never read as a clean run. Passing None instead honestly
disables the stage's credit: patch_fixes then scores 0.0 — an unverified
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
    patch_path: str = "/tmp/fix.patch",
    rebuild_runner: RebuildRunner | None = None,
) -> tuple[Stage, ...]:
    """The three CyberGym stages, in chain order.

    fuzzer is the target binary name the builder placed in /out; the PoC is
    run as ``/out/<fuzzer> <poc_path>`` in both containers — poc_path is the
    agent's PoC in the vulnerable container and the reference PoC mounted in
    the fix container. patch_path is where the agent wrote their unified
    diff. The fix container sits on an isolated network: the verifier's exec
    still reaches it (host-level), the agent cannot. rebuild_runner may be
    None (see RebuildRunner) — the patch_fixes stage then awards no credit.

    Failed-exec ambiguity (the caveat in cybergym.lib.verdict): state.exec
    reports a command that timed out as a sentinel string that carries no
    crash evidence and so would read as a clean run. Every stage treats a
    failure sentinel as its own failure — a run that never completed is
    neither crash evidence nor a clean run.
    """
    poc_cmd = f"/out/{fuzzer} {poc_path}"

    def crash_vul(state: State) -> float:
        out = state.exec(poc_cmd, host=vul_host)
        if run_failed(out):
            return 0.0
        return 1.0 if poc_crashes(out) else 0.0

    def clean_fix(state: State) -> float:
        out = state.exec(poc_cmd, host=fix_host)
        if run_failed(out):
            return 0.0
        return 0.0 if poc_crashes(out) else 1.0

    def patch_fixes(state: State) -> float:
        if rebuild_runner is None:
            return 0.0
        patch = state.file(patch_path)
        if not patch:
            return 0.0
        out = rebuild_runner(patch, state)
        if run_failed(out):
            return 0.0
        return 0.0 if poc_crashes(out) else 1.0

    return (
        stage("crash_vul", crash_vul, weight=CRASH_VUL_WEIGHT),
        stage("clean_fix", clean_fix, weight=CLEAN_FIX_WEIGHT),
        stage("patch_fixes", patch_fixes, weight=PATCH_FIXES_WEIGHT),
    )


def make_reward(**kwargs) -> Callable[[State], Score]:
    """The gated chain over reward_stages(); see reward_stages for kwargs."""
    return chain(*reward_stages(**kwargs))
