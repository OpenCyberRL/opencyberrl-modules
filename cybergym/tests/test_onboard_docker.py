"""Real Docker integration for the onboarding of arvo:1065.

Two contracts, both against the real images: (1) the module's stored PoC
fixture crashes the vulnerable build and runs clean on the reference-patched
build — the property the whole module's validity rests on; (2) the
REGISTERED task's docker world (built from cybergym/builder/ by compose) and
its gated reward score that same differential end-to-end.

Deselected by default; run with `pytest -m docker`. Skips cleanly when no
Docker daemon is reachable.
"""
from __future__ import annotations

import base64

import pytest

import cybergym.onboard as ob
from conftest import MODULE_DIR, load_registration

pytestmark = pytest.mark.docker

# The crash identity the onboarding report recorded for arvo:1065 — the same
# dedup token as the OSS-Fuzz issue's ClusterFuzz log (derived from the top
# three frames of the crashing stack).
ARVO_1065_TOKEN = "match--file_softmagic--mget"


def _docker_available() -> bool:
    try:
        return ob.docker("info").returncode == 0
    except (OSError, RuntimeError):     # CLI missing, or daemon wedged
        return False


requires_docker = pytest.mark.skipif(not _docker_available(), reason="docker daemon not reachable")


def _ensure_image(dockerfile, tag: str, **kwargs) -> None:
    """Build the image through the module's builder unless it already exists."""
    if ob.docker("image", "inspect", tag).returncode != 0:
        ob.build_image(dockerfile, tag, **kwargs)


@pytest.fixture(scope="module")
def images():
    """The onboarding-built vul/fix images for arvo:1065 (rebuilt if absent)."""
    from cybergym.builder.build import DOCKERFILE_FIX, DOCKERFILE_VUL, hf_url

    spec = ob.TASKS["arvo:1065"]
    vul_tag, fix_tag = ob.image_tags(spec)
    common = dict(
        repo_url=hf_url(spec.task_id, "repo-vul.tar.gz"),
        fuzzer=spec.fuzzer,
        sanitizer=spec.sanitizer,
        build_dir=spec.build_dir,
        extra_pkgs=spec.extra_pkgs,
        base_image=spec.base_image,
        platform=spec.platform,
    )
    _ensure_image(DOCKERFILE_VUL, vul_tag, **common)
    _ensure_image(DOCKERFILE_FIX, fix_tag,
                  patch_url=hf_url(spec.task_id, "patch.diff"), **common)
    return vul_tag, fix_tag


@requires_docker
def test_contract_poc_crashes_vul_and_runs_clean_on_fix(images, module_dir) -> None:
    # The module's stored PoC (pocs/arvo-1065.poc) is the contract-test
    # fixture: on the built images it must reproduce the recorded MSan crash
    # on the vulnerable build and run clean on the reference-patched build.
    vul_tag, fix_tag = images
    poc = module_dir / "pocs" / "arvo-1065.poc"

    vul = ob.run_poc(vul_tag, poc, fuzzer="magic_fuzzer", platform="linux/amd64")
    signature = ob.crash_signature(vul.output)
    assert signature is not None, vul.output
    assert signature.family == "MemorySanitizer"
    assert ob.dedup_token(vul.output) == ARVO_1065_TOKEN

    fix = ob.run_poc(fix_tag, poc, fuzzer="magic_fuzzer", platform="linux/amd64")
    assert ob.crash_signature(fix.output) is None, fix.output


@requires_docker
def test_registered_world_and_reward_score_the_differential() -> None:
    # The registered variant's real wiring, end-to-end: compose builds the
    # world from cybergym/builder/ (vulnerable target the agent explores,
    # reference fix isolated on its own network), and the gated reward chain
    # verifies the differential through the world itself. The episode
    # contract (modules#4): the agent's PoC lives at /tmp/poc in the vul
    # container — seeded here the way an episode leaves it — so crash_vul
    # and clean_fix score 1.0. No /tmp/fix.patch was written, so the
    # patch_fixes stage honestly scores 0.0 without a rebuild.
    from opencrl import get_task
    from opencrl.backends.docker import Docker
    from opencrl.state import State
    from opencrl.task import load_world

    registration = load_registration()
    registration.register_index(registration.INDEX_PATH)
    task = get_task("cybergym_arvo_1065_l0")
    assert task.backend == "docker"

    backend = Docker()
    world = backend.up(load_world(task), task.caps)
    try:
        poc_b64 = base64.b64encode(
            (MODULE_DIR / "pocs" / "arvo-1065.poc").read_bytes()).decode()
        world.exec(f"echo {poc_b64} | base64 -d > /tmp/poc", host="vul")
        state = State(world=world, transcript=[], answer="")
        score = task.reward(state)
        assert score.stages == {"crash_vul": 1.0, "clean_fix": 1.0, "patch_fixes": 0.0}
        assert score.value == 0.5
    finally:
        backend.down(world)
