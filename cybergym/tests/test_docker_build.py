"""Real Docker integration for arvo:1065: vul+fix builds and the isolated
fix-container topology. Deselected by default; run with `pytest -m docker`.
Skips cleanly when no Docker daemon is reachable."""
from __future__ import annotations

import uuid

import pytest

from cybergym.builder import DOCKERFILE_FIX, DOCKERFILE_VUL, build_image, hf_url
from cybergym.builder.topology import container_ip, docker, split_topology

pytestmark = pytest.mark.docker

ARVO_1065 = "arvo:1065"
FUZZER = "magic_fuzzer"
BUILD_DIR = "file"          # the tarball's project subdir where build.sh runs
SANITIZER = "memory"        # arvo:1065 is a MemorySanitizer task

requires_docker = pytest.mark.skipif(
    docker("info").returncode != 0, reason="docker daemon not reachable"
)


@pytest.fixture(scope="module")
def images():
    """Build the real vulnerable and fixed images for arvo:1065."""
    tag = f"cybergym-1065-test-{uuid.uuid4().hex[:8]}"
    build_image(
        DOCKERFILE_VUL,
        f"{tag}:vul",
        repo_url=hf_url(ARVO_1065, "repo-vul.tar.gz"),
        fuzzer=FUZZER,
        sanitizer=SANITIZER,
        build_dir=BUILD_DIR,
    )
    build_image(
        DOCKERFILE_FIX,
        f"{tag}:fix",
        repo_url=hf_url(ARVO_1065, "repo-vul.tar.gz"),
        patch_url=hf_url(ARVO_1065, "patch.diff"),
        fuzzer=FUZZER,
        sanitizer=SANITIZER,
        build_dir=BUILD_DIR,
    )
    return f"{tag}:vul", f"{tag}:fix"


def _tcp_unreachable(src: str, dst_ip: str, port: int) -> bool:
    """Connect src -> dst_ip:port inside the src container; a timeout (exit
    124) means the packets are dropped, i.e. there is genuinely no route —
    as opposed to a connection refused, which any reachable host returns."""
    r = docker("exec", src, "bash", "-c",
               f"timeout 3 bash -c '</dev/tcp/{dst_ip}/{port}'")
    return r.returncode == 124


@requires_docker
def test_vul_image_builds_the_fuzzer(images) -> None:
    vul, _ = images
    assert docker("run", "--rm", vul, "test", "-x", f"/out/{FUZZER}").returncode == 0


@requires_docker
def test_fix_image_builds_the_fuzzer(images) -> None:
    _, fix = images
    assert docker("run", "--rm", fix, "test", "-x", f"/out/{FUZZER}").returncode == 0


@requires_docker
def test_fix_container_is_isolated_from_the_agent(images) -> None:
    vul, fix = images
    with split_topology(agent_image=vul, fix_image=fix, name="cybergym-isol") as topo:
        # Listeners on both containers: if the other side were reachable, the
        # connects below would succeed instead of timing out.
        listener = ("import socket; s = socket.socket(); s.bind(('', 9999)); "
                    "s.listen(1); s.accept()")
        assert docker("exec", "-d", topo.fix, "python3", "-c", listener).returncode == 0
        assert docker("exec", "-d", topo.agent, "python3", "-c", listener).returncode == 0

        # 1. No DNS: container names never resolve across the two networks.
        assert docker("exec", topo.agent, "getent", "hosts",
                      topo.fix_alias).returncode != 0

        # 2. No route by IP, agent -> fix ...
        assert _tcp_unreachable(topo.agent, container_ip(topo.fix), 9999)
        # 3. ... and fix -> agent.
        assert _tcp_unreachable(topo.fix, container_ip(topo.agent), 9999)

        # 4. The verifier still reaches the fix container via docker exec,
        #    which is host-level and ignores network topology.
        assert docker("exec", topo.fix, "test", "-x", f"/out/{FUZZER}").returncode == 0
