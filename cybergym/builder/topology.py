"""The fix-container network topology.

The agent (and the vulnerable target it explores) share one docker network;
the fix container — which holds the reference solution — runs on a separate
network with no route to or from the agent. The verifier reaches it via
`docker exec`, which is host-level and ignores network topology.
"""
from __future__ import annotations

import subprocess
import uuid
from contextlib import contextmanager
from collections.abc import Iterator
from dataclasses import dataclass


def docker(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    """Run a docker CLI command and return the CompletedProcess — callers
    inspect returncode; the command's own failures (unknown flag, missing
    container) surface as a nonzero returncode rather than an exception.
    Raises RuntimeError if the command exceeds `timeout` seconds, and
    FileNotFoundError if the docker CLI itself is not installed."""
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True,
                              errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"docker {' '.join(args)} timed out after {timeout}s"
        ) from exc

@dataclass(frozen=True)
class SplitTopology:
    """A running agent-side container and fix container on separate networks."""

    agent_network: str
    fix_network: str
    agent: str          # container name
    fix: str            # container name
    fix_alias: str      # the fix container's alias inside its own network


def _create_network(name: str) -> None:
    r = docker("network", "create", name)
    if r.returncode != 0:
        raise RuntimeError(f"docker network create {name} failed: {r.stderr}")


def _run_container(name: str, image: str, network: str, alias: str) -> str:
    r = docker("run", "-d", "--name", name, "--network", network,
               "--network-alias", alias, image, "sleep", "infinity")
    if r.returncode != 0:
        raise RuntimeError(f"docker run {name} failed: {r.stderr}")
    return name


def container_ip(container: str) -> str:
    """The container's first network IP."""
    r = docker("inspect", "-f",
               "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
               container)
    if r.returncode != 0 or not r.stdout.strip():
        raise RuntimeError(f"no IP for container {container}: {r.stderr}")
    return r.stdout.strip()


@contextmanager
def split_topology(*, agent_image: str, fix_image: str, name: str) -> Iterator[SplitTopology]:
    """Run the agent-side and fix containers on two isolated networks.

    Tears everything down (containers first, then networks) on exit, best
    effort. The agent-side container is a stand-in for the agent's box; later
    tickets reuse this topology with the real agent image.
    """
    suffix = uuid.uuid4().hex[:8]
    agent_net = f"{name}-agent-net-{suffix}"
    fix_net = f"{name}-fix-net-{suffix}"
    agent = f"{name}-agent-{suffix}"
    fix = f"{name}-fix-{suffix}"

    _create_network(agent_net)
    try:
        _create_network(fix_net)
        try:
            _run_container(agent, agent_image, agent_net, alias="agentbox")
            _run_container(fix, fix_image, fix_net, alias="fixbox")
            yield SplitTopology(
                agent_network=agent_net,
                fix_network=fix_net,
                agent=agent,
                fix=fix,
                fix_alias="fixbox",
            )
        finally:
            docker("rm", "-f", agent)
            docker("rm", "-f", fix)
            docker("network", "rm", fix_net)
    finally:
        docker("network", "rm", agent_net)
