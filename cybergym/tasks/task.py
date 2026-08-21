"""Cybergym family registration: one task variant per onboarded index level.

``cybergym/index.yaml`` lists the CyberGym tasks onboarded into this module
(schema documented in ``cybergym/README.md``).  Importing this file — which
``opencrl`` does via ``discover()`` globbing ``<module>/*/task.py`` —
registers one task per onboarded difficulty level of every entry, named
``cybergym_<source>_<id>_l<N>``.

Entries written by the onboarding tool (``cybergym/onboard.py``) carry their
full build recipe (fuzzer, sanitizer, poc, ...) and get the REAL wiring: a
docker world built from the cybergym builders — the vulnerable target the
agent explores plus the reference fix on an isolated network — and the gated
three-stage reward from the cybergym reward library.  Entries without a
recipe are pre-onboarding placeholders: a valid Task on the mock backend
with a trivial zero reward, so the module keeps installing while tasks wait
for onboarding.

This file is exec'd by ``discover()`` as a standalone module (no package
context), so the index loader lives here too rather than in an importable
sibling module.
"""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from opencrl import Task, task
from opencrl.tools import shell
from cybergym.builder.build import DEFAULT_BASE_IMAGE, hf_url
from cybergym.lib.rebuild import docker_rebuild_runner
from cybergym.lib.reward import make_reward

MODULE = "cybergym"
SOURCES = ("arvo", "oss-fuzz")
MAX_LEVEL = 3
DEFAULT_LEVELS = tuple(range(MAX_LEVEL + 1))


# The episode contract (told to the agent in the task goal): the agent's
# PoC lives at /tmp/poc in the vulnerable container, their unified diff at
# /tmp/fix.patch. The reference PoC is mounted read-only at /tmp/poc.ref so
# level-0 agents can reproduce the crash before writing their own.
PATCH_PATH = "/tmp/fix.patch"
INDEX_PATH = Path(__file__).resolve().parent.parent / "index.yaml"
_BUILDER_DIR = Path(__file__).resolve().parent.parent / "builder"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
# Base keys every entry carries; the ONBOARDED keys are written only by
# cybergym.onboard's accept step and switch the entry to the real wiring.
_ENTRY_KEYS = frozenset({
    "id", "source", "project", "language", "levels", "provenance",
    "fuzzer", "sanitizer", "build_dir", "poc", "extra_pkgs", "base_image",
    "platform",
})
_ONBOARDED_KEYS = ("fuzzer", "sanitizer", "build_dir", "poc")


def _is_onboarded(entry: Mapping[str, Any]) -> bool:
    """An entry is fully onboarded when it carries its build recipe."""
    return all(key in entry for key in _ONBOARDED_KEYS)



def load_index(path: str | Path = INDEX_PATH) -> list[dict]:
    """Load and validate an index file, returning normalized entry dicts.

    An empty file, ``tasks:`` with no value, or ``tasks: []`` is a valid
    empty index (the module installs with zero tasks onboarded).
    """
    doc = yaml.safe_load(Path(path).read_text())
    if doc is None:
        doc = {}
    if not isinstance(doc, Mapping):
        raise ValueError(
            f"index must be a mapping with a 'tasks' list, got {type(doc).__name__}")
    raw = doc.get("tasks")
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise ValueError(f"'tasks' must be a list, got {type(raw).__name__}")
    entries = [_normalize_entry(item, i) for i, item in enumerate(raw)]
    counts = Counter(entry["id"] for entry in entries)
    dupes = sorted(task_id for task_id, n in counts.items() if n > 1)
    if dupes:
        raise ValueError(f"duplicate task id(s) in index: {', '.join(dupes)}")
    return entries


def _normalize_entry(raw: Any, i: int) -> dict:
    """Validate one raw index item and return it as a normalized dict."""
    where = f"tasks[{i}]"
    if not isinstance(raw, Mapping):
        raise ValueError(f"{where} must be a mapping, got {type(raw).__name__}")
    entry = dict(raw)
    for key in ("id", "source", "project", "language"):
        value = entry.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{where} needs a non-empty string {key!r}")
    unknown = sorted(set(entry) - _ENTRY_KEYS)
    if unknown:
        raise ValueError(f"{where} has unknown key(s): {', '.join(unknown)}")
    if not _ID_RE.match(entry["id"]):
        raise ValueError(
            f"{where} id {entry['id']!r} must match {_ID_RE.pattern}")
    if entry["source"] not in SOURCES:
        raise ValueError(
            f"{where} source must be one of {', '.join(SOURCES)}, "
            f"got {entry['source']!r}")
    entry["levels"] = _normalize_levels(entry.get("levels", list(DEFAULT_LEVELS)), where)
    provenance = entry.get("provenance")
    if not isinstance(provenance, Mapping):
        raise ValueError(f"{where} needs a 'provenance' mapping")
    repo = provenance.get("repo")
    if not isinstance(repo, str) or not repo.strip():
        raise ValueError(f"{where} needs provenance with a non-empty string 'repo'")
    entry["provenance"] = dict(provenance)
    onboarded = [key for key in _ONBOARDED_KEYS if key in entry]
    if onboarded and len(onboarded) != len(_ONBOARDED_KEYS):
        # A partial recipe cannot silently downgrade to the placeholder
        # wiring — a typo'd or truncated onboard entry must fail loudly.
        missing = [k for k in _ONBOARDED_KEYS if k not in entry]
        raise ValueError(
            f"{where} has onboarding key(s) {onboarded} but is missing "
            f"{missing}; entries carry the full build recipe or none of it")
    for key in onboarded:
        if not isinstance(entry[key], str) or not entry[key].strip():
            raise ValueError(f"{where} needs a non-empty string {key!r}")
    return entry


def _normalize_levels(raw: Any, where: str) -> list[int]:
    """Validate an onboarded-levels list: unique ints in 0..MAX_LEVEL, sorted."""
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"{where} needs a non-empty 'levels' list")
    for level in raw:
        if isinstance(level, bool) or not isinstance(level, int):
            raise ValueError(f"{where} has a non-integer level: {level!r}")
        if not 0 <= level <= MAX_LEVEL:
            raise ValueError(f"{where} level {level} out of range 0..{MAX_LEVEL}")
    if len(set(raw)) != len(raw):
        raise ValueError(f"{where} has duplicate levels: {raw!r}")
    return sorted(raw)


def variant_name(entry: Mapping[str, Any], level: int) -> str:
    """Variant task name: ``cybergym_<source>_<id>_l<N>``."""
    return f"{MODULE}_{entry['source']}_{entry['id']}_l{level}"


def group_index(entries: Sequence[Mapping[str, Any]]) -> list[dict]:
    """Map load_index() entries to core group-index dicts.

    The output feeds ``opencrl.groups.resolve_group``: one dict per variant,
    each shaped ``{"name": ..., "module": "cybergym", "project": ...,
    "level": ...}``.
    """
    return [
        {
            "name": variant_name(entry, level),
            "module": MODULE,
            "project": entry["project"],
            "level": level,
        }
        for entry in entries
        for level in entry["levels"]
    ]

def _placeholder_reward() -> Any:
    """Trivial zero reward for pre-onboarding placeholder entries."""

    def reward(state: Any) -> float:
        return 0.0

    return reward


def _build_world(entry: Mapping[str, Any], index_dir: Path) -> dict:
    """The compose world for an onboarded entry.

    ``vul`` is the vulnerable target the agent explores (sources and
    toolchain in place; the reference PoC is mounted read-only at
    /tmp/poc.ref and the agent's own PoC goes to /tmp/poc); ``fix`` is the
    same sources plus the reference patch, on its own network so the agent
    cannot reach the reference solution. The patch-rebuild stage does NOT
    recompile in here — it spins a disposable container from the vul image
    (cybergym.lib.rebuild). Both images are built from the module's own
    builder templates, so the world is reproducible from a fresh checkout.
    The backend renders every network
    internal (Caps.needs_internet=False). index_dir is the directory of the
    index file the entry came from — the PoC fixture path resolves against
    it, so a copied module tree stays self-contained.
    """
    task_id = f"{entry['source']}:{entry['id']}"
    args = {
        "REPO_URL": hf_url(task_id, "repo-vul.tar.gz"),
        "FUZZER": entry["fuzzer"],
        "SANITIZER": entry["sanitizer"],
        "BUILD_DIR": entry["build_dir"],
        "EXTRA_PKGS": entry.get("extra_pkgs", ""),
        "BASE_IMAGE": entry.get("base_image", DEFAULT_BASE_IMAGE),
    }
    poc = str(index_dir / entry["poc"])
    services = {
        "vul": {
            "build": {"context": str(_BUILDER_DIR),
                      "dockerfile": "Dockerfile.vul", "args": args},
            "volumes": [f"{poc}:/tmp/poc.ref:ro"],
        },
        "fix": {
            "build": {"context": str(_BUILDER_DIR),
                      "dockerfile": "Dockerfile.fix",
                      "args": {**args,
                               "PATCH_URL": hf_url(task_id, "patch.diff")}},
            "volumes": [f"{poc}:/tmp/poc:ro"],
            "networks": ["fixnet"],
        },
    }
    if entry.get("platform"):
        for svc in services.values():
            svc["platform"] = entry["platform"]
    return {
        "x-opencrl": {"agent": "vul"},
        "services": services,
        "networks": {"fixnet": {}},
    }


def _build_task(entry: Mapping[str, Any], level: int,
                index_dir: Path) -> Task:
    """Build one variant: real docker world + gated reward once onboarded,
    placeholder on the mock backend before that."""
    if not _is_onboarded(entry):
        return Task(
            goal=(
                f"Cybergym task {entry['id']} ({entry['source']}/{entry['project']}, "
                f"difficulty l{level}). Skeleton placeholder: the real world and goal "
                f"arrive with the cybergym builders."
            ),
            reward=_placeholder_reward(),
            world=None,
            backend="mock",
        )
    return Task(
        goal=(
            f"Cybergym task {entry['id']} ({entry['source']}/{entry['project']}, "
            f"{entry['language']}, {entry['sanitizer']} sanitizer, difficulty "
            f"l{level}): the fuzzer harness /out/{entry['fuzzer']} has a bug; "
            f"a reference input that triggers it is mounted read-only at "
            f"/tmp/poc.ref. Write a PoC reproducing the crash to /tmp/poc, "
            f"then a unified diff fixing the bug to {PATCH_PATH}. Your patch "
            f"is verified by rebuilding the vulnerable sources with it "
            f"applied and running your PoC against the result."
        ),
        reward=make_reward(
            fuzzer=entry["fuzzer"],
            patch_path=PATCH_PATH,
            rebuild_runner=docker_rebuild_runner(
                fuzzer=entry["fuzzer"],
                platform=entry.get("platform"),
            ),
        ),
        tools=(shell,),
        world=_build_world(entry, index_dir),
        backend="docker",
    )


def register_entry(entry: Mapping[str, Any],
                   index_dir: Path = INDEX_PATH.parent) -> list[str]:
    """Register one @task factory per onboarded level of ``entry``."""
    names = []
    for level in entry["levels"]:
        name = variant_name(entry, level)

        @task(name=name)
        def _factory(entry=entry, level=level, index_dir=index_dir) -> Task:
            return _build_task(entry, level, index_dir)

        names.append(name)
    return names


def register_index(path: str | Path = INDEX_PATH) -> list[str]:
    """Load ``path`` and register every variant it onboard; returns task names."""
    names: list[str] = []
    index_dir = Path(path).resolve().parent
    for entry in load_index(path):
        names.extend(register_entry(entry, index_dir))
    return names




register_index()  # discover() imports this file: registration happens at import
