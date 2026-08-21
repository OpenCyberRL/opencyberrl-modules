"""Cybergym family registration: one task variant per onboarded index level.

``cybergym/index.yaml`` lists the CyberGym tasks onboarded into this module
(schema documented in ``cybergym/README.md``).  Importing this file — which
``opencrl`` does via ``discover()`` globbing ``<module>/*/task.py`` —
registers one task per onboarded difficulty level of every entry, named
``cybergym_<source>_<id>_l<N>``.

Placeholder worlds and rewards: the real world, goal, and reward bodies come
from the cybergym builders (modules#2) and the cybergym reward library
(modules#3).  Until those land, every variant is a valid Task on the mock
backend with a trivial zero reward.  The placeholder lives here, at the
registration layer only, so the builder and reward modules stay free of it.

This file is exec'd by ``discover()`` as a standalone module (no package
context), so the index loader lives here too rather than in an importable
sibling module.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from opencrl import Task, task

MODULE = "cybergym"
SOURCES = ("arvo", "oss-fuzz")
MAX_LEVEL = 3
DEFAULT_LEVELS = (0, 1, 2, 3)

INDEX_PATH = Path(__file__).resolve().parent.parent / "index.yaml"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def load_index(path: str | Path = INDEX_PATH) -> list[dict]:
    """Load and validate an index file, returning normalized entry dicts.

    An empty file, ``tasks:`` with no value, or ``tasks: []`` is a valid
    empty index (the module installs with zero tasks onboarded).
    """
    doc = yaml.safe_load(Path(path).read_text()) or {}
    if not isinstance(doc, Mapping):
        raise ValueError(
            f"index must be a mapping with a 'tasks' list, got {type(doc).__name__}")
    raw = doc.get("tasks") or []
    if not isinstance(raw, list):
        raise ValueError(f"'tasks' must be a list, got {type(raw).__name__}")
    entries = [_normalize_entry(item, i) for i, item in enumerate(raw)]
    ids = [entry["id"] for entry in entries]
    dupes = sorted({task_id for task_id in ids if ids.count(task_id) > 1})
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
    if not _ID_RE.match(entry["id"]):
        raise ValueError(
            f"{where} id {entry['id']!r} must match {_ID_RE.pattern}")
    if entry["source"] not in SOURCES:
        raise ValueError(
            f"{where} source must be one of {', '.join(SOURCES)}, "
            f"got {entry['source']!r}")
    entry["levels"] = _normalize_levels(entry.get("levels", list(DEFAULT_LEVELS)), where)
    provenance = entry.get("provenance")
    if not isinstance(provenance, Mapping) or not provenance.get("repo"):
        raise ValueError(f"{where} needs provenance with a non-empty 'repo'")
    entry["provenance"] = dict(provenance)
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
    """Trivial zero reward standing in for the cybergym reward lib (modules#3)."""

    def reward(state: Any) -> float:
        return 0.0

    return reward


def _build_task(entry: Mapping[str, Any], level: int) -> Task:
    """Build one placeholder variant on the mock backend (real bodies: modules#2/#3)."""
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


def register_entry(entry: Mapping[str, Any]) -> list[str]:
    """Register one @task factory per onboarded level of ``entry``."""
    names = []
    for level in entry["levels"]:
        name = variant_name(entry, level)

        @task(name=name)
        def _factory(entry=entry, level=level) -> Task:
            return _build_task(entry, level)

        names.append(name)
    return names


def register_index(path: str | Path = INDEX_PATH) -> list[str]:
    """Load ``path`` and register every variant it onboard; returns task names."""
    names: list[str] = []
    for entry in load_index(path):
        names.extend(register_entry(entry))
    return names


register_index()  # discover() imports this file: registration happens at import
