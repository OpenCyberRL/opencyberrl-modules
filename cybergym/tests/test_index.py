"""Index loader tests: schema validation and the core group-index mapping."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from opencrl.groups import validate_index

MODULE_DIR = Path(__file__).resolve().parents[1]
TASK_PY = MODULE_DIR / "tasks" / "task.py"


def _registration():
    """Import the registration file the way discover() does (by path)."""
    if "cybergym_registration" not in sys.modules:
        spec = importlib.util.spec_from_file_location("cybergym_registration", TASK_PY)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return sys.modules["cybergym_registration"]


def _index_file(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "index.yaml"
    path.write_text(text)
    return path


FULL_ENTRY = """
tasks:
  - id: curl
    source: oss-fuzz
    project: curl
    language: c
    levels: [0, 2]
    provenance:
      repo: https://github.com/curl/curl
      commit: deadbeef
"""


def test_load_full_entry_normalizes_fields(tmp_path):
    reg = _registration()
    entries = reg.load_index(_index_file(tmp_path, FULL_ENTRY))
    assert entries == [{
        "id": "curl",
        "source": "oss-fuzz",
        "project": "curl",
        "language": "c",
        "levels": [0, 2],
        "provenance": {"repo": "https://github.com/curl/curl", "commit": "deadbeef"},
    }]


def test_levels_default_to_all_four(tmp_path):
    reg = _registration()
    entries = reg.load_index(_index_file(tmp_path, """
tasks:
  - id: synth
    source: arvo
    project: synthproj
    language: python
    provenance:
      repo: https://example.com/synthproj
"""))
    assert entries[0]["levels"] == [0, 1, 2, 3]


def test_real_shipped_index_is_valid_and_empty():
    reg = _registration()
    assert reg.load_index() == []


@pytest.mark.parametrize("text", ["", "tasks: []", "tasks:\n"])
def test_empty_index_is_valid(tmp_path, text):
    reg = _registration()
    assert reg.load_index(_index_file(tmp_path, text)) == []


def test_variant_name_pattern():
    reg = _registration()
    entry = {"id": "curl", "source": "oss-fuzz"}
    assert reg.variant_name(entry, 2) == "cybergym_oss-fuzz_curl_l2"
    assert reg.variant_name({"id": "x", "source": "arvo"}, 0) == "cybergym_arvo_x_l0"


def test_group_index_maps_entries_to_core_shape(tmp_path):
    reg = _registration()
    entries = reg.load_index(_index_file(tmp_path, FULL_ENTRY))
    index = reg.group_index(entries)
    assert index == [
        {"name": "cybergym_oss-fuzz_curl_l0", "module": "cybergym",
         "project": "curl", "level": 0},
        {"name": "cybergym_oss-fuzz_curl_l2", "module": "cybergym",
         "project": "curl", "level": 2},
    ]
    validate_index(index)  # accepted by the core group resolver


def test_group_index_resolves_group_filters(tmp_path):
    """The mapped index is directly consumable by opencrl.groups.resolve_group."""
    from opencrl.groups import resolve_group

    reg = _registration()
    entries = reg.load_index(_index_file(tmp_path, FULL_ENTRY))
    index = reg.group_index(entries)
    assert resolve_group("cybergym/level0", index) == ["cybergym_oss-fuzz_curl_l0"]
    assert resolve_group("cybergym/project=curl", index) == [
        "cybergym_oss-fuzz_curl_l0", "cybergym_oss-fuzz_curl_l2"]


BAD_INDEXES = [
    ("missing id", """
tasks:
  - source: arvo
    project: p
    language: c
    provenance: {repo: https://example.com/p}
"""),
    ("bad id charset", """
tasks:
  - id: Bad Id!
    source: arvo
    project: p
    language: c
    provenance: {repo: https://example.com/p}
"""),
    ("unknown source", """
tasks:
  - id: p
    source: github
    project: p
    language: c
    provenance: {repo: https://example.com/p}
"""),
    ("missing project", """
tasks:
  - id: p
    source: arvo
    language: c
    provenance: {repo: https://example.com/p}
"""),
    ("missing language", """
tasks:
  - id: p
    source: arvo
    project: p
    provenance: {repo: https://example.com/p}
"""),
    ("missing provenance", """
tasks:
  - id: p
    source: arvo
    project: p
    language: c
"""),
    ("provenance without repo", """
tasks:
  - id: p
    source: arvo
    project: p
    language: c
    provenance: {commit: deadbeef}
"""),
    ("level out of range", """
tasks:
  - id: p
    source: arvo
    project: p
    language: c
    levels: [0, 4]
    provenance: {repo: https://example.com/p}
"""),
    ("duplicate level", """
tasks:
  - id: p
    source: arvo
    project: p
    language: c
    levels: [1, 1]
    provenance: {repo: https://example.com/p}
"""),
    ("empty levels", """
tasks:
  - id: p
    source: arvo
    project: p
    language: c
    levels: []
    provenance: {repo: https://example.com/p}
"""),
    ("non-int level", """
tasks:
  - id: p
    source: arvo
    project: p
    language: c
    levels: [zero]
    provenance: {repo: https://example.com/p}
"""),
    ("duplicate ids", """
tasks:
  - id: p
    source: arvo
    project: p
    language: c
    provenance: {repo: https://example.com/p}
  - id: p
    source: arvo
    project: p
    language: c
    provenance: {repo: https://example.com/p}
"""),
    ("tasks not a list", "tasks: curl\n"),
    ("entry not a mapping", "tasks:\n  - curl\n"),
    ("document not a mapping", "- just\n- a list\n"),
]


@pytest.mark.parametrize("why, text", BAD_INDEXES, ids=[w for w, _ in BAD_INDEXES])
def test_invalid_indexes_are_rejected(tmp_path, why, text):
    reg = _registration()
    with pytest.raises(ValueError):
        reg.load_index(_index_file(tmp_path, text))
