"""Index loader tests: schema validation and the core group-index mapping."""
from __future__ import annotations

from pathlib import Path

import pytest

from opencrl.groups import validate_index

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


def _index_file(tmp_path: Path, text: str) -> Path:
    """Write ``text`` to a temp index file and return its path."""
    path = tmp_path / "index.yaml"
    path.write_text(text)
    return path


def test_load_full_entry_normalizes_fields(registration, tmp_path):
    entries = registration.load_index(_index_file(tmp_path, FULL_ENTRY))
    assert entries == [{
        "id": "curl",
        "source": "oss-fuzz",
        "project": "curl",
        "language": "c",
        "levels": [0, 2],
        "provenance": {"repo": "https://github.com/curl/curl", "commit": "deadbeef"},
    }]


def test_levels_default_to_all_four(registration, tmp_path):
    entries = registration.load_index(_index_file(tmp_path, """
tasks:
  - id: synth
    source: arvo
    project: synthproj
    language: python
    provenance:
      repo: https://example.com/synthproj
"""))
    assert entries[0]["levels"] == [0, 1, 2, 3]


def test_real_shipped_index_is_valid(registration):
    # The shipped index carries the tasks cybergym.onboard accepted; the
    # first onboarded task (arvo:1065, modules#3) carries its full build
    # recipe alongside the base schema.
    entries = registration.load_index()
    assert [e["id"] for e in entries] == ["1065"]
    entry = entries[0]
    assert entry["source"] == "arvo"
    assert entry["fuzzer"] == "magic_fuzzer"
    assert entry["poc"] == "pocs/arvo-1065.poc"
    assert entry["provenance"]["oss_fuzz_issue"] == 42470716


@pytest.mark.parametrize("text", ["", "tasks: []", "tasks:\n"])
def test_empty_index_is_valid(registration, tmp_path, text):
    assert registration.load_index(_index_file(tmp_path, text)) == []


def test_variant_name_pattern(registration):
    entry = {"id": "curl", "source": "oss-fuzz"}
    assert registration.variant_name(entry, 2) == "cybergym_oss-fuzz_curl_l2"
    assert registration.variant_name({"id": "x", "source": "arvo"}, 0) == "cybergym_arvo_x_l0"


def test_group_index_maps_entries_to_core_shape(registration, tmp_path):
    entries = registration.load_index(_index_file(tmp_path, FULL_ENTRY))
    index = registration.group_index(entries)
    assert index == [
        {"name": "cybergym_oss-fuzz_curl_l0", "module": "cybergym",
         "project": "curl", "level": 0},
        {"name": "cybergym_oss-fuzz_curl_l2", "module": "cybergym",
         "project": "curl", "level": 2},
    ]
    validate_index(index)  # accepted by the core group resolver


def test_group_index_resolves_group_filters(registration, tmp_path):
    """The mapped index is directly consumable by opencrl.groups.resolve_group."""
    from opencrl.groups import resolve_group

    entries = registration.load_index(_index_file(tmp_path, FULL_ENTRY))
    index = registration.group_index(entries)
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
    ("provenance repo not a string", """
tasks:
  - id: p
    source: arvo
    project: p
    language: c
    provenance: {repo: 42}
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
    ("levels not a list", """
tasks:
  - id: p
    source: arvo
    project: p
    language: c
    levels: 2
    provenance: {repo: https://example.com/p}
"""),
    ("unknown key", """
tasks:
  - id: p
    source: arvo
    project: p
    language: c
    foo: bar
    provenance: {repo: https://example.com/p}
"""),
    ("typoed key", """
tasks:
  - id: p
    source: arvo
    project: p
    language: c
    levles: [1]
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
    ("tasks falsy int", "tasks: 0\n"),
    ("tasks falsy string", 'tasks: ""\n'),
    ("entry not a mapping", "tasks:\n  - curl\n"),
    ("document not a mapping", "- just\n- a list\n"),
    ("document falsy int", "0"),
    ("document falsy bool", "false"),
    ("document empty string", '""'),
]


@pytest.mark.parametrize("why, text", BAD_INDEXES, ids=[w for w, _ in BAD_INDEXES])
def test_invalid_indexes_are_rejected(registration, tmp_path, why, text):
    with pytest.raises(ValueError):
        registration.load_index(_index_file(tmp_path, text))
