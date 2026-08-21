# cybergym

CyberGym benchmark tasks ([arvo](https://arvo-team.github.io/) /
[oss-fuzz](https://github.com/google/oss-fuzz) reproduced vulnerabilities) as an
OpenCyberRL task family.

One registration file (`tasks/task.py`) registers a *family* of task variants
from a declarative index — no per-task directories.

## Layout

```
cybergym/
├── index.yaml       # the onboarded-task index (schema below)
├── tasks/
│   └── task.py      # registration file: loads the index, registers variants
└── tests/           # loader + registration tests (run from the core checkout)
```

`opencrl` discovers a module by globbing `<module>/*/task.py`, which is why
the registration file lives in `cybergym/tasks/` rather than at the module
root.

## Index schema (`index.yaml`)

```yaml
tasks:                       # list of onboarded entries; [] is valid (empty module)
  - id: curl                 # required — short unique id, [a-z0-9][a-z0-9._-]*
    source: oss-fuzz         # required — "arvo" | "oss-fuzz"
    project: curl            # required — upstream project (group filter: project=)
    language: c              # required — implementation language of the target
    levels: [0, 1, 2, 3]     # optional — onboarded difficulty levels (l0–l3);
                             #   unique ints in 0..3; defaults to all four
    provenance:              # required mapping — at minimum a non-empty repo
      repo: https://github.com/curl/curl
      commit: deadbeef       # optional — pinned upstream revision
```

Loading is strict: malformed entries, unknown sources, out-of-range or
duplicate levels, missing provenance, or duplicate ids raise `ValueError`.
An empty file, `tasks:` with no value, or `tasks: []` is a valid empty index —
the module installs with zero tasks onboarded.

## Task names

Each index entry registers one task per onboarded level, named

```
cybergym_<source>_<id>_l<N>          e.g. cybergym_oss-fuzz_curl_l2
```

`<source>` and `<id>` appear verbatim from the index, so the whole name is a
single CLI-friendly token.

## Group-index contract

`tasks/task.py` exposes `group_index(entries)` mapping `load_index()` output
to the core task-index dicts consumed by `opencrl.groups.resolve_group` —
one dict per variant, shaped
`{"name": ..., "module": "cybergym", "project": ..., "level": ...}`:

```python
from opencrl.groups import resolve_group
from cybergym.tasks.task import load_index, group_index

index = group_index(load_index())
resolve_group("cybergym/level2", index)      # → ["cybergym_oss-fuzz_curl_l2", ...]
resolve_group("cybergym/project=curl", index)
```

(When the file is exec'd standalone by `discover()` there is no package
context — import it by path, the way the tests do.)

## Placeholders

The real worlds, goals, and rewards come from the cybergym builders
(opencyberrl-modules#2) and the cybergym reward library
(opencyberrl-modules#3). Until those land, every registered variant is a
valid `Task` on the **mock backend** with a trivial **zero reward**. The
placeholder exists only at this registration layer; `index.yaml` therefore
ships empty — entries are onboarded once real task bodies exist.

## Tests

From the OpenCyberRL core checkout:

```bash
uv run pytest <path-to-this-repo>/cybergym/tests/ -v
```
