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
├── onboard.py       # the onboarding tool: build, verify, report, accept
├── pocs/            # validated PoC fixtures (one per onboarded task)
├── reports/         # introspection reports (one dir per onboarded task)
├── builder/         # parameterized vul/fix image builders (modules#2)
├── lib/             # crash parsing + the gated reward chain
├── tasks/
│   └── task.py      # registration file: loads the index, registers variants
└── tests/           # loader + registration + onboarding tests
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
    # --- written only by cybergym.onboard's accept step (see below) ---
    fuzzer: magic_fuzzer     # the fuzzer binary the build produces in /out
    sanitizer: memory        # address | memory | undefined
    build_dir: file          # project subdir of /src where build.sh runs
    poc: pocs/arvo-1065.poc  # the validated PoC fixture (module-relative)
    extra_pkgs: make autoconf ...   # optional — apt packages beyond the base image
    base_image: gcr.io/...   # optional — overrides the default base builder
    platform: linux/amd64    # optional — explicit build/run platform
```
Loading is strict: malformed entries, unknown keys, unknown sources,
out-of-range or duplicate levels, missing provenance, or duplicate ids raise
`ValueError`. An empty file, `tasks:` with no value, or `tasks: []` is a
valid empty index — the module installs with zero tasks onboarded.

Entries carrying the onboarding keys (fuzzer/sanitizer/build_dir/poc) get
the **real wiring**: a docker world built from `builder/` — the vulnerable
target the agent explores, plus the reference fix isolated on its own
network — and the gated three-stage reward from `lib/reward.py`. Entries
without them are pre-onboarding placeholders (mock backend, zero reward).

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

## Onboarding a task

Tasks are onboarded one at a time, with evidence, by the onboarding tool
(`onboard.py`, modules#3):

```bash
uv run python -m cybergym.onboard arvo:1065        # from the modules repo root
```

It builds the task's vulnerable and reference-fixed images from source
(full logs and timings captured), obtains a reference PoC with recorded
provenance (the ARVO reproducer image first, the CyberGym HF dataset as
fallback), and asserts the differential end-to-end: the PoC must crash the
vulnerable build and run clean on the reference-patched build. It also
sanity-checks that the fix tree differs from the vulnerable tree only by
the reference patch. Everything lands in a human-reviewable introspection
report under `reports/<source>-<id>/` (`report.md` + `report.json`, run
logs, build logs) BEFORE anything is indexed.

When — and only when — the whole differential held, the tool accepts the
task: it stores the validated PoC as the module's contract-test fixture
(`pocs/<source>-<id>.poc`) and writes the index entry with the full build
recipe. A task with no obtainable PoC, or a failed differential, is
recorded **UNVERIFIED** in its report and never silently indexed.

Toolchain note: some old sanitizer bugs are only observable with the
toolchain they were built with — modern MSan runtimes intercept `regexec`
and unpoison `pmatch`, hiding arvo:1065's crash entirely. That task
therefore pins the 2017-04-05 OSS-Fuzz base-builder (its layer digests
match the ARVO reproducer image) via its `base_image` index key.

## Tests

From the OpenCyberRL core checkout:

```bash
uv run pytest <path-to-this-repo>/cybergym/tests/ -v            # unit tests
uv run pytest <path-to-this-repo>/cybergym/tests/ -m docker -v  # real builds
```
