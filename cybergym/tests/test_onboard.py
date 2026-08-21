"""Onboarding tool tests: PoC acquisition, differential, report, acceptance.

No Docker daemon required — docker-touching helpers are monkeypatched; the
real end-to-end run lives in test_onboard_docker.py behind -m docker.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import cybergym.onboard as ob
from conftest import load_registration


# --- the task registry -------------------------------------------------------


def test_arvo_1065_is_registered_with_its_build_recipe() -> None:
    spec = ob.TASKS["arvo:1065"]
    assert spec.project == "file"
    assert spec.language == "c"
    assert spec.fuzzer == "magic_fuzzer"
    assert spec.sanitizer == "memory"
    assert spec.build_dir == "file"
    assert spec.oss_fuzz_id == 42470716
    # MSan needs the amd64 base image, and — for THIS bug — the pre-2018
    # toolchain: modern MSan runtimes intercept regexec and unpoison pmatch,
    # hiding the crash entirely.
    assert spec.platform == "linux/amd64"
    assert "gcr.io/oss-fuzz-base/base-builder@sha256:" in spec.base_image


def test_image_tags_follow_the_source_id_convention() -> None:
    assert ob.image_tags(ob.TASKS["arvo:1065"]) == (
        "cybergym-arvo-1065:vul", "cybergym-arvo-1065:fix")


# --- reference PoC acquisition ------------------------------------------------


def test_reference_poc_prefers_the_arvo_reproducer_image(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_copy_out(image: str, path_in_image: str, dest: Path) -> None:
        calls.append(image)
        dest.write_bytes(b"P*M\x18\x00\x00\x00\x00P6M\x18")

    monkeypatch.setattr(ob, "_copy_out_of_image", fake_copy_out)
    spec = ob.TASKS["arvo:1065"]
    attempts: list[str] = []
    poc = ob.obtain_reference_poc(spec, tmp_path, attempts)
    assert poc is not None and poc.read_bytes() == b"P*M\x18\x00\x00\x00\x00P6M\x18"
    assert calls == [f"n132/arvo:{spec.oss_fuzz_id}-vul"]
    assert any("arvo" in a for a in attempts)


def test_reference_poc_records_every_failed_attempt(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(image: str, path_in_image: str, dest: Path) -> None:
        raise RuntimeError("image not on dockerhub")

    monkeypatch.setattr(ob, "_copy_out_of_image", boom)
    spec = ob.TASKS["arvo:1065"]
    attempts: list[str] = []
    assert ob.obtain_reference_poc(spec, tmp_path, attempts) is None
    # The report must show WHAT was tried: the ARVO image and the HF dataset.
    assert any("n132/arvo:42470716" in a for a in attempts)
    assert any("huggingface" in a for a in attempts)


# --- running the PoC -----------------------------------------------------------


def test_run_poc_runs_the_fuzzer_on_the_mounted_poc(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: dict = {}

    def fake_docker(*args: str, timeout: float = 120):
        recorded["args"] = args
        recorded["timeout"] = timeout
        import subprocess
        return subprocess.CompletedProcess(args, 0, stdout="Executed /tmp/poc", stderr="")

    monkeypatch.setattr(ob, "docker", fake_docker)
    poc = tmp_path / "poc"
    poc.write_bytes(b"x")
    result = ob.run_poc("cybergym-arvo-1065:vul", poc, fuzzer="magic_fuzzer",
                        platform="linux/amd64")
    args = recorded["args"]
    assert args[:2] == ("run", "--rm")
    assert "--platform" in args and "linux/amd64" in args
    assert f"{poc}:/tmp/poc:ro" in args
    assert args[-2:] == ("/out/magic_fuzzer", "/tmp/poc") or args[-3:] == (
        "/out/magic_fuzzer", "-runs=1", "/tmp/poc")
    assert result.exit_code == 0
    assert "Executed /tmp/poc" in result.output


def test_run_poc_captures_crash_output_and_exit_code(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    def fake_docker(*args: str, timeout: float = 120):
        return subprocess.CompletedProcess(
            args, 77, stdout="", stderr="WARNING: MemorySanitizer: use-of-uninitialized-value")

    monkeypatch.setattr(ob, "docker", fake_docker)
    poc = tmp_path / "poc"
    poc.write_bytes(b"x")
    result = ob.run_poc("img", poc, fuzzer="magic_fuzzer")
    assert result.exit_code == 77
    assert "MemorySanitizer" in result.output


# --- fix-diff sanity ------------------------------------------------------------


PATCH = """diff --git a/src/funcs.c b/src/funcs.c
--- a/src/funcs.c
+++ b/src/funcs.c
@@ -1,3 +1,4 @@
 #include "file.h"
+	memset(pmatch, 0, nmatch * sizeof(*pmatch));
 int file_regexec(void) { return 0; }
"""


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def test_verify_fix_diff_accepts_patch_plus_vul_tree(tmp_path: Path) -> None:
    vul = _tree(tmp_path / "vul", {"src/funcs.c": "#include \"file.h\"\nint f(void){return 0;}\n",
                                    "src/other.c": "int g(void){return 1;}\n"})
    fix = _tree(tmp_path / "fix", {"src/funcs.c": "#include \"file.h\"\nint f(void){return 0;}\n",
                                   "src/other.c": "int g(void){return 1;}\n"})
    patch = tmp_path / "patch.diff"
    patch.write_text(PATCH)
    (fix / "src/funcs.c").write_text('#include "file.h"\n\tmemset(pmatch, 0, nmatch * sizeof(*pmatch));\nint f(void){return 0;}\n')
    ok, detail = ob.verify_fix_diff(vul, fix, patch)
    assert ok, detail


def test_verify_fix_diff_rejects_drifted_trees(tmp_path: Path) -> None:
    vul = _tree(tmp_path / "vul", {"src/funcs.c": "int f(void){return 0;}\n"})
    fix = _tree(tmp_path / "fix", {"src/funcs.c": "int f(void){return 42;}\n"})
    patch = tmp_path / "patch.diff"
    patch.write_text(PATCH)
    ok, detail = ob.verify_fix_diff(vul, fix, patch)
    assert not ok
    assert "funcs.c" in detail


def test_verify_fix_diff_ignores_build_artifacts(tmp_path: Path) -> None:
    files = {"src/funcs.c": "int f(void){return 0;}\n"}
    vul = _tree(tmp_path / "vul", {**files, "src/.libs/funcs.o": "binary-ish"})
    fix = _tree(tmp_path / "fix", {**files, "src/.libs/funcs.o": "different-binary"})
    patch = tmp_path / "patch.diff"
    patch.write_text(PATCH)
    (fix / "src/funcs.c").write_text("int f(void){return 0;}\n")
    ok, _ = ob.verify_fix_diff(vul, fix, patch)
    assert ok


# --- the report ------------------------------------------------------------------


def _accepted_report() -> dict:
    return {
        "task_id": "arvo:1065",
        "status": "accepted",
        "accepted": True,
        "task": {"project": "file", "sanitizer": "memory",
                 "description": "regexec does not initialize pmatch"},
        "build": {"vul": {"image": "cybergym-arvo-1065:vul", "seconds": 121.2, "log": "vul-build.log"},
                  "fix": {"image": "cybergym-arvo-1065:fix", "seconds": 125.0, "log": "fix-build.log"},
                  "platform": "linux/amd64",
                  "base_image": "gcr.io/oss-fuzz-base/base-builder@sha256:abc"},
        "poc": {"file": "poc", "size": 12, "sha256": "deadbeef",
                "origin": "arvo-reproducer-image", "image": "n132/arvo:42470716-vul",
                "attempts": ["pulled n132/arvo:42470716-vul"]},
        "differential": {
            "vul": {"crashed": True, "exit_code": 77, "seconds": 0.4, "log": "vul-run.txt"},
            "fix": {"crashed": False, "exit_code": 0, "seconds": 0.3, "log": "fix-run.txt"},
            "crash_vul": True, "clean_fix": True,
            "crash_signature": {"family": "MemorySanitizer", "dedup_token": "match--file_softmagic--mget"}},
        "fix_diff": {"verified": True, "detail": "identical"},
        "emulation": {"host_arch": "arm64", "build_platform": "linux/amd64"},
    }


def test_write_report_emits_json_and_markdown(tmp_path: Path) -> None:
    report = _accepted_report()
    ob.write_report(report, tmp_path)
    md = (tmp_path / "report.md").read_text()
    data = json.loads((tmp_path / "report.json").read_text())
    assert data["task_id"] == "arvo:1065"
    for needle in ("arvo:1065", "MemorySanitizer", "match--file_softmagic--mget",
                   "n132/arvo:42470716-vul", "deadbeef", "accepted"):
        assert needle in md, needle


def test_write_report_marks_unverified_tasks_loudly(tmp_path: Path) -> None:
    report = _accepted_report()
    report.update(status="unverified", accepted=False)
    report["poc"] = {"attempts": ["ARVO image pull failed: 404",
                                  "HF dataset has no poc file"]}
    report["differential"] = None
    ob.write_report(report, tmp_path)
    md = (tmp_path / "report.md").read_text()
    assert "UNVERIFIED" in md
    assert "ARVO image pull failed" in md


# --- index acceptance --------------------------------------------------------------


def test_accept_into_module_writes_index_entry_and_poc(tmp_path: Path) -> None:
    module = tmp_path / "cybergym"
    (module / "reports" / "arvo-1065").mkdir(parents=True)
    (module / "reports" / "arvo-1065" / "poc").write_bytes(b"P*M")
    index = module / "index.yaml"
    index.write_text("# header comment\ntasks: []\n")

    ob.accept_into_module("arvo:1065", module,
                          report_poc=module / "reports" / "arvo-1065" / "poc")

    stored = module / "pocs" / "arvo-1065.poc"
    assert stored.read_bytes() == b"P*M"
    reg = load_registration()
    entries = reg.load_index(index)
    assert [e["id"] for e in entries] == ["1065"]
    assert entries[0]["fuzzer"] == "magic_fuzzer"
    assert entries[0]["poc"] == "pocs/arvo-1065.poc"
    assert entries[0]["provenance"]["oss_fuzz_issue"] == 42470716


def test_accept_is_idempotent(tmp_path: Path) -> None:
    module = tmp_path / "cybergym"
    (module / "reports" / "arvo-1065").mkdir(parents=True)
    (module / "reports" / "arvo-1065" / "poc").write_bytes(b"P*M")
    index = module / "index.yaml"
    index.write_text("tasks: []\n")
    ob.accept_into_module("arvo:1065", module,
                          report_poc=module / "reports" / "arvo-1065" / "poc")
    ob.accept_into_module("arvo:1065", module,
                          report_poc=module / "reports" / "arvo-1065" / "poc")
    reg = load_registration()
    assert len(reg.load_index(index)) == 1
