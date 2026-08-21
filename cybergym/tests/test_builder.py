"""Parameterized builder templates — no Docker daemon required."""
from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from cybergym.builder import (
    DEFAULT_BASE_IMAGE,
    DOCKERFILE_FIX,
    DOCKERFILE_VUL,
    build_image,
    hf_url,
)

REPO_URL = hf_url("arvo:1065", "repo-vul.tar.gz")
PATCH_URL = hf_url("arvo:1065", "patch.diff")


def test_dockerfiles_exist() -> None:
    assert DOCKERFILE_VUL.is_file()
    assert DOCKERFILE_FIX.is_file()


def test_vul_template_is_parameterized() -> None:
    text = DOCKERFILE_VUL.read_text()
    for arg in ("REPO_URL", "FUZZER", "SANITIZER", "BUILD_DIR", "BASE_IMAGE"):
        assert f"ARG {arg}" in text, arg
    # Patching is the fix variant's job.
    assert "PATCH_URL" not in text
    assert "git apply" not in text


def test_fix_template_applies_reference_patch_before_building() -> None:
    text = DOCKERFILE_FIX.read_text()
    for arg in ("REPO_URL", "PATCH_URL", "FUZZER", "SANITIZER", "BUILD_DIR", "BASE_IMAGE"):
        assert f"ARG {arg}" in text, arg
    # The reference patch is applied to the unpacked source BEFORE the build.
    assert text.index("git apply") < text.index("build.sh")


def test_templates_unpack_repo_into_src_and_check_fuzzer() -> None:
    for path in (DOCKERFILE_VUL, DOCKERFILE_FIX):
        text = path.read_text()
        # Tarball root (src-vul/ or src-fix/) is stripped; contents land in /src.
        assert "--strip-components=1" in text
        assert "-C /src" in text
        # The build is only successful if the named fuzzer landed in /out.
        assert "$OUT/$FUZZER" in text
        # Full toolchain + sources stay in-image for the patch-rebuild stage:
        # nothing may prune /src, /out or the compiler toolchain.
        assert "rm -rf /src" not in text
        assert "apt-get clean" not in text


def test_hf_url_points_at_cybergym_dataset() -> None:
    assert hf_url("arvo:1065", "repo-vul.tar.gz") == (
        "https://huggingface.co/datasets/sunblaze-ucb/cybergym"
        "/resolve/main/data/arvo/1065/repo-vul.tar.gz"
    )


def test_build_image_passes_build_args(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: dict = {}

    def fake_run(args: list[str], **kwargs) -> SimpleNamespace:
        recorded["args"] = args
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    build_image(
        DOCKERFILE_VUL,
        "cybergym-1065:vul",
        repo_url=REPO_URL,
        fuzzer="magic_fuzzer",
        sanitizer="memory",
        build_dir="file",
    )
    args = recorded["args"]
    assert args[:2] == ["docker", "build"]
    assert str(DOCKERFILE_VUL) in args
    assert "cybergym-1065:vul" in args
    for build_arg in (
        f"REPO_URL={REPO_URL}",
        "FUZZER=magic_fuzzer",
        "SANITIZER=memory",
        "BUILD_DIR=file",
        f"BASE_IMAGE={DEFAULT_BASE_IMAGE}",
    ):
        assert build_arg in args, build_arg
    assert not any(a.startswith("PATCH_URL=") for a in args)


def test_build_image_passes_patch_url_for_fix(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: dict = {}

    def fake_run(args: list[str], **kwargs) -> SimpleNamespace:
        recorded["args"] = args
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    build_image(
        DOCKERFILE_FIX,
        "cybergym-1065:fix",
        repo_url=REPO_URL,
        patch_url=PATCH_URL,
        fuzzer="magic_fuzzer",
    )
    assert f"PATCH_URL={PATCH_URL}" in recorded["args"]


def test_fix_template_requires_patch_url() -> None:
    with pytest.raises(ValueError, match="PATCH_URL"):
        build_image(DOCKERFILE_FIX, "t", repo_url=REPO_URL, fuzzer="magic_fuzzer")


def test_vul_template_rejects_patch_url() -> None:
    with pytest.raises(ValueError, match="PATCH_URL"):
        build_image(
            DOCKERFILE_VUL,
            "t",
            repo_url=REPO_URL,
            fuzzer="magic_fuzzer",
            patch_url=PATCH_URL,
        )


def test_build_image_raises_on_docker_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **kwargs: SimpleNamespace(
            returncode=1, stdout="", stderr="boom: no route to gcr.io"
        ),
    )
    with pytest.raises(RuntimeError, match="no route to gcr.io"):
        build_image(DOCKERFILE_VUL, "t", repo_url=REPO_URL, fuzzer="magic_fuzzer")
