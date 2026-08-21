"""Parameterized builder templates — no Docker daemon required."""
from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from cybergym.builder import (
    DEFAULT_BASE_IMAGE,
    DOCKERFILE_FIX,
    DOCKERFILE_VUL,
    build_image,
    hf_url,
)

BUILD_STEP = DOCKERFILE_VUL.parent / "build-step.sh"

REPO_URL = hf_url("arvo:1065", "repo-vul.tar.gz")
PATCH_URL = hf_url("arvo:1065", "patch.diff")


def test_dockerfiles_exist() -> None:
    assert DOCKERFILE_VUL.is_file()
    assert DOCKERFILE_FIX.is_file()
    assert BUILD_STEP.is_file()


def test_vul_template_is_parameterized() -> None:
    text = DOCKERFILE_VUL.read_text()
    for arg in ("REPO_URL", "FUZZER", "SANITIZER", "BUILD_DIR", "EXTRA_PKGS", "BASE_IMAGE"):
        assert f"ARG {arg}" in text, arg
    # Patching is the fix variant's job.
    assert "PATCH_URL" not in text
    assert "git apply" not in text


def test_fix_template_applies_reference_patch_before_building() -> None:
    text = DOCKERFILE_FIX.read_text()
    for arg in ("REPO_URL", "PATCH_URL", "FUZZER", "SANITIZER", "BUILD_DIR", "EXTRA_PKGS", "BASE_IMAGE"):
        assert f"ARG {arg}" in text, arg
    # The reference patch is applied to the unpacked source BEFORE the shared
    # build step runs.
    assert text.index("git apply") < text.index("COPY build-step.sh")


def test_templates_unpack_repo_into_src() -> None:
    for path in (DOCKERFILE_VUL, DOCKERFILE_FIX):
        text = path.read_text()
        # Tarball root (src-vul/ or src-fix/) is stripped; contents land in
        # /src. pipefail: a failed curl must not be masked by a succeeding tar.
        assert "set -o pipefail" in text
        assert "--strip-components=1" in text
        assert "-C /src" in text
        # Full toolchain + sources stay in-image for the patch-rebuild stage:
        # nothing may prune /src, /out or the compiler toolchain.
        assert "rm -rf /src" not in text
        assert "apt-get clean" not in text


def test_templates_install_extra_pkgs_and_clean_up() -> None:
    for path in (DOCKERFILE_VUL, DOCKERFILE_FIX):
        text = path.read_text()
        assert "apt-get install -y $EXTRA_PKGS" in text
        # apt lists bloat the layer for no benefit at runtime.
        assert "rm -rf /var/lib/apt/lists/*" in text


def test_build_step_is_the_single_shared_build_procedure() -> None:
    # The heavy build logic lives ONCE, in build-step.sh; both templates
    # COPY and run it, so the vul and fix builds cannot drift apart.
    script = BUILD_STEP.read_text()
    for path in (DOCKERFILE_VUL, DOCKERFILE_FIX):
        text = path.read_text()
        assert "COPY build-step.sh /usr/local/bin/build-step.sh" in text
        assert "RUN bash /usr/local/bin/build-step.sh" in text
    assert script.startswith("#!/bin/bash")
    # Sanitizer flags merged exactly like the OSS-Fuzz compile entrypoint.
    assert 'flags="SANITIZER_FLAGS_${SANITIZER}"' in script
    assert 'export CFLAGS="$CFLAGS ${!flags} $COVERAGE_FLAGS"' in script
    # The build is only successful if the named fuzzer landed in /out.
    assert '"$OUT/$FUZZER"' in script


def test_build_step_fails_fast_without_msan_libcxx() -> None:
    # Only the amd64 base image ships the MSan-instrumented libc++ under
    # /usr/msan. Building MSan targets without it would link uninstrumented
    # libc++ and report false-positive crashes — silent degradation that
    # would poison the clean_fix verification — so the script must refuse
    # loudly instead of skipping the staging step.
    script = BUILD_STEP.read_text()
    assert '"$SANITIZER" == "memory"' in script
    assert "! -d /usr/msan" in script

def test_build_step_matches_fuzzer_runtime_to_the_actual_arch() -> None:
    # The amd64 base image lays its runtimes out as lib/linux/
    # libclang_rt.fuzzer-<arch>.a for SEVERAL architectures; the second
    # probe's unanchored glob + head -1 picked the alphabetically first
    # (libclang_rt.fuzzer-i386.a) and the link died with "skipping
    # incompatible /usr/lib/libFuzzingEngine.a" (seen building arvo:1065
    # with SANITIZER=memory --platform linux/amd64). The probe must anchor
    # on the machine the build actually targets: uname -m (the
    # $ARCHITECTURE env is stale x86_64 in the arm64 image, so it cannot
    # drive the suffix either).
    script = BUILD_STEP.read_text()
    assert "libclang_rt.fuzzer-$(uname -m).a" in script

def test_build_step_builds_libfuzzer_when_base_has_no_prebuilt_runtime() -> None:
    # The 2017-era OSS-Fuzz base images ship libFuzzer as SOURCES under
    # /src/libfuzzer and no prebuilt runtime anywhere (their `compile`
    # entrypoint built the engine on the fly). Old MSan bugs (e.g. arvo:1065)
    # are only observable with those pre-interceptor toolchains, so
    # build-step must fall back to compiling the engine exactly like the
    # era's compile_libfuzzer did: raw CXXFLAGS + SANITIZER_FLAGS +
    # -fno-sanitize=vptr, archived into $LIB_FUZZING_ENGINE.
    script = BUILD_STEP.read_text()
    assert '"$SRC"/libfuzzer/*.cpp' in script
    assert 'ar r "$engine"' in script
    # The fallback engine build must use the RAW CXXFLAGS (pre flag-merge),
    # like compile_libfuzzer, not the coverage-instrumented merged ones.
    assert script.index('"$SRC"/libfuzzer/*.cpp') < script.index(
        'export CFLAGS="$CFLAGS ${!flags} $COVERAGE_FLAGS"')


def test_build_step_stages_msan_libcxx_era_agnostically() -> None:
    # The modern base images keep clang libs in the per-triple dir; the
    # 2017-era `compile` copied /usr/msan/lib straight into /usr/lib. Both
    # destinations get the copy so either toolchain resolves the
    # MSan-instrumented libc++.
    script = BUILD_STEP.read_text()
    assert "mkdir -p /usr/local/lib/x86_64-unknown-linux-gnu" in script
    assert "cp -R /usr/msan/lib/* /usr/lib/" in script


def test_templates_run_builds_under_bash() -> None:
    for path in (DOCKERFILE_VUL, DOCKERFILE_FIX):
        text = path.read_text()
        # The RUNs use bash-only syntax ([[ ]], pipefail); RUN's default
        # /bin/sh (dash) would reject them. SHELL must precede the first RUN
        # that needs bash.
        assert 'SHELL ["/bin/bash", "-c"]' in text
        assert text.index('SHELL ["/bin/bash", "-c"]') < text.index("apt-get install")


def test_templates_target_the_build_platform() -> None:
    for path in (DOCKERFILE_VUL, DOCKERFILE_FIX):
        text = path.read_text()
        # BuildKit's automatic platform arg, defaulting to the host platform
        # (native build) with an amd64 fallback for non-BuildKit builders;
        # the pinned multi-arch base resolves per platform.
        assert "ARG TARGETPLATFORM" in text
        assert "FROM --platform=${TARGETPLATFORM:-linux/amd64} ${BASE_IMAGE}" in text
        assert "@sha256:" in DEFAULT_BASE_IMAGE


def test_hf_url_points_at_cybergym_dataset() -> None:
    assert hf_url("arvo:1065", "repo-vul.tar.gz") == (
        "https://huggingface.co/datasets/sunblaze-ucb/cybergym"
        "/resolve/main/data/arvo/1065/repo-vul.tar.gz"
    )


def test_hf_url_rejects_malformed_task_ids() -> None:
    # Fail at call time, not later as a 404 from curl inside a docker build.
    for bad in ("1065", "arvo", "arvo:", ":1065"):
        with pytest.raises(ValueError, match="arvo:1065"):
            hf_url(bad, "error.txt")


def test_build_image_passes_build_args(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: dict = {}

    def fake_run(args: list[str], **kwargs) -> SimpleNamespace:
        recorded["args"] = args
        recorded["kwargs"] = kwargs
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
        "EXTRA_PKGS=",
        f"BASE_IMAGE={DEFAULT_BASE_IMAGE}",
    ):
        assert build_arg in args, build_arg
    assert not any(a.startswith("PATCH_URL=") for a in args)
    # Default: no explicit platform -> the templates' TARGETPLATFORM
    # handling builds natively for the docker host.
    assert "--platform" not in args


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


def test_build_image_forwards_extra_pkgs(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: dict = {}

    def fake_run(args: list[str], **kwargs) -> SimpleNamespace:
        recorded["args"] = args
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    build_image(
        DOCKERFILE_VUL,
        "t",
        repo_url=REPO_URL,
        fuzzer="magic_fuzzer",
        extra_pkgs="autoconf automake libtool",
    )
    assert "EXTRA_PKGS=autoconf automake libtool" in recorded["args"]


def test_build_image_forwards_explicit_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: dict = {}

    def fake_run(args: list[str], **kwargs) -> SimpleNamespace:
        recorded["args"] = args
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    build_image(
        DOCKERFILE_VUL,
        "t",
        repo_url=REPO_URL,
        fuzzer="magic_fuzzer",
        platform="linux/amd64",
    )
    args = recorded["args"]
    assert args[args.index("--platform") + 1] == "linux/amd64"


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

def test_build_image_writes_full_log_when_given_a_path(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # The onboarding report needs the full docker build log (not just the
    # failure tail build_image prints), so an optional log_path captures it.
    def fake_run(args: list[str], **kwargs) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout="step 1/6\nstep 2/6\n",
                               stderr="warning: something\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    log = tmp_path / "vul-build.log"
    build_image(DOCKERFILE_VUL, "t", repo_url=REPO_URL, fuzzer="magic_fuzzer",
                log_path=log)
    text = log.read_text()
    assert "step 1/6" in text and "warning: something" in text


def test_build_image_without_log_path_writes_no_log(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # No log_path -> a successful build writes nothing anywhere (the
    # original behavior; only failures report, via the raised RuntimeError).
    def fake_run(args: list[str], **kwargs) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    build_image(DOCKERFILE_VUL, "t", repo_url=REPO_URL, fuzzer="magic_fuzzer")
    assert list(tmp_path.iterdir()) == []

def test_build_image_times_out_rather_than_hanging(monkeypatch: pytest.MonkeyPatch) -> None:
    # A wedged docker build must surface as a RuntimeError naming the
    # command, not block forever.
    def hang(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=kwargs.get("timeout"))

    monkeypatch.setattr(subprocess, "run", hang)
    with pytest.raises(RuntimeError) as excinfo:
        build_image(DOCKERFILE_VUL, "t", repo_url=REPO_URL, fuzzer="magic_fuzzer")
    assert "timed out" in str(excinfo.value)
    assert "docker build" in str(excinfo.value)
