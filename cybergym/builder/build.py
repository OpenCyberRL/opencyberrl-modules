"""Build the parameterized vul/fix images through the docker CLI."""
from __future__ import annotations

import subprocess
from pathlib import Path

BUILDER_DIR = Path(__file__).resolve().parent
DOCKERFILE_VUL = BUILDER_DIR / "Dockerfile.vul"
DOCKERFILE_FIX = BUILDER_DIR / "Dockerfile.fix"

DEFAULT_BASE_IMAGE = "gcr.io/oss-fuzz-base/base-builder"

HF_DATASET = "sunblaze-ucb/cybergym"


def hf_url(task_id: str, filename: str) -> str:
    """URL of an artifact in the CyberGym Hugging Face dataset.

    task_id uses the dataset's "arvo:1065" / "oss-fuzz:42535201" form.
    """
    kind, _, number = task_id.partition(":")
    return (
        f"https://huggingface.co/datasets/{HF_DATASET}"
        f"/resolve/main/data/{kind}/{number}/{filename}"
    )


def build_image(
    dockerfile: Path,
    tag: str,
    *,
    repo_url: str,
    fuzzer: str,
    sanitizer: str = "address",
    build_dir: str = ".",
    patch_url: str | None = None,
    base_image: str = DEFAULT_BASE_IMAGE,
) -> str:
    """docker build one of the templates. Returns the tag on success.

    The templates are self-contained (everything is fetched from REPO_URL /
    PATCH_URL), so the build context is the builder directory itself.
    """
    dockerfile = Path(dockerfile)
    is_fix = dockerfile.name == DOCKERFILE_FIX.name
    if is_fix and not patch_url:
        raise ValueError("the fix template requires PATCH_URL (the reference patch.diff)")
    if not is_fix and patch_url:
        raise ValueError("PATCH_URL is only accepted by the fix template")

    args = [
        "docker", "build",
        "-f", str(dockerfile),
        "-t", tag,
        "--build-arg", f"REPO_URL={repo_url}",
        "--build-arg", f"FUZZER={fuzzer}",
        "--build-arg", f"SANITIZER={sanitizer}",
        "--build-arg", f"BUILD_DIR={build_dir}",
        "--build-arg", f"BASE_IMAGE={base_image}",
    ]
    if patch_url:
        args += ["--build-arg", f"PATCH_URL={patch_url}"]
    args.append(str(BUILDER_DIR))

    result = subprocess.run(args, capture_output=True, text=True, errors="replace")
    if result.returncode != 0:
        tail = (result.stdout + result.stderr)[-2000:]
        raise RuntimeError(f"docker build of {tag} failed (exit {result.returncode}):\n{tail}")
    return tag
