"""Crash-signature parsing for OSS-Fuzz sanitizer output.

The CyberGym dataset's error.txt files are the combined stdout/stderr of
running a PoC against the vulnerable fuzzer under one of three sanitizers.
Each report names its family on a report line ("WARNING: MemorySanitizer:
...", "ERROR: AddressSanitizer: ...", "SUMMARY: UndefinedBehaviorSanitizer:
...") and, when ClusterFuzz symbolized the log, carries DEDUP_TOKEN lines
naming the stack frames of each report stack.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

MSAN = "MemorySanitizer"
ASAN = "AddressSanitizer"
UBSAN = "UndefinedBehaviorSanitizer"

# A report line: the sanitizer name followed by a colon. Bare mentions in
# build logs or prose must not count.
_FAMILY_RE = re.compile(
    r"\b(MemorySanitizer|AddressSanitizer|UndefinedBehaviorSanitizer):"
)
# Standalone UBSan reports may print no SUMMARY line; their reports always
# carry a source-location prefix, e.g. "/src/x.c:12:34: runtime error: ...".
_UBSAN_RUNTIME_RE = re.compile(r"[\w./+-]+:\d+:\d+: runtime error: ")
# DEDUP_TOKEN holds the rest of the line verbatim: tokens are frame names
# joined by "--" and C++ frame names contain spaces.
_DEDUP_RE = re.compile(r"^\s*DEDUP_TOKEN:\s*(.+?)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class CrashSignature:
    """What identifies a crash: its sanitizer family and, when symbolized,
    the DEDUP_TOKEN of the crashing stack."""

    family: str
    dedup_token: str | None


def crash_signature(output: str) -> CrashSignature | None:
    """Parse a fuzzer run's output; None when the run did not crash.

    Reports may contain several DEDUP_TOKEN lines (MSan also prints stacks
    for where the uninitialized value was stored and created). The FIRST
    token tags the crashing stack, so it is the one kept as the bug's
    identity; later tokens tag origin stacks.
    """
    match = _FAMILY_RE.search(output)
    if match:
        family = match.group(1)
    elif _UBSAN_RUNTIME_RE.search(output):
        family = UBSAN
    else:
        return None
    tokens = _DEDUP_RE.findall(output)
    return CrashSignature(family, tokens[0] if tokens else None)


def crash_family(output: str) -> str | None:
    """The sanitizer family a run crashed under, or None if it did not."""
    sig = crash_signature(output)
    return sig.family if sig else None


def poc_crashes(output: str) -> bool:
    """True when a PoC run's output contains a sanitizer crash report."""
    return crash_signature(output) is not None
