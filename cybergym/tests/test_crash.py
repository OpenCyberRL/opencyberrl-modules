"""Crash-signature parsing against real CyberGym error.txt fixtures."""
from __future__ import annotations

from pathlib import Path

from cybergym.lib.crash import (
    ASAN,
    MSAN,
    UBSAN,
    CrashSignature,
    crash_family,
    crash_signature,
    poc_crashes,
)


def fixture(testdata: Path, arvo_id: str) -> str:
    return (testdata / "arvo" / arvo_id / "error.txt").read_text()


# --- real fixtures: one per sanitizer family present in the dataset ---------


def test_msan_fixture_is_memorysanitizer(testdata: Path) -> None:
    sig = crash_signature(fixture(testdata, "1065"))
    assert sig is not None
    assert sig.family == MSAN
    # The first DEDUP_TOKEN tags the crashing stack; later ones tag the
    # origin/allocation stacks and are not the bug's identity.
    assert sig.dedup_token == "match--file_softmagic--mget"


def test_asan_fixture_is_addresssanitizer(testdata: Path) -> None:
    sig = crash_signature(fixture(testdata, "47101"))
    assert sig is not None
    assert sig.family == ASAN
    assert sig.dedup_token == "__asan_memset--assign_file_to_slot--allocate_filename_to_slot"


def test_ubsan_fixture_is_undefinedbehaviorsanitizer(testdata: Path) -> None:
    sig = crash_signature(fixture(testdata, "3938"))
    assert sig.dedup_token == (
        "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)"
        "--fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long)"
        "--fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long))"
    )


def test_all_fixture_families_via_crash_family(testdata: Path) -> None:
    assert crash_family(fixture(testdata, "1065")) == MSAN
    assert crash_family(fixture(testdata, "47101")) == ASAN
    assert crash_family(fixture(testdata, "3938")) == UBSAN


def test_all_fixtures_are_crashes(testdata: Path) -> None:
    for arvo_id in ("1065", "47101", "3938"):
        assert poc_crashes(fixture(testdata, arvo_id)), arvo_id


# --- family detection without a DEDUP_TOKEN ---------------------------------


def test_asan_without_dedup_token() -> None:
    out = (
        "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000\n"
        "    #0 0x55 in main /src/x.c:10:3\n"
        "SUMMARY: AddressSanitizer: SEGV /src/x.c:10:3 in main\n"
    )
    assert crash_signature(out) == CrashSignature(ASAN, None)


def test_ubsan_runtime_error_without_summary() -> None:
    out = "/src/x.c:12:34: runtime error: signed integer overflow: 1 + 2 cannot be represented in type 'int'\n"
    sig = crash_signature(out)
    assert sig is not None
    assert sig.family == UBSAN
    assert sig.dedup_token is None


# --- clean output -------------------------------------------------------------


def test_clean_run_is_not_a_crash() -> None:
    out = (
        "INFO: Seed: 1\n"
        "/out/f: Running 1 inputs 1 time(s) each.\n"
        "Running: /tmp/poc\n"
        "Executed /tmp/poc in 3 ms\n"
        "*** NOTE: fuzzing was not performed, you have only\n"
        "***       executed the target code on a fixed set of inputs.\n"
    )
    assert crash_signature(out) is None
    assert crash_family(out) is None
    assert not poc_crashes(out)


def test_empty_output_is_not_a_crash() -> None:
    assert crash_signature("") is None
    assert not poc_crashes("")


def test_build_noise_is_not_a_crash() -> None:
    # Words like "AddressSanitizer" may appear in build logs or prose; only a
    # report line (family followed by a colon) counts.
    assert crash_signature("rebuilding with AddressSanitizer enabled\n") is None
    assert crash_signature("see the MemorySanitizer documentation online") is None
