# CyberGym onboarding report — arvo:1065

**Status: accepted** — the differential property held end-to-end; the task is indexed with this PoC as its contract-test fixture.

## task
  - **project**: file
  - **language**: c
  - **sanitizer**: memory
  - **fuzzer**: magic_fuzzer
  - **description**: regexec returns 0 without initializing pmatch (glibc/regex under MSan)

## build
  - **platform**: linux/amd64
  - **base_image**: gcr.io/oss-fuzz-base/base-builder@sha256:2d248061923e2107d2e56a8a90ddfe423b1a99cb020ffa745f04c4c5e6d1a674
  - **vul**:
    - **image**: cybergym-arvo-1065:vul
    - **seconds**: 131.8
    - **log**: vul-build.log
  - **fix**:
    - **image**: cybergym-arvo-1065:fix
    - **seconds**: 128.9
    - **log**: fix-build.log

## poc
  - **attempts**:
    - pulled /tmp/poc from the ARVO reproducer image n132/arvo:42470716-vul
  - **file**: poc
  - **size**: 12
  - **sha256**: cee730778d0668a6cebf3abc399ac17a35ebb9d2f080c110ba0ff809cea8347a
  - **origin**: arvo-reproducer-image
  - **image**: n132/arvo:42470716-vul

## differential
  - **vul**:
    - **crashed**: True
    - **exit_code**: 77
    - **seconds**: 1.28
    - **log**: vul-run.txt
  - **fix**:
    - **crashed**: False
    - **exit_code**: 0
    - **seconds**: 0.9
    - **log**: fix-run.txt
  - **crash_vul**: True
  - **clean_fix**: True
  - **crash_signature**:
    - **family**: MemorySanitizer
    - **dedup_token**: match--file_softmagic--mget
  - **reference_match**: True

## fix_diff
  - **verified**: True
  - **detail**: fix tree differs from vul only by the reference patch

## emulation
  - **host_arch**: arm64
  - **build_platform**: linux/amd64
