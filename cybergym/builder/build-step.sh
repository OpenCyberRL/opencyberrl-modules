#!/bin/bash -eu
# Shared compile step for the CyberGym vul/fix templates. Dockerfile.vul and
# Dockerfile.fix both COPY this file and run it, so the two builds share one
# build procedure by construction — they cannot drift apart.
#
# It reproduces the parts of the OSS-Fuzz base image's `compile` entrypoint
# that matter for C/C++ targets. The entrypoint itself cannot be used here:
# it starts with `sysctl -w vm.mmap_rnd_bits=28`, which fails under
# unprivileged `docker build` (read-only /proc/sys). Steps, in order:
#   1. validate SANITIZER, then merge its flags (SANITIZER_FLAGS_${SANITIZER})
#      and the coverage flags into CFLAGS/CXXFLAGS, as compile does;
#   2. for UBSan, drop the "function" check (compile disables it for C code);
#   3. for MSan, stage the MSan-instrumented libc++ from /usr/msan — and FAIL
#      FAST when the base image has none: only the amd64 OSS-Fuzz base images
#      ship it. Building an MSan target against uninstrumented libc++ yields
#      false-positive crashes that would silently poison the clean_fix
#      verification downstream.
#   4. stage libFuzzer as /usr/lib/libFuzzingEngine.a. The two base images lay
#      out the clang runtimes differently (amd64:
#      lib/<triple>/libclang_rt.fuzzer.a; arm64:
#      lib/linux/libclang_rt.fuzzer-<arch>.a, whose $ARCHITECTURE env is a
#      stale x86_64), so probe both layouts;
#   5. run the project's build.sh and require $OUT/$FUZZER to exist.
#
# Expected environment (set by the Dockerfiles and the base image): SANITIZER,
# FUZZER, and the OSS-Fuzz build env (CFLAGS, CXXFLAGS_EXTRA, COVERAGE_FLAGS,
# ARCHITECTURE, OUT, SRC, WORK).

case "${SANITIZER}" in
    address|memory|undefined) ;;
    *)
        echo "ERROR: unknown SANITIZER '${SANITIZER}': expected address, memory or undefined" >&2
        exit 1
        ;;
esac

flags="SANITIZER_FLAGS_${SANITIZER}"
export CFLAGS="$CFLAGS ${!flags} $COVERAGE_FLAGS"
export CXXFLAGS="$CFLAGS $CXXFLAGS_EXTRA"
if [[ "$SANITIZER" == "undefined" ]]; then
    export CFLAGS="$CFLAGS -fno-sanitize=function"
fi

if [[ "$SANITIZER" == "memory" ]]; then
    if [[ ! -d /usr/msan ]]; then
        echo "ERROR: SANITIZER=memory needs the MSan-instrumented libc++ under /usr/msan, which the $(uname -m) OSS-Fuzz base image does not ship; the binary would link uninstrumented libc++ and report false-positive crashes. Build on/for linux/amd64 (docker build --platform linux/amd64) or pick another sanitizer." >&2
        exit 1
    fi
    cp -R /usr/msan/lib/* /usr/local/lib/x86_64-unknown-linux-gnu/
    cp -R /usr/msan/include/* /usr/local/include
fi

rt="$(ls /usr/local/lib/clang/*/lib/${ARCHITECTURE}-unknown-linux-gnu/libclang_rt.fuzzer.a 2>/dev/null | head -1)"
if [[ -z "$rt" ]]; then
    rt="$(ls /usr/local/lib/clang/*/lib/linux/libclang_rt.fuzzer-*.a 2>/dev/null | head -1)"
fi
if [[ -z "$rt" ]]; then
    echo "ERROR: no libclang_rt.fuzzer runtime found in the base image (probed lib/*/${ARCHITECTURE}-unknown-linux-gnu/ and lib/linux/)" >&2
    exit 1
fi
cp "$rt" /usr/lib/libFuzzingEngine.a

bash -eux /src/build.sh

if [[ ! -x "$OUT/$FUZZER" ]]; then
    echo "ERROR: build.sh did not produce $OUT/$FUZZER" >&2
    exit 1
fi
