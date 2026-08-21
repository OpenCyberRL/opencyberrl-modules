#!/bin/bash -eu
# Shared compile step for the CyberGym vul/fix templates. Dockerfile.vul and
# Dockerfile.fix both COPY this file and run it, so the two builds share one
# build procedure by construction — they cannot drift apart.
#
# It reproduces the parts of the OSS-Fuzz base image's `compile` entrypoint
# that matter for C/C++ targets. The entrypoint itself cannot be used here:
# it starts with `sysctl -w vm.mmap_rnd_bits=28`, which fails under
# unprivileged `docker build` (read-only /proc/sys). Steps, in order:
#   1. validate SANITIZER;
#   2. stage libFuzzer as $LIB_FUZZING_ENGINE. Three base-image layouts are
#      supported: the modern per-triple libclang_rt.fuzzer.a, the per-arch
#      lib/linux/libclang_rt.fuzzer-<arch>.a (anchored on uname -m so another
#      architecture's runtime can never be picked), and the 2017-era layout
#      that ships libFuzzer as sources under $SRC/libfuzzer with no prebuilt
#      runtime at all — compiled on the fly exactly like that era's
#      compile_libfuzzer (with the RAW CXXFLAGS, before the coverage flags
#      are merged in);
#   4. merge the sanitizer flags (SANITIZER_FLAGS_${SANITIZER}) and the
#      coverage flags into CFLAGS/CXXFLAGS, as compile does;
#   5. for UBSan, drop the "function" check (compile disables it for C code);
#   6. for MSan, stage the MSan-instrumented libc++ from /usr/msan — and FAIL
#      FAST when the base image has none: building an MSan target against
#      uninstrumented libc++ yields false-positive crashes that would
#      silently poison the clean_fix verification downstream. The copy goes
#      both to the modern per-triple dir and to /usr/lib (where the
#      2017-era toolchain resolves it), so either era links the right libc++.
#   7. run the project's build.sh and require $OUT/$FUZZER to exist.
#
# Expected environment (set by the Dockerfiles and the base image): SANITIZER,
# FUZZER, and the OSS-Fuzz build env (CFLAGS, CXXFLAGS_EXTRA, COVERAGE_FLAGS,
# ARCHITECTURE, OUT, SRC, WORK, LIB_FUZZING_ENGINE).

case "${SANITIZER}" in
    address|memory|undefined) ;;
    *)
        echo "ERROR: unknown SANITIZER '${SANITIZER}': expected address, memory or undefined" >&2
        exit 1
        ;;
esac

engine="${LIB_FUZZING_ENGINE:-/usr/lib/libFuzzingEngine.a}"
rt="$(ls /usr/local/lib/clang/*/lib/${ARCHITECTURE}-unknown-linux-gnu/libclang_rt.fuzzer.a 2>/dev/null | head -1)"
if [[ -z "$rt" ]]; then
    # This layout names the runtime per architecture (fuzzer-i386.a,
    # fuzzer-x86_64.a, ...); anchor the glob on the machine we are
    # actually building for, or head -1 happily picks the alphabetically
    # first — the wrong architecture (i386 on amd64) — and the final link
    # fails with "skipping incompatible /usr/lib/libFuzzingEngine.a".
    # $ARCHITECTURE cannot drive the suffix: the arm64 image's value is a
    # stale x86_64.
    rt="$(ls /usr/local/lib/clang/*/lib/linux/libclang_rt.fuzzer-$(uname -m).a 2>/dev/null | head -1)"
fi
if [[ -n "$rt" ]]; then
    cp "$rt" "$engine"
elif [[ -d "$SRC/libfuzzer" ]]; then
    # 2017-era base image: libFuzzer ships as sources; the era's
    # compile_libfuzzer built them with the RAW CXXFLAGS (no coverage
    # flags) plus the sanitizer flags and -fno-sanitize=vptr, archived
    # into $LIB_FUZZING_ENGINE. Reproduce that verbatim.
    flags="SANITIZER_FLAGS_${SANITIZER}"
    mkdir -p "$WORK/libfuzzer"
    ( cd "$WORK/libfuzzer" \
      && "$CXX" $CXXFLAGS -std=c++11 -O2 ${!flags} -fno-sanitize=vptr \
           -c "$SRC"/libfuzzer/*.cpp -I"$SRC/libfuzzer" \
      && ar r "$engine" "$WORK"/libfuzzer/*.o ) \
      || { echo "ERROR: building libFuzzer from $SRC/libfuzzer failed" >&2; exit 1; }
    rm -rf "$WORK/libfuzzer"
else
    echo "ERROR: no libclang_rt.fuzzer runtime in the base image and no $SRC/libfuzzer sources to build one from" >&2
    exit 1
fi

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
    mkdir -p /usr/local/lib/x86_64-unknown-linux-gnu
    cp -R /usr/msan/lib/* /usr/local/lib/x86_64-unknown-linux-gnu/
    cp -R /usr/msan/lib/* /usr/lib/
    cp -R /usr/msan/include/* /usr/local/include
fi

bash -eux /src/build.sh

if [[ ! -x "$OUT/$FUZZER" ]]; then
    echo "ERROR: build.sh did not produce $OUT/$FUZZER" >&2
    exit 1
fi
