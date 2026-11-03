#!/usr/bin/env bash
#
# mayhem/build.sh — build the libnice fuzz harnesses, their standalone reproducers and the oracle.
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem, offline and re-runnable.
#   build/fuzz  sanitized static libnice (SANITIZER_FLAGS + DEBUG_FLAGS) that the harnesses link
#   build/test  independent normal-flags build of upstream's tests, run by mayhem/test.sh
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

MESON_COMMON=(--wrap-mode=nodownload -Dtests=disabled -Dexamples=disabled -Dgstreamer=disabled
  -Dgupnp=disabled -Dintrospection=disabled -Dgtk_doc=disabled)

# 1) Sanitized static libnice. `-fsanitize=fuzzer-no-link` adds coverage instrumentation to the library
#    itself, which is what lets libFuzzer see edges inside the fuzzed code.
rm -rf build/fuzz
CFLAGS="$SANITIZER_FLAGS -O1 $DEBUG_FLAGS -fsanitize=fuzzer-no-link" LDFLAGS="$SANITIZER_FLAGS" \
  meson setup build/fuzz "${MESON_COMMON[@]}" -Ddefault_library=static -Dbuildtype=plain
ninja -C build/fuzz -j"$MAYHEM_JOBS"

# 2) Each harness twice: libFuzzer binary and the run-once `-standalone` reproducer. Both link the
#    leak-sanitizer-off hook (leaks are not what this fleet fuzzes for).
GLIB_CFLAGS=$(pkg-config --cflags gio-2.0 gthread-2.0)
SYS_LIBS="$(pkg-config --libs gio-2.0 gthread-2.0 gnutls) -lm"
NICE_INC=(-I"$SRC" -I"$SRC/stun" -I"$SRC/agent" -I"$SRC/socket" -I"$SRC/random" -I"$SRC/nice"
  -I"$SRC/build/fuzz" -I"$SRC/build/fuzz/nice")
OBJ=build/fuzz/mayhem-obj
mkdir -p "$OBJ"
# shellcheck disable=SC2086
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OBJ/lsan_off.o"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
for h in fuzz_stun_message fuzz_stun_usages fuzz_pseudotcp fuzz_sdp; do
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS -O1 $DEBUG_FLAGS -fsanitize=fuzzer-no-link "${NICE_INC[@]}" $GLIB_CFLAGS \
    -c "mayhem/harnesses/$h.c" -o "$OBJ/$h.o"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $LIB_FUZZING_ENGINE "$OBJ/$h.o" "$OBJ/lsan_off.o" build/fuzz/nice/libnice.a \
    $SYS_LIBS -o "$SRC/$h"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS "$OBJ/standalone_main.o" "$OBJ/$h.o" "$OBJ/lsan_off.o" build/fuzz/nice/libnice.a \
    $SYS_LIBS -o "$SRC/$h-standalone"
done

# 3) Upstream's tests with the project's NORMAL flags, plus mayhem/selftest.c (known-answer probes),
#    so mayhem/test.sh only runs what is built here.
rm -rf build/test
env -u CFLAGS -u CXXFLAGS -u LDFLAGS \
  CFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
  meson setup build/test "${MESON_COMMON[@]}" -Dtests=enabled -Dbuildtype=debugoptimized
ninja -C build/test -j"$MAYHEM_JOBS"
# shellcheck disable=SC2086
$CC -O1 $COVERAGE_FLAGS "${NICE_INC[@]}" -I"$SRC/build/test" -I"$SRC/build/test/nice" $GLIB_CFLAGS \
  mayhem/selftest.c -Wl,--start-group build/test/agent/libagent.a build/test/stun/libstun.a \
  build/test/socket/libsocket.a build/test/random/libnice-random.a -Wl,--end-group \
  $SYS_LIBS -o build/test/mayhem_selftest
