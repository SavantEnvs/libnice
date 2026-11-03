#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# libnice's own assertion tests (built by mayhem/build.sh with normal flags). Each aborts on a failed
# assertion, but a binary that simply exits 0 would also pass, so the real oracle is the known-answer
# probes in mayhem/selftest.c: their stdout is diffed line by line against mayhem/selftest.expected
# (RFC 5389 HMAC-SHA1 + CRC32 message, MD5 credential hash, address parsing, a candidate SDP
# round-trip, and a pseudotcp transfer whose SHA-1 is checked).
T="$SRC/build/test"
UPSTREAM_TESTS=(
  stun/tests/test-parse stun/tests/test-format stun/tests/test-hmac stun/tests/test-conncheck
  stun/tests/test-bind random/nice-random-test
  tests/nice-test-address tests/nice-test-priority tests/nice-test-credentials
  tests/nice-test-pseudotcp tests/nice-test-pseudotcp-fin tests/nice-test-bsd tests/nice-test
  tests/nice-test-fullmode tests/nice-test-drop-invalid tests/nice-test-add-remove-stream
  tests/nice-test-socket-is-based-on tests/nice-test-thread tests/nice-test-turn tests/nice-test-tcp
  tests/nice-test-icetcp tests/nice-test-new-trickle tests/nice-test-restart tests/nice-test-fallback
  tests/nice-test-different-number-streams tests/nice-test-trickle tests/nice-test-consent
  tests/nice-test-bytestream-tcp tests/nice-test-send-recv tests/nice-test-udp-turn-fragmentation
  tests/nice-test-nomination
)

passed=0; failed=0
for t in "${UPSTREAM_TESTS[@]}"; do
  if [ ! -x "$T/$t" ]; then echo "FAIL $t: not built (mayhem/build.sh bug)"; failed=$((failed+1)); continue; fi
  if (cd "$T" && timeout 300 "./$t" >/tmp/libnice-test.out 2>&1); then
    echo "PASS $t"; passed=$((passed+1))
  else
    echo "FAIL $t"; tail -5 /tmp/libnice-test.out; failed=$((failed+1))
  fi
done

if [ ! -x "$T/mayhem_selftest" ]; then
  echo "FAIL mayhem_selftest: not built (mayhem/build.sh bug)"; failed=$((failed+1))
else
  timeout 120 "$T/mayhem_selftest" > /tmp/libnice-kat.out 2>/dev/null
  # one test per golden line, so a probe that prints nothing fails them all
  n=0
  while IFS= read -r want; do
    n=$((n+1))
    got=$(sed -n "${n}p" /tmp/libnice-kat.out)
    if [ "$got" = "$want" ]; then passed=$((passed+1)); else
      echo "FAIL kat line $n: want [$want] got [$got]"; failed=$((failed+1)); fi
  done < "$SRC/mayhem/selftest.expected"
  if [ "$(wc -l < /tmp/libnice-kat.out)" -ne "$n" ]; then
    echo "FAIL kat: output has $(wc -l < /tmp/libnice-kat.out) lines, expected $n"; failed=$((failed+1)); fi
fi

emit_ctrf "libnice-upstream+kat" "$passed" "$failed" 0
