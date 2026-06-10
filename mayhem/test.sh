#!/usr/bin/env bash
#
# go-ldap/mayhem/test.sh — RUN go-ldap/ldap's OWN Go unit-test suite (`go test ./...` in v3/) and
# emit a CTRF summary. exit 0 iff no test failed.
#
# PATCH-grade oracle: go-ldap's suite is a REAL known-answer suite — dn_test.go (ParseDN golden
# results), filter_test.go (filter compile/decode golden bytes), control_test.go, error_test.go's
# TestGetLDAPError (asserts result codes + messages for crafted BER packets — the exact decoder the
# fuzzer hits), bind/add/del/control marshalling, etc. They assert BEHAVIOUR/known answers, not
# "exits 0", so a no-op / `return nil` patch that breaks decode/encode FAILS this oracle.
#
# We SKIP the live-server integration tests (TestSearch*, TestConn_*, Test*DialURL, TestStartTLS,
# TestCompare, TestExtendedRequest_*, TestMatchDNError, TestMultiGoroutineSearch,
# TestTLSConnectionState, TestEntry_UnmarshalFunc, TestUnsecureDialURL) — these require a running
# OpenLDAP container (Makefile `local-server`, dials 127.0.0.1:3389/3636) and fail with
# "connection refused" in any serverless CI. They exercise the network client, NOT the parser the
# fuzzer targets, so excluding them keeps the oracle HONEST (green on a clean baseline) without
# weakening the asserted-behaviour parser/encoder tests.
#
# This script only RUNS the suite (go test compiles+runs in one step, but with the project's own
# normal flags — no sanitizer/fuzz build here).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

export PATH="/opt/toolchains/go/bin:/opt/toolchains/go-path/bin:/usr/local/go/bin:$PATH"
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
export GOPATH="${GOPATH:-/opt/toolchains/go-path}"
export GOCACHE="${GOCACHE:-/opt/toolchains/go-path/build-cache}"
export GOMODCACHE="${GOMODCACHE:-/opt/toolchains/go-path/pkg/mod}"

# Live-server integration tests to skip (need an OpenLDAP server; not the fuzzed parser surface).
SKIP_RE='^(TestCompare|TestConn_Add|TestConn_Bind|TestConn_Del|TestConn_Extended|TestConn_UnauthenticatedBind|TestConn_Unbind|TestConn_WhoAmI|TestEntry_UnmarshalFunc|TestExtendedRequest_FastBind|TestExtendedRequest_WhoAmI|TestMatchDNError|TestMultiGoroutineSearch|TestSearch|TestSearchAsync|TestSearchAsyncAndCancel|TestSearchStartTLS|TestSearchWithPaging|TestSecureDialURL|TestStartTLS|TestTLSConnectionState|TestUnsecureDialURL)$'

cd "$SRC/v3"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

if ! command -v go >/dev/null 2>&1; then
  echo "go not available — cannot run the test suite" >&2
  emit_ctrf "go-test" 0 1 0; exit 2
fi

echo "=== running: go test -skip '<live-server>' -json ./... ==="
# -json gives machine-parseable per-test events; mirror stdout for humans via a separate pass.
JSON="$SRC/mayhem-build/gotest.json"
mkdir -p "$SRC/mayhem-build"
go test -skip "$SKIP_RE" -json ./... > "$JSON" 2>"$SRC/mayhem-build/gotest.err"; rc=$?

# Show package-level summary + any build/test errors for humans.
go test -skip "$SKIP_RE" ./... 2>&1 | tail -40 || true
[ -s "$SRC/mayhem-build/gotest.err" ] && { echo "--- stderr ---"; tail -20 "$SRC/mayhem-build/gotest.err"; }

# Count test-level events (lines that carry a non-empty "Test" field). Subtests included — they
# are real asserted cases. Package-level pass/fail lines have no "Test" field and are excluded.
count_act() { grep "\"Action\":\"$1\"" "$JSON" 2>/dev/null | grep -c "\"Test\":"; }
PASSED=$(count_act pass); FAILED=$(count_act fail); SKIPPED=$(count_act skip)
: "${PASSED:=0}" "${FAILED:=0}" "${SKIPPED:=0}"

# Build failures / no-tests-compiled: go test exits non-zero but may emit no test events.
if [ "$(( PASSED + FAILED + SKIPPED ))" -eq 0 ]; then
  echo "no test events parsed; using go exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "go-test" 1 0 0; exit 0; }
  emit_ctrf "go-test" 0 1 0; exit 1
fi

# Trust the parsed failures; if go reported a non-zero exit but we counted 0 failures (e.g. a
# package build error), force a failure so the oracle is honest.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then FAILED=1; fi

# ── Behavioral probe via the dynamically-linked fuzz_get_ldap_error binary (anti-reward-hacking, §6.3) ──
# Go test binaries are statically linked, so the LD_PRELOAD sabotage mechanism cannot neuter them.
# /mayhem/fuzz_get_ldap_error IS dynamically linked (built with clang+ASan). Run it single-shot
# against a known BER-encoded LDAP corpus entry and assert that libFuzzer emits "Executed" —
# proving it actually processed the input. The sabotage LD_PRELOAD neuters fuzz_get_ldap_error
# (not in /usr/bin etc.), causing it to exit silently → the grep fails → FAILED increments →
# the oracle is NOT reward-hackable.
PROBE_INPUT="$SRC/mayhem/testsuite/bindresponse_success.ber"
if [ -x /mayhem/fuzz_get_ldap_error ] && [ -f "$PROBE_INPUT" ]; then
  echo "=== behavioral probe: fuzz_get_ldap_error single-shot on known corpus ==="
  PROBE_OUT=$(/mayhem/fuzz_get_ldap_error "$PROBE_INPUT" 2>&1 || true)
  if echo "$PROBE_OUT" | grep -q "Executed"; then
    echo "PROBE PASS: fuzz_get_ldap_error executed the corpus input (BER decoder active)"
    PASSED=$(( PASSED + 1 ))
  else
    echo "PROBE FAIL: fuzz_get_ldap_error produced no 'Executed' output (decoder inactive or sabotaged)"
    echo "Output was: $PROBE_OUT"
    FAILED=$(( FAILED + 1 ))
  fi
fi

emit_ctrf "go-test" "$PASSED" "$FAILED" "$SKIPPED"
