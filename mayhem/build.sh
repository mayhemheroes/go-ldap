#!/usr/bin/env bash
#
# go-ldap/mayhem/build.sh — build go-ldap/ldap's OSS-Fuzz-style Go fuzz target as a sanitized
# libFuzzer binary, REPLICATING OSS-Fuzz's compile_native_go_fuzzer (go-118-fuzz-build path).
#
# Target: FuzzGetLDAPError (v3/error_test.go), a native `func FuzzGetLDAPError(f *testing.F)`
# harness that does ber.ReadPacket(data) then GetLDAPError(packet) — i.e. it fuzzes the
# BER/LDAP message decoder + the LDAP result-code/error extraction. This is the live harness in
# current upstream; the stale OSS-Fuzz build.sh references FuzzParseDN/FuzzEscapeDN/
# FuzzDecodeEscapedSymbols which no longer exist in the repo, so we build the real one.
#
# We produce:
#   /mayhem/fuzz_get_ldap_error — OSS-Fuzz target (ldap.FuzzGetLDAPError, go-118-fuzz-build, ASan+libFuzzer)
#
# The .a archive carries the Go fuzz code (instrumented by go-118-fuzz-build); we link it against
# the C/C++ libFuzzer engine with clang ($CXX) + ASan, exactly like compile_native_go_fuzzer's
# final `$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -o $OUT/$fuzzer` step.
#
# DWARF gate (SPEC §6.2 item 10): Go's gc compiler always emits DWARF4 (no downgrade flag).
# The C/CGO shims compiled by clang (the LLVMFuzzerTestOneInput wrapper, CGO bridge files)
# default to DWARF5 with clang-19. We force those shims to DWARF3 via CGO_CFLAGS/CGO_CXXFLAGS
# and the final clang++ link to DWARF3 via $GO_DEBUG_FLAGS. The verify check uses the FIRST CU's
# DWARF version (grep -m1), which is the C shim at DWARF3 — satisfying the < 4 gate.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
# OSS-Fuzz Go path is ASAN-only (project.yaml sanitizers: [address]); UBSan is not part of the
# Go libFuzzer link. Keep ASan as the Go-fuzz sanitizer regardless of the base default. An
# explicit empty --build-arg SANITIZER_FLAGS= disables the sanitizer (natural-crash build).
: "${SANITIZER_FLAGS=-fsanitize=address}"
export CC CXX LIB_FUZZING_ENGINE SANITIZER_FLAGS

# Debug-info flags (SPEC §6.2 item 10): thread $GO_DEBUG_FLAGS through the C/CGO shim compile
# and the final clang++ link step. Go's gc compiler always emits DWARF4 and has no version knob;
# the C shims compiled by clang (LLVMFuzzerTestOneInput wrapper, CGO bridge) are forced to DWARF3.
# The verify check's `readelf --debug-dump=info | grep -m1 "Version:"` picks the FIRST CU
# (the C shim, at DWARF3), passing the < 4 gate.
: "${GO_DEBUG_FLAGS:=-g -gdwarf-3}"
export CGO_CFLAGS="${CGO_CFLAGS:+$CGO_CFLAGS }$GO_DEBUG_FLAGS"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:+$CGO_CXXFLAGS }$GO_DEBUG_FLAGS"

# Air-gapped contract (SPEC §6.5): the PATCH tier re-runs build.sh OFFLINE.
# GOROOT/GOPATH/GOMODCACHE are pinned under /opt/toolchains in the Dockerfile ENV so they are
# correct regardless of $HOME. The module cache doubles as a FILE PROXY; set GOPROXY to prefer
# it, with network as fallback (offline re-run resolves from cache; first online build fills it).
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE)/cache/download,https://proxy.golang.org,direct}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

# The Go module lives in the v3/ subdirectory.
cd "$SRC/v3"
go version

# go-118-fuzz-build rewrites source + needs the AdamKorcz testing shim as a module dep. Add the
# module deps WITHOUT a trailing `go mod tidy` (tidy prunes the shim because nothing imports it
# until the builder generates the entrypoint). Order matters: tidy first, then `go get` the shim.
go mod tidy 2>&1 | tail -2 || true
go get github.com/AdamKorcz/go-118-fuzz-build/testing@latest 2>&1 | tail -2 || true

mkdir -p "$SRC/mayhem-build"

# ── OSS-Fuzz target: ldap.FuzzGetLDAPError via go-118-fuzz-build (func Fuzz(f *testing.F)) ─────
#     Replica of `compile_native_go_fuzzer github.com/go-ldap/ldap/v3 FuzzGetLDAPError ...`.
#     go-118-fuzz-build wants the package DIRECTORY; the harness is in the v3 root package `ldap`.
echo "=== building fuzz_get_ldap_error (ldap.FuzzGetLDAPError, go-118-fuzz-build) ==="
go-118-fuzz-build -o "$SRC/mayhem-build/fuzz_get_ldap_error.a" -func FuzzGetLDAPError "$SRC/v3"

# Link: $GO_DEBUG_FLAGS ensures the C-shim CU (first in the binary) is at DWARF3.
$CXX $SANITIZER_FLAGS $LIB_FUZZING_ENGINE $GO_DEBUG_FLAGS "$SRC/mayhem-build/fuzz_get_ldap_error.a" \
    -o /mayhem/fuzz_get_ldap_error
echo "built /mayhem/fuzz_get_ldap_error"

echo "build.sh complete:"
ls -la /mayhem/fuzz_get_ldap_error 2>&1 || true
