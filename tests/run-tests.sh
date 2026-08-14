#!/usr/bin/env bash
# run-tests.sh - build acc and run every tests/test-*.sh script.
# Exits 0 iff all tests pass.

set -u

cd "$(dirname "$0")/.." || exit 1
export REPO_DIR="$(pwd)"

TMP="$(mktemp -d /tmp/acc-bash-tests.XXXXXX)" || exit 1
trap 'rm -rf "$TMP"' EXIT

echo "Building acc binary..."
if ! go build -o "$TMP/acc" .; then
	echo "FATAL: build failed"
	exit 1
fi
export ACC_BIN="$TMP/acc"
export TEST_TMP="$TMP"

# Tests use fixed (throwaway) secrets and the UWCedar.png QR fixture, whose
# site no longer exists - no real credentials are involved.
unset ACC_CFG ACC_ENCRYPT_PW

pass=0
fail=0
failed=()

for t in "$REPO_DIR"/tests/test-*.sh; do
	echo
	echo "======================================================================"
	echo "== $(basename "$t")"
	echo "======================================================================"
	if bash "$t"; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
		failed+=("$(basename "$t")")
	fi
done

echo
echo "======================================================================"
if [ "$fail" -eq 0 ]; then
	echo "ALL PASSED: $pass test scripts, 0 failures"
	exit 0
fi
echo "FAILURES:   ${failed[*]}"
echo "PASSED: $pass test scripts, FAILED: $fail"
exit 1
