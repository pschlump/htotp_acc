#!/usr/bin/env bash
# test-02-verify.sh - --verify in both forms: --get2fa <name> --verify <code>
# and standalone --verify <name>:<code>.  Exit codes: 0 verified, 1 not.

set -u
. "$(dirname "$0")/lib.sh"

WORK_DIR="$TEST_TMP/02-verify"
mkdir -p "$WORK_DIR"
CFG="$WORK_DIR/acc.cfg.json"
NAME="verify-test"

"$ACC_BIN" -cfg "$CFG" -create-update "$NAME" -secret JBSWY3DPEHPK3PXP -issuer Example >/dev/null 2>&1

PIN=$("$ACC_BIN" -cfg "$CFG" -get2fa "$NAME" -is_script)
assert_match '^[0-9]{6}$' "$PIN" "get2fa prints a 6-digit code"

# A definitely-wrong code: flip the first digit.
if [ "${PIN#0}" = "$PIN" ]; then
	WRONG="0${PIN:1}"
else
	WRONG="1${PIN:1}"
fi

# Paired form: --get2fa <name> --verify <code>
OUT=$("$ACC_BIN" -cfg "$CFG" -get2fa "$NAME" -is_script -verify "$PIN" 2>&1)
RC=$?
assert_eq "$RC" "0" "paired verify of correct pin exits 0"
assert_match 'Verified: '"$PIN" "$OUT" "paired verify reports Verified"

OUT=$("$ACC_BIN" -cfg "$CFG" -get2fa "$NAME" -is_script -verify "$WRONG" 2>&1)
RC=$?
assert_eq "$RC" "1" "paired verify of wrong pin exits 1"
assert_match 'Failed To Verify' "$OUT" "paired verify reports failure"

# Standalone form: --verify <name>:<code>  (no --get2fa needed)
OUT=$("$ACC_BIN" -cfg "$CFG" -verify "$NAME:$PIN" 2>&1)
RC=$?
assert_eq "$RC" "0" "standalone verify of correct pin exits 0"
assert_match 'Verified: '"$PIN" "$OUT" "standalone verify reports Verified"

OUT=$("$ACC_BIN" -cfg "$CFG" -verify "$NAME:$WRONG" 2>&1)
RC=$?
assert_eq "$RC" "1" "standalone verify of wrong pin exits 1"
assert_match 'Failed To Verify' "$OUT" "standalone verify reports failure"

# Entry names can themselves contain a colon ("/issuer:user"); the split
# must happen on the LAST colon of the argument.
"$ACC_BIN" -cfg "$CFG" -create-update dave@2c-why.com -secret JBSWY3DPEHPK3PXP -issuer www.example.com >/dev/null 2>&1
FULL=$("$ACC_BIN" -cfg "$CFG" -list | grep 'dave@')
PIN2=$("$ACC_BIN" -cfg "$CFG" -get2fa "${FULL#/}" -is_script)
OUT=$("$ACC_BIN" -cfg "$CFG" -verify "$FULL:$PIN2" 2>&1)
RC=$?
assert_eq "$RC" "0" "standalone verify with colon-in-name exits 0"
assert_match 'Verified: '"$PIN2" "$OUT" "colon-in-name verify reports Verified"

# Missing colon is a usage error.
OUT=$("$ACC_BIN" -cfg "$CFG" -verify "$PIN" 2>&1)
RC=$?
assert_eq "$RC" "1" "standalone verify without colon exits 1"
assert_match 'Usage' "$OUT" "standalone verify without colon prints usage"

# Unknown entry name fails.
assert_exit 1 "standalone verify of unknown entry exits 1" "$ACC_BIN" -cfg "$CFG" -verify "nobody:$PIN"

finish
