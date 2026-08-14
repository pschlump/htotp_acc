#!/usr/bin/env bash
# test-04-output-ttl.sh - --get2fa output modes: --output file contents,
# --show-ttl format, and the error path when the output file cannot be
# written (must exit 1 and say so, not fail silently).

set -u
. "$(dirname "$0")/lib.sh"

WORK_DIR="$TEST_TMP/04-output-ttl"
mkdir -p "$WORK_DIR"
CFG="$WORK_DIR/acc.cfg.json"
NAME="output-test"
OUTFILE="$WORK_DIR/pin.txt"

"$ACC_BIN" -cfg "$CFG" -create-update "$NAME" -secret JBSWY3DPEHPK3PXP -issuer Example >/dev/null 2>&1

# --is_script prints the bare code.
OUT=$("$ACC_BIN" -cfg "$CFG" -get2fa "$NAME" -is_script)
assert_match '^[0-9]{6}$' "$OUT" "is_script prints a bare 6-digit code"

# --show-ttl prints "<code> <seconds-left>" with seconds within the window.
OUT=$("$ACC_BIN" -cfg "$CFG" -get2fa "$NAME" -is_script -show-ttl)
assert_match '^[0-9]{6} [0-9]+$' "$OUT" "show-ttl prints '<code> <seconds>'"
TTL=$(printf '%s\n' "$OUT" | awk '{print $2}')
if [ "$TTL" -ge 1 ] && [ "$TTL" -le 30 ]; then
	ok "ttl ($TTL) is within 1..30"
else
	bad "ttl out of range: got $TTL want 1..30"
fi

# --output writes the code (plus newline) to the file.
rm -f "$OUTFILE"
assert_exit 0 "--output succeeds" "$ACC_BIN" -cfg "$CFG" -get2fa "$NAME" -is_script -output "$OUTFILE"
if [ -f "$OUTFILE" ]; then
	ok "output file was created"
else
	bad "output file was not created: $OUTFILE"
fi
assert_match '^[0-9]{6}$' "$(tr -d '\n' <"$OUTFILE")" "output file contains the 6-digit code"

# The written code is the one that verifies right now.
OUT=$("$ACC_BIN" -cfg "$CFG" -verify "$NAME:$(tr -d '\n' <"$OUTFILE")" 2>&1)
RC=$?
assert_eq "$RC" "0" "code from --output file verifies"
assert_match 'Verified:' "$OUT" "verify of file code reports Verified"

# Unwritable output path must exit 1 with an error on stderr, not silently
# skip writing.
BAD="$WORK_DIR/no-such-dir/pin.txt"
OUT=$("$ACC_BIN" -cfg "$CFG" -get2fa "$NAME" -is_script -output "$BAD" 2>&1 >/dev/null)
RC=$?
assert_eq "$RC" "1" "unwritable --output exits 1"
assert_match 'Unable to write output' "$OUT" "unwritable --output reports the error"

finish
