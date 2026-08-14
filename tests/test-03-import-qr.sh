#!/usr/bin/env bash
# test-03-import-qr.sh - QR code analysis with example-QR.png (a defunct site;
# safe test data).  Imports the QR, then cross-checks the stored entry
# against the URI that `qr-decode` reads out of the same image, and
# round-trips a generated code through --verify.

set -u
. "$(dirname "$0")/lib.sh"

WORK_DIR="$TEST_TMP/03-import-qr"
mkdir -p "$WORK_DIR"
CFG="$WORK_DIR/acc.cfg.json"
QR="$REPO_DIR/tests/example-QR.png"

ENTRY="uwcedar.io:pschlump@uwyo.edu"
SECRET_UPPER="UN6C5CZBZ6TQ7BRVPCD2STWDTJ5RTQXF"

# --- Import the QR code -------------------------------------------------
OUT=$("$ACC_BIN" -cfg "$CFG" -import "$QR" 2>&1)
assert_match 'Successfully imported /'"$ENTRY" "$OUT" "import reports the entry name"
OUT=$("$ACC_BIN" -cfg "$CFG" -list)
assert_eq "$OUT" "/$ENTRY" "imported entry appears in -list"

# --- Cross-check with qr-decode -----------------------------------------
# qr-decode prints the text encoded in the QR; the secret in the otpauth://
# URI must match what acc stored.
if command -v qr-decode >/dev/null 2>&1; then
	# qr-decode prefixes its output with the decoded file's name.
	URI=$(qr-decode "$QR" | sed -E 's/^[^:]*: //')
	assert_match '^otpauth://totp/' "$URI" "qr-decode reads an otpauth URI"
	QR_SECRET=$(printf '%s\n' "$URI" | sed -E 's/.*[?&]secret=([^&]+).*/\1/')
	assert_eq "$(printf '%s' "$QR_SECRET" | tr 'a-z' 'A-Z')" "$SECRET_UPPER" "qr-decode secret matches fixture"
	STORED=$("$ACC_BIN" -cfg "$CFG" -get-secret "$ENTRY")
	assert_eq "$STORED" "$(printf '%s' "$QR_SECRET" | tr 'a-z' 'A-Z')" "stored secret matches the QR's secret"
	ISSUER=$(printf '%s\n' "$URI" | sed -E 's/.*[?&]issuer=([^&]+).*/\1/')
	assert_eq "$ISSUER" "uwcedar.io" "qr-decode issuer matches fixture"
else
	echo "  SKIP: qr-decode not found on PATH - cross-check skipped"
	echo "  (checked: entry present in config)"
fi

# --- Generate a code for the imported entry and verify it ---------------
PIN=$("$ACC_BIN" -cfg "$CFG" -get2fa "$ENTRY" -is_script)
assert_match '^[0-9]{6}$' "$PIN" "get2fa generates a code from the imported QR secret"
OUT=$("$ACC_BIN" -cfg "$CFG" -verify "$ENTRY:$PIN" 2>&1)
RC=$?
assert_eq "$RC" "0" "standalone verify of generated code exits 0"
assert_match 'Verified: '"$PIN" "$OUT" "generated code verifies"

# --- --gen-qr round-trips the provisioning URI ---------------------------
OUT=$("$ACC_BIN" -cfg "$CFG" -gen-qr "$ENTRY" 2>&1)
assert_match "URI: otpauth://totp/" "$OUT" "gen-qr prints the provisioning URI"
assert_match "secret=$SECRET_UPPER" "$OUT" "gen-qr URI contains the stored secret"
assert_match "issuer=uwcedar.io" "$OUT" "gen-qr URI contains the issuer"

# --- Re-import updates rather than duplicates ---------------------------
"$ACC_BIN" -cfg "$CFG" -import "$QR" >/dev/null 2>&1
assert_eq "$("$ACC_BIN" -cfg "$CFG" -list | grep -c "^/$ENTRY$")" "1" "re-import does not duplicate the entry"

finish
