#!/usr/bin/env bash
# test-01-config.sh - config file creation, --create-update, --list, --get-secret, --delete.

set -u
. "$(dirname "$0")/lib.sh"

WORK_DIR="$TEST_TMP/01-config"
mkdir -p "$WORK_DIR"
CFG="$WORK_DIR/acc.cfg.json"

# A missing config is created empty on first use (the warning goes to stdout
# on that first invocation only, so capture it in the same run).
"$ACC_BIN" -cfg "$CFG" -list >"$WORK_DIR/list.out" 2>"$WORK_DIR/list.err"
RC=$?
assert_eq "$RC" "0" "list on missing config succeeds"
assert_match 'creating new config' "$(cat "$WORK_DIR/list.out")" "warns that a new config was created"

# --create-update stores an entry; --list shows it.
OUT=$("$ACC_BIN" -cfg "$CFG" -create-update bob -secret JBSWY3DPEHPK3PXP -issuer Example 2>&1)
assert_match 'Successfully imported|Successfully' "$OUT" "create-update reports success"
OUT=$("$ACC_BIN" -cfg "$CFG" -list)
assert_eq "$OUT" "/Example:bob" "list shows the new entry"

# --get-secret returns the stored secret.
OUT=$("$ACC_BIN" -cfg "$CFG" -get-secret bob)
assert_eq "$OUT" "JBSWY3DPEHPK3PXP" "get-secret returns the secret"

# A lowercase secret is normalized to uppercase (the htotp decoder only
# accepts uppercase base32 - lowercase secrets used to hang --get2fa).
"$ACC_BIN" -cfg "$CFG" -create-update carol -secret jbswy3dpehpk3pxp -issuer Example >/dev/null 2>&1
OUT=$("$ACC_BIN" -cfg "$CFG" -get-secret carol)
assert_eq "$OUT" "JBSWY3DPEHPK3PXP" "lowercase secret is stored uppercase"

# Re-running --create-update on the same name updates, not duplicates.
"$ACC_BIN" -cfg "$CFG" -create-update bob -secret JBSWY3DPEHPK3PXP -issuer Example >/dev/null 2>&1
assert_eq "$("$ACC_BIN" -cfg "$CFG" -list | grep -c '^/Example:bob$')" "1" "update does not duplicate the entry"

# --delete removes the entry.
OUT=$("$ACC_BIN" -cfg "$CFG" -delete bob 2>&1)
assert_match 'Deleted' "$OUT" "delete reports success"
OUT=$("$ACC_BIN" -cfg "$CFG" -list)
assert_eq "$OUT" "/Example:carol" "deleted entry no longer listed"

# --get-secret on an unknown name fails with a nonzero exit.
assert_exit 1 "get-secret on missing entry fails" "$ACC_BIN" -cfg "$CFG" -get-secret nobody

finish
