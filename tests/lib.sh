#!/usr/bin/env bash
# lib.sh - shared assertions for the acc bash test suite.
# Sourced by each tests/test-*.sh script.  Uses $ACC_BIN (the binary under
# test), $REPO_DIR (repo root), and $WORK_DIR (per-test scratch directory),
# all exported by tests/run-tests.sh.

checks=0
failures=0

ok() {
	checks=$((checks + 1))
	echo "  ok: $*"
}

bad() {
	failures=$((failures + 1))
	checks=$((checks + 1))
	echo "  FAIL: $*"
}

# assert_eq <actual> <expected> <message>
assert_eq() {
	if [ "$1" = "$2" ]; then
		ok "$3"
	else
		bad "$3: got [$1] want [$2]"
	fi
}

# assert_match <extended-regex> <text> <message>
assert_match() {
	if printf '%s\n' "$2" | grep -qE -- "$1"; then
		ok "$3"
	else
		bad "$3: [$2] does not match /$1/"
	fi
}

# assert_exit <expected-code> <message> <command...>
assert_exit() {
	local want=$1 msg=$2
	shift 2
	"$@" >/dev/null 2>&1
	local got=$?
	if [ "$got" -eq "$want" ]; then
		ok "$msg (exit $want)"
	else
		bad "$msg: exit=$got want=$want"
	fi
}

# finish prints the per-script summary and exits 0 iff nothing failed.
finish() {
	echo "-- $(basename "$0"): $((checks - failures))/$checks checks passed"
	[ "$failures" -eq 0 ]
}
