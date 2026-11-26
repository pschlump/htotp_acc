# ac - Command Line TOTP Authenticator

`acc` is a two-factor authenticator for the command line. It performs the same
function as Google Authenticator (RFC 6238 TOTP, SHA1, 6 digits, 30 second
window) but runs in a terminal, which makes it useful for:

- Testing logins that require two-factor authentication.
- Scripting and automation that needs current TOTP codes (e.g. `sudo` protected
  by `pam_google_authenticator`, CI pipelines, ssh-based tooling).

Secrets are stored in a config file (default `acc.cfg.json`, mode `0600`).

## Build

```
$ go build
```

This produces the `./acc` binary. `make` regenerates `version.go` with the git
commit, tag, and build date before building.

## Test

```
$ go test ./...
```

or

```
$ make test
```

The test suite covers the encryption helpers and runs the compiled CLI
end-to-end against throwaway config files (create, list, generate, verify,
delete, QR import, and error paths).

## Quick start

Save the QR code image presented by the site (or screen-capture it to a file),
then import it:

```
$ ./acc --import ~/Downloads/711210.png
Successfully imported /app.example.com:demo5@gmail.com
```

List the accounts in the config file:

```
$ ./acc --list
/app.example.com:demo5@gmail.com
```

Generate the current 2FA code:

```
$ ./acc --gen2fa "/app.example.com:demo5@gmail.com"
```

Without `--is_script` the code is copied to the clipboard and a countdown shows
how many seconds remain before the code rolls over.

## Adding an entry from a secret

If you have the base32 secret instead of a QR code:

```
$ ./acc --create-update bob@example.com --secret "CKDPKQHM3RWX456R" --issuer example.com
```

This creates (or updates) the entry `/example.com:bob@example.com`. Both
`--secret` and `--issuer` are required.

To create a new random secret (e.g. to enroll a server-side authenticator):

```
$ ./acc --create-new-secret
Secret: VZNZS2YL75EWJSHE
```

## Scripting / automation

`--is_script` prints just the code (no clipboard, no countdown), suitable for
capturing in a shell:

```
$ CODE=$(./acc --gen2fa "/example.com:bob@example.com" --is_script)
$ echo "$CODE"
483920
```

Use `--output <file>` to write the code to a file instead, and `--verify` to
check a code:

```
$ ./acc --gen2fa "/example.com:bob@example.com" --output ./out/,otk
$ ./acc --gen2fa "/example.com:bob@example.com" --verify "$(cat ./out/,otk)"
Verified: 483920 with user bob@example.com
```

`--gen2fa` and `--get2fa` are synonyms (`--gen2fa` exists because it is the
author's most common typo).

### Example: sudo with pam_google_authenticator

Store the sudo password with the entry and let `--sudo-pipe` emit
`password` and `TOTP` on two lines for `sudo -S`:

```
$ ./acc --create-update phil --secret "CKDPKQHM3RWX456R" --issuer myserver --password 'sudopassword'
$ ./acc --sudo-pipe myserver | ssh phil@myserver 'sudo -S id'
```

The password never appears in the command line, shell history, or transcripts —
only in the config file (use `--encrypted`/`$ACC_ENCRYPT_PW` to protect it).
Add `--min-ttl 10` to guarantee the code has at least 10 seconds of life left
before it is used.

Add `--no-reuse` when the server's PAM rejects a reused code
(`pam_google_authenticator`'s default `DISALLOW_REUSE`) and you run
back-to-back sudo commands: two invocations in the same 30-second window would
otherwise emit the identical code and the second one fails. With `--no-reuse`,
acc remembers the last window it emitted per entry (in a small state file —
`--state`, `$ACC_STATE`, or `acc.state.json` next to `--cfg`) and, if the
current window was already used, waits for the next one, emitting 2 seconds
into it so a slightly-behind server clock never sees a code from the future.

See `docs/exsms-2FA-setup.md` for the full setup notes of an example system
using 2FA with sudo, passwords, 2fA and this tool.

## Enrolling a new server / user

`--enroll` generates a random secret, stores the entry, and prints everything
needed to configure the server side (`google-authenticator`,
`pam_google_authenticator`, etc.):

```
$ ./acc --enroll phil --issuer myserver --qr phil-myserver.png
Name: /myserver:phil
Secret: VZNZS2YL75EWJSHE
URI: otpauth://totp/myserver:phil?secret=VZNZS2YL75EWJSHE&issuer=myserver
...
```

## Generating a QR code for an entry

`--gen-qr` renders a scannable QR code for an existing entry's provisioning URI
(so you can add an account you already have stored to a phone authenticator). By
default it prints compact terminal art:

```
$ ./acc --gen-qr myserver
URI: otpauth://totp/myserver:phil?secret=VZNZS2YL75EWJSHE&issuer=myserver

███ ▄▄▄▄▄ █ ▄▀█ ... ███
...
```

For reliable scanning, write a PNG and open it in Preview:

```
$ ./acc --gen-qr myserver --qr-file myserver.png --qr-view
URI: otpauth://totp/myserver:phil?secret=VZNZS2YL75EWJSHE&issuer=myserver
QR code written to: myserver.png
```

`--qr-view` opens the file with `open` (Preview on macOS; `xdg-open` on Linux).
The name accepts the same unique-substring match as the other commands.

## Audit logging

`acc` keeps an append-only audit log of every credential release
(`--sudo-pipe`) and every config mutation (`--create-update`, `--enroll`,
`--import`, `--delete`). It is **on by default and cannot be disabled** — there
is deliberately no `--audit-disable`. Offline/emergency operation uses the
`best-effort` policy, which still writes the local record.

```
$ acc --sudo-pipe "/myserver:phil" --min-ttl 10 --no-reuse \
      --audit-reason "deploy v1.2" --audit-issue CHG-123 \
      --audit-event-id-file /tmp/deploy.event-id \
  | ssh phil@myserver "sudo -S -p '' id"
```

### What is (and is not) recorded

`acc` can only attest to **credential release from this workstation**. It cannot
know whether SSH connected, whether PAM accepted the password/TOTP, whether sudo
succeeded, or what the remote command did. **Remote sshd, sudo and PAM logs stay
authoritative for actual privileged command execution**, and they are still
needed: manual entry, another workstation, console access, `ACC_PIPE=cat` or a
modified `acc` binary all bypass workstation instrumentation. Every operator
workstation that holds privileged credentials (for ExSMS: Philip's *and* Jake's)
needs this binary and its own sink configuration.

The log is **not tamper-proof against the workstation user**. Tamper
resistance comes from shipping records off-host to an immutable store. No
signature scheme is implemented.

Never logged: passwords, TOTP seeds or codes, the encryption password, bearer
tokens, config contents, provisioning URIs/QR data, parent-process arguments,
environment values, response bodies from the sink, or a user-supplied entry name
that failed to resolve (a pasted secret must not land in the log — only
`entry_resolve_failed` is recorded).

### Files, permissions, locking

| File | Purpose |
|---|---|
| `<log>` (default `acc.audit.jsonl` next to `--cfg`) | JSON Lines, append-only, never rewritten |
| `<log>.delivery.json` | delivery cursor (byte offset of the first unshipped record) |
| `<log>.lock` | `flock(2)` lock serializing append, flush and rotate across processes |
| `<log>.<UTC timestamp>` | archives from `--audit-rotate` |

All are regular files, mode `0600`; symlinks and non-regular files are refused
(an existing file with group/other permissions is refused too). A missing parent
directory is created `0700`; an existing directory is never chmod'ed. Each
record is one locked write followed by `fsync`; the cursor is replaced by temp
file + `fsync` + rename. A corrupt or partially written log is a **loud failure
that blocks credential release**, never skipped. The spool is capped at 64 MiB:
at the limit new releases are refused until records are shipped and the log is
rotated; nothing is truncated or dropped.

### `--sudo-pipe` lifecycle

1. A `requested` record is appended and fsynced **before** any TOTP is
   generated or any `--no-reuse` window is burned. If this fails: no stdout,
   exit 1.
2. The entry is resolved and the code generated (`--min-ttl`/`--no-reuse`
   unchanged). On failure a `blocked` record (static `error_code`) is appended,
   exit 1, no stdout.
3. An `emitted` record is appended and fsynced. It means *acc is about to
   release / released the pair to stdout* — **not** that remote auth or sudo
   succeeded.
4. Delivery per policy (below). Under `require`, nothing is written to stdout
   until the sink has accepted every record through `emitted`.
5. If `--audit-event-id-file` was given, the event UUID plus a newline is
   written atomically (0600). Failure means no stdout.
6. Exactly `<password>\n<totp>\n` goes to stdout. Audit warnings only go to
   stderr. The audit metadata is never an extra stdout line.

If delivery or the event-ID file fails after `emitted`, credentials are
withheld and a `blocked` record is appended, so the log honestly shows a record
that was emitted-then-withheld. A crash can leave a `requested` with no final
phase; `--audit-status` reports it as `unfinished_requests` rather than
inventing an outcome.

Config-change events (`acc.config_change`, action `create_update`, `enroll`,
`import` or `delete`) append `requested` before the mutation (an audit failure
prevents the change) and `applied` after the config is saved atomically. Only the
canonical target (`/issuer:user`, issuer, account) is recorded — never the
secret, password, URI or QR. A sink failure after a mutation leaves a pending
record and a warning; the config is never rolled back for it.

### Policies

* **`best-effort`** (default): the local append is mandatory. Delivery is tried
  within `--audit-timeout`; on failure all records stay pending, a sanitized
  warning goes to stderr, and the credentials are still released (exit 0).
* **`require`**: needs a sink (and a usable token file, if configured). Any
  delivery failure → no credentials, exit 1; records remain pending.

Under both policies a local append/fsync/cursor failure, event-ID-file failure
or log-integrity failure always blocks the release. With **no sink** configured
delivery mode is `local_only`: records are kept locally and do not count as
pending for a nonexistent destination. A sink configured later ships only
records appended after that point — there is **no backfill** of archived or
pre-configuration records, so configure the sink before the audited operation.

Exit codes: `2` usage/flag errors (including `--audit-policy require` without a
sink, a bad sink URL, or incompatible flags); `1` operational failures; `0`
success (including best-effort delivery failure with a successful release).

### HTTPS receiver contract

The default `json` sink format sends each pending record to a generic receiver.
The `loki` sink format instead wraps the same record in Loki's native push API.
Set `--audit-sink-format loki` (or `ACC_AUDIT_SINK_FORMAT=loki`) and use the
full push endpoint, for example:

```
export ACC_AUDIT_SINK=https://ops-box.agenticquartz.com/loki/loki/api/v1/push
export ACC_AUDIT_SINK_FORMAT=loki
export ACC_AUDIT_TOKEN_FILE=/path/to/0600-token-file
acc --audit-flush
```

Each Loki request has one stream with `job=acc`, the event `kind`, and the
`workstation` hostname as labels. Its value timestamp is `occurred_at` in
nanoseconds and its log line is the unchanged audit JSON event. Start with
`best-effort`, verify delivery and querying, then use `require` if credential
release must fail closed on a Loki outage. The doubled prefix above is specific
to the current ops-box Caddy route: Caddy strips the first `/loki`, and Loki
expects the second. A proxy that preserves the path should use the standard
single-`/loki` push URL instead.

For each pending record, in append order:

```
POST <audit-sink>
Content-Type: application/json
Accept: application/json
Authorization: Bearer <token>        (only if --audit-token-file is set)
Idempotency-Key: <record_id>
X-Acc-Audit-Record-Id: <record_id>

<the exact JSONL record as one JSON object, or its Loki push wrapper>
```

* Any `2xx` = accepted; the cursor advances only then.
* Network errors, `408`, `429`, `5xx` are retryable; the record stays pending.
* Any other status (including `3xx` — redirects are **never** followed) is a
  receiver/configuration error: the record stays pending and the flush stops. A
  poisoned record is never skipped.
* A crash after acceptance but before the cursor update, or a lost cursor file,
  resends records. Generic JSON receivers must be idempotent on `record_id`.
  Loki does not deduplicate push requests, so retries are at-least-once and
  consumers must use the line's `record_id` to recognize duplicates.
* HTTPS is required except for loopback test receivers. URLs with userinfo,
  query string or fragment are rejected, and the URL is never printed. The
  token file must be a regular, non-symlink `0600` file; one trailing newline is
  trimmed. During `--sudo-pipe` `--audit-timeout` is one budget for all pending
  records; `--audit-flush` applies it per request.

### Record schema (`schema_version` 1)

```json
{
  "schema_version": 1,
  "record_id": "UUID, unique per JSONL record (the idempotency key)",
  "event_id": "UUID shared by all phases of one operation",
  "kind": "acc.sudo_release | acc.config_change",
  "phase": "requested | emitted | blocked | applied",
  "occurred_at": "RFC3339Nano UTC",
  "tool": {"git_commit": "", "git_tag": "", "go_version": ""},
  "workstation": {"hostname": "", "os": "", "arch": "", "username": ""},
  "process": {"pid": 0, "ppid": 0, "parent_executable": "base name only", "terminal": false},
  "request": {"min_ttl_seconds": 0, "no_reuse": false, "reason": "", "issue": ""},
  "change": {"action": "create_update|enroll|import|delete", "reason": "", "issue": ""},
  "target": {"entry": "/issuer:user", "issuer": "", "account": ""},
  "audit": {"policy": "best-effort|require", "sink_configured": false},
  "result": {"outcome": "requested|credentials_emitted|blocked|applied", "error_code": "optional"}
}
```

`request` appears on `acc.sudo_release`, `change` on `acc.config_change`;
`target` is absent when an entry could not be resolved. Versioning policy:
adding optional fields keeps `schema_version`; removing/renaming a field or
changing its meaning increments it. Receivers should ignore unknown fields.
`error_code` values: `entry_resolve_failed`, `totp_generation_failed`,
`config_unavailable`, `audit_sink_config_invalid`, `audit_delivery_failed`,
`event_id_file_failed`, `config_write_failed`.

### Operations

```
$ acc --audit-status     # {"schema_version":1,"records":8,"pending":2,"delivery_mode":"https",
                         #  "oldest_pending_at":"...","sink_configured":true,
                         #  "last_delivery":"retryable_error","unfinished_requests":0}
$ acc --audit-flush      # retry in order; exit 0 only when nothing is pending;
                         # includes content-free http_status when the sink replied
$ acc --audit-rotate     # archive a fully shipped log, start a fresh 0600 log
```

These run **before** the authenticator config is created or decrypted: they work
without `ACC_ENCRYPT_PW`, never generate a TOTP, and never create an empty
config. `--audit-status` is content-free (no entry names, reasons, URLs, tokens).
`last_delivery` is `accepted`, `pending`, `retryable_error`, `config_error` or
`none`. `--audit-rotate` takes the same lock, verifies the log and cursor, refuses
while anything is pending, hard-links the log to a never-overwritten
`<log>.<UTC timestamp>` archive, swaps in a fresh log and reset cursor, and leaves
the original untouched on any failure. Rotation of a log that is empty or absent
is a no-op.

**Safe retention:** rotate only after `--audit-status` shows `pending: 0`; copy
the archive off-host (or confirm the immutable store already holds every
`record_id`) before deleting it. Deleting archives is an operator decision;
`acc` never deletes them.

## Environment variables

| Variable | Description |
|---|---|
| `ACC_CFG` | Default config file path (overridden by `--cfg`). |
| `ACC_ENCRYPT_PW` | Config encryption password (overridden by `--encrypted`). Required to read an encrypted config. |
| `ACC_STATE` | `--no-reuse` state file (overridden by `--state`). |
| `ACC_AUDIT_LOG` | Audit log path (overridden by `--audit-log`). |
| `ACC_AUDIT_SINK` | HTTPS audit receiver URL (overridden by `--audit-sink`). |
| `ACC_AUDIT_SINK_FORMAT` | `json` (default) or `loki` (overridden by `--audit-sink-format`). |
| `ACC_AUDIT_TOKEN_FILE` | File holding the sink bearer token (overridden by `--audit-token-file`). |
| `ACC_AUDIT_POLICY` | `best-effort` (default) or `require` (overridden by `--audit-policy`). |
| `ACC_TEST_SSH_HOST` | Tests only: enables the live `--check-time` test against this ssh host. |

## All flags

| Flag | Description |
|---|---|
| `--cfg <file>` | Config file path (default `$ACC_CFG` or `acc.cfg.json`). Created if missing. |
| `--import <png>` | Import a QR code image; adds or updates the entry. |
| `--create-update <user>` | Create/update an entry; requires `--secret` and `--issuer`. |
| `--secret <base32>` | Secret for `--create-update`. |
| `--issuer <name>` | Issuer/realm for `--create-update`/`--enroll`. |
| `--password <pw>` | Password stored with an entry (used by `--sudo-pipe`). |
| `--enroll <user>` | Generate a secret, store the entry, print the provisioning URI. Requires `--issuer`. |
| `--qr <png>` | With `--enroll`: also write a QR code image of the URI. |
| `--gen-qr <name>` | Generate a scannable QR code for an entry's provisioning URI (terminal art by default). |
| `--qr-file <png>` | With `--gen-qr`: write the QR as a PNG file instead of printing terminal art. |
| `--qr-view` | With `--gen-qr --qr-file`: open the PNG with the system viewer (Preview on macOS). |
| `--delete <name>` | Delete an entry by name (e.g. `/example.com:bob@example.com`). |
| `--list` | List all entry names in the config file. |
| `--get2fa <name>` | Generate the current TOTP code for an entry. |
| `--gen2fa <name>` | Typo-tolerant alias for `--get2fa`. |
| `--verify <code>` | With `--get2fa`: verify a code instead of generating one. |
| `--get-secret <name>` | Print the stored secret for an entry. |
| `--create-new-secret` | Generate and print a new random 16-char base32 secret. |
| `--sudo-pipe <name>` | Print `<password>\n<totp>` for piping into `sudo -S`. |
| `--min-ttl <secs>` | Wait for the next window if fewer than this many seconds remain on the code. |
| `--no-reuse` | Never emit the same TOTP window twice for an entry; waits for a fresh window (for replay-protected servers). |
| `--state <file>` | State file for `--no-reuse` (default `$ACC_STATE`, else `acc.state.json` next to `--cfg`). |
| `--show-ttl` | With `--is_script`: print `<code> <seconds-left>`. |
| `--check-time <host>` | Compare the local clock with `<host>` via ssh (detect TOTP skew). |
| `--is_script` | Machine-readable output only; skip clipboard and countdown. |
| `--output <file>` | Write the generated code to a file. |
| `--encrypted <pw>` | Encrypt the stored config data with this password (default `$ACC_ENCRYPT_PW`). |
| `--db_flag <flags>` | Comma-separated debug flags (`dump-db-flag` to list). |
| `--audit-log <file>` | JSONL audit log (default `$ACC_AUDIT_LOG`, else `acc.audit.jsonl` next to `--cfg`). |
| `--audit-sink <url>` | HTTPS receiver for audit records (default `$ACC_AUDIT_SINK`; none = local-only). `--audit-sink ""` forces local-only. |
| `--audit-sink-format <format>` | `json` (default) or `loki`; default `$ACC_AUDIT_SINK_FORMAT`. Use Loki's push API URL, including any reverse-proxy prefix. |
| `--audit-token-file <file>` | File (mode 0600) with the sink bearer token (default `$ACC_AUDIT_TOKEN_FILE`). The token is never accepted on the command line. |
| `--audit-policy <p>` | `best-effort` (default) or `require` (default `$ACC_AUDIT_POLICY`). |
| `--audit-timeout <dur>` | Delivery timeout, `100ms`..`30s`, default `2s`. |
| `--audit-reason <text>` | Optional reason recorded with the event (max 512 bytes, no control characters). |
| `--audit-issue <text>` | Optional issue/incident/change reference (max 128 bytes). |
| `--audit-event-id-file <file>` | With `--sudo-pipe`: write the release's event UUID (0600) for a deployment wrapper. |
| `--audit-status` | Print one content-free JSON status object. Standalone. |
| `--audit-flush` | Retry pending sink delivery in order; exit 0 only if nothing remains pending. Standalone. |
| `--audit-rotate` | Archive a fully shipped log and start a fresh one. Standalone. |
| `--version` | Print version information. |
| `--help` | Print usage. |

Names may be given with or without the leading `/`, and any **unique
substring** of a name works too (e.g. `--get2fa myserver` for
`/myserver:phil`); ambiguous substrings are rejected with a list of matches.

## Encrypted config

When `--encrypted` or `ACC_ENCRYPT_PW` is set, the entry list is stored as an
AES-256-GCM-encrypted JSON blob (`encrypted_data`) instead of plaintext:

```
$ export ACC_ENCRYPT_PW='your-config-password'   # e.g. in ~/.zshrc
$ ./acc --list                                    # transparently decrypts
```

Reading an encrypted config without the password fails; a wrong password fails
the GCM authentication check. Note: existing plaintext configs are converted
the next time an entry is written (import/create-update/enroll/delete).

## Config file format

```json
{
  "ac_config_item": [
    {
      "Name": "/example.com:bob@example.com",
      "Username": "bob@example.com",
      "Secret": "CKDPKQHM3RWX456R",
      "Realm": "example.com",
      "Digits": 0
    }
  ]
}
```

The file is created with mode `0600` because it contains shared secrets. Keep
it out of version control (it is in this repo's `.gitignore`).

## Notes

- Only SHA1 is supported at the moment (matching Google Authenticator).
- Clocks must be reasonably in sync between `acc` and the validating server;
  TOTP codes roll every 30 seconds.
