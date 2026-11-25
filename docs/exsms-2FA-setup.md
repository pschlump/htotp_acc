# exsms 2FA / sudo Setup Notes

Notes on giving an AI agent (Kimi Code CLI) access to a Linux server with
password-protected sudo and TOTP 2FA via `pam_google_authenticator`.

## Scenario

- Linux server with a user account `phil`.
- Passwordless (key-based) SSH login to `phil`.
- sudo to root currently requires no password.
- Plan: require a password for sudo, plus a TOTP 2FA code via the Google
  Authenticator PAM module (`pam_google_authenticator`).
- The `acc` tool in this repo (`acc.go`) stores TOTP secrets in
  `acc.cfg.json` and can emit the current code (`--get2fa` / `--gen2fa`).

## Can the agent use this?

Yes to all three parts:

1. **SSH** — key-based login is ideal; the agent runs `ssh phil@host ...`
   through a non-interactive shell, no prompt needed.

2. **sudo with password** — the shell is non-interactive, but sudo reads the
   password from stdin with `-S`:

   ```bash
   echo 'thepassword' | ssh phil@host 'sudo -S whoami'
   ```

   Each Bash call is a fresh shell, so the password must be piped in on every
   sudo invocation (unless `timestamp_timeout` is raised in sudoers).

3. **TOTP via pam_google_authenticator** — sudo's PAM conversation prompts
   are also answered from stdin under `-S`. The tool's `--sudo-pipe` mode
   prints the stored password and a fresh TOTP code on two lines, ready to
   pipe into `sudo -S`:

   ```bash
   ./acc --sudo-pipe myserver --min-ttl 10 | ssh phil@myserver 'sudo -S id'
   ```

   The password comes from the config entry (`--create-update ... --password`),
   so it never appears in the command line. `--min-ttl 10` guarantees the code
   has at least 10 seconds left before sudo sees it.

## Audit logging for credential release (Philip and Jake)

Production deploys and recovery run `acc --sudo-pipe ... | ssh HOST "sudo -S ..."`.
Both Philip and Jake have privileged production access from their own
workstations, so **both workstations need this `acc` build and an independent
sink configuration**. `acc` now records every release locally *before* the
password/TOTP is written (see the README "Audit logging" section for the full
flag list, record schema and receiver contract).

```bash
# initial rollout: durable local spool, best-effort shipping
export ACC_AUDIT_SINK=https://audit.exsms.example.invalid/acc      # placeholder host
export ACC_AUDIT_TOKEN_FILE=~/.pjs/acc-audit.token                 # 0600, provisioned out of band
acc --sudo-pipe "/exsms-1:phil" --min-ttl 10 --no-reuse \
    --audit-reason "deploy canary" --audit-issue CHG-123 \
    --audit-event-id-file "$DEPLOY_DIR/acc.event-id" \
  | ssh phil@canary-host.example.invalid "sudo -S -p '' true"

# later, once the receiver and alerting are proven: refuse to release unless
# the sink accepted the record first
acc --sudo-pipe "/exsms-1:phil" --audit-policy require ...
```

Four correlated evidence sources make up the ExSMS audit trail; `acc` supplies
only the first:

1. `acc` credential-release events (each operator workstation) — *this change*;
2. remote sshd authentication/session records;
3. remote sudo/PAM accepted/rejected command records;
4. deployment/change manifests or break-glass result records.

`emitted` means "acc released the pair to stdout", **not** that SSH connected,
PAM accepted the code, or sudo ran anything. Remote sshd/sudo/PAM logs remain
authoritative for what actually executed. A local log is also not tamper-proof
against the workstation user — off-host delivery to immutable retention is the
tamper-resistance layer. Nothing secret is written to the log (no password, TOTP
seed/code, encryption password, token, config body or parent arguments).

**Correlation.** `--audit-event-id-file` writes the release's `event_id` (UUID,
mode 0600, never on the credential stdout stream). The deploy wrapper should copy
that UUID into the deployment manifest; match it to the remote `sshd`/`sudo` log
lines by workstation `hostname`/`username` and the `occurred_at` window of the
`emitted` record.

**Emergency / offline.** There is no switch to turn auditing off. With the sink
unreachable, `best-effort` (the default) still writes the local record, releases
the credentials, warns on stderr and leaves the records pending; run
`acc --audit-flush` when connectivity returns. Check `acc --audit-status`
(`pending`, `oldest_pending_at`, `unfinished_requests`) and rotate with
`acc --audit-rotate` only when nothing is pending; copy archives off-host before
deleting anything locally.

**Follow-up (not deployed by this change):**

- Makefile/deploy wrappers capture `--audit-event-id-file` and add the UUID to
  deployment manifests.
- Use `--audit-policy require` for normal production deploys only after the
  receiver and retry/alerting are proven; start with durable best-effort spool.
- Off-host alerts for pending age, repeated `require` failures, and credential
  release without a matching remote sudo session.
- Jake receives the same binary/capability with his own token and sink config.
- The receiver must be idempotent on `record_id` (records can be resent after a
  crash or cursor loss).

## Caveats

- **Clock skew** — the machine running `acc` and the server must have synced
  clocks. The module's window setting gives some slack.
- **Timing / reuse** — codes roll every 30s. With default `disallow-reuse`
  behavior, a failed attempt burns the code; wait for the next window.
- **PAM/sudoers config** —
  - `Defaults requiretty` in sudoers blocks the stdin trick entirely;
    make sure it is off.
  - Odd module stacking (e.g. `nullok` placement) can change prompting
    behavior.

## Security note

With `--sudo-pipe` the sudo password lives only in the config file, not in
session context, command lines, or transcripts. Protect the config by setting
`ACC_ENCRYPT_PW` — stored in the **OS keystore** (macOS Keychain / Windows
Credential Manager on WSL) and pulled into the environment by the shell rc,
not hardcoded in `~/.zshrc` (see below). Entries are then stored as an
Argon2id-derived key (per-file salt) + AES-256-GCM encrypted blob, so an
offline brute force of a stolen config is expensive rather than trivial. The
config file path can be defaulted with `ACC_CFG`.

Config files written by older versions of `acc` (a single-pass SHA-256 key,
no salt) are still decrypted on read and re-encrypted in the stronger format
on the next write, so upgrading requires no manual migration.

Safer still: a restricted sudoers entry limited to the specific commands
needed, `NOPASSWD` for those commands only, or a dedicated service account
instead of full root sudo.

## Storing `ACC_ENCRYPT_PW` in the OS keystore

The encryption password is the one secret that used to sit in a dotfile. Keep
it in the OS credential store instead and have the shell rc pull it out;
`acc` itself is unchanged (it reads `$ACC_ENCRYPT_PW` or `--encrypted` as
before). Full runbook with caveats: the "Storing `ACC_ENCRYPT_PW` in the OS
keystore" section of `2FA-SUDO-SETUP.md` in the exsms repo docs.

### macOS — Keychain (`security` CLI)

```sh
# one-time, in a real Terminal (login keychain unlocked; -U = update if exists)
security add-generic-password -a "$USER" -s acc-encrypt-pw -w '<password>' -U

# in ~/.zshrc, replacing any hardcoded export:
export ACC_ENCRYPT_PW="$(security find-generic-password -a "$USER" -s acc-encrypt-pw -w 2>/dev/null)"

# verify in a NEW terminal tab, without printing the secret:
[ -n "$ACC_ENCRYPT_PW" ] && echo set
```

Caveats: reads from cron/agent sandboxes fail with "User interaction is not
allowed" (no GUI session); click **Always Allow** if the first read prompts.

### WSL — Windows Credential Manager (`powershell.exe` + PasswordVault)

```bash
# one-time, from the WSL shell
powershell.exe -NoProfile -Command '
  $v = New-Object Windows.Security.Credentials.PasswordVault
  $c = New-Object Windows.Security.Credentials.PasswordCredential("htotp_acc","acc-encrypt-pw","<password>")
  $v.Add($c)'

# in ~/.bashrc (tr -d is mandatory: Windows exe output ends in CRLF):
export ACC_ENCRYPT_PW="$(powershell.exe -NoProfile -Command \
  '(New-Object Windows.Security.Credentials.PasswordVault).Retrieve("htotp_acc","acc-encrypt-pw").Password' 2>/dev/null \
  | tr -d '\r\n')"
```

### Both platforms

- **Rotation does not re-encrypt:** updating the stored password does not
  change the password an existing `acc.cfg.json` was encrypted with — losing
  the stored value means losing the config. Keep a sealed backup of the old
  export until the new flow is verified.
- The only remaining command-line exposure is `--password` at enrollment
  (visible to `ps`/shell history briefly); prefix the command with a space
  (with `HIST_IGNORE_SPACE` set) if that matters.

## Server-side setup checklist (TODO)

- [ ] Set a password for `phil` (or the sudo target user).
- [ ] Install `libpam-google-authenticator`.
- [ ] Enroll: `./acc --enroll phil --issuer myserver --qr phil.png` — put the
      printed secret in `~phil/.google_authenticator` on the server (or scan
      the QR with the server-side setup flow). Set `ACC_CFG`; store
      `ACC_ENCRYPT_PW` in the OS keystore (see above).
- [ ] Add `auth required pam_google_authenticator.so` to `/etc/pam.d/sudo`.
- [ ] Ensure `requiretty` is not set in sudoers.
- [ ] Check clock skew: `./acc --check-time myserver`.
- [ ] Test: `./acc --sudo-pipe myserver --min-ttl 10 | ssh phil@myserver 'sudo -S id'`.
