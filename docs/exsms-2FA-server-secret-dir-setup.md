# exsms 2FA — Server-Side Setup with a Root-Owned Secret Directory

Companion to [`exsms-2FA-setup.md`](./exsms-2FA-setup.md), which covers the
agent side (`acc --sudo-pipe`, piping password+TOTP into `sudo -S`). This note
completes that file's *“Server-side setup checklist (TODO)”* and answers one
specific hardening question:

> **Store the TOTP seeds in a directory that is NOT owned by the user who is
> logging in** — e.g. `/var/lib/google-authenticator/` (in a past setup this
> was `/var/authenticator/`), so the logging-in user cannot read their own
> seed.

The scenario is unchanged: Linux server, user `phil`, key-based SSH, and we
want `sudo` to require a password **plus** a TOTP code from
`pam_google_authenticator`. The `acc` tool (in
`~/go/src/github.com/pschlump/htotp_acc`) holds the seed and emits codes.

---

## 1. Why move the seed out of the home directory?

`pam_google_authenticator`’s default is to keep the seed in
`~/.google_authenticator`, owned by the user. The user can therefore **read
their own seed** and generate codes without the token device/app — which
collapses TOTP from “something you *have*” into “something you can *read off
the disk you already control*.” For a human that is a tolerable trade-off; for
an automated agent that only ever needs to *produce* codes, leaving the seed in
the user’s home gives away the second factor to anyone who reaches that shell.

Putting the seed in a **root-owned** directory that the logging-in user cannot
read restores the property: the seed exists in exactly two places — your token
(`acc` / phone) and root’s file. The user authenticating can prove possession
of a code but cannot exfiltrate the seed.

---

## 2. How this works (the one option that matters)

By default the module **rejects** any secret file not owned by the
authenticating user. The clean, supported way around that is the **`user=root`**
module option:

```
auth required pam_google_authenticator.so \
    secret=/var/lib/google-authenticator/${USER} \
    user=root
```

What each piece does (verified against the upstream `google-authenticator-libpam`
README):

| Token / option | Effect |
|---|---|
| `secret=/var/lib/google-authenticator/${USER}` | Look up the seed at a central, absolute path. `${USER}` expands to the **authenticating** username (e.g. `phil`), giving one file per user. `~` / `${HOME}` are also supported, **but are forbidden once you use `user=`** — so use `${USER}`. |
| `user=root` | “Force the PAM module to switch to a hard-coded user id prior to doing any file operations.” It also changes the ownership check: the file must now be owned by **root** (the `user=` value) instead of by the logging-in user. This is what lets a `root:root` file pass. **Not** a DANGEROUS option. |

The seed file therefore lives at `/var/lib/google-authenticator/phil`, owned
`root:root`, mode `0600`, inside a `0700 root:root` directory. The module
(running as root for `sudo`) reads it; `phil` cannot.

> Do **not** reach for `no_strict_owner`. It works (it disables the ownership
> check entirely) but is flagged DANGEROUS upstream because it accepts *any*
> owner. `user=root` keeps the ownership check active — it just checks for root
> — which is exactly the security property you want.

A few rules the module enforces, and how we satisfy them:

- **Ownership:** file owned by the `user=` account ⇒ own it `root:root`.
- **Permissions:** file readable/writable *only by its owner* (default `0600`);
  any group/other bit is rejected (would need the DANGEROUS `allowed_perm=`).
  ⇒ use exactly `0600`.
- **`DISALLOW_REUSE` writes the file:** the module records the last-used time
  step, so the owner (root) needs **write** ⇒ `0600`, not `0400`.
- **No `~`/`${HOME}` with `user=`** ⇒ we use `${USER}`.

---

## 3. Prerequisites

- A working `acc` binary: `cd ~/go/src/github.com/pschlump/htotp_acc && make`.
- A root path to the server for the *initial* file creation (existing
  passwordless sudo, a root shell, or a console). After step 6 you will use
  `acc --sudo-pipe` for all privileged changes.
- Clocks in sync on both ends (TOTP rolls every 30 s):
  `acc --check-time myserver`. On the server: `timedatectl status` should show
  *“System clock synchronized: yes”* (run `chrony`/`systemd-timesyncd`/`ntp`).

---

## 4. Runbook

### Step 1 — Install the PAM module

Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y libpam-google-authenticator
```

RHEL/Fedora (EPEL):

```sh
sudo dnf install -y google-authenticator
```

Confirm the module is loadable:

```sh
ls -l /lib/*/security/pam_google_authenticator.so \
  /usr/lib*/security/pam_google_authenticator.so 2>/dev/null
```

### Step 2 — Create the root-owned secret directory

```sh
sudo install -d -o root -g root -m 0700 /var/lib/google-authenticator
```

(`0700` so even the list of enrolled usernames is hidden from non-root users.
Root bypasses the perms anyway, so the module can still read it.)

> Prefer `/var/lib/…` (FHS “variable state, machine-local”). If you want to
> match your earlier muscle memory, `/var/authenticator` works identically —
> just change the path in the `secret=` line and the `install`/`tee` commands
> below. Avoid `/etc/…` for seeds; `/etc` conventionally holds shareable,
> backed-up config, and a seed is a secret, not config.

### Step 3 — Generate the seed and build the server file

#### Method A — `acc` generates (recommended; acc stays the source of truth)

On your workstation:

```sh
cd ~/go/src/github.com/pschlump/htotp_acc
# ACC_ENCRYPT_PW comes from the shell rc, which pulls it from the OS keystore
# (macOS Keychain / Windows Credential Manager) — see exsms-2FA-setup.md.
./acc --enroll phil --issuer myserver --qr /tmp/phil-myserver.png
```

This prints and stores the entry, e.g.:

```
Name:   /myserver:phil
Secret: VZNZS2YL75EWJSHE
URI:    otpauth://totp/myserver:phil?secret=VZNZS2YL75EWJSHE&issuer=myserver
```

Also store the sudo password with the entry now (used by `--sudo-pipe`):

```sh
# --password is used once at enrollment (visible to ps/history briefly; prefix
# with a space if HIST_IGNORE_SPACE is set). Afterwards --sudo-pipe reads it
# from the encrypted config — it never appears on a command line again.
./acc --create-update phil --issuer myserver \
      --secret VZNZS2YL75EWJSHE --password 'phil-sudo-password'
```

Now create the server-side seed file **as root** (run while you still have a
straightforward root path), using **that exact secret** as line 1:

```sh
sudo tee /var/lib/google-authenticator/phil >/dev/null <<'EOF'
VZNZS2YL75EWJSHE
" RATE_LIMIT 3 30
" WINDOW_SIZE 3
" DISALLOW_REUSE
" TOTP_AUTH
EOF
sudo chown root:root /var/lib/google-authenticator/phil
sudo chmod 0600       /var/lib/google-authenticator/phil
```

The option lines mirror what the official `google-authenticator` CLI writes by
default:

| Line | Meaning |
|---|---|
| `VZNZS2YL75EWJSHE` | The base32 seed (line 1). |
| `" RATE_LIMIT 3 30` | Max 3 attempts per 30 s. |
| `" WINDOW_SIZE 3` | Accept current code ±3 steps (±90 s) for skew. Default is 3; raise only if clocks drift. |
| `" DISALLOW_REUSE` | A code used once cannot be reused. **Burns the code on a failed attempt** — wait for the next 30 s window. Requires the file be writable (hence `0600`). |
| `" TOTP_AUTH` | Time-based (RFC 6238), not HOTP. |

Scratch codes (the five 8-digit one-time backups the CLI normally emits) are
optional and omitted here — automation never uses them. If you want them,
append five random 8-digit numbers, one per line, after the options.

#### Method B — official CLI writes the canonical file (alternative)

Use this if you want the option lines guaranteed byte-for-byte canonical, then
import the printed seed into `acc`:

```sh
# As root; writes /root/.google_authenticator and prints secret + scratch codes:
sudo google-authenticator -t -d -f -W 3 -r 3 -R 30 -e -q
#   capture the printed base32 secret, then:
sudo install -o root -g root -m 0600 /root/.google_authenticator \
        /var/lib/google-authenticator/phil
sudo shred -u /root/.google_authenticator
```

Then on the workstation, give `acc` the same seed:

```sh
./acc --create-update phil --issuer myserver \
      --secret <PRINTED_SECRET> --password 'phil-sudo-password'
```

### Step 4 — Wire it into `/etc/pam.d/sudo`

Add the module line **after** the password auth, so the prompt order is
**password → TOTP** — which is the exact order `acc --sudo-pipe` emits
(password on line 1, code on line 2):

```sh
# /etc/pam.d/sudo   (Debian/Ubuntu; on RPM distros the equivalent auth lines
#                    live directly in /etc/pam.d/sudo or /etc/pam.d/system-auth)
@include common-auth
auth required pam_google_authenticator.so secret=/var/lib/google-authenticator/${USER} user=root
```

> **Prompt order is load-bearing.** `--sudo-pipe` always prints
> `<password>\n<totp>\n`. Whatever prompts first in the PAM `auth` stack is fed
> the first stdin line. Keep password auth ahead of the TOTP module.
> Do **not** add `forward_pass` here — it merges password+code into one prompt
> and breaks the two-line pipe.
> Do **not** add `nullok` for sudo: without it, any user lacking a seed file is
> *denied* sudo (what you want). `nullok` would let an un-enrolled user skip 2FA.

On Debian/Ubuntu, `@include common-auth` pulls in `pam_unix` (the password
prompt). If your `/etc/pam.d/sudo` instead lists `auth` lines explicitly, place
the `pam_google_authenticator` line immediately after the `pam_unix`/password
line.

### Step 5 — Tighten sudoers

Make sudo require the password and allow the stdin (`-S`) flow:

```sh
# Ensure these are set:
sudo visudo
#   Defaults !requiretty                 # requiretty breaks 'sudo -S' over ssh
#   Defaults timestamp_timeout=0         # optional: re-prompt every time (matches
#                                        #   the "fresh shell each call" model)
#   phil ALL=(ALL) ALL                   # password required (NOT NOPASSWD)
```

`Defaults requiretty` must be **off** for `phil`; otherwise sudo refuses to
read the password/TOTP from stdin under `ssh … 'sudo -S …'`.

### Step 6 — Verify the seed is hidden from the user

```sh
sudo stat -c '%U:%G %a %n' /var/lib/google-authenticator /var/lib/google-authenticator/phil
#   root:root 700 /var/lib/google-authenticator
#   root:root 600 /var/lib/google-authenticator/phil

sudo -u phil cat /var/lib/google-authenticator/phil
#   MUST fail:  cat: /var/lib/google-authenticator/phil: Permission denied

sudo -u phil ls /var/lib/google-authenticator
#   MUST fail:  ls: cannot open directory '...': Permission denied
```

If either `phil` command succeeds, stop and fix the ownership/mode before
proceeding — the hardening has not taken effect.

### Step 7 — Test end-to-end via `acc`

```sh
cd ~/go/src/github.com/pschlump/htotp_acc
./acc --check-time myserver                                   # skew check first
./acc --sudo-pipe myserver --min-ttl 10 | ssh phil@myserver 'sudo -S id'
#   expected:  uid=0(root) gid=0(root) groups=0(root)
```

`--min-ttl 10` guarantees the code has ≥10 s of life before sudo sees it (avoids
the window rolling over mid-prompt). Each ssh/sudo call is a fresh shell, so the
password+code are piped on **every** invocation unless you raise
`timestamp_timeout`.

---

## 5. Optional — TOTP for SSH login (not just sudo)

Same `user=root` + central-directory pattern; the only additions are sshd knobs.
In `/etc/pam.d/sshd`, add **above** `@include common-auth`:

```
auth required pam_google_authenticator.so secret=/var/lib/google-authenticator/${USER} user=root
```

…and in `/etc/ssh/sshd_config`:

```
UsePAM yes
KbdInteractiveAuthentication yes     # (older OpenSSH: ChallengeResponseAuthentication yes)
```

Then `sudo systemctl reload sshd`. With key-based login already working, this
adds a TOTP prompt after the key exchange. Note sshd 2FA interacts with
`AuthenticationMethods`; if you want *both* key and TOTP, set
`AuthenticationMethods publickey,keyboard-interactive`. Test from a **second**
session before closing your working one.

---

## 6. Operations

**Clock skew** — TOTP needs synced clocks. Monitor with
`acc --check-time myserver`; ensure `timedatectl` shows synchronized.

**Re-enroll / rotation** — `./acc --enroll phil --issuer myserver --qr …`
generates a fresh seed in `acc`, then rebuild
`/var/lib/google-authenticator/phil` as root with the new line 1 (Method A,
Step 3). Re-scan the QR on any phone.

**Backup / recovery** — `acc.cfg.json` (encrypted via `ACC_ENCRYPT_PW`) already
holds the seed and is your off-server backup. Optionally, as root:
`sudo tar -C / -cf - var/lib/google-authenticator | openssl enc … > ga-seeds.enc`
to offline-store all seeds. Losing both the seed file and `acc.cfg.json` means
re-enroll from console root.

**Troubleshooting** — temporarily add `debug` to the module line and watch:

```sh
# /etc/pam.d/sudo
auth required pam_google_authenticator.so secret=/var/lib/google-authenticator/${USER} user=root debug

sudo journalctl -f        # or: tail -f /var/log/auth.log
```

Look for the resolved path (`Secret file: /var/lib/google-authenticator/phil`),
ownership/permission complaints, or “Invalid verification code” (skew or a
burned `DISALLOW_REUSE` code — wait one window and retry). Remove `debug` when
done.

---

## 7. Quick reference

```sh
# Directory + one seed file (root-owned, user-hidden)
sudo install -d -o root -g root -m 0700 /var/lib/google-authenticator
sudo tee    /var/lib/google-authenticator/phil >/dev/null <<'EOF'
VZNZS2YL75EWJSHE
" RATE_LIMIT 3 30
" WINDOW_SIZE 3
" DISALLOW_REUSE
" TOTP_AUTH
EOF
sudo chown root:root /var/lib/google-authenticator/phil
sudo chmod 0600      /var/lib/google-authenticator/phil

# PAM line (in /etc/pam.d/sudo, after password auth)
auth required pam_google_authenticator.so secret=/var/lib/google-authenticator/${USER} user=root

# Generate code + pipe into sudo over ssh
./acc --sudo-pipe myserver --min-ttl 10 | ssh phil@myserver 'sudo -S id'
```

| Item | Value |
|---|---|
| Secret dir | `/var/lib/google-authenticator` (`0700 root:root`) — or `/var/authenticator` to match the old layout |
| Secret file | `/var/lib/google-authenticator/<user>` (`0600 root:root`) |
| Module option that permits non-user ownership | `user=root` |
| Path token (works with `user=`) | `${USER}` (not `~`, not `${HOME}`) |
| Prompt order must match | password → TOTP (= `--sudo-pipe` output order) |
| Avoid | `no_strict_owner`, `allowed_perm=`, `forward_pass`, `nullok` (for sudo) |
