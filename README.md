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

## Environment variables

| Variable | Description |
|---|---|
| `ACC_CFG` | Default config file path (overridden by `--cfg`). |
| `ACC_ENCRYPT_PW` | Config encryption password (overridden by `--encrypted`). Required to read an encrypted config. |
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
| `--show-ttl` | With `--is_script`: print `<code> <seconds-left>`. |
| `--check-time <host>` | Compare the local clock with `<host>` via ssh (detect TOTP skew). |
| `--is_script` | Machine-readable output only; skip clipboard and countdown. |
| `--output <file>` | Write the generated code to a file. |
| `--encrypted <pw>` | Encrypt the stored config data with this password (default `$ACC_ENCRYPT_PW`). |
| `--db_flag <flags>` | Comma-separated debug flags (`dump-db-flag` to list). |
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
