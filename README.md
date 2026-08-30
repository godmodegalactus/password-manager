# pwmgr

Deterministic password manager backed by a Ledger hardware wallet. Passwords
are derived on demand from a secp256k1 ECDSA signature produced by the
Ethereum app's `personal_sign` on your Ledger — nothing sensitive is ever
stored on disk.

## How it works

For each site you save a small policy record (label, username, length, charset,
counter). When you ask for a password:

1. The message `pwmgr:v1:<site>:<username>:<counter>` is shown on the Ledger
   for your approval as an EIP-191 personal message.
2. The Ethereum app signs it with the secp256k1 key at a fixed hardened path
   dedicated to pwmgr (see below). ECDSA nonces are generated per RFC 6979,
   so the signature is deterministic — the same message always produces the
   same 65 bytes (`[v, r, s]`).
3. HKDF-SHA256 stretches those bytes into a password of the requested length
   over the requested character set. Rejection sampling keeps the character
   distribution uniform.

Losing the entries file loses the *policy* (length, charset, counter) — not
the passwords. Losing the Ledger seed loses everything. Your 24-word Ledger
backup *is* your password backup.

## Derivation path

`m/44'/60'/0x1627ddd1'/0/0`

Standard BIP44 Ethereum shape (`m/44'/60'/account'/change/address_index`) with
a pwmgr-reserved account index. `0x1627ddd1` is the first four bytes of
`sha256("pwmgr")`, masked to fit BIP32's hardened space. This account is
reserved for pwmgr — do **not** import this key into a wallet you use for
real Ethereum transactions. A dApp that talked you into `personal_sign`-ing a
message shaped like `pwmgr:v1:...` with your normal account could reconstruct
that site's password.

## Requirements

- A Ledger device (Nano S / S Plus / X / Stax / Flex)
- The Ethereum app installed and open on the device (blind-signing NOT
  required — pwmgr messages are ASCII and displayed verbatim)
- On Linux, the standard Ledger udev rules
- Rust toolchain (1.80+) to build

## Install

```sh
cargo build --release
# copy target/release/pwmgr onto your $PATH
```

## Usage

### Interactive mode

Run with no arguments:

```sh
pwmgr
```

You get a menu: `Get password / List entries / Add or update / Remove /
Show Ledger address / Show config path / Quit`. Entries are keyed by
`(site, username)`, so the same site can have multiple accounts. On Add, if
an entry for the same `(site, username)` pair already exists, the prompts
pre-fill with its current values so bumping just the counter (to rotate) or
changing the length is one keystroke.

### One-shot subcommands (for scripts)

```sh
pwmgr add github.com --username me --length 24 --charset symbols
                                     # saves the entry AND signs on the Ledger,
                                     # printing the derived password on stdout
pwmgr add github.com --username work # a second account on the same site
pwmgr get github.com --username me --copy   # pick which account
pwmgr get github.com                 # ok when the site has exactly one account
pwmgr list
pwmgr rm github.com --username work  # remove one account; --username required
                                     # when the site has more than one
pwmgr address                        # show the derivation address (safe to publish)
pwmgr where                          # show entries.json path
```

`get --ad-hoc <site> --length N --charset X --counter K` derives without a
stored entry — useful for one-off passwords.

### Rotating a password

Bump the counter — the entry is updated and the new password is derived in the
same step:

```sh
pwmgr add github.com --counter 1     # keeps everything else; the derived password changes
```

## Charsets

- `symbols` (default) — a–z, A–Z, 0–9, and `!@#$%^&*()-_=+[]{};:,.<>/?` (88 chars)
- `alphanumeric` — a–z, A–Z, 0–9 (62 chars)
- `digits` — 0–9 (for PINs)
- `hex` — 0–9, a–f

## Security model

- **Ledger + PIN = master password.** Anyone with your unlocked Ledger can
  derive every password. Same threat model as a normal password manager where
  the attacker has the master password.
- **The signature is the password material.** It never leaves the pwmgr
  process. Signatures and derived passwords are wrapped in `Zeroizing` so
  their memory is wiped on drop.
- **The Ledger display is the authoritative approval.** Always read the
  `pwmgr:v1:...` message on the device before approving — that's the anchor
  that protects you if the entries file has been tampered with.
- **Knowing your Ethereum address does *not* let anyone derive your passwords.**
  Signing requires the private key, which never leaves the Ledger.
- **The entries file has no secrets.** It's still written with `0600` on unix
  (and its parent directory with `0700`) so other local users can't enumerate
  your saved sites.

## Files

- `~/Library/Application Support/pwmgr/entries.json` (macOS)
- `~/.config/pwmgr/entries.json` (Linux)
- `%APPDATA%\pwmgr\entries.json` (Windows)

Run `pwmgr where` to print the exact path.

## Not yet implemented

- Clipboard auto-clear after N seconds
- Device picker when multiple Ledgers are attached
- File lock so concurrent `add` calls can't clobber each other
