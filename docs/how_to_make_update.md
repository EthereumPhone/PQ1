# How to ship a firmware update

A practical recipe for the firmware maintainer. For the *why* + threat
model see `docs/firmware-update.md`; this doc is the
copy-paste-and-go checklist.

---

## One-time setup

Do this once per product line, on an **offline** / air-gapped laptop.
The vendor private key is the single most sensitive artifact in the
whole system — if you lose it, every future update requires a device
replacement (FSBL is immutable). If someone else gets it, they can
silently sign malicious firmware for every device that trusts you.

### 1. Generate the vendor signing key

```bash
cargo run -p fwsign -- keygen --out vendor-key.enc
```

You'll be prompted twice for a passphrase. Choose one you will
actually remember — there is no recovery. The output `vendor-key.enc`
is a 126-byte Argon2id + XChaCha20-Poly1305 blob; it's safe to keep
on disk, but the passphrase must be separate (e.g. in a password
manager on a different machine, or written down in a safe).

### 2. Export the public key

```bash
cargo run -p fwsign -- pubkey \
    --key vendor-key.enc \
    --out vendor-pubkey.bin
```

`vendor-pubkey.bin` is 32 bytes: `pk_seed[16] || pk_root[16]`. This
is public — commit it to the repo, publish it on your website, pin
it in a tweet, whatever. **Users need this file to verify releases
independently.**

### 3. Bake the pubkey into the FSBL

The FSBL is immutable on production devices (WRP1A-locked before
RDP-2 burn). Whatever pubkey ships on a device determines which
vendor's releases that device accepts. Burn this in at factory
provisioning time:

```bash
make fsbl FSBL_VENDOR_PUBKEY=/secure/path/to/vendor-pubkey.bin
```

The resulting `target/fsbl/thumbv8m.main-none-eabi/release/pqsigner-fsbl`
is what you flash to pages 0–3 of bank 1 during factory provisioning.
Confirm the fingerprint matches (build.rs prints it):

```
// SHA-256(pubkey): 7f3a2b…
```

Users who want to check they have the right pubkey hash this file
with `sha256sum vendor-pubkey.bin` and compare.

### 4. Back it all up

- **`vendor-key.enc`** → two copies on offline media, stored in two
  different physical locations.
- **Passphrase** → separate from the key, ideally memorised + one
  written copy in a sealed envelope in a safe.
- **`vendor-pubkey.bin`** → in the repo + on the website + in the
  companion app. Also save its SHA-256 separately so users can
  cross-check.

Don't skip this. Losing the key is unrecoverable.

---

## Per-release pipeline

Every new release follows the same four steps.

### 1. Decide a version number

```
fw_version: u32, monotonic, strictly greater than the previously
            signed version AND strictly greater than every device's
            current OTP rollback floor.
```

A device ships at version `1`, so the first update you sign must be
version `2` or higher. Skipping versions (e.g. v2 → v5) burns 3 OTP
bits at install time instead of 1, but is otherwise fine. There are
1024 bits of OTP budget per device — enough for one update per month
for 85 years.

### 2. Build the release reproducibly

```bash
git checkout $release_commit
make release RELEASE_FEATURES=stm32u585,se050,optiga-trust-m,dual-se,ui-oled
```

`make release` runs `verify-repro` first (two clean builds, diff),
and fails loudly if the output isn't byte-identical. If this fails,
stop — something is leaking build-host state into the firmware and
users won't be able to reproduce your hashes. See
`docs/reproducible-builds.md` for debugging tips.

On success, `target/release/secure.elf` and
`target/release/nonsecure.elf` are what goes into the signature.
The target also prints the 8 BIP-39 measurement words — save these
for the release notes.

### 3. Sign the release

```bash
cargo run --release -p fwsign -- sign \
    --key vendor-key.enc \
    --version 2 \
    --secure target/release/secure.elf \
    --nonsecure target/release/nonsecure.elf \
    --slot A \
    --build-id $(git rev-parse HEAD | sha256sum | head -c 64) \
    --out release-v2.pqfw
```

You'll be prompted for the vendor passphrase. The output is a single
`release-v2.pqfw` file (~1.1 MB) containing the manifest + both image
halves + metadata. **One `.pqfw` per release** — the same file installs
into slot A or slot B; the device picks whichever is inactive.

`--slot` stamps the unsigned `slot` metadata byte for traceability;
it has no cryptographic effect. Pick A by convention.

### 4. Publish

Upload `release-v2.pqfw` wherever you distribute releases (GitHub
Releases, your CDN, etc.). Include in the release notes:

- The git commit hash.
- The fw_version number.
- The 8 BIP-39 measurement words (both secure + nonsecure).
- The SHA-256 of `release-v2.pqfw`.

Users with sensitive setups can optionally also download
`release-v2.sig` (the raw 4008-byte signature, extract with
`fwsign extract-sig`) for fully offline verification without
handling the `.pqfw` envelope.

---

## What users do

For reference — so you know what the other end of the pipeline
looks like.

### Normal user

1. Open the companion updater app.
2. App fetches `release-v2.pqfw` from your published URL.
3. User plugs in their device, unlocks with PIN.
4. Companion streams the `.pqfw` over USB HID (~2 s).
5. Device shows new measurement words on the OLED.
6. User compares against your published words, long-presses right to
   confirm.
7. Device bumps OTP floor, writes manifest, resets.
8. FSBL boots the new slot; if it fails to confirm alive, FSBL
   reverts to the previous release.

### Auditor / paranoid user

```bash
# 1. Rebuild from source.
git clone ...
cd sphincs_rust && git checkout <commit-from-release-notes>
make release RELEASE_FEATURES=stm32u585,se050,optiga-trust-m,dual-se,ui-oled

# 2. Pull the signature out of the .pqfw.
cargo run --release -p fwsign -- extract-sig \
    --bundle release-v2.pqfw --out release-v2.sig

# 3. Verify the vendor signed EXACTLY this build at EXACTLY this
#    version.
cargo run --release -p fwsign -- verify-release \
    --version 2 \
    --secure target/release/secure.elf \
    --nonsecure target/release/nonsecure.elf \
    --signature release-v2.sig \
    --pubkey vendor-pubkey.bin
```

If that passes, the release is genuinely vendor-signed and
byte-identical to the source. If it fails, don't install it.

---

## Sanity checks before you publish

Run these every time. They're fast.

```bash
# 1. The signature you just made verifies.
cargo run --release -p fwsign -- verify \
    --bundle release-v2.pqfw \
    --pubkey vendor-pubkey.bin
# → "verify: PASS"

# 2. The same bundle verifies via the source-only path (mimics what
#    an independent auditor does).
cargo run --release -p fwsign -- verify-release \
    --version 2 \
    --secure target/release/secure.elf \
    --nonsecure target/release/nonsecure.elf \
    --signature <(cargo run --release -p fwsign -- extract-sig --bundle release-v2.pqfw --out /dev/stdout) \
    --pubkey vendor-pubkey.bin
# → "verify-release: PASS"

# 3. Quick inspect — does the manifest contain what you expect?
cargo run --release -p fwsign -- inspect --bundle release-v2.pqfw
# Check: fw_version, secure_hash, nonsecure_hash, build_id match
#        the release notes.

# 4. Re-run verify-repro just in case.
make verify-repro RELEASE_FEATURES=...
# → "verify-repro: PASS"
```

---

## Common gotchas

- **Forgot to bump the version.** `fwsign sign` refuses if `--version`
  is not strictly greater than the last signed version recorded in
  `~/.local/share/fwsign/ledger.jsonl`. Bump and retry.
- **Different build host → different ELFs.** Reproducibility depends
  on the pinned toolchain + the `--remap-path-prefix` flags. If
  you're signing from a laptop that isn't on `nightly-2026-04-06`,
  install the right toolchain first (rustup honours
  `rust-toolchain.toml` automatically).
- **Tampered the `.pqfw` after signing.** The manifest's CRC catches
  accidental corruption, but you should always re-run `fwsign verify`
  on the distributed file, not just the one you just produced.
- **Shipped a bundle with the wrong FSBL-embedded pubkey.** If you
  change `FSBL_VENDOR_PUBKEY` between runs, every device flashed
  with the old FSBL will reject your new releases. There is **no**
  recovery for this — the FSBL is immutable on production units.
- **Forgot the passphrase.** No recovery. Every future release
  requires issuing new devices (with a new factory-provisioned
  pubkey). Treat the passphrase like a root CA key.
- **Device shows an unexpected measurement.** Do NOT confirm. Either
  the `.pqfw` you installed is a different build than the vendor
  intended, or the companion app is malicious. Cancel and
  investigate before retrying.

---

## Release-notes template

Copy this, fill in the blanks, paste into GitHub Releases:

```markdown
# PQSigner v2 (2026-MM-DD)

**Firmware version:** 2
**Git commit:** abc123...
**Build features:** stm32u585,se050,optiga-trust-m,dual-se,ui-oled

## Measurement words (verify on-device after update)

Secure image:   1 foo  2 bar  3 baz  4 qux  5 ...  8 ...
Nonsecure image: 1 foo  2 bar  3 baz  4 qux  5 ...  8 ...

## Artifacts

- `release-v2.pqfw` — the update bundle (SHA-256: ...)
- `release-v2.sig` — standalone signature (for offline verification)

## How to verify (optional but recommended)

See `docs/how_to_make_update.md` § "Auditor / paranoid user".

## Changes

- ...
```

The measurement-word lines are the anchor that lets users check their
device is running exactly what you built.
