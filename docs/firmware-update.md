# Firmware update

End-to-end flow:

```
vendor laptop             user laptop                 device (STM32U585)
┌──────────────────┐     ┌──────────────────┐      ┌──────────────────────┐
│ make release     │     │ companion app    │USB   │ runtime firmware     │
│   ├─ verify-repro│──►  │  fwsign verify   │HID   │  ├─ CMD_FW_BEGIN     │
│   └─ ELFs        │.pqfw│  stream chunks   │────► │  ├─ CMD_FW_CHUNK×N   │
│ fwsign sign      │     │  progress bar    │      │  ├─ CMD_FW_COMMIT    │
│   └─ .pqfw       │     │  confirm words   │      │  │    └─ user OK     │
└──────────────────┘     └──────────────────┘      │  ├─ SCB.AIRCR reset  │
                                                    │ FSBL                 │
                                                    │  ├─ read manifests   │
                                                    │  ├─ C10 verify       │
                                                    │  ├─ image hash check │
                                                    │  ├─ pick newer slot  │
                                                    │  └─ branch → runtime │
                                                    └──────────────────────┘
```

## Invariants

1. **Only vendor-signed releases can be installed.** The FSBL holds
   the vendor SPHINCS+C10 public key compiled in at factory provisioning
   time. No release signed by any other key will ever boot.
2. **Firmware updates require PIN unlock.** Wallet seed is never
   accessed during an update, but unlock is required as defence in
   depth — a stolen locked device cannot be silently flashed even to a
   not-yet-revoked vendor release.
3. **Anti-rollback is enforced via STM32U585 OTP.** 32 × 32-bit OTP
   words = 1024 increments. Each commit clears one bit. Neither RDP
   regression nor physical fuse attack can reset the floor.
4. **The FSBL is immutable after provisioning.** Pages 0–3 of bank 1
   are WRP1A-locked before RDP-2. Any FSBL bug is a device
   replacement.
5. **Power-fail safe.** The inactive slot is fully erased, written,
   and re-hashed before any pointer change. The final commit is two
   atomic page writes (manifest + boot state); a torn write is
   detected by FSBL at boot.
6. **User-consent gated.** Every commit shows the new firmware's 8
   BIP-39 measurement words on the OLED; the user holds long-right
   to confirm. Matching the words against the vendor's published
   release is the anchor that prevents a MitM companion app from
   slipping a (vendor-signed but user-unauthorised) release in.

## Storage layout

```
Bank 1 — secure (1 MB, SECWM1: all 128 pages secure):
  pages 0–3       FSBL               32 KB   (WRP1A-locked)
  page  4         Manifest A          8 KB
  page  5         Manifest B          8 KB
  page  6         Boot state          8 KB   (try-once + active slot)
  pages 7–64      Slot A secure     464 KB
  pages 65–122    Slot B secure     464 KB
  pages 123–127   Reserved (legacy, SE050 admin, OPTIGA PBS)

Bank 2 — non-secure (1 MB, SECWM2: all 128 pages NS):
  pages 0–63      Slot A NS         512 KB
  pages 64–127    Slot B NS         512 KB

OTP user area (starts 0x0BFA_0000):
  words 0–31      Rollback counter (1024 bits, one per commit)
```

Current footprint for comparison: secure ≈ 354 KB / 464 KB capacity,
nonsecure ≈ 90 KB / 512 KB capacity. Plenty of headroom.

## What gets signed (v0x02)

Only three inputs feed the SPHINCS+C10 signature:

```
signed_preimage = b"PQFW_V1"          // 7 bytes, domain-separation tag
                || fw_version_be_u32   // 4 bytes
                || secure_hash[32]     // SHA-256 of flat secure image
                || nonsecure_hash[32]  // SHA-256 of flat NS image
                                       // 75 bytes total

signed_digest   = SHA-256(signed_preimage)      // 32 bytes

signature       = sphincs_c10::sign(vendor_sk, signed_digest)   // 4008 bytes
```

Every other field in the manifest is **unsigned metadata**. An
auditor rebuilding the firmware from source can reconstruct those
75 bytes from `(version, secure.elf, nonsecure.elf)` alone — no
manifest parsing, no `.pqfw` envelope, no device-specific state.

Concretely, what's signed vs. unsigned:

| Field               | Signed? | Purpose                                                                 |
|---------------------|---------|-------------------------------------------------------------------------|
| `fw_version`        | YES     | Rollback binding — prevents replay of old signatures with a high version claim |
| `secure_hash`       | YES     | Binds the firmware image content                                         |
| `nonsecure_hash`    | YES     | Binds the firmware image content                                         |
| `vendor_pubkey_fpr` | no      | Fast-reject hint for the device; not authority-bearing                   |
| `build_id`          | no      | Informational (git commit); displayed in the companion app               |
| `slot` (A/B)        | no      | Informational; FSBL identifies A/B by flash address, not this field     |
| `secure_len`, `nonsecure_len` | no | Streaming hint; the hashes cover the declared-length image, so lying about length breaks the hash |
| `boot_counter_snap` | no      | Device state written post-sign                                           |
| `try_once_flag`     | no      | Device state written post-sign                                           |
| `crc32`             | no      | Torn-write detection; integrity only                                     |

**One signature works for either slot.** The vendor emits one
`.pqfw` per release, not two — the same signed bytes install
identically into slot A or slot B.

## Manifest format (8 KB flash page)

See `fw-manifest/src/lib.rs` — single source of truth. Unsigned
metadata + post-sign device state still lives in the page, organised
for flash-write alignment and FSBL's read convenience:

```
offset  size  field                   signed?
─────────────────────────────────────────────
    0      4  magic "PQSF"               no
    4      1  manifest_version = 0x02    no
    5      1  slot (informational)       no
    6      2  reserved                   no
    8      4  fw_version (u32 BE)        YES
   12      4  secure_len                 no
   16      4  nonsecure_len              no
   20     32  secure_hash (SHA-256)      YES
   52     32  nonsecure_hash (SHA-256)   YES
   84     32  vendor_pubkey_fpr          no  (fast-reject check)
  116     32  build_id (git commit)      no  (informational)
  148     32  manifest_digest            = SHA-256(signed_preimage)
  180   4008  SPHINCS+C10 signature      over manifest_digest
 4188      4  boot_counter_snap          no  (post-sign device state)
 4192      1  try_once_flag              no  (post-sign device state)
 8188      4  CRC-32 (IEEE)              no  (integrity only)
```

## Command flow on the device

1. `CMD_FW_BEGIN` (8 KB manifest payload)
   - Verify unlock; run full crypto verify chain on the manifest.
   - Determine inactive slot; reject if manifest claims the active.
   - Erase inactive manifest + secure + NS pages.
   - Seed an SRAM-only `FwUpdateCtx`.
   - Reset activity timer (counts as user consent for the session).
2. `CMD_FW_CHUNK` (up to 1024 bytes of image data per APDU)
   - Bounds-check offset / kind / length.
   - Write via `write_slot_quadword_verified` (dual-bank aware).
   - Update running SHA-256.
3. `CMD_FW_COMMIT`
   - Re-hash written images, compare against manifest's signed hashes.
   - Compute 8 BIP-39 words; render confirm dialog.
   - On user confirm:
     - `otp::bump_to(fw_version)`.
     - Write manifest page (with `try_once = TRIED` + fresh CRC).
     - Write boot-state page pointing at new slot.
     - `SCB::sys_reset()`.
4. `CMD_FW_STATUS` / `CMD_FW_ABORT` — progress + cancel at any time.

## FSBL boot sequence

Covered in `fsbl/src/main.rs`. Summary:

- Read both manifests.
- Run the same verify chain (structural, CRC, digest, vendor fpr,
  C10 signature, rollback floor) on each.
- Re-hash each candidate's secure + NS images from flash.
- Pick the highest-version fully-valid slot, honouring try-once:
  - `TRIED + boot_state.active_slot == candidate` → revert.
  - `COMMITTING` → torn, fall back.
  - `COMMITTED` → safe to boot.
- Set VTOR + jump to the slot's reset handler.

## Vendor release pipeline

```
# One-time, on an offline signing machine.
fwsign keygen --out vendor-key.enc
fwsign pubkey --key vendor-key.enc --out vendor-pubkey.bin

# Per release.
git checkout $RELEASE_COMMIT
make release RELEASE_FEATURES=stm32u585,se050,optiga-trust-m,dual-se,ui-oled
make fsbl FSBL_VENDOR_PUBKEY=/path/to/vendor-pubkey.bin

fwsign sign \
  --key vendor-key.enc \
  --version $VERSION_U32 \
  --secure target/release/secure.elf \
  --nonsecure target/release/nonsecure.elf \
  --slot A \
  --build-id $(git rev-parse HEAD | sha256sum | head -c 64) \
  --out release-v${VERSION_U32}.pqfw
```

**One `.pqfw` per release.** The v0x02 signed preimage doesn't cover
the slot identifier, so one signed release installs identically into
A or B. The companion updater picks the inactive slot on the device;
the signature verifies either way. (`--slot` stamps the unsigned
metadata byte for traceability but has no cryptographic effect.)

## Verify-it-yourself

The point of the v0x02 signed-preimage design is that anyone can
verify a release from source alone — without trusting any tool the
vendor ships, without parsing the `.pqfw` envelope, and without
comparing against any vendor-published artifact beyond the 32-byte
public key and the 4008-byte signature.

### 1. Rebuild reproducibly

```bash
# Install the pinned toolchain the vendor uses.
rustup default nightly-2026-04-06
rustup target add thumbv8m.main-none-eabi

# Check out the exact commit the vendor's release notes point at.
git clone https://github.com/<vendor>/sphincs_rust.git
cd sphincs_rust
git checkout <release-commit>

# Build with the same feature set the vendor used.
make release RELEASE_FEATURES=stm32u585,se050,optiga-trust-m,dual-se,ui-oled
```

`make release` runs `verify-repro` first (two clean builds, diff).
If that passes, `target/release/secure.elf` and
`target/release/nonsecure.elf` are byte-for-byte identical to what
the vendor built from the same commit.

### 2. Compute the image hashes (optional — `fwsign` will do this internally)

```bash
cargo run -p fwmeasure -- target/release/secure.elf
cargo run -p fwmeasure -- target/release/nonsecure.elf
```

These print the 8 BIP-39 words and the raw SHA-256 — the same
hashes that go into the signed preimage.

### 3. Verify the vendor's signature over your build

```bash
# Either extract the signature from the vendor's .pqfw:
cargo run -p fwsign -- extract-sig \
    --bundle release-v42.pqfw \
    --out   release-v42.sig

# ... or use a signature file the vendor published directly.

# Then run the signature check.
cargo run -p fwsign -- verify-release \
    --version   42 \
    --secure    target/release/secure.elf \
    --nonsecure target/release/nonsecure.elf \
    --signature release-v42.sig \
    --pubkey    vendor-pubkey.bin
```

Under the hood that does exactly this — no shortcuts, no hidden
state:

```rust
let preimage = b"PQFW_V1"
    || version.to_be_bytes()
    || sha256(flatten(secure.elf))
    || sha256(flatten(nonsecure.elf));
let digest = sha256(preimage);
assert!(sphincs_c10::verify(pk_seed, pk_root, digest, signature));
```

If that passes, you have cryptographic proof that:

1. The vendor (holder of the matching SK) signed *this exact build*.
2. Any byte-level change to the firmware would break the hash and
   break the signature.
3. The release is bound to a specific version number (rollback
   protection).

### What this does NOT prove

* The vendor's intent. A signed release is authentic, not
  necessarily benign. Review the source before trusting what you're
  about to install.
* Device-specific acceptance. Your particular chip may have a
  higher OTP rollback floor than this release — only the device can
  answer that, and it does so at `CMD_FW_COMMIT` time.

## Cryptographic primitives (complete inventory)

The entire firmware-update chain is post-quantum for signing and
verification. The only non-PQ primitives are in the at-rest
encryption of the vendor's private key (a passphrase-protected blob
on an offline machine) — and those are chosen for PQ safety via
conservative key sizes.

| Primitive                | Where used                                | PQ safety |
|--------------------------|-------------------------------------------|-----------|
| **SPHINCS+C10** (h=18, d=2, k=13, a=11, w=8) | Release signatures (`fwsign sign`, `fsbl::verify`, `cmd_fw_begin`) | **PQ-secure by construction** (hash-based; no number-theoretic assumption to break). ~128-bit classical / ~80-bit quantum security. |
| **SHA-256**              | Every hash in the sign/verify path: image hashes, signed digest, SPHINCS+C10 tweakable hashes, manifest CRC preimage. | PQ-safe per Grover — effective pre-image security ≈ 2^128 quantum. |
| **CRC-32 (IEEE)**        | Manifest torn-write detection only. Not authority-bearing. | N/A (not a cryptographic primitive). |
| Argon2id                 | Vendor SK at-rest passphrase-based KDF (`fwsign keystore`). Never in the verification path. | PQ-safe (memory-hard → no quantum speedup). |
| XChaCha20-Poly1305       | Vendor SK at-rest AEAD. Never in the verification path. | PQ-safe with 256-bit key (Grover → effective 128-bit). |

None of Argon2id or XChaCha20-Poly1305 appear anywhere the device
reads or the FSBL verifies. They only protect the vendor's SK file
from offline brute-force by someone who steals the signing
machine's disk.

A concrete consequence: a future cryptographically relevant quantum
computer (CRQC) capable of breaking elliptic-curve crypto does
**not** break PQSigner firmware authentication. Every step from
"vendor signs" to "FSBL verifies" uses only hash-based primitives.

## Companion-side protocol

USB HID APDU v2 (class byte `0xF0`):

| INS  | Name          | Chained? | Payload              |
|------|---------------|----------|----------------------|
| 0x70 | FW_BEGIN      | yes      | 8 KB manifest        |
| 0x71 | FW_CHUNK      | no       | 8-byte hdr + ≤1 KB   |
| 0x72 | FW_COMMIT     | no       | none                 |
| 0x73 | FW_STATUS     | no       | none (returns 10 B)  |
| 0x74 | FW_ABORT      | no       | none                 |

Status word mapping:
- `0x9000` — OK.
- `0x6982` — PIN not verified (device locked).
- `0x6985` — bad state / chunk / flash error (retriable).
- `0x6A80` — bad manifest / version / image (fetch different release).
- `0x6501` — OTP exhausted (device end-of-life for updates).
- `0x6984` — idle wipe (re-unlock, restart BEGIN).

## Current implementation status

| Component                    | State                    |
|------------------------------|--------------------------|
| `.cargo/config.toml`         | ✔ landed                 |
| `make verify-repro`          | ✔ passes                 |
| `fw-manifest` crate          | ✔ landed, tests pass     |
| `fwsign` CLI                 | ✔ landed, tests pass     |
| `fwsign` deterministic sign  | ✔ verified               |
| secure `hw::flash` bank 2    | ✔ landed                 |
| secure `hw::otp`             | ✔ landed                 |
| secure `hw::boot_state`      | ✔ landed                 |
| `fsbl/` crate                | ✔ builds, 18 KB / 32 KB  |
| `shared` CMD_FW_* / INS codes | ✔ landed                |
| secure `fw_update/` module   | ✔ landed                 |
| secure `cmd_fw_*` handlers   | ✔ landed                 |
| NSC CMSE veneers             | ✔ landed                 |
| NS `nsc_api` wrappers        | ✔ landed                 |
| NS USB dispatcher            | ✔ landed                 |
| Trusted-UI confirm dialog    | ⚠ stubbed (returns false; must be filled in after the ongoing `secure/src/ui/` refactor lands so it can reuse the same multi-page `confirm()` flow the sign path uses) |
| A/B slot linker scripts      | ⚠ not reshaped (current firmware still boots at 0x0C00_0000; Phase 4 will split the secure/NS memory.x into `--slot A|B` variants) |
| Companion updater tool       | ⚠ out of scope (see `tools/fwupdate.py` as the intended next-session artifact) |
| Hardware bring-up            | ⚠ out of scope — requires real board + probe-rs |
| WRP1A in `ob-configurator`   | ⚠ out of scope — Phase 7 |
| `make flash-hw-production`   | ⚠ out of scope — Phase 7 |

## Known gotchas

- **Signature reverify at COMMIT** — the signature check at BEGIN is
  a fast-reject; at COMMIT we only re-run image-hash checks against
  the just-written bytes. The C10 sig is not re-verified because the
  manifest bytes don't change between BEGIN and COMMIT (they're in
  SRAM the whole time). FSBL on the next reboot does the full
  re-verify anyway, so anything that slips past a broken COMMIT-time
  check still fails the FSBL boot.
- **Manifest-vendor-fpr trust anchor** — the secure firmware checks
  the new manifest's `vendor_pubkey_fpr` against the CURRENTLY-RUNNING
  slot's manifest fpr (which FSBL already verified against the
  real vendor pubkey). This is correct iff the running slot's
  manifest is intact. In a pathological case where the active slot
  boots from a manifest whose fpr has been swapped, this check would
  accept a malicious release. FSBL's pubkey-vs-manifest-fpr check
  is the defining gate; the secure-side check is defence in depth.
