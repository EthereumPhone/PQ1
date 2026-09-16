# Firmware update

> **Pre-production legacy implementation — not a shipping design.** The active
> code below still contains the rejected bitwise OTP tally and nonfunctional
> try-once rollback path. STM32U585 user OTP is 512 bytes / 32 one-program
> 128-bit ECC quad-words; it does not provide 1,024 per-bit increments.
> `stm32u585 + mode-production` is compile-blocked. The unapproved Draft 1.1
> research candidate and its proposed interfaces are
> [`a-b-firmware-rollback-architecture.md`](../security/a-b-firmware-rollback-architecture.md).
> Ordinary releases are unlimited within a security epoch; only a security-
> epoch revocation consumes the still-open replicated OTP record codec.
> Sections describing v0x02/`PQFW_V1`, the legacy layout, and current commands
> remain bring-up documentation only.

Legacy bench flow (not production-authorized):

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
3. **Target anti-rollback is an epoch floor rooted in STM32U585 OTP.** A
   same-epoch ordinary release performs zero OTP writes. An epoch advance uses
   complete fresh quad-words through a proposed typed/replicated codec. The
   physical codec, interruption recovery, and silicon receipts remain open and
   no production codec has been selected;
   the legacy per-bit implementation is not valid or production-eligible.
4. **The FSBL must be immutable after provisioning.** The legacy bench layout
   uses pages 0–3. Draft 1.1 proposes pages 0–4 with a 40,960-byte hard ceiling,
   but the geometry, physical LOAD-span fit, RAM/stack bound, option-byte
   ceremony, and hardware receipts remain unapproved. Any eventual immutable
   FSBL bug is a device replacement.
5. **Candidate power-loss contract.** Draft 1.1 proposes preserving the last confirmed
   fallback through PENDING and ATTEMPTED, seals CONFIRMED only after the
   proposed health/finalization flow, and lets a future approved immutable
   FSBL establish the epoch floor. It is not implementation-approved; its durable
   journal/OTP construction and resource, release-policy, factory, and silicon
   gates remain open. The legacy two-page commit is not power-fail-safe.
6. **User-consent gated.** The target flow shows the new firmware's 8
   BIP-39 measurement words on the NV3007 LCD; the user holds long-right
   to confirm. Matching the words against the vendor's published
   release is the anchor that prevents a MitM companion app from
   slipping a (vendor-signed but user-unauthorised) release in.
7. **FSBL-rooted post-install verification.** Under the future approved
   factory geometry, after COMMIT writes the new slot and the device reboots,
   the WRP-protected FSBL re-hashes
   the now-active slot and renders ITS view of the 8 words on the
   NV3007 LCD before branching into the new firmware. The user MUST see
   the same 8 words FSBL shows that they confirmed at install time
   (the "Nf" page) — if the two diverge, the bytes that landed in
   flash are not the bytes whose hash was signed. Do not enter the
   PIN in that state. See [`measured-boot.md`](../security/measured-boot.md) for
   the threat model and the trust chain.

## Legacy storage layout (not the Draft 1.1 candidate layout)

```
Bank 1 — secure (1 MB, SECWM1: all 128 pages secure):
  pages 0–3       FSBL               32 KB   (legacy bench allocation;
                                               not factory/WRP authority)
  page  4         Manifest A          8 KB
  page  5         Manifest B          8 KB
  page  6         Boot state          8 KB   (try-once + active slot)
  pages 7–64      Slot A secure     464 KB
  pages 65–122    Slot B secure     464 KB
  page  123       Off-chain/UserOp counters       8 KB
  page  124       MCU PIN-attempt log             8 KB
  page  125       Wipe/duress admin state          8 KB
  page  126       Wrapped BHK only (no PBS)        8 KB
  page  127       Legacy secure key/state          8 KB

Bank 2 — non-secure (1 MB, SECWM2: all 128 pages NS):
  pages 0–63      Slot A NS         512 KB
  pages 64–127    Slot B NS         512 KB

OTP user area (starts 0x0BFA_0000):
  32 × 16-B QWs   Physical allocation OPEN; legacy bit tally rejected
```

Current footprint for comparison: secure ≈ 354 KB / 464 KB capacity,
nonsecure ≈ 90 KB / 512 KB capacity. Plenty of headroom.

## Legacy implementation: what gets signed (v0x02)

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

**Legacy behavior: one signature works for either slot.** The vendor emits one
`.pqfw` per release, not two — the same signed bytes install
identically into slot A or slot B. Historical Draft 0.9 proposed slot-bound V4
artifacts; Draft 1.1 instead proposes slot-bound V6 artifacts and separate A/B
signatures. Neither research layout is current implementation authority.

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

## Legacy command flow on the device (production-blocked)

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
   - The current code writes the legacy manifest + boot-state, attempts
     `otp::bump_to(fw_version - 1)`, then resets. Confirmation was moved to
     BEGIN. This sequence is retained for bench diagnosis only: the unary OTP
     operation is invalid and the floor can retire the fallback before health.
4. `CMD_FW_STATUS` / `CMD_FW_ABORT` — progress + cancel at any time.

## Legacy FSBL boot sequence (production-blocked)

Covered in `fsbl/src/main.rs`. Summary:

- Read both manifests.
- Run the same verify chain (structural, CRC, digest, vendor fpr,
  C10 signature, rollback floor) on each.
- Re-hash each candidate's secure + NS images from flash.
- Pick the highest-version fully-valid slot. The two-candidate path consults
  try-once metadata, but the single-candidate fast path cannot revert after
  the floor excludes the old slot:
  - `TRIED + boot_state.active_slot == candidate` → legacy runner-up only if
    that runner-up is still floor-admissible.
  - `COMMITTING` → torn, fall back.
  - `COMMITTED` → safe to boot.
- Set VTOR + jump to the slot's reset handler.

## Vendor release pipeline

> **Currently blocked.** `make release`, `make fsbl-release`, and
> `make prod-check-ship` intentionally fail until an approved rollback
> backend and resource gates close. The commands below document the legacy
> bench tooling; they are not a production release procedure.

```
# One-time, on an offline signing machine.
fwsign keygen --out vendor-key.enc
fwsign pubkey --key vendor-key.enc --out vendor-pubkey.bin
# Review SHA-256(vendor-pubkey.bin), then commit it as the sole line in:
# config/production-firmware-vendor-key.sha256

# Per release.
git checkout $RELEASE_COMMIT
# make release  # REFUSED while the rollback backend is quarantined

fwsign sign \
  --legacy-bench-unsafe \
  --key vendor-key.enc \
  --fsbl target/pqsigner-release/fsbl.elf \
  --trusted-fingerprint target/pqsigner-release/vendor-key.sha256 \
  --version $VERSION_U32 \
  --secure target/pqsigner-release/secure.elf \
  --nonsecure target/pqsigner-release/nonsecure.elf \
  --slot A \
  --build-id $(git rev-parse HEAD | sha256sum | head -c 64) \
  --out release-v${VERSION_U32}.pqfw
```

The former `make release` pipeline is disabled and performs no packaging.
`fwsign sign --legacy-bench-unsafe` retains artifact/key consistency checks for
bench research, but emits unsigned-slot V1 and grants no production authority.

**Legacy: one `.pqfw` per release.** The v0x02 signed preimage doesn't cover
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
FSBL_VENDOR_PUBKEY=/absolute/path/to/vendor-pubkey.bin make release
```

`make release` runs `verify-repro` first (two clean builds, diff).
If that passes, `target/pqsigner-release/secure.elf` and
`target/pqsigner-release/nonsecure.elf` are byte-for-byte identical to what
the vendor built from the same commit.

### 2. Compute the image hashes (optional — `fwsign` will do this internally)

```bash
cargo run -p fwmeasure -- target/pqsigner-release/secure.elf
cargo run -p fwmeasure -- target/pqsigner-release/nonsecure.elf
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
    --secure    target/pqsigner-release/secure.elf \
    --nonsecure target/pqsigner-release/nonsecure.elf \
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
* Production eligibility or device-specific acceptance. No production backend
  is currently authorized. In the target design, the FSBL admits a signed
  `security_epoch > rejected_through_epoch`; runtime COMMIT does not own the
  floor.

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
- `0x6501` — legacy OTP-exhausted status. In the target design, exhausted epoch
  capacity blocks a further security-epoch revocation, not ordinary same-epoch
  releases.
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
| secure `hw::otp`             | ✘ legacy unary codec; production-fenced |
| secure `hw::boot_state`      | ✘ legacy try-once state; replacement interface only proposed by unapproved Draft 1.1 |
| `fsbl/` crate                | ✔ bench build; production release blocked |
| `shared` CMD_FW_* / INS codes | ✔ landed                |
| secure `fw_update/` module   | ✔ landed                 |
| secure `cmd_fw_*` handlers   | ✔ landed                 |
| NSC CMSE veneers             | ✔ landed                 |
| NS `nsc_api` wrappers        | ✔ landed                 |
| NS USB dispatcher            | ✔ landed                 |
| Trusted-UI confirm dialog    | ⚠ stubbed (returns false; must be filled in after the ongoing `secure/src/ui/` refactor lands so it can reuse the same multi-page `confirm()` flow the sign path uses) |
| A/B slot linker scripts      | ⚠ not reshaped (current firmware still boots at 0x0C00_0000; Phase 4 will split the secure/NS memory.x into `--slot A|B` variants) |
| Companion updater tool       | ⚠ out of scope (see `tools/fwupdate.py` as the intended next-session artifact) |
| Draft 1.1 approval/backend/resource fit | ⚠ OPEN — research candidate only; no implementation approval |
| Hardware bring-up            | ⛔ intentionally stopped before sacrificial-silicon tests |
| WRP1A in `ob-configurator`   | ⚠ out of scope — Phase 7 |
| `make flash-hw-production`   | ⚠ out of scope — Phase 7 |

**UPDATE 2026-09-16 — the FSBL half of the boot chain now has a silicon
receipt; the update path above still does not.** Read the "Hardware bring-up"
row narrowly: it means BEGIN / CHUNK / COMMIT and the slot flip have never been
exercised on hardware, and that is still true.

What *did* run, on a pq1 board (AL_A66_MB_V10), is the **non-monolithic boot
path** this subsystem depends on: the FSBL admitted manifest A, re-hashed both
slot images from flash and matched them against the signed manifest, passed the
tz-1 option-byte tripwire, rendered the fingerprint, and **branched into slot
A**. Device read-back receipts: FSBL `4a8d28f7…` (29,616 B), manifest A
`dfd66ca1…`, secure slot A `7ab247ce…` (385,568 B), NS slot A `71acea1e…`
(7,488 B). Reproduced byte-for-byte across two runs, the second from a freshly
erased marker page, with both controls re-read in-session. Details and the
procedural traps are in `docs/hardware/evt-silicon-validation.md`.

That receipt is scoped: it used a `stage-marker` diagnostic build (which gives
the FSBL a flash-write path production forbids) signed with the development
vendor key, at RDP-0 with no WRP and no RDP-2, on the legacy pages-0..3
geometry (cutover #540 still open), and no fault-injection sweep of
`verify_images` has run (#591). It is evidence toward invariant #10's "silicon
receipts" and "non-monolithic shipping image" gates, not closure of either.

Two known latent bugs adjacent to this table, both found 2026-09-16:
`tools/ob-configurator/src/main.rs:124` writes `0x0018_0000` directly to
`FLASH_SECBOOTADD0R` (`FLASH_S + 0x4C`), but that register holds the boot
address in bits `[31:7]`, so the correct word is `0x0C00_007C` (issue #37 states
this explicitly: "the register *word* ≠ the boot *address*"); as written it
selects `0x0018_0000`, and `shared::lockdown::secboot_selects` rejects it. The
same `0x0C00_007C` vs `0x0018_0000` contradiction is the stated blocker on
issue #214, and RM0456 §7.9.16 resolves it — `SECBOOTADD0_BOOT_LOCK` is bit 0,
now pinned in `shared/src/lockdown.rs`.

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
