# USB Firmware-Update Hardening — Audit, Threat Model, Fuzzing

> **First pass, 2026-05-24.** Foundational audit of the over-USB
> firmware-update path against a malicious-host adversary, with a threat
> model, a cross-reference to Trezor's bootloader, and a prioritized
> punch list. The companion `cargo fuzz` harness is in
> `fw-manifest/fuzz/`.

## 0 — What this document is (and isn't)

**Is:** the security-relevant **map** of every byte the host can influence
on the FW-update path, the **defenses** that already gate it (verified
file:line), and a **prioritized list** of hardening opportunities.

**Isn't:** an implementation of fixes. Each finding gets a one-line
recommended change; the actual hardening commits come next, one at a
time, with the fuzz harness re-run after each.

The anti-rollback decision itself is already silicon-validated by
`make fw-rollback-hw` (real `verify_manifest` chain, dev-key signatures,
six assertions including downgrade-rejection — see commit `49c9308`).
The work here covers the **transport + parser + state machine** around
that decision.

---

## 1 — Adversary model

A host that can send arbitrary USB HID frames to the device. Specifically
it **cannot**:

- Press the OLED confirm button (the final COMMIT 4-page dialog requires
  a physical user press; `e2e-test` short-circuits this, but `e2e-test`
  is fenced out of `mode-production`).
- Read or compute the vendor's offline SPHINCS+C10 signing key.
- Bypass the OTP rollback floor (one-way, even with arbitrary USB).

It **can** (this audit's scope):
- Send malformed APDU/HID frames at any rate.
- Send valid-shape frames in adversarial orderings (CHUNK without BEGIN;
  two BEGINs in a row; ABORT mid-stream; STATUS races).
- Forge unsigned manifests, malformed signed manifests, or manifests
  signed by the wrong key.
- Send arbitrary `(chunk_offset, chunk_len, image_kind)` triples.
- Wait indefinitely between APDUs to extend pending state.
- After the user enters their PIN once, run any subsequent CMD until the
  device locks or the FW-update context is dropped.

---

## 2 — Attack surface, end-to-end

Every byte the host writes that reaches the secure world has to cross
these layers. Listed in order:

### 2.1 USB HID transport — `nonsecure/src/usb/{transport,commands,hid}.rs`

| Layer | Bound | Where enforced |
|---|---|---|
| HID report → APDU frame | `lc` ≤ APDU max | `transport.rs` (`usbd_hid` framing) |
| Multi-APDU chain → CHAIN_BUF | ≤ `CHAIN_BUF_LEN` | `chain.step(ins, p1, lc, CHAIN_BUF_LEN)` @ `commands.rs:232`. Bounded by Rust slice indexing on the `copy_from_slice` at 235/241 — no overflow possible. |
| Per-CMD bound (e.g. FW_BEGIN must be exactly `MANIFEST_SIZE`) | exact-length check | `cmd_fw_begin` @ `commands.rs:1091`: `if len != MANIFEST_SIZE { SW_WRONG_LENGTH }`. ✓ |
| Per-CHUNK payload bound | `[FW_CHUNK_HEADER_LEN, FW_CHUNK_HEADER_LEN + FW_MAX_CHUNK]` | `cmd_fw_chunk` @ `commands.rs:1103-1104`. ✓ |

**Gap:** `chain.step` is bounded by the *global* max (`CHAIN_BUF_LEN` = max
of all chains), not the per-CMD limit. So an FW_BEGIN accumulation can
balloon up to `CHAIN_BUF_LEN` bytes before the *execute*-time
`len != MANIFEST_SIZE` check rejects it. Bounded by `CHAIN_BUF_LEN`,
no overflow, but lets an attacker waste cycles. → **LOW**, finding #4.

### 2.2 NSC gateway boundary — `secure/src/nsc/`

Every CMSE veneer entry. Order of checks I verified per handler:

| Handler | Checks (top of `run`) | Destructive op |
|---|---|---|
| `cmd_fw_begin` | (1) PIN sentinel; (2) NS-pointer validate (8 KB); (3) `verify_manifest(m, otp_floor)` (full chain incl. SPHINCS+C10 signature); only then (4) `flash::erase_slot(inactive)` | Erase inactive slot |
| `cmd_fw_chunk` | (1) `HandlerGuard::enter()` (blocks SysTick idle-wipe); (2) PIN sentinel; (3) total_len bounded; (4) NS-pointer validate; (5) snapshot header+data; (6) `check_chunk` (size, monotonicity, `checked_add` for `offset+len` AND `base+offset`); only then `staging::write_chunk` | Flash quadword writes |
| `cmd_fw_commit` | (1) PIN sentinel; (2) take `FW_UPDATE` ctx; (3) `verify::verify_images` (re-hash from flash, compare against signed hashes); (4) `confirm_commit` (4-page OLED dialog) | `otp::bump_to(new_ver)` + manifest write + boot-state write + `sys_reset` |
| `cmd_fw_status` | (1) PIN sentinel; reads `FW_UPDATE` state | None |
| `cmd_fw_abort` | (no PIN) drops `FW_UPDATE` (zeroizes via Drop) | None — leftover half-erased pages are harmless (FSBL rejects manifest-less slot) |

**Verified good:**
- ✓ Slot erase happens **after** the full verify chain (incl. signature)
  in BEGIN — contra one of the Explore audit's claims.
- ✓ PIN is rechecked at every CHUNK (`peek_state(|s| s.pin_verified.check_sentinel()) != OK_SENTINEL`) — contra another Explore claim.
- ✓ `check_chunk` uses `checked_add` on both `offset + len` and
  `base_addr + chunk_offset` — both layers protected against overflow.
- ✓ `FwUpdateCtx` is `ZeroizeOnDrop`; BEGIN drops the prior context
  on re-seed; ABORT drops it.

### 2.3 Manifest parser — `fw-manifest/src/lib.rs`

The verify chain (run from `fw_update::verify_manifest`):

1. `verify_structural` — magic, manifest_version, slot byte legal.
2. `verify_crc` — CRC-32 IEEE over `[0..OFF_CRC32)` (covers everything
   incl. the signature region — flipping any byte breaks CRC first).
3. `verify_digest` — recomputes `SHA-256(signed_preimage)`, compares to
   the manifest's stored digest. Recomputed, not trusted.
4. `verify_vendor_fpr` — `SHA-256(pk_seed||pk_root) == manifest.fpr`.
5. `verify_signature` — `sphincs_c10::verify(pk, digest, sig)`, wrapped
   in `fi::check_true_into_sentinel` (F-7 FI hardening: double-evaluate
   with `wait_random` between, sentinel commit).
6. `verify_rollback` — `fw_version > rollback_floor` (strict).

---

## 3 — Threat scenarios

For each: what the attacker tries, where it's caught.

| # | Scenario | Caught at | Status |
|---|---|---|---|
| 1 | Forge manifest, sign with wrong key | step 4 `verify_vendor_fpr` (or 5) | ✓ defended |
| 2 | Sign correctly but bump version below floor | step 6 `verify_rollback` (silicon-validated by `fw-rollback-hw`) | ✓ defended |
| 3 | CHUNK without preceding BEGIN | `FW_UPDATE.is_none()` → reject | ✓ |
| 4 | COMMIT without BEGIN | same | ✓ |
| 5 | BEGIN twice → second one re-erases the slot, drops the first ctx (zeroized) | by design — see `fw_update/mod.rs` comment "earlier BEGIN without COMMIT/ABORT drops here and zeroises" | ✓ |
| 6 | ABORT mid-stream, then re-BEGIN — does old hash state leak in? | `FW_UPDATE = None` zeroizes; new BEGIN re-erases + seeds fresh `IncrementalSha256` | ✓ |
| 7 | Send CHUNK with `chunk_offset = u32::MAX` | `check_chunk` uses `checked_add` — returns `Overflow` | ✓ |
| 8 | Send CHUNK with valid arithmetic but `chunk_offset != received` | `check_chunk` rejects with `NonMonotonic` | ✓ |
| 9 | Send 4 GB CHUNK | `chunk_len > FW_MAX_CHUNK` → `TooLarge` | ✓ |
| 10 | Send valid-shape CHUNK with `data.len()` ≠ declared `chunk_len` | NS chunk parser checks declared vs actual; secure-side `check_chunk` validates against `data_len` | ✓ |
| 11 | **Sign a manifest declaring `secure_len = 0xFFFF_FFFF`** | `check_chunk` only validates `end > expected_len` (the declared one), NOT against actual slot capacity → would let chunks past the slot if `checked_add` survived. **Finding #1** | **Gap** |
| 12 | Race CHUNK against SysTick idle-wipe | `HandlerGuard::enter()` blocks the wipe for chunk duration | ✓ |
| 13 | Lock the device mid-stream, then continue CHUNKs from a different host | PIN sentinel rechecked every CHUNK | ✓ |
| 14 | After PIN unlock, run an FW-update without the user noticing | `confirm_commit` requires physical button press on a 4-page dialog before any OTP/flash | ✓ |
| 15 | Timing-leak the vendor pubkey via the fpr compare | Slice `==` is short-circuiting; **the value compared is the build-baked public fpr** — leaking it tells the attacker nothing they don't already have. **Finding #2** (LOW, hygiene) | Hygiene gap |
| 16 | Tamper bytes inside the signature region | CRC covers `[0..OFF_CRC32)` (incl. sig region) → CRC mismatch *before* sig check. To isolate sig-only failures, the test corrupts the sig pre-finalize (CRC recomputed). | ✓ — by design |
| 17 | OOM the device by sending many partial APDU streams | CHAIN_BUF is fixed-size; partial streams can't grow it | ✓ |
| 18 | Wedge the device by sending half an APDU then never finishing | Inactivity timeout (120 s) eventually elapses; idle wipe runs (`HandlerGuard` doesn't hold across CHUNKs) | ✓ (relies on timeout) |
| 19 | Trigger `confirm_commit` and hold the device hostage in the dialog | The dialog presents 4 pages of fingerprint/version info; **timeout behavior is worth verifying** (open question) | Open Q |
| 20 | Reserved bytes in the manifest used as a covert channel | `verify_structural` may not enforce reserved bytes are zero (open question) | Open Q |
| 21 | Call `write_chunk` directly without `check_chunk` (future code path) | `write_chunk` has `base_addr + chunk_offset` and `expected - received` arithmetic with NO defense-in-depth checks — assumes caller validated. **Finding #3** | Internal coupling |
| 22 | Send `image_kind = 0xFF` | `staging::write_chunk` returns `BadKind`; `check_chunk` also validates → reject | ✓ |
| 23 | Brick the active slot during update | BEGIN computes `inactive = !active`, erases only that. The active slot's running image is on the alternate bank. | ✓ (A/B slot design) |

---

## 4 — Cross-reference: Trezor bootloader USB FW-update

Trezor's analogue lives in `core/embed/projects/bootloader/`. Key
contrasts and shared patterns:

| Defense | Trezor | PQSigner | Note |
|---|---|---|---|
| Wire format | **protobuf** (`messages.proto`: `FirmwareErase`, `FirmwareUpload`, …) — self-describing, strongly-typed | **fixed 8 KB binary manifest** + APDU chain — simpler, no parser complexity, less self-describing | Trade-off: protobuf gives stronger framing guarantees but adds a fuzz-attack surface (the nanopb decoder). Our manifest's structural check is a few bytes. |
| Host-declared length bound | `FirmwareErase.length` is **bounded against `FIRMWARE_MAXSIZE`** (1664 KB per model) | `expected_secure_len` / `expected_nonsecure_len` from the manifest are **not bounded against slot capacity** — only against themselves at CHUNK time | **Adopt.** See finding #1. |
| Per-chunk size | `IMAGE_CHUNK_SIZE = 128 KB` (Trezor) | `FW_MAX_CHUNK` (smaller; HID-friendly) | Both bound per-chunk; our smaller size means more APDUs, but USB HID throughput is the bottleneck either way. |
| Signature scheme | Ed25519 (multi-sig vendor in some models) | SPHINCS+C10 (PQ) | Different threat model; our PQ choice is invariant #5. |
| Anti-rollback | `FIRMWARE_MONOTONIC_VERSION` — bootloader rejects below current | `verify_rollback` with OTP floor — strict `fw_version > floor` | Same model. Silicon-validated this session. |
| User confirm before destructive op | User enters bootloader = consent; firmware erase proceeds | `confirm_commit` 4-page OLED dialog before *any* OTP/flash write | We're stricter — the user actively confirms each commit, not just the upgrade session. |
| A/B slot recovery after bad update | Bricks until reflash on most models (single-slot) | **A/B slots** — bad update means FSBL falls back to the still-good active slot | We're better here. |
| Fuzzing | Has a `tests/` directory with mostly happy-path unit tests; no formal fuzz harness in the public tree | Adding one now (this session). | |

**Trezor's `FirmwareErase.length` bound is the cleanest pattern to copy.**
That's finding #1.

---

## 5 — Prioritized findings

Each finding: `SEVERITY | LOCATION | one-line problem | one-line fix`.
Only items I **verified by reading the code myself** (the Explore agent's
audit had several confidently-wrong specifics; those are excluded).

| # | Sev | Where | Problem | Fix |
|---|---|---|---|---|
| 1 | **MED** | `secure/src/nsc/cmd_fw_begin.rs` BEGIN seeding (~line 105–120) | Manifest-declared `secure_len`/`nonsecure_len` not bounded against actual slot capacity. A signed manifest with absurd lengths would let later chunks write past the slot until per-chunk `checked_add` finally trips. Signature-gated, but Trezor bounds this explicitly. | In BEGIN, reject manifests where `m.secure_len() > slot_secure_capacity()` or `m.nonsecure_len() > slot_ns_capacity()`. |
| 2 | LOW | `fw-manifest/src/lib.rs:428` | `verify_vendor_fpr` uses `&expected == self.vendor_pubkey_fpr()` — Rust slice `==` is short-circuiting. The value isn't secret (it's the build-baked public fpr), so the leak reveals nothing; but it's an unmotivated non-CT compare in a security-critical path. | Use `subtle::ConstantTimeEq::ct_eq` for hygiene. |
| 3 | LOW | `secure/src/fw_update/staging.rs::write_chunk` | All arithmetic (`base_addr + chunk_offset`, `expected - received`, `abs_addr + off`) is unchecked, relying on `check_chunk` having been called first. Today the only caller does call it; any future code path that calls `write_chunk` directly has overflow/underflow bugs latent. | Either belt-and-braces `checked_add`/`checked_sub` inside `write_chunk`, or typestate (a `ChunkValidated` token from `check_chunk` that `write_chunk` requires). |
| 4 | LOW | `nonsecure/src/usb/commands.rs:232` | `chain.step(ins, p1, lc, CHAIN_BUF_LEN)` passes the *global* max as the bound; per-CMD bounds are checked only at execute time. Lets an attacker accumulate up to `CHAIN_BUF_LEN` bytes before per-CMD rejection. Bounded by Rust slice indexing — no overflow — just wasted cycles. | Switch on `ins` and pass the per-CMD bound (`CHAIN_BUF_LEN_FW`, `CHAIN_BUF_LEN_SIGN`, etc.). |
| 5 | INFO | `fw-manifest/src/lib.rs` `verify_structural` | Open Q: are reserved bytes (`OFF_RESERVED_1`) verified to be zero? If not, they're a 2-byte covert channel from a malicious vendor. | Verify; if missing, add `if self.bytes[OFF_RESERVED_1..OFF_RESERVED_1+2] != [0, 0] { return Err(Structural) }`. |
| 6 | INFO | `secure/src/fw_update/mod.rs::confirm_commit` | Open Q: does the 4-page dialog have a timeout? An attacker who reaches COMMIT can otherwise pin the device in the dialog indefinitely (user can press cancel, but a slow-burn DoS until power cycle). | Verify; if missing, bound on the same 120 s inactivity TIM as the rest of the secure world. |

**Not findings (verified false from the Explore audit, included here so
they don't get re-litigated):**

- PIN-not-rechecked-per-CHUNK → **wrong**: `cmd_fw_chunk` rechecks the
  PIN sentinel at every CHUNK call.
- Slot erase before validation → **wrong**: erase runs only after the
  full `verify_manifest` chain (incl. signature) returns Ok.
- `check_chunk` overflow → **wrong**: uses `checked_add` at both
  arithmetic layers.

---

## 6 — Fuzzing harness

Scaffold at `fw-manifest/fuzz/` (cargo-fuzz / libFuzzer). The targets
are organized by **how close to attacker input** they sit:

1. **`fuzz_target_verify_manifest`** — feed an arbitrary 8 KB byte slice
   into `ManifestRef::new` + the **full** verify chain (structural →
   CRC → digest → vendor_fpr → signature → rollback). Stub the vendor
   pubkey with a fixed pair so the fuzzer drives bytes, not keys.
   Crashes/panics from any input are bugs. This is the **highest-value
   target** because it sits right at the boundary between attacker bytes
   and the secure-world trust decision.
2. **`fuzz_target_structural_crc`** — narrower: structural + CRC only.
   Faster iteration; catches parser bugs without the SPHINCS verify
   bottleneck.
3. **`fuzz_target_check_chunk`** — `(image_kind, chunk_offset, chunk_len)`
   tuples against a stubbed `FwUpdateCtx`. Validates the arithmetic /
   monotonicity guards.

**Initial corpus:** a known-good dev-signed manifest from
`make fw-rollback-hw` (extracted via probe-rs at runtime, or
generated by the existing in-firmware path); plus a few mutations
(bit-flips in each field) so the fuzzer has a baseline of "almost
valid" to mutate.

**Coverage:** the SPHINCS+C10 verify itself is a known-good external
dep (the sphincs-c10 crate has its own KAT tests); we don't fuzz the
crypto, we fuzz the **framing** + **structural** + **arithmetic**
around it.

**How to run** (once nightly + cargo-fuzz are installed):

```bash
cd fw-manifest && cargo +nightly fuzz run fuzz_target_verify_manifest
```

A `make fuzz-manifest` target wraps this. The harness is host-side (no
hardware required); CI can run it on a budget. Crashes land in
`fuzz/artifacts/`.

---

## 7 — Open questions queued for the implementation pass

These need verification before fixing (so we don't "fix" something that
isn't broken — see the Explore-audit false-positive list in §5):

1. Does `verify_structural` already reject non-zero reserved bytes?
   (Finding #5.)
2. Does `confirm_commit` honour the 120 s inactivity timeout, or can an
   attacker pin the user in the dialog? (Finding #6.)
3. Should we ever permit an in-flight CHUNK to span the secure/NS image
   boundary? (Today it can't, because `image_kind` is fixed per-chunk
   and `received_secure`/`received_nonsecure` are tracked separately —
   but the design intent is worth documenting.)

---

## 8 — Suggested implementation order

1. **Finding #1** (bound `secure_len`/`nonsecure_len` against slot
   capacity) — single highest-value change. ~5 lines in BEGIN.
2. **Finding #2** (CT compare in `verify_vendor_fpr`) — 3 lines.
3. **Findings #5/#6** — verify open questions; either close (with a
   doc/work-todo note) or patch.
4. **Finding #4** (per-CMD chain bound) — straightforward switch on `ins`.
5. **Finding #3** (`write_chunk` belt-and-braces) — small refactor; do
   after the fuzz harness has a clean baseline, so we can confirm the
   refactor doesn't break the happy path.
6. Run `make fuzz-manifest` after each change. Commit per finding.
