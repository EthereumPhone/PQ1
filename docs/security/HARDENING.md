# Hardware Wallet Hardening Requirements

**Project:** SPHINCS+ hardware wallet on STM32U585 (B-U585I-IOT02A) + NXP EdgeLock SE050, Rust, TrustZone-M.

**Purpose:** Consolidated security requirements and invariants. Every item here is load-bearing. Skipping any of them weakens the whole chain.

---

## 1. Threat Model (Write This Down First)

Before writing code, commit to an explicit threat model. The design below targets:

- **In scope:** remote/software attackers, firmware exploits, stolen powered-off device, bus snooping, casual physical access, skilled physical attacker with bench equipment during or shortly after a legitimate unlock.
- **Out of scope (acknowledge explicitly):** nation-state lab attackers with unlimited FIB/SEM budget, coerced unlock (rubber-hose, shoulder-surf), supply-chain compromise of silicon vendors.
- **Partially mitigated:** fault injection, cold-boot attacks on SRAM, SE050 die-level invasive attacks.

Document your trust boundaries, your list of secrets, and where each secret is allowed to exist (which chip, which memory region, which lifetime). Enforce those invariants in the Rust type system.

---

## 2. Architecture Invariants

### 2.1 Secret Residency Rules

| Secret | Lives in | Never allowed in |
|---|---|---|
| BIP-39 entropy / seed | SE050 at rest; U585 Secure SRAM briefly during signing | U585 flash, NS world, logs, debug output |
| SPHINCS+ `SK.seed`, `SK.prf`, `PK.seed` | U585 Secure SRAM briefly during signing | Anywhere persistent on U585, NS world |
| SCP03 static keys | Factory transport keys derive from the factory-burned per-device OTP master. The candidate first-field flow replaces them with final keys derived from the BHK (no TRNG salt); production approval and recovery evidence remain OPEN | Flash as a standalone key blob, NS world, logs, debug output |
| PIN (raw) | U585 Secure SRAM for microseconds during stretching | Anywhere else, ever |
| Stretched PIN (AESKey credential) | U585 Secure SRAM for one SCP03 handshake | Persistent storage, NS world |
| SE050 attestation root cert | U585 Secure flash (hardcoded in image) | N/A (public) |

### 2.2 World Separation

- **Secure world owns:** I²C driver to SE050, SCP03 state, PIN stretching, SPHINCS+ implementation, all secret handling, the inactivity timer, the wipe routine.
- **Non-Secure world owns:** UI, keypad/touch, display, network (if any), everything else.
- **NSC boundary:** minimal surface. Entry points accept opaque requests (sign this hash, unlock with this PIN) and return only non-secret outputs (signatures, success/failure, public keys).

### 2.3 The Seed Never Crosses to NS

There is no legitimate NSC call that returns the seed, the mnemonic, the SPHINCS+ secret key, or any derivative from which they can be recovered. If you find yourself writing one, stop and redesign.

---

### 2.4 Trusted-display consent gate

Two consent policies coexist, by path, since 2026-09-22:

| Path | The sign gesture is armed… | Since |
|---|---|---|
| Legacy 16×4 page dialog (`ui::confirm`, `confirm_core::seen_last`) | only after the LAST page has been displayed (scroll-to-end; a premature long-right / chord is demoted to "advance one page") | `ccfa5f61`, 2026-06-26 (WYSIWYS audit: every spliced loud page — native value, gas, Safe refund, ERC-8213 — was skippable from page 0) |
| Pixel trusted UI (`ui-px`, `ui::px::confirm_px` / `px::lcd::run_flow`, pilot = Safe flow) | on the opening ask, the auto-inserted `Confirm?` (6th screen when ≥ 7 details) and the returning ask; **never on a detail** | owner decision 2026-09-22, following PQ-UI `DESIGN.md` § Input "Commit arming" |

**UPDATE 2026-09-22 (later the same day, owner decision on the EVT):** on the
pixel path the sign gesture is the **two-button chord click** — both buttons
down together, the sign fires when both are released
(`InputFsm` → `Gesture::ChordClick` → `FlowDriver` `Gesture::Chord` →
`NavResult::Sign`) — not the design's 2 s hold-right, which is now a no-op
everywhere on that path (hold-left still declines everywhere). Rationale:
parity with the legacy dialog, whose `hw::buttons::wait_event` has always
synthesised the two-button chord as the confirm. Residual accepted: the sign
is an instantaneous gesture rather than a 2 s deliberate hold, so a squeeze
on a commit-armed screen signs; a chord formed from the post-tap window (one
side already up) never clicks, so a fast left-tap-then-right-tap cannot
sign, and details remain unarmed. The `FihBool` gate and single
`OK_SENTINEL` site are unchanged. PQ-UI `DESIGN.md` § Input (vendored) still
describes hold-right; the device deviates here and in `TAP_MAX_MS` (500 ms).

The pixel path intentionally re-opens the class the 2026-06-26 fix closed for
that path only: a user can sign from the opening ask without paging through
the details. Mitigations the design supplies: declining is armed on every
screen (hold-left), the `Confirm?` early exit sits after five detail screens,
the returning ask is the demo's canonical hold point, and every value the
legacy pages showed is present in the transcript (host fact differential in
`safe_screens_render_pure_tests.rs`). The arming flag is a `FihBool`
re-derived from the record's `commit` byte (double read) on every screen
change; the `OK_SENTINEL` is minted at exactly one site.

**Revert switch:** `secure/src/ui/px/confirm_px.rs::PX_COMMIT_REQUIRES_SEEN_LAST = true`
restores scroll-to-end semantics on the pixel path (hold-right on the asks is
a no-op until the returning ask has been displayed); the loop maintains
`seen_last` either way so no other change is needed. Do not re-litigate the
owner decision without new evidence; record any change here and in
`CLAUDE.md` Pre-Production Caveats.

**Device input model (frozen 2026-09-23, port plan step 1).** The
device's gesture grammar on the pixel path is this table; the conformance
oracle is the vendored PQ-UI `handoff/spec/gestures.json` (an 80-row executed
truth table) + `traces.json`, and the deliberate deviations from it are the
single list `tools/pq-ui/PORT_DEVIATIONS.toml`, machine-checked against
`handoff/spec/motion.json` by `make pq-ui-port-diff` (an unrecorded drift is
a red build).

| Constant (`pqsigner-ui-px`) | Device | Reference | Note |
|---|---|---|---|
| `DEBOUNCE_MS` (`input.rs`) | 25 | — | SysTick ISR lockout per side, first edge exact; device-only |
| `TAP_MAX_MS` (`motion.rs`) | **500** | 250 | recorded deviation (EVT #1 2026-09-22: deliberate presses run 250–400 ms) |
| `DOUBLE_TAP_MS` | 250 | 250 | entry contexts only |
| `CHORD_MS` | 150 | 150 | the other side within this = the chord |
| `HOLD_COMMIT_MS` | 2000 | 2000 | hold-left decline fires here |
| `HOLD_SNAPBACK_MS` | 200 | 200 | early-release drain |
| `PRESS_FEEDBACK_MS` | 120 | 120 | chevron nudge |

| Screen kind | tap L / R | hold-left | hold-right | chord click (both down, fires on release) |
|---|---|---|---|---|
| Hero (opening / returning ask), `Confirm?` | navigate | decline | **no-op** (reference: sign) | **sign** (reference: unbound) |
| Detail / Value | navigate, page-turn | decline | no-op | ignored (never armed) |
| Status / film / ending | **input-dead**: edges are ignored while the film plays and its result holds; the inactivity deadline and idle wipe stay enforced | | | |

Input during a transit retargets the springs and is never dropped. The film
(`ui::px::lcd::film_*`) runs around the signer's FI chain, paced by its opaque
`fn(u8)` progress hook, and cannot change any decision: by the time it
starts, the `OK_SENTINEL` has been minted and re-proved. The upstream
catalogue (`handoff/catalog/actions/{hold-right-sign,unbound-gestures,
tap-navigate}.md`) still describes the reference grammar; a device-deviation
note for those pages is proposed upstream (see `tools/pq-ui/UPSTREAM.txt`).

## 3. SE050 Configuration

### 3.1 Authentication Object

- Type: **AESKey** (not UserID — UserID is plaintext on the I²C bus).
- `TAG_MAX_ATTEMPTS = 10`. Must be non-zero; zero means infinite.
- Credential is the *stretched* PIN output, never the raw PIN.
- Counter is pre-decremented in flash before verify — power-pull during verify does not grant a free retry.

### 3.2 Seed Storage Object

- Type: Binary file object containing the 16–32 bytes of BIP-39 entropy.
- Policy: `ALLOW_READ` **only** when authenticated by the specific Auth Object ID above.
- Policy: **no** access for Auth Object ID `0x00000000` (the "any user" pseudo-ID).
- Policy: **no** `ALLOW_WRITE` or `ALLOW_DELETE` except for a distinct admin auth object used only during provisioning.
- Consider storing the precomputed SPHINCS+ `PK.root` in a separate non-secret binary object to avoid recomputing on every boot.

### 3.3 Channel

- **SCP03** via AESKey or ECKey (FastSCP) auth. Prefer ECKey for cleaner at-rest posture (no shared symmetric secret in U585 flash).
- All communication with the SE050 after boot attestation must run inside an SCP03 session. No plaintext APDUs touching secrets, ever.

### 3.4 Boot-Time Attestation

On every boot, before trusting the SE050:

1. Generate a fresh random nonce in Secure world (from U585 TRNG or SE050 RNG — do not reuse).
2. Request an attested signature over the nonce using the SE050's NXP-provisioned attestation key.
3. Verify the signature chains to NXP's root certificate, hardcoded in the Secure image.
4. Verify the SE050's unique ID matches the value pinned at provisioning time. A genuine-but-different SE050 must be rejected.
5. Only then open the SCP03 session.
6. On any failure: refuse to proceed, display a tamper warning, do not accept a PIN.

### 3.5 Provisioning

- **Current lifecycle split (work-todo #36):** the factory burns the per-device OTP master and uses it to install the device's transport SCP03/admin/PBS credentials plus the required SE structure, policy, and attestation state. It then ships at RDP-0 so the owner can verify flash and option bytes before first power. It does not install the final pairing credentials, perform the BHK first write, create the wallet seed, or set RDP-2.
- On first field boot, after pre-power verification, the **secure app early-boot** candidate self-locks RDP-2 and performs the BHK first write. It then replaces SE050 transport credentials with unsalted BHK-derived final SCP03/admin credentials and replaces the OPTIGA transport PBS with a final value derived from the per-die DHUK plus a fresh TRNG salt persisted in the page-127 journal, before the seed wizard. The FSBL only authenticates and hands off the selected slot.
- That candidate is implemented behind `rdp2-self-lock`, but the authenticated handoff, authenticate-before-rotate rule, old/new/KVN recovery proof, exact E140 ordering, silicon receipts, and production approval remain OPEN. This document does not authorize an irreversible action; follow the `EthereumPhone/PQ1` production gates (labels `source:production-todo`, `ship-blocker`) and work-todo #36.
- The storage boundary is: flash page 126 holds only the DHUK-wrapped BHK; page 127 owns the first-boot journal and non-secret OPTIGA salt; final SE050 SCP03/admin material derives from the BHK and has no standalone flash key blob.
- Create the PIN-auth and seed objects only during the reviewed first-field ceremony after the final secure-channel rotation.
- Pin the SE050 unique ID to U585 Secure flash.
- Apply SE050 transport lock if applicable to your variant.
- U585 RDP Level 2 is the final MCU option-byte lockdown step before the final pairing rotation and seed wizard. **Irreversible; per work-todo #36 the candidate programs it from secure-app early boot on first field boot, not at the factory: devices ship at RDP-0 so users can verify flash, option bytes, and OTP over SWD before first power.**
- Consider NXP EdgeLock 2GO if you need to provision at volume.
- Provisioning must run in a clean-room environment. A compromised provisioning station compromises every device that passes through it.

---

## 4. STM32U585 Configuration

### 4.1 TrustZone & Memory Protection

- Enable TrustZone. Configure SAU and IDAU to partition flash, SRAM, and peripherals.
- **GTZC configuration is the #1 source of TrustZone-M leaks.** Budget real time for it and have it reviewed.
- Mark as Secure: I²C to SE050, TIM used for inactivity timer, TAMP, SAES, PKA, HASH, TRNG, BKPSRAM holding secrets.
- Block **all** DMA controllers from mastering into Secure SRAM unless the DMA instance is itself Secure.
- MPU regions covering Secret SRAM must be enforced in both S and NS worlds.

### 4.2 Debug & Readout Protection

- **RDP Level 2** in production. Irreversible. The current candidate self-programs it from secure-app early boot on first field boot — devices ship at RDP-0 for pre-first-power user verification (work-todo #36).
- Debug ports (SWD, JTAG) disabled by RDP-2.
- Boot from internal flash only. Disable bootloader access in option bytes.
- Verify the RDP level in boot code; refuse to run if debug build flags are set in a production image.

### 4.3 At-Rest Key Protection

- The candidate's factory transport PBS derives from the factory-burned per-device OTP master; its final OPTIGA PBS derives from the per-die DHUK plus the non-secret TRNG salt persisted in page 127. Legacy bench builds may still use deterministic DHUK or development roots.
- Flash page 126 stores only the BHK wrapped under the per-die DHUK; final SE050 SCP03/admin material derives from that BHK without the OPTIGA salt.
- A flash dump transplanted to another U585 must be useless.
- The candidate derivations are implemented, but first-field handoff/recovery, E140 ordering, silicon evidence, and production approval remain OPEN.

### 4.4 Hardware Peripherals to Use

- **TRNG**: for all nonces, challenges, and any randomness. Audit that `rand_core` is wired to this, not to a software PRNG.
- **HASH**: for SHA-256 acceleration inside SPHINCS+ (pick the SHA2 parameter set specifically to benefit from this).
- **SAES**: for DHUK/BHK derivation and BHK wrap/unwrap operations; the hardware roots never become CPU-visible.
- **TAMP**: wire any tamper inputs (case switch, mesh) into the wipe handler.
- **BOR**: set to a high threshold so brownout detection fires with enough headroom for the wipe ISR.

### 4.5 Inactivity Timer (2-Minute Seed Wipe)

- Timer runs on a **Secure** TIM instance. NS world cannot stop, reprogram, or observe it.
- "Activity" is defined by Secure world (e.g., completed signing operation). NS world opinion is ignored; a compromised NS image cannot keep the seed alive by spamming fake activity.
- On timeout: fire the wipe routine.
- Also fire the wipe on: tamper event, unexpected reset reason, low-power mode entry, integrity check failure, any NSC call returning an error, brownout interrupt.

### 4.6 Power-Loss Wipe

- External supervisor or programmable BOR trips above the minimum operating voltage, with enough margin for the wipe ISR to complete.
- Bulk capacitor sized to hold the U585 through the worst-case ISR runtime under full load. **Measure this on real hardware; don't estimate.**
- Wipe ISR: zeroize Secret SRAM regions, clear caches, clear CPU registers, write a "clean shutdown" flag.
- Wipe ISR is written defensively: loop twice, verify after, use DMA/SAES for bulk clearing if faster than software loop.
- Same ISR handler is invoked by TAMP events.

### 4.7 Temperature Sensing

- Use the internal temperature sensor to refuse operation below (e.g.) 0°C, mitigating cold-boot attacks that freeze SRAM to extend retention.
- Check temperature on boot and periodically during operation.

---

## 5. PIN Handling

### 5.1 Flow

1. NS UI collects PIN digits, passes a byte buffer into a Secure NSC entry point.
2. Secure world copies the PIN into a Secure-only buffer, zeroizes the NS-facing buffer immediately.
3. Secure world computes `PIN_key = KDF(PIN, device_salt)` where:
   - KDF is PBKDF2-HMAC-SHA256 with a high iteration count.
   - `device_salt` is a random per-device value stored on the SE050 as a non-secret binary object.
4. `PIN_key` is used as the AESKey credential to open an SCP03 session against the SE050's PIN auth object.
5. On success: read the seed binary object inside the SCP03 session.
6. Zeroize `PIN_key` and the raw PIN immediately after the SCP03 handshake completes.

### 5.2 Stretching Requirements

- Iteration count / memory parameter sized so that a single PIN guess takes hundreds of milliseconds on the U585. Users will feel it; that's the point.
- Even if the SE050's retry counter is somehow bypassed, per-guess CPU cost makes offline brute force painful.
- The stretched value is a 128-bit AES key, not a short PIN.

### 5.3 Consider

- **Duress PIN:** a second PIN that unlocks a decoy wallet or triggers a wipe. Architectural, not a bug, but worth deciding on.
- **Progressive delay:** increasing delay between attempts in Secure world before the SCP03 handshake is attempted, to make online brute force slower than the 10-strike limit would suggest.

---

## 6. SPHINCS+ Implementation

### 6.1 Parameter Set

- Use **SPHINCS+C10** (`h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205`, 4008-byte signature) with SHA-256 on this platform. Rationale:
  - `f` variants are dramatically faster than `s` variants on Cortex-M33 (often 10-30×).
  - SHA2 lets you use the U585 HASH peripheral for the inner hash loop.
  - SHAKE and Haraka have no hardware acceleration on this chip.
- Benchmark on real hardware before committing. Paper numbers lie.
- Document the parameter set in your protocol spec with a domain separation tag; changing it later is a migration problem.

### 6.2 Derivation from BIP-39

1. Read 16–32 bytes of entropy from SE050 over SCP03.
2. Compute BIP-39 seed: `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048)` → 64 bytes.
3. Derive SPHINCS+ key material via HKDF-SHA256 with an explicit domain separation label, e.g. `"SPHINCS+C10/v1"`.
4. Extract `SK.seed`, `SK.prf`, `PK.seed` (3 × *n* bytes).
5. Run SPHINCS+ keygen to compute `PK.root`, or load it from the SE050 if precomputed.

**Question to resolve:** do you actually need BIP-39? If human-recoverable word lists aren't a product requirement, store the SPHINCS+ seed material directly on the SE050 and skip the BIP-39 layer. Simpler, less code, smaller attack surface.

### 6.3 Implementation Sourcing

- Candidates: `pqcrypto-sphincsplus` (PQClean via FFI), pure-Rust `sphincs-plus` crates.
- Audit whichever you pick. "Reference implementation" and "pure Rust" both mean "not necessarily constant-time or fault-hardened."
- Pin the version. Vendor the code if you can. Review every line that touches `SK.seed` or `SK.prf`.
- Run against NIST PQC test vectors in CI. Differential test against a second implementation if possible.

### 6.4 Side-Channel Hardening

- Constant-time execution for every secret-dependent operation. `subtle` crate for comparisons and conditional selects.
- No secret-dependent branches, no secret-dependent memory access patterns.
- Disable compiler optimizations that might introduce variable-time code (e.g., table lookups that become branches). Inspect the generated assembly for critical inner loops.
- Power analysis is a real threat on an unshielded board. Full DPA resistance is hard, but at minimum avoid the worst patterns (secret-dependent hash inputs without randomization).

### 6.5 Fault Hardening

- Redundant computation of critical steps (WOTS+ chains, FORS).
- **Verify the signature before releasing it.** If verification fails, zeroize and refuse. This catches fault injections that corrupted the signing process.
- Canary values checked at function boundaries.
- Control-flow integrity where practical.
- None of this is in PQClean or most pure-Rust crates by default. You add it.

### 6.6 Memory Budget

- Secret key material: up to 96 bytes.
- Signing working set: 8–64 KB of stack depending on parameter set.
- Signature buffer: 4008 bytes (SPHINCS+C10).
- Ensure Secure-world stack is sized accordingly. Default CubeIDE/CubeMX stacks are too small.
- All of this must be in Secure SRAM, GTZC-protected.

---

## 7. Rust-Specific Requirements

### 7.1 Toolchain & Targets

- Target: `thumbv8m.main-none-eabihf`.
- Stable Rust where possible. Nightly only if required for `cmse_nonsecure_entry` or similar — document the exact reason.
- Separate crates for Secure image and NS image; shared `nsc-interface` crate defining the ABI with `#[repr(C)]` types.
- Reproducible builds. Pin the toolchain version in `rust-toolchain.toml`.

### 7.2 Mandatory Crates

- **`zeroize`**: for every secret. Use `ZeroizeOnDrop` derives. Do not rely on plain `Drop` or manual assignment — the compiler will elide it.
- **`subtle`**: for constant-time operations.
- **`rand_core`** wired to U585 TRNG or SE050 RNG. Never a software PRNG for secrets.
- Audit every other dependency that touches secrets.

### 7.3 Lints & Build

- `#![deny(unsafe_op_in_unsafe_fn)]`
- `#![warn(clippy::pedantic, clippy::nursery)]`
- `#![deny(clippy::indexing_slicing)]` (forces explicit bounds handling)
- Every `unsafe` block has a `// SAFETY:` comment explaining the invariant. Reviewed explicitly in code review.
- `cargo audit` and `cargo deny` in CI. Fail the build on any advisory.
- `cargo-geiger` to track `unsafe` surface across dependencies.

### 7.4 Type System Enforcement

Lean into the type system to make invariants compile-time errors:

- `struct Seed([u8; 64])` with `ZeroizeOnDrop`, constructed only inside the unlock flow, consumed by signing.
- `struct UnlockedSession<'a>` that borrows from a live SCP03 session; signing functions take `&UnlockedSession` so they cannot be called without one.
- `struct NsPtr<T>` wrapping raw pointers from NS with a checked constructor that validates length and alignment. Rest of the Secure code only handles validated types.
- Mark secret-bearing types `!Copy` and `!Clone` so they can't be silently duplicated.

### 7.5 NSC Boundary

- Every NSC entry point validates every parameter. Treat NS as fully hostile.
- Length fields validated before use.
- Pointers validated to point into NS memory, not into Secure memory (prevents NS from tricking Secure into reading its own secrets through a "buffer").
- No panics across the NSC boundary. Set a panic handler that wipes secrets and resets.
- Return types expose only non-secret data.

### 7.6 What Rust Does Not Save You From

Say this out loud to yourself before every commit:

- Side-channel leaks. The borrow checker does not know what timing is.
- Fault injection. Rust compiles to the same machine code C does.
- Zeroization actually happening under optimization — use `zeroize`, not assignment.
- Stack frame ghosts after function return — minimize secret lifetime depth.
- GTZC/MPU/peripheral config bugs.
- Bugs in your dependencies.
- Provisioning and supply-chain problems.

---

## 8. Zeroization Discipline

- Every secret has a clear lifetime and a clear zeroization point.
- Use `zeroize::Zeroize` and `ZeroizeOnDrop` everywhere. Never plain `memset` or assignment.
- Compiler fences around zeroization calls (the `zeroize` crate handles this; verify).
- After sensitive operations, explicitly clear the stack region used. `zeroize` has helpers; if not, write a small assembly routine.
- Clear CPU registers after returning from crypto operations if the ABI allowed secrets into them.
- Cache flushes if secrets may have been cached.
- Verify zeroization in tests — write a test that runs a signing operation and then scans Secure SRAM for any byte pattern matching the test key. Fail loudly if found.

---

## 9. Provisioning Security

- Clean-room facility. No network on provisioning stations.
- HSM-backed generation of per-device SCP03 keys, or EdgeLock 2GO.
- Provisioning logs never contain secret material. Audit every log statement.
- Factory acceptance is a completion-flag check (`is_provisioned` + OTP sentinel read over probe-rs), not cryptographic per-unit attestation — a malicious provisioning station can forge it. Real per-unit attestation (SE050 ECKey attestation, #22 / S-G) is unbuilt. First-field acceptance, after owner verification, separately proves the RDP-2 self-lock, BHK first write, final secure-channel rotation, and seed-wizard completion.
- Tamper-evident packaging between facility and user.
- A provisioning station compromise compromises every device that passed through it during the compromise window. Have a plan.

---

## 10. Update Mechanism

Firmware update is its own project, outside the scope of this document, but note:

- Updates must be signed with a key held in an HSM, verified by the bootloader before any code runs.
- The verification key is stored in a region covered by RDP-2 and option bytes that prevent modification.
- Production anti-rollback remains quarantined. The legacy secure-flash and unary-OTP mechanisms are rejected; Draft 1.1 is a preserved, non-implementation-approved research candidate whose journal, OTP/ECC, resource, factory, and silicon gates remain OPEN. Follow `docs/STATUS.md`; no backend is selected here.
- Rollback plan for broken updates that doesn't involve unlocking RDP-2.
- Update process must not require exposing secrets.
- Test updates on field hardware before every release, not just in the lab.

---

## 11. Testing & Verification

- Unit tests for all cryptographic primitives against published test vectors (NIST PQC for SPHINCS+, BIP-39 spec vectors, etc.).
- Differential tests against a second implementation where available.
- Host-side tests with a mock SE050 for logic.
- On-device integration tests for hardware interaction.
- Fuzz every NSC entry point (`cargo fuzz`) with AFL-style mutation.
- Property-based tests (`proptest`) for anything with nontrivial invariants.
- Zeroization verification tests that scan SRAM after operations.
- Boot-time attestation negative tests: what happens if the SE050 responds with a wrong cert, a replayed nonce, a malformed APDU, no response at all.
- Timing tests on critical paths; flag any data-dependent variation.
- Power-loss tests on real hardware: cut power at many points during a signing operation and verify no secrets survive in any persistent memory.

---

## 12. Operational

### 12.1 Before Touching Real Funds

- **External security audit** from a firm with embedded/TrustZone/secure-element specialization (NCC Group, Trail of Bits, Quarkslab, Kudelski, etc.).
- Fault injection testing on real hardware (lab time).
- Public bug bounty with meaningful rewards.
- Gradual rollout: start with small amounts, wait months, scale up only if nothing surfaces.
- Do not store your own significant funds on it until it has been under public scrutiny for an extended period.

### 12.2 Incident Response

- Have a vulnerability disclosure policy before you ship.
- Have a plan for pushing updates fast when (not if) a flaw is found.
- Have a plan for informing users whose devices may be compromised.
- Reserve capacity to triage reports from researchers.

### 12.3 Documentation

- Threat model document, updated as the design evolves.
- Protocol specification covering every APDU, every NSC call, every crypto primitive and its parameters.
- A "known limitations" document listing what you *don't* protect against, so users can make informed decisions.

---

## 12.4 ERC-7730 Timing Channels

The on-device ERC-7730 clear-signing renderer walks a Merkle-verified
descriptor's `FormatHeader` field list, evaluates each field's
`Visibility` rule (`Always` / `Never` / `Optional` / `IfNotIn` /
`MustMatch`), and dispatches across fifteen wire operations. Enrolled nested
calldata uses the proof-set child path; encrypted operands and unenrolled
calldata hard-refuse. Two
sub-questions about timing channels:

1. **Are visibility-rule evaluation paths secret-dependent?** No.
   Descriptor bytes enter the firmware only after Merkle verification
   against the firmware-pinned `ERC7730_DESCRIPTORS_ROOT`. The bytes
   are public registry data, not key material. The walker's
   instruction trace is a function of the descriptor + the inbound tx
   bytes (`(chain_id, to_address, calldata)`), both of which the
   attacker already knows. There is no secret-dependent branch in the
   rule evaluator, the path walker, or any renderer route. → No
   `subtle::ConstantTimeEq` or branch-balanced
   rewrite is required for this surface.

2. **Stack-budget defence.** Nested calldata is limited to one child level;
   a child format containing another calldata field hard-refuses.
   `MAX_NESTED_DEPTH = 8` bounds nested EIP-712 struct descent and
   `pqsigner_erc7730::ir::MAX_NESTING = 8` bounds nested EIP-712 validation
   and path-program steps. Both
   `render_erc7730_pages` and `render_erc7730_eip712_pages` write a
   `STACK_CANARY = 0xDEAD_BEEF` to a stack-resident `u32` at entry and
   `assert!`-check it at exit (volatile read/write so LLVM cannot
   prove the value dead). A hostile descriptor that somehow defeats
   the depth cap and recurses unbounded smashes the canary →
   `assert!` panic → secure-world panic handler routes through
   `secure_log!` + halt. This is a belt-and-braces tripwire behind the
   independent structural bounds; those bounds are the primary defence.

3. **What this does NOT defend.** Stack canary is a single-fault
   detection mechanism. A multi-fault attack that simultaneously
   overflows the stack AND glitches the assert's compare instruction
   bypasses. Defence in depth: IR validation and the renderer independently
   enforce the path, EIP-712, and one-child calldata limits, while the `Pages`
   buffer's `MAX_PAGES = 31` bound caps page emission — neither path can grow
   without bound even if the canary is defeated.

---

## 13. Honest Caveats

Things that must be acknowledged plainly:

1. **Coerced unlock defeats everything.** No PIN-gated system survives a user being forced to unlock it. Architecturally unfixable without multi-party approval.
2. **Lab attacks on the SE050 die** are rare but not impossible. EAL 6+ is very high resistance, not absolute.
3. **The SRAM exposure window** during signing and during the 2-minute cache is the biggest remaining attack surface for a skilled physical attacker. Fault injection and cold-boot attacks both target this window. The 2-minute cache is a UX concession; consider whether your users need it.
4. **Implementation bugs are the most likely failure mode.** More likely than cryptographic breaks, more likely than hardware exploits. Every shipped wallet vulnerability in history proves this. Spend your paranoia budget on code review, not on exotic attacks.
5. **First-party custom hardware wallets have a poor track record.** Not because the builders were dumb. Because the attack surface is enormous and the economic incentive for attackers scales with the funds stored. Use an audited existing wallet if you can. Build custom only if you have a real reason the existing ones can't serve.
6. **SPHINCS+ is unusual for cryptocurrency.** Verify that your signing scheme actually matches what you need to sign. Don't build the wrong crypto stack.

---

## 14. The One-Line Summary

**Architecture is necessary but not sufficient. Execution is where wallets live or die. Assume every line of code is wrong until proven otherwise, minimize the time secrets exist in any form, and do not trust your own confidence.**
