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
| SCP03 static keys | U585 Secure flash, HUK-wrapped | Plain flash, NS world, any unwrapped form outside SAES operations |
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

- Rotate the SE050 factory-default SCP03 platform keys to device-unique keys **before the device leaves your facility**.
- Create the PIN auth object, seed binary object, and all policies in the same authenticated provisioning session.
- Wrap the new SCP03 keys with the U585's HUK-derived key via SAES and write the ciphertext to Secure flash in the same provisioning step.
- Pin the SE050 unique ID to U585 Secure flash.
- Apply SE050 transport lock if applicable to your variant.
- Enable U585 RDP Level 2 as the final production step. **This is irreversible; do it last.**
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

- **RDP Level 2** in production. Final step before shipping. Irreversible.
- Debug ports (SWD, JTAG) disabled by RDP-2.
- Boot from internal flash only. Disable bootloader access in option bytes.
- Verify the RDP level in boot code; refuse to run if debug build flags are set in a production image.

### 4.3 At-Rest Key Protection

- SCP03 keys (or ECKey private key) stored **wrapped** in Secure flash.
- Wrapping key is derived from the U585 HUK via SAES; the wrapping key itself never leaves the SAES peripheral.
- A flash dump transplanted to another U585 must be useless.
- The wrapped blob lives in a Secure flash region governed by GTZC.

### 4.4 Hardware Peripherals to Use

- **TRNG**: for all nonces, challenges, and any randomness. Audit that `rand_core` is wired to this, not to a software PRNG.
- **HASH**: for SHA-256 acceleration inside SPHINCS+ (pick the SHA2 parameter set specifically to benefit from this).
- **SAES**: for HUK-wrapped key operations.
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
   - KDF is PBKDF2-HMAC-SHA256 with a high iteration count, or Argon2id if it fits.
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

- Prefer **`-128f` or `-192f` with SHA2** on this platform. Rationale:
  - `f` variants are dramatically faster than `s` variants on Cortex-M33 (often 10-30×).
  - SHA2 lets you use the U585 HASH peripheral for the inner hash loop.
  - SHAKE and Haraka have no hardware acceleration on this chip.
- Benchmark on real hardware before committing. Paper numbers lie.
- Document the parameter set in your protocol spec with a domain separation tag; changing it later is a migration problem.

### 6.2 Derivation from BIP-39

1. Read 16–32 bytes of entropy from SE050 over SCP03.
2. Compute BIP-39 seed: `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048)` → 64 bytes.
3. Derive SPHINCS+ key material via HKDF-SHA256 with an explicit domain separation label, e.g. `"SPHINCS+-128f-simple-sha2/v1"`.
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
- Signature buffer: 8–50 KB.
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
- Post-provisioning verification: each device is challenged before shipping to prove it's in the expected state (PIN auth object present, seed object present, RDP-2 set, attestation working).
- Tamper-evident packaging between facility and user.
- A provisioning station compromise compromises every device that passed through it during the compromise window. Have a plan.

---

## 10. Update Mechanism

Firmware update is its own project, outside the scope of this document, but note:

- Updates must be signed with a key held in an HSM, verified by the bootloader before any code runs.
- The verification key is stored in a region covered by RDP-2 and option bytes that prevent modification.
- Downgrade protection via a monotonic counter in Secure flash.
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

- **External security audit** from a firm with embedded/TrustZone/secure-element specialization (NCC Group, Trail of Bits, Quarkslab, Kudelski, etc.). Budget $30K–$150K. Yes, really.
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
