# Research Prompt F — PQSigner OS vs Trezor Safe 7: Architecture Comparison

## Research question

Using the PQSigner OS architecture described below and inlined in full,
produce a detailed, evidence-based comparison with the **Trezor Safe 7**
(SatoshiLabs, announced Oct 2025). Do not treat this as marketing
copy — treat it as a security engineering review. Where Trezor Safe 7
is better, say so explicitly. Where PQSigner is better, say so
explicitly. Where both have open problems, name them.

Compare across these dimensions, in this order:

1. **Secure-element strategy**
   - Trezor Safe 7 reportedly uses a Tropic Square **TROPIC01** secure
     element alongside an MCU; document the exact role it plays
     (storage only? PIN gate? signing? entropy source?). Cite Trezor /
     Tropic documentation.
   - Compare to PQSigner's **dual-SE** architecture (NXP SE050 +
     Infineon OPTIGA Trust M V3), XOR-split entropy, hardware PIN
     gates on both chips.
   - Is dual-SE net-better than single-SE-with-open-design? Name
     concrete attack classes where each wins.

2. **Cryptographic algorithms (signing + key derivation)**
   - Trezor Safe 7: what curves / signature schemes does it support on-
     device? Any post-quantum scheme today, announced, or on roadmap?
   - PQSigner: SPHINCS+C10 for bootstrap and slot transactions, with no
     classical signer anywhere. ERC-4337 smart-account model (no EOA;
     slot keys register on-chain while the bootstrap key is immutable).
   - Evaluate the classical-vs-PQ trade-off honestly: Trezor's curve
     choices are battle-tested and ubiquitous; PQSigner's PQ choices
     are NIST-finalized but rare in production wallets and much larger
     signatures (4,008 bytes vs 64 bytes).

3. **Seed storage, recovery, and derivation**
   - Trezor Safe 7 seed storage location + PIN-lockout policy + Shamir
     / SLIP-39 support + passphrase support.
   - PQSigner: 24-word BIP-39 entropy XOR-split across two SEs, re-
     derived into SRAM each unlock, zeroized on lock/timeout. No
     SLIP-39, no passphrase (yet).
   - Recovery semantics: what does "restore from backup" look like on
     each? How is the PQ recovery contract preserved (same 24 words →
     same PQ keys)?

4. **PIN security and lockout**
   - Trezor Safe 7 PIN gate: software counter, SE counter, or MCU-
     enforced? Max-attempts behaviour?
   - PQSigner: every attempted PIN is pre-committed to MCU flash page 124,
     OPTIGA E120 is a silicon-monotonic lifetime counter, and SE050 UserID
     independently enforces max 10. Boot reconciliation is directional:
     E120 ahead of page 124 fails closed; a page-124 lead is retained rather
     than rolled back. The true cold-reboot receipt for both directions is
     still OPEN and must not be inferred from an in-run cache-reset harness.

5. **Firmware update model and verifiability**
   - Trezor Safe 7 firmware update: signed by whom, with what keys,
     verified by which chip? Rollback protection?
   - PQSigner target: a production-gated immutable FSBL verifies a vendor
     SPHINCS+C10 firmware manifest and displays an 8-BIP-39-word SHA-256
     fingerprint on the NV3007 LCD. The current legacy bench FSBL exercises
     the display path but is not an immutable production trust root; geometry,
     WRP/factory, resource, rollback-backend, and silicon gates remain open.
     The secure runtime shows the same advisory fingerprint. Firmware updates
     use the authenticated streaming update commands.
   - Pros/cons of each model for a paranoid user.

6. **Supply chain + attestation ("is my new box genuine?")**
   - Trezor Safe 7 out-of-box attestation: what does the device prove
     to Trezor Suite on first connection? Historical Trezor
     attestation failures (incl. anti-clone bypasses). Any FIDO-like
     signed-UID chain?
   - PQSigner: dual-SE UID cert chains (NXP root + Infineon root) +
     STM32-UID cross-binding planned (work-todo #22). Current state
     is: no attestation implemented yet.
   - Which design better defeats an interdiction attacker (repackaging
     Mallory)?

7. **Physical / side-channel security posture**
   - Trezor Safe 7 tamper detection, glitch protection, ECC on SRAM,
     BOR/PVD, anti-SCA claims.
   - PQSigner: Stage 1 brownout hardening landed (reset-cause class,
     verified flash writes); stages 2-5 planned (BOR/PVD/IWDG/TAMP/ECC
     config, fault-injection countermeasures, SLH-DSA SCA hardening).
     Explicitly not yet: hardware-level tamper switches, active mesh,
     decap defence.
   - Which design gets to production first on this axis?

8. **Open-source / reproducibility / external review**
   - Trezor's long-standing open-source firmware and third-party audit
     record — cite actual audit reports.
   - PQSigner: fully open-source (no NDA components in the firmware
     code path), BUT depends on closed-source SE firmware on SE050 +
     OPTIGA Trust M. Reproducible-build mechanics and CI gates exist; the
     production packaging/signing ceremony and shipment remain quarantined.
   - What does "verifiable hardware wallet" actually mean in each
     case?

9. **Smart-contract / AA / MPC integration posture**
   - Trezor Safe 7's support for smart-contract wallets today (Safe,
     Argent, ERC-4337 passkey/4337 signers). Does it clear-sign any
     AA structures or just EIP-712?
   - PQSigner: native ERC-4337 smart account with PQ-only signers and
     on-device native ERC-7730, Safe, MultiSend, and CoW decoding;
     deterministic CREATE2 address on all chains from bootstrap PK.
   - Which is the better on-ramp for the smart-wallet / AA world?

10. **UX / ergonomics honestly**
    - Signature size (PQSigner 4,008 bytes per C10 signature vs 64 bytes) — ergonomic
      fallout on USB latency, mempool propagation, L2 inclusion cost.
    - User prompts per transaction, number of button presses, display
     constraints (PQSigner: NV3007 LCD; Trezor Safe 7: 1.54"
      color touchscreen).
    - Recovery ceremony complexity. Backup verification flow.

11. **What Trezor does that PQSigner should steal (concrete list)**
    - Specific design patterns, audit artefacts, or UX flows from
      Trezor that PQSigner should copy, with citations.

12. **What PQSigner does that Trezor can't easily adopt**
    - Things structurally locked out by Trezor's architecture (dual-SE
      retrofit, PQ-only signing, on-device AA / native clear-signing,
      etc.).

Deliverables:
- A table summarising each dimension ("Trezor Safe 7 | PQSigner OS |
  winner | confidence").
- For every claim about Trezor Safe 7, cite a Trezor blog post, wiki
  page, GitHub repo, audit report, CVE, or trusted-third-party
  teardown. Do not invent specs.
- If Trezor Safe 7 details are not public enough to answer a question,
  say so explicitly and downgrade confidence.

**Style / ground rules.**
- No marketing voice. "Safer in X sense, weaker in Y sense" is the
  target tone.
- PQSigner's accepted trade-offs (see preamble) are not up for
  re-litigation. "Just use secp256k1" is not a valid critique.
- "Trezor Safe 7 has not disclosed this publicly" is a perfectly
  acceptable answer — please use it where true.
- Cite specific documents, not general web searches.
- Note that Trezor Safe 7 launched on 2025-10-13; materials older
  than that describe earlier Trezor models (One, Model T, Safe 3,
  Safe 5) and may not apply.


---

## Project context (condensed; current sources are linked in each bundle)

**What this is.** PQSigner OS: a post-quantum ERC-4337 smart-wallet
firmware for STM32U585 (Cortex-M33 + ARM TrustZone) on the
B-U585I-IOT02A Discovery board. Only external interface is USB-C. No
Bluetooth, no UART, no debug access in production (RDP Level 2
planned).

**Secure elements.** **Dual**-SE architecture, not single:
- **NXP SE050** (I2C1, addr `0x48`, EAL6+): stores `half_E` of XOR-
  split BIP-39 entropy. Hardware PIN gate via UserID (10 attempts).
- **Infineon OPTIGA Trust M V3** (I2C1, addr `0x30`, EAL6+): stores
  `half_O`. Shielded Connection (AES-128-CCM-8) for bus encryption.

Both chips are mandatory. Neither alone reveals any bit of the seed —
only `half_O XOR half_E = entropy`.

**Why signing must run on the Cortex-M33, not the SE.** Bootstrap and
slot signatures both use the project's **SPHINCS+C10** hash-based
post-quantum scheme; there is no classical or ML-DSA signer. No
commercial secure element currently computes it. The SEs are gated
storage, not signing accelerators. The seed
therefore transits STM32 secure-world SRAM during the active signing
window (~120 s idle timeout, then zeroize). TrustZone SAU+GTZC isolates
this from the non-secure world.

**TrustZone partition.** Secure world (flash bank 1, SRAM1) owns all
crypto, PIN, persistent secrets, transaction decoding, and the trusted
NV3007 LCD UI. Non-secure world owns USB transport. Crossings go through
the fixed NSC gateway with pointer validation and TOCTOU-safe copy-in.

**Power supervision state.** BOR, PVD, ECC (except SRAM1 which is
always-on), IWDG all at factory defaults. Stage 1 of a 5-stage brownout
roadmap added reset-cause classification + verified flash writes; the
rest is planned. `make stm32-harden-opts` is a one-time option-byte
setup target (sets BOR3 + SRAM2_RST=0) but has not been run yet. See
`docs/security/brownout-hardening.md` for the full plan.

**VBAT.** Production hardware uses a **0.47 F supercap** (not a
battery) on VBAT via Schottky from Vdd. Bounded retention (~12-24 h
after unplug). The dev board has an unpopulated CR1220 holder whose
pads can be reused for a tack-soldered supercap during validation.
Indefinite-retention tamper monitoring during long cold storage is
explicitly out of scope — the 24-word BIP-39 backup is the long-term
security anchor.

**Accepted trade-offs (research that contradicts these is not useful):**
1. Seed transits STM32 SRAM during signing. Unavoidable until SE can
   do SLH-DSA.
2. SE050's value is hardware PIN gate + XOR storage, not "seed never
   leaves silicon." Don't suggest "do all signing on SE050" — it
   can't.
3. USB-C is the only external interface.
4. Out of scope: EAL6+ invasive decapping attacks.

**Dark Skippy and similar nonce-exfil attacks do NOT apply.** Hash-
based SLH-DSA has no nonce. Don't chase this.

**Current SCP03 lifecycle.** The SE050 SCP03 channel is active (every TX
has CLA=0x84). Factory defaults are not an acceptable production state:
the factory transport credentials are derived from the per-device OTP master
burned for that handoff. After RDP2 self-lock and the BHK first write, the
implemented first-field candidate rotates SE050 SCP03/admin credentials to
the final BHK axis and rotates the OPTIGA E140 PBS to the final DHUK derivation
bound to a fresh TRNG salt persisted in the page-127 journal. Page 126 holds
only the DHUK-wrapped BHK. This candidate is not a production-approved
ceremony: authenticated per-unit handoff and authenticate-before-rotate,
durable old/new/KVN recovery, the exact E140 lifecycle-versus-final-rotation
order, and silicon receipts remain OPEN.

---

## Style guidance

- Cite specific RM0456 / AN5342 / ES0499 / UM11225 / Infineon doc
  sections where possible. Prefer "per AN5342" over inventing
  revision numbers you aren't sure of.
- Say "I don't know" on things not answerable from public sources,
  rather than guessing.
- Give concrete, implementable code / register values — hand-wave
  recommendations without specifics are not useful.
- Respect the architecture above. Suggestions that require signing
  on the SE are category errors for this project.

---


## Relevant docs and code


### From `README.md`

[![PQ1](../../../docs/pq1_banner_image.jpg)](https://freedomfactory.io)

# PQ1

A **post-quantum ERC-4337 hardware wallet** (the **PQ1**) where every primitive that protects the seed — at rest, in transit between chips, in firmware updates, in transaction signing — is a NIST PQC standard or a Grover-resistant symmetric primitive. The secure elements' channel layers (which we cannot replace) are symmetric-rooted — no public-key handshake ever crosses a bus — so even against a future CRQC the strongest attack on recorded traffic is depth-limited Grover key search (NIST Category 1, the same floor as the SPHINCS+C10 signatures themselves).

**Target hardware:** STM32U585 (Cortex-M33, TrustZone) + Infineon OPTIGA Trust M V3 + NXP EdgeLock SE050. No single die, no single vendor, and no future cryptographically-relevant quantum computer (CRQC) should recover the seed from harvested traffic or extracted ciphertext.

**Build one yourself:** every part is off-the-shelf — [`DIY.md`](../../../DIY.md) has the ~$150 bill of materials (Mouser links included), the wiring, and the first-flash guide.

> **Firmware-format authority correction — 2026-07-15.** The existing
> `PQFW_V1`/75-byte proof and implementation are legacy bench evidence only.
> Historical V4/80-byte text remains in some owner documents, while the
> more-specific Draft 1.1 describes V6/121 bytes as a research candidate with
> no implementation authority. No replacement schema is currently selected.
> Reconcile those owners before implementation or formalization; later V4
> passages in this README are historical candidate text, not current approval.

> **Status — 2026-04, pre-production bring-up. All-C10 cutover complete.**
> Every transaction is signed with **SPHINCS+C10** (W+C_F+C, `h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205, sig=4008`) — hash-based, no lattice or number-theoretic assumptions, no classical fallback. The *same* primitive signs both Type 1 (bootstrap → slot registration) and Type 2 (slot → user tx); there is no FORS+C and no secp256k1/P-256/Ed25519 anywhere. The firmware boots and runs on a real **B-U585I-IOT02A** with the OPTIGA Trust M V3 Shield + NXP OM-SE050ARD on Arduino R3 headers, and on QEMU `mps2-an505`. Dual-SE XOR entropy split, three-way PIN-attempt consumption (MCU + OPTIGA + SE050), both SE drivers, and the Tier-1 SAES-CMAC(DHUK) KDF are validated end-to-end on silicon; the boot counter check is directionally MCU→OPTIGA E120 because the SE050 attempt count is not peek-readable. On-chain contracts (`PQSmartWallet` + factory + `PQMultiOwnable`) target **EntryPoint v0.6** behind cheap ERC-1967 proxies at a deterministic CREATE2 address keyed on `sha256(masterPkSeed‖masterPkRoot)`. SHA-256 throughout the PQ stack (routed to the STM32U585 HASH peripheral); Keccak-256 only for EVM-mandated hashes.
>
> **No devices have shipped and no on-chain wallets hold funds.** Anything described below as "frozen" or "a hard fork to change" is the shape the team intends to commit to *at launch* — domain tags, the C10 parameter set, the CREATE2 salt, and the EntryPoint version can all still be changed cleanly before first shipment. The bring-up branch carries known production-invariant regressions; see `CLAUDE.md` "Pre-Production Caveats".

```
                  ┌──────────────────────────────────────────────────┐
                  │              STM32U585  (Cortex-M33)              │
                  │                                                   │
                  │  ┌───────────────── SECURE WORLD ───────────────┐ │   ┌──── NON-SECURE WORLD ────┐
                  │  │                                                │ │   │                          │
                  │  │  PIN → gated_unlock (page-124 pre-commit)      │ │   │  USB HID / LCD forward   │
                  │  │     → SE-derived auth via hw::secret_keys      │ │   │  Companion app drives    │
   ┌──────────┐   │  │     → SAES-CMAC(DHUK, label) [Tier 1]          │ │   │  (chain_id, slot_index,  │
   │ OPTIGA   │◄──┼──┤                                                │ │   │   flags) per sign call   │
   │Trust M V3│   │  │  OPTIGA.unlock(K_O)  → half_O                  │◄┼───┼──►┌──────────────────┐  │
   │(Shielded │   │  │  (Shielded Conn AES-128-CCM-8;                 │ │   │   │ NSC gateway      │  │
   │  Conn,   │   │  │   E120 LUC + F1D0 AuthRef silicon-gated)       │ │   │   │ sign·unlock·     │  │
   │ E120 LUC)│   │  │                                                │ │   │   │ status·fw-update │  │
   └──────────┘   │  │  SE050.unlock(K_E)   → half_E                  │ │   │   └──────────────────┘  │
   ┌──────────┐   │  │  (SCP03 AES-CMAC + AES-CBC; admin UserID       │ │   │                          │
   │  SE050   │◄──┼──┤   keys: BHK prod; DHUK fallback; OTP dev)      │ │   │  no secrets, ever        │
   │  (SCP03  │   │  │                                                │ │   └──────────────────────────┘
   │  + admin │   │  │  E       = HKDF(half_O ⊕ half_E)               │ │
   │  UID)    │   │  │  bip39_seed ← PBKDF2-SHA512(BIP-39(E))         │ │
   └──────────┘   │  │  master = HMAC-SHA512("sphincs-c6-v1", seed)   │ │
                  │  │  master_sk / slot_sk ← sphincs_c10::keygen     │ │
                  │  │  type1_sig ← C10.sign(master_sk, userOpHash)   │ │
                  │  │  type2_sig ← C10.sign(slot_sk,   userOpHash)   │ │
                  │  │  verify-before-release (FI guard, both sigs)   │ │
                  │  │  zeroize on lock/timeout/tamper/brownout       │ │
                  │  │                                                │ │
                  │  │  TRNG / HASH / SAES (DHUK) / TAMP / BOR        │ │
                  │  │  Secure-only inactivity TIM · MCU PIN counter  │ │
                  │  └────────────────────────────────────────────────┘ │
                  └──────────────────────────────────────────────────┘
                                          ▲
                                          │  FSBL (current: legacy bench code;
                                          │  target: approved + WRP-protected)
                                          │  verifies C10+SHA-256 on bench; production
                                          │  rollback/factory authority remains blocked
```

## Design Properties

Each item below is implemented today (QEMU and/or real STM32U585), partial, or planned. See [Implementation Status](#implementation-status) for the per-item state.

- **Post-quantum signatures, one primitive everywhere** — SPHINCS+C10 for both Type 1 (bootstrap slot registration) and Type 2 (per-slot user tx). The on-chain contract has a single `c10Verifier` immutable wired to both dispatch paths. Per-chain caps `MAX_BOOTSTRAP_USES = MAX_SLOT_USES = 65,536` are immutable; combined ≈ 2³² user txns/chain before that chain is permanently frozen. **Per-KEY margin (corrected 2026-07-26):** slot keys are chain-bound so 65,536 is a true per-key cap (birthday floor 96 b); the **bootstrap key is chain-independent** (invariant #6, for cross-chain address stability), so its per-key budget across `C` chains is `C × 65,536` and its generic floor degrades as `96 − 2·log₂ C` (94 b at 2 chains). Documented as the P14 caveat in `Quantitative.lean`; realistic bootstrap usage is tens of signatures (slot rotations only). *(Implemented; `forge test` covers both paths.)*
- **Post-quantum firmware signing (pre-production)** — the existing V1/75-byte signer and FSBL verify SPHINCS+C10 artifacts on the bench, but their rollback/try-once backend is rejected and compile-blocked from production. Historical Draft 0.9/V4 is preserved as research evidence. Draft 1.1 proposes slot-bound manifest v6 and an exact 121-byte `PQFW_V6` preimage, but remains an unapproved research candidate; journal/ECC/OTP, FLASH, RAM/stack, release-policy, factory, and silicon gates remain open.
- **Symmetric-only SE tunnels (no harvestable handshake)** — no public-key
  exchange crosses I²C. The `rdp2-self-lock` candidate implements a journaled
  first-field transport→final transition before the seed wizard: SE050
  credentials become BHK-rooted and the OPTIGA PBS binds a persisted fresh
  TRNG salt to the DHUK derivation. This is not yet a production-approved
  ceremony: the authenticated factory handoff/receipt, old/new/KVN recovery
  proof, exact E140 order, and silicon evidence remain OPEN and
  production-blocking. Once that ceremony is closed, the accepted residual is
  Grover key search on AES-128 session keys (~2⁶⁴ serial, NIST Category 1 —
  the same floor as SPHINCS+C10 itself), per recorded session, requiring a
  physical tap during a live unlock, twice over thanks to the XOR split. *(An
  ML-KEM-1024 inner wrap was prototyped and descoped 2026-07-07 — owner
  decision; see `docs/security/ml-kem-inner-wrap.md`.)*
- **TrustZone isolation** — signing key, PIN state, key derivation, and crypto confined to the secure world. The NSC gateway (sign / batch-sign / off-chain sign / unlock / lock / status / wallet-address / init-code / firmware-update) is the only crossing point, with NS pointer validation and TOCTOU defense (NS buffers copied to S-stack before parse). On silicon the gateway runs through real ARMv8-M CMSE veneers (`make e2e-hw`); QEMU uses a shared-memory mailbox (workaround for a QEMU 8.2.2 MPC S-alias bug).
- **Dual secure elements (split entropy)** — BIP-39 entropy is XOR-split: `half_O` on OPTIGA, `half_E` on SE050. Either chip alone reveals zero bits. `E = HKDF(half_O ⊕ half_E)` happens only in S-SRAM during unlock, then zeroized. *(Validated on silicon; both on I2C1 at 0x30 / 0x48.)*
- **Three-way PIN-attempt enforcement** — every ordinary wrong attempt charges FI-hardened MCU page 124, OPTIGA E120 LUC, and the SE050 silicon UserID. Page 124 and SE050 enforce the user-facing 10-attempt bound; E120 is a separate 32-lifetime-attempt anti-extraction backstop. Boot checks the readable counters directionally (`E120_used > page124_used` means rollback/tamper); the SE050 attempt attribute is policy-denied and is not a boot input. `CMD_GET_REMAINING` uses page 124 plus runtime driver mirrors, not a three-way silicon read receipt. *Silicon evidence from `make pin-gate-hw-counter-e2e` covers per-attempt consumption/desync recovery within one run, and `make pin-gate-wipe-e2e` covers lockout/wipe. A reboot-based silicon receipt for both directional boot-ordering cases remains open; those branches are not claimed as hardware-E2E-validated.*
- **Three-tier DHUK + BHK + OTP key hierarchy** — Tier 1 (DHUK, `SAES-CMAC(DHUK, label‖counter)`) is **landed** behind `saes-dhuk`. At RDP0 the DHUK is an ST-substituted constant shared across boards (per-die uniqueness only at RDP ≥ 1). The Tier-2 BHK lifecycle and page-127 salted first-boot journal exist in the quarantined `rdp2-self-lock` candidate; production review and silicon evidence remain open.
- **Trusted-display clear-signing** — every signable artifact is decoded and rendered in S-world before confirm by **native on-device decoders**. **Safe** EIP-712 `SafeTx` and **CoW Swap** EIP-712 `GPv2Order` are verified in-world (`secure/src/tx/eip712/{safe,cowswap}/`) and decoded locally. **ERC-20** transfers and CoW order legs render symbol/decimals from a Merkle-verified metadata bundle; accepted **ERC-7730** descriptors, including supported Aave v3 operations, render field-level pages. Allowlisted `MultiSendCallOnly` DELEGATECALL batches are strictly decoded record-by-record. Only genuinely absent opaque calls/records may reach loud blind pages; registry-known/Bloom-positive calls without valid bound semantics, incomplete Aave descriptors, malformed or prohibited batches, other delegatecalls, and page-budget overflow refuse.
  The clear-signing guarantee covers structured on-chain and typed-data dispatch. Explicit EIP-1271 `RAW32` remains a separate `! BLIND RAW32` off-chain tier and must never be used by a companion to downgrade a typed-data request.
- **Boot-time self-test & measurement** — `hw::hash::init_clock()` runs a `SHA-256("abc")` KAT (halt on mismatch); `make saes-self-test-hw` runs the SAES round-trip + 8-byte DHUK fingerprint. The secure-world image hash is rendered as 8 BIP-39 words on the NV3007 LCD for trustless comparison against `fwmeasure`.
- **Hardening hooks** — STM32U585 TAMP (Trezor-port; log-only on this branch, production flips to `trigger_lockout_wipe()`), TIM2 CH1 PWM consumption mask (PA5), UI-capture screenshot-hash harness. All feature-gated; CI keeps them out of production.
- **No heap** — `#![no_std]`, stack-only, no `Vec`/`Box`/`String`. `zeroize` on every secret; `subtle` for constant-time compares; `// SAFETY:` on every `unsafe`.

## Quick Start

```bash
make play               # interactive QEMU — laptop arrow keys drive the two wallet buttons
make run                # mock-SE smoke test in QEMU
make e2e                # automated unified-sign e2e in QEMU (mock SE)
make e2e-hw             # automated e2e on real STM32U585 (dual-SE) via probe-rs
make test-key-speed     # DWT-timed signing bench on real hardware
make measure            # print the 8 BIP-39 measurement words for this build
```

| Key | Action |
|---|---|
| `←` | Left button — back / scroll down |
| `→` | Right button — next / scroll up |
| `←`+`→` | Confirm (press both together) |
| `Esc` / `Ctrl-C` | Cancel / quit |

Build a dual-SE **nonshipping bench** firmware (the explicit feature makes the
legacy rollback backend visible and is forbidden in production):

```bash
make FEATURES="dual-se,stm32u585,ui-lcd,saes-dhuk,usb,legacy-fw-rollback-unsafe" all
```

Expected real-hardware key-speed (`hw-sha256`, auto under `stm32u585`): first-sign ≤ 3 s (master keygen + slot keygen + 2× sign); Type-2 cached slot ≈ 1.1 s; second-chain first-sign ≈ 2.5 s. Substantially higher means the HASH peripheral isn't being used.

**HW probe-rs gotcha.** `probe-rs` doesn't implement semihosting `SYS_READC`, so `ui-semihosting` PIN prompts hang on real silicon. Use `make test-key-speed` (no reads) or `make play-hw-display` (arrow keys via the probe-rs handshake). QEMU is unaffected.

### Prerequisites

- Rust nightly (`rust-toolchain.toml`), `arm-none-eabi-ld`, QEMU with `mps2-an505`
- Hardware: B-U585I-IOT02A + OPTIGA Trust M V3 Shield (`TRUSTMV3SHIELDTOBO1`) + NXP OM-SE050ARD on Arduino R3 headers, driven via ST-LINK + `probe-rs`

## Project Structure

```
sphincs_rust/
├── secure/        TrustZone SECURE world (main.rs, crypto.rs, sau.rs, nsc/, aa/, tx/,
│                  optiga/, se050/, dual_se.rs, fw_update/, measured_boot.rs, ui/, hw/)
├── nonsecure/     NON-SECURE world: USB HID + APDU v2 router, NS gateway caller, e2e runner,
│                  generated erc20_db.bin / names_db.bin
├── shared/        Cross-world #[repr(C)] types, NscStatus, CMD constants, wire-format sizes
├── proto/         pqsigner-proto — protocol constants/enums/sizes (source of truth for Solidity)
├── sphincs-c10/   SPHINCS+C10 signing library (no_std, SHA-256)
├── bip39/         24-word English BIP-39 (no_std)
├── domain/ tx-core/ aa/ tx/ hal/ pqsigner-erc7730/   pure-logic workspace crates
├── contracts/smart-wallet/   Foundry project — PQSmartWallet, Factory, PQMultiOwnable,
│                             verifiers/SPHINCsC10Asm.sol (stateless Yul C10 verifier)
├── fsbl/          first-stage bootloader (legacy bench link: 32 KiB; Draft 1.1 resources OPEN)
├── fwsign/ fwmeasure/ fw-manifest/   host signer/verifier, measurement tool, manifest chain
├── dbgen/         host ERC20/names/selectors/ERC-7730 DB + Merkle-tree builder
├── tools/         webhid_test.html, wallet_run_hw.py, …
└── docs/          architecture.md, HARDENING.md, threat-model.md, …
```

See `CLAUDE.md` for the full per-file map and the non-negotiable invariants.

## Authenticated companion databases

The full catalogue blobs stay on the host/companion. Secure firmware pins only
their 32-byte Merkle roots (`secure/src/db_roots.rs`) and verifies every
companion-supplied lookup bundle before its metadata can reach the display.

| DB | Source | NS artifact | Secure anchor |
|---|---|---|---|
| ERC20 metadata | `secure/data/erc20.json` | `tools/companion-stub/erc20_db.bin` | `ERC20_DB_ROOT` |
| Address names | `secure/data/names.json` | `tools/companion-stub/names_db.bin` | `NAMES_DB_ROOT` |
| Function selectors | `secure/data/selectors.json` | `tools/companion-stub/selectors_db.bin` | `SELECTOR_DB_ROOT` |
| ERC-7730 descriptors | `secure/data/erc7730-registry/{registry,ercs}/**/*.json` + `secure/data/erc7730/policy.toml` | `tools/companion-stub/erc7730_db.bin` | `ERC7730_DESCRIPTORS_ROOT` |

`cargo run -p dbgen` reads the pinned inputs, builds the SHA-256 Merkle trees,
appends per-entry proofs, and writes the `.bin` files plus `db_roots.rs`. All
generated files are committed. `nonsecure/build.rs` checks the small E2E blobs
used by the QEMU companion stub; production firmware embeds no catalogue blob.
The trust chain is fully offline: firmware-signing key → root in secure flash →
Merkle proof walk → verification. Catalogue changes must go through the pinned
vendor/install workflow, regenerate with `dbgen`, and pass `make check-codegen`.

## Cryptographic Primitives

Every primitive that touches a secret, with PQ status. **Classical** entries are display-only (never reach the seed), a residual SE-vendor surface we wrap with planned PQ confidentiality, or a planned migration.

| Where | Primitive | Size | PQ | Notes |
|---|---|---|---|---|
| **Tx signing (Type 1 + 2)** | SPHINCS+C10 (W+C_F+C, h=18 d=2 a=11 k=13 w=8 l=43 target_sum=205) | sig 4008 B, pk 32 B | ✅ | One primitive for bootstrap *and* per-slot. Verifier `SPHINCsC10Asm.sol` runs in-EVM via the SHA-256 precompile. The on-chain `SignatureWrapper(ownerIndex, sig)` is 4128 B (4008 padded to 4032 + 3×32 header) |
| **Firmware signing** | SPHINCS+C10 (same params) | sig 4008 B | ⚠️ | Legacy V1 bench path exists. Draft 1.1 proposes manifest-v6 but is not implementation-approved; production remains blocked on its journal/ECC/OTP, FLASH, RAM/stack, release-policy, factory, and silicon gates. No classical fallback |
| **OPTIGA wire** | Shielded Connection: TLS-PRF + AES-128-CCM-8; candidate final PBS is DHUK-derived and binds a persisted TRNG salt | tag 8 B | ⚠️ | Symmetric-rooted (no Shor surface). Candidate code exists; authenticated factory handoff, recovery proof, E140 ordering, and silicon evidence remain production-blocking. Only after that closure does the accepted Grover-2⁶⁴ tapped-session residual apply |
| **OPTIGA PIN gate** | AuthRef (`0xF1D0`) + E120 LUC (silicon-monotonic) | — | ✅ | Trezor-parity; immune to PBS extraction. Hardware-cleared by `Change=Auto(F1D0)` over transient auth on success |
| **SE050 wire** | SCP03 (AES-CMAC + AES-CBC); candidate final credentials use the BHK derivation axis | k 16/32 B | ⚠️ | Symmetric-rooted (no Shor surface). The journaled transport→BHK candidate exists, but its handoff and old/new/KVN recovery contract plus silicon evidence remain unapproved. Session keys have no forward secrecy |
| **SE050 PIN gate** | UserID auth (constant-time, max 10) | — | ✅ | Hardware retry counter; surfaces only via `SW=0x63Cx` |
| **SE050 admin PIN** | Current helper: `SAES-CMAC(BHK,…)`; DHUK fallback; OTP only in explicit dev/legacy builds | 16 B | ⚠️ | Derived on demand and never stored as a flash PIN. Page 126 holds the wrapped BHK. The candidate first boot rekeys the transport UserID to this final helper; production validation and recovery authority remain OPEN |
| **MCU PIN counter** | Page-124 quad-word programs | 10-attempt cap | ✅ | FI-hardened pre-commit in `nsc::gated_unlock`: bump *before* touching the SE driver, with post-bump readback (`+1` or `InternalError`) |
| **SE chip attestation** | ECDSA over a vendor curve | — | ❌ | Proof-of-presence only; cryptographic device identity will be a pinned SPHINCS+C10 cert (planned) |
| **Tier 1 root** | STM32U585 DHUK via SAES `KEYSEL=001`; `SAES-CMAC(DHUK, label‖counter)` | 16 B/block | ✅ | DHUK never CPU-visible. RDP0 = ST constant; per-die uniqueness at RDP ≥ 1 |
| **Tier 2 root (planned)** | BHK — TRNG-burnt, DHUK-wrapped, TAMP-backup-loaded, `SECCFGR`-locked | 32 B | ✅ | Defense in depth; planned to host SE050 SCP03 |
| **Factory transport root** | Per-device OTP master, TRNG-generated and burned by the factory before shipment | 32 B | ✅ | Derives only the initial SE050 SCP03/admin and OPTIGA PBS transport credentials. Field firmware must never auto-burn it or reuse it as a final device root; the candidate first boot replaces those transport credentials after RDP-2. |
| **BIP-39 → C10 master** | PBKDF2-HMAC-SHA512 (2048) → `HMAC-SHA512("sphincs-c6-v1", seed)` (acct 0) / `…("sphincs-c6-v1-acct", seed‖acct_be4)` (accts 1..=255) | 64 B | ✅ | `"c6"` tag is historical (carried through the C10 cutover). Acct 0 reproduces the legacy derivation byte-for-byte |
| **Slot derivation** | `slot_entropy = sha256(slot_master‖"slot_entropy"‖chain_id_be8‖slot_index_be4)`; `slot_sk_seed = sha256("slot_c10_sk_seed"‖slot_entropy)`; `slot_pk_seed = sha256("slot_c10_pk_seed"‖slot_entropy) & N_MASK` | 32 B sk, 16 B pk | ✅ | **Chain-bound** (post-Coinbase port): slot keys differ per chain. Stateless within the 2¹⁸ tree; cached in SRAM for the unlock session only |
| **Anti-rollback floor** | Draft 1.1 research candidate | — | ⚠️ | Ordinary releases within one security epoch would consume no OTP. The candidate is not implementation-approved; the physical codec/capacity, interruption recovery, ECC handling, resource fit, and silicon evidence remain OPEN. The legacy 1,024-bit tally is invalid on STM32U585 and production-fenced |
| **TRNG mixing** | STM32 TRNG today; planned ⊕ OPTIGA ⊕ SE050 TRNG | 32 B | ✅ | Quantum offers nothing against true randomness |
| **Clear-sign decoders** | Native on-device decode (Safe / CoW / ERC-7730 / ERC-20 / typed-call) | — | ❌ | Display-only — gates *what is shown before signing*, never reaches the seed. |
| **Clear-sign DB auth** | SHA-256 Merkle tree over pinned leaves; 32-byte root in secure flash | root 32 B | ✅ | Anchored to the firmware-signing key; fully offline (no on-chain governance lookups) |

**Choices frozen at launch** (changing any reproduces a different keypair / on-chain address — today a re-provisioning cost on bench boards, not a user-visible fork):

| Parameter | Value |
|---|---|
| Signing parameter set | SPHINCS+C10 (h=18 d=2 a=11 k=13 w=8 l=43 target_sum=205, sig 4008) |
| BIP-39 → C10 master | `HMAC-SHA512("sphincs-c6-v1", seed)` (acct 0) / `…-acct‖acct_be4` (accts 1..=255) |
| Master pubkey shape | `masterPkSeed = sha256("pk_seed"‖master[..32]) & N_MASK`; `masterSkSeed = sha256("sk_seed"‖master[..32])` |
| CREATE2 salt | `sha256(masterPkSeed ‖ masterPkRoot)` — same address on every chain for a given `account_index` |
| Slot tags | `"slot_entropy"`, `"slot_r"`, `"slot_c10_sk_seed"`, `"slot_c10_pk_seed"`, `"pqwallet-slot-master"(-acct)` |

## Quantum Threat Model

**The dominant threat is Harvest Now, Decrypt Later (HNDL):** an adversary records all I²C traffic today and decrypts it once a CRQC exists. For a wallet holding long-term funds this matters because the adversary need not be present at decryption time.

**How the shipping design defeats HNDL:** there is nothing Shor-breakable to
harvest. Every signature is hash-based, and both SE tunnels use pre-shared
symmetric roots — no ECDH, RSA, or KEM handshake crosses I²C or USB. The
quarantined `rdp2-self-lock` candidate implements the journaled first-field
rotation: BHK-rooted SE050 credentials and a DHUK-rooted OPTIGA PBS bound to a
persisted fresh TRNG salt. The authenticated factory handoff/receipt,
old/new/KVN recovery proof, E140 ordering, and silicon evidence remain OPEN and
production-blocking. Once closed, a recorded bus trace can only be attacked by
Grover key search on an AES-128 session key: ~2⁶⁴ *serial* quantum operations
(NIST Category 1 — the identical floor SPHINCS+C10's n=16 parameters sit at),
per session, and the sensitive payloads (PIN, entropy halves) only cross during
a live unlock, so harvesting requires a physical interposer on a powered
device. The XOR split then demands two independent such breaks on two different
buses under two different keys. **Accepted residual (owner decision
2026-07-07):** this Grover-2⁶⁴-with-physical-tap bound is the design's floor for
bus confidentiality; a prototyped ML-KEM-1024 inner wrap that would have lifted
stored-half confidentiality above it was descoped (retained feature-gated
in-tree — `docs/security/ml-kem-inner-wrap.md`). Because session keys derive
deterministically from the statics (no forward secrecy), this acceptance
depends on completing the per-device final-rotation ceremony — fleet-shared or
reconstructible final statics would invalidate it.

**Residual classical surface we accept:** OPTIGA Shielded Connection KDF (symmetric-only; worst case Grover-accelerated PBS brute force, still > 128-bit PQ); SE050 secure-channel auth (MITM needs real-time physical bus tampering on a powered device; a MITM'd half is still only one XOR share); SE factory attestation (ECDSA — proof-of-presence only); OPTIGA/SE050 internal firmware (single-chip compromise leaks zero seed bits); U585 RDP-2 + HUK-SAES (the irreducible "extract the specific die" attack).

**We explicitly do *not* defend against:** coerced unlock; an active CRQC adversary with sustained physical access to a powered, unlocked device; a fundamental break of SPHINCS+ / SHA-256 (civilization-scale; recovery is a firmware update to a SHA-3/SHAKE-based scheme); side-channel / fault attacks on U585 silicon (orthogonal to PQ; mitigated by TAMP / consumption-mask / verify-before-release / FI-hardened `gated_unlock` + `docs/security/HARDENING.md`).

**Why hash-based signatures for the actual money:** lattice schemes rely on LWE hardness with a far younger cryptanalytic track record than hash functions. For the signing key and firmware signing we use SPHINCS+C10, whose only assumption is SHA-256 — with the inner-wrap descope, no lattice assumption appears anywhere in the shipping trust path.

### Why two secure elements?

A single SE is a single point of trust. The production target pairs **OPTIGA Trust M V3** (CC EAL6+ AVA_VAN.5, Shielded Connection) with **NXP SE050** (CC EAL6+ AVA_VAN.5, SCP03 + UserID) so a vendor-level break of either must overlap with one of the other to recover the seed.

| Attack | Single-SE | Dual-SE (this design) |
|---|---|---|
| Class-break on one vendor's firmware / invasive die attack | seed exposed | other half still secret — zero bits leaked |
| Backdoored RNG in one chip | biased entropy | XOR with the other SE's TRNG + STM32 TRNG preserves uniformity |
| Stolen powered-off device | one retry counter | three attempt gates: page 124 + SE050 enforce 10 attempts, E120 provides a 32-lifetime-attempt backstop; exhaustion/blocked auth drives the full admin-wipe path |
| U585 secure-SRAM compromise during active unlock | full break | full break (irreducible window — minimised by 120 s timeout + TAMP/BOR wipe ISR) |

Cost: one extra I²C peripheral, ~$3 BOM, ~50 ms unlock latency.

## Security Model

| Layer | Protection |
|---|---|
| **Seed at rest (OPTIGA)** | `half_O` in object `0xF1D1`, `Read = Auto(0xF1D0) + Conf(0xE140)` — readable only after an AuthRef HMAC-SHA-256 challenge against the PIN-derived `0xF1D0` *and* through the AES-128-CCM-8 Shielded Connection |
| **Seed at rest (SE050)** | `half_E = E ⊕ half_O` in an SE050 binary object whose read policy is bound to a UserID opened only inside SCP03. Current bring-up admin/SCP03 material uses the BHK axis; DHUK is the non-BHK fallback and OTP is dev/legacy only. The production-final fresh-TRNG rotation remains OPEN as described below |
| **Seed reconstruction** | `E = HKDF(half_O ⊕ half_E)` only in S-SRAM, for microseconds, then zeroized. Mnemonic / seed / master / slot keys recomputed on demand, dropped on lock / idle / panic |
| **Key transport** | OPTIGA Shielded Connection (TLS-PRF + AES-128-CCM-8) and SE050 SCP03. Current bring-up material comes from deterministic `hw::secret_keys` helpers (DHUK-derived OPTIGA PBS, BHK-axis SE050 credentials); legacy dev fallback is quarantined. These helpers are not production-final. The required fresh-TRNG final rotation, durable public salt/state, cut recovery, and exact E140 ordering remain OPEN and production-blocking. Flash page 126 is reserved for the wrapped SE050 BHK when enabled; it is not PBS storage |
| **PIN handling** | Raw PIN never leaves S-world; the trusted UI runs entirely in S-world. NS never sees a digit, cursor, or confirm decision. SE challenges derived via `hw::secret_keys` so neither chip stores the PIN |
| **Retry counters** | Three-way per-attempt consumption (MCU page 124 + OPTIGA E120 LUC + SE050 UserID); boot cross-check is directional page124→E120, while SE050 independently enforces max-10 lockout |
| **Boot self-tests** | `SHA-256("abc")` KAT (halt on FAIL); `make saes-self-test-hw` SAES round-trip + DHUK fingerprint. Production gates the self-test feature out |
| **TAMP / SCA mask** | TAMP monitors backup-domain voltage, LSE, JTAG/SWD@RDP>0, crypto fault, IWDG (log-only on this branch; production flips to `trigger_lockout_wipe()`). TIM2 CH1 PWM consumption mask on PA5 |
| **Memory isolation** | TrustZone (SAU + IDAU + MPC + GTZC); DMA into secure SRAM blocked; NS pointer validation + TOCTOU defense; no panics across NSC |
| **Inactivity / power loss** | Secure-only TIM enforces a 120 s idle wipe; TAMP and BOR fire the same ISR; bulk cap sized so the ISR completes under brownout |
| **Crash safety** | Panic handler zeroizes secrets and resets before halting; idempotent `wipe-for-wizard` dev recovery path |
| **Production lockdown** | **Not authorized yet.** Draft 1.1 proposes an immutable pages-0..4 FSBL envelope, but FLASH/RAM, option-byte, factory, and silicon gates remain open. The RDP/WRP/self-provision sequence in work-todo #36 is research input, not an executable ceremony. |

### Boot → Unlock → Sign → Lock

Every step runs in the **secure world**; NS drives nothing more sensitive than "show this string" / "button pressed".

```
1. SECURE BOOT      FSBL verifies the SPHINCS+C10 sig of both images → SAU/IDAU/MPC/GTZC →
                    mark LCD bus, button GPIOs, both SE buses, TRNG/HASH/SAES/PKA/TAMP/BKPSRAM
                    Secure-only → SHA-256 KAT (halt on FAIL) → SAES self-test (feature-gated)
2. ATTESTATION      (planned) nonce ← TRNG; verify each SE's factory cert vs pinned vendor root +
                    pinned UID. FAIL → tamper screen + halt. PASS → boot NS, show "Enter PIN"
3. PIN ENTRY        trusted path entirely in S-world; raw digits only in S-SRAM; NS never sees them
4. gated_unlock     pre := page-124 read; bump; if read != pre+1 → InternalError (FI guard, refuse
                    SE driver). Derive PBS / SCP03 / admin via secret_keys. OPTIGA: Shielded Conn +
                    F1D0 AuthRef (E120-gated) → read half_O. SE050: SCP03 + UserID → read half_E.
                    Correct PIN → reset all 3 counters. 10th wrong on ANY → factory_reset_admin +
                    page-124 erase + page-125 wipe-flag → cold boot enters the wizard
5. RECONSTRUCT      E = HKDF(half_O ⊕ half_E); zeroize halves; BIP-39 → seed → master →
                    master_sk; slot keys derived per-call from (slot_master, chain_id, slot_index),
                    cached in SRAM only
6. ACTIVE WINDOW    ≤ 120 s inactivity (Secure-only TIM; NS pings ignored). Per CMD_SIGN_USEROP:
                    parse → draw decoded fields → (re)keygen slot if uncached → user CONFIRM →
                    C10.sign (Type 1 if FLAG_REGISTER_SLOT, always Type 2) → verify-before-release
                    → emit [type1_len|t1|type2_len|t2] bundle → reset timer
7. LOCK / WIPE      120 s idle, TAMP, BOR, any NSC panic, or a sign-verify mismatch → zeroize all
                    cached secrets + stack + registers, loop-twice + verify → "Locked" screen
```

**Invariants the dual-SE design hangs on:** (1) the trusted path is contiguous button → S-ISR → LCD → S-world (GTZC marks all of it Secure-only); (2) the PIN buffer never crosses the NSC boundary — there is no `enter_pin(bytes)` call, only `request_unlock()`; (3) activity is defined by S-world button presses, never NS pings; (4) every ordinary PIN attempt is charged through page 124 and both SE auth paths, while boot can only perform the documented directional page124/E120 rollback check; (5) the firmware is stateless w.r.t. slot selection — no `next_q`-in-flash, no per-signature flash writes (slot keys re-derived on demand; SPHINCS+C10 is stateless within its 2¹⁸ tree).

## Formal Verification (Lean 4)

Two machine-checked proof tracks, one shared specification. A proof applies to
a shipped release only when an identity-bound receipt connects that exact
release artifact to its source, configuration, generated models, toolchain,
assumption closure, and proof result. Frozen parameters or wire formats alone
do not establish that correspondence. A release may be separately authorized
without FV, but it must not be described retrospectively as verified without
that binding.

**On-chain track (established).** `contracts/verification/` holds a Lean 4
specification of SPHINCS+C10 verification (`SphincsCVerify/Spec/` — WOTS, FORS,
ADRS, hypertree) plus wallet-model theorems (`theft_free` and its per-claim
corollaries: caps are unresettable, the bootstrap key can't be removed, the
CREATE2 address is chain-independent, EIP-1271 forbids the bootstrap key).
Every proof is re-checked by the Lean kernel; the remaining trust surface is a
small, *named* axiom list (`docs/AXIOM_STATUS.json`) — e.g. "the SHA-256
precompile implements FIPS 180-4" — each entry carrying its discharge artifact
(NIST CAVS known-answer tests, Halmos bytecode sessions against pinned
codehashes, or a citation). CI enforces no-`sorry` and lints the axiom list.

**Firmware track (in progress — work-todo §33).** The pure-logic firmware
crates (`sphincs-c10`, `aa`, `domain`, the wire-format parsers) are translated
to Lean with [Charon](https://github.com/AeneasVerif/charon) +
[Aeneas](https://github.com/AeneasVerif/aeneas), then proven equivalent to the
*same* `SphincsCVerify` spec the on-chain verifier was proven sound against.
Proof grinding is designed to be mostly AI-driven (a scheduled prover loop in
CI; the Lean kernel re-checks every proof, so AI output can never compromise
soundness), with an adversarial spec-validation layer — property-based
counterexample search on every spec before proof effort, plus differential
fuzzing of the executable Lean spec against the real Rust crate on the host.
Research and tool selection: [docs/verification/lean-verification-research-2026-06.md](../../../docs/verification/lean-verification-research-2026-06.md).

What this unlocks, in value order:

1. **Firmware↔chain binding.** The headline goal theorem must show that the
   bytes the firmware signs over a parsed sign-request are exactly the custom
   SHA-256 `PQSmartWallet.sphincsDigest(userOp)` the wallet recomputes—not the
   EntryPoint canonical keccak `userOpHash`, which this wallet ignores. The
   existing extracted `compute_user_op_hash` theorem is tooling-only; the
   production `compute_sphincs_digest_v06` bridge remains open. No finite test
   suite can close that gap exhaustively; a current-source theorem can.
2. **Signer/verifier correspondence.** The firmware's C10 signer and the
   on-chain verifier proven against one spec, ending any possibility of
   silent algorithmic drift between the two implementations.
3. **Panic-freedom on the attacker-facing parsers** (USB → wire-format), as a
   machine-checked DoS-hardening property — near-free under Aeneas's monadic
   translation.

**Status (2026-06):** extraction pipeline works end-to-end on `sphincs-c10`
(the crypto core — ADRS/WOTS/FORS/Merkle/hash — extracts cleanly after small,
test-pinned refactors; three UI-plumbing error sites remain). No firmware
theorem is proven yet; the first equivalence targets are
`address.rs ↔ Spec/Adrs.lean`.

**Honest scope.** A kernel-checked theorem here means: *proven, modulo the
enumerated axiom list, Aeneas translation fidelity, and rustc*. It says
nothing about side channels, fault injection, or silicon behaviour — those
remain covered by the SCA/FI bench (`tools/sca/`) and on-silicon validation.
Any claim of "verified" in docs or marketing must carry the assumption list.

## Implementation Status

🟢 tested (QEMU and/or real STM32U585 silicon) · 🔵 code exists, untested/partial · ⏳ not started · 🚫 blocked on hardware/lab

| Component | Status |
|---|---|
| TrustZone partitioning (SAU + IDAU + MPC/GTZC) | 🟢 QEMU + HW (TZSC enforcement + USB coexistence silicon-validated 2026-05-20; only TAMP/GTZC2 follow-up open) |
| NSC gateway (NS pointer validation, CMSE veneers / mailbox) | 🟢 QEMU + HW |
| BIP-39 → SPHINCS+C10 derivation, master + per-slot, multi-account (256/seed) | 🟢 QEMU + HW |
| OPTIGA Trust M V3: IFX I2C + APDU + Shielded Connection | 🟢 HW |
| OPTIGA E120 LUC silicon PIN counter + F1D0/E120 transient-auth reset | 🟢 HW |
| SE050: T1oI2C + APDU + SCP03; admin-wipe e2e | 🟢 HW |
| Dual-SE XOR entropy split; MCU page-124 FI-hardened counter; three-way PIN-attempt enforcement | 🟢 HW |
| Tier 1 SAES-CMAC(DHUK) KDF + SAES driver self-test | 🟢 HW |
| `sphincs-c10` library; HW SHA-256 routing (HASH peripheral, boot KAT) | 🟢 QEMU + HW |
| Trusted UI (NV3007 LCD + 2-button), seed wizard / PIN entry / confirm dialogs | 🟢 QEMU + HW |
| `#![no_std]`/no-heap/zeroize, panic-handler wipe, inactivity timeout | 🟢 QEMU + HW |
| Native clear-sign (Safe / CoW / ERC-7730 / ERC-20); Merkle-verified DBs | 🟢 QEMU |
| EIP-712 Safe + CoW Swap verifiers; ERC-7730 renderer | 🟢 QEMU |
| Automated e2e (`make e2e` QEMU; `make e2e-hw` silicon) | 🟢 |
| ERC-1967 proxy contracts (PQSmartWallet + Factory + PQMultiOwnable), Foundry suite | 🟢 |
| Hash-signature firmware update (FSBL + `fwsign` + `fw-manifest` + streaming `fw_update/`) | ⚠️ legacy bench implementation; Draft 1.1 is an unapproved research candidate; production blocked on software, resource, factory, and silicon gates |
| Firmware measurement at boot (SHA-256 → 8 BIP-39 words) | 🟢; bit-packed shared rendering verified |
| Firmware rollback journal + typed OTP floor | 🚫 production-blocked pending software backend, resource gates, and later owner-authorized silicon evidence |
| TAMP driver (log-only); consumption-mask hook | 🟢 implemented |
| Tier 2 BHK; boot-time attestation; device-identity cert | ⏳ not started |
| ML-KEM-1024 inner wrap | 🚫 descoped 2026-07-07 (owner decision — accepted Grover-only bus residual; prototype retained feature-gated) |
| Mixed-RNG (STM32 ⊕ OPTIGA ⊕ SE050 TRNG); PIN-entry digit scrambling | 🔵 partial / ⏳ |
| Custom PCB; HUK-SAES at-rest wrap; production TAMP wipe; first-boot RDP-2 self-lock validation (work-todo #36); FI/SCA lab | 🚫 blocked on HW |

## Firmware Update Model

A **hash-signature** model combining open-source reproducible builds with manufacturer approval — end-to-end SPHINCS+C10 + SHA-256, no classical fallback.

```
Candidate:     Draft 1.1 proposes manifest-v6 over an exact 121-byte `PQFW_V6` preimage
               binding slot, versions, image lengths/hashes, and vendor-key fingerprint.
FSBL (target): verify both slots, decode typed marker/floor state, select under the candidate
               state machine, and establish a security-epoch floor only after CONFIRMED.
Device (target): stream and verify a candidate, enter restricted probation, complete the
               candidate health protocol, then seal CONFIRMED. Runtime never writes the floor.
```

- **One PQ algorithm in the verification path** — the FSBL has one pubkey and one algorithm; a "just in case" classical fallback would defeat the PQ property, so there is none.
- **Signing the preimage IS signing the firmware** — once approved and implemented, SHA-256 collision resistance would tie Draft 1.1's proposed 121-byte, slot-bound V6 preimage to the exact binaries, lengths, vendor key, and rollback tuple. No such implementation authority exists yet.
- **Epoch split** — ordinary releases only advance `release_version`; OTP is consumed only when `security_epoch` revokes older vulnerable releases. The physical OTP design is still open and production-blocked.
- **PIN unlock required on every `CMD_FW_*`** (the seed is never accessed, but this blocks silent re-flash of a stolen device). The at-rest vendor SK is Argon2id + XChaCha20-Poly1305 wrapped — only on the signing machine, never on the device.

See [docs/firmware/firmware-update.md](../../../docs/firmware/firmware-update.md) and [docs/firmware/reproducible-builds.md](../../../docs/firmware/reproducible-builds.md).

## Build Modes

| Feature | Description |
|---|---|
| `mock-se` | Mock SE in SRAM (QEMU default) |
| `optiga-trust-m` / `se050` | Real OPTIGA Trust M V3 / SE050 via I2C1 |
| `dual-se` | Both production SEs + XOR entropy split (implies `optiga-trust-m` + `se050`) |
| `optiga-hw-counter` | Silicon OPTIGA PIN counter via E120 LUC bound to F1D0 Execute. **Destructive on first provisioning** |
| `spi1-arduino` | SPI1 on the Arduino R3 headers (PE12–PE15; implied by `ui-lcd`) |
| `saes-dhuk` / `saes-self-test` | Tier-1 `SAES-CMAC(DHUK)` KDF / boot self-test of the SAES driver |
| `tamp` / `consumption-mask` | TAMP (log-only on this branch) / TIM2 CH1 PWM SCA mask on PA5 |
| `stm32u585` | Real hardware target (vs QEMU `mps2-an505`). **Implies `hw-sha256`** |
| `hw-sha256` | Route `sphincs-c10` SHA-256 through the HASH peripheral |
| `ui-semihosting` / `ui-lcd` / `ui-noop` | Console (QEMU) / NV3007 SPI LCD / silent |
| `usb` | USB OTG init |
| `debug-log` / `e2e-test` / `mock-se` / `otp-hardcoded-master-key` / `ui-capture` | **Dev/test only — CI gates these OFF for production** |

Mode aliases: `mode-production` (no dev features) · `mode-bringup` (`debug-log`) · `mode-e2e` · `mode-bench`.

## Bring-up Roadmap

Each phase has a hard exit criterion before the next starts. Full backlog: the `EthereumPhone/PQ1` issue tracker (labels `source:work-todo` / `source:production-todo`).

- **Phase 0 — bring-up complete (today).** All-C10 firmware boots on the B-U585I-IOT02A; dual-SE split, three-way PIN-attempt enforcement, Tier-1 DHUK KDF, OPTIGA Shielded-Connection unlock, SE050 admin-wipe, and the FSBL firmware-update path all run end-to-end. The directional boot cross-check and known production-invariant regressions are stated in `CLAUDE.md`.
- **Phase 1 — close the bring-up regressions (in progress).** Restore the GTZC `TZSC_SECCFGR` allowlist (incl. GTZC2 USB-OTG); strip `debug-log`/`e2e-test`/`mock-se` from production builds + restore the `compile_error!` fences; remove dev log/register dumps; wire TAMP IRQ → `trigger_lockout_wipe()`; move BOR/inactivity to the Secure-only TIM; land Tier 2 (BHK); step a board to RDP1 and re-validate per-die DHUK uniqueness.
- **Phase 2 — boot-time attestation (still on the devkit).** Pin a SPHINCS+C10 device-identity cert; implement mixed-RNG and PIN digit scrambling. (The ML-KEM-1024 inner wrap formerly in this phase was descoped 2026-07-07 — owner decision; bus confidentiality rests on the symmetric-rooted tunnels + per-device key rotation.) Exit: attestation verified at boot; halves cross the bus only under per-device-keyed AEAD (trace-verified).
- **Phase 3 — custom PCB, HUK-SAES, GTZC, production peripheral set.** Design/review the PCB (U585 + both SEs + NV3007 LCD + buttons + tamper mesh + EMI can); HUK-SAES wrap the at-rest secrets; GTZC-mark every Secure-only peripheral; MPU boundaries; block DMA into S-SRAM; wire case switch / tamper mesh / temp sensor / BOR to the wipe ISR (measure bulk-cap holdup on real HW).
- **Phase 4 — secure boot, provisioning, lockdown (blocked).** Approve an exact
  successor to the Draft 1.1 research candidate, close its rollback
  backend/resource gates, and produce a replacement factory receipt before
  defining any irreversible ceremony. Sacrificial-unit
  and RDP2 work is explicitly outside the current software-only milestone.
- **Phase 5 — pre-launch validation.** External audit, FI + SCA lab time on the locked PCB, public bug bounty before any sale, gradual rollout with a long observation window.

## Pre-Production Shipping Checklist

Nothing here is optional. Run through the entire list **per device class**, not per software release. Each item is something that has bricked, leaked, or burned a hardware-wallet vendor in the last decade.

**A. Hardware design & PCB** *(full spec: [`docs/hardware/hardware_requirements.md`](../../../docs/hardware/hardware_requirements.md))*
- [ ] PCB review by an embedded-security specialist (not the layout engineer)
- [ ] Evaluate moving SE050 off the shared I2C1 (0x30 / 0x48) to a second peripheral; independent reset for each SE
- [ ] No test pads / debug headers / probe points on any SE bus, LCD bus, button GPIO, or S-world peripheral
- [ ] Tamper mesh across all four layers over U585 + both SEs; case switch → TAMP with pull + noise filter
- [ ] BOR threshold + bulk capacitance **measured on real HW** so the wipe ISR completes before V_dd collapses
- [ ] Temperature sensor across the operating envelope; cold-boot threshold tested; retain only the SWD + NRST verification pads required for pre-first-power inspection, with no JTAG or second debug header (first field boot self-locks RDP-2 and disables debug in silicon)
- [ ] EMI can over U585 + both SEs; power-rail filtering vs ripple-injection; no glitchable clock to S-world peripherals
- [ ] Second-source every BOM part (an OPTIGA/SE050 stockout must not force a swap that breaks pinned attestation)

**B. Provisioning facility**
- [ ] Clean-room, no network / removable media / personal devices; reproducible, signed, re-imaged station OS per batch
- [ ] HSM-backed factory trust-anchor, attestation, and per-device transport-key ceremonies (or EdgeLock 2GO for SE050 at volume); two-person rule on HSM roots. The line must not generate or retain final pairing secrets.
- [ ] Per-device transport SCP03/PBS state and UID bindings are installed at the factory; the final pairing rotation happens on-device after first-field RDP-2 self-lock. Current code's deterministic DHUK/BHK helpers are not the still-open final salted-rotation protocol.
- [ ] Logs never contain secret material (CI scan for high-entropy strings); tamper-evident packaging; signed per-batch report
- [ ] Provisioning-station compromise plan (detect / scope / notify); quarantine + manual review for any post-provisioning failure

**C. Firmware build pipeline**
- [ ] **Reproducible builds** — same git SHA → byte-identical image, verified in CI on every push; toolchain pinned + archived per release
- [ ] All git deps pinned to a commit hash; `cargo audit` + `cargo deny` clean (fail on advisory); `cargo-geiger` archived per release
- [ ] `#![deny(unsafe_op_in_unsafe_fn, clippy::indexing_slicing)]`; every `unsafe` has a reviewed `// SAFETY:`
- [ ] LTO + overflow checks on; debug info / semihosting / panic strings stripped from the production image
- [ ] No `debug-log`/`e2e-test`/`mock-se`/`otp-hardcoded-master-key`/`ui-capture` in production (CI-gated); SBOM signed per release
- [ ] Release artifacts signed by an HSM release key, hash published via ≥ 2 channels; built on an air-gapped host

**D. Cryptographic verification**
- [ ] SPHINCS+C10 test vectors pass on-target; output matches `SPHINCsC10Asm.sol` byte-for-byte; differential test vs a second HBS impl
- [ ] BIP-39, HKDF PIN-stretch, HKDF-SHA256, SHA-512, AES-256-GCM (SAES path) test vectors pass
- [ ] SCP03 + Shielded-Connection + attestation negative tests (replay, malformed, wrong keys/UID, timeout)
- [ ] PIN brick test (nine prior wrong attempts, then the tenth wrong attempt bricks exactly once, verified by zeroized r-mem read-back); power-loss tests at every step of every flow
- [ ] Three-way per-attempt test plus directional page124/E120 rollback cases (`make pin-gate-hw-counter-e2e` is the starting point); full recovery test on a fresh device B

**E. Side-channel & fault hardening**
- [ ] External FI lab (voltage / EM / clock glitch) against PIN entry, attestation, signing, wipe; SCA lab (SPA/DPA) with and without the EMI can + consumption mask
- [ ] Constant-time inspection of the *generated assembly* for every secret-dependent SPHINCS+C10 loop (`subtle` is a contract, not a guarantee)
- [ ] Verify-before-release wired into every signing path; wipe ISR loop-twice + read-back verified under brownout and TAMP
- [ ] Stack scrub + CPU register scrub + cache flush after every secret-touching routine; cold-boot mitigation (freeze-spray tested); DMA-into-S-SRAM denied by GTZC

**F. STM32U585 secure boot & option bytes** *(how-to: "Locking the STM32 to your firmware only" below)*
- [ ] Approve an immutable SPHINCS+C10 FSBL artifact, final page geometry, both-bank protection, and factory ceremony. Draft 1.1's pages-0..4 proposal grants no burn authority (work-todo #36).
- [ ] FSBL refuses any slot whose preimage sig doesn't verify (CI flips one bit, confirms halt); image verification before any of your code runs
- [ ] C10 vendor sk lives only in an air-gapped HSM (Argon2id + XChaCha20-Poly1305 at-rest wrap, two-person rule, no on-disk copies)
- [ ] `TZEN=1`; devices ship at **RDP-0** for pre-first-power user verification and the FSBL self-programs `RDP=0xCC` (Level 2) on the first field boot as the **final** lockdown step (work-todo #36; verified by JTAG/SWD refusal on locked units); `nBOOT0`/`nSWBOOT0`/`nBOOT_SEL`/`nBOOT_LOCK` force internal-flash boot
- [ ] `SECBOOTADD0` + `SECWM1/2` cover all S-flash; HDPL increments hand off bootROM → S → NS; OBKEY anti-rollback advances per update
- [ ] All debug option bytes disabled; BOOT0 tied low / removed; option-byte profile burned via the HSM-signed script (no manual clicks); independent verification on a sample of finished units

**F2. Post-quantum cryptography**
- [ ] **Recovery contract committed at launch**: C10 params, BIP-39 → C10 tag, CREATE2 salt, slot tags — after first ship, any change is a user-visible hard fork
- [ ] Verify-before-release on every Type 1/2 sig (double-evaluated with a sentinel)
- [ ] Per-device SCP03 + PBS rotation verified on every shipped unit (I²C-trace scan confirms no fleet-default statics; load-bearing since the ML-KEM inner-wrap descope 2026-07-07); mixed TRNG reachable + un-bypassable
- [ ] No classical-fallback verifier anywhere in the FSBL (CI confirms no ECDSA/Ed25519/RSA under any feature flag)
- [ ] External audit of the `sphincs-c10` crate (address encoding, WOTS chains, zeroization, SHA-256 SCA)
- [ ] Documented + drilled PQ migration path if SHA-256 is broken; recovery test that the same 24 words survive a migration

**G. Update mechanism**
- [ ] Updates signed by an HSM key separate from provisioning; verified before any new code runs; verification key under RDP-2
- [ ] Downgrade protection via the monotonic counter; update never exposes a secret over USB; rate-limited + physical confirm on the secure UI
- [ ] Field-tested on staging hardware before public rollout; documented recovery path for a bricked fleet (RDP-2 cannot be unlocked)

**H. External validation**
- [ ] External audit by an embedded + TrustZone + SE firm of the *signed production image*
- [ ] All findings fixed or risk-accepted with external sign-off; public bug bounty + VDP published before any device ships
- [ ] Independent FI report from a lab; independent attestation that the build is reproducible

**I. Operational readiness**
- [ ] Incident response plan + out-of-band advisory channel (signed, ≥ 2 media); committed threat model + protocol spec (every APDU / NSC call / primitive / tag, versioned)
- [ ] Published "known limitations" doc; gradual rollout (small batch, ≥ 60-day public scrutiny); no company treasury on-device until long-proven; EOL + migration plan; CE/FCC/RoHS, correct EAL citation

**J. The "honest caveats" page in the box**
- [ ] Plain-language list of what the device does *not* protect against (coerced unlock, SE-die lab attack, vendor supply-chain, your own bugs); recommends a passphrase for coercion threat models and multi-sig for high value; states bug-bounty contact + firmware-signing-key fingerprint; translated per market

## Target: locking the STM32 to approved firmware only

This is the intended production state, not the current bench state. After the
rollback architecture, physical geometry, both-bank protection, option-byte
ceremony, and silicon receipts are approved, the STM32U585 boot path is meant
to enforce “this chip only runs firmware signed by *this* key” with a custom
WRP-protected FSBL that verifies SPHINCS+C10 before mutable firmware runs. The
current legacy FSBL verifies C10 artifacts on the bench but is explicitly
production-fenced and grants no irreversible burn authority.

```
HDPL0  System Bootloader (immutable) — dispatches to the FSBL per option bytes
HDPL1  Target FSBL (future approved WRP range) — holds the 32-byte C10 vendor key and verifies/measures A/B slots.
       Draft 1.1 proposes a release-version + security-epoch tuple and typed OTP floor, but is
       not implementation-approved; journal/ECC/OTP, FLASH, RAM/stack, and silicon gates remain OPEN.
       The legacy 1024-bit/75-byte-preimage path is production-fenced and must not ship.
HDPL2  Secure-world firmware — configures SAU/MPC/GTZC, opens SE buses, holds the
       OPTIGA PBS + SE050 SCP03 keys (derived via hw::secret_keys)
HDPL3  Non-secure firmware — UI shell, USB; no access to S-flash, SE buses, or any HDPL1/2 secret
```

In that target state, each authorized HDPL transition irrevocably hides the
previous level's option bytes and OBKEYs. No such statement authorizes or
records a transition on the current bench tree.

**No bring-up/burn sequence is currently authorized.** `fwsign sign` is a
legacy bench-only command requiring an explicit unsafe acknowledgement; release,
factory, and RDP2 targets fail non-ignorably. The future ceremony will be
written only after an exact rollback architecture digest is implementation-approved, its open software decisions close, and the owner
separately authorizes named sacrificial hardware.

**What this gives you:** only firmware signed by the vendor C10 key runs (a SHA-256 class-break is the only way past); PQ confidentiality of stored secrets (post inner-wrap); no debug access, no bootloader fallback, no option-byte rollback, no flash patching of the FSBL; HDPL hides keys from later stages.

**Read before burning your first option byte:** ST AN5447 (OEMiROT for STM32U5), AN5054, UM2851, RM0456 (Flash/RDP/OEMiROT/HDPL), AN5156; the TF-M STM32U5 port and MCUboot (references only); NIST FIPS 203 (ML-KEM), FIPS 205 (SLH-DSA — note we use the W+C_F+C variant, not stock SLH-DSA), SP 800-208, IR 8413; CNSA 2.0; and the in-tree `sphincs-c10/` crate + `SPHINCsC10Asm.sol` — the authoritative spec for our exact parameter set.

## Documentation

Start with this README → `docs/STATUS.md` (the security/verification frontier — what is done, what is open, and why, with an evidence pointer per row) → `CLAUDE.md` (invariants, file map, conventions) → the `EthereumPhone/PQ1` issue tracker (backlog — labels `source:work-todo` / `source:production-todo`) → the subsystem doc for your task.

- **Architecture / hardening:** `CLAUDE.md`, `docs/security/HARDENING.md`, `docs/security/threat-model.md`, `docs/security/production-security.md`, `docs/security/brownout-hardening.md`. `docs/architecture/architecture.md` is the current index.
- **Secure elements:** `docs/secure-elements/se050-userid-pin-auth.md`, `docs/secure-elements/se050-factory-reset.md`, `docs/secure-elements/optiga-bringup-status.md`, `docs/secure-elements/OPTIGATRUSTM/*.md`
- **Firmware / builds:** `docs/firmware/firmware-update.md`, `docs/firmware/reproducible-builds.md`
- **Wallet / clear-signing:** `CLAUDE.md` (§Wire formats + §Recovery / Key derivation — the authoritative wallet design), `contracts/smart-wallet/` (the ERC-4337 v0.6 account + Yul C10 verifier), `docs/companion/companion-app-integration.md`, `docs/companion/erc7730-integration.md`, `docs/companion/erc8213-fingerprints.md`.
- **USB / dev:** `docs/companion/usb-protocol-v2.md`, `docs/hardware/usb-hid-setup.md`, `docs/hardware/dev-board-setup.md`, `docs/hardware/hardware_requirements.md`
- **Formal verification:** `contracts/verification/` (Lean proofs + axiom status), `docs/verification/lean-verification-research-2026-06.md` (tooling research), work-todo §33 (firmware track)

## Acknowledgements

- **On-chain SPHINCS+ verifier and the C10 parameter set — [Nicolas Consigny](https://github.com/nconsigny) (`nconsigny`, <nicolas@ethereum.org>).** The Yul verifier this wallet deploys, `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol`, is derived from `SPHINCs-C10Sha256Asm.sol` in [nconsigny/SPHINCs-](https://github.com/nconsigny/SPHINCs-) (MIT), and the C10 parameter set itself originated in that repository (commit `0516a11`, 2026-04-09, from its Fluhrer–Dang security sweep — see `docs/verification/c10-fips205-delta-audit.md` §Addendum). The Python reference signer that `sphincs-c10/` was written against comes from the same work. PQSigner's changes on top are the SHA-256 firmware-parity constraints, N-mask key-shape enforcement in the verifier, FORS-forest binding to the hypertree leaf position, and the 65,536-per-chain use caps.
- **Trezor** — the TAMP tamper-detection driver is a GPLv3 port from `trezor-firmware`.
- **Solady / Coinbase Smart Wallet** — nested EIP-712 (`replaySafeHash`), ERC-6492 signature checking, and the multi-owner account shape the ERC-4337 v0.6 account is compatible with.

## License

Copyright (c) 2026 Freedom Factory Inc.

- **Firmware and everything else in this repository:** [GNU General Public License v3.0](LICENSE) (GPLv3). Note that ported third-party GPLv3 code (e.g. the Trezor-derived TAMP driver) is compatible with and remains under GPLv3.
- **Smart contracts (`contracts/`):** [MIT License](contracts/LICENSE). Vendored third-party contract dependencies (Solady, Coinbase Smart Wallet reference code, forge-std, etc.) remain under their own licenses.

Vendor datasheets, application notes, and the NXP Plug & Trust middleware are **not** distributed in this repository (their licenses do not permit redistribution). Download them from the respective vendors: STMicroelectronics (RM0456, STM32U585 datasheet, UM2839), NXP (SE050 datasheet, AN12413, AN12436, AN12514, AN13539, Plug & Trust middleware), Infineon (OPTIGA Trust M doc pack), and the display-controller vendors (NV3007, SSD1306). The SPHINCS+C parameter-set paper is open access at [eprint.iacr.org/2022/778](https://eprint.iacr.org/2022/778).

## ⚠️ Early access — work in progress

**PQ1 is unfinished, not yet audited, and not ready to hold value.** We are
open-sourcing it early, while it is still being built, rather than presenting it
as finished after the fact — the design and the code should be reviewable in the
open. Expect breaking changes.

- **No devices have shipped** and no on-chain wallet holds funds. Do not use this
  to protect real value.
- **An external security audit by Trail of Bits is currently under way**, and no
  external audit has been finalized. Treat the security claims above as
  unconfirmed until that work lands — the reviews under `docs/audits/` are our
  own.
- **Ship-blocking work is still open**, including irreversible secure-element
  provisioning steps. [`docs/STATUS.md`](../../../docs/STATUS.md) tracks the state of each
  subsystem — what is done, what is open, and why.
- Values described above as "frozen" — domain-separation tags, the C10 parameter
  set, the CREATE2 salt, the EntryPoint version — are what we intend to commit to
  *at launch*, and can still change cleanly before first shipment.

Review, reproduction, and bug reports are welcome — see
[`SECURITY.md`](SECURITY.md).



### From `CLAUDE.md`

# PQSigner OS — LLM Context

> **Agent process entry point:** Claude Code loads this file directly. Before
> non-trivial work, read [`AGENTS.md`](../../../AGENTS.md), which routes current status,
> the planning/review workflow, and applicable adversarial-review playbooks.
> The project contract below remains authoritative for its stated scope.

Post-quantum ERC-4337 hardware wallet on **STM32U585 (Cortex-M33, TrustZone) + OPTIGA Trust M V3 + SE050**. **SPHINCS+C10 only** for signing — pure PQ, no ECDSA fallback. Account-abstraction smart account on **EntryPoint v0.6** (Coinbase-Smart-Wallet-compatible) — **frozen target, no v0.7/v0.8 migration**: the v0.6 instance address + ABI are baked into `initCode`, the userOpHash preimage, and the on-chain factory; switching EntryPoint versions would change the CREATE2 init-code hash and break invariant #6 (same 24 words → same address on every chain). v0.6 stays supported by EIP-4337 bundlers indefinitely; if v0.6 is ever sunset, the response is to keep using direct EOA-bundled execution against the same wallet contract, not to redeploy. Same 24 words → same on-chain address on every chain (CREATE2 salt = `sha256(masterPkSeed‖masterPkRoot)`). SHA-256 inside the PQ stack; Keccak-256 only for EVM-mandated hashes (userOpHash, EIP-712, EIP-1559, ERC-7201, CREATE2 opcode).

**Status (2026-04, pre-production bring-up).** All-C10 cutover complete: bootstrap **and** slot keys are C10 (`h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205, sig=4008`). Boots on real B-U585I-IOT02A and QEMU mps2-an505. Both SE drivers + Tier-1 SAES-CMAC(DHUK) KDF working; three-way PIN-attempt consumption (MCU page 124 + OPTIGA E120 LUC + SE050 silicon UserID) and the 10-wrong-PIN brick/admin-wipe flow were validated end-to-end. Boot reconciliation has the narrower directional scope stated in invariant #2. On-chain caps: `MAX_BOOTSTRAP_USES = MAX_SLOT_USES = 65,536` (≈ 2^32 txns/chain). **Per-KEY margin, stated honestly (corrected 2026-07-26):** slot keys are chain-bound, so 65,536 is a true per-key cap (birthday floor 96 b). The **bootstrap key is chain-INDEPENDENT** (invariant #6 requires it for cross-chain address stability), so its per-key budget across `C` chains is `C x 65,536`, NOT 65,536 — its generic-multi-target floor degrades as `96 - 2*log2(C)` (94 b at 2 chains, 88 b at 16). This is the documented P14 caveat (`Quantitative.lean` P14 + `advantage_floor_within_bootstrap_cap_crosschain`); realistic bootstrap usage is tens of signatures (slot rotations only), so practical exposure is far below the cap. Firmware is **stateless w.r.t. slot selection** — companion supplies `(chain_id, slot_index, flags)` on every sign. Page 123 durably tracks each slot's off-chain count, reconciled UserOp count, generated UserOp-signature tally, and registration state.

**Shipping model (owner decision 2026-07-14 — work-todo #36).** The factory flashes the firmware and retains responsibility for SE-internal irreversible provisioning/lockdown on per-device *transport* keysets — S-1/S-2/S-3 metadata/object preparation, UserID/LUC, attestation objects, and the eventual OPTIGA lifecycle ratchets — then ships at **RDP-0** so anyone can verify flash + option bytes + OTP over SWD (connect-under-reset, **before first power**) against the reproducible build. On the **first field boot** the device self-locks to RDP-2 (only then is the per-die DHUK final), performs the BHK first write, and replaces the transport credentials before entering the seed wizard. The `rdp2-self-lock` candidate now implements the device-side journaled flow: transport→BHK-rooted SE050 SCP03/admin rotation and transport→persisted-TRNG-salted DHUK OPTIGA PBS rotation. That code is implementation evidence, not a production-approved ceremony. A batch-uniform/erased shipping image still lacks the reviewed authenticated per-unit factory handoff/receipt, authenticate-before-rotate contract, atomic durable old/new/KVN recovery proof, selected E140 lifecycle order, and silicon receipts. No migration protocol or irreversible ordering is authorized by this summary. There is **no factory/fixture RDP-2 burn** and no factory-held final pairing secret.

**Trusted-display clear-signing.** Every signable artifact is decoded and rendered inside the secure world before the user presses confirm — no blind-sign path for known shapes. (1) **Safe transactions:** the EIP-712 `SafeTx` typed-data hash is verified in S-world (`secure/src/tx/eip712/safe/`) and the inner `to/value/data/operation` is decoded locally — ERC-20 transfers and Safe owner/threshold/module/guard changes render on the LCD with full parameters; the companion never gets to substitute a hash. Safe `multiSend` batches (selector `0x8d80ff0a`, the shape the Safe web UI emits for anything multi-step) clear-sign per record: `operation=1` (DELEGATECALL) is accepted ONLY against the three pinned canonical `MultiSendCallOnly` deployments, the packed records are strictly decoded (`secure/src/tx/eip712/safe/multi_send.rs` — per-record op==0, ≤6 records, exact framing) and each record routes through the same inner ladder (ERC-20 / ETH / Safe-mgmt / CoW / loud per-record blind) with divider pages; any rule violation or page-budget overflow refuses to sign — a DELEGATECALL is never blind-signed. (`operation=0` calls to a MultiSend address stay loud blind-sign — under CALL the Safe isn't msg.sender for the records.) (2) **CoW Swap orders:** the EIP-712 `GPv2Order` is verified in S-world (`secure/src/tx/eip712/cowswap/`) and the order payload is decoded **on-device** — token name/symbol/decimals come from the firmware-pinned `ERC20_DB_ROOT` (the same Merkle root the ERC-20 transfer path uses), so the user sees the exact intent (e.g. `SELL 0.2 USDC for at least 0.0004 WETH`) rather than a 32-byte digest. ERC-7730 clear-sign descriptors and the typed-call ABI parser are likewise pure on-device decoders; incomplete registry-known formats are hard refusals. (3) **Safe-wrapped CoW orders:** when a SafeTx's inner call is CowSwap `GPv2Settlement.setPreSignature(orderUid, true)` — directly, or as a record inside an allowlisted `MultiSendCallOnly` batch (the Safe UI's actual `[approve(vault relayer), setPreSignature]` shape) — the same CoW v3 pipeline verifies the order bound to the presign calldata (the *record's* bytes for multiSend) with `orderUid.owner == the Safe` (not the wallet `sender`), and the render combines Safe context (banner, address, nonce, refund pages) with the full order intent — unmistakably "a CoW order for this specific Safe". One binding resolver (`secure/src/tx/eip712/safe/cow_binding.rs`) and the shared `cowswap_display::append_order_body_pages` keep all flows code-identical; see `docs/companion/companion-safe-cowswap-presign.md` (single-call + the folded-in multiSend-batch section).

**Scope of the clear-signing guarantee:** “no blind-sign path for known shapes” above applies to the structured on-chain and typed-data dispatchers. Explicit EIP-1271 `RAW32` is a separate, loudly-labelled blind off-chain tier; it is not a semantic fallback for a typed-data request. **Forced blind is likewise not clear signing.** If the default-off `erc7730-forced-blind` feature is implemented and enabled, only cleanly absent metadata for an exact member of the separately authenticated refused-known set `F = K \ C`, in the enumerated single steady-state Type-2 case for a slot already registered by the normal Type-1 rotation path, may enter its separate on-device ceremony. A tuple in the firmware's accepted clear set `C` either clear-signs or fatal-refuses: descriptor omission cannot downgrade it, and any present descriptor's validation, binding, or render failure is fatal. ERC-8176 may support catalogue admission into `C`; it grants no runtime signing authority and no semantic claim to forced raw pages. Feature-off and rollback behavior remain hard refusal, and all independent production-configuration, trusted-UI/FI, resource, provenance, rollback, and release gates remain required.

## Non-Negotiable Invariants

Production contract — every shipping build must respect ALL. Pre-production may temporarily violate one (note in next section).

1. **Dual-chip seed split.** BIP-39 entropy is XOR-split: `half_O` on OPTIGA, `half_E` on SE050. Neither chip alone reveals any bit. Never store full entropy on one chip or transmit a half across.
2. **Hardware PIN gating; three-way per-attempt consumption, directional boot cross-check.** PIN comparison stays in SE silicon. `gated_unlock` precharges MCU page 124; an ordinary wrong-PIN attempt then advances OPTIGA E120 and the SE050 UserID. Page 124 and SE050 enforce the user-facing 10-attempt bound; E120 is a separate 32-lifetime-attempt anti-extraction backstop. At boot firmware can read page 124 and E120 and wipes when `E120_used > page124_used`; an MCU lead is a conservatively charged power-cut/transport-error state. The production SE050 UserID policy denies attempt-attribute reads (`SW=0x6986`), so SE050 is not a boot-reconciliation input; `AuthMethodBlocked` still maps to `PinLocked` and the wipe path. Do not claim three-way boot reconciliation. Making that property genuinely three-way requires a separately reviewed SE050 policy/backend and silicon decision.
3. **E2E encrypted SE tunnels.** OPTIGA Shielded Connection uses TLS-PRF + AES-128-CCM-8; SE050 SCP03 uses AES-CMAC + AES-CBC. No plaintext secret crosses I2C. The `rdp2-self-lock` candidate contains the journaled transport→final device-side rotation: SE050 SCP03/admin move to the BHK axis, while OPTIGA PBS moves to a DHUK derivation bound to a persisted fresh-TRNG salt. Page 126 is exclusively the DHUK-wrapped SE050 BHK; page 127 owns the first-boot journal and salt. Production remains blocked until the authenticated per-unit factory handoff/receipt, authenticate-before-rotate rule, atomic durable old/new/KVN recovery adequacy, E140 ordering, and silicon evidence are reviewed and closed. The ML-KEM-1024 inner wrap was DESCOPED 2026-07-07 (owner decision, do not re-raise — see work-todo #9): both tunnels are symmetric-rooted (no Shor material on the bus), so the accepted residual is Grover-2⁶⁴ (Cat-1) key search against physically-tapped sessions; consequence: per-device final rotation is load-bearing for this acceptance.
4. **All secrets only in TrustZone secure world.** NS never sees PIN, entropy, signing key, or derived secret. NSC gateway returns opaque non-secret data. Validate NS pointers and copy NS buffers to S-stack before parse (TOCTOU).
5. **One signing primitive: SPHINCS+C10.** Both Type 1 (bootstrap → slot registration) and Type 2 (slot → user tx). No FORS+C, no classical signer (secp256k1, P-256, Ed25519). Wallet has a single `c10Verifier`. Host-only `dbgen` may verify externally mandated ERC-8176 EAS/secp256k1 signatures solely to admit catalogue inputs; its production verifier holds no signing key, creates no wallet/FW-update/on-chain authority, and is fenced by `make classical-crypto-boundary`.
6. **Bootstrap C10 keys immutable per-wallet (launch invariant).** CREATE2 salt depends only on `(masterPkSeed, masterPkRoot)`; rotating changes the address. No `rotateMasterKeys` and no ownership model that could introduce one.
7. **Per-chain caps monotonic, unresettable.** `bootstrapUses < 65,536`, `slotUses[i] + offchainSigCount[i] < 65,536`. No `reset*` or `increaseMax*` path. Exhausted chains stay frozen.
8. **Stateless slot selection.** Companion supplies `(chain_id, slot_index, flags)` on every sign. No flash slot store, no recovery state machine in S-world. Slot keys re-derived on demand and cached in SRAM only.
9. **Off-chain sig counter, combined cap.** Firmware tracks `local_offchain_count` + `last_userop_count` per slot in flash page 123 (log-structured, 16 B/increment, compaction). Refuses to sign past `MAX_OFFCHAIN_GAP = 100` unbacked sigs or past the combined cap. Post-restore, `CMD_SIGN_OFFCHAIN` for an unregistered slot is rejected — forces a Type 1 rotation via `CMD_SIGN_USEROP` first. The forced-blind steady Type-2 branch enforces the same registration prerequisite and cannot create registration through its tally write.
10. **Verify-once-physically trust chain (owner decision 2026-07-21).** The device's entire post-sale trust story is: (a) ship at RDP-0 so anyone can verify flash + option bytes (including staged WRP) + OTP over SWD, connect-under-reset **before first power**, against the reproducible build; (b) the verified image contains an FSBL whose pages are WRP-protected and which measures the active firmware slots and renders the 8-word fingerprint at boot; (c) first field boot self-locks to RDP-2, which freezes the option bytes forever — WRP on the FSBL range becomes physically permanent, so **no firmware update can ever modify, unprotect, or bypass the measuring code**; (d) from then on the boot-time fingerprint is proof of what is installed — the user never has to trust a firmware update again. Consequences that bind every future change: no runtime write path (fw_update or otherwise) may touch the FSBL range; the WRP-set → RDP-2 ordering is mandatory (RDP-2 with unprotected FSBL pages permanently forfeits the guarantee for that die); the FSBL must own the display for its fingerprint window (a later fake screen is the accepted residual — the *boot-time* window is the anchor, keep it visually distinctive); and the shipping image must actually flash the FSBL in the slot layout (monolithic builds are bench-only). Currently OPEN gates before this invariant is claimable: geometry MIGRATION (the frozen registry — pages 0..4, 40,960 B, `FSBL_MAX_LOAD_SPAN` 38,912 — landed as the `pqsigner-geometry` crate (FA-1.1) and is CI-pinned, but the bench **linker is still 32 KiB** and the image occupies pages 0..3, so the cutover is outstanding: issue #540. `make fsbl` reports the derived range, and adopting 40 KiB before the cutover would freeze page 4 while empty. **UPDATE 2026-10-05:** at the `opt-level = "z"` release profile the FSBL span dropped to **19,708 B** and the image now fits **3** pages, so `make fsbl` reports that the declared 4-page range would freeze page 3 while empty — the same class of waste as the page-4 note, one page earlier), both-bank WRP/option-byte ceremony, non-monolithic shipping image, FI-hardened FSBL image verify (EF-swarm F15), silicon receipts. **Geometry MEASUREMENT is closed** (2026-09-01, `scripts/check_fsbl_geometry.py`, run by `make fsbl`): the gate reads the physical LOAD span from the program headers rather than `size -B` text+data (which undercounts by any inter-segment gap — 28,704 vs 28,700 when that was written; 19,708 at `z`, see above), fails on more than one LOAD segment, on a start address that is not the boot base, and on a span that exceeds the region, and **derives the WRP page range from the image instead of assuming it**. Stack is bounded rather than closed: `-Z emit-stack-sizes` gives 50 frames totalling 10,372 B of 16,384 B (the tz-1 tripwire, #366, added two frames and 352 B of flash), and since no acyclic path can exceed the sum of all frames that is a genuine upper bound — subject to the stated caveats (no recursion, functions that emit no frame, interrupt frames on top). A call-graph worst case still needs `cargo-call-stack`.

## Pre-Production Caveats

No devices shipped, no funds on-chain — domain tags / parameters are still renamable pre-launch. Known acceptable regressions:

- **⚠️ SHIP BLOCKERS — OPTIGA shipping-state lockdown (S-1, S-2, S-3 — all three required before any device leaves the bench).** S-1 is the unclosed F1D0 authorization/lifecycle ceremony: the candidate metadata uses `Auto(F1D0)`, but its irreversible ordering and silicon receipt are not production-approved. S-2 is the still-open type-`0x11` Protected-Update pool `{0xE0E8,0xE0E9,0xE0EF}` plus the device-certificate retype boundary. The observed `0xE0E3` is already a full type-`0x12` device certificate; the retired public-sample helper targeting it is a mis-targeted no-op, not the live anchor path. S-3 requires `optiga-hw-counter` and its production evidence. Compile-time fences prevent these candidates from masquerading as shipping closure: `OPTIGA_S2_PRODUCTION_BLOCKED` rejects every `mode-production + optiga-trust-m` build while S-2 is open, the retained helper emits no APDU, and the irreversible experimental feature pair is deliberately unbuildable. Ordinary pairing also never ratchets E140; that factory-side action remains OPEN relative to final credential rotation. **Owners:** GitHub issues [`label:ship-blocker`](https://github.com/EthereumPhone/PQ1/issues?q=label%3Aship-blocker) (production-todo retired 2026-07-19; original "OPTIGA Trust M V3 — LcsO transitions" at `docs/archive/production-todo-retired-2026-07-19.md`) and `docs/STATUS.md` §A. The SE-side blockers **S-5/S-6/S-7 are RESOLVED 2026-05-28** (`docs/security/security-review-2026-05.md` §§C-7/C-8/C-9 = Fixed); S-7d's on-silicon `VERIFY` status mapping is resolved as `0x6986` and recorded in `docs/STATUS.md`. The OPTIGA bring-up state is acceptable ONLY because nothing has shipped.

- **TZSC config (invariant #4):** regressed then fixed; enforcement **and** USB-coexistence **silicon-validated 2026-05-20** (`make gtzc-enforcement-hw` → 7/7 secure peripherals RAZ-fault on NS access; device still enumerates `1209:7051` over USB-C). `secure/src/sau.rs` wires `GTZC1_TZSC_SECCFGR{1,3}` (AHB2 AES/HASH/RNG/PKA/SAES + I2C1/2 SECURE; OTG stays NS). Only TAMP (in GTZC2) remains as a follow-up.
- **Debug instrumentation may ship in this branch.** `debug-log` allowed on hardware, `secure_log!` in the wizard, NS pre-USB register dumps, DHCSR-gated semihosting prints in `hw::hash::init_clock`. CI must still gate production on `debug-log` / `e2e-test` / `mock-se` OFF.
- **Pixel trusted-UI pilot (`ui-px`, owner decision 2026-09-22).** Under `ui-px` every sign dialog (Safe, single-UserOp, rotation, direct CoW, ERC-7730, off-chain, batch — port plan steps 1-3; `forced_blind` excepted) renders as PQ-UI design screens (`pqsigner-ui-px` crate, `secure/src/ui/px/`, `docs/ui/pixel-ui-pilot.md`) and arms the sign gesture (the two-button chord click — both down together, fires on release; hold-right is a no-op, hold-left declines; owner decision 2026-09-22 on the EVT) on the opening ask / `Confirm?` / returning ask per PQ-UI `DESIGN.md` § Input. **Scroll-to-end is ON (owner decision 2026-09-24, `PX_COMMIT_REQUIRES_SEEN_LAST = true`), superseding the 2026-09-22 decision to reverse it:** the chord arms only after the LAST screen has actually been painted, matching the legacy 16×4 dialogs and the 2026-06-26 gate. An ERC-20 transfer is 8 screens with the recipient on 3 and the amount on 4, so signing from the opening ask approved a destination and value that had never been displayed. `fsbl-tests/tests/paired_constants.rs` pins the two paths together. See `docs/security/HARDENING.md` §2.4. Do not re-litigate without new evidence. **Atlas in the NS slot (owner decision 2026-09-23, port plan § Flash):** the glyph atlas + marks (`nonsecure/assets/ui-px/atlas.pq1a`, 74 KB, NS feature `ui-px-atlas`) live at a fixed offset of the FSBL-measured NS flash slot, never in the secure image; the secure image pins their SHA-256 (`secure/src/ui/px/atlas_root.rs`, generated by `make ui-px-assets`) and `ui::px::assets` re-hashes the window before AND after every pixel dialog plus once more in the sign handler before release — a swapped glyph is a refusal, never a signature (a wrong font is a WYSIWYS input). Trailers are native screens (`tx/display/trailer_screens.rs`, one per proven trailer page, derived from the same page builders, per-slot + set proofs); no `Legacy` record exists on any pixel sign route. **Budget, re-measured 2026-10-05** (`make size-report-px BOARD=pq1`; physical span cross-checked against `readelf -l` LOAD, which is the method `check_fsbl_geometry.py` uses — `size` text+data undercounts by any inter-segment gap). Against the 466,944 B v6 secure slot (`geometry::SECURE_SLOT_SPAN`):

| build | span | vs slot |
|---|---:|---:|
| no `ui-px` (today's shipping shape) | 431,680 B | fits, 35,264 B spare |
| + `ui-px`, `opt-level = "s"` | 545,504 B | **78,560 B OVER** |
| + `ui-px`, secure `opt-level = "z"` | 481,376 B | **14,432 B over** (current setting) |
| + `ui-px`, everything `"z"` | 475,648 B | 8,704 B over — rejected on frame time, see below |

`z` on the non-UI firmware recovered 64,128 B — 82% of the gap — with no code deleted and no family dropped; crypto stays at opt-level 3 so signing throughput is untouched. **Frame time is NOT fenced off and is unmeasured at `z`:** `pqsigner-ui-px` stays at `"s"`, but the per-frame work is split and the slower half is in `sphincs-tz-secure`, which moved to `z` — `ui::px::lcd::{present_frame_ex, blit_strip}` is the measured 24 ms blit, while the raster left at `"s"` is only 8-11 ms. **FRAME TIME MEASURED ON THE PANEL 2026-10-05** (EVT screen unit, `ui-px-bench` + `ui-px-frametime` at 40 MHz `ui-px-spi40`, worst-case per second, render/blit/period ms): `pqsigner-ui-px` at `z` gives **15/20/36**, at `s` **11/19/31**. The whole difference is in RENDER (−4 ms, −27%) — that crate is the rasteriser; the blit is the SPI stream and does not move. `z` there cost ~4 ms against a **16 ms** pacing target for 5,984 B, so **it is reverted to `"s"`**; the parent profile stays at `z` and keeps its 64,128 B. **Neither setting meets the frame target** (31 ms ≈ 32 fps against `FRAME_PERIOD_MS` = 16 ms, `ui/px/lcd.rs:47` — i.e. roughly 2x over, not the 29% an earlier version of this line implied), and that is NOT an opt-level problem: see the SPI note below. **CORRECTION 2026-10-06:** this entry previously called 24 ms "the budget". That was a measured nine-strip blit COST (`ui/px/lcd.rs:62`) mislabelled as a target; `docs/ui/pixel-ui-pilot.md` states it correctly — "frame period ≈ 24 ms (≈ 40 fps; **the 16 ms cap never binds**)". Related: the 19-20 ms blit figures below are PARTIAL repaints — a full 428x142 panel at 40 MHz has a 24.31 ms wire floor, so no full repaint can read below it, and the full-panel blit has never actually been measured. **Security re-verified at `z`** (2026-10-05): `make checkct` proves kdf/fors/th/saes/ct_eq all `secure` on thumbv8m with the by-design-insecure fisher_yates control still firing (so non-vacuous) — and `tools/sca/checkct/Cargo.toml` deliberately MIRRORS the root `opt-level`, so it had to move to `z` too or the proof would have certified codegen the device does not ship; `make check-checkct-profile` now binds the pair. The FI double-compute is intact (`c10_sign_verified_with_progress_inner` still has 2 `sign_with_shuffle` calls + 2 FI verified-checks, same as at `s`), and the opt-level-3 crypto (sphincs-c10, sha2) is byte-identical across s/z. Caveat on the apparent FI-check drop elsewhere: `z` enables LLVM's MachineOutliner, which factors identical FI call sequences into `OUTLINED_FUNCTION_*` helpers (5 helpers hold 1 FI call each and are invoked 39 times), so STATIC FI call-site counts are not a valid metric at `z`. The FSBL is pinned back to `"s"`, but only ~756 B of its 8,996 B change reverted — a per-package override does not reach its dependencies — so the trust root is still largely `z` and its 18/18 silicon boot proof and the 10,372-B stack bound were both taken at all-`s` and have NOT been re-taken. **Why `ui-px` costs 113,824 B at `"s"`:** .text +103,584 / .rodata +9,472 — 91% is code, and the shared `tx::display` decode/classify modules actually SHRANK 1,482 B, so the decode logic is not the cost. Two presentation stacks coexist: for erc7730/userop/cow/offchain/trailer the pixel emitter ADAPTS the 16×4 painter's `Pages` (`erc7730_screens.rs` records that the in-renderer `Screens` sink was dropped so the audited renderer stays untouched), `safe_screens`/`batch_screens` are native, and `px_lift` (4,152 B) is the comparator proving the two agree. The remaining 14,432 B and the port's `PX_HEADROOM_MIN` of 40,960 B are an open owner decision; bank 1 has ZERO spare pages (the registry owns all 128) while the bank-2 NS slot has 275,100 B free (149,436 B image + 75,176 B atlas of 499,712 B), so the candidate levers are geometry, not diet. Every span above is a floor: `mode-production` + `rdp2-self-lock` are still absent (the S-2 fence blocks them). **The SHIPPING config has never been frame-time measured at all:** every number above is at 40 MHz, but `PX_SHIP_FEATURES` does not include `ui-px-spi40`, so the ship image drove the panel at 20 MHz where `hw/spi_hw.rs:221` documents a **~48 ms full repaint** — 3x the 16 ms target, before any render cost. **FIXED 2026-10-06** (`ee084e30`): the prescaler is now board-derived (`board::LCD_SPI_MBR`), so `BOARD=pq1` ships 40 MHz with no feature flag; iota2 stays at 20 MHz because its LD2 LED loads PE13 = SCK. The port plan's "≈ 40 fps on the sweep" describes a configuration we do not ship. Tracked separately, along with panel tearing (TE is mapped and enabled but never waited on) and the `PLAY_CAP_MS` freeze. `ui-px` stays out of `make release`; the CI budget step is informational until the lever lands.
- **Domain tags are sticky-but-renamable.** Tag `"sphincs-c6-v1"` is historical (was a different parameter set when written; now C10). Don't rename mid-bring-up (re-provisions every bench board); coordinated cleanup pre-launch is fine.

When a task touches an invariant-adjacent subsystem (TZSC allowlist, gateway surface, SE provisioning, key derivation), respect the invariant. Pure bring-up wiring (clocks, GPIO, peripheral-init order) prioritises lighting up; note any regression here.

## Lifecycle

Boot → legacy bench FSBL verify slots + render 8-word fingerprint on the NV3007 LCD (~6.9 s on pq1: 2.9 s verify MEASURED + a 4 s fingerprint reading window, the latter a policy constant set to match the secure world's long-standing `measured_boot::WORDS_MS`; the 4 s hold and the new total are EXPECTED, not yet re-measured on silicon — see `docs/security/measured-boot.md`) → branch into active slot → SAU/GTZC → SAES self-test → SE attest → PIN entry (S-world trusted UI) → unlock both SEs → reconstruct entropy in S-SRAM → active signing window (120 s idle timeout, S-only TIM; NS pings do NOT reset it) → zeroize on lock/tamper/brownout/inactivity. Treating the FSBL as an immutable production trust root remains contingent on the approved geometry, WRP/option-byte ceremony, production link/resource gates, and silicon receipts.

The FSBL fingerprint and the secure-world `measured_boot::run` screen show the SAME 8 words for the same active slot (both derived via `sphincs_tz_bip39::firmware_fingerprint_lines`). In the current bench implementation the FSBL row is the earlier measurement and the secure-world row is advisory; neither establishes production immutability. After the FSBL geometry/WRP/factory/silicon gates close, the FSBL row is intended to become the immutable trust root. Honest-row divergence is a strong defect/tamper signal.

**Sign dispatch** (`cmd_sign_userop.rs`, companion-driven; successful Type-2 releases are durably tallied on page 123):

```
parse {chain_id, flags{INCLUDE_INIT_CODE | REGISTER_SLOT | account_index | slot_index}, header, inner_tx}
  deploy:   INCLUDE_INIT_CODE, slot=0, !REGISTER_SLOT
            factory registers slot 0; emit initCode + Type-2 only
  rotation: REGISTER_SLOT, slot>=1, !INCLUDE_INIT_CODE
            emit bootstrap Type-1 + slot Type-2 (nonce base+1)
  normal:   neither flag; emit Type-2 only
  before release: durably commit the successful Type-2 tally
```

`SLOT_CACHE` in SRAM is keyed on `(account_index, chain_id, slot_index)` — slot keys are chain-bound, so a cross-chain hop at the same slot triggers a fresh <1 s keygen.

## Gateway Commands

`pqsigner_proto::CMD_*` is the source of truth (mirrored in `shared::CMD_*`).

| CMD | Name | Purpose |
|-----|------|---------|
| 1 | GET_REMAINING | min over MCU count + runtime SE-driver remaining-attempt mirrors; not a boot-reconciliation receipt |
| 2 | REQUEST_UNLOCK | trusted-UI PIN entry → `gated_unlock` |
| 7 | SIGN_USEROP | unified Type 1/Type 2 sign; flags drive `INCLUDE_INIT_CODE` and `REGISTER_SLOT` |
| 11 | IS_UNLOCKED | 1/0 |
| 12 | LOCK | zeroize cached secrets |
| 14 | GET_WALLET_ADDRESS | CREATE2-predicted ERC-1967 proxy address (<1 s on first call after unlock for master keygen, < 1 ms cached) |
| 15 | GET_INIT_CODE | pre-compute the 4280-B `initCode` for `(account_index, chain_id)` (companion gas-estimation) |
| 16 | SIGN_OFFCHAIN | EIP-1271 / ERC-6492 sig (4016 B deployed, 8616 B counterfactual via `flags` byte); refuses if slot unregistered (deployed path), gap ≥ `MAX_OFFCHAIN_GAP` (100), or combined cap exceeded |
| 17 | OFFCHAIN_STATUS | per-slot `(local_offchain_count, last_userop_count, registered)` |
| 20–24 | FW_BEGIN/CHUNK/COMMIT/STATUS/ABORT | streaming firmware update (PIN unlock required on every call) |
| 30 | SIGN_USEROP_BATCH | atomic multi-UserOp sign with single user confirm |
| 200 | TEST_PIN_LOCKOUT | E2E-only — burns a wrong-PIN cycle; compiled out of production |

CMDs 3, 5, 8, 9, 10, 13 are reserved in `proto` but not currently dispatched.

On STM32U585, NSC uses real CMSE `cmse-nonsecure-entry` veneers; on QEMU it's a shared-memory mailbox.

## Wire formats (frozen — on-chain verifier depends on them)

### Unified sign input (NSC + USB)

```
offset  size  field
  0     8    chain_id (u64 BE)
  8     4    flags (u32 BE: bit 31 INCLUDE_INIT_CODE, bit 30 REGISTER_SLOT,
                              bits 29..22 account_index (8b, 0..=255),
                              bits 21..0  slot_index    (22b))
 12    20    sender (PQSmartWallet address)
 32    20    entry_point (EntryPoint v0.6 address)
 52    32    nonce (u256 BE, base nonce for first UserOp in bundle)
 84   5x32   call_gas_limit, verification_gas_limit, pre_verification_gas,
             max_fee_per_gas, max_priority_fee_per_gas (u256 BE each)
244    32    paymaster_and_data_hash (sha256, SHA256_EMPTY when none)
276    20    to_address (inner tx recipient)
296    32    value (u256 BE)
328     2    data_len (u16 BE, 0..=4096)
330     N    data
```

### Unified sign output

```
[new_offchain_count(8 BE)]
[init_code_len(4 BE)][init_code...]      ← 4280 B when FLAG_INCLUDE_INIT_CODE, else 0
[type1_len(4 BE)][type1_wrapper...]      ← 4128 B when FLAG_REGISTER_SLOT, else 0
[type2_len(4 BE)][type2_wrapper...]      ← always 4128 B
```

`new_offchain_count` is the per-slot `local_offchain_count` baked into the Type 2 calldata via `executeWithOffchainCount(...)`. `type{1,2}_wrapper = abi.encode(uint256 ownerIndex, bytes c10Sig)`. `OWNER_BYTES_LEN = 64`, `C10_SIG_LEN = 4008`.

### Off-chain (EIP-1271 / ERC-6492) output

Input header is 17 B (`account(1) | chain(8) | slot(4) | kind(1) | payload_len(2) | flags(1)`); the new `flags` byte at offset 16 carries the EIP-6492 `account_deployed` bit (bit 0). The companion picks the bit by `eth_getCode`-ing the predicted CREATE2 address before calling.

- **`account_deployed = 1` (wallet on-chain):** firmware returns 4016 B = `[new_local_offchain_count(8 BE)][C10 sig (4008)]` — byte-identical to pre-EIP-6492 builds. Companion wraps as `abi.encode(uint256 ownerIndex, bytes c10Sig)` and the dapp calls `wallet.isValidSignature(rawHash, wrappedSig)`.
- **`account_deployed = 0` (counterfactual):** firmware returns 8616 B = `[new_local_offchain_count(8 BE)][ERC-6492 blob(8608)]`. The blob is `abi.encode(address factory, bytes factoryCalldata, bytes signatureWrapper) || EIP6492_MAGIC` (`0x6492…6492`, 32 B). `factory = PQ_SMART_WALLET_FACTORY`, `factoryCalldata = initCode[20..]` (i.e. the exact deploy bytes whose hash is baked into the CREATE2 address), and `signatureWrapper = abi.encode(1, c10Sig)` (ownerIndex 1 = slot 0). The dapp routes the blob through any EIP-6492-aware verifier (Solady `SignatureCheckerLib.isValidERC6492SignatureNow`, Ambire `UniversalSigValidator`, viem `verifyMessage`) which deploys-then-verifies in one `eth_call`. Constraints: `slot_index` MUST be `0` (the factory only seeds slot 0 at deploy); slot 0 is auto-registered (`local=last=0`) on the first counterfactual call to a never-used wallet.

In both modes the wallet recomputes `replaySafeHash(rawHash)` (Solady-nested EIP-712: `(name="PQSmartWallet", version="1", chainId, address(this))`) and verifies. **The firmware — never the companion — performs this `replaySafeHash` nesting, for every off-chain kind.** For `kind = RAW32` the companion sends the dapp's *raw* hash `H` (the value it passes to `isValidSignature`) and the firmware nests it via `aa::eip1271::replay_safe_hash` before signing; for `kind = PERSONAL_SIGN`/`EIP712_TYPED` the firmware likewise nests in S-world. This is a security invariant, not a convenience: the on-chain Type-1/Type-2 UserOp path verifies a *bare* slot/bootstrap C10 sig over a SHA-256 `sphincsDigest`, so a firmware that bare-signed a companion-chosen 32-byte value would be a UserOp-forgery oracle (`raw32(sphincsDigest(drainOp))` → valid Type-2 sig → drain behind a blind page). On-device keccak nesting keeps every off-chain signed value computationally separated from any `sphincsDigest` — equal images would require a keccak-256/SHA-256 cross-preimage (Lean discharges via `keccak_sha256_cross_separation`, an explicit `… ∨ BreaksHash` cross-function assumption, not a structural impossibility) (fixed 2026-06-11; was the pre-fix RAW32 design where the companion pre-nested).

`RAW32` remains intentionally opaque: replay-safe nesting prevents the UserOp-forgery oracle, but it cannot prove how a dapp obtained `H`. A hostile companion can submit the final hash of otherwise-supported typed data as `RAW32` and suppress its semantic pages; the device therefore shows `! BLIND RAW32` plus the complete hash. Companions MUST preserve the dapp-requested method and MUST NOT downgrade typed data to `RAW32`. Disabling `RAW32` in production remains the preferred policy unless an explicit compatibility decision accepts this residual.

### On-chain validation

`PQSmartWallet.validateUserOp` ABI-decodes `SignatureWrapper(uint256 ownerIndex, bytes signatureData)`:

- `ownerIndex == 0` (Type 1): check `bootstrapUses < MAX_BOOTSTRAP_USES`, verify bootstrap C10 sig over `userOpHash`, install slot pubkey at the wrapper's `ownerIndex`, bump `bootstrapUses`, emit `BootstrapKeyUsed`.
- `ownerIndex >= 1` (Type 2): check combined cap `slotUses[i] + offchainSigCount[i] < MAX_SLOT_USES`, verify slot C10 sig, bump `slotUses[i]`, emit `SlotKeyUsed`. The slot's `executeWithOffchainCount(ownerIndex, newOffchainCount, target, value, data)` runs in execution phase: monotonic update of `offchainSigCount[i]` (re-checks cap belt-and-braces) then dispatches the user's call. Does **not** bump `bootstrapUses`.
- `wallet.isValidSignature(hash, sig)` (EIP-1271): `view`-only, nests via Solady EIP-712, dispatches to the same C10 verifier. Returns `0x1626ba7e` / `0xffffffff`. No counter bump. Bootstrap key (`ownerIndex == 0`) **forbidden** here.

## Recovery / Key derivation

One seed → 256 wallets via `account_index ∈ [0, 255]`. Account 0 reproduces the pre-multi-account derivation byte-for-byte.

```
bip39_seed = PBKDF2-HMAC-SHA512(BIP-39(entropy_256), salt="mnemonic", iters=2048)   // 64 B

# Bootstrap master (SPHINCS+C10)
account_index == 0:  master = HMAC-SHA512("sphincs-c6-v1", bip39_seed)
account_index  > 0:  master = HMAC-SHA512("sphincs-c6-v1-acct", bip39_seed || account_index_be4)
masterSkSeed = sha256("sk_seed" || master[..32])
masterPkSeed = sha256("pk_seed" || master[..32]) & N_MASK   // top 16 B kept, bottom 16 zero
(masterSk, masterPkRoot) = c10::keygen(masterSkSeed, masterPkSeed[..16])

# Slot master entropy
account_index == 0:  slot_master = sha256("pqwallet-slot-master" || bip39_seed)
account_index  > 0:  slot_master = sha256("pqwallet-slot-master-acct" || bip39_seed || account_index_be4)

# Per-slot derivation (chain-bound, post-Coinbase-port: slot keys differ per chain)
slot_entropy   = sha256(slot_master || "slot_entropy" || chain_id_be8 || slot_index_be4)
slot_r         = sha256(slot_master || "slot_r"        || chain_id_be8 || slot_index_be4)
slot_sk_seed   = sha256("slot_c10_sk_seed" || slot_entropy)
slot_pk_seed   = sha256("slot_c10_pk_seed" || slot_entropy) & N_MASK
(slotSk, slotPkRoot) = c10::keygen(slot_sk_seed, slot_pk_seed[..16])

# On-chain wallet address (same on every chain, given account_index)
salt = sha256(masterPkSeed || masterPkRoot)            // we control the preimage
addr = CREATE2(factory, salt, keccak256(initCode))     // EVM hashes with keccak256
```

The `"sphincs-c6-v1"` tag is historical (was a different parameter set when written; now C10). **Do not rename mid-bring-up.**

## Build and Test

```bash
make play                    # interactive QEMU (arrow-key UI)
make run                     # non-interactive smoke (QEMU, mock SE)
make e2e                     # automated unified-sign e2e (QEMU)
make e2e-hw                  # e2e on real STM32U585 via probe-rs (see HW gotcha)
make play-hw-display         # interactive NV3007 LCD + arrow-key forwarding
make test-key-speed          # DWT-timed signing bench (no semihosting reads)
make measure                 # build + print 8 BIP-39 measurement words
make saes-self-test-hw       # SAES driver: SW + DHUK round-trip + fingerprint
make optiga-hw-counter-e2e   # provision E120 LUC + drive PIN cycles
make pin-gate-hw-counter-e2e # three-way per-attempt + in-run recovery; no reboot/reconcile coverage
make pin-gate-wipe-e2e       # 10 wrong PINs → assert factory-reset on both SEs
make wipe-for-wizard         # dev-only: wipe both SEs + page 124, halt; cold boot enters wizard
cd contracts/smart-wallet && forge test -vv
cargo test -p sphincs-tz-secure --tests --release
```

**Board targets (`BOARD=`).** Every hardware target builds for one of two physical boards. `BOARD=iota2` (**default**) is the ST B-U585I-IOT02A dev kit, STM32U585AII6 / 169-pin — what every bench flow has always assumed. `BOARD=pq1` is the AL_A66_MB_V10 production board, STM32U585CIU6 / 48-pin UFQFPN, which **bonds only PA0–15, PB0–15 and PC13** (no port D/E/…, and no PB11). `BOARD` sets both the cargo feature and the probe-rs chip name (`STM32U585AIIx` / `STM32U585CIUx`) — e.g. `make test-key-speed BOARD=pq1`. The pin maps live one-per-board in `secure/src/board/{iota2,pq1}.rs` and drivers read constants from there rather than hard-coding a port base.

**Naming a board is MANDATORY on every `stm32u585` build** — `secure/src/board/mod.rs` hard-errors when neither feature is set, and when both are. The earlier "opt-in to pq1, `board-iota2` is inert" model was retracted 2026-08-31: `#[cfg(feature = "board-pq1")] compile_error!` fences are *silent* when the feature is absent, so a recipe that omitted the board compiled the iota2 pin map with every pq1 fence quiet — which is how `build-hw-prodtest BOARD=pq1` came to put iota2 pins on pq1 silicon. `BOARD_FEATURE`/`CHIP` are `override`-derived from `BOARD` so they cannot be detached from each other, and a `FEATURES` board that disagrees with `BOARD` is a hard error.

**Ported:** debug console UART (iota2 USART1/PA9 → pq1 USART2/PA2, AF7 both); the secure-element path (OPTIGA keeps I2C1/PB8/PB9/AF4, SE050 moves to its own **I2C4 on PB6/PB7 AF5** — `board::SE_I2C_BUSES` is the bus *set*, so `i2c_hw` keeps a single `pub fn init`; OPTIGA reset PE0 → PA15; new `hw::se_power` asserts pq1's `LDO2_EN` (PA8) + `SE1_EN` (PB5) before any bus traffic); buttons; USB (pq1 hands only PA11/PA12 to NS — never PA15/PB5/PB15, which are `SE_RST`/`SE1_EN`/`LCM_EN` there); the OPTIGA reset *pulse* (`reset_pin::hard_pulse`, because the live path `pin_diag::run` hardcoded PA4/PD5/PE0 and would have strobed pq1's display CS); the SCA scope trigger (PD2 → PB3); and the **NV3007 LCD** — `spi_hw` + `lcd_nv3007` now derive every pin, the peripheral base and the AF number from `board::LCD_*`. pq1's panel is SPI1 on **PA4 (CS) / PA5 (SCK) / PA7 (MOSI)**, non-contiguous, below pin 8 (so AF nibbles are in `AFRL`, not `AFRH`) and with **no MISO** — PA6, the MISO position, is `NC` on the board. DC/RST/TE/backlight are PB0/PB1/PB2/PB15; pq1 gets a real hardware reset pulse where iota2 uses `SWRESET` (`board::LCD_RST_IS_DRIVABLE`).

`sau.rs` secures I2C4 (SECCFGR1 bit 16) on pq1, plus **UCPD1 (bit 19)** and **TIM2 (bit 0)** on both boards, under exact-equality `const assert!` arms. UCPD1 matters because it is a second handle on PA15/PB15 that `GPIOx_SECCFGR` does not cover; TIM2 because NS could otherwise clear `TIM2_CR1.CEN` and flat-line the production-mandatory consumption mask.

The **consumption mask** is ported too: pq1 runs it on **TIM3_CH1 / PA6 / AF2** because every TIM2_CH1 pin is taken there (PA0 `LEFT KEY`, PA5 the LCD `SCK`, PA15 `SE_RST`), and `sau.rs` secures TIM3 alongside TIM2 so NS cannot stop either. A `selftest_pin_toggles()` samples `IDR` to catch an AF number that is right for the peripheral but wrong for the pin — it passed on pq1 silicon. **What that does NOT establish:** neither board drives a load from the mask pin (iota2's PA5 is unclaimed, pq1's PA6 is `NC`), and a randomised *duty* only modulates power across a resistive load, so the mask's actual dilution is unmeasured on both — see `evt-silicon-validation.md` §9. Production forces this feature, so pq1 can now *build* a shipping image while that security property remains unevidenced; treat the fence as satisfied-by-construction, not demonstrated.

**Still iota2-only, each a loud `compile_error!` rather than a runtime trap:** `boot-pulse` (hardcodes PE13) and `pin-diag-boot` (sweeps the Arduino header and drives PA8 = pq1's SE rail enable). See `docs/hardware/evt-silicon-validation.md` §1–§2 for the verified as-built map. **Trap:** PA8 is the RIGHT button on iota2 and `LDO2_EN` — the enable for the rail powering *both* secure elements — on pq1.

**`make help`** lists the runnable top-level targets (self-documented from the `Makefile`, so it never drifts); **`make -C contracts/verification help`** lists the FV / spec-assurance gates (`verify-*`). The root `Makefile` has ~160 targets total — `make help` surfaces the ones you actually run; read the file for the build/flash variants, fsbl, release packaging, and optiga-reset internals it doesn't surface.

**HW probe-rs gotcha.** `probe-rs` does not implement semihosting `0x07 SYS_READC`. Any `ui-semihosting` PIN prompt on real silicon hangs in the polling loop with a storm of `Target wanted to run semihosting operation 0x7 ...` warnings. This hits `make e2e-hw` because the NS test driver still calls `CMD_REQUEST_UNLOCK` even when `e2e-test` pre-unlocks the secure side. QEMU is unaffected. Workarounds: `make test-key-speed` (no reads, prints `=== PASS ===`) or `make play-hw-display` (arrow keys via probe-rs `print` handshake).

**Timings on hardware — measured, not the old targets (#699).** On pq1, 2026-09-18, `make test-key-speed BOARD=pq1`, with `[S] hash: HW SHA-256 self-test PASS` in the same boot: first sign (type1 + slot keygen + type2) ≈ 14–17 s; Type-2 on a cached slot ≈ 6.4–7.2 s (C10 target-sum grinding spreads single runs by ±1 s or more). The older "first-sign ≤ 3 s / cached ≈ 1.1 s" figures do not match this silicon. Do **not** read a slow sign as "HASH peripheral unused" — first check the boot log for the self-test PASS line.

**HW SHA-256 self-test.** `hw::hash::init_clock()` runs a `SHA-256("abc")` KAT. Look for `[S] hash: HW SHA-256 self-test PASS` early in boot — `FAIL — HALT` parks the CPU in `loop { wfe() }`.

**Targets / profile.** `thumbv8m.main-none-eabi` for both worlds. Release: `opt-level = "s"`, LTO, `codegen-units = 1`, `overflow-checks = true`. `sphincs-c10` / `sha2` / `hmac` always `opt-level = 3`.

## Feature flags

`secure/Cargo.toml` has ~50 flags. Active vocabulary:

- **Backend (mutually exclusive at top level):** `mock-se` · `optiga-trust-m` · `se050` · `dual-se` (implies optiga + se050). (The standalone TROPIC01 backend was removed 2026-07-14 — owner decision; dual-SE only.)
- **Platform / UI:** `stm32u585` (real hardware, implies `hw-sha256`) vs QEMU default. UI: `ui-semihosting` · `ui-lcd` (NV3007 SPI LCD — the only shipping display; the SSD1306 `ui-oled` backend was removed 2026-06-30) · `ui-noop` (silent for headless USB).
- **Mode profiles** (axis aliases): `mode-production` (no debug-log/e2e-test/mock-se) · `mode-bringup` (`debug-log`) · `mode-e2e` (`debug-log`+`e2e-test`+skip flags) · `mode-bench`.
- **Hardening / accelerators (compose):** `saes-dhuk` (Tier-1 KDF) · `saes-self-test` · `tamp` (Trezor-port; log-only by itself) · `tamp-wipe` (production escalation — fires `tzic::trigger_intrusion_wipe` on a confirmed tamper; default-off for bench safety, **forced ON for shipping dual-SE images** by the `nsc/mod.rs` ship-blocker fence alongside `tzic-wipe`) · `consumption-mask` (TIM2 CH1 PWM on PA5; caller must call `randomize()` periodically) · `usb`.
- **OPTIGA hardware counter:** `optiga-hw-counter` (E120 LUC bound to F1D0; immune to PBS extraction; **destructive on first provisioning** — rewrites F1D0 metadata).
- **First-boot self-lock candidate (work-todo #36):** `rdp2-self-lock` (implies `bhk`; **production-only**, forced ON for `mode-production` by the `nsc/mod.rs` S-1-style fence, incompatible with every dev/test feature, requires `dual-se`). Owns the candidate on-device flow in `secure/src/first_boot/`: Phase A verifies the ship option-byte profile + blank per-device pages 123–127 then programs RDP=0xCC (irreversible), Phase B journals a resumable BHK first-write + transport→final rotation of SE050 SCP03/admin + OPTIGA PBS. Absent from every bench/QEMU build (behaviour OFF is byte-identical). Compile-check: `make build-rdp2-self-lock`. This is not production authority; the handoff/recovery/E140-order/silicon gates above remain open. Refs: `docs/provisioning/first-boot-provisioning.md` (candidate responsibility split + field error codes + silicon runbook).
- **Dev / test (NEVER ship):** `debug-log` · `e2e-test` (fixed mnemonic + PIN, short-circuits secure-side `confirm()` **and**, since a8961636, `enter_pin()`, which returns the e2e PIN `00000000`. Before that fix a panel-less board wedged forever in the PendSV idle re-unlock ~120 s after unlock; the fix was validated free-running on pq1 silicon 2026-09-18 across three idle deadlines. Caveat, #692: on these images every PendSV retry goes through `gated_unlock`, so a persistent SE fault burns the whole 10-attempt page-124 budget before the 46a30658 retry guard can fire) · `otp-hardcoded-master-key` (fixed ASCII OTP-master so re-flashed bench boards keep stable admin/SCP03/PBS bytes) · `ui-capture` (SHA-256 of every displayed frame).

CI must gate shipped firmware on `debug-log` / `e2e-test` / `mock-se` / `otp-hardcoded-master-key` / `ui-capture` OFF. The `compile_error!` fences in `nsc/mod.rs` and the `saes-self-test` runner enforce most of this.

## Code Conventions

- `#![no_std]`, no heap, no allocator. Stack-only. No `Vec` / `Box` / `String`.
- `zeroize::ZeroizeOnDrop` on every secret type with compiler fences.
- `subtle` for constant-time compares. No secret-dependent branches.
- Every `unsafe` block has a `// SAFETY:` comment. `#![deny(unsafe_op_in_unsafe_fn)]`, `#![warn(clippy::pedantic)]`.
- **`unsafe` taxonomy.** Five categories that are structurally required and one that is not. **Required:** (1) CMSE `unsafe extern "C"` veneers (TrustZone ABI); (2) NS pointer deref after `NsPtr<T>` validation in `secure/src/nsc/*` — and the same NS-pointer window-check + volatile-copy primitives extracted verbatim into `shared/src/ns_ptr_validate.rs` so they are Kani-proven + Miri-checked host-side (re-exported by `nsc/{ns_ptr,ptr_validate}.rs`); (3) `unsafe extern "C"` SHA-256 hooks consumed by `sphincs-c10` under `hw-sha256`; (4) FI volatile read/write helpers in `secure/src/fi.rs` — plus the FI stack-canary `read_volatile`/`write_volatile` in `pqsigner-erc7730/src/display/render/mod.rs` and double-render transcript-poison writes in `pqsigner-erc7730/src/display/mod.rs` that rode into the host crate with the render dispatch (all must stay `read_volatile`/`write_volatile` to defeat compiler folding; a `black_box` or ordinary-store swap is a silent FI-weakening); (5) `static mut` bookkeeping for the HASH peripheral's 4-byte merge buffer and similar single-threaded driver state. The `.semgrep` `no-unsafe-in-pure-logic-crates` gate excludes exactly those three host-relocated files (allowlist asserted by `make invariant-gates`); any *new* `unsafe` in a pure-logic crate is still a hard error. **Avoidable:** ad-hoc per-register MMIO `read_volatile`/`write_volatile` — funnel each peripheral's registers through `hw::mmio::{Reg32, RoReg32}`, which encapsulates the unsafe once at the address-binding step. UI/log code that materialises ASCII-by-construction buffers must use `crate::ui::ascii_str` rather than `core::str::from_utf8_unchecked`.
- NS pointer validation on every gateway call before any deref. NS buffers copied to S-stack before parse.
- Cross-world types in `shared/src/lib.rs` with `#[repr(C)]`.
- Secret types are `!Copy + !Clone`.
- FI-hardened signing on every Type 1 / Type 2 sig — `crypto::c10_sign_verified*` is a **double-compute → byte-compare → verify-before-release** chain (RFC 9814 §A.2 / Genêt TCHES 2023): sign twice over identical inputs, constant-time-compare the two 4008-B signatures (the *redundant-recomputation* countermeasure — verify-after-sign **alone is insufficient** against SPHINCS+ grafting faults, since a random faulted sig is more likely to still verify than to fail), then verify-before-release, all under an `fi::CfiCounter` 7-step gate with F-2 Hamming-distant sentinels, F-16 DPA shuffle, and fresh 3-source OptRand. Do **not** weaken this to verify-only (a known-insufficient FI gate).

## Key File Map

Pure-logic primitives live in standalone workspace crates so host signers / bench tooling can reuse them without secure-world hardware deps. Secure-side files at the same names are thin re-export shims.

### Workspace crates (pure logic)
| Path | Purpose |
|------|---------|
| `proto/src/lib.rs` | `pqsigner-proto` — protocol constants + enums + wire sizes. Source of truth for Solidity `PqsignerProto` (via `xtask gen-solidity-constants`). Zero deps. |
| `tx-core/src/{eip1559,hash,rlp}.rs` | RLP, EIP-1559 envelope, U256, keccak256. |
| `aa/src/{userop,eip1271}.rs` | EntryPoint v0.6 UserOp hash + Solady-nested EIP-712 PersonalSign. |
| `domain/src/lib.rs` | KDF, AES-GCM wrap, BIP-39 → C10 derivation, slot derivation. |
| `tx/src/{erc20,names,selectors}/` | Merkle-bundle verifiers + ERC-20 calldata decoder. `verify_*_bundle` takes `root: &[u8;32]`. |
| `hal/src/lib.rs` | Trait surface (`Rng`, `Sha256`, `Saes`, `Flash`, `Otp`, `Tamp`, `ConsumptionMask`, `I2cBus`, `SpiBus`, `Buttons`, `Uart`, `Platform`, `BootStage`). Driver impls deferred. |
| `shared/src/lib.rs` | Cross-world `#[repr(C)]` types, `NscStatus`, CMD constants. |
| `sphincs-c10/` | C10 signing — `SigningKey::keygen/sign`, `verify`, hypertree, wots, fors, merkle, address, hash, params. |
| `bip39/` | 24-word English BIP-39 (no_std). |
| `pqsigner-erc7730/src/{ir,walker,bundle,binding,abi}.rs` | ERC-7730 clear-signing — IR parser, path walker, Merkle bundle verifier, `(chain_id, contract, ds)` binding cross-checks. Host-runnable; firmware re-exports via `secure/src/tx/erc7730.rs`. |
| `pqsigner-erc7730/src/display/{mod,primitives}.rs` + `display/render/{mod,formatters,intent,nested,calldata_nested}.rs` | Shared display substrate (`Pages`/`MAX_PAGES`/`ascii_str` + byte-writer primitives) **and the full ERC-7730 renderer** (intent banner + 15 FormatOp dispatchers + nested-EIP-712/calldata descent) — moved here 2026-07-04 so the render dispatch is host-linkable/fuzzable/Kani-provable. |
| `pqsigner-erc7730/src/render/{params,visibility,resolve,array,enums}.rs` | TLV parameter parser, visibility evaluator (`should_render_with_mode`), path/offset resolvers — the Kani-proven pure half of the renderer. |

### Secure world
| Path | Purpose |
|------|---------|
| `secure/src/main.rs` | Entry: SAU → RCC → SAES self-test → provision → unlock → boot NS. |
| `secure/src/sau.rs` | SAU + GTZC config (TZSC enforcement silicon-validated 2026-05-20; only TAMP/GTZC2 follow-up open — see Pre-Production Caveats). |
| `secure/src/crypto.rs` | Re-export shim over `pqsigner-domain` + FI-hardened `c10_sign_verified*` + `WalletStore`-bound `provision_from_mnemonic` / `store_macd_encrypted`. |
| `secure/src/aa/mod.rs` | Re-export shim over `pqsigner-aa`. |
| `secure/src/tx/mod.rs` | Re-export shim over `pqsigner-tx-core` + display + EIP-712. |
| `secure/src/tx/display/*` | Trusted-UI page renderers (value transfer, ERC-20 known/unknown, contract creation, slot rotation, blind sign, batch, EIP-1271, Safe, typed_call). |
| `secure/src/tx/display/erc7730/mod.rs` | Re-export shim over `pqsigner_erc7730::display::render` (the renderer moved to the host crate 2026-07-04; `pick_sign_pages` stays in `tx/display/mod.rs` and calls the host entry). |
| `secure/src/tx/display/erc8213.rs` | ERC-8213 fingerprint pages (2-page banner + full 32-byte hash). |
| `secure/src/tx/erc7730_render/mod.rs` | Re-export shim over `pqsigner_erc7730::render` (params/visibility/resolve/array/enums + `RenderErr`). |
| `secure/src/tx/erc7730.rs` | Re-export shim over `pqsigner-erc7730` + the firmware-pinned `ERC7730_DESCRIPTORS_ROOT`. |
| `secure/src/tx/eip712/{cowswap,safe}/` | EIP-712 typed-data verifiers (test vectors + verify). |
| `secure/src/tx/typed_call/{abi,parser}.rs` | Solidity ABI typed-call parser. |
| `secure/src/{erc20,names,selectors}/mod.rs` | Re-export shims over `pqsigner-tx`; pass `crate::db_roots::*`. |
| `secure/src/db_roots.rs` | Compiled-in Merkle roots for trust-bundles. |
| `secure/src/fi.rs` | FI helpers: sentinel patterns + double-checked verify. |
| `secure/src/timeout.rs` | S-only TIM-driven inactivity timeout (NS pings do NOT reset). |
| `secure/src/offchain_state.rs` | Page-123 log-structured per-slot off-chain counter store + compaction. |
| `secure/src/dual_se.rs` | XOR entropy split; admin-wipe coordination. |
| `secure/src/measured_boot.rs` | Boot SHA-256 → 8 BIP-39 words on the NV3007 LCD. |
| `secure/src/fw_update/{staging,verify}.rs` | Streaming state machine BEGIN → CHUNK* → COMMIT. |

### NSC gateway
| Path | Purpose |
|------|---------|
| `secure/src/nsc/mod.rs` | Dispatcher + `gated_unlock` (page-124 attempt counter, FI-hardened pre-commit). |
| `secure/src/nsc/state.rs` | `SecureState` singleton: `pin_verified`, `master_secret`, `SLOT_CACHE` keyed on `slot_index`. |
| `secure/src/nsc/cmd_sign_userop.rs` | **Unified Type 1 / Type 2 sign handler** (1241 lines). |
| `secure/src/nsc/cmd_sign_userop_batch.rs` | Atomic multi-UserOp sign (766 lines). |
| `secure/src/nsc/cmd_sign_offchain.rs` | EIP-1271 sig + per-slot off-chain counter bump. |
| `secure/src/nsc/cmd_offchain_status.rs` | Per-slot counter readback. |
| `secure/src/nsc/cmd_request_unlock.rs` | PIN entry + dual-SE unlock. |
| `secure/src/nsc/cmd_get_wallet_address.rs` | CREATE2-predicted proxy address. |
| `secure/src/nsc/cmd_get_init_code.rs` | Pre-computed 4280-B `initCode`. |
| `secure/src/nsc/cmd_fw_*.rs` | Five firmware-update handlers. |
| `secure/src/nsc/cmd_test_pin_lockout.rs` | E2E-only wrong-PIN burner. |
| `secure/src/nsc/{ptr_validate,ns_ptr}.rs` | NS pointer validation; `NsPtr<T>` typestate yielding `ReadPtr<T>` / `WritePtr<T>` proofs. |

### Secure elements
| Path | Purpose |
|------|---------|
| `secure/src/optiga/{mod,ifx_i2c,apdu,shield,i2c}.rs` | OPTIGA Trust M driver (4-layer IFX I2C + Shielded Connection). OIDs: `0xE140` PBS, `0xE120` LUC, `0xF1D0` AuthRef, `0xF1D1` half_O, `0xF1D2` master, `0xF1D3` VK, `0xF1D4` bootstrap VK. E120 binding under `optiga-hw-counter`. |
| `secure/src/se050/{mod,scp03,apdu,t1oi2c,i2c}.rs` | SE050 driver (T=1' + SCP03 + UserID PIN). Admin UserID `max_attempts=0`; current OID range `0x7B0C_*`. |

### UI / hardware drivers
| Path | Purpose |
|------|---------|
| `secure/src/ui/{mod,lcd,semihosting,noop,capture,confirm,pin_entry,seed_wizard,secret_text}.rs` | `pub trait Ui` + backends (`lcd` = NV3007; the SSD1306 `oled` + RTT `mirror` backends were removed 2026-06-30). `confirm`/`pin_entry`/`seed_wizard` are the trusted-path dialogs. |
| `secure/src/hw/mmio.rs` | Typed `Reg32`/`RoReg32` MMIO handles. Encapsulates `unsafe { read_volatile/write_volatile }` once per address so peripheral drivers expose safe `.read()`/`.write()`/`.modify()` APIs. |
| `secure/src/hw/hash.rs` | STM32U585 HASH peripheral; `pqsigner_sha256_*` extern fns consumed by `sphincs-c10` under `hw-sha256`. Uses `mmio` for register access. |
| `secure/src/hw/saes.rs` | SAES driver (AES-256-ECB) under `KEYSEL ∈ {Software, DHUK, BHK, DHUK^BHK}`. |
| `secure/src/hw/saes_cmac.rs` | `cmac_dhuk(msg) -> tag` thin SAES adaptor. |
| `secure/src/hw/secret_keys.rs` | Current per-purpose key API. Factory transport SCP03/admin/PBS credentials derive from the factory-burned per-device OTP master. The candidate final OPTIGA PBS derives from DHUK plus the persisted TRNG salt; final SE050 SCP03/admin credentials derive from BHK. Explicit dev/legacy configurations use hardcoded or deterministic fallback roots. The first-boot implementation remains production-quarantined pending its named handoff, recovery, silicon, and ordering gates. |
| `secure/src/hw/otp.rs` | Rejected legacy unary rollback tally (bench-only, production-fenced) + device-master/factory legacy OTP regions. Draft 1.1 is a research candidate for the replacement typed floor API; its implementation, physical codec, ECC, interruption, and durability gates remain open. |
| `secure/src/hw/flash.rs` | Bank-2 writes, ICACHE invalidate, `pin_attempts_{read,bump,reset}` on page 124, admin-page (125) wipe-flag. |
| `secure/src/hw/tamp.rs` | TAMP (Trezor-port). Log-only by default; under `tamp-wipe` (production) escalates to `tzic::trigger_intrusion_wipe`. |
| `secure/src/hw/consumption_mask.rs` | TIM2 CH1 PWM on PA5, randomised duty cycle. |
| `secure/src/hw/uart.rs` | USART1 VCP (GPIOA AF7), used by SAES RDP1 self-test + dev logging. |
| `secure/src/hw/boot_state.rs` | Legacy try-once page (nonfunctional for the promised rollback contract and production-fenced). Draft 1.1 proposes replacement marker/journal interfaces but is not implementation-approved. |
| `secure/src/hw/{rcc,rng,usb_hw,buttons,spi,spi_hw,i2c,i2c_hw,i2c2_probe}.rs` | Bare-metal peripheral drivers. |

### Non-secure world / host tools
| Path | Purpose |
|------|---------|
| `nonsecure/src/main.rs` | NS entry (USB or interactive demo). |
| `nonsecure/src/nsc_api.rs` | NS-side gateway caller. |
| `nonsecure/src/usb/{commands,hid,transport}.rs` | APDU v2 router + USB HID. |
| `nonsecure/src/e2e_test.rs` | Non-interactive end-to-end test runner. |
| `fwmeasure/` | Host firmware measurement tool. |
| `fw-manifest/` | Legacy v0x02/PQFW_V1 manifest + verify chain (bench only). Draft 1.1 proposes manifest-v6/`PQFW_V6` with a 121-byte signed preimage; it is neither implemented nor implementation-approved. |
| `fwsign/` | Legacy bench release-signing CLI; production packaging is quarantined pending candidate approval and backend closure. |
| `fsbl/` | Legacy bench bootloader. It is not yet an immutable production trust root. The frozen 40-KiB registry (pages 0..4) landed as `pqsigner-geometry`; this crate still links against the legacy 32-KiB region, cutover #540. Carries the tz-1 option-byte read-back tripwire (`optbytes.rs`): reads only, halts on a persistent mismatch. The physical FLASH LOAD-span gate is CLOSED and the stack is bounded (`scripts/check_fsbl_geometry.py`, run by `make fsbl`); the WRP/option-byte ceremony and a call-graph worst-case stack remain OPEN. |
| `dbgen/` | Merkle-DB builder (ERC-20 / names / selectors / ERC-7730 descriptor roots). |
| `xtask/` | Host workspace tooling — codegen, doc-checks, release packaging. |
| `tools/webhid_test.html`, `tools/wallet_run_hw.py` | Browser companion + probe-rs arrow-key forwarder. |

### Contracts
| Path | Purpose |
|------|---------|
| `contracts/smart-wallet/src/PQSmartWallet.sol` | ERC-4337 v0.6 account behind ERC-1967 proxy; `validateUserOp` dispatches on `ownerIndex`. EIP-1271 via Solady (nested EIP-712, ERC-6492). |
| `contracts/smart-wallet/src/PQSmartWalletFactory.sol` | CREATE2 factory; `createAccount` requires bootstrap C10 sig over `addSlot0Digest(chainId, slot0PkSeed, slot0PkRoot)` (squat-defence). |
| `contracts/smart-wallet/src/PQMultiOwnable.sol` | ERC-7201 storage: `ownerAtIndex`, `bootstrapUses`, `slotUses[i]`, `offchainSigCount[i]` + bumps. |
| `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol` | Stateless Yul C10 verifier (SHA-256 precompile). Single immutable reused for Type 1 / Type 2 / EIP-1271. |
| `contracts/smart-wallet/src/verifiers/ISPHINCSVerifier.sol` | Verifier interface (test/prod swap). |

## What NOT to do

- **No classical signer** anywhere — firmware, contract, FW-update path. One algorithm in the wallet, one in the FSBL. No "just-in-case" fallback.
- **No secrets in NS world.** Not even temporarily.
- **No software PIN compare** — SE silicon only.
- **No plaintext secrets on I2C / SPI** — always Shielded Connection / SCP03 / Noise_KK1.
- **No full entropy on a single chip** — each SE gets one XOR half.
- **No heap.** Stack only. No `Vec` / `Box` / `String`.
- **No software PRNG for secret or signature-reaching randomness** — BIP-39 entropy, seeds, signing keys, PIN material, SE handshake/session keys, OptRand, and every value that enters a signature, a KDF, a tunnel key or an on-chain artifact MUST come from the hardware TRNG (`rng::byte` / `rng::fill`, which fail loudly) or `rng_strong` — STM32 TRNG, or semihosting `/dev/urandom` on QEMU. **Narrow carve-out, non-secret countermeasure parameters only** (2026-10-08, after the research below): the *length* of an FI delay (`fi::wait_random`, and any future always-on RDI, #805) and the PWM duty of the consumption mask MAY be served from a hardware-TRNG-seeded deterministic generator, subject to **all** of: (a) seeded and reseeded only from the hardware TRNG under a documented bounded policy, failing loudly — never a fixed constant; (b) effective internal state ≥ 246 bits (BSI AIS 20/31 v3.0 DRG.2.3/3.3/4.3 class text) with the state treated as a secret — secure-world SRAM only, zeroized on lock/tamper/brownout, never reachable over NSC, seed *and* algorithm integrity- and confidentiality-protected (JIL v3.2.1 §182); (c) the instance serves that one parameter and nothing else — a second consumer voids the carve-out, which is also why such a generator must NOT live in `rng.rs` (the `negative_no_software_prng_seed_in_rng_module` gate keeps the secret path absolute); (d) the degraded path (contention, reseed failure, buffer miss) is bounded, loud, documented, and NOT the dominant path, with a **measured** fallback rate in the evidence record; (e) no approved/certified-RNG claim attaches — a ChaCha DRBG is not one of SP 800-90A's three mechanisms, so it is a non-approved algorithm with no security claimed; (f) the FSBL's deterministic delay stub is covered by the same rule or recorded as a known contract-vs-code gap.

  **Why this is scoped rather than absolute, and what the evidence does and does not say.** The absolute form was stricter than every certification scheme examined — *including for key material* — while the code already contained an undocumented instance of exactly this pattern (`hw/consumption_mask.rs` seeds an xorshift32 from the platform TRNG for PWM duty, reseeded ~1 s, fail-closed; its gate calls it "deliberate and documented… NOT a key-derivation RNG"). A 111-agent research pass (2026-10-08) established: **REQUIRED — nothing.** FIPS 140-3, the CMVP IG, SP 800-90A/C, CC/JIL and PP-0084 are *measurably silent* on countermeasure-timing randomness (zero occurrences of "random delay", "jitter", "desynchron", "dummy", "shuffl" across ~600 KB, with negative controls; FIPS 140-3's non-invasive sections are bare divider pages and SP 800-140F §6.2 reads "No additional requirements at this time"). Where the schemes *do* speak, a TRNG-seeded DRBG is the **normative construct, not a deviation**: every SP 800-90C RBG class contains a DRBG, CMVP IG C.H *requires* an approved DRBG for random IVs, AIS 20/31 calls DRG.3 suitable for all cryptographic applications bar those needing guaranteed fresh entropy, and an EAL6+ secure element (Goodix GSE20) ships a software DRG.3 as an evaluated function. **The counterweight, which is why the conditions above are not optional:** CC/JIL names DPA/SPA countermeasures among the consumers broken by an RNG attack and grants them **no lower tier** — "it is only a countermeasure" is supported by no source. **What is NOT established:** the research's sub-questions on threat-model quantification and on documented failures produced **zero** surviving claims, and the premise that DRBG output is indistinguishable from per-call TRNG bytes to an attacker who cannot read SRAM was **refuted 0–3**. Comparable-product practice was confirmed for **one** vendor (Trezor). So this carve-out rests on an *a fortiori* argument from certification practice — owner judgement on 2026-10-08, not a proven security equivalence. Re-run it if SP 800-140F is ever populated. Full evidence, citation corrections and amendment targets: #805.
- **No casual KDF tag changes** (`"sphincs-c6-v1"`, `"sphincs-c6-v1-acct"`, `"pk_seed"`, `"sk_seed"`, `"pqwallet-slot-master"`, `"pqwallet-slot-master-acct"`, `"slot_entropy"`, `"slot_r"`, `"slot_c10_sk_seed"`, `"slot_c10_pk_seed"`). Account 0 must keep the original tags for cross-developer reproducibility.
- **No skipping verify-before-release** on Type 1 / Type 2 sigs.
- **No `rotateMasterKeys` / `resetBootstrapUses` / `resetSlotUses` / `increaseMax*`** in wallet or factory.
- **No EntryPoint v0.7 / v0.8 migration.** v0.6 is the frozen target. Its address and ABI are baked into `initCode`, the userOpHash preimage, and the factory; bumping the version would change the CREATE2 init-code hash and break invariant #6 (cross-chain address stability). If v0.6 bundlers are ever sunset, fall back to direct EOA-bundled execution against the same wallet — do not redeploy.
- **No new per-signature flash state** beyond the page-123 EIP-1271 counter.
- **NS does not control the inactivity timer** — only S-world button presses on confirm dialogs reset it.
- **No `debug-log` / `e2e-test` / `mock-se` / `otp-hardcoded-master-key` / `ui-capture` / `legacy-fw-rollback-unsafe`** in production builds. CI must gate.
- **Rollback manifest work is not implementation-approved.** Draft 0.9's V4/80-byte format is a preserved historical reference. Draft 1.1 proposes the exact 121-byte `PQFW_V6 || schema || physical_slot || release_version || security_epoch || secure_image_length || nonsecure_image_length || secure_image_hash || nonsecure_image_hash || vendor_key_fingerprint` preimage, but remains a research/review candidate with open backend, resource, ECC, release-policy, and silicon gates. Do not treat either layout as current implementation authority. Adoption or any schema change requires an exact approved specification digest, the required dual review, and an owner stage decision.
- **No "reset rollback floor" path.** OTP is one-way by design.
- **No runtime writes to the eventual approved FSBL range.** The current
  pages-0..3/32-KiB layout is legacy bench-only; Draft 1.1 proposes pages 0..4
  but leaves geometry, both-bank protection, factory, and silicon gates open.

## External review models (adversarial review / planning / advisory)

Two **non-Claude** models are wired on this box and may be used freely for **adversarial review, design
critique, planning, and advisory** roles — especially on FV/crypto-modeling decisions, before committing to a
multi-session approach, and as a second opinion on any claim you are about to bank as fact.

| Model | How to invoke | Notes |
|-------|---------------|-------|
| **GPT-5.6** | `mcp__codex__codex` MCP tool — pass `prompt`, `cwd`, `sandbox: "read-only"`, `approval-policy: "never"` | Agent with repo access; reads files itself. Long reviews get backgrounded (>120 s) and notify on completion. |
| **Kimi K3** | CLI: `export PATH="$HOME/.kimi-code/bin:$PATH"; kimi -p "<prompt>"` (run from the target repo) | **NOT an MCP.** `--auto`, `--yolo`, and `--plan` are each INCOMPATIBLE with `-p` (hard error). Agent with repo access; verbose — redirect to a file and read the tail. Very long runs: use `run_in_background`. |

**How to use them well** (learned 2026-07-19, when they jointly killed an unsound EasyCrypt reduction design
before it cost multiple sessions):

- Give them the **file paths and line numbers** and tell them explicitly to *read the actual code, not trust
  your summary* — their value comes from checking your framing against source.
- Ask them to **attack a specific decision**, state the failure mode you most fear, and demand a prioritized
  list of holes + a recommended action + "where is my read too optimistic". Vague "review this" wastes them.
- Say **"do not modify any file"** (both are agents and will edit if allowed), then `git status` afterwards.
- **Run both and compare.** Convergence on a disqualifier is strong evidence; divergence is where the real
  information is (in the 2026-07-19 review both found the same fatal flaw, but only one found the better fix,
  and only the other found the deeper foundations problem).
- **Verify their load-bearing citations yourself** before acting — treat their output as a lead, not a fact.

The `advisor` tool (stronger Claude reviewer, sees the full transcript) is complementary: use it for
calibration/honesty-of-claims and approach selection; use GPT-5.6 / Kimi K3 when you need an *independent*
model to check domain reasoning against the source.

## Work tracking

Action tracking lives on **GitHub Issues** (repo `EthereumPhone/PQ1`). `docs/work-todo.md` and `docs/production-todo.md` were retired 2026-07-19: their open items were migrated to issues labelled `source:work-todo` / `source:production-todo` (plus `priority:*`, `surface:*`, `ship-blocker`), and the full pre-migration content is archived at `docs/archive/work-todo-retired-2026-07-19.md` and `docs/archive/production-todo-retired-2026-07-19.md`. After completing implementation tasks, close the matching issue with the evidence (commit, tests, receipts) in the close comment. Historical `work-todo #N` / section references in this and other docs resolve through the archive copy.

**Docs hygiene — amend, don't duplicate.** Before creating a new doc, `grep`/`find` over `docs/` + `contracts/verification/docs/` (and the "Deep-dive docs" list below) for one that already covers the topic and update *that* instead. This repo has many overlapping docs (`STATUS.md`, `FV_VALUE_AND_GAPS.md`, `THE_CLAIM.md`, the `docs/*-sota-*.md` surveys, per-subsystem status/postmortem files), and a parallel new doc almost always duplicates an existing one and drifts stale. Prefer additive dated `UPDATE <date>` notes + a snapshot-date bump over rewriting (preserves the honest history the FV docs depend on). Create a new doc only when no existing one fits the scope.

## Deep-dive docs

- `README.md` — full architecture, threat model, shipping checklist
- `docs/architecture/architecture.md`, `docs/security/HARDENING.md`, `docs/firmware/firmware-update.md`, `docs/firmware/reproducible-builds.md`
- `docs/secure-elements/se050-userid-pin-auth.md`, `docs/secure-elements/optiga-bringup-status.md`, `docs/secure-elements/optiga-brick-postmortem.md`
- `docs/companion/companion-app-integration.md`, `docs/companion/companion-batch-sign-integration.md`, `docs/companion/usb-protocol-v2.md`
- `docs/archive/handoff-modularity-refactor.md` — workspace-crate extraction phases
- `docs/archive/handoff-unsafe-reduction.md` — per-peripheral migration of MMIO `read_volatile`/`write_volatile` to `hw::mmio::{Reg32, RoReg32}`; queue + footguns + irreducible categories
- `docs/hardware/dev-board-setup.md`, `docs/hardware/hardware_requirements.md`, `docs/architecture/trezor-comparison.md`
- `docs/secure-elements/se050-stress-harness.md` — `make se050-stress*` on-silicon stress runner; how to run, read output, add a test, and the S-5/S-6 silicon verifiers



### From `docs/security/HARDENING.md`

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
| Pixel trusted UI (`ui-px`, `ui::px::confirm_px` / `px::lcd::run_flow`; every sign dialog since port step 3, 2026-09-23 — `forced_blind` excepted) | **only after the LAST screen has been painted** (scroll-to-end, `PX_COMMIT_REQUIRES_SEEN_LAST = true`), and then only on the opening ask, the auto-inserted `Confirm?` (6th screen when ≥ 7 details) or the returning ask; **never on a detail** | owner decision **2026-09-24** (see the UPDATE below), superseding 2026-09-22 |

**UPDATE 2026-09-23 (port plan step 3):** the pixel path now carries every
sign dialog — Safe, every single-UserOp route, the slot-rotation consent,
direct CoW, ERC-7730, the off-chain kinds (typed, `personal_sign`, RAW32) and
each batch member plus the batch's final ask — so the row above applies to
all of them under `ui-px`. `forced_blind` keeps its own ceremony; the legacy
row still governs every build without `ui-px`.

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

**SUPERSEDED 2026-09-24 — see the UPDATE below. The paragraph is kept because
the mitigations it lists are still real, and because the reasoning that was
accepted and then reversed is worth preserving.** ~~The pixel path
intentionally re-opens the class the 2026-06-26 fix closed for that path only:
a user can sign from the opening ask without paging through the details.~~
Mitigations the design supplies: declining is armed on every
screen (hold-left), the `Confirm?` early exit sits after five detail screens,
the returning ask is the demo's canonical hold point, and every value the
legacy pages showed is present in the transcript (host fact differential in
`safe_screens_render_pure_tests.rs`). The arming flag is a `FihBool`
re-derived from the record's `commit` byte (double read) on every screen
change; the `OK_SENTINEL` is minted at exactly one site.

**UPDATE 2026-09-24 — REVERSED, by owner decision: the gate is ON.**
`secure/src/ui/px/confirm_px.rs::PX_COMMIT_REQUIRES_SEEN_LAST` is now `true`.
Owner, asked directly whether the pixel path should still require paging past
the recipient and the amount: *"all screens should be viewed before the user
can sign."*

The concrete case that decided it: an ERC-20 transfer is EIGHT screens
(`tx::display::erc20_known`). The opening screen says "Send USDC"; the
RECIPIENT is screen 3 and the AMOUNT is screen 4. With the gate off, one chord
click on the opening ask approved a transfer whose destination and value had
never been displayed. The mitigations listed above (decline armed everywhere,
the `Confirm?` early exit after five details, the values present in the
transcript) are real but none of them puts the recipient in front of the user.

The evidence is a real paint, not an index: `FlowDriver::mark_rendered` is
called by the presenter immediately after `build_and_present` (`px/lcd.rs`) and
after `text::present` (`confirm_px.rs`), and sets `seen_last` only when
`cur + 1 == count` — the same "evidence of display, not merely an index
assignment" rule `confirm_core.rs` states for the legacy path. As this section
already noted, the loop maintains `seen_last` either way, so the constant was
the only change needed.

The two paths now AGREE, and `fsbl-tests/tests/paired_constants.rs` pins them
so they cannot drift apart silently again.

RESIDUAL, not closed by this change: on the legacy path `seen_last` is a
`FihBool` (complement pair + double read); on the pixel path it is a plain
`bool` feeding the `FihBool` arming flag. A stuck-at fault on the pixel
`seen_last` would defeat scroll-to-end without defeating arming. Worth
hardening; tracked separately.

Do not re-litigate without new evidence; record any change here and in
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

- **TRNG**: for all nonces, challenges, and every value that is secret or reaches a signature. Audit that `rand_core` is wired to this, not to a software PRNG. **This line used to read "any randomness", which contradicted its own sibling in §"RNG" below ("Never a software PRNG *for secrets*") and did not match the code** — `hw/consumption_mask.rs` has always seeded an xorshift32 from the platform TRNG for PWM duty. Both are now scoped the same way, and the one narrow exception for non-secret countermeasure parameters, with its six mandatory conditions, is stated once in `CLAUDE.md` § "What NOT to do" rather than restated here (see #805).
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



### From `docs/security/brownout-hardening.md`

# Brownout & Glitch Hardening — Design + Roadmap

## Why this document exists

A hardware wallet that can lose power mid-operation at any moment must be
designed so that *every possible point of interruption* leaves the device
in a recoverable state. Today PQSigner OS has one targeted crash-safety
mechanism (the wipe-in-progress flag at flash page 125 QW 1) which we
validated end-to-end. Everywhere else, we depend on the chip happening
to not lose power during critical multi-step sequences. That's not good
enough for a production device that stores transaction-signing seeds.

This document defines the failure classes we need to tolerate, catalogues
what the STM32U585 silicon provides for free, audits what we currently
don't use, and lays out a **5-stage rollout** that turns brownout
robustness from "mostly-OK-by-accident" into a measurable property.

## Threat taxonomy

"Brownout" means Vcc sags or collapses at an arbitrary instant during
execution. The failure classes that matter for a wallet, from most to
least catastrophic:

| Class | Event | Today's behaviour |
|---|---|---|
| **A. Torn flash QW** | 128-bit quad-word program interrupted mid-flight. Some bits committed, others indeterminate; ECC may flag on read. | Undetected. `write_quadword` returns Ok if the error flags didn't set, regardless of whether the bytes actually landed correctly. |
| **B. Partial page erase** | 8 KB page erase aborted mid-sweep. Cells partially erased. | Undetected. Next read returns unpredictable mix. |
| **C. Multi-QW write window** | Between QW0 and QW1 of a 32-byte write, Vcc dies. Half-good, half-blank on reboot. | Undetected. No CRC, no length, no magic — readers trust raw bytes. |
| **D. SE050 mid-APDU** | I2C dies during an SCP03 command. SE050 NVM is APDU-atomic but we don't verify post-hoc. | Silent state drift: firmware thinks delete succeeded, object still on chip. |
| **E. Dual-SE ordering** | STM32 wipes one secure element, then Vcc dies before the other secure-element wipe completes. | Partially covered by the wipe-in-progress flag, but the flag does not encode which SE operations completed. There is no PBS flash page to erase. |
| **F. SRAM residue** | Abnormal reset before panic handler runs. Secrets linger in SRAM1 retention until next power-on. | `panic_handler` zeroizes, but any reset path that skips it leaves SRAM intact. No boot-time sanitization. |
| **G. Half-flashed firmware** | OTA / DFU interrupted by brownout. Firmware partially programmed. | Out of scope for this doc — addressed by the separate measured-boot + signed-update work (work-todo.md items 14-16). |
| **H. Option-byte write** | Can brick the chip if interrupted or mis-sequenced. | Current runtime performs none. The only planned exception is the still-unimplemented, owner-gated first-field RDP2 self-lock; it needs its own cut-safe ceremony and sacrificial evidence. |

Current design addresses **E partially** (wipe flag) and **F partially**
(panic handler zeroize). Everything else is unmitigated.

**Cross-references to the 2026-04-14 deep-research round** (see
`docs/security/production-security.md` for the full synthesis):

- Bundle A (fault injection) confirms: **BOR/IWDG/ECC/TAMP factory
  defaults are directly attackable**. Masaryk U 2024/2025 thesis
  (Simonik) demonstrated 76% PIN-glitch bypass on STM32U5A9 — same
  core family as our U585. Our Stage 2 plan is now a must-ship, not
  a nice-to-have.
- Bundle A also surfaces: **SLH-DSA verify-after-sign is insufficient**
  per RFC 9814 + Genêt TCHES 2023. A single fault during signing
  produces a signature that often still verifies. Double-compute on
  disjoint SRAM is mandatory. Tracked on `EthereumPhone/PQ1` (label
  `source:work-todo`, item #18), not in this doc (out of brownout scope).
- Bundle C surfaces: **we are currently signing with OptRand = 0**.
  That enables PRF(SK.seed) horizontal-DPA recovery in few traces.
  Fresh TRNG per signature required. Tracked in #18.
- Bundle D surfaces: **DWC2 has silicon errata** (TxFIFO write
  atomicity + ZLP race data-leak) that brownout-adjacent reset paths
  can trip into. Tracked in #19.

## Target board: B-U585I-IOT02A

This roadmap is written against the STMicro B-U585I-IOT02A Discovery
kit. Chip is **STM32U585AII6Q** (LQFP144, 2 MB flash, 786 KB SRAM in
four blocks, full peripheral set). Details that affect the plan:

| Feature | B-U585I-IOT02A state | Implication |
|---|---|---|
| **CR1220 battery holder (VBAT)** | **Present but unpopulated by default** on the dev board. Production hardware will use a **0.47 F–1 F supercapacitor** instead — see "VBAT power source" below. | Dev board needs either a CR1220 installed OR a supercap tack-soldered to the holder pads with a Schottky from Vdd. Stage 4 works either way. |
| NRST user button (B2) | Wired directly to MCU NRST pin | "One level more thorough than `probe-rs reset`" option for tests. Still does not cut SE050 Vcc. |
| LSE 32.768 kHz crystal | Present | Enables `LSE` for RTC and IWDG timing. LSI-clocked IWDG works fine without it — LSE is a "nice to have" for accurate timekeeping. |
| On-board ST-LINK V3 | Integrated | `probe-rs reset` uses SWD SYSRESETREQ. Does NOT interrupt USB Vbus → SE050 shield stays powered across reset. True cold cycle requires unplugging USB. |
| On-board STSAFE-A110 | Present, I2C2 bus | Currently unused by this firmware (only the `stsafe-probe` feature detects it). Not in scope for brownout work. |
| OM-SE050ARD-E shield | Arduino-header mounted | SE050 powered from shield's 5V pin which is fed by USB. Any full-power-cycle test must disconnect USB; any warm reset keeps SE050 alive. |

### STM32U585 SRAM layout & integrity

The four SRAM blocks have different integrity capabilities. Relevant to
every stage of this plan:

| Block | Size | Secure alias | ECC-capable | Parity | Notes |
|---|---|---|---|---|---|
| SRAM1 | 192 KB | `0x3000_0000` | Yes (single-bit correct, double-bit detect) | — | Main SRAM, currently hosts nearly all our state. |
| SRAM2 | 64 KB | `0x3003_0000` | Yes (option byte `SRAM2_ECC`) | Optional (mutually exclusive with ECC) | Target for Stage 2 secret relocation. Option byte `SRAM2_RST=0` makes silicon auto-erase this on every *system* reset (BOR, pin, SW, IWDG, WWDG, OBL — not standby wakeup). |
| SRAM3 | 512 KB | `0x3004_0000` | Yes (option byte `SRAM3_ECC`) | — | Unused today. Biggest block. |
| SRAM4 | 16 KB | `0x3800_0000` | No | Yes (unverified) | SmartRun domain; retained through Stop 2. |
| Backup SRAM | 2 KB | **`0x4003_6400`** (NS) / `0x5003_6400` (S) | Yes (option byte `BKPSRAM_ECC`) — **32-bit ECC** per AN5342 | — | VBAT-retained; auto-wiped on any TAMP event. |

### How SRAM ECC actually works on U5

**Correction from an earlier version of this doc:** ECC on SRAM2, SRAM3
and Backup SRAM is **NOT always-on.** It is configurable per-block via
the option bytes `SRAM2_ECC`, `SRAM3_ECC`, `BKPSRAM_ECC`. AN5342
describes this explicitly: ECC is "configurable for each SRAM block
individually" and "enabled or disabled by the control bits in the OB
space." Factory default is **disabled** on the user-configurable
blocks. The datasheet's line "786-Kbyte SRAM with ECC OFF or 722-Kbyte
SRAM including up to 322-Kbyte SRAM with ECC ON" quantifies the
tradeoff (each ECC-enabled block loses storage to parity bits).

**SRAM1 ECC** is part of the block's definition — cannot be disabled,
always active. Single-bit flips on SRAM1 are silently corrected today
regardless of firmware configuration. That's the only ECC we get for
free right now.

**Everything else** (SRAM2, SRAM3, Backup SRAM) requires an explicit
option-byte write during provisioning to even activate ECC — and then a
runtime config via RAMCFG to route uncorrectable errors somewhere useful:

- `RAMCFG_MxCR.ECCIE` — enable ECC-error interrupt signalling for the block.
- `RAMCFG_MxIER.ECCSEIE` — route single-bit corrections to an
  interrupt. Usually left disabled (already corrected; flooding an ISR
  with every cosmic-ray hit is noise). Stage 2 wires a counter into a
  backup register instead.
- `RAMCFG_MxIER.ECCDEIE` — route double-bit detections to an interrupt.
- `RAMCFG_MxIER.ECCNMI` — promote the double-bit event to an NMI
  instead of a maskable interrupt. **This is the bit we want for
  brownout defense** — a double-bit hit on a secret region must not be
  blockable by a misconfigured NVIC priority.
- `RAMCFG_MxISR` — status register (which errors fired since last
  clear). **Errata ES0499 §2.2.23**: these flags are only updated when
  the corresponding interrupts are enabled. Polling-based ECC monitoring
  without interrupt enable silently misses errors. Stage 2 must enable
  the interrupt (even if we don't take action) to get accurate status.
- `RAMCFG_MxFEAR` — failure address register, pinpoints the flipped
  location of the most recent uncorrectable error.

Current firmware state: **no ECC is enabled anywhere we control.**
SRAM1 has always-on correction (silicon default); everywhere else is
running without ECC until Stage 2 sets the option bytes and configures
RAMCFG.

Stage 2 will:
1. Set `SRAM2_ECC = 1` + `SRAM3_ECC = 1` via option bytes (extending
   the `stm32-harden-opts` target).
2. On first boot after option-byte change, zero SRAM2 + SRAM3 before
   any read (ECC bits for uninitialised memory are indeterminate and
   fire spurious double-bit errors otherwise — AN5342 §4.1.1).
3. Enable `ECCIE + ECCDEIE + ECCNMI` on each ECC-capable block.
4. Implement `#[exception] fn NonMaskableInt()` to zeroize + soft-reset
   on any double-bit event, reading `RAMCFG_MxISR` + `RAMCFG_MxFEAR` to
   log which block + address faulted.

## What STM32U585 gives us for free

STMicroelectronics anticipated brownout robustness. The U5 silicon has
extensive supervisor and integrity hardware that we leave at chip
defaults today:

### Power supervision
- **BOR (Brown-Out Reset)**: 5 levels via option byte `BOR_LEV[2:0]` in
  `FLASH_OPTR`. Trips clean reset when Vdd drops below threshold. Levels
  BOR0 (~1.7 V) through BOR4 (~**2.8 V**).
  - *Clarification*: flash program/erase operations work down to
    V<sub>DD</sub> = 1.71 V per the U5 datasheet; BOR3 is not a hard
    "minimum for flash writes" requirement, it's a best-practice
    threshold that buys margin against wait-state misconfiguration
    during brownout. For a wallet that performs rare flash writes during
    PIN-lockout wipe, BOR3 or BOR4 is appropriate.
- **PVD (Programmable Voltage Detector)**: configurable threshold via
  **`PVDLS[2:0]`** (the U5 spelling; L4-era docs call it `PLS`) in
  `PWR_SVMCR`. Enable with `PVDE` in the same register. Fires EXTI
  line 16 on threshold crossing — usable as "last-gasp" warning before
  BOR.
- **PVM (Peripheral Voltage Monitors)**: independent monitors for VddA,
  VddUSB, VddIO2.

### Reset-cause observability
- **`RCC_CSR`** sticky flags: `BORRSTF`, `PINRSTF`, `SFTRSTF`,
  `IWDGRSTF`, `WWDGRSTF`, `LPWRRSTF`, `OBLRSTF`. Classify every reset and
  respond differently.

### Watchdogs
- **IWDG**: independent watchdog on LSI clock. Immune to main-clock
  failure. 2-5 s timeout bounds any wedged state.

### Memory protection
- **Option byte `SRAM2_RST=0`**: silicon auto-erases all 64 KB of SRAM2
  on every reset of any kind (POR, BOR, software, watchdog). Turn this
  on and put active-window secrets in SRAM2 — get hardware zeroization
  without firmware correctness dependency.
- **ECC on SRAM1/2/3**: single-bit correction is always active in
  hardware (silicon feature, not a toggle). Double-bit detection is
  also always computed, but reporting requires enabling
  `RAMCFG_MxIER.DEIE` + implementing an NMI handler. See the SRAM
  section above for the full picture.
- **`RAMCFG_MxISR`** — status register that accumulates ECC events
  since last clear. Readable at any time for diagnostics.
- **`RAMCFG_MxFEAR`** — failure address register, pinpoints the
  flipped location of the most recent uncorrectable error.

### Backup domain (Vbat, already wired on B-U585I-IOT02A via CR2032)
- **32 × 32-bit `TAMP_BKPxR`** backup registers: survive Vdd loss.
  Perfect for wipe-phase state machine, diagnostic last-cause log,
  cross-reboot counters.
- **2 KB Backup SRAM** at `0x4002_4000`: Vbat-retained, auto-wiped on
  any TAMP event.

### Flash integrity
- **ECC on flash**: **9 parity bits per 128-bit quad-word** (total flash
  word = 137 bits). A torn QW write triggers an ECC double-error on the
  entire 128-bit word, not on individual 64-bit halves. Flagged via
  `FLASH_ECCR.ECCD`.
- **Page erase timing**: **typical 1.5 ms** (10k endurance cycles),
  rising to ~1.7 ms at 100k. The datasheet max (3-4 ms) applies at
  worst-case temperature + end-of-life. Use typical for PVD-to-BOR
  energy budgeting; use max for hard-deadline safety analysis.
- **WRP** (write protect) and **HDP** (hide protection): lock our
  reserved pages against accidental corruption.

### Tamper subsystem (TAMP)
- **Internal tampers**: clock monitoring, temperature monitor, voltage
  monitor. Any of these can auto-wipe backup regs + backup SRAM +
  crypto peripheral state in hardware. Exact wipe latency isn't spelled
  out in ST docs; safe to assume "fast enough relative to physical
  attack timescales" but do not rely on a specific µs figure.
- **External tamper pins** with edge/level detection and filtering.

### VBAT power source: supercap, not battery

Production hardware-wallet design choice: the backup-domain power
source is a **supercapacitor**, not a coin cell. Rationale:

- **No battery chemistry in the enclosure.** No leakage, no swelling,
  no age-out, no user-replacement lifecycle, no shipping-restrictions
  associated with lithium cells.
- **Sealed-for-life BOM.** 20+ year capacitor lifetime vs ~10 year
  battery shelf life.
- **Lower assembly cost** than holder + retention + cell.
- **Trade-off**: tamper-monitoring retention after unplug is bounded
  (hours to ~1 day), not indefinite. Acceptable given our dual-SE XOR
  split + EAL6+ decap-out-of-scope threat model.

Reference design:

```
Vdd (3V3) ─[Schottky BAT54]──┬── VBAT pin
                             │
                             ├── [C 0.47 F, 3.3 V supercap]
                             │
                            GND
```

- **Supercap**: 0.47 F / 3.3 V radial (Panasonic EECS-GW0H474H or
  equivalent), ~6.8 mm × 2 mm. Self-leakage 5-10 µA.
- **Schottky BAT54** (or similar): prevents supercap back-feeding Vdd
  during unplug.
- **Optional 10-47 Ω series R** between Vdd and the Schottky anode:
  limits inrush current on first plug-in from empty. Skippable if the
  main Vdd regulator handles the brief surge gracefully.

Expected runtime math at U5 backup-domain load (~2-3 µA backup
peripherals + ~5-10 µA supercap leakage = ~10 µA total, usable
voltage swing 3 V → 1.65 V):

| Supercap | Usable energy | Runtime |
|---|---|---|
| 0.47 F | ~700 mJ | ~12 hours |
| 1 F | ~1.4 J | ~24 hours |
| 5 F (Li-ion capacitor) | ~7 J | ~5 days |

Firmware implications — minimal:

- The Stage 1.5b VBAT canary pattern works unchanged. "Canary missing
  AND device was off for longer than supercap retention" simply means
  "supercap drained between sessions" rather than "battery dead." The
  firmware response is identical: note it in diagnostics, fall back to
  flash-based state, continue.
- **Cold-boot charge-up**: first plug-in from a fully-drained supercap
  charges with τ = R_series × C. With R_series = 47 Ω and C = 0.47 F,
  τ ≈ 22 s; VBAT reaches ~2 V (usable) in ~3τ = ~1 minute. Stage 4
  should gate backup-register writes on a PVM-monitored VBAT threshold,
  or simply wait 60 s after cold boot before writing.

Dev-board addition path (for validation work today, before a custom
PCB exists): tack-solder a 0.47 F supercap across the CR1220 holder
pads (+ and − terminals map to VBAT and GND). If the dev board ties
VBAT to Vdd via a solder bridge (SB), open it and replace with a
Schottky in the same footprint for proper isolation; otherwise the
cap will also drain the Vdd rail on unplug and runtime falls well
short of spec. See the B-U585I-IOT02A schematic for the specific SB
designator.

### STM32U585 security-relevant errata (ES0499)

Material bugs worth knowing before we write code against any of the
above features:

- **§2.2.7 / §2.2.8 — incorrect backup-domain reset.** When VBAT and
  VDD share a source, after power-on the backup domain registers can
  hold unpredictable values, potentially causing spurious tamper events
  that block SRAM2 and PKA access. Workaround: enable backup-domain
  monitoring (`MONEN=1`) or ensure VDD drops below ~100 mV for >200 ms
  before re-powering. Impacts Stage 4 reliability if we rely on
  backup-register state after arbitrary reset sequences.
- **§2.2.10 — system reset during Stop 2 with SRAM power-down can
  permanently lock the device.** Fixed in die revision cut 3.3 (Rev U);
  verify the chip rev on our dev board before using Stop 2. Not a
  concern yet because we don't enter Stop 2.
- **§2.2.23 — SRAM ECC error flags only update when interrupts are
  enabled.** Polling `RAMCFG_MxISR` without enabling `ECCIE` silently
  misses events. Stage 2 must enable ECCIE even if the ISR is a no-op,
  purely to keep the status register accurate.
- **IWDG EWI in Stop modes is broken** on U585. Not fixed. Only Run /
  Sleep modes fire the Early-Wakeup Interrupt. Impacts any future
  low-power design that relies on IWDG EWI as the wake-up path.

## Current posture

From a systematic audit of the codebase:

| Feature | Status | Location |
|---|---|---|
| BOR level | chip default until `make stm32-harden-opts` runs; target BOR3 (~2.7 V) | option bytes |
| PVD | disabled | no code (Stage 2) |
| `RCC_CSR` read | **Stage 1 done**: classified + logged every boot | `secure/src/reset_cause.rs` |
| IWDG | disabled | no code (Stage 4) |
| `SRAM2_RST` | chip default until `make stm32-harden-opts` runs; target 0 (auto-erase) | option bytes |
| Post-flash-write verify | **Stage 1 done**: `write_quadword_verified` + read-back compare | `secure/src/hw/flash.rs` |
| Multi-QW tearing guard | post-hoc detect only (from verified writes); Stage 5 adds A/B slots | `secure/src/hw/flash.rs` |
| Flash structure headers (magic/ver/CRC) | none | raw bytes (Stage 3) |
| Panic handler zeroize | yes | `main.rs` (pre-existing) |
| Boot-time dirty-reset zeroize | **Stage 1 done**: abnormal `ResetCause` triggers `zeroize_sensitive_state` | `main.rs` |
| ECC single-bit correction (SRAM1/2/3) | silicon feature; always active; no config needed | HW |
| ECC double-bit NMI reporting | **off** (RAMCFG untouched); double-bit = silent corruption | no code (Stage 2) |
| RAMCFG diagnostics | none — we don't know actual ECC event counts | no code (Stage 1.5) |
| VBAT presence detection | none — Stage 4 depends on backup regs surviving | no code (Stage 1.5) |
| Backup regs / backup SRAM | unused | N/A (Stage 4) |
| SE050 post-APDU verify | fire-and-forget | `se050/mod.rs` |
| Dual-SE ordering guard | single-state flag only | `dual_se.rs` |

## The 5-stage plan

Each stage is independently landable, independently valuable, and leaves
the codebase in a compilable + shippable state. Stages must land in
order — later stages assume infrastructure from earlier ones.

### Stage 1 — Foundational supervision (this PR)

Smallest usable chunk that moves the needle.

- **1a. Reset-cause classification.** New `hw/reset_cause.rs` reads
  `RCC_CSR` before any peripheral init, classifies into `Cold /
  Software / Watchdog / LowPower / OptionByte / Unknown`, clears sticky
  flags, exposes result to `main`. Log each boot's cause.
- **1b. Verified flash writes.** New `write_quadword_verified` in
  `hw/flash.rs` reads back after every write and compares. New error
  variant `VerifyMismatch`. Active multi-QW writers (`write_key`, BHK
  provisioning, and persistent marker/state writers) switch to verified
  form. Torn-write detection: class **A** and class **C** failures now
  observable.
- **1c. Option-byte setup target.** `make stm32-harden-opts` runs
  `STM32_Programmer_CLI` to set `BOR_LEV=3` + `SRAM2_RST=0` on a given
  device. Run once per chip during provisioning. Documents consequences.
  - *Stage 2 will extend this target* with `SRAM2_ECC=1`,
    `SRAM3_ECC=1`, `BKPSRAM_ECC=1`, `IWDG_SW=0` (hardware watchdog),
    `IWDG_STOP=0`, `IWDG_STDBY=0`. None of these are at the right
    default — see production-security.md for the full set.
- **1d. Dirty-reset boot hygiene.** When `reset_cause()` returns
  anything other than `Cold` or `Software`, main() calls
  `nsc::zeroize_sensitive_state()` before doing any unlock work. Belt-
  and-suspenders for class **F**.

Addresses: A (detect), C (detect), F (mitigate).
Does NOT yet address: B, D, E (beyond existing), G, option-byte side of H.

### Stage 1.5 — Diagnostic visibility (small, precedes Stage 2)

Two tiny additions that don't change behaviour but give us ground truth
before we start configuring things. Each is ~20-30 lines.

- **1.5a. RAMCFG register dump at boot.** New `hw/ramcfg.rs`: reads
  `RAMCFG_M1ISR..M4ISR` + `RAMCFG_M1CR..M4CR` + `RAMCFG_MxFEAR` once at
  boot, logs via `secure_log!`. Tells us: (a) whether any ECC events
  accumulated since last clear (single-bit corrections are silently
  happening every few minutes at sea level from cosmic rays — we should
  see them); (b) what the actual RAMCFG defaults are on this chip,
  replacing my earlier guesses. No side effects, pure diagnostic.
- **1.5b. VBAT presence canary.** Write a known magic value to
  `TAMP_BKPR31` at first boot; check it on every subsequent boot. If
  the magic survives, VBAT is live. If it's lost, VBAT is dead/absent
  and we should not depend on backup-register persistence in Stage 4.
  Log the result; don't gate on it yet (Stage 4 is where it matters).

Addresses: prerequisite for making informed choices in Stages 2 and 4.

### Stage 2 — PVD last-gasp + SRAM2 relocation + ECC reporting

- **PVD interrupt.** Enable `PVDE` with `PVDLS` ~200 mV above `BOR_LEV`.
  EXTI16 handler (`PVD_IRQ`) fires when Vdd crosses threshold going
  down. In the ISR: set a "dirty shutdown" flag in a TAMP backup
  register, zeroize master secret + decrypted entropy + PIN buffers in
  SRAM, `wfi()` and let BOR finish.
- **SRAM2 relocation** for active-window secrets. Move `nsc::state`,
  `crypto::master_secret_buf`, entropy decryption buffers from SRAM1 to
  SRAM2 (`0x3003_0000`). Requires linker script split. After this, the
  `SRAM2_RST=0` option byte (set in Stage 1c) guarantees hardware
  zeroization of active secrets on every reset regardless of firmware
  correctness.
  - **Initialisation gotcha**: ECC-protected SRAM must be fully written
    before being read, or the uninitialised ECC bits produce spurious
    double-bit errors on first access. During early boot, memset the
    relocation region before any other code touches it.
- **ECC enablement + double-bit NMI.**
  1. Extend `stm32-harden-opts` Makefile target to set `SRAM2_ECC = 1`,
     `SRAM3_ECC = 1`, and `BKPSRAM_ECC = 1` option bytes. Without
     these, ECC is *not running* on those blocks (correction from an
     earlier version of this doc).
  2. On first boot after the option bytes change, zero every byte of
     SRAM2 / SRAM3 / Backup SRAM before any read — uninitialised ECC
     bits produce spurious double-bit errors per AN5342.
  3. Enable `ECCIE + ECCDEIE + ECCNMI` in `RAMCFG_MxIER` for each
     ECC-enabled block. `ECCNMI=1` promotes the double-bit event to a
     non-maskable interrupt (vs. a regular maskable one).
  4. Implement `#[exception] fn NonMaskableInt()`: read
     `RAMCFG_MxISR` to identify which block faulted, log
     `RAMCFG_MxFEAR`, zeroize the secret region, trigger a soft reset
     via `SCB::AIRCR`. Stage 1d's dirty-reset path then cleans up on
     the resulting boot (classified as `ResetCause::Software`).
  - Route single-bit events to an incrementing counter in a backup
    register, not an NMI — they're already corrected and flooding an
    ISR with every cosmic-ray hit is noise.
  - Per ES0499 §2.2.23, `ECCIE` must be enabled for the status flags
    to update at all. Always enable it even if the ISR is a no-op.
- **Abort-on-PVD for flash writes.** If PVD is already asserted, reject
  flash writes immediately — never start a QW program under unstable
  Vcc.

Addresses: A (prevent), C (prevent), F (hardware guarantee),
uncorrectable ECC (prevent silent corruption).

### Stage 3 — Flash structure integrity

- **Versioned + CRC-protected blob wrapper.** `hw/persist.rs` defines:
  ```
  struct PersistHeader {
      magic: u32,        // per-blob sentinel
      version: u16,      // migration compat
      payload_len: u16,
      crc32: u32,        // over payload bytes
      payload: [u8; N],
  }
  ```
  Every persistent structure that still exists (the wrapped BHK and future
  records; not the root-derived admin PIN or PBS) goes
  through this wrapper. On read: check magic + CRC; mismatch → treat as
  blank + trigger recovery.
- **Migration path** for already-provisioned devices: version 0 =
  legacy raw bytes; auto-upgrade to version 1 on first write after
  upgrade.

Addresses: A (post-hoc detect), C (post-hoc detect + recover).

### Stage 4 — Backup-register wipe state machine + IWDG

- **TAMP backup-register access.** `hw/backup.rs` with `DBP` enable
  and `BKP[0..n]` read/write wrappers.
- **Replace single-bit wipe flag** (currently page 125 QW 1) with a
  multi-state counter in backup register 0:
  ```
  0x00 = idle
  0x01 = wipe_started
  0x02 = se050_cleaned (pending OPTIGA erase)
  0x03 = fully_complete (transient)
  ```
  Boot-time resume picks up at the correct point regardless of when
  power was lost. Solves class **E** completely.
- **IWDG enable** with 5 s timeout. Kick every iteration of the main
  loop. Wedge-recovery: any infinite loop or deadlock triggers a
  watchdog reset, Stage 1d's dirty-reset hygiene kicks in.
- **Reset-cause persistence.** Write `ResetCause` to TAMP_BKPR1 every
  boot for diagnostic cross-reboot visibility.

Addresses: E (complete), general wedge-recovery.

### Stage 5 — A/B slots for critical state

Belt-and-suspenders defense against even the most pathological tearing
scenarios.

- **Page 125 redesign** with A/B slots:
  ```
  QW 0  Slot A header (magic | ver | CRC of PIN_A)
  QW 1  Slot A admin_pin (16 B)
  QW 4  Slot B header
  QW 5  Slot B admin_pin (16 B)
  QW 8  current_slot_pointer (1 byte: 0xFF=A / 0x00=B)
  QW 9+ unused
  ```
  Update protocol: write fully to inactive slot → verify CRC → atomic
  bit-clear flip of pointer. Torn update leaves active slot intact.
- **Do not apply this pattern to an OPTIGA PBS page.** The PBS is now
  DHUK-derived at boot and has no flash page. Bank-1 page 126 instead holds the
  wrapped SE050 BHK when enabled; any redundancy or migration proposal for
  that page needs a separate BHK-owner design and must not be inferred from
  this historical slot sketch.
- **Migration**: detect old single-slot layout at boot, relocate to
  A/B.

Addresses: residual risk at A, B, C even if Stages 1-4 have a bug.

### Beyond Stage 5 (out of scope for this roadmap)

- **Hardware bulk capacitance** — add 22 µF decoupling cap near MCU to
  widen PVD-to-BOR window from ~94 µs to ~440 µs. PCB revision change.
- **TAMP peripheral full config** — external tamper pins, temperature
  monitor, voltage monitor. Wallet-enclosure-design-dependent.
- **Signed firmware update with brownout-safe flashing** — tracked
  separately on `EthereumPhone/PQ1` (label `source:work-todo`, items 14/15/16).

## Testing methodology

Validated at each stage; the test matrix grows monotonically.

### Software (fast iteration, CI-friendly)

- **Crash-point injection.** Feature flags `crash-inject-{1..N}`
  substitute `panic!()` at labelled points (after every flash write,
  inside every multi-step sequence). CI runs the normal flows and
  validates recovery. Tells us precisely which points are survivable.
- **Flash-tearing simulator.** Wrap `write_quadword` in a test mode
  that probabilistically drops the second QW in multi-QW writes.
  Validates CRC + recovery paths.
- **`FakeFlash` unit tests.** In-memory flash with programmable
  truncation at arbitrary byte offsets. Tests every persistent
  structure at every truncation point.

### Hardware (real silicon, slower)

- **Warm reset via `probe-rs reset`.** Exists (`se050-crash-safety-e2e`
  Makefile target). Exercises STM32 reset path; does NOT cut SE050 Vcc.
- **Hard reset via NRST.** Same scope as probe-rs reset. Slightly more
  thorough (resets analog peripherals).
- **Cold cycle via USB unplug.** True cold boot for both chips.
  Manual, but validated end-to-end: see `docs/secure-elements/se050-factory-reset.md`
  and the `[E2E-CRASH]` test log.
- **Programmable USB power switch** (e.g. uhubctl-compatible hub).
  ~$15. Automated cold cycles at any interval. Enables statistical
  testing: run 1000 cycles, require 100% pass rate.
- **Voltage sag tool** (programmable bench supply). Drop Vdd from
  3.3 V to 1.5 V with configurable slew. Validates PVD timing, BOR
  trip, last-gasp handler actually runs before catastrophic failure.
- **Brownout-during-specific-op injection.** External timer triggered
  by a GPIO from the DUT cuts power N microseconds after a labelled
  point. Rigorous but needs a custom board.

## What NOT to do

- **Do not add general runtime option-byte writes.** Option-byte writes require
  `OBL_LAUNCH`, which resets the chip, and an unexpected write can brick the
  wallet. The sole planned runtime exception is the still-unimplemented,
  owner-gated first-field RDP2 self-lock after user verification. Its exact
  cut-safe sequence must be separately reviewed and validated on named
  sacrificial units. All other option-byte writes require an independently
  authorized external provisioning plan; this document grants none.
- **Do not move the existing wipe-in-progress flag location in Stage 1
  or 2.** Stage 4 will replace it wholesale. Changing its format twice
  risks migration bugs.
- **Do not choose BOR below BOR3 (~2.7 V) for this wallet.** Flash
  actually works down to V<sub>DD</sub> = 1.71 V, so "below BOR3 = torn
  writes" is not an ST spec — it's a design choice. BOR3 gives margin
  against wait-state misconfiguration at low V<sub>DD</sub> and keeps
  us comfortably above flash spec minimums. Lowering it saves nothing
  meaningful for a wallet on USB power.
- **Do not assume SRAM contents on reset.** Even with `SRAM2_RST=0`,
  SRAM1 retains unless explicitly cleared. Never trust "SRAM is zero on
  boot."
- **Do not trust `write_quadword` return value alone.** The
  `ERR_MASK`-only check passes torn writes. Always use the verified
  wrapper (Stage 1b onward) for persistent data.
- **Do not skip the post-CRC check when reading** (Stage 3 onward).
  CRC verification is what turns "torn write detected" into "torn write
  recovered from."
- **Do not extend the PVD handler** to do anything longer than ~94 µs
  of work (at our typical 35 mA draw + default 4.7 µF decoupling).
  Page erase is ~3-4 ms — unreachable as last-gasp action.
- **Do not use backup-register state without VBAT power.** On the
  B-U585I-IOT02A dev board the CR1220 holder is unpopulated by
  default; production hardware uses a supercap instead of a battery
  (see "VBAT power source" above). Either way, firmware must verify
  via the Stage 1.5b canary that VBAT is live before trusting backup-
  register state. If the canary is missing, Stage 4 falls back to
  flash-based state.
- **Do not assume VBAT is unbounded on production hardware.** With
  the supercap design, backup-domain retention after unplug is ~12-24
  hours, not years. Tamper-auto-erase during long cold-storage periods
  is NOT in our threat model — the 24-word backup is the long-term
  security anchor, not on-device state.
- **Do not enable ECC reporting without pre-initialising the region.**
  ECC-protected SRAM has hidden parity bits that reset to an
  indeterminate state on power-up. Reading uninitialised ECC memory
  after you've enabled `DEIE` will fire spurious NMIs from
  double-bit-error *detection* even though no real corruption occurred.
  Always memset the block before enabling reporting.
- **Do not assume "single-bit ECC correction" is active on SRAM2,
  SRAM3, or Backup SRAM until option bytes `SRAM2_ECC` / `SRAM3_ECC` /
  `BKPSRAM_ECC` are set.** Only SRAM1 has always-on ECC as a silicon
  property. Every other block runs with ECC *off* at factory default.
  This correction replaces earlier guidance in this doc.
- **Do not wire single-bit correction events to an NMI.** They
  accumulate constantly at sea level. Route them to an incrementing
  counter in a backup register for post-mortem diagnostics; the NMI
  handler should only fire on uncorrectable (double-bit) events — and
  only via the `ECCNMI` bit in `RAMCFG_MxIER`, not by promoting a
  regular interrupt.
- **Do not rely on `RAMCFG_MxISR` status without enabling the matching
  ECC interrupt.** ES0499 §2.2.23: the status flags only update when
  the corresponding interrupt is enabled. Pure polling silently misses
  errors.
- **Do not assume the B-U585I-IOT02A ships with a battery.** The board
  has a CR1220 holder that is *unpopulated by default*. Stage 4's
  backup-register state machine requires a populated cell or it
  collapses to "equivalent to SRAM1" (lost on Vdd drop). Stage 1.5
  adds a canary to detect this at runtime.

## Invariants (post-Stage 5)

At the end of the roadmap the following will hold:

1. **No persistent secret ever stored as raw bytes.** Every flash blob
   has magic + version + length + CRC.
2. **No torn QW write goes undetected.** Verified writes catch it at
   write-time; CRC catches it at read-time.
3. **Every reset classifies its cause.** The first action on boot is
   reading `RCC_CSR`; dispatch follows.
4. **Abnormal resets zeroize SRAM2 in hardware.** `SRAM2_RST=0`
   guarantees this without firmware involvement. Active-window
   secrets live in SRAM2 (Stage 2).
5. **Wipe-in-progress state survives arbitrary crash points.** The
   4-state machine in backup register 0 tells boot-time resume exactly
   where to pick up, whether the crash happened pre-SE050-wipe,
   during, post-SE050-wipe, or during OPTIGA erase.
6. **Uncorrectable SRAM corruption never returns silent garbage.**
   `RAMCFG_MxIER.DEIE` is enabled on all ECC-capable blocks; a
   double-bit detection fires an NMI that zeroizes + soft-resets
   rather than returning the corrupted bytes to the caller.
7. **Statistical confidence**: 1000-cycle cold-boot harness passes
   100%.

## Status

- Stage 1: **complete** (commit `b00527e`). Verified on hardware: reset
  classifier correctly reports `software` under `probe-rs run`
  SYSRESETREQ (`RCC_CSR=0x14004400`); admin-wipe e2e test still passes;
  all 7 feature combos build clean.
- Stage 1.5 (RAMCFG + VBAT diagnostics): **not started**
- Stage 2 (PVD + SRAM2 + ECC NMI): not started
- Stage 3 (flash CRC/magic/version): not started
- Stage 4 (backup-register state machine + IWDG): not started
- Stage 5 (A/B slots): not started
- Bench hardware (USB power switch, voltage sag tool): not acquired
- **Option-byte application on the dev board**: `make
  stm32-harden-opts` target exists but has NOT been run yet — chip is
  still at factory defaults for BOR and SRAM2_RST.

## File map (post-Stage 1)

| Concern | File |
|---|---|
| Reset-cause classification | `secure/src/reset_cause.rs` (new, top-level so QEMU can compile) |
| Verified flash writes | `secure/src/hw/flash.rs` (`write_quadword_verified`) |
| Boot-time dispatch | `secure/src/main.rs` |
| Option-byte setup | `Makefile` target `stm32-harden-opts` |
| This doc | `docs/security/brownout-hardening.md` |



### From `docs/security/production-security.md`

# Production Security — synthesis of 2026-04-14 research round

This document consolidates findings from 4 parallel AI deep-research
sessions (bundles A, B, C, D — prompt E has not yet run) into a single
actionable reference. It is *not* the code; it is the distilled plan.
Implementation tasks track on `EthereumPhone/PQ1` (label `source:work-todo`, items #18-22).

Raw research results live under `docs/security/research-bundles/results/`. Each
finding below cites the responsible bundle plus any verification caveats.

**Scope of this doc:** threats, mitigations, and architectural decisions
that the research round surfaced. For the staged brownout-hardening
rollout see `docs/security/brownout-hardening.md`. For the SE050 PIN-lockout
factory-reset design see `docs/secure-elements/se050-factory-reset.md`.

---

## 1. Critical findings as found in the 2026-04 research round

This is a dated synthesis, not a current priority list. Resolved or superseded
items are marked in place; current authority lives in `docs/STATUS.md` and
the `EthereumPhone/PQ1` issue tracker (label `source:production-todo`).

1. **SLH-DSA verify-after-sign is inadequate**. Current code assumes
   signing the blob, re-verifying, and failing closed is enough. Per
   RFC 9814 and Genêt (TCHES 2023) a single fault during SLH-DSA
   signing produces a signature that often still verifies. Double-
   compute on disjoint SRAM regions + constant-time compare is the
   only defence. Cost: ~2 s per signature at C10 (double-compute) — acceptable.
   *Source: bundle A.*

2. **We are currently signing deterministically (OptRand = 0)**. This
   enables PRF(SK.seed) recovery via horizontal DPA on unprotected
   Cortex-M33 in 1-10 traces against Saarinen's 2024 TVLA baseline.
   Every signature must draw a fresh 16 B (128f) / 24 B (192f) from
   STM32 TRNG as OptRand. One-line fix with massive SCA impact.
   *Source: bundle C.*

3. **NXP SE050 SCP03 keys must not remain the published factory
   defaults.** The factory installs only per-device transport keysets and
   ships at RDP0. After owner verification, the first-field ceremony
   self-locks RDP2 and performs the BHK first write. The implemented candidate
   then rotates SE050 to unsalted BHK-rooted final SCP03/admin credentials and
   OPTIGA to a DHUK + page-127-TRNG-salt final PBS before the seed wizard. The exact E140
   ratchet-versus-final-rotation ordering remains OPEN and owner/silicon
   gated. *Source: bundle B and work-todo #36.*

4. **USB path has two concrete silicon-errata bugs** we have not
   addressed: DWC2 TxFIFO write atomicity (ES0499 §2.26.x) and ZLP
   race leaking stale FIFO data. The latter is a **data-leak** from
   the USB controller's own SRAM under specific SNAK/CNAK/EPENA
   timing. Both fixable in driver code. *Source: bundle D.*

5. **Masaryk University 2024/2025 thesis demonstrates 76% PIN-glitch
   bypass on STM32U5A9** — same Cortex-M33 family as our U585. Factory
   defaults (BOR=0, IWDG off, ECC off, TAMP off) are the attack
   surface. Our Stage 1 brownout work partially addresses this;
   Stage 2 needs to land before any talk of production. *Source:
   bundle A + C.*

6. **RESOLVED/SUPERSEDED — the original OPTIGA PBS flash seal mixed in
   `measured_boot::firmware_hash()` and bricked pairing after an update.**
   The bench failure remains valid historical evidence (§1 of
   `docs/secure-elements/optiga-brick-postmortem.md`), but the intermediate
   proposal to use the OTP master as the final PBS root is not current
   production architecture. The factory-burned OTP master is transport-only;
   the candidate final PBS derives from DHUK plus a page-127-persisted TRNG
   salt, with no secret PBS flash copy. Page 126 belongs only to the wrapped
   BHK. Handoff, recovery, ordering, silicon evidence, and production approval
   remain OPEN under work-todo #36. See the current-state override in §2.6. *Source: bench failure,
   2026-04-17; later lifecycle corrections.*

## 2. Per-topic summary

### 2.1 Fault injection (bundle A → todo #18)

**Threat model**: voltage glitch, EMFI, laser FI, Rowhammer. The U5 has
no public glitch bypass yet but sits on the same core as the demonstrated
Masaryk attack; presumed vulnerable until proven otherwise. We can't
rely on silicon.

**Mandatory mitigations**:

- **SLH-DSA double-compute** with disjoint SRAM regions for the two
  computations. Compare via constant-time compare; release only on
  match. Verify-after-sign does NOT substitute.
- **FihInt complement-storage** (0x1AAA_AAAA / 0x1555_5555 magic
  constants XOR'd with a mask) for every security-critical boolean:
  `pin_verified`, `blob_cached`, `match_ok`, signature-release gate.
- **PIN lockout fail-in**: current code is `if remaining == 0, wipe`
  — single glitch can skip. Invert to `if remaining != 0, continue;
  else wipe` so a skipped branch fails safe (wipes).
- **Volatile reads only** on security-critical values. `core::ptr::
  read_volatile` has a formal LLVM IR guarantee; `core::hint::
  black_box` explicitly has "no guarantees for cryptographic purposes"
  per Rust stdlib docs.
- **Hardware supervisor config** (overlaps with todo #21):
  - BOR_LEV = 3 or 4 in option bytes
  - IWDG_SW = 0 (hardware watchdog, 100-500 ms)
  - SRAM2_ECC = 1, SRAM3_ECC = 1 (ECC is OFF by default on U5)
  - SRAM2_RST = 0 (auto-erase on reset)
  - PVD enabled at highest threshold below 3.3 V
  - TAMP ITAMP1-3 enabled with automatic backup-domain erasure
  - CSS on HSE

**Strongly recommended**:

- Control-flow-integrity step counters (increment before critical
  call, decrement after, fail on mismatch).
- Random delays from TRNG before critical comparisons.
- Redundant volatile reads (2-3×) with OR-based fail-in logic.

**Cost**: ~2 s per signature (double-compute), +~5 instructions per
protected boolean (FihInt). Acceptable for a wallet UX.

### 2.2 Production key management (bundle B → todo #20)

**Historical proposal.** Trezor Safe 5 uses single-SE + binding; the
following retained research proposed dual-SE + signed binding record + OTP
anchor + monotonic counter. It is not current implementation or ceremony
authority.

> **UPDATE 2026-07-14 (work-todo #36 — ship-RDP-0 decision).** Retained as
> research input, but **stage 2 now executes ON-DEVICE at first field boot,
> not on the factory fixture**: devices ship at RDP-0 (batch-uniform image,
> user-verifiable over SWD via connect-under-reset before first power); the
> secure-app early boot self-locks to RDP-2, and only then — with the per-die
> DHUK final — does firmware do the BHK first-write, rotate SE050 SCP03/admin
> to unsalted BHK-rooted final credentials, and rotate OPTIGA PBS to DHUK plus
> a page-127-persisted fresh TRNG salt off the factory-installed
> OTP-master-derived *transport* credentials. Step 10
> ("Burn RDP Level 2") is no longer a fixture action. The historical stage-1
> FMK proposal is superseded; the candidate factory transport credentials all
> derive from the factory-burned per-device OTP master.

**Historical factory provisioning proposal — superseded by the current
transport-to-first-field lifecycle above:**

Stage 1 at RDP0 (debug attached):
1. Read all 3 UIDs (STM32 at `0x0BFA_0700`, SE050 via GetInfo, OPTIGA
   OID `0xE0C2`).
2. Derive per-device SCP03 keys: `enc = AES_CMAC(FMK, "SCP03-ENC" ||
   SE050_UID)`, similarly for MAC and DEK.
3. Rotate SE050 SCP03 via PUT KEY (INS=0xD8) from KVN=0x0B → KVN=0x11.
4. Provision OPTIGA PBS (TRNG ⊕ STM32 RNG, 64 bytes). Apply metadata
   lock: `LcsO=Operational`, `Read=Never`, `Change=Conf(0xE140)`.
   **Irreversible.**
5. Create binding record, ECDSA-P256 sign with provisioner key.
6. Store binding 3× (STM32 flash wrapped, SE050 object 0x10000001,
   OPTIGA OID 0xF1D1). SHA-256 anchor → OTP bytes 6-37.
7. Burn OTP provisioned flag.

Stage 2 at RDP1+ (after reset):
8. Wrap MasterKey with real DHUK via SAES. **DHUK at RDP0 is a known
   constant**; wrapping there achieves nothing.
9. Two-level wrap: DHUK-ECB(MasterKey) → HKDF(MasterKey, purpose) →
   AES-GCM(per-use key, SCP03/PBS/binding payload). Single-level ECB
   has no integrity.
10. Burn RDP Level 2 (permanent, irreversible).

**Boot-time anti-swap**:
- Read all 3 UIDs, verify signature, verify OTP anchor hash.
- Mismatch → erase Key Pages + wipe SE050 + permanent brick.
- Boot overhead ~500 ms – 1.2 s (acceptable).

**Cited NXP default SCP03 keys** (from AN12436, per research):
```
ENC = 85 2B 59 62 E9 CC E5 D0 BE 74 6B 83 3B CC 62 87
MAC = DB 0A A3 19 A4 08 69 6C 8E 10 7A B4 E3 C2 6B 47
DEK = 4C 2F 75 C6 A2 78 A4 AE E5 C9 AF 7C 50 EE A8 0C
```

⚠ **Verify against current AN12436** before using. Research cited
"Rev 2.4" which is unverified and may be wrong. Same caveat for SAES
register bit fields (`KEYSEL`, `KMOD`, `KEYSIZE`) — the research author
explicitly flagged those as uncertain; cross-check with CMSIS header
`stm32u585xx.h` before writing SAES code.

**Firmware upgrade path**: blob magic 0x504B4559 + version byte +
HKDF label. On boot, if `blob.version < current`, re-wrap with new
HKDF label and flash new format. STM32U585 DHUK does not rotate per
firmware, unlike STM32H5, so migration is simple.

**Historical anti-rollback proposal (superseded):** OPTIGA monotonic counter
at OID `0xF1E0`, Conf(0xE140)-protected. Production anti-rollback is currently
quarantined; Draft 1.1 is a preserved, non-implementation-approved research
candidate and no backend is selected until its OPEN resource, journal,
OTP/ECC, factory, and silicon gates close.

### 2.3 Side-channel (bundle C → todo #18)

**Threat surface**: PRF(SK.seed) leaks the master secret via horizontal
DPA on unprotected Cortex-M33. Saarinen's CRYPTO 2024 SLotH paper
reports t-stat = 24.5 at 1000 traces — catastrophic leakage.

**Mitigations that stack**:

- **OptRand mandatory** (see section 1). Breaks determinism,
  prevents chosen-message PRF recovery.
- **Signing rate limit + 2^16 rotation**: 1 sig/sec, 500/day, hard
  rotate after 2^16 signatures per key. ERC-4337 wallets unlikely to
  exceed 100 sigs/day.
- **WOTS chain + FORS tree shuffling** via Fisher-Yates, TRNG-seeded.
  Negligible perf cost (<2%); breaks trace alignment for profiled DPA.
- **Zeroize + DSB barrier** after every signing call. Use `zeroize`
  crate; follow with `core::sync::atomic::compiler_fence(SeqCst)` +
  `__dsb(0xF)` to prevent SRAM residue.
- **GTZC peripheral lockdown**: lock HASH / RNG / SAES to secure
  privileged mode so non-secure world cannot DMA-snoop (BUSted!
  style attacks). Affects every NSC gateway entry.

**Architectural decision pending — SHAKE vs SHA2-256 parameter set**
(historical framing; see closing note below):

| | SLH-DSA-SHA2 | SLH-DSA-SHAKE |
|---|---|---|
| HASH peripheral support | Yes (not DPA-resistant per UM3370) | No (software SHAKE required) |
| Masking cost | 3-5× (inefficient on Cortex-M33) | 1.5-2× (cleaner) |
| PRF-tree (Fluhrer 2024) | No | ⚠ **Citation unverified** — see §3 |
| Backward compat with on-chain verifier | Tied to current contract | Requires contract change |

Recommendation: evaluate SHAKE migration before Stage 2 implementation.
If on-chain verifier can be parameterised, SHAKE is the materially-
stronger SCA posture.

**⚠ Caveat on SHAKE migration analysis**: the Fluhrer ePrint 2024/500
"PRF-tree with 1.7× overhead, backward-compatible" citation that
bundle C used to argue for SHAKE is **not verifiable** per the
2026-04-15 verification round (see §3). Treat the SHAKE-vs-SHA2
decision as open — do NOT commit to SHAKE on the basis of Fluhrer's
claimed overhead figure. Independent analysis of SLH-DSA-SHAKE-128f
performance + masking cost on Cortex-M33 is needed before this
decision is production-ready. The qualitative argument (SHAKE is
easier to mask than SHA-256) still holds; the specific 1.7× overhead
number does not.

> **Update 2026-04-30 (audit overlay).** The all-C10 cutover (commit
> `7b2a339`, 2026-04-17) locked the parameter set to **SPHINCS+C10 over
> SHA-256** (`sig_len = 4008 B`, `h=18, d=2, a=11, k=13, w=8, l=43,
> target_sum=205`). The on-chain verifier (`SPHINCsC10Asm.sol`) is
> SHA-256-only and reuses the EVM SHA-256 precompile. SHAKE migration is
> therefore deferred indefinitely — it would require a fresh on-chain
> verifier, fresh wallet addresses (CREATE2 salt depends on master keys),
> and a factory redeploy. The qualitative SCA argument still motivates
> independent masking work on the SHA-256 path, not a primitive swap.

**HASH peripheral**: **provides zero DPA protection** per UM3370.
Useful for performance (~66 cycles/block) and timing-channel elimination
only. Software countermeasures remain mandatory.

**Caveats on numerical claims**: the research cites "SLotH" and
"SLasH-DSA 2025" papers with specific trace-count numbers. Author
plausibility and paper existence confirmed for SLotH; exact TVLA
numbers and the SLasH-DSA paper remain unverified per §3. The
qualitative conclusion (unprotected Cortex-M33 leaks PRF(SK.seed)
catastrophically) is defensible; the specific trace-count bounds
should not be cited as pinpoint figures.

### 2.4 USB hardening (bundle D → todo #19)

**Threat surface**: only external interface; primary remote attack
vector. Host computer is untrusted by design.

**DWC2 silicon bugs (STM32U5 errata ES0499)**:

- **§2.26.x TxFIFO write atomicity**: CPU must not access any other
  endpoint's CSR between successive 32-bit pushes to one TxFIFO.
  Violation corrupts `DIEPTSIZx.XFRSIZ` to zero. Mitigation: single-
  packet transfers (`DIEPTSIZ.XFRSIZ = DIEPCTL.MPSIZ`); no interleaving
  in ISR.
- **§2.26.x ZLP race**: under specific SNAK/CNAK/EPENA timing the
  controller sends a stale TX-FIFO data packet instead of a ZLP,
  **leaking data from a different session**. Mitigation: enforce
  AHB-cycle delays in the SNAK/CNAK/EPENA sequence per errata; flush
  all FIFOs on USB reset via `GRSTCTL.RXFFLSH | GRSTCTL.TXFFLSH`
  with TXFNUM=0x10.

⚠ Research cited exact §2.26.3 and §2.26.2 section numbers. These are
**plausible but unverified** — confirm against the actual ES0499 PDF
before citing in code comments. Treat the concrete advice (sequence
SNAK/CNAK/EPENA, flush FIFOs on reset, atomic TxFIFO writes) as sound
regardless of exact section numbering.

**USB stack hardening patterns**:

- **FI-resistant `min()` everywhere a control-transfer length is
  clamped**. Pattern:
  ```rust
  fn fi_min(a: usize, b: usize) -> usize {
      let r = core::cmp::min(a, b);
      if r > a || r > b {
          return if a < b { a } else { b };
      }
      r
  }
  ```
  Defeats Colin O'Flynn USENIX WOOT 2019 EMFI-on-branch attack.
  Post-transfer verification: assert `DIEPTSIZ.XFRSIZ` did not exceed
  declared length.
- **Bounded APDU reassembly**: enforce `4 ≤ declared_len ≤ 4096` at
  seq=0; 5 s timeout with buffer scrub; abort if seq=0 arrives
  mid-reassembly (sets anomaly counter for diagnostics).
- **HID OUT rate limiter**: token bucket, ~200 reports/sec sustained,
  bucket 64. NAK endpoint when empty.
- **APDU CLA/INS allowlist** at non-secure *before* any NSC gateway
  call. Reject malformed APDUs before they cross the trust boundary.
- **Response-buffer locking** for 17,088-byte SLH-DSA signatures.
  Chunked via ISO 7816 `SW=0x61xx` (GET_RESPONSE), 30 s timeout,
  scrub on anything other than GET_RESPONSE arriving.

**Runtime config**:
- `OTG_GUSBCFG.FDMOD = 1` (device-only).
- `OTG_GINTMSK`: disable SOFM (timing side-channel), MMISM (OTG),
  PRTIM (host). Enable WUIM / OEPINTM / IEPINTM / ENUMDNEM / USBRSTM
  / USBSUSPM / RXFLVLM.
- FIFO sizing per RM0456 formula with ≥30% safety margin.
- IWDG 2 s timeout, kicked per USB transaction.

**NSC gateway hygiene** (every command):
1. `cmse_check_address_range` on every NS pointer.
2. Copy-in to secure SRAM (TOCTOU defense).
3. Process secure copy, never trust original.
4. Copy-out result if needed.
5. Clear all registers before BXNS return.

**OTG_FS architectural advantage**: no DMA engine. All USB data is
CPU-mediated → TrustZone/GTZC memory protections apply to every byte.
Do NOT migrate to OTG_HS without re-doing the threat analysis — HS has
DMA and loses this property.

⚠ **Hallucination flagged**: the research cites `CVE-2026-4179` for a
"Zephyr STM32 USB device driver infinite loop." No such CVE exists in
the National Vulnerability Database as of the research cutoff — the
format is right but the ID is fabricated. Do **not** reference this
CVE in code comments or public docs. The structural advice (IWDG
timeout, bounded reassembly, rate limiter) stands regardless.

### 2.5 Supply-chain attestation (bundle E → todo #22)

Bundle E surfaces a **triple-UID binding manifest** as the load-bearing
defence — no shipping wallet currently does this, and it closes the
single-chip-replacement attack surface that has bitten every existing
wallet (Trezor Safe 3 via Ledger Donjon glitch on the STM32-OPTIGA
pre-shared secret; Ledger Snake demo via arbitrary MCU code while SE
attestation passed; ColdCard via firmware factory-reset without
changing the tamper bag). Bundle B (§2.2) already specified per-device
SCP03 rotation + OPTIGA PBS lock + ECDSA-P256 binding record; bundle E
**extends** that with SLH-DSA manifest replacement, firmware-hash
inclusion, transparency log, and a WebUSB user-verification ceremony.

**What Bundle E adds on top of Bundle B:**

1. **SLH-DSA-128s factory manifest** replaces Bundle B's ECDSA-P256
   binding record. Post-quantum resistant; signature is ~7.8 KB
   (fine — it's stored once, read on every boot). The factory HSM
   signing key runs through an M-of-N ceremony with geographically
   distributed shares.
2. **CBOR manifest schema** with explicit fields:
   ```
   {
     manifest_type:        "PQS-BIND-v1",
     se050_uid:            <18 B from SE050 IDENTIFY>,
     optiga_uid:           <27 B from OID 0xE0C2>,
     stm32_uid:            <12 B from 0x0BFA_0590>,
     firmware_hash:        SHA3-256(firmware_image),   // NEW vs Bundle B
     firmware_version:     <monotonic counter>,
     device_serial:        SHA3-256(se050_uid || optiga_uid || stm32_uid),
     production_ts:        <ISO 8601>,
     manifest_version:     1,
     factory_pubkey_fp:    SHA3-256(factory_pubkey)[:16]
   }
   ```
   Firmware-hash inclusion means the manifest also acts as a measured-
   boot anchor — ties chip identity to a specific firmware build.
3. **SE050 boot-time attestation** via `Se05x_API_ReadObject_W_Attst`
   with caller-supplied 16-byte freshness nonce. Returns 18-byte
   chipId + ECDSA-SHA256 signature over response. Verify signature
   chains to NXP root CA. ⚠ **Variant constraint**: only SE050 C/E/F
   have pre-provisioned attestation certs at OID `0xF0000013`; variants
   A/B/D have keys but no cert. Confirm we're on C/E/F before relying
   on attestation.
4. **OPTIGA boot-time attestation** via `optiga_crypt_ecdsa_sign` with
   key at OID `0xE0F0`, cert read from OID `0xE0E0`, chains to
   Infineon OPTIGA ECC Root CA 2. Same freshness nonce across both SEs.
5. **STM32U585 anti-counterfeit probes** at boot (detect remarked
   chips / clones):
   - CPUID / DBGMCU_IDCODE — expect Cortex-M33 r0p4, DEV_ID `0x482`.
     Read at `0xE0044000`.
   - UID register at `0x0BFA_0590`: validate lot bytes are printable
     ASCII (`0x20`..`0x7E`), wafer number < 25, UID not all-0 or
     all-0xFF.
   - DHUK probe via SAES: run a DHUK-gated op, verify output against
     factory-recorded expected value.
   - Errata fingerprinting: `DBGMCU_DBG_AUTH_DEVICE.AUTH_ID` reads
     zero at RDP0 (documented silicon quirk); a clone "fixing" this
     outs itself. MSI-frequency low-drift (up to 25%) and ICACHE/
     DCACHE behavior on Stop mode exit are mask-specific.
   - Flash ECC: AN5342 documents SEC-DED; test last-64KB-block of
     SRAM3 behavior.
6. **Transparency log**: append-only record of every device serial +
   manifest hash. Published (Merkle-anchored per the research's
   suggestion; exact scheme TBD). Enables detection of rogue
   production runs — any device with valid manifest but missing from
   log fails the ceremony, even if factory HSM is compromised.
7. **WebUSB box-opening ceremony** at `verify.pqsigner.io`:
   - Browser sends fresh random challenge via WebUSB.
   - Both SEs sign it (SE050 with NXP-attested key; OPTIGA with
     Infineon-attested key).
   - Website verifies both signatures independently chain to their
     respective pinned root CAs, and that the UIDs match the binding
     manifest, and the manifest's SLH-DSA signature verifies against
     the published factory pubkey.
   - Customer sees green-checkmark + device serial without installing
     any tool.

**Boot-time verification ceremony** (runs in secure world before
entropy reconstruction):
1. Read STM32 UID from `0x0BFA_0590`.
2. Load binding manifest from secure flash.
3. Verify SLH-DSA-128s signature with factory pubkey (stored in
   write-protected OTP).
4. Compare manifest.stm32_uid against hardware. Halt on mismatch.
5. Probe SE050 (I2C addr `0x48`, IoT applet AID), attested read with
   fresh nonce, extract chipId. Compare against manifest.se050_uid
   AND against SE050's own signed chipId. Halt on mismatch.
6. Probe OPTIGA (I2C addr `0x30`), read UID from `0xE0C2`, ECDSA-sign
   same nonce with `0xE0F0`. Compare to manifest.optiga_uid. Halt.
7. Compute SHA3-256 of firmware image; compare to
   manifest.firmware_hash. Halt on mismatch.
8. Check monotonic anti-rollback counter (from Bundle B).
9. Set ATTESTATION_PASSED; proceed to normal boot.

Failure at any step → permanent lockdown: neither SE releases entropy
half; USB reports specific failure reason (manifest invalid / UID
mismatch / firmware hash mismatch / etc.).

**Hallucination flags from Bundle E** (fold these into the verification
log in §3 below):

- **"Ledger Donjon March 2025 attack on Trezor Safe 3"** — cited as
  justification for the Tier B threat tier but no link / ticket /
  blog post reference. Future-dated relative to the AI's training
  cutoff (Feb 2025). **Treat as unverified**; the technical threat
  model holds regardless but this specific attack should not be cited
  as proof without verification.
- **"Trezor Safe 7"** — claimed to add TROPIC01 for dual attestation.
  Does not exist as a shipping product as of knowledge cutoff. Safe 5
  is the current Trezor flagship. **Omit from comparison tables**
  until it actually ships.
- **"Masaryk University 2024/2025 thesis by Oliver Simonik"** — 76%
  PIN-glitch on STM32U5A9. Plausible but unverified (no link /
  repository citation).
- **"BlaatSchaap research"** on STM32F103 clone detection — plausible
  but unverified pseudonymous researcher.
- **"TheCharlatan May 2020 ColdCard firmware-reset attack"** —
  plausible but unverified (no link).
- **ES0499 specific bit positions** cited in the chip-ID probe list
  (`AUTH_ID` bitfield behavior at RDP0, MSI frequency anomaly) —
  plausible but unverified; cross-check against current ES0499 PDF
  before implementing.
- **STM32U5 clone "do not exist as of early 2025"** — properly
  hedged as absence-of-evidence rather than evidence-of-absence.
  Treat as current best-available assessment, not a guarantee.

**ECDSA vs SLH-DSA binding signature decision**:
Bundle B used ECDSA-P256 for the binding record because it's small and
SE050/OPTIGA can do it natively. Bundle E argues SLH-DSA-128s is more
defensible long-term (PQ-resistant, no key-extraction from factory HSM
via Shor). Since we're already computing SLH-DSA on the MCU for
transaction signing, adding SLH-DSA verification of the manifest at
boot is free. Recommendation: **go with Bundle E's SLH-DSA manifest**;
retire Bundle B's ECDSA binding record design. This is a material
change to work-todo #20 scope.

### 2.6 Device root-key architecture (work-todo #24)

> **Current-state override (2026-07-14).** This section preserves the
> historical failure analysis and staged proposal; it is not the current page
> map or an implementation plan. The factory-burned OTP master derives only
> transport credentials. The candidate final OPTIGA PBS derives from DHUK plus
> the page-127-persisted TRNG salt and has no secret flash copy. Bank-1 page 126
> is exclusively the DHUK-wrapped SE050 BHK when `bhk` is enabled, and no
> persistent firmware-update failure counter remains. The historical route
> below that reused the OTP master as a final root is rejected for production.
> Current lifecycle and rollback authority stays with the `EthereumPhone/PQ1`
> production items (label `source:production-todo`), `docs/STATUS.md`, and the
> production-fenced rollback architecture record.

**Threat context.** The OPTIGA Trust M pairing-secret flow that landed
during early bring-up (`setup_pbs_no_handshake`, `hw/huk.rs`, flash page
126) has a concrete reliability failure: every legitimate firmware
update bricks the device. The bench chip that surfaced this is
permanently unpaired for Shielded Connection. Fixing the underlying
root-key architecture before silicon ships is a production gate.

Full root-cause analysis: `docs/secure-elements/optiga-brick-postmortem.md`.

**The bug in two sentences.** The Platform Binding Secret is generated
from the STM32 TRNG and persisted to flash page 126 under an AES-256-
GCM seal whose wrap key mixes in `measured_boot::firmware_hash()`. Any
firmware rebuild — a one-byte diff is enough — changes the hash,
changes the key, fails GCM authentication on next boot, leaves the
chip-side PBS (which is locked at LcsO=Operational) reachable only to
a PBS value the MCU can no longer reconstruct. One-way brick of the
bus-encryption path.

**Architectural response — Trezor's layered root-key model on STM32U5.**

Reading `~/repos/trezor-firmware/core/embed/sec/{secret_keys,secret,
secure_aes}/stm32u5/` shows Trezor stacks three keys:

| Layer | What | When generated | Software access | Survives FW update |
|---|---|---|---|---|
| **DHUK** | Factory-fused 256-bit per-chip key in ST silicon | At wafer test (ST) | SAES-only (`CRYP_KEYSEL_HW`); never in memory | Yes |
| **BHK** | 32 B of device TRNG in HDP-protected flash page, loaded into TAMP backup registers at boot | First boot, on-device | SAES-only after `TAMP_SECCFGR.BHKLOCK`; software can't read post-boot | Yes (regeneration = factory reset) |
| **OTP master** | 32 B of device TRNG in flash OTP block | First boot, on-device (`secret_keys.c:177-194`) | Readable by secure-world firmware | Yes (OTP is permanent per silicon) |

> **PQSigner current state (2026-07-20):** the BHK row above is Trezor's
> architecture; in PQSigner the HDP hide-protect layer is *deferred*, not
> current. The ship profile leaves HDP disabled (`HDP1EN = HDP2EN = 0`;
> nothing in `secure/src` writes `SECWM1R2`/`SECHDPCR`, and
> `verify_ship_profile` has no HDP field), so the implemented
> `bhk`-feature BHK sits in *ordinary* bank-1 flash page 126
> (`0x0C0F_C000`), DHUK-wrapped — a flash dump exposes only the wrapped
> blob. HDP1 (enable + `HDP1_PEND` covering the FSBL + `HDP1_ACCDIS` at
> boot-exit) is the tracked deferred item (`EthereumPhone/PQ1` issue #39);
> when it lands it also joins `verify_ship_profile`.

Trezor derives per-purpose keys (OPTIGA pairing, TROPIC01 pairing,
storage salt, NRF auth, MCU device-auth) from the OTP master via HMAC.
The DHUK and BHK additionally encrypt the OTP master and other secrets
at rest in the "secret" flash page, so a flash dump alone doesn't leak
raw key bytes.

**Our staged adoption plan.**

*Stage 1 — OTP-derived master with HKDF subkey layer* (this doc
landing + current implementation). Reserve bytes 128..160 of STM32U585
OTP (two quad-words past the rollback tally) for a 32-byte device
master key. On first secure-world boot, if the region is unburned,
fill 32 bytes from STM32 TRNG and program (irreversible). On every
subsequent boot, `read_device_master` returns those 32 bytes. A new
`secure/src/hw/secret_keys.rs` exposes domain-labelled HKDF-SHA256
subkeys: `optiga_pairing_secret`, `se050_scp03_enc_key`,
`se050_scp03_mac_key`, `tropic01_pairing_key`. `setup_pbs_no_handshake`
consumes `optiga_pairing_secret` instead of `rng::fill`; the flash-
page-126 AES-GCM seal is deleted outright. `hw/huk.rs::derive_device_
key` re-roots off the OTP master — the line that reads `h.update(&fw_
hash)` becomes `h.update(&hw::otp::read_device_master())`. `measured_
boot::firmware_hash()` is preserved unchanged: it still drives the 8-
BIP-39-word OLED attestation and will feed the #22 supply-chain
manifest; it just stops being an input to wrap-key derivation. Closes
the brick scenario.

*Stage 2 — SAES + BHK uplift* (merges with work-todo #7 HUK-SAES).
Port Trezor's BHK pattern: first-boot TRNG into an HDP-protected flash
page, load into TAMP backup registers at boot, set `TAMP_SECCFGR.BHKL
OCK` so secure-world code can only *use* the key via SAES, not read
it. Wrap the OTP master with DHUK at rest so a chip decap alone
doesn't yield the raw bytes. The `secret_keys::*` API surface stays
unchanged — OPTIGA / SE050 / Tropic drivers do not move.

**Why first-boot self-provisioning beats a factory-burn workflow** for
an open-source wallet: the TRNG output only ever exists on the user's
own hardware, never passes through the vendor's hands, and the factory
does not need to hold or protect any per-device secret. The customer
can independently verify on unboxing that OTP is still unburned before
powering the device up, which is a stronger property than trusting a
factory tamper-evident bag. This matches Trezor's `flash_otp_is_locked
? read : (fill + write + lock)` pattern exactly (`secret_keys.c:177-
194`). The residual supply-chain concern is that "first boot" must
happen on a device running our signed firmware — otherwise an attacker
who intercepts the device pre-first-boot could flash a key-exfiltrating
stub, boot once to capture TRNG, then restore the real firmware.
Defence stack: secure boot (work-todo #13) + tamper-evident packaging
+ a user-side verification script that confirms the binding manifest
(work-todo #22) matches the device before first power-on.

**Testing posture — hardcoded key during bring-up.** Until we are
confident the derivation is stable across rebuilds, we do *not* want
to burn real OTP on our dev bench. `secure/Cargo.toml` gains an
`otp-hardcoded-master-key` Cargo feature, OFF by default. When
enabled, `read_device_master` returns a fixed 32-byte constant
(deliberately distinctive byte pattern so it cannot be confused for a
real key in logs), `is_device_master_burned` returns true, and
`ensure_device_master` is a no-op. A loud boot-time warning via
`secure_log!` flags the insecure configuration. A `compile_error!`
guard fails the build if the feature is set without `debug-log` or
`e2e-test` also enabled (i.e. on a production profile). Flip the
feature off and the first-boot TRNG path takes over. We validate end-
to-end on a fresh OPTIGA chip only after the hardcoded path is proven
stable across reflashes with differing firmware hashes.

**Extraction cost across layers.**

| Attacker capability | Stage-1 OTP master | Stage-2 OTP master under SAES | Stage-2 BHK post-lock |
|---|---|---|---|
| Secure-world RCE, read memory | Reads the 32 bytes directly via `read_volatile(0x0BFA_0080)` | Same — OTP remains plain-readable; DHUK wrap protects only at rest | Cannot read; can only USE via SAES on this device |
| Flash-dump + transplant to second board | UID of target board is wrong → derived keys wrong anyway; not viable | Same, with DHUK also wrong → ciphertext undecipherable on target | Same, and BHK never lived in transferable flash |
| Debug port after RDP regression | OTP survives RDP regression | Same | BHK regeneration on RDP2→0 wipes TAMP-backed key |
| Decap + microprobe OTP cells | Feasible ($10–100K, destructive, single device) | Same, then attacker still needs DHUK from silicon | BHK lives transiently in TAMP; substantially harder |
| Supply-chain attacker between factory and user | No key on-device yet; attacker can substitute their own TRNG | Same | Same |

Stage 1 solves the brick. Stage 2 additionally raises the bar from
"secure-world RCE = remote key exfiltration" to "attacker must keep
running code on *this specific device* for every signature they want
to forge" — a qualitative change in the attacker cost model.

**Files touched in Stage 1.**

- `secure/src/hw/otp.rs` — add `read_device_master`, `burn_device_
  master`, `is_device_master_burned`, `ensure_device_master`.
- `secure/src/hw/secret_keys.rs` *(new)* — HKDF-SHA256 wrappers.
- `secure/src/hw/mod.rs` — register `secret_keys` module.
- `secure/src/hw/huk.rs` — swap `firmware_hash` → OTP master in
  `derive_device_key`.
- `secure/src/optiga/mod.rs` — rewrite `setup_pbs_no_handshake`,
  simplify `load_pbs`.
- `secure/src/hw/flash.rs` — delete `read_pbs` / `write_pbs` /
  `erase_pbs_page` / `PBS_PAGE_ADDR` / `PbsLoadError` / `PBS_WRAP_
  DOMAIN` / `PBS_BLOB_LEN` / `is_pbs_blank`.
- `secure/Cargo.toml` — drop `optiga-bringup-fresh`, add `otp-
  hardcoded-master-key`.
- `secure/src/measured_boot.rs` — unchanged (keeps driving OLED
  attestation + #22 manifest).

### Empirically validated: SE PIN gate survives a DHUK/BHK leak

The full threat-model claim — "a DHUK leak (or, post-Phase-2C, a BHK
leak) does not drain funds because the user PIN gate is enforced in
SE silicon, not by the encrypted channel" — is now backed by a
falsifiable hardware test rather than just a code review.

`run_admin_extract_attempt` (`secure/src/se050/mod.rs`) provisions an
isolated test sentinel on OID range `0x7B0B_xxxx` under the same
two-entry `TAG_POLICY` template the production code uses for half_E
(`apdu::build_policy`, `se050/apdu.rs:339-365`):

- user entry: `READ | WRITE | DELETE | REQUIRE_SM`
- admin entry: `DELETE | REQUIRE_SM` (no `READ` bit)

The test then opens an admin session (with the admin PIN that is, in
the threat model, recoverable from a DHUK leak), authenticates
successfully against the chip, and:

1. attempts to READ the sentinel — the chip refuses with
   `SW=0x6986` ("security status not satisfied"),
2. immediately DELETEs all three objects in the same session — the
   chip accepts, proving the refusal in step 1 was a genuine read-
   deny and not bogus authentication.

Validated 2026-05-11 on B-U585I-IOT02A board #1 (ST-LINK SN
`0029…3838`) via `make se050-admin-extract-attempt-e2e`. Semihosting
trace ends with:

```
[E2E-EXTRACT] step 4: admin-auth read REFUSED (Status(27014)) — security property holds
[E2E-EXTRACT] step 5: admin-auth delete OK (admin session was genuinely admin → step 4 refusal was a real READ deny, not bogus-auth)
[E2E-EXTRACT] PASS: admin can DELETE but NOT READ user-PIN-gated secrets
```

Operational implication of this finding: a DHUK leak (or future BHK
leak) gives the attacker the SE050 admin PIN, which lets them
**brick** a stolen wallet (delete the seed half — DoS only) but not
**extract** funds. To extract, they still need 1-in-1,000,000 luck
on the user-PIN gate before the SE auto-bricks at the 10-attempt
cap. The test is repeatable and should run in CI on any commit
touching `secure/src/se050/apdu.rs` so that an accidental
`AR_ALLOW_READ` bit added to the admin policy entry fails the build
loudly rather than silently regressing the threat model. The
OPTIGA side (`half_O` gated by `Auto(F1D0)` AuthRef, where E140/PBS
authenticates the channel but does not satisfy the read AC) is a
different mechanism with the same property and is not yet covered
by an analogous E2E.

## 3. Hallucination + verification log

The research-round prompts told the AI to cite primary sources and
say "I don't know" rather than guess. Across the 5 responses, here's
the status of every flagged citation — after a 2026-04-15 verification
round of web searches.

**Lesson learned from this verification round**: most of our initial
hallucination-flagging was wrong. We called items hallucinated because
they were future-dated relative to our own model's training cutoff;
they were actually real publications from after the cutoff. Be less
aggressive flagging things as fabricated in future rounds — verify
first, flag second.

| Claim | Source | **Verification status (2026-04-15)** | Action |
|---|---|---|---|
| `CVE-2026-4179` (Zephyr STM32 USB infinite loop) | bundle D | ✅ **REAL**. Published 2026-03-16. Zephyr advisory `GHSA-9xg7-g3q3-9prf`, CWE-835, CVSS 6.1. Affects Zephyr ≤ 4.3.0 drivers/usb/device/usb_dc_stm32.c. | Safe to cite. Note advisory is about `usb_write()` from ISR + `k_yield()`, not explicitly malicious USB host — read the GHSA before re-describing. |
| `CVE-2021-42553` (STM32Cube USB Host buffer overflow) | bundle D | ✅ **REAL**. NVD, CVSS 9.8 CRITICAL. | Safe to cite. |
| **RFC 9814** (SLH-DSA verify-after-sign inadequate) | bundle A | ✅ **REAL**. Proposed Standard, July 2025. §5 quote: *"Verifying a signature before releasing the signature value is a typical fault-attack countermeasure; however, this countermeasure is not effective for SLH-DSA."* | Safe to cite — directly supports the double-compute mandate. |
| NXP **AN12436** SCP03 default keys (ENC/MAC/DEK) | bundle B | ✅ **REAL**. Latest revision is Rev 2.4 (8 July 2024). All three hex values match byte-for-byte against earlier retrievable rev 1.6. | Safe to cite. |
| STM32U5 **errata ES0499** existence | bundle D | ✅ **REAL**, Rev 11 (December 2025) current. §2.2.15 confirmed verbatim ("OTG_FS is reset by OTGRST and DCMI_PSSIRST bits"). | Cite ES0499 safely. |
| ES0499 specific sub-section numbers (§2.26.2, §2.26.3, §2.26.4, §2.26.5) | bundle D | 🟡 **Partially verified.** USB OTG errata is indeed in ES0499; exact sub-section numbering could not be confirmed from public search snippets. May have shifted between revisions. | Download Rev 11 and pin citations to it before quoting section numbers in code. |
| **AN5342** (Flash ECC / SRAM ECC option bytes) | bundle A | ✅ **REAL**. Title: "How to use ECC management for internal memories protection on STM32 MCUs." Originally STM32H7-focused, broadened to multi-series. | Cite safely. Some STM32U5-specific ECC detail lives in RM0456 rather than AN5342; open current AN5342 to confirm U585-specific option-byte wording. |
| **RM0456** covers SAES peripheral | bundle B | ✅ **REAL**. Confirmed. | Safe to cite. Pin latest revision number when writing code against specific bit fields. |
| STM32U585 SAES bit fields (KEYSEL / KMOD positions) | bundle B | 🟡 Research author explicitly flagged as unknown; confirmation not attempted in this verification round. | Cross-check CMSIS `stm32u585xx.h` before writing SAES code. |
| **Ledger Donjon March 2025 Trezor Safe 3** glitch | bundle E | ✅ **REAL**. Blog post dated March 12, 2025 at `ledger.com/why-secure-elements-make-a-crucial-difference-to-hardware-wallet-security`. TRZ32F429 voltage-glitched, pre-shared secret extracted from flash, firmware attestation bypassed. Trezor's own confirmation at `trezor.io/vulnerability/donjon-s-trezor-safe-3-evaluation`. | Safe to cite. |
| **Trezor Safe 7** with TROPIC01 | bundle E | ✅ **REAL**. Announced October 21, 2025 (`trezor.io/trezor-safe-7`; `tropicsquare.com/news-and-events/...trezor-safe-7`). Shipping late 2025 / early 2026. Transparent secure element + EAL6+ secondary SE (dual attestation). | Safe to cite. This is the closest existing product to our PQSigner OS architecture. |
| **Trezor Safe 5** uses STM32U5 | bundle E | ✅ **REAL**. Confirmed via Trezor product page + Ledger blog. | Safe to cite. |
| Ledger Donjon 2025 statement that "no public fault injection attack on STM32U5" | bundle E | ✅ **REAL**. Exact quote in the Ledger blog post (`ledger.com/why-secure-elements-make-a-crucial-difference...` March 12, 2025). Note: **already superseded by the Simonik thesis** below. | Safe to cite, but qualify that it was true as of publication and has since been invalidated. |
| **Masaryk U Simonik thesis** 76% PIN-glitch on STM32U5A9 | bundle A / C / E | ✅ **REAL**. Bachelor's thesis by Oliver Simonik at Masaryk U on fault injection against STM32U5 (Trezor Safe 5). Referenced at `it4sec.substack.com/p/fault-injection-attack-on-the-stm32u5`. Thesis PDF on `is.muni.cz` (not directly retrieved this round — verify the URL before quoting page numbers). | Safe to cite. This is the empirical demonstration that STM32U5 is **not** glitch-immune. |
| **BlaatSchaap** STM32F103 clone research | bundle E | ✅ **REAL**. `blaatschaap.be/identifying-32f103-clones/` + multi-part Cortex-M series. Uses CPUID/ROMTABLE differences. Specific r2p1 vs r1p1 exact revision strings not confirmed this round. | Safe to cite for the approach; verify exact revision strings against primary source. |
| **TheCharlatan May 2020 ColdCard firmware-reset** | bundle E | ✅ **REAL**. `thecharlatan.ch/COLDCARD-Supply-Chain/`. | Safe to cite. |
| **Saleem Rashid 2018 Ledger Nano Snake demo** | bundle E | ✅ **REAL**. `saleemrashid.com/2018/03/20/breaking-ledger-security-model/`; Krebs on Security coverage. | Safe to cite. |
| **wallet.fail at 35C3** | bundle D | ✅ **REAL**. `media.ccc.de/v/35c3-9563-wallet_fail`. December 2018 CCC. | Safe to cite. |
| **SiliconToaster** (Ledger Donjon EMFI tool) | bundle D / E | ✅ **REAL**. `github.com/Ledger-Donjon/silicon-toaster`, LGPLv3, Hardwear.io 2020 paper (`eprint.iacr.org/2020/1115`). | Safe to cite. |
| **"Extraktor" Ledger Donjon ~$100 glitch board** | bundle D | ❌ **Cannot confirm** this specific tool name. Not found in Donjon's public repos / blog. Likely misremembering of SiliconToaster (which *is* real) or a non-public internal tool. | Do **not** cite "Extraktor" by name; say "published Ledger Donjon glitching tooling" if referring to the general capability. |
| **CanSecWest 2024 / VoidStar STM32F4 RDP bypass** | bundle D / E | ✅ **REAL**. Matthew Alt (VoidStar Security LLC), talk title "Glitching in 3D: Low-Cost EMFI Attacks." `secwest.net/presentations-2024/glitching-in-3d-low-cost-emfi-attacks`, `voidstarsec.com`. | Safe to cite. |
| "Riscure LFI on ColdCard" | bundle D / E | 🔴 **Attribution WRONG.** The ColdCard Mk2 ATECC508A single-laser-shot + Mk3 ATECC608A multi-shot attacks were done by **Ledger Donjon (Olivier Hériveaux)**, NOT Riscure. See `blog.coinkite.com/laser-fault-injection/`, SSTIC 2020/2021 papers, `ledger.com/blog/coldcard-pin-code`. | Correct attribution when citing. Research content is correct; credit is wrong. |
| **Colin O'Flynn "MIN()imum Failure" USENIX WOOT 2019** | bundle D | ✅ **REAL**. Safe to cite. |
| **Thomas Roth TrustZone-M on SAM L11 at 36C3** | bundle D | ✅ **REAL**. `media.ccc.de/v/36c3-10859-trustzone-m_eh...`. |
| **Saß et al. μ-Glitch USENIX Security 2023** | bundle A | ✅ **REAL**, 4-fault TrustZone-M bypass demonstrated. Safe to cite. |
| **Spensky et al. GlitchResistor DSN 2021** | bundle A | ✅ **REAL**. Specific "100% success at 8-cycle window" figure not reverified, but paper exists and characterises success rates in this ballpark. |
| **Genêt "Grafting Trees" TCHES 2023** | bundle A | ✅ **REAL**. Paper by Aymeric Genêt, TCHES 2023, single-fault universal-forgery via grafting subtree into SPHINCS+ hypertree. Safe to cite; this is the canonical reason verify-after-sign doesn't save SLH-DSA. |
| **Kannwischer et al. COSADE 2018** (DPA on SPHINCS-256 BLAKE) | bundle C | ✅ **REAL**. Springer LNCS 10815. ~10k traces for 32-bit chunk is consistent with paper. |
| **Saarinen "SLotH" CRYPTO 2024** + specific TVLA numbers (t=24.5 at 1k traces) | bundle C | 🟡 Saarinen's work on PQC side-channels is real. The specific SLotH paper title + exact numerical claims could not be independently confirmed in this verification round. | Verify against the actual paper before committing architectural decisions that depend on the trace-count figure. |
| **Fluhrer ePrint 2024/500** — PRF-tree 1.7× overhead, backward-compat | bundle C | ❌ **Does not exist as described** per verification agent. The claim "backward-compatible PRF-tree" is technically implausible — changing PRF tree structure changes verification output. | **Do not base architectural decisions on this citation** until verified. Treat SHAKE migration discussion as open question pending an independent reference. |
| **Belenky et al. TCHES 2023 / COSADE 2021** specific trace counts (275K / 30K) | bundle C | 🟡 Author works on side-channels; specific trace counts unverified. | Treat as indicative rather than pinpoint benchmarks. |
| **Boy et al. "SLasH-DSA 2025" Rowhammer universal forgery** | bundle A / C | 🟡 **Uncertain.** Post-May-2025 cutoff. OpenSSL SLH-DSA support shipped in OpenSSL 3.5 early 2025, so an attack paper in 2025 is plausible, but neither we nor our verification agents could confirm its existence. | Do not cite until independently found. The underlying Rowhammer-vs-PQ-signing threat class is real regardless. |
| **Fox-IT AES-256 EM attack** (5 min at 1 m) | bundle C | ✅ **REAL**. Fox-IT whitepaper by Ramsay & Van Woudenberg, 2017. Safe to cite. |
| **Kraken Security Labs Trezor glitching** ($75, 15 min) | bundle D | ✅ **REAL**. January 2020 disclosure. Safe to cite. |
| **NCC Group "CM-1-C" pattern label** | bundle A | 🟡 NCC Group's multi-part fault-injection-countermeasures series is real (`research.nccgroup.com/2021/07/08/software-based-fault-injection-countermeasures-part-2-3/`) and covers complement-storage + redundant-check patterns. The specific "CM-1-C" identifier could not be located. | Cite the NCC Group series by URL; do not cite "CM-1-C" by name. |
| **MCUboot magic constants 0x1AAA_AAAA / 0x1555_5555** | bundle A | ✅ **REAL**. Documented in MCUboot design docs; values chosen specifically for fault-injection hardening. Safe to cite. |
| **Ringzer0 PicoEMP STM32F4 RDP bypass** | bundle D | 🟡 PicoEMP (by Colin O'Flynn / NewAE) is real; STM32F4 RDP EMFI bypasses exist; specific claim of "Ringzer0 + PicoEMP + 3D printer automated scanning" could not be tied to a specific publication. | Cite PicoEMP generically; don't invent specific research attributions. |

**Bottom line**: of the 30+ technical references in the 5 research
bundles, fewer than a handful are actual hallucinations. The round
was more accurate than my initial skepticism suggested. Going
forward: verify-then-flag, not flag-then-verify.

## 4. Implementation sequencing

See todo items #18-24 for the full work list. Suggested phasing:

**Phase 0 — Device root-key architecture (todo #24)** — ~3 days
Land `hw/otp.rs` master-key API (read / burn / ensure) + `hw/secret_
keys.rs` HKDF subkeys + OPTIGA `setup_pbs_no_handshake` rewrite +
`hw/huk.rs` re-root off `firmware_hash`. Delete `PBS_PAGE_ADDR` flash-
seal infrastructure and the `optiga-bringup-fresh` Cargo feature.
Closes the production-breaking firmware-update brick (§2.6). Unblocks
#7 (HUK-SAES) and #20 (factory provisioning) downstream. Initial
testing under `otp-hardcoded-master-key`; real OTP burn proven on a
fresh OPTIGA shield before this phase is considered complete.

**Phase 1 — Stage 2 brownout foundation (todo #21)** — ~1 week
Landing BOR/IWDG/ECC/PVD/TAMP/CSS at factory defaults to secure config.
Everything that follows depends on this.

**Phase 2 — SCA mandatory-minimums (todo #18 P0 items)** — ~1 week
OptRand + double-compute + FihInt + PIN lockout fail-in. No SHAKE
migration yet; it's the architectural question for Phase 4.

**Phase 3 — USB hardening (todo #19)** — ~1 week
FI-resistant min + bounded reassembly + rate limiter + DWC2 errata
workarounds. Independent of Phases 1-2.

**Phase 4 — Architectural decision: SHAKE vs SHA2** — design work,
not code. Requires on-chain verifier assessment. Blocks the final
SLH-DSA parameter pin for production.

**Phase 5 — Production key management (todo #20)** — ~2-3 weeks
Host-side provisioning tooling, two-stage RDP flow, binding record,
anti-swap boot verification. Largest single item.

**Phase 6 — Run bundle E + apply findings (todo #22)** — TBD
Supply-chain attestation; likely augments Phase 5.

Total ≈ 6-8 weeks of focused work to reach production-ready security
posture, excluding the on-chain verifier work for a SHAKE migration.

## 5. What this doc is NOT

- Not a code specification — see the `EthereumPhone/PQ1` issue tracker
  (label `source:work-todo`) for actionable tasks, and the code itself once
  implemented.
- Not a threat model — see `docs/security/HARDENING.md` and `CLAUDE.md`
  invariants. This doc documents *mitigations* surfaced by research,
  not the overall threat taxonomy.
- Not a replacement for primary-source documentation — every register
  name / protocol detail cited here should be verified against ST
  RM0456, NXP UM11225, Infineon OPTIGA Trust M User Manual, etc.
  before code lands. The research gave us direction; the primary
  sources give us correctness.



### `secure/src/dual_se.rs`

```rust
//! Dual-SE XOR entropy split: OPTIGA Trust M + SE050.
//!
//! The 32-byte BIP-39 entropy is XOR-split into two halves:
//!   `half_O` (stored on OPTIGA Trust M) and `half_E` (stored on SE050).
//! Neither chip alone reveals any bit of the seed.
//!
//! On unlock, both SEs are PIN-verified independently (hardware-gated),
//! the halves are fetched, and the full entropy is reconstructed:
//!   `entropy = half_O XOR half_E`
//!
//! The master_secret is derived from the full entropy:
//!   `master_secret = KDF("sphincs-master", entropy, 0)`
//!
//! Both SEs store the same master_secret (encrypted under their own
//! per-SE PIN scheme) so we can cross-verify: if the two don't match,
//! one chip has been tampered with.

use crate::crypto;
use crate::optiga::OptigaTrustM;
use crate::se050::Se050;
use crate::secure_element::{SeError, UnlockError, WalletStore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// XOR two 32-byte arrays. Inherently constant-time.
fn xor_32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Dual secure element wrapper.
///
/// Manages XOR-split entropy across OPTIGA Trust M (half_O) and SE050 (half_E).
/// Both SEs run their own PIN verification (hardware-gated); the master
/// secret returned by each must match (derived from the same full entropy).
pub struct DualSecureElement {
    pub optiga: OptigaTrustM,
    pub se050: Se050,
    /// Cached encrypted entropy blob (full entropy encrypted under master_secret).
    /// Used by the signing flow to avoid re-authenticating per sign.
    entropy_blob_cache: [u8; crypto::ENTROPY_BLOB_LEN],
    blob_cached: crate::fih::FihBool,
}

impl DualSecureElement {
    pub const fn new() -> Self {
        Self {
            optiga: OptigaTrustM::new(),
            se050: Se050::new(),
            entropy_blob_cache: [0; crypto::ENTROPY_BLOB_LEN],
            blob_cached: crate::fih::FihBool::new_false(),
        }
    }

    /// Load Platform Binding Secret for OPTIGA Trust M (delegates to inner driver).
    pub fn load_pbs(&mut self) {
        self.optiga.load_pbs();
    }

    /// Bring-up transport OPTIGA E140 pairing, run before the legacy seed
    /// wizard draws entropy — see `OptigaTrustM::pair_for_first_boot` for why
    /// (mandatory `ensure_shield` in `random()` needs a paired chip). This is
    /// not the production-final fresh-TRNG rotation or E140 lock ceremony.
    /// The OPTIGA-level error detail is logged by the inner driver;
    /// callers only branch on success.
    pub fn pair_optiga_for_first_boot(&mut self) -> Result<(), SeError> {
        self.optiga
            .pair_for_first_boot()
            .map_err(|_| SeError::InternalError)
    }

    /// Generate a fresh OPTIGA-side XOR half via a 3-source TRNG mix
    /// (STM32 ⊕ OPTIGA ⊕ SE050). The security of the dual-SE split
    /// depends critically on this half being unpredictable: if an
    /// attacker recovers the SE050 half (or guesses this one), they
    /// reconstruct the seed by XOR. Mixing three sources means any single
    /// unbroken source preserves entropy.
    ///
    /// Uses the explicit-handle `rng_strong::fill_with_store` path so holding
    /// `&mut self` never re-enters the global SE singleton. That path obtains
    /// and validates the two chip streams separately before folding either.
    ///
    /// Both-or-fail (finding F1): each SE's `random()` contribution is
    /// mandatory — a failed read aborts provisioning rather than being
    /// silently dropped. The previous `if …is_ok()` mixing let `half_o`
    /// degrade to the platform TRNG alone when both SE reads failed or were
    /// glitched: an attacker who influenced the STM32 TRNG and later extracted
    /// the SE050 half could then recover the full seed (`half_E XOR half_O`),
    /// defeating invariant #1. This matches the strict semantics of
    /// `DualSecureElement::random`. Also fail-closed on an all-zero result
    /// (stuck-at-0 fault surviving all three sources).
    fn generate_split_half(&mut self) -> Result<[u8; 32], SeError> {
        // `half_o` = the OPTIGA-side half in both the real and decoy
        // splits (the SE050 half is `entropy XOR half_o`).
        let mut half_o = [0u8; 32];
        if crate::rng_strong::fill_with_store(&mut half_o, self).is_err() {
            secure_log!(
                "[DUAL/prov] strict STM32+OPTIGA+SE050 draw FAILED — refusing degraded split"
            );
            half_o.zeroize();
            return Err(SeError::InternalError);
        }
        Ok(half_o)
    }

    /// Wipe the OPTIGA side of a dual-SE store, supplying the legacy E120
    /// reset path with a strict three-source transient authorization value.
    /// A failed source skips only that optional counter reset; the underlying
    /// OPTIGA wipe still runs without a weaker replacement secret.
    pub(crate) fn reset_optiga_for_admin(&mut self) -> Result<(), SeError> {
        #[cfg(all(feature = "optiga-hw-counter", not(feature = "optiga-lock-operational")))]
        let result = {
            let mut transient_secret = Zeroizing::new([0u8; 32]);
            let result = if crate::rng_strong::fill_with_store(&mut *transient_secret, self)
                .is_ok()
            {
                self.optiga
                    .factory_reset_with_transient_secret(&mut *transient_secret)
                    .map_err(|_| SeError::InternalError)
            } else {
                secure_log!(
                    "[DUAL] strict transient-auth RNG failed — skipping optional \
                     OPTIGA E120 reset; continuing best-effort wipe"
                );
                self.optiga.factory_reset_admin()
            };
            transient_secret.zeroize();
            crate::fi::zeroize_barrier();
            result
        };
        #[cfg(not(all(feature = "optiga-hw-counter", not(feature = "optiga-lock-operational"))))]
        let result = self.optiga.factory_reset_admin();
        result
    }
}

impl WalletStore for DualSecureElement {
    fn is_provisioned(&mut self) -> bool {
        self.optiga.is_provisioned() && self.se050.is_provisioned()
    }

    fn provision(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), SeError> {
        secure_log!("[DUAL/prov] start");

        // Keep every reconstructing split-half copy in an auto-wiping wrapper.
        // This closure is intentional: all four wrappers drop before the
        // barrier below on success, either SE provisioning error, or either
        // optional ML-KEM sealing error. Returning directly from one of those
        // branches must never leave a raw half live on the stack.
        let provision_result = (|| -> Result<(), SeError> {
            let half_o = Zeroizing::new(self.generate_split_half()?);
            secure_log!("[DUAL/prov] rng OK (3-source XOR mix), calling optiga.provision");
            let half_e = Zeroizing::new(xor_32(entropy, &half_o));

            // Under the ML-KEM hybrid inner wrap (#28), seal each half BEFORE it
            // crosses I²C: the SE stores the 32-byte AES-GCM ciphertext (object
            // size unchanged), and the 1568-byte ML-KEM ct + 16-byte tag go to
            // the ct-store. Without the feature the direct-half flow remains
            // byte-for-byte identical; the two Copy aliases are also Zeroizing.
            #[cfg(feature = "mlkem-inner-wrap")]
            let (se_half_o, se_half_e) = (
                Zeroizing::new(
                    crate::pq_wrap::seal_half_for_se(
                        crate::pq_wrap::HalfId::OptigaHalfO,
                        0,
                        &half_o,
                    )
                    .map_err(|_| SeError::InternalError)?,
                ),
                Zeroizing::new(
                    crate::pq_wrap::seal_half_for_se(
                        crate::pq_wrap::HalfId::Se050HalfE,
                        0,
                        &half_e,
                    )
                    .map_err(|_| SeError::InternalError)?,
                ),
            );
            #[cfg(not(feature = "mlkem-inner-wrap"))]
            let (se_half_o, se_half_e) =
                (Zeroizing::new(*half_o), Zeroizing::new(*half_e));

            // Both SEs get the same master_secret (derived from full entropy).
            // This lets us cross-verify on unlock.
            //
            // OPTIGA Trust M stores its half-object + master_secret behind the
            // HMAC auth reference PIN gate; SE050 stores its half-object behind
            // hardware UserID PIN gating. The VK and bootstrap VK are identical
            // on both chips.
            if let Err(e) =
                self.optiga
                    .provision(&se_half_o, master_secret, vk, bootstrap_vk, pin)
            {
                secure_log!("[DUAL/prov] optiga.provision FAILED: {:?}", e);
                return Err(e);
            }
            secure_log!("[DUAL/prov] optiga OK, calling se050.provision");
            if let Err(e) =
                self.se050
                    .provision(&se_half_e, master_secret, vk, bootstrap_vk, pin)
            {
                secure_log!("[DUAL/prov] se050.provision FAILED: {:?}", e);
                return Err(e);
            }
            Ok(())
        })();

        // The closure's Zeroizing locals have dropped on every exit. Keep an
        // explicit compiler barrier at the security boundary before exposing
        // its Result to the caller.
        crate::fi::zeroize_barrier();
        provision_result?;

        secure_log!("[DUAL] Provisioned: entropy XOR-split across OPTIGA Trust M + SE050");
        Ok(())
    }

    #[cfg(feature = "duress-pin")]
    fn provision_duress(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        duress_pin: &[u8; 8],
    ) -> Result<(), SeError> {
        // `entropy` is the FULL decoy entropy; XOR-split it across the two
        // chips exactly like the real wallet — invariant #1 (no full
        // entropy on a single chip) applies to the decoy too. A fresh
        // 3-source half is drawn so the decoy split is independent of the
        // real one.
        secure_log!("[DUAL/duress] start");
        let mut half_o = self.generate_split_half()?;
        let mut half_e = xor_32(entropy, &half_o);

        if let Err(e) = self.optiga.provision_duress(&half_o, master_secret, vk, bootstrap_vk, duress_pin) {
            secure_log!("[DUAL/duress] optiga.provision_duress FAILED: {:?}", e);
            half_o.zeroize();
            crate::fi::zeroize_barrier();
            half_e.zeroize();
            return Err(e);
        }
        if let Err(e) = self.se050.provision_duress(&half_e, master_secret, vk, bootstrap_vk, duress_pin) {
            secure_log!("[DUAL/duress] se050.provision_duress FAILED: {:?}", e);
            half_o.zeroize();
            crate::fi::zeroize_barrier();
            half_e.zeroize();
            return Err(e);
        }

        half_o.zeroize();
        crate::fi::zeroize_barrier();
        half_e.zeroize();
        crate::fi::zeroize_barrier();
        secure_log!("[DUAL/duress] Provisioned decoy: entropy XOR-split across OPTIGA + SE050");
        Ok(())
    }

    #[cfg(feature = "duress-pin")]
    fn duress_is_provisioned(&mut self) -> bool {
        self.optiga.duress_is_provisioned() && self.se050.duress_is_provisioned()
    }

    /// §32 P3: attempt to unlock the DECOY wallet with `pin`. Reads both
    /// decoy halves (OPTIGA F1D9 via F1D8 auto-state auth; SE050
    /// `DURESS_ENTROPY_OBJ` via the duress UserID), reconstructs the decoy
    /// entropy, and returns the decoy master. Returns `Err(PinIncorrect)`
    /// if `pin` is not the duress PIN — the caller (`gated_unlock`) then
    /// falls through to the real `unlock`.
    ///
    /// Timing: BOTH chips' duress verifies run even when the first fails
    /// (no short-circuit), mirroring the three-counter-lockstep of the
    /// real `unlock` and keeping the op-count uniform across real/duress
    /// entries. The OPTIGA verify fires only LUC(E121) — the real E120 is
    /// never touched on a duress entry, so no lockout drift.
    #[cfg(feature = "duress-pin")]
    fn unlock_duress(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], UnlockError> {
        // OPTIGA returns (half_o, stored_decoy_master_from_F1DA); SE050
        // returns half_e. Both chips are ALWAYS verified (no `?` short-
        // circuit) so the op-count is uniform across real/duress entries.
        let ro = unsafe { self.optiga.duress_read_half(pin) };
        let re = self.se050.duress_read_half(pin);
        match (ro, re) {
            (Ok((mut half_o, mut stored_master)), Ok(mut half_e)) => {
                let mut full = xor_32(&half_o, &half_e);
                half_o.zeroize();
                crate::fi::zeroize_barrier();
                half_e.zeroize();
                crate::fi::zeroize_barrier();

                // FI cross-check (parity with the real `unlock`): the
                // master derived from the reconstructed decoy entropy MUST
                // equal the decoy master stored on-chip (F1DA). Defends a
                // glitch on the halve reads that yields wrong entropy.
                // Two `ct_eq` compares separated by `wait_random`, gated
                // through the hamming-distant sentinel.
                let derived_master = crypto::kdf(b"sphincs-master", &full, 0);
                let c1: bool = derived_master.ct_eq(&stored_master).into();
                crate::fi::wait_random();
                let c2: bool = derived_master.ct_eq(&stored_master).into();
                stored_master.zeroize();
                crate::fi::zeroize_barrier();
                if crate::fi::check_true_into_sentinel(|| c1 && c2) != crate::fi::OK_SENTINEL {
                    full.zeroize();
                    crate::fi::zeroize_barrier();
                    secure_log!("[DUAL/duress] CRITICAL: decoy entropy doesn't match stored master");
                    return Err(UnlockError::InternalError);
                }

                let blob = crypto::encrypt_entropy_blob(&full, &derived_master);
                self.entropy_blob_cache.copy_from_slice(&blob);
                self.blob_cached.set_true();
                full.zeroize();
                crate::fi::zeroize_barrier();
                secure_log!("[DUAL/duress] decoy wallet unlocked");
                Ok(derived_master)
            }
            (other_o, other_e) => {
                if let Ok((mut h, mut m)) = other_o {
                    h.zeroize();
                    m.zeroize();
                    crate::fi::zeroize_barrier();
                }
                if let Ok(mut h) = other_e {
                    h.zeroize();
                    crate::fi::zeroize_barrier();
                }
                Err(UnlockError::PinIncorrect)
            }
        }
    }

    /// §32 P3 timing PAD: run one duress verify on each chip (no read).
    /// Called on a duress-correct unlock to replace the SKIPPED real
    /// verify so the total op-count matches a real unlock (4 verifies +
    /// 2 reads either way). The OPTIGA verify is the matched-LUC twin of
    /// the real F1D0 verify; the SE050 verify twins the real UserID
    /// verify. Best-effort — a transient failure here doesn't fail the
    /// already-successful unlock; it only perturbs the timing pad.
    #[cfg(feature = "duress-pin")]
    fn duress_pad(&mut self, pin: &[u8; 8]) {
        let _ = unsafe { self.optiga.duress_verify(pin) };
        let _ = self.se050.duress_verify(pin);
    }

    fn unlock(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], UnlockError> {
        // Three-counter lockstep: call SE050 on every PIN attempt,
        // even when OPTIGA rejects it, so SE050's UserID silicon
        // counter advances in sync with MCU page-124 and OPTIGA E120
        // LUC. Skip SE050 only on a non-PIN OPTIGA error (I2C /
        // session fault) — don't burn an SE050 silicon attempt slot
        // for a transient comm glitch.
        //
        // OPTIGA stores master_secret explicitly; its `unlock` returns
        // what provision wrote — this is the authoritative value for
        // the consistency check below and for the final return.
        // SE050's `unlock` returns `kdf("sphincs-master", half_e, 0)`
        // which is meaningful here as the decrypt key for SE050's own
        // entropy_blob cache (different from OPTIGA's master).
        let optiga_result = self.optiga.unlock(pin);

        let se050_result = match &optiga_result {
            Ok(_) | Err(UnlockError::PinIncorrect) => {
                Some(self.se050.unlock(pin))
            }
            Err(_) => None,
        };

        // Resolve OPTIGA first. If OPTIGA rejected the PIN, zeroize
        // any master SE050 accidentally returned (pathological
        // desync: PIN matched SE050 but not OPTIGA — chip-swap or
        // out-of-band SE050 reset scenario) and propagate the OPTIGA
        // error to the caller BEFORE any downstream SE050 read path.
        let master_o = match optiga_result {
            Ok(mo) => mo,
            Err(e) => {
                if let Some(Ok(mut me)) = se050_result {
                    me.zeroize();
                }
                return Err(e);
            }
        };

        // OPTIGA accepted → SE050 was called. Resolve its result.
        let master_e = match se050_result
            .expect("OPTIGA Ok branch always calls SE050")
        {
            Ok(me) => me,
            Err(e) => {
                let mut m = master_o;
                m.zeroize();
                return Err(e);
            }
        };
        // Keep master_e alive — it's the key SE050 used to encrypt
        // its own entropy_blob cache. Zeroize after decrypt below.

        // Now reconstruct the full entropy from both halves, encrypt it
        // under master_secret, and cache the blob for the signing flow.
        //
        // Read half_O from OPTIGA (encrypted entropy blob → decrypt)
        // Read half_E from SE050 (encrypted entropy blob → decrypt)
        let mut blob_o = [0u8; 64];
        let blob_o_len = self.optiga.read_entropy_blob(&mut blob_o)
            .map_err(|_| UnlockError::InternalError)?;
        let mut half_o = crypto::decrypt_entropy_blob(
            &blob_o[..blob_o_len], &master_o
        ).map_err(|_| UnlockError::InternalError)?;
        blob_o.zeroize();
        // Under the inner wrap, what the SE stored (and we just decrypted) is
        // the 32-byte AES-GCM ciphertext; open it (ct + tag from the ct-store)
        // to recover the real half_O. The borrow in `&half_o` ends before the
        // re-assignment.
        #[cfg(feature = "mlkem-inner-wrap")]
        {
            half_o = crate::pq_wrap::open_half_from_se(
                crate::pq_wrap::HalfId::OptigaHalfO, 0, &half_o,
            )
            .map_err(|_| UnlockError::InternalError)?;
        }

        let mut blob_e = [0u8; 64];
        let blob_e_len = self.se050.read_entropy_blob(&mut blob_e)
            .map_err(|_| UnlockError::InternalError)?;
        // SE050's blob is encrypted under ITS master_secret
        // (`kdf("sphincs-master", half_e, 0)`), not OPTIGA's. The
        // two chips encrypt their caches independently; each must
        // be decrypted with the matching key.
        let mut half_e = crypto::decrypt_entropy_blob(
            &blob_e[..blob_e_len], &master_e
        ).map_err(|_| UnlockError::InternalError)?;
        blob_e.zeroize();
        // Same for half_E on the SE050.
        #[cfg(feature = "mlkem-inner-wrap")]
        {
            half_e = crate::pq_wrap::open_half_from_se(
                crate::pq_wrap::HalfId::Se050HalfE, 0, &half_e,
            )
            .map_err(|_| UnlockError::InternalError)?;
        }
        let mut me = master_e;
        me.zeroize();

        // Reconstruct the full entropy
        let mut full_entropy = xor_32(&half_o, &half_e);
        half_o.zeroize();
        crate::fi::zeroize_barrier();
        half_e.zeroize();
        crate::fi::zeroize_barrier();

        // Verify consistency: kdf("sphincs-master", full_entropy, 0) must
        // equal the master_secret we already got from both SEs.
        //
        // FI hardening: two independent `ct_eq` compares with a volatile
        // delay between, gated through `fi::check_true` so the boolean
        // cannot be faulted to `true` via a single skip.
        let derived_master = crypto::kdf(b"sphincs-master", &full_entropy, 0);
        let c1: bool = derived_master.ct_eq(&master_o).into();
        crate::fi::wait_random();
        let c2: bool = derived_master.ct_eq(&master_o).into();
        if crate::fi::check_true_into_sentinel(|| c1 && c2) != crate::fi::OK_SENTINEL {
            full_entropy.zeroize();
            crate::fi::zeroize_barrier();
            let mut mo = master_o;
            mo.zeroize();
            secure_log!("[DUAL] CRITICAL: reconstructed entropy doesn't match master!");
            return Err(UnlockError::InternalError);
        }

        // Cache the encrypted full-entropy blob for the signing flow.
        let blob = crypto::encrypt_entropy_blob(&full_entropy, &master_o);
        self.entropy_blob_cache.copy_from_slice(&blob);
        self.blob_cached.set_true();

        full_entropy.zeroize();
        crate::fi::zeroize_barrier();

        secure_log!("[DUAL] Unlocked: entropy reconstructed from XOR split");
        Ok(master_o)
    }

    fn read_entropy_blob(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.blob_cached.is_true_fi() || buf.len() < crypto::ENTROPY_BLOB_LEN {
            return Err(SeError::SlotNotFound);
        }
        buf[..crypto::ENTROPY_BLOB_LEN].copy_from_slice(&self.entropy_blob_cache);
        Ok(crypto::ENTROPY_BLOB_LEN)
    }

    fn read_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        // Both SEs store the same VK; read from SE050 (cached, no session overhead)
        self.se050.read_vk(buf)
    }

    fn read_bootstrap_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        self.se050.read_bootstrap_vk(buf)
    }

    fn remaining_attempts(&mut self) -> u8 {
        // Return the minimum of both SEs (more restrictive)
        let o = self.optiga.remaining_attempts();
        let e = self.se050.remaining_attempts();
        o.min(e)
    }

    fn sync_remaining_with_mcu(&mut self, mcu_used: u8) {
        self.optiga.sync_remaining_with_mcu(mcu_used);
        self.se050.sync_remaining_with_mcu(mcu_used);
    }

    fn zeroize_caches(&mut self) {
        self.entropy_blob_cache.zeroize();
        self.blob_cached.set_false();
        self.optiga.zeroize_caches();
        self.se050.zeroize_caches();
    }

    fn pin_attempt_count(&mut self) -> Option<u8> {
        // OPTIGA exposes a peek-safe counter (E120 in the production
        // `optiga-hw-counter` configuration). The production SE050 UserID
        // policy denies `ReadObjectAttributes` with SW=0x6986, so its leg is
        // `None`; see `Se050::pin_attempt_count_raw`.
        //
        // Combined value: MAX of whatever's available — counters
        // are "attempts USED" (higher = closer to lockout), so the
        // strict aggregate is `max`, not `min`. Reconciliation uses the
        // available count directionally (`se_used > mcu_used`), because the
        // MCU is precharged and may benignly lead. Intra-SE divergence is
        // meaningful only when both legs are actually readable.
        let o = self.optiga.pin_attempt_count();
        let s = self.se050.pin_attempt_count();
        match (o, s) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    fn pin_attempt_counts_divergent(&mut self) -> bool {
        // Tamper signal: OPTIGA and SE050 disagree on remaining attempts
        // even though both reported a value. Only flagged when both
        // Some — None on either side means "no readable counter, no
        // comparison possible," not divergence.
        match (
            self.optiga.pin_attempt_count(),
            self.se050.pin_attempt_count(),
        ) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        }
    }

    /// Legacy combined-SE helper for non-key protocol callers. Pull random
    /// bytes from both SEs and XOR-mix them in-place; per-source bytes never
    /// leave this function. Security-critical entropy does not use this
    /// already-combined result: `rng_strong` calls `random_optiga` and
    /// `random_se050` separately and verifies each contribution.
    ///
    /// **Strict (both-or-fail).** Both OPTIGA and SE050 MUST contribute.
    /// If either chip fails to provide entropy we return `Err` — the
    /// caller propagates that. Degrading to a single SE under EMFI / I2C
    /// glitching on one of the two buses would let an attacker reduce entropy to
    /// effectively two sources (STM32 + one SE) without anything
    /// noticing; refusing the call is the loud failure mode.
    fn random(&mut self, buf: &mut [u8]) -> Result<(), SeError> {
        let mut tmp = [0u8; 32];
        let mut off = 0;
        while off < buf.len() {
            let len = (buf.len() - off).min(tmp.len());

            // OPTIGA contribution — mandatory.
            self.optiga.random(&mut tmp[..len]).map_err(|_| {
                tmp.zeroize();
                SeError::InternalError
            })?;
            for i in 0..len {
                buf[off + i] ^= tmp[i];
            }
            // SE050 contribution — mandatory.
            tmp.zeroize();
            self.se050.random(&mut tmp[..len]).map_err(|_| {
                tmp.zeroize();
                SeError::InternalError
            })?;
            for i in 0..len {
                buf[off + i] ^= tmp[i];
            }
            tmp.zeroize();

            off += len;
        }
        Ok(())
    }

    fn random_optiga(&mut self, buf: &mut [u8]) -> Result<(), SeError> {
        self.optiga
            .random(buf)
            .map_err(|_| SeError::InternalError)
    }

    fn random_se050(&mut self, buf: &mut [u8]) -> Result<(), SeError> {
        self.se050
            .random(buf)
            .map_err(|_| SeError::InternalError)
    }

    /// Wipe both SEs via their admin recovery paths and clear SRAM caches.
    ///
    /// OPTIGA: `optiga.factory_reset()` overwrites every user OID through
    /// the shielded-connection path (`Change = Auto(F1D0) OR Conf(0xE140)`).
    /// Works even if the user PIN is forgotten. The DHUK-derived PBS remains
    /// reproducible and the shield stays available for re-provisioning; the
    /// user OIDs are now blank. No PBS is stored on flash page 126.
    ///
    /// SE050: delegates to its own `factory_reset_admin` which uses the
    /// admin UserID at 0x7B10_00A0 to delete user objects.
    ///
    /// A best-effort attempt is made on each backend — if one fails we
    /// still try the other and wipe SRAM state.
    fn factory_reset_admin(&mut self) -> Result<(), SeError> {
        let optiga_result = self.reset_optiga_for_admin();
        let se050_result = self.se050.factory_reset_admin();

        self.zeroize_caches();

        // Surface the first error we saw, but SRAM is zeroized regardless.
        optiga_result.and(se050_result)?;

        secure_log!("[DUAL] Factory reset complete — OPTIGA user data wiped, SE050 wiped");
        Ok(())
    }
}

impl DualSecureElement {
    /// End-to-end roundtrip test of the full dual-SE admin-wipe
    /// integration. Covers both: the XOR-split entropy reconstruction
    /// (unique dual-SE value-add) AND the `factory_reset_admin`
    /// dispatch that wipes both chips.
    ///
    /// Scope: `DualSecureElement::provision` + `DualSecureElement::
    /// unlock` + `DualSecureElement::factory_reset_admin`, all on
    /// real production OID ranges.
    ///
    /// Flow:
    /// 1. Pre-clean cascade (admin-auth → user-PIN → unauth). Tolerates
    ///    prior test contamination.
    /// 2. Verify both chips report `!is_provisioned()` after step 1.
    /// 3. Provision fresh test data: entropy=0x55 pattern, master_secret
    ///    derived via the same `kdf("sphincs-master", entropy, 0)` the
    ///    DualSE unlock path uses (so the consistency check passes),
    ///    vk=0xAA, bootstrap_vk=0xBB, pin=`b"dualwipe"`.
    /// 4. Verify both chips now report `is_provisioned()`.
    /// 5. Call `unlock(test_pin)` and verify the returned master_secret
    ///    byte-exactly matches what we provisioned. Proves both chips
    ///    authenticated AND the XOR reconstruction matches.
    /// 6. Call `factory_reset_admin()` — the production dispatch that
    ///    wipes both chips in sequence.
    /// 7. Verify both chips report `!is_provisioned()` post-wipe.
    /// 8. Call `unlock(test_pin)` again — must fail (no seed derivable
    ///    from a wiped pair).
    ///
    /// Uses the REAL production object ranges: OPTIGA F1D0..F1D4 + F1E1,
    /// SE050 0x7B10_xxxx (v6). This test DESTROYS any prior wallet
    /// state on both chips. Re-run the normal first-boot wizard
    /// afterwards to restore.
    ///
    /// LcsO-safety: the `dual-se-admin-wipe-e2e` feature MUST NOT imply
    /// `optiga-lock-operational`. All OPTIGA operations on the
    /// exercised paths stay at LcsO=Creation — `lock_oid` is a no-op
    /// under the default feature set.
    ///
    /// Robustness: relies on the conditional page-125 erase in
    /// `Se050::factory_reset_admin` (landed 2026-04-21) — an
    /// unconditional erase would desync flash admin PIN from chip
    /// admin UserID on any Transport glitch, stucking the v5 range
    /// the same way that bug stuck v3 and v4.
    #[cfg(feature = "dual-se-admin-wipe-e2e")]
    pub fn run_admin_wipe_roundtrip(&mut self) -> Result<(), SeError> {
        let test_entropy: [u8; 32] = [0x55; 32];
        let test_master = crate::crypto::kdf(b"sphincs-master", &test_entropy, 0);
        let test_vk: [u8; 32] = [0xAA; 32];
        let test_bvk: [u8; 32] = [0xBB; 32];
        let test_pin: [u8; 8] = *b"dualwipe";

        // ---- 1. Pre-clean ----
        //    Goal: normalise both chips to unprovisioned regardless of
        //    what the prior state is. Three cases we have to cover:
        //
        //    (a) Both chips already unprovisioned. No-op.
        //    (b) Both provisioned with matching admin PIN in flash. The
        //        normal production wipe path works. Just call
        //        `factory_reset_admin`.
        //    (c) SE050 provisioned but flash page 125 is erased (e.g.
        //        the prior `optiga-admin-wipe-e2e` run cleared it as
        //        post-test hygiene). `factory_reset_admin` falls
        //        through to `iterative_wipe(None, None)` which is
        //        unauthenticated — user objects with the two-entry
        //        TAG_POLICY cannot be deleted that way. We have to
        //        try user-PIN candidates to wipe SE050 `0x7B0E_xxxx`.
        //
        //    Strategy: OPTIGA unconditional (Conf(E140) always works),
        //    SE050 admin-first then user-PIN-fallback cascade. Erase
        //    page 125 at the end so `provision()` below generates a
        //    fresh admin PIN.
        secure_log!("[DUAL-E2E-ADMIN] step 1: pre-clean");

        // OPTIGA: Conf(E140) wipe. Idempotent on blank chips.
        if let Err(e) = self.reset_optiga_for_admin() {
            secure_log!("[DUAL-E2E-ADMIN] step 1: OPTIGA factory_reset error {:?} (continuing)", e);
        }

        // SE050 wipe cascade. Each stage only fires if the prior
        // stage left objects behind.
        //
        //   (a) Admin-auth factory reset (page 125 has admin PIN).
        //       Deletes user UserID + gated data + self-deletes admin
        //       UserID. The production PIN-lockout path.
        //   (b) User-auth factory reset with dev-PIN candidates. Tries
        //       `user_factory_reset(pin)` which verifies PIN, deletes
        //       user-gated data, AND self-deletes the user UserID in
        //       the same authenticated session. Plain
        //       `iterative_wipe(Some(USERID), Some(pin))` (which we
        //       tried first iteration) deletes the data objects but
        //       cannot self-delete the UserID itself — that's the
        //       exact gap the first hardware run surfaced.
        //   (c) Unauthenticated iterative sweep as a last-ditch
        //       catch-all for legacy objects without policies.
        //
        // Legacy objects in the 0x7b000xxx / 0x7b002xxx ranges that
        // the chip picked up from early-build firmware are permanently
        // stuck (user noted — specific range was bumped to skip them).
        // They will remain after pre-clean. That's fine: `is_provisioned`
        // only checks the current USERID_OBJ (0x7b10_0000), so the
        // stuck legacy objects don't affect the test.
        #[cfg(feature = "stm32u585")]
        unsafe {
            // Stage (a): admin-auth wipe via the v6 HUK-derived admin
            // PIN (`factory_reset_admin` → `secret_keys::se050_admin_pin`
            // → `derive_into_bhk(...)` — `SAES-CMAC(BHK, …)` in a `bhk`
            // build, `SAES-CMAC(DHUK, …)` with `saes-dhuk`, `HKDF(OTP-
            // master/const, …)` legacy — → `admin_factory_reset` →
            // conditional page-125 erase). This is the only admin-PIN
            // source on v6 chips; the pre-v6 page-125 PIN slot is gone
            // (no `write_admin_pin`).
            let r = self.se050.factory_reset_admin();
            secure_log!("[DUAL-E2E-ADMIN] pre-clean stage (a): factory_reset_admin → {:?}", r.as_ref().err());

            // Stage (b): user-PIN cascade if USERID_OBJ survived.
            let se_prov_before = self.se050.is_provisioned();
            secure_log!("[DUAL-E2E-ADMIN] pre-clean stage (b): se050.is_provisioned()={}", se_prov_before);
            if se_prov_before {
                const PIN_CANDIDATES: &[&[u8]] = &[
                    b"00000000", // e2e-test fast-path default (most common)
                    b"dualwipe", // our own test PIN (prior run)
                    b"12345678",
                    b"11111111",
                ];
                for &pin in PIN_CANDIDATES {
                    let r = self.se050.user_factory_reset(pin);
                    secure_log!(
                        "[DUAL-E2E-ADMIN] pre-clean stage (b): user_factory_reset({:?}) → {:?}",
                        core::str::from_utf8(pin).unwrap_or("?"),
                        r.as_ref().err(),
                    );
                    if r.is_ok() {
                        break;
                    }
                }
            }

            // Stage (c): unauthenticated sweep as final catch-all.
            let se_prov_mid = self.se050.is_provisioned();
            secure_log!("[DUAL-E2E-ADMIN] pre-clean stage (c): se050.is_provisioned()={}", se_prov_mid);
            let _ = self.se050.iterative_wipe(None, None);

            // Deliberately NO `erase_admin_page()` here. Page 125's
            // lifecycle is owned by `Se050::factory_reset_admin` (the
            // WalletStore wrapper), which now conditionally erases
            // only when the chip's admin UserID is confirmed gone.
            // Pre-clean's job is to get the chip to a state where
            // `provision()` can succeed — and provision handles every
            // page-125 state correctly as long as flash + chip are
            // paired.
            //
            // The earlier unconditional erase here is what stuck v4:
            // a Transport glitch in stage (a) left admin on the chip,
            // then the erase burned the matching flash PIN.
        }

        // ---- 2. Verify both chips unprovisioned after pre-clean ----
        if self.optiga.is_provisioned() {
            secure_log!("[DUAL-E2E-ADMIN] step 2 FAILED: OPTIGA still provisioned after pre-clean");
            return Err(SeError::InternalError);
        }
        if self.se050.is_provisioned() {
            secure_log!("[DUAL-E2E-ADMIN] step 2 FAILED: SE050 still provisioned after pre-clean");
            return Err(SeError::InternalError);
        }
        secure_log!("[DUAL-E2E-ADMIN] step 2: both chips unprovisioned after pre-clean OK");

        // ---- 3. Provision fresh test data ----
        secure_log!("[DUAL-E2E-ADMIN] step 3: provision");
        self.provision(&test_entropy, &test_master, &test_vk, &test_bvk, &test_pin)?;
        secure_log!("[DUAL-E2E-ADMIN] step 3: provision OK");

        // ---- 4. Verify both chips provisioned ----
        if !self.optiga.is_provisioned() {
            secure_log!("[DUAL-E2E-ADMIN] step 4 FAILED: OPTIGA not provisioned after provision");
            return Err(SeError::InternalError);
        }
        if !self.se050.is_provisioned() {
            secure_log!("[DUAL-E2E-ADMIN] step 4 FAILED: SE050 not provisioned after provision");
            return Err(SeError::InternalError);
        }
        secure_log!("[DUAL-E2E-ADMIN] step 4: both chips provisioned OK");

        // ---- 5. Pre-wipe unlock: master_secret roundtrip ----
        //    Authenticates both chips, reads both entropy halves, XORs
        //    them back, derives master_secret from full entropy, and
        //    cross-checks against what each chip returned. All three
        //    branches have to agree for unlock to return Ok.
        secure_log!("[DUAL-E2E-ADMIN] step 5: unlock");
        let recovered = match self.unlock(&test_pin) {
            Ok(m) => m,
            Err(e) => {
                secure_log!("[DUAL-E2E-ADMIN] step 5 FAILED: unlock returned {:?}", e);
                return Err(SeError::InternalError);
            }
        };
        if recovered != test_master {
            secure_log!("[DUAL-E2E-ADMIN] step 5 FAILED: master_secret mismatch post-unlock");
            return Err(SeError::InternalError);
        }
        secure_log!("[DUAL-E2E-ADMIN] step 5: unlock OK (master_secret matches)");

        // ---- 6. The wipe proper — production dispatch ----
        //    Calls `DualSecureElement::factory_reset_admin` (via the
        //    WalletStore trait on self). That cascades to OPTIGA's
        //    factory_reset (Conf(E140) path) + SE050's
        //    factory_reset_admin (admin-auth DELETE of user UserID
        //    and gated data, plus admin self-delete). Page 125 now
        //    only gets erased if admin UserID is confirmed gone from
        //    the chip (conditional erase, landed alongside this
        //    test).
        secure_log!("[DUAL-E2E-ADMIN] step 6: factory_reset_admin");
        self.factory_reset_admin()?;
        secure_log!("[DUAL-E2E-ADMIN] step 6: factory_reset_admin OK");

        // ---- 7. Verify both chips unprovisioned ----
        if self.optiga.is_provisioned() {
            secure_log!("[DUAL-E2E-ADMIN] step 7 FAILED: OPTIGA still provisioned after wipe");
            return Err(SeError::InternalError);
        }
        if self.se050.is_provisioned() {
            secure_log!("[DUAL-E2E-ADMIN] step 7 FAILED: SE050 still provisioned after wipe");
            return Err(SeError::InternalError);
        }
        secure_log!("[DUAL-E2E-ADMIN] step 7: both chips unprovisioned post-wipe OK");

        // ---- 8. Post-wipe unlock must fail ----
        //    The contract is "no seed derivable from a wiped pair."
        //    OPTIGA hits the sentinel path → NotProvisioned. SE050
        //    has no objects to read → auth fails. Either ERROR is
        //    fine; only Ok(_) is a test failure.
        match self.unlock(&test_pin) {
            Ok(_) => {
                secure_log!("[DUAL-E2E-ADMIN] step 8 FAILED: unlock SUCCEEDED after wipe");
                Err(SeError::InternalError)
            }
            Err(e) => {
                secure_log!("[DUAL-E2E-ADMIN] step 8: post-wipe unlock correctly failed ({:?})", e);
                Ok(())
            }
        }
    }

    /// Multi-unlock / cross-reboot validation for the SE050 entropy-
    /// corruption fix (PE0 RST, no more shield ENA cross-coupling).
    ///
    /// Flow:
    /// - If both chips already provisioned: reuse state (this is the
    ///   "we already booted once" branch — the interesting one).
    /// - Else: run the same pre-clean cascade as `run_admin_wipe_
    ///   roundtrip` then provision fresh.
    /// - Do `iterations` consecutive unlock() calls. Each one
    ///   re-authenticates both chips, reads both entropy halves, XORs
    ///   them, derives master_secret, cross-checks. All iterations
    ///   must return the SAME master_secret (== `test_master`). Any
    ///   drift between iterations flags SE050 NVM corruption.
    ///
    /// Does NOT wipe at the end — that's how we preserve state so the
    /// next cold boot (re-invocation of `probe-rs run`) can exercise
    /// the already-provisioned branch.
    #[cfg(feature = "dual-se-multi-unlock-e2e")]
    pub fn run_multi_unlock_roundtrip(&mut self, iterations: u32) -> Result<(), SeError> {
        let test_entropy: [u8; 32] = [0x55; 32];
        let test_master = crate::crypto::kdf(b"sphincs-master", &test_entropy, 0);
        let test_vk: [u8; 32] = [0xAA; 32];
        let test_bvk: [u8; 32] = [0xBB; 32];
        let test_pin: [u8; 8] = *b"dualwipe";

        // Probe by attempting an unlock with the test PIN. If both chips
        // are already provisioned with matching state from a prior boot,
        // this returns the expected master_secret and no pre-clean is
        // needed. Otherwise we fall through to wipe + fresh-provision.
        // `optiga.is_provisioned()` can't be used as the discriminator
        // because it needs the shielded connection up, which cold boot
        // hasn't established yet → false negative.
        secure_log!("[DUAL-MULTI] probing unlock() to detect prior provisioning...");
        let probe = self.unlock(&test_pin);
        match &probe {
            Ok(m) if m == &test_master => {
                secure_log!("[DUAL-MULTI] probe: Ok(master matches)");
            }
            Ok(_) => {
                secure_log!("[DUAL-MULTI] probe: Ok BUT master_secret mismatch — state corruption?");
            }
            Err(e) => {
                secure_log!("[DUAL-MULTI] probe: Err({:?})", e);
            }
        }
        let already_provisioned = matches!(probe, Ok(ref m) if *m == test_master);

        if already_provisioned {
            secure_log!("[DUAL-MULTI] boot state: ALREADY PROVISIONED (probe unlock matched)");
            secure_log!("[DUAL-MULTI] phase A: skipping pre-clean + provision");
            // The probe unlock counts as iteration 1; do N-1 more.
            secure_log!("[DUAL-MULTI] iter 1/{}: master_secret matches (via boot probe)", iterations);
            for i in 2..=iterations {
                let recovered = match self.unlock(&test_pin) {
                    Ok(m) => m,
                    Err(e) => {
                        secure_log!("[DUAL-MULTI] iter {}/{}: unlock FAILED {:?}", i, iterations, e);
                        return Err(SeError::InternalError);
                    }
                };
                if recovered != test_master {
                    secure_log!("[DUAL-MULTI] iter {}/{}: master_secret MISMATCH", i, iterations);
                    return Err(SeError::InternalError);
                }
                secure_log!("[DUAL-MULTI] iter {}/{}: master_secret matches", i, iterations);
            }
        } else {
            // Probe failed → chips are fresh / stale / mismatched. Wipe,
            // provision, then do `iterations` unlocks.
            if let Ok(_) = probe {
                secure_log!("[DUAL-MULTI] boot state: probe unlocked but master mismatched — reprovisioning");
            } else {
                secure_log!("[DUAL-MULTI] boot state: probe unlock FAILED → fresh provisioning");
            }

            if let Err(e) = self.reset_optiga_for_admin() {
                secure_log!("[DUAL-MULTI] pre-clean: OPTIGA factory_reset error {:?} (continuing)", e);
            }

            #[cfg(feature = "stm32u585")]
            unsafe {
                // Admin-auth wipe via the v6 HUK-derived admin PIN
                // (`secret_keys::se050_admin_pin` → `derive_into_bhk`,
                // i.e. BHK in a `bhk` build / DHUK / OTP-legacy).
                let _ = self.se050.factory_reset_admin();
                if self.se050.is_provisioned() {
                    const PIN_CANDIDATES: &[&[u8]] = &[
                        b"00000000", b"dualwipe", b"12345678", b"11111111",
                    ];
                    for &pin in PIN_CANDIDATES {
                        if self.se050.user_factory_reset(pin).is_ok() {
                            break;
                        }
                    }
                }
                let _ = self.se050.iterative_wipe(None, None);
            }

            if self.optiga.is_provisioned() {
                secure_log!("[DUAL-MULTI] pre-clean FAILED: OPTIGA still provisioned");
                return Err(SeError::InternalError);
            }
            if self.se050.is_provisioned() {
                secure_log!("[DUAL-MULTI] pre-clean FAILED: SE050 still provisioned");
                return Err(SeError::InternalError);
            }

            secure_log!("[DUAL-MULTI] pre-clean OK; provisioning fresh");
            self.provision(&test_entropy, &test_master, &test_vk, &test_bvk, &test_pin)?;
            secure_log!("[DUAL-MULTI] phase A: provision OK");

            for i in 1..=iterations {
                let recovered = match self.unlock(&test_pin) {
                    Ok(m) => m,
                    Err(e) => {
                        secure_log!("[DUAL-MULTI] iter {}/{}: unlock FAILED {:?}", i, iterations, e);
                        return Err(SeError::InternalError);
                    }
                };
                if recovered != test_master {
                    secure_log!("[DUAL-MULTI] iter {}/{}: master_secret MISMATCH", i, iterations);
                    return Err(SeError::InternalError);
                }
                secure_log!("[DUAL-MULTI] iter {}/{}: master_secret matches", i, iterations);
            }
        }

        secure_log!("[DUAL-MULTI] all {} unlocks verified; state preserved for next cold boot", iterations);

        // Clear stale MCU wipe-flag + PIN attempts left over from prior
        // failed `dual-se-admin-wipe-e2e` runs or from our own pre-clean.
        // Without this, the boot-time wipe trigger in `main.rs`
        // re-fires on every reboot, wiping both chips and defeating the
        // "cross-boot already-provisioned" branch this test is meant to
        // exercise. Safe because the chips are now provisioned cleanly
        // and SE050's admin UserID lifecycle is the pre-existing bug
        // tracked in `project_se050_admin_wipe.md`, not our concern.
        #[cfg(feature = "stm32u585")]
        unsafe {
            if crate::hw::flash::is_wipe_armed() {
                if crate::hw::flash::erase_admin_page().is_ok() {
                    secure_log!("[DUAL-MULTI] cleared stale wipe flag (page 125 erased)");
                }
            }
            let _ = crate::hw::flash::pin_attempts_reset();
        }

        Ok(())
    }
}

```


### `secure/src/nsc/mod.rs`

```rust
//! Secure gateway with trusted-UI sign confirmation.
//!
//! Two transports, selected at compile time by the `stm32u585` feature:
//!
//!   * **QEMU mps2-an505** (`not(feature = "stm32u585")`): SysTick-polled
//!     shared-memory mailbox. This is the workaround for QEMU 8.2.2's
//!     broken SG instruction check — `poll_gateway()` runs from the
//!     SysTick handler, reads `CMD`/`ARG0..2` out of NS SRAM, runs
//!     [`dispatch`], writes `RESULT`, and raises `DONE`.
//!   * **Real STM32U585** (`feature = "stm32u585"`): proper ARMv8-M
//!     CMSE `cmse-nonsecure-entry` veneers. The `--cmse-implib` linker
//!     pass emits SG stubs for every `nsc_*` entry point below into
//!     `veneers.o`; the non-secure crate links against that implib and
//!     calls them as regular `extern "C"` functions. There is no
//!     mailbox and no SysTick poll — NS issues `BLXNS` → SG →
//!     secure-state-handler → `BXNS` synchronously. The `cmd_*`
//!     handlers are shared across both transports; the only thing that
//!     changes is who pulls the trigger.
//!
//! Gateway commands are defined in `sphincs_tz_shared::CMD_*`; the
//! authoritative table lives in `CLAUDE.md`. Each command has its own
//! `cmd_*.rs` handler that the QEMU [`dispatch`] and STM32U585 CMSE
//! veneers below both call into.
//!
//! ## Layout
//!
//! This module is split along command boundaries so each `cmd_*` handler
//! lives in its own file and the shared plumbing (state, pointer
//! validation) lives alongside. Adding a new gateway command means
//! creating a new `cmd_*.rs` submodule, adding a match arm in
//! [`dispatch`] (and a CMSE veneer on stm32u585), and wiring up a new
//! `CMD_*` constant in `sphincs_tz_shared`.
//!
//!   * [`state`]         — single `SecureState` singleton + `with_state`
//!     closure accessors. The one and only place `static mut` lives.
//!   * [`ptr_validate`]  — NS SRAM/flash pointer + length validators.

mod batch_call_digest;
mod cmd_get_init_code;
mod cmd_get_remaining;
mod cmd_get_wallet_address;
mod cmd_is_unlocked;
mod cmd_lock;
mod cmd_offchain_status;
mod cmd_offchain_sync;
mod cmd_pin_attempt_log;
mod cmd_request_unlock;
mod cmd_sign_offchain;
mod cmd_sign_userop;
#[cfg(feature = "erc7730-forced-blind")]
mod cmd_sign_userop_forced;
mod cmd_sign_userop_batch;
#[cfg(feature = "e2e-test")]
mod cmd_test_pin_lockout;
#[cfg(all(feature = "stm32u585", feature = "e2e-test"))]
mod cmd_tzic_status;
#[cfg(feature = "prodtest")]
mod prodtest;

// Firmware-update commands. Only built for the STM32U585 target
// because they depend on the bank-2 flash / OTP primitives that the
// QEMU build doesn't model.
#[cfg(feature = "stm32u585")]
mod cmd_fw_abort;
#[cfg(feature = "stm32u585")]
mod cmd_fw_begin;
#[cfg(feature = "stm32u585")]
mod cmd_fw_chunk;
#[cfg(feature = "stm32u585")]
mod cmd_fw_commit;
#[cfg(feature = "stm32u585")]
mod cmd_fw_status;

mod batch_trailers;
mod factory_calldata;
mod ns_ptr;
mod ptr_validate;
mod sig_wrapper;
mod state;
mod trailer;

// Coldcard-class configuration fence: a production claim is valid only when
// the hardware platform and the complete three-source entropy backend are
// selected by value. In particular, `mode-production` without `stm32u585`
// would compile `rng.rs`'s QEMU `/dev/urandom` backend; checking only that an
// RNG-related macro/feature exists is not sufficient evidence of its value.
#[cfg(all(
    feature = "mode-production",
    any(
        not(feature = "stm32u585"),
        not(feature = "dual-se"),
        not(feature = "optiga-trust-m"),
        not(feature = "se050"),
    ),
))]
compile_error!(
    "PRODUCTION_ENTROPY_BACKENDS_REQUIRED: mode-production requires the \
     stm32u585 hardware TRNG plus dual-se (OPTIGA Trust M + SE050). Refusing \
     a production-declared image that could select host randomness or omit a \
     mandatory hardware entropy source."
);

// Refuse to build hardware images that also enable any of the dev-only
// features. `debug-log` and `ui-semihosting` leak secure-world state via
// the semihosting channel; `ui-mirror` streams the OLED over RTT;
// `ui-capture` emits per-frame SHA-256 fingerprints over the secure-log
// channel; `mock-se` substitutes an in-SRAM fake SE; the rest each
// replace some part of the production trust model with a dev-only
// shortcut. Any of these on a `stm32u585` release build is a
// ship-blocker.
//
// Hardware test images opt in by also enabling `e2e-test` (which exposes
// `set_e2e_unlocked` so the automated harness never needs to drive the
// PIN UI). `e2e-test` is the unambiguous "not-shippable" marker, so when
// it's on we permit the other dev features needed to drive the tests
// (`make e2e-hw`, `make test-key-speed`). CI must still gate shipped
// firmware on `e2e-test` being OFF.
#[cfg(all(
    feature = "stm32u585",
    not(debug_assertions),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
    any(
        feature = "debug-log",
        feature = "ui-semihosting",
        feature = "ui-capture",
        feature = "mock-se",
        feature = "otp-hardcoded-master-key",
        feature = "saes-self-test",
        feature = "uart-console",
        feature = "boot-pulse",
        feature = "bhk-hardcoded-master-key",
        feature = "se050-rotate-scp03",
        feature = "se050-scp03-allow-factory-fallback",
        feature = "sca-trigger",
    )
))]
compile_error!(
    "Hardware release builds (stm32u585 + !debug_assertions) must not enable \
     debug-log / ui-semihosting / ui-mirror / ui-capture / mock-se / \
     otp-hardcoded-master-key / bhk-hardcoded-master-key / saes-self-test / \
     uart-console / boot-pulse / se050-rotate-scp03 / \
     se050-scp03-allow-factory-fallback / sca-trigger. These \
     features leak secure-world state, replace the SE with a mock, replace \
     the per-device OTP master key or BHK with a shared compile-time \
     constant, halt the boot flow after a diagnostic, stream diagnostic \
     bytes on PA9 UART, pulse PE13 with boot-progress markers, perform a \
     one-shot irreversible SCP03 key-rotation ceremony then halt, fall back \
     to the published AN12436 factory SCP03 keys on a derived-key mismatch \
     (a fail-OPEN that hands the SE050 channel to attacker-known keys), or \
     toggle a GPIO around security-critical primitives so a ChipWhisperer / \
     NewAE-Scaffold rig can sync trace captures (a fatal leak on a \
     production unit). ERC-7730 dev provenance is guarded separately by the \
     generated root fence plus the mode-production fence below. Hardware test \
     images may opt in by also enabling \
     `e2e-test` (auto-provisioning, non-interactive) or `dev-testkey` \
     (interactive UI, OTP substituted with a compile-time constant)."
);

// ML-KEM inner-wrap ship gate (#28 piece 2b). `mlkem-inner-wrap` routes the
// dual-SE provision/reconstruct through the ML-KEM hybrid wrap, but its
// ct-store (`pq_wrap::ct_store`) is currently SRAM-backed — a QEMU-validation
// stand-in that is LOST on reboot, so a real device could provision but never
// unlock after a power cycle. The persistent flash ct-store + on-silicon
// validation of the hardware key path are piece 2b-d (NOT done). Forbid it on a
// production hardware release; single-boot bench/test images (e2e-test /
// dev-testkey) may opt in to validate the wrap on silicon. NOTE: the QEMU
// dev-key path (`pq_wrap::device_keys` under `not(stm32u585)`) is structurally
// impossible here — a hardware image is always `stm32u585`, which selects the
// real `hw::secret_keys` derivation, never the deterministic dev keys.
#[cfg(all(
    feature = "mlkem-inner-wrap",
    feature = "stm32u585",
    not(debug_assertions),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
))]
compile_error!(
    "mlkem-inner-wrap (#28 piece 2b) must not be in a production hardware \
     release: its ct-store is SRAM-backed (QEMU-validation only — lost on \
     reboot, so unlock-after-power-cycle would fail), and the persistent flash \
     ct-store + on-silicon hardware-key validation (piece 2b-d) are not done. \
     Bench it via a single-boot hardware test image (e2e-test / dev-testkey)."
);
// Belt-and-braces: the canonical ship profile must never carry it.
#[cfg(all(feature = "mode-production", feature = "mlkem-inner-wrap"))]
compile_error!(
    "mode-production and mlkem-inner-wrap are mutually exclusive (#28 piece \
     2b-d not done — SRAM ct-store). Remove mlkem-inner-wrap from production."
);

// Tier-1 channel-key REQUIRE-fence (finding F8c). The denylist fence above
// stops dev/leaky features shipping; this one stops a shipping dual-SE image
// going out with NON-Tier-1 channel-key roots. Without `saes-dhuk`,
// hw::secret_keys::derive_into uses the legacy OTP-master + HKDF arm (not
// SAES-CMAC(DHUK)); without `se050-derived-scp03`, se050::scp03::load_platform_keys
// returns the PUBLISHED AN12436 factory SCP03 keys. A default `make release`
// previously compiled both legacy roots silently — contrary to invariant #3
// (E2E-encrypted SE tunnels; no attacker-known keys on the channel). Make a
// missed opt-in a build error rather than a silent factory-key ship.
//
// Scoped to shipping dual-SE images (the production target). Bench/test images
// opt out via `e2e-test` / `dev-testkey` (the same not-shippable markers the
// denylist fence honours). `bhk` is intentionally NOT required here: enabling
// it without phase-2B silicon provisioning produces zero-keyed derivations, so
// the Tier-2 SE050 split stays a tracked follow-up, not a ship gate.
#[cfg(all(
    feature = "stm32u585",
    not(debug_assertions),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
    feature = "dual-se",
    any(not(feature = "saes-dhuk"), not(feature = "se050-derived-scp03")),
))]
compile_error!(
    "Shipping dual-SE hardware builds (stm32u585 + dual-se + !debug_assertions) \
     must enable BOTH `saes-dhuk` and `se050-derived-scp03` (Tier-1 channel-key \
     roots). Without `saes-dhuk` the SE-tunnel/pairing keys derive from the \
     legacy OTP-master + HKDF path instead of SAES-CMAC(DHUK); without \
     `se050-derived-scp03` the SE050 SCP03 channel uses the PUBLISHED AN12436 \
     factory keys — both violate invariant #3 (no attacker-known keys on the SE \
     channel). Add `saes-dhuk,se050-derived-scp03` to the build (they are in the \
     default RELEASE_FEATURES). Bench/test images opt out with `e2e-test` or \
     `dev-testkey`. Note: `bhk` (Tier-2 SE050 split) is a separate follow-up and \
     must NOT be enabled until phase-2B BHK provisioning exists, or derivations \
     are zero-keyed."
);

// Dedicated guard: `mode-production` + `erc7730-dev-unattested` is a
// contradictory trust claim. This feature does NOT relax an on-device
// attestation gate (none exists); it makes the display state that the
// firmware-pinned Merkle root was generated under the dev-unattested host
// policy. `db_roots.rs` carries a second, generated fence tying the feature to
// the exact root provenance. Production must use a genuinely ERC-8176-verified
// root and must never show the dev warning.
#[cfg(all(
    feature = "mode-production",
    feature = "erc7730-dev-unattested",
))]
compile_error!(
    "mode-production and erc7730-dev-unattested are mutually exclusive. \
     The feature truthfully marks a dev-unattested pinned catalogue and renders \
     its warning page; it does not enable or bypass an on-device verifier. \
     Shipping firmware requires a root generated by real ERC-8176 EAS \
     signature/identity verification, then must drop this feature."
);

// Production liveness fence. The secure-owned IWDG bounds a wedged NS USB
// loop, noninteractive gateway work, and disabled-interrupt deadlocks. Trusted
// physical-input waits receive only the independently idle-bounded exception
// in `hw::iwdg`; omitting the feature silently removes that fail-safe.
#[cfg(all(
    feature = "mode-production",
    feature = "stm32u585",
    not(feature = "iwdg"),
))]
compile_error!(
    "stm32u585 + mode-production requires `iwdg`. The production watchdog \
     bounds NS/secure hangs; trusted-UI waits remain limited by the 120 s \
     secure inactivity timer. Build both worlds through `make release`, which \
     enables the matching NS heartbeat feature."
);

// Forced blind adds signing authority and therefore has a narrower production
// configuration than ordinary clear signing. `iwdg` implies the exact
// STM32U585 Secure-alias implementation and the compile-time-pinned
// GTZC1_TZSC_SECCFGR1 bit-7 image in `sau.rs`; `ui-lcd` implies the physical
// GPIO buttons. P73S/Bloom are unconditional generated roots and the positive
// feature itself co-embeds P73K, so there is no permissive runtime artifact
// selector to fence here. The canonical production bundle separately keeps
// this feature forbidden until implementation review and #79 silicon closure.
#[cfg(all(
    feature = "mode-production",
    feature = "erc7730-forced-blind",
    any(
        not(feature = "stm32u585"),
        not(feature = "iwdg"),
        not(feature = "ui-lcd"),
    ),
))]
compile_error!(
    "ERC7730_FORCED_BLIND_PRODUCTION_PREREQUISITES: mode-production + \
     erc7730-forced-blind requires stm32u585, iwdg with Secure-only \
     GTZC1 bit-7 attribution/Secure alias, and the physical ui-lcd/button \
     backend. P73S/Bloom/P73K remain fixed generated artifacts. This source \
     fence is not #79 CPU/GPDMA silicon-denial evidence."
);

// Dedicated guard: `otp-hardcoded-master-key` + `optiga-lock-operational` is
// a specifically catastrophic combination. The lock feature irreversibly
// ratchets protected user-object metadata while the hardcoded-master-key
// feature makes the PBS a compile-time constant shared by every such device.
// Anyone knowing that constant can satisfy Conf(E140), so the supposedly
// locked object policy would be rooted in a published credential. Ordinary
// pairing no longer ratchets E140 itself, but this combination remains unsafe.
#[cfg(all(
    feature = "otp-hardcoded-master-key",
    feature = "optiga-lock-operational",
))]
compile_error!(
    "otp-hardcoded-master-key and optiga-lock-operational are mutually \
     exclusive. Enabling both would irreversibly lock protected objects while \
     their Conf(E140) authority is rooted in a shared compile-time PBS, \
     effectively publishing the Shielded Connection credential."
);

// The retained S-2 helper previously targeted the wrong OIDs and treated an
// omitted DataType tag as if it removed an existing TrustAnchor type. OPTIGA
// metadata updates are not yet proven to provide that replacement semantics,
// so compiling the would-be ceremony is unsafe. Keep the exact candidate
// inventory in the fail-closed helper for future silicon work, but do not emit
// a runnable irreversible image until type transition, data readback,
// lifecycle, and AC verification are all specified and validated.
#[cfg(all(feature = "mode-production", feature = "optiga-trust-m"))]
compile_error!(
    "OPTIGA_S2_PRODUCTION_BLOCKED: the real type-0x11 trust-anchor pool \
     E0E8/E0E9/E0EF and the device-certificate retype boundary remain OPEN. \
     No production OPTIGA image may compile until the exact closure ceremony \
     is implemented, reviewed, and silicon-validated. Enabling an \
     irreversible acknowledgement or `optiga-lock-operational` does not \
     satisfy this gate."
);

#[cfg(all(
    feature = "optiga-lock-operational",
    feature = "factory-production-irreversible-im-sure"
))]
compile_error!(
    "OPTIGA_TA_POOL_LOCKDOWN_BLOCKED: the S-2 trust-anchor neutralization \
     helper is not executable authority. The candidate pool is exactly \
     E0E8/E0E9/E0EF, but safe DataType replacement plus data/AC/lifecycle \
     readback has not been specified or silicon-validated. Do not build an \
     irreversible image until that ceremony is separately reviewed."
);

// Prodtest is a reversible acceptance-test image.  It must never share a
// build with a persistent-root, option-byte/shipping, SE-rotation, lifecycle,
// or factory ceremony path.  In particular, an acknowledgement feature is
// not authority to consume the BHK first write (which runs before prodtest's
// main-loop short-circuit) or mutate either secure element.  The safe prodtest
// profile uses `dev-testkey`; an unqualified prodtest build would use the real
// OTP-master path and is rejected here as well.
#[cfg(all(
    feature = "prodtest",
    any(
        feature = "bhk",
        feature = "se050-rotate-scp03",
        feature = "optiga-lock-operational",
        feature = "factory-provisioning",
        feature = "factory-provisioning-rehearsal",
        feature = "factory-production-irreversible-im-sure",
        feature = "mode-production",
        feature = "rdp-enforce-halt",
        feature = "tamp-wipe",
        feature = "tzic-wipe",
        not(any(feature = "dev-testkey", feature = "otp-hardcoded-master-key")),
    )
))]
compile_error!(
    "PRODTEST_PERSISTENT_ACTION_FORBIDDEN: `prodtest` is a reversible \
     acceptance-test profile and is unconditionally incompatible with real \
     BHK/OTP roots, option-byte or shipping profiles, SE key rotation, OPTIGA \
     lifecycle ratchets, persistent tamper-wipe handlers, and factory \
     ceremony features. An irreversible \
     acknowledgement does not relax this fence. Use the non-persistent \
     `prodtest,dev-testkey` profile; run any destructive experiment only in a \
     separately reviewed, owner-authorized sacrificial harness."
);

// Direct-Cargo defence for single-purpose reset/wipe/provision/stress images.
// These features replace normal boot with code that mutates persistent MCU or
// secure-element state. They are useful only as named bench harnesses and can
// never be composed with a production image, even if some other quarantine
// would also reject today's build.
#[cfg(all(
    feature = "mode-production",
    any(
        feature = "se050-factory-reset",
        feature = "se050-reset-e2e",
        feature = "se050-admin-wipe-e2e",
        feature = "se050-crash-safety-e2e",
        feature = "se050-admin-extract-attempt-e2e",
        feature = "se050-stress",
        feature = "optiga-admin-wipe-e2e",
        feature = "optiga-nuclear-reset",
        feature = "dual-se-admin-wipe-e2e",
        feature = "optiga-hw-counter-e2e",
        feature = "duress-probe-e2e",
        feature = "duress-provision-e2e",
        feature = "pin-gate-e2e",
        feature = "dual-se-multi-unlock-e2e",
        // Added 2026-09-24 with the ui-px-evt merge. `se-lcd-diag` replaces
        // normal boot, is terminal, and performs the SAME OPTIGA E140
        // pairing write a first boot performs — squarely this fence's
        // subject. `dev-dfu` is worse than destructive: two buttons at
        // power-up clear nSWBOOT0/nBOOT0 and drop the part into the ROM
        // USB-DFU bootloader, i.e. a physical-access firmware-replacement
        // path that bypasses the FSBL measured-boot chain of invariant #10.
        // Both were in the Makefile's PROD_FORBIDDEN and NOTHING else: a
        // direct `cargo build --features dev-dfu,mode-production` was
        // accepted, because the denylist is a Makefile-only barrier.
        feature = "se-lcd-diag",
        feature = "dev-dfu",
        // Frame-time overlay: prints render/blit timings over the trusted
        // display. Not destructive, but it paints over consent screens.
        feature = "ui-px-frametime",
    )
))]
compile_error!(
    "PRODUCTION_DESTRUCTIVE_HARNESS_FORBIDDEN: mode-production cannot include \
     any reset, wipe, persistent provisioning, stress, counter-mutation, or \
     stateful E2E harness. Use each feature only through its named bench target \
     and never on a unit intended to ship."
);

// Dedicated guard: `fw-rollback-e2e` is a dev/test image that embeds the dev
// vendor SIGNING seed and replaces `main()` with a self-contained
// anti-rollback test that halts. It must never coexist with `mode-production`.
#[cfg(all(feature = "mode-production", feature = "fw-rollback-e2e"))]
compile_error!(
    "mode-production and fw-rollback-e2e are mutually exclusive. \
     fw-rollback-e2e embeds the development vendor signing seed and short- \
     circuits boot into a firmware anti-rollback test — never a shipping image."
);

// Firmware-rollback backend quarantine. The legacy hardware implementation
// treated one ECC-protected OTP quad-word as a reusable per-bit tally, but
// STM32U585 user OTP permits only one program operation per 128-bit QW.
// FA-1.5 (Draft 1.1 §14 L4375) removed that runtime floor writer from
// `cmd_fw_commit` (the handler now refuses fail-closed; no epoch-bump
// success path exists in any build). Draft 1.1 remains the research
// candidate for replacement interfaces and deliberately leaves approval
// plus physical journal/ECC/OTP/resource gates open. It is not
// implementation authority.
//
// Shipping builds are blocked unconditionally. Bench images must carry a
// conspicuous no-behaviour-change opt-in (normally inherited from debug-log,
// mock-se, e2e-test, or otp-hardcoded-master-key). Factory provisioning is
// blocked separately because its entry and completion receipts reprogram the
// same OTP QW and therefore cannot complete on this MCU.
//
// CARVE-OUT (issue #541; see `secure/build.rs` for the full statement):
// the named §5 warning-build measurement profile links conservative
// reservation stubs that fail closed at runtime and has NO reachable
// epoch-bump success path — it is explicitly not a target of this
// quarantine.
#[cfg(all(feature = "mode-production", feature = "stm32u585"))]
compile_error!(
    "FW_ROLLBACK_PRODUCTION_BLOCKED: the legacy firmware rollback path \
     reprograms ECC-protected OTP quad-words. Approve and implement the \
     replacement contract, then close OPEN-JRN-HW/DUR, OPEN-FLASH-HW, \
     OPEN-ECC, OPEN-RAM, OPEN-OTP, release/factory, and silicon gates before \
     removing this fence."
);
#[cfg(all(
    feature = "stm32u585",
    not(feature = "mode-production"),
    not(feature = "legacy-fw-rollback-unsafe")
))]
compile_error!(
    "FW_ROLLBACK_UNSAFE_OPT_IN_REQUIRED: non-shipping STM32U585 builds that \
     still contain the legacy firmware rollback backend must explicitly \
     enable `legacy-fw-rollback-unsafe`."
);
#[cfg(all(feature = "stm32u585", feature = "factory-provisioning"))]
compile_error!(
    "FW_ROLLBACK_FACTORY_BLOCKED: factory provisioning and rehearsal are \
     disabled until the factory receipt stops reprogramming one write-once \
     STM32U585 OTP quad-word."
);

// Dedicated guard: `mode-production` + `ui-noop` (trusted-UI finding UI2,
// work-todo #12c). `ui-noop` is the silent headless Display/Input backend used
// only by dev/test targets (all of which also carry `e2e-test`/`mock-se`).
// Under the scroll-to-end `confirm()`, its `wait_button` returns `(Right,Short)`
// forever, so a headless build cannot obtain a genuine physical confirm — every
// sign would hang, or, if the hang were "fixed" by returning `(Right,Long)`,
// AUTO-CONFIRM every signature with zero physical consent (a total trusted-path
// bypass). A shipping image MUST drive a real display backend (`ui-lcd`).
#[cfg(all(feature = "mode-production", feature = "ui-noop"))]
compile_error!(
    "mode-production and ui-noop are mutually exclusive. ui-noop is the silent \
     headless UI backend (dev/test only): it cannot obtain a genuine physical \
     confirm — every sign would hang, or auto-confirm with zero user consent if \
     the hang were 'fixed'. Ship with a real display backend (`ui-lcd`)."
);

// Dedicated guard: `fwup-transport-e2e` is the over-USB FW-update transport
// e2e test. It short-circuits CMD_FW_COMMIT to stop *before* the OTP
// rollback-floor bump + boot-state write + sys_reset, so the chip stays
// reflashable. That short-circuit must never reach a shipping image — a
// production COMMIT that skips OTP would never raise the rollback floor.
#[cfg(all(feature = "mode-production", feature = "fwup-transport-e2e"))]
compile_error!(
    "mode-production and fwup-transport-e2e are mutually exclusive. \
     fwup-transport-e2e short-circuits CMD_FW_COMMIT before the OTP \
     bump + reboot so the test chip stays reflashable — never a shipping image."
);

// MED-2 ship gate (audits/tz-tamper-debug-20260611): `e2e-test` and
// `dev-testkey` are the two dev escape hatches that ship FIXED secrets —
// `e2e-test` auto-provisions a fixed mnemonic + PIN and short-circuits every
// secure-side confirm()/enter_pin(); `dev-testkey` substitutes the per-device
// OTP master key with a compile-time constant (it pulls in
// `otp-hardcoded-master-key`). Both turn OFF the main hardware-release fence
// above (it excludes them at the `not(feature = "e2e-test")` /
// `not(feature = "dev-testkey")` lines so `make e2e-hw` / `make
// play-hw-display` can drive the tests), so nothing else catches them in a
// shipping image. `mode-production` is the explicit "this is a shipping
// build" declaration; it must reject both. We key on `mode-production` ALONE
// (not the broader `stm32u585 + !debug_assertions` hardware-release condition
// used by the denylist above and one arm of the S-3 fence) because
// stm32u585+release+e2e-test IS the legitimate `make e2e-hw` hardware-test
// image. The belt-and-braces companion is `make prod-check`, which resolves
// the actual shipping feature set (catching a release built WITHOUT
// mode-production too) and is wired into `make release` + CI.
#[cfg(all(feature = "mode-production", feature = "e2e-test"))]
compile_error!(
    "mode-production and e2e-test are mutually exclusive (ship gate MED-2). \
     e2e-test auto-provisions a FIXED test mnemonic + PIN and short-circuits \
     every secure-side confirm()/enter_pin() — never a shipping image. Build \
     hardware-test images with `stm32u585,e2e-test` (no mode-production)."
);

#[cfg(all(
    feature = "mode-production",
    feature = "erc7730-nested-calldata-test-fixture"
))]
compile_error!(
    "mode-production cannot activate the synthetic ERC-7730 nested-calldata enrollment"
);
#[cfg(all(feature = "mode-production", feature = "dev-testkey"))]
compile_error!(
    "mode-production and dev-testkey are mutually exclusive (ship gate MED-2). \
     dev-testkey substitutes the per-device OTP master key with a shared \
     compile-time constant (via otp-hardcoded-master-key), so every unit built \
     with it derives identical admin / SCP03 / PBS secrets — never a shipping \
     image."
);

// S-3 ship-blocker: a production OPTIGA build MUST use the silicon E120 LUC
// counter (`optiga-hw-counter`). Without it the only PIN-attempt cap is the
// firmware soft counter at F1E1 + the MCU page-124 counter — both of which a
// desoldered / PBS-extracting bench attacker bypasses entirely (F1D0.Execute is
// ALW, so the chip answers unbounded HMAC-verify queries), giving an unbounded
// PIN brute force. Because the PIN is shared with the SE050, that defeats the
// whole wallet. Hardware TEST images may opt out via `e2e-test` / `dev-testkey`
// (they deliberately exercise the soft path); SHIPPING images may not.
#[cfg(all(
    feature = "optiga-trust-m",
    any(
        feature = "mode-production",
        all(feature = "stm32u585", not(debug_assertions)),
    ),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
    not(feature = "optiga-hw-counter"),
))]
compile_error!(
    "Production OPTIGA builds require `optiga-hw-counter` (ship-blocker S-3). \
     Without it the PIN attempt cap is a firmware soft counter the chip does \
     not enforce, so a desoldered / PBS-extracting bench attacker gets \
     unbounded HMAC-verify attempts against F1D0 and can brute-force the PIN. \
     Enable `optiga-hw-counter`, or build a non-shipping test image with \
     `e2e-test` / `dev-testkey`."
);

// S-2 quarantine: the retired recovery feature writes sample-certificate
// material and type-0x11 metadata to E0E3, but the observed object is a full
// type-0x12 device certificate.  The operation is therefore mis-targeted and
// destructive even in a dev build.  Keep the source only as incident evidence;
// no Cargo profile may compile it into a runnable image until a replacement is
// separately specified, reviewed, and authorized for named sacrificial parts.
#[cfg(feature = "optiga-reset-oids")]
compile_error!(
    "OPTIGA_RESET_OIDS_RETIRED: `optiga-reset-oids` is a mis-targeted E0E3 \
     recovery experiment and is unconditionally quarantined. The observed \
     E0E3 is a full type-0x12 device certificate, not the type-0x11 anchor \
     assumed by this path. No dev, test, factory, or production build may \
     execute it."
);

// S-1 candidate-profile diagnostic: the currently modeled hardened metadata
// uses `Change = Auto(F1D0)` + LcsO=Operational under
// `optiga-lock-operational` (the `Auto(F1D0)` bytes are wired at
// `optiga/apdu.rs:1080`). Without that class of closure F1D0 can remain
// rewritable: a desoldered-OPTIGA bench
// attacker overwrites the AuthRef HMAC key with a chosen one, self-authenticates,
// resets the E120 LUC counter, and brute-forces the PIN without bound — and
// because the PIN is shared with the SE050, that defeats the whole wallet.
//
// This diagnostic is DELIBERATELY keyed to `mode-production` ALONE — NOT the
// `all(stm32u585, not(debug_assertions))` belt-and-braces the S-2/S-3 fences
// use. `optiga-lock-operational` performs an IRREVERSIBLE LcsO ratchet (OPTIGA
// SRM: LcsO is monotonic, no reverse path), so it must never be added merely to
// clear this diagnostic or to a dev/test RELEASE hardware build:
// `make e2e-hw` / `play-hw-display` build `--release` (so `not(debug_assertions)`)
// WITHOUT `mode-production`, and forcing the ratchet on them would brick dev
// bench chips. The final E140 actor/order, credential rotation, recovery, and
// complete metadata ceremony remain OPEN. This fence models a candidate
// baseline; it grants no hardware, factory, or shipment authority.
//
// NOTE: this fence does not *fix* S-1. Closing S-1 requires a reviewed final
// lifecycle plus owner-authorized sacrificial validation. The unconditional
// rollback quarantine separately keeps current production images unavailable.
#[cfg(all(
    feature = "mode-production",
    feature = "optiga-trust-m",
    not(feature = "optiga-lock-operational"),
))]
compile_error!(
    "Candidate OPTIGA profile is incomplete without a reviewed S-1 metadata \
     closure. `optiga-lock-operational` is an irreversible sacrificial-test \
     candidate, NOT a production fix or instruction: do not enable it merely \
     to clear this diagnostic. The final E140/credential ordering and recovery \
     ceremony remain OPEN, and current production remains quarantined."
);

// work-todo #36 ship gate: a production build MUST enable `rdp2-self-lock`,
// the first-boot RDP-2 self-lock + on-device pairing rotation. Devices ship at
// RDP-0 (batch-uniform, user-verifiable over SWD before first power); the first
// field boot verifies the ship option-byte profile, self-locks RDP-2, and
// rotates the SE pairing secrets off the factory transport keysets — before
// the seed wizard. Without this feature a shipped unit would stay at RDP-0
// (debug open) forever and keep the public transport keysets as its live
// pairing secrets.
//
// Keyed to `mode-production` rather than `not(debug_assertions)`: release-mode
// bench builds are not shipping images. The converse guard immediately below
// also rejects `rdp2-self-lock` without `mode-production`, so the two features
// are coupled and no bench/dev build can carry the irreversible path.
#[cfg(all(feature = "mode-production", not(feature = "rdp2-self-lock")))]
compile_error!(
    "Production builds require `rdp2-self-lock` (work-todo #36): the first field \
     boot self-locks RDP Level 2 and rotates the SE pairing secrets off the \
     factory transport keysets, before the seed wizard. Without it a shipped \
     unit stays at RDP-0 (debug port open) with the public transport keysets as \
     its live SCP03/PBS/admin secrets. Release-mode bench builds remain outside \
     `mode-production` and therefore cannot carry the self-lock feature."
);

// The converse is equally important: never produce a flashable image carrying
// the irreversible self-lock path unless it is the explicit production
// configuration. Compile-only coverage lives in the pure host model while the
// production build remains quarantined by the independent rollback gate.
#[cfg(all(feature = "rdp2-self-lock", not(feature = "mode-production")))]
compile_error!(
    "RDP2_SELF_LOCK_REQUIRES_MODE_PRODUCTION: `rdp2-self-lock` contains the \
     irreversible RDP=0xCC and secure-element rotation path and must not compile \
     into a bench/dev image. Use the pure first_boot host tests until the \
     production rollback quarantine is closed."
);

// work-todo #36 anti-footgun: `rdp2-self-lock` must NEVER compile into a
// dev / QEMU / bench / test image — its first boot programs RDP=0xCC
// (irreversible) and rotates SE keys against the factory transport state. A
// bench board is not in that state, so a production FSBL on it would brick.
// `mock-se` / `*-hardcoded-master-key` would make the "rotate off the real
// transport keysets" step meaningless.
#[cfg(all(
    feature = "rdp2-self-lock",
    any(
        feature = "e2e-test",
        feature = "dev-testkey",
        feature = "mock-se",
        feature = "otp-hardcoded-master-key",
        feature = "bhk-hardcoded-master-key",
        feature = "factory-provisioning",
    ),
))]
compile_error!(
    "`rdp2-self-lock` (work-todo #36) is incompatible with dev/test features \
     (e2e-test / dev-testkey / mock-se / otp-hardcoded-master-key / \
     bhk-hardcoded-master-key / factory-provisioning). Its first \
     boot performs the IRREVERSIBLE RDP=0xCC burn and rotates SE pairing \
     secrets against the factory transport state — a bench/QEMU/test board is \
     not in that state and would self-brick. Build the production image without \
     these features, or a dev image without `rdp2-self-lock`."
);

// work-todo #36 config guard: `rdp2-self-lock` requires `dual-se`. Phase B
// rotates BOTH secure elements' pairing secrets (SE050 SCP03/admin + OPTIGA
// PBS) off the factory transport keysets. Without `dual-se` the Phase-B glue
// is compiled out while Phase A would still program RDP-2 — locking the device
// without ever provisioning it. `dual-se` is the shipping seed-split config
// (invariant #1) anyway, so this only rules out a broken bench combination.
#[cfg(all(feature = "rdp2-self-lock", not(feature = "dual-se")))]
compile_error!(
    "`rdp2-self-lock` (work-todo #36) requires `dual-se`: first-boot Phase B \
     rotates BOTH SEs' pairing secrets off the factory transport keysets. \
     Without `dual-se` the rotation glue is compiled out while Phase A still \
     locks RDP-2 — locking the device without provisioning it."
);

// SCA ship-blocker (audit secret-lifecycle 20260611, MEDIUM-3): a production
// hardware build MUST enable the power-consumption mask (`consumption-mask`).
// The ~7 s SPHINCS+C10 keygen/sign produces a characteristic power-draw
// signature a bench CPA/DPA rig can correlate against the WOTS chain seeds and
// FORS leaf secrets. `consumption-mask` drives a TIM2-CH1 PWM on PA5 whose duty
// is re-randomised from the SysTick handler, so the signature stays
// uncorrelated across the whole signing window; without it the only sign-path
// SCA defenses are the F-16 shuffle and the F-17 rate limiter. This mirrors the
// S-3 `optiga-hw-counter` pattern: the feature is not auto-composed, the fence
// forces a shipping build to opt in. Hardware TEST images may opt out via
// `e2e-test` / `dev-testkey` (they run non-shipping paths and keep timing
// deterministic); SHIPPING images may not.
#[cfg(all(
    feature = "stm32u585",
    not(debug_assertions),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
    not(feature = "consumption-mask"),
))]
compile_error!(
    "Production hardware builds (stm32u585 + !debug_assertions) require \
     `consumption-mask` (ship-blocker; audit secret-lifecycle 20260611 \
     MEDIUM-3). Without it the SPHINCS+C10 keygen/sign window runs with an \
     undiluted power signature, exposing the WOTS/FORS secrets to a bench \
     CPA/DPA attacker. Enable `consumption-mask` (it implies `stm32u585`; its \
     TIM2-CH1 PWM mask runs on PA5 — free on iota2, but SPI1_SCK, the LCD \
     clock, on pq1 — where the mask now runs on TIM3_CH1/PA6 instead; see the \
     module header in hw/consumption_mask.rs for what that does and does NOT \
     establish, since neither board drives a load from the mask pin and its \
     effectiveness is unmeasured), or build a non-shipping test image with \
     `e2e-test` / `dev-testkey`."
);

// MEDIUM-1 ship-blocker (audit tz-tamper 20260611): a production hardware
// build MUST enable tamper monitoring AND the production intrusion-response
// escalation on BOTH detectors — TAMP (`tamp` + `tamp-wipe`) and the GTZC1
// illegal-access controller (`tzic-wipe`). Without `tamp` the device does
// ZERO tamper detection; with `tamp` but without `tamp-wipe` / `tzic-wipe` a
// detected tamper (voltage / clock glitch, ITAMP9 crypto-peripheral-fault FI
// canary, SWD-at-RDP>0) or an NS->secure illegal access is merely logged and
// the device continues — the zeroize-SRAM + arm-wipe-flag + reset response
// (`hw::tzic::trigger_intrusion_wipe`) never fires, so a fault-injection
// campaign against the SAES/PKA/TRNG gets unbounded attempts with no penalty.
// Keyed on `dual-se` (the production seed-split SE config, invariant #1) so
// the fence targets shipping images only and never forces a brick-on-tamper
// response onto mock / single-SE bench builds — mirrors how the
// `optiga-hw-counter` / `se050-derived-scp03` fences key on their backend.
// These features are not auto-composed, so the fence forces a shipping build
// to opt in. Hardware TEST images may opt out via `e2e-test` / `dev-testkey`
// (they keep the log-only path so a probe-rs glitch session doesn't wipe the
// bench chip).
#[cfg(all(
    feature = "dual-se",
    any(
        feature = "mode-production",
        all(feature = "stm32u585", not(debug_assertions)),
    ),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
    not(all(feature = "tamp", feature = "tamp-wipe", feature = "tzic-wipe")),
))]
compile_error!(
    "Production dual-SE builds require `tamp` + `tamp-wipe` + `tzic-wipe` \
     (ship-blocker; audit tz-tamper 20260611 MEDIUM-1). Without them a \
     detected tamper (voltage/clock glitch, ITAMP9 crypto-peripheral fault, \
     SWD-at-RDP>0) or an NS->secure illegal access is only logged — the \
     zeroize-SRAM + arm-wipe-flag + reset intrusion response never fires, so \
     a fault-injection campaign gets unbounded attempts with no penalty. \
     Enable `tamp` + `tamp-wipe` + `tzic-wipe` (add `tamp-irq` for \
     lowest-latency response), or build a non-shipping test image with \
     `e2e-test` / `dev-testkey`."
);

// HIGH-1 ship-blocker (audit se-tunnels 20260611): a candidate production
// configuration MUST at minimum root its current transport SCP03 channel in
// per-device derived transport keys (`se050-derived-scp03`), not
// the published AN12436 factory keyset. Without the feature,
// `scp03::load_platform_keys` returns `PLATFORM_{ENC,MAC,DEK}` — the public
// SE050C2 OEF-0xA201 constants — and `establish()` derives the session keys from
// them, so a logic analyzer on I2C1 reconstructs `s_enc`/`s_rmac` from the
// on-wire SCP03 handshake challenges and DECRYPTS `half_E` (the SE050 seed share)
// out of every unlock. `scp03_logic.rs` says it outright: such a channel is
// "plaintext-equivalent to a bus sniffer with the datasheet". Invariant #3 break;
// weakens #1. Mirrors the S-3 `optiga-hw-counter` pattern — the feature is not
// auto-composed, so this fence records a candidate-profile prerequisite. It
// does not authorize the sacrificial `se050-rotate-scp03` PUT KEY path or any
// write to a real unit. This fence is necessary but not sufficient:
// it does not implement the still-open fresh-TRNG production-final rotation,
// durable public state, cut recovery, or coordinated E140 ordering. `dual-se`
// implies `se050`, so this also covers the candidate dual-chip build. NOTE:
// fencing out the *fallback* fail-OPEN
// (`se050-scp03-allow-factory-fallback`, above) shut the back door; this shuts
// the front door — shipping with the feature simply OFF. Hardware TEST images
// may opt out via `e2e-test` / `dev-testkey`.
#[cfg(all(
    feature = "se050",
    any(
        feature = "mode-production",
        all(feature = "stm32u585", not(debug_assertions)),
    ),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
    not(feature = "se050-derived-scp03"),
))]
compile_error!(
    "Candidate SE050 profile is incomplete without non-public SCP03 transport \
     keys (ship-blocker; audit se-tunnels 20260611 HIGH-1). Without \
     `se050-derived-scp03` the static keys are the \
     PUBLISHED AN12436 factory constants (`PLATFORM_{ENC,MAC,DEK}`), so the SE050 \
     secure channel is plaintext-equivalent to a bus sniffer holding the \
     datasheet: a logic analyzer on I2C1 reconstructs the session keys from the \
     on-wire SCP03 handshake challenges and decrypts `half_E` out of every unlock \
     (invariant #3 break, weakens #1). The existing derived-key/PUT-KEY path is \
     sacrificial evidence only; do not run it or enable features merely to clear \
     this diagnostic. The fresh-TRNG final rotation, durable state, cut recovery, \
     and coordinated E140 ordering remain OPEN; current production is quarantined."
);

// MEDIUM-1 ship-blocker (audit se-tunnels 20260611): `optiga-no-shield` turns
// `ensure_shield()` into a no-op and routes every OPTIGA APDU through the
// plaintext `send_command` branch, so `half_O` (the OPTIGA seed share) and the
// PIN-auth HMAC challenge/response transit I2C in cleartext — a bus attacker
// reads the OPTIGA seed share directly off the wire (invariant #3 break, weakens
// #1). It is a dev affordance for a bricked/unreachable E140 and must never reach
// a shipping image. Same shape as the S-2 `optiga-reset-oids` fence. Hardware
// TEST images may opt out via `e2e-test` / `dev-testkey`.
#[cfg(all(
    feature = "optiga-no-shield",
    any(
        feature = "mode-production",
        all(feature = "stm32u585", not(debug_assertions)),
    ),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
))]
compile_error!(
    "`optiga-no-shield` must not ship (ship-blocker; audit se-tunnels 20260611 \
     MEDIUM-1): it disables the Shielded Connection entirely, so `half_O` and the \
     PIN-auth APDUs transit I2C in plaintext and a bus attacker reads the OPTIGA \
     seed share directly off the wire (invariant #3 break, weakens #1). Drop \
     `optiga-no-shield` from production builds, or build a non-shipping test image \
     with `e2e-test` / `dev-testkey`."
);

// ---------------------------------------------------------------------------
// UI-axis mutual exclusivity (Phase 2)
//
// `ui-semihosting`, `ui-oled`, and `ui-noop` are mutually exclusive UI
// *backends* — exactly one provides the `Display` and `Input` types that
// `secure/src/ui/mod.rs` re-exports. The `ui-mirror` flag sits on top of
// `ui-oled` (it implies it) and `ui-capture` sits on top of any backend
// (it emits a SHA-256 hash of every flushed frame as a side effect), so
// those two compose with the backend axis rather than competing with it.
//
// Combining two backends compiles today (the first cfg-match wins
// silently), which is footgun-shaped. This fence makes "two backends"
// a build error.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "ui-semihosting", feature = "ui-noop"))]
compile_error!(
    "UI backends `ui-semihosting` and `ui-noop` are mutually exclusive. \
     Pick exactly one."
);

#[cfg(all(feature = "ui-lcd", feature = "ui-semihosting"))]
compile_error!(
    "UI backends `ui-lcd` and `ui-semihosting` are mutually exclusive. \
     Pick exactly one."
);

#[cfg(all(feature = "ui-lcd", feature = "ui-noop"))]
compile_error!(
    "UI backends `ui-lcd` and `ui-noop` are mutually exclusive. Pick exactly \
     one. (`ui-lcd` became a standalone Display backend in Phase C; the old \
     Phase A/B `ui-lcd`+`ui-noop` pairing is no longer valid.)"
);

// Four `ui-oled-bench` mutual-exclusion fences stood here (vs `ui-capture`,
// `ui-lcd`, `ui-semihosting`, `ui-noop`) until 2026-09-23. They died with the
// backend, not with the rule: the "exactly one UI backend" requirement is
// still enforced below, and `ui-lcd`/`ui-semihosting`/`ui-noop` remain
// mutually exclusive through their own fences.
//
// `ui-px-evt` added a fifth, `ui-px` vs `ui-oled-bench`; it went the same way
// for the same reason. His PRODUCTION fence below is kept — it is about the
// trusted display, not about the dead bench backend.

#[cfg(all(feature = "mode-production", feature = "ui-px", not(feature = "ui-lcd")))]
compile_error!(
    "`ui-px` in a `mode-production` image requires the physical NV3007 (`ui-lcd`): \
     the text presenter is a QEMU / bench aid, not a trusted display."
);

// At least one UI backend must be selected when targeting actual hardware
// or QEMU. (Pure `cargo test -p sphincs-tz-secure --tests` builds run on
// the host with neither stm32u585 nor any UI backend — those are exempt
// because they exercise pure-logic modules only.)
#[cfg(all(
    not(test),
    target_arch = "arm",
    not(any(
        feature = "ui-semihosting",
        feature = "ui-noop",
        feature = "ui-lcd",
    ))
))]
compile_error!(
    "Exactly one UI backend must be selected: `ui-semihosting`, `ui-noop` or \
     `ui-lcd`. (`ui-capture` composes with any backend.) The bench-only \
     `ui-oled-bench` SSD1306 backend was removed 2026-09-23."
);

// ---------------------------------------------------------------------------
// Secure-element-axis mutual exclusivity (Phase 2)
//
// `dual-se` is the explicit "both production SEs simultaneously" build,
// implemented as `dual-se = ["optiga-trust-m", "se050"]`. Outside of
// `dual-se`, exactly one of {mock-se, se050, optiga-trust-m}
// must be selected.
//
// The selection is done in `secure/src/main.rs` today by a chain of
// `#[cfg(all(feature = "mock-se", not(feature = "se050"), ...))]` blocks
// (negative-condition voting) — i.e., simultaneous selection compiles
// silently with a "first match wins" semantics. Make it loud here.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "mock-se", feature = "se050"))]
compile_error!(
    "Secure-element backends `mock-se` and `se050` are mutually exclusive. \
     Pick exactly one."
);

#[cfg(all(feature = "mock-se", feature = "optiga-trust-m"))]
compile_error!(
    "Secure-element backends `mock-se` and `optiga-trust-m` are mutually \
     exclusive. Pick exactly one. (Note: `dual-se` implies both `optiga-trust-m` \
     and `se050`, so combining `mock-se` with `dual-se` is also forbidden.)"
);

// At least one SE backend must be selected when targeting hardware or QEMU.
#[cfg(all(
    not(test),
    target_arch = "arm",
    not(any(
        feature = "mock-se",
        feature = "se050",
        feature = "optiga-trust-m",
        feature = "dual-se",
    ))
))]
compile_error!(
    "Exactly one secure-element backend must be selected: `mock-se`, \
     `se050`, `optiga-trust-m`, or `dual-se`."
);

#[cfg(not(feature = "stm32u585"))]
use sphincs_tz_shared::{
    NscStatus, CMD_GET_INIT_CODE, CMD_GET_REMAINING, CMD_GET_WALLET_ADDRESS, CMD_IS_UNLOCKED,
    CMD_LOCK, CMD_NONE, CMD_OFFCHAIN_STATUS, CMD_OFFCHAIN_SYNC, CMD_REQUEST_UNLOCK,
    CMD_SIGN_OFFCHAIN, CMD_SIGN_USEROP, CMD_SIGN_USEROP_BATCH, SHARED_MAILBOX_BASE,
};

// ---------------------------------------------------------------------------
// Shared-memory mailbox layout (QEMU NS SRAM, derived from shared crate
// constants). Only used on the QEMU transport; the STM32U585 build uses
// CMSE veneers and never touches the mailbox.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "stm32u585"))]
const SHARED_CMD: *mut u32 = SHARED_MAILBOX_BASE as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_ARG0: *mut u32 = (SHARED_MAILBOX_BASE + 4) as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_ARG1: *mut u32 = (SHARED_MAILBOX_BASE + 8) as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_ARG2: *mut u32 = (SHARED_MAILBOX_BASE + 12) as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_RESULT: *mut u32 = (SHARED_MAILBOX_BASE + 16) as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_DONE: *mut u32 = (SHARED_MAILBOX_BASE + 20) as *mut u32;

/// Arguments handed to a `cmd_*` handler. On the QEMU transport these
/// are read out of the shared mailbox in [`poll_gateway`] before
/// dispatch runs (a TOCTOU snapshot so NS can't race the validator).
/// On the STM32U585 CMSE transport they're just the three `u32`
/// register arguments of the `nsc_*` veneer wrapped into a struct so
/// the shared `cmd_*::run` bodies can stay identical across transports.
pub(super) struct GatewayArgs {
    pub(super) arg0: u32,
    pub(super) arg1: u32,
    pub(super) arg2: u32,
}

// ---------------------------------------------------------------------------
// Public API consumed by `secure/src/main.rs`
// ---------------------------------------------------------------------------

/// Whether the device is currently unlocked (PIN verified this session).
pub fn is_unlocked() -> bool {
    state::peek_state(|s| s.pin_verified.is_true_fi())
}

/// Is there definitely nothing to wipe? (#802)
///
/// The INVERSE of `is_unlocked`, and deliberately not its negation. This
/// answers "is the device in the exact, intact, locked state?" — so a
/// corrupted or torn `pin_verified` answers `false` and the caller wipes,
/// where `!is_unlocked()` would answer `true` and let secrets sit.
///
/// Cheap by design: two volatile loads, no TRNG, no random delay. It is
/// called from SysTick at 1 kHz; `is_true_fi` there cost 25.7% of the CPU
/// and defended nothing the per-tick repetition did not already defend.
#[must_use]
pub fn is_definitely_locked() -> bool {
    state::peek_state(|s| s.pin_verified.is_exactly_false())
}

/// Shared TOCTOU snapshot buffer for the three mutually-exclusive sign
/// handlers (`cmd_sign_userop`, `cmd_sign_userop_batch`,
/// `cmd_sign_offchain`). Each used to own a private `static mut SNAP_BUF`
/// sized to its own protocol maximum (≈25 KB / ≈41 KB / ≈5.7 KB). Because
/// the dispatcher is single-threaded and non-reentrant (see
/// [`HandlerGuard`] / [`handler_is_busy`]) exactly one of these handlers
/// can be live at a time, so the three buffers were never simultaneously
/// in use — they only ever cost permanent BSS.
///
/// Reserving all three independently pushed `.bss` up against the top of
/// the 128 KB secure SRAM, leaving the deep `cmd_sign_userop` register-slot
/// path (slot keygen + bootstrap keygen + two FI-doubled C10 signs, each
/// holding several KB of stack buffers) with too little stack headroom: at
/// its deepest the stack grew down past the BSS top and clobbered the
/// adjacent `state::SLOT_CACHE` (its discriminant zeroed → `None`), making
/// the Type-2 sign read an empty cache and return `InternalError`. Folding
/// the snapshots into one buffer sized to the largest claimant reclaims the
/// two idle copies (~31 KB of BSS) and restores ample stack headroom.
///
/// Each handler still validates its own payload length against its own
/// protocol-max constant before copying; a `const` assert in each pins
/// that constant ≤ [`SIGN_SNAP_BUF_LEN`] so an oversized handler can never
/// silently overrun the shared buffer.
pub(super) const SIGN_SNAP_BUF_LEN: usize =
    sphincs_tz_shared::SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN;

/// The shared snapshot storage itself. Only ever borrowed (filled, parsed,
/// then wiped) inside a single handler invocation, under the non-reentrant
/// dispatcher — never aliased across handlers.
pub(super) static mut SIGN_SNAP_BUF: [u8; SIGN_SNAP_BUF_LEN] = [0u8; SIGN_SNAP_BUF_LEN];

/// The pixel-UI screen transcript (`ui-px`) is NOT a static of its own: it
/// overlays the tail of [`SIGN_SNAP_BUF`] that the single-sign handler never
/// fills (its snapshot maximum is well below the batch maximum the buffer is
/// sized for). Costing ~10 KB of BSS instead collided with the batch
/// handler's stack on QEMU's 128 KB SRAM — the exact BSS-vs-stack class the
/// shared buffer exists to prevent. The single handler splits its snapshot
/// off the front of the buffer and hands the remainder here.
#[cfg(feature = "ui-px")]
const _: () = assert!(core::mem::align_of::<pqsigner_ui_px::Screens>() == 1);

/// View a scratch byte region as the screen transcript (no copy). `None`
/// when the region is too small.
#[cfg(feature = "ui-px")]
fn px_screens_view(scratch: &mut [u8]) -> Option<&mut pqsigner_ui_px::Screens> {
    if scratch.len() < pqsigner_ui_px::SCREENS_BYTES {
        return None;
    }
    let p = scratch.as_mut_ptr().cast::<pqsigner_ui_px::Screens>();
    // SAFETY: `Screens` is `#[repr(C)]`, alignment 1 (asserted above), made
    // only of `u8` arrays so every bit pattern is a valid value, and the
    // region is at least `SCREENS_BYTES` long. The unique `&mut [u8]` borrow
    // is reborrowed for the returned lifetime, so no other reference to those
    // bytes is live meanwhile.
    Some(unsafe { &mut *p })
}

/// Confirm a sign request through the pixel UI: build the screen transcript
/// from the SAME verified inputs the legacy pages were built from, bind it
/// to the already-proven `pages`, and run the design's confirm loop.
///
/// The legacy `pages` stay the proof substrate: every dispatcher / trailer
/// `*_proof` has already run over them. The lift (`tx::display::px_lift`)
/// re-emits the route body (Safe, a single-UserOp family, or the rotation
/// consent) AND the handler's trailers as design screens (twice,
/// hash-compared; every trailer screen derived from the same page builder as
/// its proven page), appends the returning hero and the design's `Confirm?`,
/// and proves the assembly — no `Legacy` record anywhere — before anything
/// is shown. Any failure is a refusal — never a fall-back to the page
/// dialog.
#[cfg(feature = "ui-px")]
pub(super) fn px_confirm(
    scratch: &mut [u8],
    pages: &crate::tx::display::Pages,
    inputs: &crate::tx::display::px_lift::ContentInputs<'_>,
) -> Result<(crate::ui::confirm::ConfirmResult, u32), &'static str> {
    use crate::tx::display::px_lift;
    let screens = px_screens_view(scratch).ok_or("px scratch")?;
    let receipt = px_lift::emit_content(screens, inputs).map_err(|()| "px body")?;
    let body_len = receipt.body.legacy_pages;
    px_lift::append_returning_hero(screens).map_err(|()| "px hero")?;
    let confirm_at = px_lift::insert_confirm(screens, &receipt.family).map_err(|()| "px confirm")?;
    crate::fi::scrub_sentinel_register();
    let verdict =
        px_lift::transcript_proof(screens, pages, &inputs.body, body_len, &receipt, inputs.trailers, confirm_at);
    crate::fi::scrub_sentinel_register();
    if verdict != crate::fi::OK_SENTINEL {
        return Err("px transcript");
    }
    // The glyph atlas is a WYSIWYS input that lives in the NS slot: prove it
    // against the pinned root right before the dialog paints with it, and
    // again after the user's answer — a swap during the dialog is a refusal.
    #[cfg(feature = "ui-lcd")]
    let atlas = crate::ui::px::assets::verify_atlas().map_err(|()| "px atlas")?;
    #[cfg(not(feature = "ui-lcd"))]
    let atlas = ();
    // The endings (decline resolve, signing film) wear this family's disc
    // and captions.
    #[cfg(feature = "ui-lcd")]
    crate::ui::px::lcd::set_film_look(
        receipt.family.look,
        receipt.family.signed,
        receipt.family.declined,
        receipt.family.failed,
    );
    let out = crate::ui::px::confirm_screens_checked(screens, &atlas);
    // The transcript holds no secret, but leave nothing stale behind.
    screens.volatile_poison_and_reset();
    #[cfg(feature = "ui-lcd")]
    {
        drop(atlas);
        crate::fi::scrub_sentinel_register();
        if crate::ui::px::assets::atlas_root_proof() != crate::fi::OK_SENTINEL {
            return Err("px atlas changed");
        }
        crate::fi::scrub_sentinel_register();
    }
    Ok(out)
}

/// A pixel consent outside the sign path (port step 4: the firmware
/// update's two consents). `build` writes the transcript into the shared
/// snapshot buffer — free here: no sign handler is running under the
/// non-reentrant dispatcher — the design's flow rules are checked
/// (`check::check_flow`), and the dialog runs against a freshly verified
/// atlas that is re-proven after the answer. `Err` = the pixel path cannot
/// run (no verified atlas, a transcript error): the caller shows its page
/// dialog instead, whose glyphs are secure-resident — a broken NS atlas
/// must never make the firmware update, the way to repair it, unreachable.
#[cfg(feature = "ui-px")]
pub(crate) fn px_confirm_plain(
    build: impl FnOnce(&mut pqsigner_ui_px::Screens) -> Result<(), ()>,
) -> Result<(crate::ui::confirm::ConfirmResult, u32), &'static str> {
    #[cfg(feature = "ui-lcd")]
    let atlas = crate::ui::px::assets::verify_atlas().map_err(|()| "px atlas")?;
    #[cfg(not(feature = "ui-lcd"))]
    let atlas = ();
    // SAFETY: single-threaded dispatcher; only sign handlers borrow the
    // shared snapshot buffer and none is in flight during this handler, so
    // this is the unique reference for the duration of the dialog.
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(SIGN_SNAP_BUF) };
    let screens = px_screens_view(buf).ok_or("px scratch")?;
    if build(screens).is_err() || pqsigner_ui_px::check::check_flow(screens).is_err() {
        screens.volatile_poison_and_reset();
        return Err("px transcript");
    }
    // No film plays on these consents (nothing is signed); the handler's own
    // status (CANCELED, …) follows the answer.
    let out = crate::ui::px::confirm_screens_checked(screens, &atlas);
    screens.volatile_poison_and_reset();
    #[cfg(feature = "ui-lcd")]
    {
        drop(atlas);
        crate::fi::scrub_sentinel_register();
        if crate::ui::px::assets::atlas_root_proof() != crate::fi::OK_SENTINEL {
            // The answer was given against glyphs that changed: refuse.
            return Ok((crate::ui::confirm::ConfirmResult::Cancelled, crate::fi::FAIL_SENTINEL));
        }
        crate::fi::scrub_sentinel_register();
    }
    Ok(out)
}

/// The Safe route (`px_confirm` over the Safe body).
#[cfg(feature = "ui-px")]
pub(super) fn px_confirm_safe(
    scratch: &mut [u8],
    pages: &crate::tx::display::Pages,
    tx_chain_id: u64,
    safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    cow: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    resolver: &crate::names::NameResolver<'_>,
    facts: &crate::tx::display::TrailerFacts<'_>,
) -> Result<(crate::ui::confirm::ConfirmResult, u32), &'static str> {
    let meta = crate::tx::display::safe_route_meta(tx_chain_id, safe_v1, safe_exec, erc20);
    let inputs = crate::tx::display::px_lift::ContentInputs {
        body: crate::tx::display::px_lift::Body::Safe {
            safe_v1,
            safe_exec,
            cow,
            erc20: meta,
            resolver,
        },
        trailers: facts,
    };
    px_confirm(scratch, pages, &inputs)
}

/// A single-UserOp route (value / contract call, ERC-20, typed call, blind).
#[cfg(feature = "ui-px")]
pub(super) fn px_confirm_userop(
    scratch: &mut [u8],
    pages: &crate::tx::display::Pages,
    body: crate::tx::display::userop_screens::UserOpInputs<'_>,
    facts: &crate::tx::display::TrailerFacts<'_>,
) -> Result<(crate::ui::confirm::ConfirmResult, u32), &'static str> {
    let inputs = crate::tx::display::px_lift::ContentInputs {
        body: crate::tx::display::px_lift::Body::UserOp(body),
        trailers: facts,
    };
    px_confirm(scratch, pages, &inputs)
}

/// A direct CoW Swap order (no Safe context).
#[cfg(feature = "ui-px")]
pub(super) fn px_confirm_cow(
    scratch: &mut [u8],
    pages: &crate::tx::display::Pages,
    v3: &crate::tx::eip712::cowswap::VerifiedCowswapV3,
    facts: &crate::tx::display::TrailerFacts<'_>,
) -> Result<(crate::ui::confirm::ConfirmResult, u32), &'static str> {
    let inputs = crate::tx::display::px_lift::ContentInputs {
        body: crate::tx::display::px_lift::Body::Cow { v3 },
        trailers: facts,
    };
    px_confirm(scratch, pages, &inputs)
}

/// An authenticated ERC-7730 render: the body is the proven page range
/// before the handler's trailers.
#[cfg(feature = "ui-px")]
pub(super) fn px_confirm_erc7730(
    scratch: &mut [u8],
    pages: &crate::tx::display::Pages,
    chain_id: u64,
    family: crate::tx::display::userop_screens::Family,
    facts: &crate::tx::display::TrailerFacts<'_>,
) -> Result<(crate::ui::confirm::ConfirmResult, u32), &'static str> {
    let tail = crate::tx::display::expected_trailer_count(facts);
    let body_len = pages.len.checked_sub(tail).ok_or("px body")?;
    let inputs = crate::tx::display::px_lift::ContentInputs {
        body: crate::tx::display::px_lift::Body::Erc7730 {
            pages,
            start: 0,
            body_len,
            chain_id,
            family,
        },
        trailers: facts,
    };
    px_confirm(scratch, pages, &inputs)
}

/// The slot-rotation consent.
#[cfg(feature = "ui-px")]
pub(super) fn px_confirm_rotation(
    scratch: &mut [u8],
    pages: &crate::tx::display::Pages,
    chain_id: u64,
    slot_index: u32,
    facts: &crate::tx::display::TrailerFacts<'_>,
) -> Result<(crate::ui::confirm::ConfirmResult, u32), &'static str> {
    let inputs = crate::tx::display::px_lift::ContentInputs {
        body: crate::tx::display::px_lift::Body::Rotation { chain_id, slot_index },
        trailers: facts,
    };
    px_confirm(scratch, pages, &inputs)
}

/// HIGH-7 guard: depth counter incremented on handler entry,
/// decremented on exit. SysTick refuses to wipe when depth > 0 so
/// a long-running signing handler that holds stack-local copies of
/// secrets can't have the BSS copy zeroed out from underneath it
/// (which would leave the stack copies disagreeing with the state
/// the user just had wiped — a classic aliasing-under-ISR bug).
///
/// Stored as `AtomicU32` so the entry-side `fetch_add(1)` is a
/// single LDREX/STREX RMW. An earlier plain-`static mut` version had
/// a tiny but real race window between the read of the old value
/// and the write of `+1` where SysTick could observe `depth == 0`,
/// run idle-wipe, then resume — leaving the handler operating on
/// wiped state. The wipe is fail-safe (the handler bails out at the
/// pin-verified check) but the race violates the docstring promise
/// that "SysTick refuses to wipe when depth > 0".
static HANDLER_DEPTH: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Guard type: increment on construction, decrement on drop.
pub(crate) struct HandlerGuard;

impl HandlerGuard {
    /// RAII guard — call at the top of every long-running gateway
    /// handler (sign, request_unlock). Drop at function exit.
    pub(crate) fn enter() -> Self {
        HANDLER_DEPTH.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        HandlerGuard
    }
}

impl Drop for HandlerGuard {
    fn drop(&mut self) {
        // Saturating decrement via CAS loop. `fetch_sub` would
        // underflow if Drop ever runs more times than `enter`
        // (cannot happen in safe Rust, but stays conservative).
        use core::sync::atomic::Ordering;
        let mut cur = HANDLER_DEPTH.load(Ordering::SeqCst);
        loop {
            let next = cur.saturating_sub(1);
            match HANDLER_DEPTH.compare_exchange_weak(
                cur, next, Ordering::SeqCst, Ordering::SeqCst,
            ) {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }
}

/// Read the current handler-busy depth from a SysTick handler.
pub fn handler_is_busy() -> bool {
    HANDLER_DEPTH.load(core::sync::atomic::Ordering::SeqCst) > 0
}

/// Test-only helper: stamp the secure-side master secret and mark the
/// device unlocked directly, skipping the interactive PIN dialog. Used
/// by the `e2e-test` boot path; compiled out of every other build.
#[cfg(feature = "e2e-test")]
pub fn set_e2e_unlocked(master: [u8; 32]) {
    state::with_state(|s| s.mark_unlocked(master));
}

/// Set the gateway to "unlocked" state with the given master secret.
/// Used by the first-boot wizard to auto-unlock after provisioning.
pub fn unlock_with_master(master: [u8; 32]) {
    state::with_state(|s| s.mark_unlocked(master));
}

/// Install a master secret after a genuine successful PIN verification and,
/// when the default-off forced-blind feature is selected, arm exactly one
/// volatile forced attempt.
///
/// This is deliberately separate from [`unlock_with_master`] and
/// [`set_e2e_unlocked`].  First-boot auto-unlock, provisioning/test helpers,
/// and every other non-PIN unlock must remain Disarmed.  The three current
/// callers sit immediately inside successful `gated_unlock` result arms;
/// host source-call-graph tests pin that exclusivity.
#[inline(never)]
pub(crate) fn unlock_after_verified_pin(master: [u8; 32]) -> u32 {
    state::with_state(|s| {
        s.mark_unlocked(master);

        #[cfg(feature = "erc7730-forced-blind")]
        {
            let armed = s.forced_attempt.arm_forced_attempt_after_pin();
            // Fail-in: only the exact OK sentinel preserves the newly
            // unlocked session.  A bad/invalid/readback-faulted arm destroys
            // the secret and returns the Hamming-distant failure sentinel.
            if armed == crate::fi::OK_SENTINEL {
                return crate::fi::OK_SENTINEL;
            }
            s.zeroize_sensitive();
            crate::fi::FAIL_SENTINEL
        }

        #[cfg(not(feature = "erc7730-forced-blind"))]
        {
            // Feature-off semantics are the pre-existing generic unlock.
            crate::fi::OK_SENTINEL
        }
    })
}

/// Gated unlock — every PIN verify MUST go through this.
///
/// Wraps the raw `WalletStore::unlock` with the MCU-side attempt
/// counter at secure-flash page 124:
///
///   1. Check the counter. If ≥ MAX_ATTEMPTS, refuse — return
///      `PinLocked`. Caller is responsible for running
///      `trigger_lockout_wipe` on that signal.
///   2. **Pre-commit**: bump the counter BEFORE calling the SE
///      driver. A power loss or glitch between here and the chip
///      verify leaves the attempt charged. Without this, an
///      attacker who reliably cuts power mid-verify could brute-
///      force without burning MCU attempts.
///   3. Call `WalletStore::unlock`. On `Ok`, erase the counter
///      (fresh start); on `Err`, leave the bump committed. If the
///      erase itself fails, refuse with `InternalError` (fail-closed)
///      rather than release the master with the counter still charged
///      — a swallowed reset failure would drift a correct-PIN device
///      toward a spurious lockout/wipe (F17/SCAFI-5).
///   4. If the flash bump itself fails (PROGERR or post-write
///      readback mismatch), refuse the attempt with
///      `InternalError`. Prevents the "glitch flash writes to
///      burn SE attempts without MCU attempts" attack.
///
/// QEMU (no `stm32u585`): passthrough — no flash, no counter, just
/// `se.unlock(pin)`. The counter gate is a production hardware
/// hardening; dev QEMU builds don't need it.
///
/// See `trigger_lockout_wipe` in `cmd_request_unlock.rs` for the
/// wipe path that follows from `PinLocked`.
///
/// # Safety
/// Caller must hold exclusive access to `se` (the `static mut
/// crate::SE` driver). Production callers obtain this via the
/// single-threaded gateway dispatcher; tests construct a dedicated
/// `WalletStore` instance. Touches secure-flash page 124 via the
/// `flash` driver on `stm32u585` — preconditions for those writes
/// are documented in `hw::flash`.
pub unsafe fn gated_unlock(
    se: &mut impl crate::secure_element::WalletStore,
    pin: &[u8; 8],
) -> Result<[u8; 32], crate::secure_element::UnlockError> {
    use crate::secure_element::UnlockError;

    // §18 P1 — entry jitter. The PIN gate is linear from its external
    // trigger (USB `CMD_REQUEST_UNLOCK` dispatch, boot-unlock, PendSV
    // re-unlock) to the F-15 sentinel check, with no internal shuffle
    // like the sign path's F-16. A profiled single-fault attacker
    // (Masaryk-thesis class, ~76 % on STM32U5) lands a glitch at a
    // FIXED offset from that trigger. `wait_random()` here desyncs the
    // absolute trigger→gate offset by 0..255 loop iterations
    // (~0..19 µs at 160 MHz). This is a meaningful window against an
    // UNCALIBRATED single-shot attacker but does NOT defeat a
    // profile-then-attack rig with multi-attempt statistical recovery
    // — the F-15 sentinel + F-17 rate limiter are the load-bearing
    // defenses there. `#[inline(never)]` on both `wait_random` and
    // `wait_random_loop` keeps this a real `bl` (a glitch that skips
    // the call skips only the jitter, not the gate that follows).
    crate::fi::wait_random();

    #[cfg(feature = "stm32u585")]
    {
        // F-15 hardening: double-read the page-124 counter to defend
        // against a value-fault that clamps the load register, then
        // route the "below lockout" predicate through the F-2
        // sentinel-encoding pattern. The conditional below becomes
        // FAIL-IN: a single-fault that skips the gate evaluates the
        // sentinel comparison against a garbage register value (which
        // is overwhelmingly unlikely to coincide with OK_SENTINEL),
        // so the firmware falls through to `Err(PinLocked)` instead
        // of into the bump+verify branch. A flash-side glitch that
        // underreports the counter on one read is caught by the
        // mismatch check.
        let pre_count_a = crate::hw::flash::pin_attempts_read();
        crate::fi::wait_random();
        let pre_count_b = crate::hw::flash::pin_attempts_read();
        if pre_count_a != pre_count_b {
            crate::pin_attempt_log::record(
                crate::pin_attempt_log::AttemptReason::CounterUnstable,
                pre_count_a,
            );
            return Err(UnlockError::PinLocked);
        }
        let pre_count = pre_count_a;
        crate::pin_attempt_log::note_precharge(pre_count);

        // Affirmative "allowed to proceed" — Hamming-distant sentinel
        // returned only on a clean `pre_count < MAX_ATTEMPTS`. The
        // caller compares the value rather than branching on a bool.
        let allowed = crate::fi::check_true_into_sentinel(
            || pre_count < sphincs_tz_shared::MAX_ATTEMPTS,
        );
        if allowed != crate::fi::OK_SENTINEL {
            // Short-circuit at MAX: nothing burned, nothing wiped here.
            crate::pin_attempt_log::record(
                crate::pin_attempt_log::AttemptReason::AlreadyAtMax,
                pre_count,
            );
            return Err(UnlockError::PinLocked);
        }

        // MEDIUM-2 (audit pin-unlock 20260625): FAIL-IN the pre-commit
        // bump, mirroring the sentinel'd `allowed` gate above. `pin_attempts_bump`
        // (now `#[inline(never)]`) programs the next QW and internally verifies
        // the post-bump count; here we ALSO require — through the Hamming-distant
        // sentinel — that the counter advanced by EXACTLY one relative to
        // `pre_count`. The secure default is the `!= OK_SENTINEL` refusal: a
        // single glitch that skips the `bl pin_attempts_bump` (leaving a stale
        // `Ok`) or skips a refusal branch leaves the re-read count == `pre_count`,
        // so `bumped` lands != OK_SENTINEL and we refuse WITHOUT calling the SE —
        // the old `if ….is_err() { return }` shape let a skipped branch fall
        // through into `se.unlock` with page-124 uncharged.
        //
        // NB: `check_true_into_sentinel` invokes its closure TWICE. The single
        // mutating `pin_attempts_bump()` call therefore happens once, ABOVE the
        // closure; the closure only RE-READS the counter (a side-effect-free
        // flash read), so there is no double-bump.
        let bump_result = crate::hw::flash::pin_attempts_bump();
        let bumped = crate::fi::check_true_into_sentinel(|| {
            // SAFETY: `pin_attempts_read` is a side-effect-free flash read;
            // exclusive SE/flash access holds via the single-threaded
            // dispatcher. The closure is a safe context (the enclosing
            // `unsafe fn` body's implicit unsafe does not extend into it),
            // so the read needs its own `unsafe` block.
            bump_result == Ok(pre_count + 1)
                && unsafe { crate::hw::flash::pin_attempts_read() } == pre_count + 1
        });
        if bumped != crate::fi::OK_SENTINEL {
            crate::pin_attempt_log::record(
                crate::pin_attempt_log::AttemptReason::PrechargeFailed,
                pre_count,
            );
            // Flash write fault (PROGERR / readback mismatch), a faulted or
            // skipped bump, or the counter did not advance by exactly one.
            // Refuse without ever calling the SE driver.
            return Err(UnlockError::InternalError);
        }
    }

    // Trezor-parity: randomise the timing of the SE-side PIN compare
    // so a clock-aligned EM glitch can't reliably target the SE I2C
    // transaction. The SE silicon's own PIN-compare is constant-time,
    // but the MCU-side I/O setup (clock to-the-SE, SCP03 setup) is
    // not — `wait_random` perturbs that window. Symmetric `wait_random`
    // on the other side of the call would also defend a fault on the
    // result code's arrival back into r0.
    crate::fi::wait_random();
    // §32 P3 — duress-first dispatch (timing-uniform). Try the DECOY
    // credential first; on a match, run a matched-LUC pad (a 2nd duress
    // verify, standing in for the SKIPPED real verify so E120 never
    // drifts) and return the decoy master. On no match, fall through to
    // the real unlock. Both correct paths execute the same op-count
    // (4 SE verifies + 2 reads) so an observer cannot tell real-correct
    // from duress-correct by total unlock latency (deniability). A
    // duress-correct unlock resets the MCU counter exactly like a real
    // success (handled by the shared post-match logic below) — else the
    // lockout state would distinguish duress from real.
    #[cfg(feature = "duress-pin")]
    let result = match se.unlock_duress(pin) {
        Ok(mut m) => {
            // §32 P5: duress matched. If the device is configured for
            // wipe-on-duress, WIPE both wallets and report PinLocked
            // instead of opening the decoy. Timing uniformity is NOT
            // required here (the wipe IS the outcome — by the time an
            // observer notices the latency, the secret is already gone),
            // so we skip the duress_pad. The downstream Err arm returns
            // PinLocked WITHOUT resetting page-124 (the wipe is terminal).
            //
            // F26/LIFE-1 (cut point B): FAIL-IN shape. The decoy release
            // — the attacker's bypass target under coercion — is the
            // EXPLICIT conditional riding the Hamming-distant sentinel
            // (which double-reads the mode byte with a wait_random
            // between); the wipe is the fall-through. A skipped/garbled
            // branch or a faulted read lands on WIPE, never on decoy.
            // The read itself is fail-closed (`is_duress_wipe_mode`:
            // only a pristine-blank QW means decoy).
            #[cfg(feature = "stm32u585")]
            let open_decoy = crate::fi::check_true_into_sentinel(|| {
                !crate::hw::flash::is_duress_wipe_mode()
            });
            #[cfg(not(feature = "stm32u585"))]
            let open_decoy = crate::fi::check_true_into_sentinel(|| true);
            if open_decoy == crate::fi::OK_SENTINEL {
                se.duress_pad(pin);
                Ok(m)
            } else {
                use zeroize::Zeroize;
                m.zeroize();
                crate::fi::zeroize_barrier();
                secure_log!("[NSC] duress=wipe configured — wiping device");
                let _ = se.factory_reset_admin();
                Err(UnlockError::PinLocked)
            }
        }
        Err(_) => se.unlock(pin),
    };
    #[cfg(not(feature = "duress-pin"))]
    let result = se.unlock(pin);
    crate::fi::wait_random();

    // FI guard: capture the discriminant twice, separated by
    // `wait_random()`, and route the verdict through the
    // hamming-distant sentinel in `fi::check_true`. A single
    // glitch that turns an `Err` into an `Ok` selection would have
    // to also defeat both `is_ok()` re-evaluations and the sentinel
    // compare. This raises the cost of the "wrong PIN unlocks +
    // resets the counter" attack from a single fault to a multi-
    // fault sequence; the SE silicon counter still rate-limits at
    // the cryptographic gate.
    //
    // Note: if `result` is `Ok(_)` with garbage master_secret
    // (because the SE driver itself was glitched at the chip
    // boundary), the downstream AES-GCM entropy_blob decrypt MAC
    // check will reject it. This FI guard is defense in depth, not
    // a primary gate.
    let is_ok_1 = result.is_ok();
    crate::fi::wait_random();
    let is_ok_2 = result.is_ok();
    // Sentinel-encoded verdict (not a bare `bool`) — a glitch on this call or
    // on the `match`'s guard then almost certainly yields a value `!= OK_SENTINEL`
    // and so falls to the `Ok(_) => InternalError` arm rather than `Ok(master)`.
    let verdict = crate::fi::check_true_into_sentinel(|| is_ok_1 && is_ok_2);

    match result {
        Ok(master) if verdict == crate::fi::OK_SENTINEL => {
            // F17/SCAFI-5: do NOT swallow a page-124 reset failure.
            // The pre-commit above charged the counter BEFORE the SE
            // verify; a silently-failed reset leaves it charged after
            // a CORRECT PIN, so N good unlocks accumulate N markers →
            // spurious 10-attempt lockout → trigger_lockout_wipe (a
            // silent self-brick with no diagnostic). FAIL-IN like the
            // bump gate above: the refusal is the fall-through, the
            // `Ok(master)` release rides on the Hamming-distant
            // sentinel. Nothing was stamped into SecureState yet, so
            // failing closed here costs only a retry.
            #[cfg(feature = "stm32u585")]
            {
                let reset_result = crate::hw::flash::pin_attempts_reset();
                let reset_ok =
                    crate::fi::check_true_into_sentinel(|| reset_result.is_ok());
                if reset_ok != crate::fi::OK_SENTINEL {
                    // The PIN was CORRECT but the counter stayed charged.
                    // Repeat this and the budget walks to a lockout with the
                    // user doing nothing wrong — the self-brick the comment
                    // above describes, now visible instead of silent (#715).
                    crate::pin_attempt_log::record_outcome(
                        crate::pin_attempt_log::AttemptReason::OkResetFailed,
                    );
                    return Err(UnlockError::InternalError);
                }
            }
            crate::pin_attempt_log::record_outcome(
                crate::pin_attempt_log::AttemptReason::OkReset,
            );
            Ok(master)
        }
        Ok(_) => {
            // FI inconsistency between the two reads of `result.is_ok()` (or a
            // glitched `verdict`) — refuse without resetting the MCU counter.
            // Counter stays bumped from the pre-commit above.
            crate::pin_attempt_log::record_outcome(
                crate::pin_attempt_log::AttemptReason::NoVerdict,
            );
            Err(UnlockError::InternalError)
        }
        Err(e) => {
            // A real chip-side verdict is what the budget exists for; anything
            // else burned an attempt without judging the PIN.
            crate::pin_attempt_log::record_outcome(match e {
                UnlockError::PinIncorrect => {
                    crate::pin_attempt_log::AttemptReason::PinIncorrect
                }
                UnlockError::PinLocked => crate::pin_attempt_log::AttemptReason::AlreadyAtMax,
                _ => crate::pin_attempt_log::AttemptReason::NoVerdict,
            });
            Err(e)
        }
    }
}

/// Boot-time directional rollback check between MCU page 124 and the readable
/// OPTIGA attempt counter (E120 LUC under `optiga-hw-counter`; F1E1 only in a
/// non-production soft-counter build). Because `gated_unlock` precharges page
/// 124 before SE verification, benign states have `mcu >= e120`: equality
/// after both advances, or an MCU lead after a cut/transport error. Only
/// `e120 > mcu` proves page-124 rollback and triggers the wipe.
///
/// This is deliberately not described as three-way boot reconciliation. The
/// production SE050 UserID policy denies an attempt-attribute read with
/// `SW=0x6986`, so `Se050::pin_attempt_count` returns `None`. SE050 still
/// participates in every ordinary PIN attempt, independently enforces its
/// max-10 lockout, and maps `AuthMethodBlocked` to the wipe path. Making its
/// counter boot-readable requires a separately reviewed policy/backend and
/// silicon decision; a VERIFY probe would itself consume an attempt.
///
/// On an unprovisioned/backend-unavailable boot, no readable SE leg means no
/// comparison is possible and the function logs and returns. For a future
/// multi-SE backend where both counters are safely readable,
/// `pin_attempt_counts_divergent` remains an additional tamper input.
///
/// Called once per boot from `main.rs` after SE init but before
/// the gateway accepts any unlock command. On tamper detection it
/// triggers `factory_reset_admin` + zeroizes SRAM secrets — same
/// path as `trigger_lockout_wipe`.
#[cfg(feature = "stm32u585")]
pub unsafe fn reconcile_pin_attempts<S>(se: &mut S)
where
    S: crate::secure_element::WalletStore,
{
    let mcu = crate::hw::flash::pin_attempts_read();
    let se_used = se.pin_attempt_count();
    let se_split = se.pin_attempt_counts_divergent();

    // If no readable SE leg exists (shield not yet up, or an unprovisioned chip
    // at first boot) there is nothing to compare. Skip — but loudly, so the
    // lost cross-check is visible rather than silently mistaken for
    // agreement on a frozen value.
    let se_count = match se_used {
        Some(s) => s,
        None => {
            #[cfg(feature = "debug-log")]
            secure_log!("[reconcile] SE attempt-counter leg unavailable — cross-check skipped");
            return;
        }
    };

    // Pre-commit invariant: MCU page-124 is bumped BEFORE the SE verify, so in
    // every benign state MCU LEADS (or equals) the SE counter — `mcu == se`
    // (the verify ran and both advanced) or `mcu == se + 1` (a power-cut or a
    // transport error in the sub-ms window between the MCU bump and the
    // SE-silicon bump). The SE counter EXCEEDING MCU is therefore the
    // unambiguous tamper signal: it means page-124 was rolled back
    // out-of-band (e.g. a TZ-bypass flash erase) while the SE silicon retained
    // its count. Comparing `se > mcu` (NOT `se != mcu`) is what lets the live
    // E120 leg detect the rollback WITHOUT false-wiping on benign power-cuts
    // or flaky-I2C retries (which only ever make MCU lead, never the SE).
    let mcu_vs_se = se_count > mcu;
    let tamper = mcu_vs_se || se_split;

    // FI hardening (audit pin-unlock 20260625): route the "no tamper, safe to
    // continue boot" verdict through the Hamming-distant sentinel and FAIL-IN.
    // The secure default is to WIPE: a single glitch that flips a real
    // disagreement to `tamper = false` lands a value != OK_SENTINEL and falls
    // through to the wipe path below rather than silently booting a tampered
    // device. (Recomputed twice inside `check_true_into_sentinel`; `tamper` is
    // a pure local, so the double evaluation has no side effect.)
    let safe = crate::fi::check_true_into_sentinel(|| !tamper);
    if safe == crate::fi::OK_SENTINEL {
        return;
    }

    crate::ui::show_status("TAMPER DETECT", "wiping...");
    #[cfg(feature = "debug-log")]
    secure_log!(
        "[reconcile] MCU={} SE_used={:?} SE_split={} → wipe",
        mcu, se_used, se_split
    );
    let _ = se.factory_reset_admin();
    let _ = crate::hw::flash::pin_attempts_reset();
    crate::ui::show_status("WIPED", "tamper signal");
}

/// QEMU / non-stm32u585 stub. No flash, no real SE counter to read.
#[cfg(not(feature = "stm32u585"))]
pub unsafe fn reconcile_pin_attempts<S>(_se: &mut S)
where
    S: crate::secure_element::WalletStore,
{
}

/// Zeroize all sensitive global state. Called from the panic handler,
/// the inactivity wipe, and the cancel/idle-wipe branches of every
/// interactive dialog.
pub fn zeroize_sensitive_state() {
    // Panic/tamper paths do not unwind RAII guards. Revoke the watchdog's
    // trusted-UI wait exception before wiping secrets so a fault inside an
    // input backend cannot keep the watchdog fed until the 120 s idle limit.
    crate::timeout::clear_trusted_ui_wait();
    state::with_state(|s| s.zeroize_sensitive());
    // SAFETY: category 5 — exclusive mutable borrow of the
    // `static mut crate::SE` driver. Single-threaded secure world,
    // non-reentrant gateway: nothing else touches the SE while this
    // wipe runs. `zeroize_caches` clears the SE wrapper's in-RAM
    // session state without issuing any I2C traffic.
    unsafe {
        use crate::secure_element::WalletStore;
        (&mut *core::ptr::addr_of_mut!(crate::SE)).zeroize_caches();
    }
}

/// Initialize the shared-memory mailbox by clearing CMD/RESULT/DONE.
/// Must be called once during boot before [`poll_gateway`]. QEMU-only;
/// the STM32U585 CMSE path has no mailbox and no boot-time init.
#[cfg(not(feature = "stm32u585"))]
pub fn init_gateway() {
    // SAFETY: category 2 (QEMU transport — shared-memory mailbox in
    // NS SRAM). The mailbox base/end pair is a compile-time constant
    // from `sphincs_tz_shared`; we are writing to fixed addresses
    // inside that NS region. Volatile stores ensure the cleared
    // values land in memory before NS reads them. Called exactly
    // once during secure-world boot, before NS is allowed to run.
    unsafe {
        core::ptr::write_volatile(SHARED_CMD, CMD_NONE);
        core::ptr::write_volatile(SHARED_RESULT, 0);
        core::ptr::write_volatile(SHARED_DONE, 0);
    }
}

/// Poll the mailbox once and, if a command is pending, dispatch it to
/// the right `cmd_*` handler, write the result word, raise DONE, and
/// clear CMD. The dispatch runs to completion without yielding — the
/// single-threaded invariant the whole state/sign machinery relies on.
/// QEMU-only; never called on the STM32U585 CMSE path.
#[cfg(not(feature = "stm32u585"))]
pub fn poll_gateway() {
    // SAFETY: category 2 (QEMU mailbox path). All eight pointers point
    // into a compile-time-fixed NS-SRAM mailbox region — no runtime
    // validation needed because the addresses are not derived from
    // attacker-supplied input. Volatile reads form the TOCTOU snapshot
    // (CMD + ARG0..2 captured atomically before `dispatch` runs, so NS
    // can't race the validator). Volatile writes commit the response in
    // the ordered sequence RESULT → DONE → clear CMD so NS never sees
    // DONE=1 with stale RESULT.
    unsafe {
        let cmd = core::ptr::read_volatile(SHARED_CMD);
        if cmd == CMD_NONE {
            return;
        }

        let args = GatewayArgs {
            arg0: core::ptr::read_volatile(SHARED_ARG0),
            arg1: core::ptr::read_volatile(SHARED_ARG1),
            arg2: core::ptr::read_volatile(SHARED_ARG2),
        };

        let result = dispatch(cmd, &args);

        core::ptr::write_volatile(SHARED_RESULT, result);
        // Order matters: write RESULT before DONE so NS can't see DONE=1
        // with stale RESULT. Then clear CMD last so NS can issue another.
        core::ptr::write_volatile(SHARED_DONE, 1);
        core::ptr::write_volatile(SHARED_CMD, CMD_NONE);
    }
}

/// Route a single mailbox command to its handler. All commands run with
/// exclusive access to `SecureState` for the duration of dispatch (see
/// the non-reentrant invariant on [`poll_gateway`]).
/// Route a mailbox command to its `cmd_*::run` handler (QEMU only).
///
/// # Safety
/// Called only from `poll_gateway`, which holds the single-threaded
/// invariant: no other gateway dispatch is concurrently in flight.
/// Each `cmd_*::run` is itself `unsafe fn` because of `static mut`
/// driver state and NS pointer derefs — see their per-fn `# Safety`
/// docs.
#[cfg(not(feature = "stm32u585"))]
unsafe fn dispatch(cmd: u32, args: &GatewayArgs) -> u32 {
    match cmd {
        CMD_GET_REMAINING => cmd_get_remaining::run(),
        CMD_REQUEST_UNLOCK => cmd_request_unlock::run(),
        CMD_SIGN_USEROP => cmd_sign_userop::run(args),
        CMD_SIGN_USEROP_BATCH => cmd_sign_userop_batch::run(args),
        CMD_GET_WALLET_ADDRESS => cmd_get_wallet_address::run(args),
        CMD_GET_INIT_CODE => cmd_get_init_code::run(args),
        CMD_SIGN_OFFCHAIN => cmd_sign_offchain::run(args),
        CMD_OFFCHAIN_STATUS => cmd_offchain_status::run(args),
        CMD_OFFCHAIN_SYNC => cmd_offchain_sync::run(args),
        CMD_IS_UNLOCKED => cmd_is_unlocked::run(),
        CMD_LOCK => cmd_lock::run(),
        #[cfg(feature = "e2e-test")]
        sphincs_tz_shared::CMD_TEST_PIN_LOCKOUT => cmd_test_pin_lockout::run(),
        // PRESENT IN PRODUCTION, deliberately: its whole purpose is explaining
        // a lockout on a shipped unit, and shipping images carry no debug-log.
        // Read-only, no secret material — see the disclosure note in
        // `crate::pin_attempt_log`. Placed ABOVE the prodtest block so it is
        // not mistaken for a prodtest-gated command.
        sphincs_tz_shared::CMD_GET_PIN_ATTEMPT_LOG => cmd_pin_attempt_log::run(args),

        // Prodtest commands — only present in the `prodtest` build
        // profile, never in production firmware.
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_GET_ID => prodtest::cmd_get_id_run(args),
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_DISPLAY_PATTERN => {
            prodtest::cmd_display_pattern_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_SAES_SELFTEST => {
            prodtest::cmd_saes_selftest_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_BHK_SELFTEST => {
            prodtest::cmd_bhk_selftest_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_FLASH_RW => prodtest::cmd_flash_rw_run(args),
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_TRNG_SAMPLE => {
            prodtest::cmd_trng_sample_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_OPTIGA_HANDSHAKE => {
            prodtest::cmd_optiga_handshake_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_SE050_HANDSHAKE => {
            prodtest::cmd_se050_handshake_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_USB_LOOPBACK => {
            prodtest::cmd_usb_loopback_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_BUTTON_TEST => {
            prodtest::cmd_button_test_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_RGB_TEST => prodtest::cmd_rgb_test_run(args),
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_RGB_OSD => prodtest::cmd_rgb_osd_run(args),
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_RNG_CONFIG => prodtest::cmd_rng_config_run(args),
        _ => NscStatus::InternalError as u32,
    }
}

// ---------------------------------------------------------------------------
// CMSE veneers — STM32U585 hardware transport
// ---------------------------------------------------------------------------
//
// Each function below is an ARMv8-M Security Extension entry point. The
// linker's `--cmse-implib` pass emits an SG stub for every one into
// `veneers.o`; that implib gets linked into the non-secure world, so NS
// resolves a normal `extern "C"` symbol at the stub address and calls it
// with `BLXNS`. The stub issues `SG`, switches to secure state, clears
// caller-saved registers, and transfers control here. On return the
// compiler emits `BXNS` back to NS.
//
// The bodies are intentionally thin: each one constructs a `GatewayArgs`
// snapshot and delegates straight to the same `cmd_*::run` handler the
// QEMU `dispatch()` path uses, so handler semantics stay identical
// across transports.
//
// Categories of `unsafe` in this section:
//
// 1. **CMSE veneers (`extern "cmse-nonsecure-entry" fn`)** — irreducible
//    category 1. The function signature is generated by the
//    `cmse-nonsecure-entry` attribute and is structurally `extern "C"`
//    with the TrustZone non-secure-entry calling convention. The linker
//    emits an SG stub in `veneers.o`; NS calls the stub via `BLXNS`,
//    the stub issues `SG`, switches to secure state, clears caller-
//    saved registers, and transfers control here. Cannot be made safe
//    without breaking the TrustZone ABI.
//
// 2. **`unsafe { cmd_*::run(...) }` calls** — each `cmd_*::run` is
//    `unsafe fn` because of its `static mut` driver access (`SE`,
//    `SLOT_CACHE`, `SNAP_BUF`, `FW_UPDATE`) and NS pointer derefs.
//    The CMSE veneer is the unique caller in production; the
//    single-threaded non-reentrant dispatcher invariant (no two
//    veneers in flight at once) makes the `unsafe` block sound — see
//    each handler's own `# Safety` doc-comment for the per-handler
//    precondition list.

/// CMD_GET_REMAINING — returns the remaining PIN attempts.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_remaining_attempts() -> u32 {
    secure_log!("[NSC] get_remaining_attempts");
    let r = unsafe { cmd_get_remaining::run() };
    secure_log!("[NSC] get_remaining_attempts -> {}", r);
    r
}

/// CMD_REQUEST_UNLOCK — secure UI prompts for PIN, never crosses NS.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_request_unlock() -> u32 {
    secure_log!("[NSC] request_unlock");
    let r = unsafe { cmd_request_unlock::run() };
    secure_log!("[NSC] request_unlock -> {}", r);
    r
}

/// CMD_SIGN_USEROP — unified Type 1 / Type 2 sign command.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_userop(
    payload_ptr: u32,
    sig_out_ptr: u32,
    total_len: u32,
) -> u32 {
    secure_log!("[NSC] sign_userop (len={})", total_len);
    let args = GatewayArgs { arg0: payload_ptr, arg1: sig_out_ptr, arg2: total_len };
    let r = unsafe { cmd_sign_userop::run(&args) };
    secure_log!("[NSC] sign_userop -> {}", r);
    r
}

/// CMD_SIGN_USEROP_BATCH — atomic multi-call sign command. Same
/// Type 1 / Type 2 wire output as `nsc_sign_userop`; payload differs
/// (header + N inner-tx blocks). See `cmd_sign_userop_batch.rs` for
/// the contract.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_userop_batch(
    payload_ptr: u32,
    sig_out_ptr: u32,
    total_len: u32,
) -> u32 {
    secure_log!("[NSC] sign_userop_batch (len={})", total_len);
    let args = GatewayArgs { arg0: payload_ptr, arg1: sig_out_ptr, arg2: total_len };
    let r = unsafe { cmd_sign_userop_batch::run(&args) };
    secure_log!("[NSC] sign_userop_batch -> {}", r);
    r
}

/// CMD_IS_UNLOCKED — return 1 if unlocked, 0 if locked.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_is_unlocked() -> u32 {
    secure_log!("[NSC] is_unlocked");
    let r = unsafe { cmd_is_unlocked::run() };
    secure_log!("[NSC] is_unlocked -> {}", r);
    r
}

/// CMD_LOCK — zeroize secrets and lock the device.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_lock() -> u32 {
    secure_log!("[NSC] lock");
    let r = unsafe { cmd_lock::run() };
    secure_log!("[NSC] lock -> {}", r);
    r
}

/// Register the NS USB-loop heartbeat counter address with the secure
/// IWDG watcher. Called once from NS boot. `addr` is the address of the
/// NS `static mut` heartbeat counter; the secure side range-validates
/// it against NS SRAM before storing. Returns 0 on success, 1 if the
/// address failed validation. Gated on `iwdg` on both sides so a
/// non-iwdg build links no dangling veneer symbol.
#[cfg(all(feature = "stm32u585", feature = "iwdg"))]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_register_heartbeat(addr: u32) -> u32 {
    secure_log!("[NSC] register_heartbeat(0x{:08x})", addr);
    // TZ4 / work-todo #12b: validate the NS-supplied 4-byte heartbeat address
    // through the SAME FI-doubled NS-pointer typestate every other veneer uses
    // (`validate_read` runs `validate_ns_read_ptr` twice through
    // `check_true_into_sentinel`). This adds the shared-mailbox-disjoint check
    // and the hardware `TT`/SAU reclassification that iwdg's inline window check
    // lacked, and requires two coordinated faults to bypass. `iwdg`'s own
    // alignment+window check stays as defense-in-depth (and covers the 4-byte
    // alignment the `read_volatile(_ as *const u32)` in SysTick relies on).
    if ns_ptr::NsPtr::<u8>::new(addr).validate_read(4).is_err() {
        return 1;
    }
    if crate::hw::iwdg::register_ns_heartbeat(addr) {
        0
    } else {
        1
    }
}

/// CMD_TEST_PIN_LOCKOUT — non-interactive brute-force verification.
/// Destructive (locks SE050 silicon + maxes MCU counter); only built
/// under `e2e-test`. See `cmd_test_pin_lockout.rs` for the contract.
#[cfg(all(feature = "stm32u585", feature = "e2e-test"))]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_test_pin_lockout() -> u32 {
    secure_log!("[NSC] test_pin_lockout");
    let r = unsafe { cmd_test_pin_lockout::run() };
    secure_log!("[NSC] test_pin_lockout -> {}", r);
    r
}

/// CMD_TZIC_STATUS — read the GTZC1 illegal-access counter.
///
/// Non-destructive, no PIN required: returns the running u32 count of
/// NS→SECURE access violations the TZIC IRQ has logged since boot.
/// Pairs with the `gtzc-test` NS validation driver — see
/// `cmd_tzic_status.rs`.
#[cfg(all(feature = "stm32u585", feature = "e2e-test"))]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_tzic_status() -> u32 {
    let r = unsafe { cmd_tzic_status::run() };
    secure_log!("[NSC] tzic_status -> {}", r);
    r
}

// ---------------------------------------------------------------------------
// Prodtest CMSE veneers (`prodtest` feature)
// ---------------------------------------------------------------------------

/// CMD_GET_PIN_ATTEMPT_LOG (4) — why each PIN attempt was consumed (#715).
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_pin_attempt_log(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { cmd_pin_attempt_log::run(&args) };
    secure_log!("[NSC] get_pin_attempt_log -> {}", r);
    r
}

/// CMD_PRODTEST_GET_ID (100) — read STM32 UID + firmware version.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_get_id(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_get_id_run(&args) };
    secure_log!("[NSC] prodtest_get_id -> {}", r);
    r
}

/// CMD_PRODTEST_DISPLAY_PATTERN (101) — render NV3007 LCD test pattern.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_display_pattern(in_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: in_ptr,
        arg1: 0,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_display_pattern_run(&args) };
    secure_log!("[NSC] prodtest_display_pattern -> {}", r);
    r
}

/// CMD_PRODTEST_SAES_SELFTEST (102) — DHUK fingerprint.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_saes_selftest(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_saes_selftest_run(&args) };
    secure_log!("[NSC] prodtest_saes_selftest -> {}", r);
    r
}

/// CMD_PRODTEST_BHK_SELFTEST (103) — BHK fingerprint.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_bhk_selftest(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_bhk_selftest_run(&args) };
    secure_log!("[NSC] prodtest_bhk_selftest -> {}", r);
    r
}

/// CMD_PRODTEST_FLASH_RW (104) — flash R/W round-trip on the test page.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_flash_rw(in_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: in_ptr,
        arg1: 0,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_flash_rw_run(&args) };
    secure_log!("[NSC] prodtest_flash_rw -> {}", r);
    r
}

/// CMD_PRODTEST_TRNG_SAMPLE (105) — N bytes from MCU TRNG.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_trng_sample(in_ptr: u32, out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: in_ptr,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_trng_sample_run(&args) };
    secure_log!("[NSC] prodtest_trng_sample -> {}", r);
    r
}

/// CMD_PRODTEST_OPTIGA_HANDSHAKE (106) — exercise OPTIGA I²C + APDU.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_optiga_handshake(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_optiga_handshake_run(&args) };
    secure_log!("[NSC] prodtest_optiga_handshake -> {}", r);
    r
}

/// CMD_PRODTEST_SE050_HANDSHAKE (107) — exercise SE050 T=1' + APDU.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_se050_handshake(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_se050_handshake_run(&args) };
    secure_log!("[NSC] prodtest_se050_handshake -> {}", r);
    r
}

/// CMD_PRODTEST_USB_LOOPBACK (108) — echo N bytes for USB integrity.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_usb_loopback(
    in_ptr: u32,
    out_ptr: u32,
    n: u32,
) -> u32 {
    let args = GatewayArgs {
        arg0: in_ptr,
        arg1: out_ptr,
        arg2: n,
    };
    let r = unsafe { prodtest::cmd_usb_loopback_run(&args) };
    secure_log!("[NSC] prodtest_usb_loopback({}) -> {}", n, r);
    r
}

/// CMD_PRODTEST_BUTTON_TEST (109) — 3-step LEFT/RIGHT/BOTH verification.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_button_test(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_button_test_run(&args) };
    secure_log!("[NSC] prodtest_button_test -> {}", r);
    r
}

/// CMD_PRODTEST_RGB_TEST (110) — light the 9 RGB LEDs and report the AW21036's
/// identity, a bus scan and an ACK tally. `in_ptr` is 6 bytes
/// `[r, g, b, gcc, en, reserved]`; `out_ptr` is 24 bytes.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_rgb_test(in_ptr: u32, out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: in_ptr,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_rgb_test_run(&args) };
    secure_log!("[NSC] prodtest_rgb_test -> {}", r);
    r
}

/// CMD_PRODTEST_RNG_CONFIG (112) — TRNG certified-configuration receipt.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_rng_config(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_rng_config_run(&args) };
    secure_log!("[NSC] prodtest_rng_config -> {}", r);
    r
}

/// CMD_PRODTEST_RGB_OSD (111) — per-channel open/short detection. `in_ptr` is
/// 4 bytes `[gcc, en, reserved, reserved]`; `out_ptr` is 24 bytes.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_rgb_osd(in_ptr: u32, out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: in_ptr,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_rgb_osd_run(&args) };
    secure_log!("[NSC] prodtest_rgb_osd -> {}", r);
    r
}

// ---------------------------------------------------------------------------
// Firmware-update CMSE veneers
// ---------------------------------------------------------------------------

/// CMD_FW_BEGIN — initiate firmware-update streaming session.
/// arg0 = manifest_ptr, arg2 = MANIFEST_SIZE (8192).
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_begin(manifest_ptr: u32, manifest_len: u32) -> u32 {
    let args = GatewayArgs {
        arg0: manifest_ptr,
        arg1: 0,
        arg2: manifest_len,
    };
    unsafe { cmd_fw_begin::run(&args) }
}

/// CMD_FW_CHUNK — stream one image chunk. arg0 = chunk_ptr, arg2 = chunk_len.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_chunk(chunk_ptr: u32, chunk_len: u32) -> u32 {
    let args = GatewayArgs {
        arg0: chunk_ptr,
        arg1: 0,
        arg2: chunk_len,
    };
    unsafe { cmd_fw_chunk::run(&args) }
}

/// CMD_FW_COMMIT — finalize staged update. No args.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_commit() -> u32 {
    let args = GatewayArgs { arg0: 0, arg1: 0, arg2: 0 };
    unsafe { cmd_fw_commit::run(&args) }
}

/// CMD_FW_STATUS — read update progress. arg1 = out_ptr.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_status(out_ptr: u32) -> u32 {
    let args = GatewayArgs { arg0: 0, arg1: out_ptr, arg2: 0 };
    unsafe { cmd_fw_status::run(&args) }
}

/// CMD_FW_ABORT — discard partial update.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_abort() -> u32 {
    unsafe { cmd_fw_abort::run() }
}

/// CMD_GET_WALLET_ADDRESS — compute CREATE2-predicted wallet address for
/// `account_index` (0..=255). Account 0 is the legacy single-account
/// derivation; higher indices yield independent on-chain wallets from
/// the same BIP-39 seed. `show = 1` routes the derived address through
/// the trusted-OLED confirm (#472) before any NS-bound write.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_wallet_address(
    out_ptr: u32,
    account_index: u32,
    show: u32,
) -> u32 {
    secure_log!("[NSC] get_wallet_address (acct={})", account_index);
    let args = GatewayArgs { arg0: out_ptr, arg1: account_index, arg2: show };
    let r = unsafe { cmd_get_wallet_address::run(&args) };
    secure_log!("[NSC] get_wallet_address -> {}", r);
    r
}

/// CMD_GET_INIT_CODE — return the 4280-byte ERC-4337 initCode for
/// `(account_index, chain_id)`. Companion uses it to get accurate
/// gas estimates for first-deploy UserOps; the same bytes are
/// emitted by the deploy path of `CMD_SIGN_USEROP`. See the command
/// docs in `shared::CMD_GET_INIT_CODE`.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_init_code(
    in_ptr: u32,
    out_ptr: u32,
    in_len: u32,
) -> u32 {
    secure_log!("[NSC] get_init_code (len={})", in_len);
    let args = GatewayArgs { arg0: in_ptr, arg1: out_ptr, arg2: in_len };
    let r = unsafe { cmd_get_init_code::run(&args) };
    secure_log!("[NSC] get_init_code -> {}", r);
    r
}

/// CMD_SIGN_OFFCHAIN — sign an EIP-1271 hash with the slot key.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_offchain(
    in_ptr: u32,
    out_ptr: u32,
    in_len: u32,
) -> u32 {
    secure_log!("[NSC] sign_offchain (len={})", in_len);
    let args = GatewayArgs { arg0: in_ptr, arg1: out_ptr, arg2: in_len };
    let r = unsafe { cmd_sign_offchain::run(&args) };
    secure_log!("[NSC] sign_offchain -> {}", r);
    r
}

/// CMD_OFFCHAIN_STATUS — read the firmware's per-slot off-chain state.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_offchain_status(
    in_ptr: u32,
    out_ptr: u32,
    in_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: in_ptr, arg1: out_ptr, arg2: in_len };
    unsafe { cmd_offchain_status::run(&args) }
}

/// CMD_OFFCHAIN_SYNC — bump the firmware's per-slot `last_userop_count`
/// to a companion-supplied floor. See `cmd_offchain_sync::run` for the
/// full rationale (firmware-reflash recovery).
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_offchain_sync(in_ptr: u32, in_len: u32) -> u32 {
    let args = GatewayArgs { arg0: in_ptr, arg1: 0, arg2: in_len };
    unsafe { cmd_offchain_sync::run(&args) }
}

```
