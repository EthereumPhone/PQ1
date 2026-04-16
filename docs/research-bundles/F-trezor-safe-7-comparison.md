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
   - PQSigner: SLH-DSA-SHA2-128f (migrating 192f) transaction signer,
     ML-DSA-44 bootstrap signer, no classical signer anywhere. ERC-4337
     smart-account model (no EOA, keys rotate on-chain).
   - Evaluate the classical-vs-PQ trade-off honestly: Trezor's curve
     choices are battle-tested and ubiquitous; PQSigner's PQ choices
     are NIST-finalized but rare in production wallets and much larger
     signatures (17-35 KB vs 64 bytes).

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
   - PQSigner: hardware-enforced counters on both SEs (SE050 UserID
     max 10; OPTIGA Trust M auth reference + firmware-managed decr-
     before-auth counter at OID 0xF1D5). Admin-wipe secondary UserID
     for post-lockout recovery.

5. **Firmware update model and verifiability**
   - Trezor Safe 7 firmware update: signed by whom, with what keys,
     verified by which chip? Rollback protection?
   - PQSigner: measured-boot + 8-BIP-39-word SHA-256 displayed on OLED,
     user visually compares with host tool output. Planned: ML-DSA-44-
     signed measurement hash (not binary) for reproducible-build
     verification. Firmware flashed over ST-LINK (no USB DFU).
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
     OPTIGA Trust M. Reproducible builds planned not shipped.
   - What does "verifiable hardware wallet" actually mean in each
     case?

9. **Smart-contract / AA / MPC integration posture**
   - Trezor Safe 7's support for smart-contract wallets today (Safe,
     Argent, ERC-4337 passkey/4337 signers). Does it clear-sign any
     AA structures or just EIP-712?
   - PQSigner: native ERC-4337 smart account with PQ-only signers, on-
     device Groth16 ZK clear-signing for Aave v3 (+ CowSwap planned),
     deterministic CREATE2 address on all chains from bootstrap PK.
   - Which is the better on-ramp for the smart-wallet / AA world?

10. **UX / ergonomics honestly**
    - Signature size (PQSigner 17-35 KB per tx vs 64 bytes) — ergonomic
      fallout on USB latency, mempool propagation, L2 inclusion cost.
    - User prompts per transaction, number of button presses, display
      constraints (PQSigner: SSD1306 128x64 OLED; Trezor Safe 7: 1.54"
      color touchscreen).
    - Recovery ceremony complexity. Backup verification flow.

11. **What Trezor does that PQSigner should steal (concrete list)**
    - Specific design patterns, audit artefacts, or UX flows from
      Trezor that PQSigner should copy, with citations.

12. **What PQSigner does that Trezor can't easily adopt**
    - Things structurally locked out by Trezor's architecture (dual-SE
      retrofit, PQ-only signing, on-device AA / ZK clear-signing,
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

## Project context (condensed — full version in `docs/ai-research-briefing.md`)

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

**Why signing must run on the Cortex-M33, not the SE.** Transaction
signatures are **post-quantum SLH-DSA (SPHINCS+ SHA2-128f, migrating
to 192f)**. No commercial secure element currently computes SLH-DSA.
Bootstrap signatures are **ML-DSA-44** (also PQ, also not SE-capable).
The SEs are gated storage, not signing accelerators. The seed
therefore transits STM32 secure-world SRAM during the active signing
window (~120 s idle timeout, then zeroize). TrustZone SAU+GTZC isolates
this from the non-secure world.

**TrustZone partition.** Secure world (flash bank 1, SRAM1) owns all
crypto, PIN, persistent secrets. Non-secure world (flash bank 2,
SRAM2) owns UI, USB, tx parsing. Crossings go through 6 NSC gateway
commands with pointer validation and TOCTOU-safe copy-in.

**Power supervision state.** BOR, PVD, ECC (except SRAM1 which is
always-on), IWDG all at factory defaults. Stage 1 of a 5-stage brownout
roadmap added reset-cause classification + verified flash writes; the
rest is planned. `make stm32-harden-opts` is a one-time option-byte
setup target (sets BOR3 + SRAM2_RST=0) but has not been run yet. See
`docs/brownout-hardening.md` for the full plan.

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

**Current SCP03 state.** The SE050 SCP03 channel is active (every TX
has CLA=0x84). Using NXP default static keys; rotation to per-device
keys + HUK-SAES wrapping is a production-readiness item (work-todo #7).

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

# PQSigner OS

A **post-quantum hardware wallet** designed so that *every* cryptographic primitive that protects the seed — at rest, in transit between chips, in firmware updates, in transaction signing — is either a NIST PQC standard or a symmetric primitive at a key size that survives Grover's algorithm. The classical secure channels of the secure elements (which we cannot replace) are wrapped inside a PQ confidentiality layer so the SEs never see plaintext halves.

The design target is a **STM32U585 + Infineon OPTIGA Trust M V3 + NXP EdgeLock SE050**. No single die, no single vendor, and no future cryptographically-relevant quantum computer should be able to recover the seed from harvested traffic or extracted ciphertext.

> **Status: dual-SE implemented.** The TrustZone firmware boots and runs on a real **B-U585I-IOT02A** dev board (STM32U585, Cortex-M33). The secure world, SAU/GTZC configuration, and first-boot wizard execute on silicon. See [`docs/dev-board-setup.md`](docs/dev-board-setup.md) for board setup instructions. Both secure element drivers are written: **OPTIGA Trust M V3** (pure Rust IFX I2C stack + AES-128-CCM shielded connection) and **NXP SE050** (T1oI2C + SCP03). The dual-SE XOR entropy split is wired and tested — BIP-39 entropy is split across both chips. The ML-KEM inner-wrap, ML-DSA hybrid OEMiROT, custom PCB, and production STM32 bring-up are the remaining **target architecture** items. Read the [Implementation Status](#implementation-status) table for what actually exists and where it actually runs today.

```
                  ┌──────────────────────────────────────────────────┐
                  │              STM32U585  (Cortex-M33)              │
                  │                                                   │
                  │  ┌───────────────── SECURE WORLD ───────────────┐ │   ┌──── NON-SECURE WORLD ────┐
                  │  │                                                │ │   │                          │
                  │  │  PIN → KDF → {K_T, K_E}                        │ │   │  USB / display / buttons │
                  │  │                                                │ │   │  Tx parser, RLP, UI       │
   ┌──────────┐   │  │  OPTIGA.unlock(K_O)  → wrapped_O               │ │   │                          │
   │ OPTIGA   │◄──┼──┤  ML-KEM-1024.Decaps(sk_pq, wrapped_O) → half_O │ │   │   ┌──────────────────┐   │
   │Trust M V3│   │  │                                                │◄┼───┼──►│ NSC gateway      │   │
   │(Shielded │   │  │  SE050.unlock(K_E)   → wrapped_E               │ │   │   │ 4 commands only  │   │
   │  Conn)   │   │  │  ML-KEM-1024.Decaps(sk_pq, wrapped_E) → half_E │ │   │   └──────────────────┘   │
   └──────────┘   │  │                                                │ │   │                          │
   ┌──────────┐   │  │  E       = HKDF(half_O ⊕ half_E)               │ │   │  no secrets, ever        │
   │  SE050   │◄──┼──┤  mnemonic ← BIP-39(E)                          │ │   │                          │
   │  (SCP03  │   │  │  slh_seed ← HKDF(PBKDF2-SHA512(mnemonic))      │ │   └──────────────────────────┘
   │  outer)  │   │  │  sk       ← SLH-DSA-SHA2-192f.keygen           │ │
   └──────────┘   │  │  signature ← sk.sign(hash)                     │ │
                  │  │  zeroize(everything)                           │ │
                  │  │                                                │ │
                  │  │  HUK-SAES wraps:                               │ │
                  │  │    • ML-KEM-1024 secret key (PQ wrap layer)    │ │
                  │  │    • OPTIGA Trust M Platform Binding Secret     │ │
                  │  │    • SE050 SCP03 / ECKey static key            │ │
                  │  │  TRNG / HASH / SAES / TAMP / BOR               │ │
                  │  │  Inactivity timer (Secure-only TIM)            │ │
                  │  └────────────────────────────────────────────────┘ │
                  └──────────────────────────────────────────────────┘
                                          ▲
                                          │  OEMiROT (HDPL1)
                                          │  verifies firmware via
                                          │  ML-DSA-65 + Ed25519 hybrid
                                          │  before any of your code runs
```

## Design Properties

This is the *target architecture* for the production wallet. Every bullet here is either implemented in QEMU today, partially implemented in QEMU today, or planned for the STM32 bring-up. See [Implementation Status](#implementation-status) for the per-item state.

- **Post-quantum transaction signatures** — SLH-DSA-SHA2-192f (FIPS 205), ~192-bit PQ security. Hash-based, no number-theoretic assumptions, no known quantum speedup beyond Grover (factored into the parameter choice). *(Currently SHA2-128f in QEMU; 192f migration is part of the production bring-up.)*
- **Post-quantum firmware signing via hash-signature model** — instead of signing firmware binaries, the manufacturer signs the **firmware measurement hash** (the same SHA-256 displayed as 8 BIP-39 words at boot). Anyone can build the firmware from source (reproducible build), download the manufacturer's published signature, and flash the device. The device verifies: (1) the signature on the hash is valid (manufacturer's public key), and (2) the hash matches the installed firmware. This decouples build from approval — users build, the manufacturer approves. Neither can cheat: users can't forge the signature, and the manufacturer can't sign firmware that doesn't match the open-source code. Signature stored outside the measured flash region to avoid circular dependency. *(Not yet implemented — target for STM32 bring-up. See [Firmware Update Model](#firmware-update-model) for the full design.)*
- **Post-quantum confidentiality of all SE traffic** — both halves of the entropy are **ML-KEM-1024-encapsulated + AES-256-GCM-sealed** *before* they ever touch the I²C bus. The classical Shielded Connection / SCP03 layers carry only opaque ciphertext. *(Inner-wrap layer not yet implemented — target for STM32 bring-up.)*
- **TrustZone isolation** — signing key, PIN state, ML-KEM secret key, and crypto ops confined to the secure world. *(On real STM32U585 silicon the six-command gateway runs through proper ARMv8-M CMSE `cmse-nonsecure-entry` veneers — exercised end-to-end under `make e2e-hw`. The QEMU mps2-an505 build uses a shared-memory mailbox + SysTick poll instead, as a workaround for a QEMU 8.2.2 MPC S-alias bug that breaks the SG instruction check.)*
- **Dual secure elements (split entropy)** — BIP-39 entropy is XOR-split across an Infineon OPTIGA Trust M V3 and an NXP SE050. Compromising either chip in isolation reveals **zero** bits of the seed. *(Fully implemented with dual-SE XOR split across OPTIGA Trust M and SE050. Both chips share I2C1 at addresses 0x30 and 0x48.)*
- **Boot-time attestation of both chips** — fresh nonce signed by each SE's factory attestation key, verified against pinned vendor roots and pinned per-device UIDs. The classical SE attestation is treated as *proof of presence*; the cryptographic root of device identity is the ML-DSA-signed device certificate pinned in HDPL1 OEMiROT at provisioning. *(Not yet implemented — both attestation paths and the ML-DSA device cert are target.)*
- **Firmware measurement at boot** — SHA-256 of the secure-world flash image is computed at every boot and displayed as 8 BIP-39 words on the trusted OLED. A companion host tool (`fwmeasure`) computes the same words from a reproducible build of the open-source firmware. The user visually compares — no secrets, no attestation keys, fully trustless. *(Implemented. Run `make measure` on the host to get the expected words.)*
- **Mixed-RNG generation** — wallet entropy is `STM32_TRNG ⊕ OPTIGA_TRNG ⊕ SE050_TRNG`. All three are post-quantum (Grover offers no meaningful speedup against true randomness). *(Currently uses host `/dev/urandom` via semihosting under QEMU.)*
- **Hardware-enforced retry limits** — 10 wrong PIN attempts on either chip locks out its half. OPTIGA Trust M uses authorization references with firmware-managed attempt counter (protected by shielded connection). SE050 uses UserID auth with hardware-enforced max attempts. Cross-chip lockstep via intent log in S-flash planned. *(Attempt counters implemented on both chips; cross-chip lockstep / intent log not yet written.)*
- **PQ-safe symmetric crypto throughout** — AES-256-GCM, SHA-256, SHA-512, HMAC-SHA256, HKDF-SHA256, PBKDF2-HMAC-SHA512. Every key, MAC tag, and hash is sized so that Grover's algorithm leaves ≥ 128-bit effective security. *(Implemented in QEMU.)*
- **No heap** — `#![no_std]`, stack-only allocation, no allocator attack surface. *(Implemented.)*
- **Hardened gateway** — NS pointer validation, TOCTOU defense, sensitive memory zeroization, custom panic handler that clears secrets before halting. *(The same `cmd_*::run` handlers are shared across both transports — only the entry point differs. Exercised on QEMU and on real STM32U585 under `make e2e-hw`.)*
- **ZK clear signing** — for supported DeFi protocols (Aave V3 today), the wallet refuses to display a human-readable action string unless a Groth16 proof over BLS12-381 cryptographically certifies that the string is a faithful ABI interpretation of the raw calldata. The full VK pool lives in non-secure firmware rodata; the secure world only embeds a 32-byte Merkle root of the VK DB and re-verifies every supplied VK against that root before running Groth16, so neither the companion app nor a compromised non-secure world can substitute a malicious VK. *(Implemented in QEMU via `CMD_CLEAR_SIGN` (5); host-side `zk-test` crate verifies the Aave V3 supply proof in ~3.3 ms; automated `make e2e` suite exercises all four sign-dispatch levels end-to-end.)*
- **ERC20-aware trusted display** — for transactions whose recipient contract is in the firmware's pinned ERC20 DB, the trusted UI renders "Send 100.000000 USDC to 0xabc..." with symbol and decimals from a Merkle-verified metadata bundle. Unknown contracts fall through to a Ledger-style "⚠ BLIND SIGNING" warning. The ERC20 DB is in non-secure rodata (Merkle-anchored the same way as the VK DB), so adding tokens does not cost any secure flash. *(Implemented in QEMU; `dbgen` crate builds the Merkle trees at build time.)*

## Prerequisites

- Rust nightly (see `rust-toolchain.toml`)
- `arm-none-eabi-ld` (ARM bare-metal linker)
- QEMU with `mps2-an505` machine support (`qemu-system-arm`)
- For real hardware: TROPIC01 TS1302 devkit connected at `/dev/ttyACM0`

## Quick Start

### Interactive: drive the wallet with your laptop's arrow keys

```bash
make play
```

Maps your two arrow keys to the two physical buttons of the emulated
hardware wallet. Walk through the first-boot wizard, see the 24 BIP-39
words on the OLED, do the spot-check, sign a transaction.

| Key            | Action                                   |
|----------------|------------------------------------------|
| `<-`           | Left button — back / scroll down         |
| `->`           | Right button — next / scroll up          |
| `<-` + `->`    | Confirm (press both arrows together)     |
| `Esc`          | Cancel / back out                        |
| `Ctrl-C`       | Quit                                     |

### Non-interactive smoke test

```bash
make run                # raw single-char protocol, useful for piping inputs
make run-tropic01       # use the real TROPIC01 chip via /dev/ttyACM0
```

Expected end-of-run output:
```
[S] Wallet ready
[NS] Non-secure world started!
[NS] Remaining PIN attempts: 10
[NS] Get pubkey: Ok
[NS] Pubkey[0..4]: [30, 77, d8, 24]
[NS] Unlock: Ok
[NS] Sign: Ok
[NS] Sig len: 35664 bytes        # SLH-DSA-SHA2-192f
[NS] === All tests passed! ===
```

> Note: signature length goes from 17088 (SHA2-128f) to 35664 bytes (SHA2-192f). The PQ signing-key parameter set is part of the recovery contract — see "Cryptographic Primitives" below.

## Project Structure

```
sphincs_rust/
+-- Cargo.toml              # Workspace root
+-- Makefile                 # Build orchestration (secure -> veneers -> nonsecure -> QEMU)
+-- secure/                  # TrustZone SECURE world firmware
|   +-- src/
|   |   +-- main.rs          # Boot: SAU -> enroll -> SysTick -> boot NS
|   |   +-- nsc.rs           # Secure gateway (5 commands, pointer validation)
|   |   +-- crypto.rs        # KDF, AES-GCM, PIN state, enrollment
|   |   +-- pin.rs           # PIN verification via MAC-and-Destroy
|   |   +-- sau.rs           # SAU + MPC configuration
|   |   +-- tropic01_se.rs   # TROPIC01 e2e encrypted sessions
|   |   +-- secure_element.rs # SecureElement trait + mock impl
|   |   +-- db_roots.rs      # Generated: Merkle roots of ERC20 + VK DBs
|   |   +-- erc20/           # ERC20 dispatcher + bundle Merkle verifier
|   |       +-- calldata.rs  #   Strict ABI decoder (transfer/transferFrom/approve)
|   |       +-- dispatch.rs  #   Picks TxKind (ValueTransfer/Erc20Known/BLIND/...)
|   |       +-- merkle.rs    #   sha256 Merkle proof verifier
|   |       +-- bundle.rs    #   NS → S metadata bundle parser + verifier
|   |   +-- zk/              # ZK clear signing (Groth16 + Poseidon)
|   |       +-- groth16.rs   #   BLS12-381 pairing verifier (no alloc)
|   |       +-- poseidon.rs  #   Poseidon hash over BLS12-381 scalar field
|   |       +-- vk_bundle.rs #   NS → S VK bundle parser + Merkle verifier
|   +-- memory.x             # Linker script (S flash + NSC + S SRAM)
+-- nonsecure/               # TrustZone NON-SECURE world firmware
|   +-- src/
|   |   +-- erc20_db.bin     # Full ERC20 DB (generated by dbgen)
|   |   +-- erc20_db.rs      #   + local lookup → bundle builder
|   |   +-- vk_db.bin        # Full ZK VK DB (generated by dbgen)
|   |   +-- vk_db.rs         #   + local lookup → bundle builder
|   |   +-- e2e_test.rs      # Non-interactive e2e runner (gated, make e2e)
+-- shared/                  # Shared types (NscStatus, db_format, constants)
+-- dbgen/                   # Host-side DB + Merkle tree builder
+-- zk-test/                 # Host-side E2E test for the ZK verifier
+-- desktop/                 # Host-side CLI (sphincs-wallet)
+-- secure/data/             # Curated source data for dbgen
|   +-- erc20.json           # ERC20 metadata (chain_id, addr, name, symbol, decimals)
|   +-- vks.json             # VK manifest (protocol → vk file + deployments)
|   +-- vks/*.vk.bin         # Per-protocol 960-byte VKs
|   +-- vks.review.txt       # Generated: release-review manifest (sha256 per VK)
+-- tools/
|   +-- export_zk_constants.js  # Export Poseidon constants from poseidon-bls12381
+-- docs/
    +-- architecture.md      # Detailed technical architecture
```

## Documentation Map

The repo has accumulated several design + roadmap docs. They overlap less
than they look — each has a specific purpose. **Read the right one for
what you need:**

### Start here

| If you want to… | Read |
|---|---|
| Understand the architecture top-down | `README.md` (this file) + `docs/architecture.md` |
| Navigate the code as a contributor | `CLAUDE.md` (project context, invariants, file map) |
| Set up a B-U585I-IOT02A dev board | `docs/dev-board-setup.md`, `docs/hardware_requirements.md` |

### Plan + roadmap

| If you want to… | Read |
|---|---|
| See the full backlog (what's done, what's planned) | `docs/work-todo.md` |
| Synthesise the 2026-04-14 deep-research findings into "what to do next" | `docs/production-security.md` |
| Drive a future AI-research session with project context | `docs/ai-research-briefing.md` + `docs/research-bundles/` |
| See what's already been researched (raw artefacts) | `docs/research-bundles/results/` |

### Subsystem-specific design

| If you want to… | Read |
|---|---|
| Understand the brownout / glitch / supervisor 5-stage rollout (BOR, PVD, ECC, IWDG, TAMP, supercap on VBAT) | `docs/brownout-hardening.md` |
| Understand the SE050 PIN-lockout factory-reset design (admin UserID + 2-entry TAG_POLICY) | `docs/se050-factory-reset.md` |
| Understand the SE050 native UserID PIN auth flow | `docs/se050-userid-pin-auth.md` |
| Side-channel + fault-injection hardening requirements | `docs/HARDENING.md` (existing) + `docs/production-security.md` §2.1 (new) |
| ERC-4337 wallet contract design | `docs/pq-aa-wallet-design.md` |
| OPTIGA Trust M integration (IFX I2C, shielded connection) | `docs/OPTIGATRUSTM/*.md` |
| Firmware measurement / signed updates | `docs/sphincs-c7-firmware-integration.md`, README §"Firmware Update Model" |
| USB protocol on the wire | `docs/usb-protocol-v2.md`, `docs/usb-hid-setup.md` |
| OLED mirror / dev tooling | `docs/oled-mirror.md` |

### Per-domain quick map (which doc covers each concern)

The four "live" planning docs split responsibilities like this — if it's
not in the doc you opened, check the right one:

| Concern | Lives in |
|---|---|
| BOR / PVD / IWDG / SRAM-ECC / TAMP / CSS / supercap on VBAT | `brownout-hardening.md` |
| Wipe-in-progress flag + crash-safe factory-reset | `brownout-hardening.md` (mechanism) + `se050-factory-reset.md` (SE050-side) |
| SLH-DSA double-compute + OptRand + FihInt + PIN fail-in | `production-security.md` §2.1 + `work-todo.md` #18 |
| SCP03 key rotation + HUK-SAES wrapping + binding record | `production-security.md` §2.2 + `work-todo.md` #20 |
| SLH-DSA side-channel mitigations (rate limit, shuffling, SHAKE-vs-SHA2 decision) | `production-security.md` §2.3 + `work-todo.md` #18 |
| USB hardening (DWC2 errata, FI-resistant min, rate limiter) | `production-security.md` §2.4 + `work-todo.md` #19 |
| Supply-chain attestation (research not yet run) | `research-bundles/E-supply-chain.md` (bundle ready) + `work-todo.md` #22 |
| Hallucination/verification flags from research | `production-security.md` §3 + `ai-research-briefing.md` §5 |

### Why three planning docs, not one

- **`brownout-hardening.md`** is a focused multi-stage rollout (Stage 1
  → Stage 5) for chip-level voltage/glitch supervisors. Mixing in
  unrelated software-side findings would make the staged rollout
  harder to follow.
- **`production-security.md`** is the synthesis of the 2026-04-14 deep-
  research round across all 4 areas (fault injection, SCA, USB, key
  management) — a single place to read "what did we learn and what
  must we do."
- **`work-todo.md`** is the actionable index. When you sit down to
  implement, this is what you read first.

If you're new to the repo, the order is: this README → CLAUDE.md →
`work-todo.md` → whichever subsystem doc matches the issue you're
working on.

## Build Modes

| Feature | Description |
|---------|-------------|
| `mock-se` | Mock secure element in SRAM (default, for QEMU testing) |
| `tropic01-se` | Real TROPIC01 chip via SPI (bare-metal SPI1/SPI2 on STM32U585, semihosting bridge on QEMU) |
| `spi1-arduino` | Use SPI1/PE12-PE15 (Arduino R3 headers) instead of default SPI2/PB12-PB15 for TROPIC01 |
| `se050` | Real SE050 via I2C1 + SCP03 |
| `dual-se` | Both SEs active with XOR entropy split (implies `tropic01-se` + `se050`) |
| `stm32u585` | Real STM32U585 hardware target (vs QEMU mps2-an505) |
| `debug-log` | Enable semihosting debug output (remove for production) |
| `pka-accel` (secure) | Route BLS12-381 Fp arithmetic through the STM32U585 PKA |
| `e2e-test` | Non-interactive scripted test mode — **never ship in production** |

Build without debug output for production:
```bash
make FEATURES=tropic01-se all
```

## On-device databases (ERC20 + ZK VK)

The wallet ships two embedded read-only databases in **non-secure
firmware rodata**, both Merkle-anchored to 32-byte roots pinned in
secure flash. Everything the trusted UI displays for a known token or
a clear-signed DeFi action comes from these DBs.

| DB | Source | Built artifact (NS side) | Secure-side anchor |
|---|---|---|---|
| ERC20 metadata | `secure/data/erc20.json` | `nonsecure/src/erc20_db.bin` | `ERC20_DB_ROOT` in `secure/src/db_roots.rs` |
| ZK clear-signing VKs | `secure/data/vks.json` + `secure/data/vks/*.vk.bin` | `nonsecure/src/vk_db.bin` | `VK_DB_ROOT` in `secure/src/db_roots.rs` |

Both DBs are built by a single host-side tool:

```bash
cargo run -p dbgen
```

This reads the JSON sources, sorts entries by `(chain_id, contract)`,
interns strings (for the ERC20 DB) and dedups VKs (for the VK DB),
builds a SHA-256 Merkle tree over the canonical leaf encodings,
appends per-entry Merkle proofs to each `.bin` blob, and writes:

- `nonsecure/src/erc20_db.bin` — full ERC20 DB + per-entry proofs, `include_bytes!`d into the NS firmware image
- `nonsecure/src/vk_db.bin` — same for the VK DB
- `secure/src/db_roots.rs` — the two 32-byte roots, `include!`d into the secure firmware image
- `secure/data/vks.review.txt` — a human-readable build-traceability manifest of `(protocol, chain_id, contract, sha256(vk))` triples. The release reviewer diffs this against the previous release before signing; the trust chain is entirely offline (no `clearSigningVKHash` lookups, no governance RPCs)

Every generated file is **checked into the repo** (same pattern as
`tools/export_zk_constants.js`) so downstream builds do not need the
Rust host toolchain — only a fresh JSON edit requires rerunning
`dbgen`.

### Adding an ERC20 token

1. Edit `secure/data/erc20.json`:
   ```json
   { "chain_id": 42161, "address": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
     "name": "USD Coin", "symbol": "USDC", "decimals": 6 }
   ```
2. Run `cargo run -p dbgen`.
3. Commit the JSON source AND the regenerated
   `nonsecure/src/erc20_db.bin` + `secure/src/db_roots.rs`.

The tool hard-errors on `name`/`symbol` strings over 255 bytes,
duplicate `(chain_id, contract)` keys, and the same contract appearing
on multiple chains with different metadata (typical copy-paste bug).

### Adding a ZK clear-signing protocol

1. Produce the 960-byte Groth16 verification key via the in-tree
   Circom toolchain: add a row to `circuits/circuits.json`, drop the
   `.circom` source under `circuits/<protocol>/`, then run
   `tools/build_vks.sh <id>`. See `circuits/README.md` for the full
   authoring workflow and `circuits/UPSTREAM.md` for the Aave V3
   provenance. The script writes directly into `secure/data/vks/`.
2. Add a protocol block to `secure/data/vks.json` listing every
   `(chain_id, contract)` deployment that shares this VK:
   ```json
   {
     "protocol": "aave-v3-pool-v1",
     "vk_file": "aave_v3_pool.vk.bin",
     "deployments": [
       { "chain_id": 1,     "address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
         "label": "Aave V3 Pool, Mainnet" }
     ]
   }
   ```
3. Run `cargo run -p dbgen`.
4. **Audit the diff of `secure/data/vks.review.txt`** — this file is a
   build-traceability artifact, NOT a governance comparison sheet.
   The reviewer diffs it against the previous release to confirm no
   unexpected `(chain_id, contract, sha256(vk))` triples were added,
   then signs the firmware release. The trust chain is entirely
   offline: firmware-signing key → `VK_DB_ROOT` in secure flash →
   Merkle proof walk → Groth16 verification. No on-chain comparison.
5. Commit the new `circuits/<protocol>/` sources, the new
   `vks/*.vk.bin`, the updated `vks.json`, the regenerated
   `nonsecure/src/vk_db.bin`, and the regenerated
   `secure/src/db_roots.rs` and `secure/data/vks.review.txt`.

### Sanity guards

- **Round-trip test** — `dbgen` parses every `.bin` it just wrote back
  through its own host-side mirror of the runtime parser and walks
  every generated Merkle proof up to the root. Any writer/reader
  drift fails the build immediately.
- **Magic-bytes validator** — `nonsecure/build.rs` sniffs the first
  four bytes of `erc20_db.bin` (`b"ERC2"`) and `vk_db.bin` (`b"VKDB"`)
  on every NS build. If the JSON was edited but `dbgen` was never
  rerun, the secure firmware still links fine but the non-secure
  build panics at compile time with a clear "run `cargo run -p dbgen`"
  message.
- **Release-review manifest** — `secure/data/vks.review.txt` is a
  build-artifact (checked in alongside the binary) that lists every
  pinned VK with its SHA-256 for human inspection at
  firmware-signing time.

### Regenerating + running the automated tests

```bash
cargo run -p dbgen     # regenerate all four outputs from source JSON
make all               # build both worlds
make e2e               # scripted end-to-end: all four trust levels in QEMU
```

`make e2e` compiles both worlds with the `e2e-test` cargo feature
(deterministic provisioning + auto-confirm + dispatch logging), runs
QEMU with stdin closed, and asserts every scenario routed to the
right `TxKind` variant AND returned `NscStatus::Ok`. See
[docs/architecture.md](docs/architecture.md) for the full test
spec and the four scenarios it runs.

## Cryptographic Primitives

Every primitive that touches a secret is listed below with its post-quantum status. Anything marked **classical** is wrapped inside something marked **PQ** before any secret reaches it.

| Where | Primitive | Key / output size | PQ status | Notes |
|---|---|---|---|---|
| **Transaction signing** | SLH-DSA-SHA2-192f (FIPS 205) | sig 35 664 B, pk 48 B | ✅ PQ | Hash-based, no number-theoretic assumptions. Frozen as part of the recovery contract |
| **Firmware signing (primary)** | ML-DSA-65 (Dilithium3, FIPS 204) | sig ~3 309 B, pk ~1 952 B | ✅ PQ | Verified by OEMiROT before any of your code runs |
| **Firmware signing (backup leg)** | Ed25519 | sig 64 B, pk 32 B | ❌ classical | Hybrid safety net while ML-DSA matures. **Both** signatures must verify. Drop in a future hardware revision once ML-DSA has the same battle-test history as Ed25519 |
| **Inner PQ wrap (both halves)** | ML-KEM-1024 (Kyber, FIPS 203) | ct 1568 B, pk 1568 B, sk 3168 B | ✅ PQ | Encapsulates a 32-byte AES-256-GCM key per stored half. The PQ secret key is HUK-SAES-wrapped in U585 secure flash |
| **Inner wrap AEAD** | AES-256-GCM | key 32 B, tag 16 B | ✅ PQ | Grover halves to 2^128, still well above the 2^80 brute-force barrier |
| **Tropic01 wire channel (outer)** | Noise_KK1 = X25519 + ChaCha20-Poly1305 (chip-defined) | k 32 B | ❌ classical | Carries opaque PQ-wrapped ciphertext only. A future CRQC that breaks X25519 from harvested traffic decrypts → still ML-KEM ciphertext |
| **SE050 wire channel (outer)** | SCP03 (AES-CMAC + AES-CBC) or FastSCP (ECDH + AES) | k 16/32 B | ⚠️ mixed | SCP03 symmetric cipher is PQ-safe; FastSCP key establishment is ECDH and is *classical*. Both transport opaque PQ-wrapped ciphertext only |
| **SE chip attestation (factory)** | ECDSA over a vendor curve | — | ❌ classical | Treated as proof of presence, not as the cryptographic root of identity |
| **Cryptographic device identity** | ML-DSA-65 device certificate, signed at provisioning by your manufacturing-HSM root, pinned in HDPL1 OEMiROT | sig ~3 309 B | ✅ PQ | This is the actual root of trust for "is this physical device the one we provisioned" |
| **Auth-key derivation (PIN → K_T, K_E)** | HKDF-SHA256 | out 32 B | ✅ PQ | SHA-256 retains 128-bit collision resistance under Grover. PIN brute-force is rate-limited by the SE hardware (MACD slot destruction on Tropic01, UserID attempt counter on SE050), not by CPU cost |
| **MAC-and-Destroy chain (Tropic01)** | HMAC-SHA256 | out 32 B | ✅ PQ | Same |
| **BIP-39 → SPHINCS+ seed expansion** | PBKDF2-HMAC-SHA512 (2048 iters) + HKDF-SHA256 | out 72 B | ✅ PQ | SHA-512 retains 256-bit pre-image resistance under Grover |
| **At-rest key wrapping (U585)** | AES-256 via SAES, key derived from per-die HUK | k 32 B | ✅ PQ | The HUK never leaves the SAES peripheral |
| **Anti-rollback monotonic counter** | SHA-256 hash chain in OBKEY area | — | ✅ PQ | |
| **TRNG entropy mixing** | XOR of three independent hardware TRNGs | 32 B | ✅ PQ | Quantum mechanics offers nothing against true randomness |
| **Recovery encoding** | BIP-39 24 words ↔ 256-bit entropy | 32 B | ✅ PQ | 256 bits ≥ 128-bit PQ security |
| **ZK clear-sign verifier** | Groth16 over BLS12-381 (4 pairings, no alloc) | proof 384 B, vk 960 B | ❌ classical | Verifies that a human-readable string is a faithful ABI interpretation of the calldata. Not part of the seed/recovery contract — only gates *what gets displayed before signing*. A CRQC break of BLS12-381 would let an attacker forge a proof for a misleading display string, but cannot leak the seed. Migration target: STARKs / Plonky3 once the proof sizes fit in flash |
| **ZK public-signal binding** | Poseidon over BLS12-381 scalar field (alpha=5, Hades) | digest 32 B | ❌ classical | Binds calldata + readable string into the Groth16 public inputs. Same threat model as the verifier itself |
| **ZK VK authentication** | SHA-256 Merkle tree over pinned (chain_id, contract, vk) leaves; 32-byte root embedded in secure flash | root 32 B | ✅ PQ | Trust anchor is the firmware-signing key itself: the release reviewer diffs `secure/data/vks.review.txt` against the previous release and confirms the added rows correspond to circuits actually authored under `circuits/`. Fully offline — no on-chain governance lookups anywhere in the project. NS provides the VK + proof at sign time; S verifies the Merkle proof against its embedded root before Groth16 ever runs |
| **ERC20 metadata authentication** | SHA-256 Merkle tree over pinned (chain_id, contract, name, symbol, decimals) leaves; 32-byte root in secure flash | root 32 B | ✅ PQ | Same Merkle anchor as the VK DB. Stops NS from lying about "this is USDC" — trusted-display text only renders if the proof walks cleanly up to the embedded root |

**Frozen choices** (part of the recovery contract — changing any of these means the same 24 words produce a different keypair):

| Parameter | Value | Why |
|---|---|---|
| SLH-DSA parameter set | `SHA2_192f_simple` | ~192-bit PQ security, Cortex-M33 friendly via HASH peripheral, signature fits in 36 KB SRAM budget |
| BIP-39 → SLH-DSA expansion | HKDF-SHA256, info=`"sphincs-slh-seed/v2"` | v2 = the post-192f rev. v1 was the development 128f path |
| KEM | ML-KEM-1024 | NIST level 5, 256-bit PQ security, biggest parameter that still fits the BOM |
| KEM-AEAD binding | AES-256-GCM with key = `HKDF(K_shared, info="pq-wrap/v1")` | |

## Quantum Threat Model

This section names exactly which quantum threats we defend against and which ones we honestly cannot.

### The dominant threat: Harvest Now, Decrypt Later (HNDL)

An adversary records every byte of I²C / SPI traffic between U585, Tropic01, and SE050 today, archives it for 10–20 years, and decrypts it once a cryptographically-relevant quantum computer (CRQC) exists. For a hardware wallet that holds long-term funds, **this is the dominant quantum threat** — the adversary doesn't need to be near the device when they decrypt, only when the device was used.

**How this design defeats HNDL:**

1. The classical Noise_KK1 / SCP03 layer carries only **ML-KEM-1024-encapsulated AES-256-GCM ciphertext**, never plaintext halves. When a CRQC breaks X25519/ECDH and decrypts the captured outer layer, the result is still an opaque ML-KEM ciphertext.
2. Decapsulating that requires the ML-KEM-1024 secret key, which lives only inside a HUK-SAES-wrapped blob in U585 secure flash. Recovering it requires physical extraction of the *specific* U585 die, plus a working attack on STM32U5 RDP-2, plus extraction of the per-die HUK from the SAES peripheral.
3. Even granted all of that, the attacker has only one half. The other half is on the *other* SE, encrypted under a *different* ML-KEM ciphertext, gated by the *other* SE's PIN-bound retry counter, which is destroyed after 9 wrong PIN attempts.

In short: HNDL recovers ML-KEM ciphertext, not seeds. You can post the captured I²C traces on the internet without consequence.

### The residual classical surface

We are honest about what we cannot make PQ:

| Residual surface | What it lets a CRQC attacker do | Why we accept it |
|---|---|---|
| **Tropic01 secure-channel authentication** (Noise_KK1 uses X25519 for both KEM and identity) | After breaking X25519, an active attacker with physical I²C access *while the device is running* could MITM the Tropic01 channel | MITM requires *real-time* physical bus tampering on a powered device. Already a stronger access requirement than HNDL. The PQ inner-wrap means even a successful MITM of the outer channel cannot read the half. The attacker can at best deny service |
| **SE050 secure-channel authentication** (ECDSA / ECDH for SCP03 ECKey) | Same as above for SE050 | Same. The PQ wrap inside makes confidentiality independent of the channel |
| **SE factory attestation chains (both ECDSA)** | A CRQC attacker with the manufacturer's silicon could mint a forged attestation that survives boot-time verification | We treat factory attestation as proof of presence only. The cryptographic identity of the device is the **ML-DSA-signed device certificate** pinned in HDPL1 OEMiROT — this is what actually gates "is this device the one we provisioned" |
| **Tropic01 / SE050 internal firmware** uses classical primitives we cannot inspect or replace | A CRQC class-break of Tropic01 or SE050 could expose the contents of one chip's storage | The other chip still holds the other half, encrypted under a *different* ML-KEM key. Single-chip compromise reveals zero bits of the seed |
| **U585 RDP-2 + HUK-SAES** depends on the security of an AES-256 wrap and STM32 hardware countermeasures, which are not formally PQ-certified | A CRQC + invasive die work could in theory recover the HUK and unwrap the ML-KEM secret key | This is the irreducible "physically extract the specific U585 die" attack. Tamper mesh, BOR-fired wipe, and the inactivity timer are the mitigations. Same threat as today minus the quantum part |

### What we explicitly do *not* defend against

- **Coerced unlock.** No PIN-gated wallet survives the user being forced to enter the PIN. PQ does not change this.
- **Active CRQC adversary with sustained physical access to a powered, unlocked device.** Same answer as today: the irreducible attack window is the active session in S-SRAM.
- **A future cryptanalytic break of SLH-DSA, ML-KEM, or ML-DSA.** We pick the most conservative parameter sets available (192-bit PQ for signing, level-5 for KEM) and we hybrid-sign firmware so a class-break of *one* PQ scheme does not immediately compromise updates.
- **Side-channel and fault attacks against the U585 silicon.** PQ is orthogonal. Mitigated by the same HARDENING.md measures as the classical design.

### Why hash-based signatures (SLH-DSA) for the actual money

Lattice schemes (ML-DSA, ML-KEM) rely on the hardness of LWE / Module-LWE. These are believed to resist quantum attacks, but the security reduction is much less mature than the half-century of cryptanalysis behind hash functions. **For the wallet's signing key — the thing that authorises moving funds — we use SLH-DSA, whose only assumption is the security of SHA-256.** If a lattice break ever appears, your transaction signatures are unaffected; only the firmware update and wrap layers need to migrate, and the wallet itself keeps signing.

We use ML-DSA only for firmware signing (because the signature size matters more there) and ML-KEM only for inner-wrap confidentiality (because it's the only PQ KEM with practical sizes). If lattices fall, the recovery path is: ship a firmware update — signed by the *Ed25519 hybrid leg* of OEMiROT — that swaps ML-KEM for a hash-based KEM (e.g. classic McEliece) and ML-DSA for SLH-DSA. The wallet's funds are never at risk because the transaction-signing key never depended on lattices.

## Security Model

| Layer | Protection |
|-------|------------|
| **Seed at rest (Tropic01 half)** | `half_T` is **ML-KEM-1024-encapsulated + AES-256-GCM-sealed** before it ever crosses the SPI bus. The opaque PQ-wrapped blob is then XOR-encrypted under the MAC-and-Destroy chain (10 attempts, AppNote scheme), opened only by `K_T = HKDF(PIN, "tropic01-pairing/v1")` |
| **Seed at rest (SE050 half)**    | `half_E = E ⊕ half_T` is **ML-KEM-1024-encapsulated + AES-256-GCM-sealed** in U585 before being written to an SE050 binary object. The object's `ALLOW_READ` policy is bound to a single AES (or ECKey) auth object, opened only inside an SCP03 session. The SE050 only ever sees PQ ciphertext |
| **PQ inner-wrap secret key** | ML-KEM-1024 secret key (3168 B) lives only in U585 secure flash, HUK-SAES-wrapped. Never decapsulates unless an unlock is in progress. Used for both halves with separate domain-separation tags |
| **Seed reconstruction** | `E = HKDF(half_T ‖ half_E, info="bip39-entropy/v2")` happens *only* in U585 secure SRAM, for microseconds, then zeroized. Mnemonic and SLH-DSA seed are recomputed every unlock and never persisted in any form |
| **Key transport (Tropic01, outer)** | Noise_KK1 e2e encrypted SPI session (X25519 + ChaCha20-Poly1305), per-device pairing key generated from TRNG at first provisioning and stored in secure flash (page 127, `0x0C0FE000`). **Carries only ML-KEM ciphertext** — even a complete CRQC break of X25519 reveals only the inner PQ blob |
| **Key transport (SE050, outer)** | SCP03 (or FastSCP / ECKey), static keys HUK-SAES-wrapped in U585 secure flash. **Carries only ML-KEM ciphertext.** A flash dump moved to a different U585 is useless |
| **PIN handling** | Raw PIN is KDF-stretched to per-chip auth keys inside the secure world; PIN buffer wiped before the gateway returns. K is split via HKDF into per-chip auth keys K_T and K_E; raw PIN never crosses to either SE. Brute-force is rate-limited by SE hardware (MACD slot destruction / UserID attempt counter), not by CPU cost |
| **Retry counters** | Both chips share a 10-attempt cap. Each PIN attempt is bracketed by a `PENDING{attempt=N+1}` record in S-flash so a power glitch between Tropic01 and SE050 increments cannot grant a free retry. If the two counters ever disagree on boot, the wallet wipes |
| **Boot attestation** | Fresh U585-TRNG nonce signed independently by Tropic01 and SE050, both certificate chains verified against pinned vendor roots, both UIDs matched against pinned values. Any failure ⇒ no PIN entry |
| **RNG** | Wallet entropy = `STM32_TRNG ⊕ Tropic01_TRNG ⊕ SE050_TRNG`. All session nonces from STM32 TRNG. No software PRNGs |
| **Memory isolation** | TrustZone (SAU + IDAU + MPC + GTZC), DMA mastering into secure SRAM blocked, NS pointer validation on every gateway call, no panics across NSC |
| **Inactivity / power loss** | Secure-only TIM enforces a 2-minute idle wipe. TAMP and BOR fire the same wipe ISR. Bulk cap sized so the ISR completes under brownout |
| **Crash safety** | Custom panic handler zeroizes secrets and resets before halting |
| **Build hardening** | LTO, overflow checks, debug info stripped, git deps pinned, `cargo audit` + `cargo deny` in CI |
| **Production** | RDP Level 2 burned as the final provisioning step (irreversible). Both SE auth-object policies frozen in the same provisioning session |

### Boot → Unlock → Sign → Lock lifecycle

Every step below runs in the **secure world**. The non-secure world drives nothing more sensitive than "show this string" and "user pressed a button"; the gateway is an opaque request channel and never sees a secret, a PIN digit, or a confirm decision.

```
   POWER ON
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ 1. SECURE BOOT                                               │
│    • Configure SAU / IDAU / MPC / GTZC                       │
│    • Mark OLED bus, button GPIOs, both SE buses, TRNG, HASH, │
│      SAES, TAMP, BKPSRAM as Secure-only                      │
│    • Verify NS image signature before enabling NS            │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ 2. DUAL-CHIP ATTESTATION  (refuses to proceed on any failure)│
│    nonce ← STM32_TRNG                                        │
│                                                              │
│    ── Tropic01 ──────────────────                            │
│       open Noise_KK1 with HUK-wrapped pairing key            │
│       request cert chain → verify against pinned             │
│         Tropic Square root in S-flash                        │
│       verify pinned UID                                      │
│                                                              │
│    ── SE050 ──────────────────                               │
│       open transient SCP03 with HUK-wrapped static key       │
│       request attestation signature over nonce               │
│       verify chain against pinned NXP root in S-flash        │
│       verify pinned UID                                      │
│                                                              │
│    on FAIL  → secure OLED shows tamper warning, halt         │
│    on PASS  → boot NS world, show "Enter PIN" on OLED        │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ 3. PIN ENTRY  (trusted path — runs entirely in S-world)      │
│    • OLED draws the PIN entry UI                             │
│    • Button GPIOs read directly by S-world ISR               │
│    • Raw digits live ONLY in a Secure-SRAM buffer            │
│    • NS never sees the digits, never sees the cursor pos     │
│    • PENDING{attempt = N+1} written to S-flash atomically    │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ 4. UNLOCK BOTH SECURE ELEMENTS  (with PQ inner wrap)         │
│    K_T = HKDF(PIN, "tropic01-pairing/v1")                    │
│    K_E = HKDF(PIN, "se050-aeskey/v1")                        │
│    sk_pq = SAES_unwrap(HUK, sk_pq_wrapped)  // ML-KEM-1024   │
│    zeroize(PIN_buffer)                                       │
│                                                              │
│    ── Tropic01 ─────────────────────                         │
│    macd_blob = Tropic01.macd_unlock(slot=N, K_T)             │
│    pq_blob_T = AES-GCM-decrypt(K_macd, macd_blob)            │
│              = ct_T ‖ aead_T                                 │
│    K_share_T = ML-KEM-1024.Decaps(sk_pq, ct_T)               │
│    half_T    = AES-GCM-decrypt(HKDF(K_share_T,"pq-wrap/v1"), │
│                                aead_T)                       │
│                                                              │
│    ── SE050 ─────────────────────                            │
│    pq_blob_E = SE050.scp03_open(K_E).read_binary("half_E")   │
│              = ct_E ‖ aead_E                                 │
│    K_share_E = ML-KEM-1024.Decaps(sk_pq, ct_E)               │
│    half_E    = AES-GCM-decrypt(HKDF(K_share_E,"pq-wrap/v1"), │
│                                aead_E)                       │
│                                                              │
│    zeroize(K_share_T, K_share_E, sk_pq, K_T, K_E,            │
│            ct_T, ct_E, aead_T, aead_E)                       │
│                                                              │
│    BOTH advance their retry counters as part of the SAME     │
│    PENDING transaction. If either side fails, both counters  │
│    are forced to position N+1 on next boot.                  │
│                                                              │
│    On 9th wrong PIN: both halves are destroyed in hardware.  │
│    On correct PIN:   both counters reset to 0, PENDING clear │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ 5. RECONSTRUCT IN SECURE SRAM ONLY                           │
│    E         = HKDF(half_T ⊕ half_E, info="bip39-entropy/v2")│
│    zeroize(half_T) ; zeroize(half_E)                         │
│    mnemonic  ← BIP-39(E)         (in-memory only, never shown)│
│    bip39_seed ← PBKDF2-HMAC-SHA512(mnemonic, "", 2048)        │
│    slh_seed  ← HKDF(bip39_seed, "sphincs-slh-seed/v2")        │
│    sk        ← SLH-DSA-SHA2-192f.keygen(slh_seed)             │
│    zeroize(mnemonic) ; zeroize(bip39_seed) ; zeroize(slh_seed)│
│                                                              │
│    Cached for the active window: { E, sk, vk }               │
│    Not cached: PIN, K, K_T, K_E, sk_pq, K_share_*,           │
│                half_T, half_E, mnemonic, bip39_seed, slh_seed│
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ 6. ACTIVE WINDOW  (≤ 120 s of inactivity)                    │
│                                                              │
│    Inactivity timer = Secure-only TIM. NS cannot read,       │
│    pause, reset, or reprogram it. The S-world is the SOLE    │
│    authority on what counts as "activity":                   │
│      • a real button press during a confirm dialog → reset  │
│      • a successful sign confirmation              → reset  │
│      • NS gateway calls (get_pubkey, get_remaining)→ ignored │
│      • NS spamming "I'm alive" pings              → ignored │
│                                                              │
│    For each sign request from NS:                            │
│      a. NS posts {hash, decoded_tx_blob} via gateway         │
│      b. S-world parses tx, draws decoded EIP-1559 fields     │
│         on the secure OLED (chain, to, value, gas, nonce)   │
│      c. User presses CONFIRM (long-press both buttons) on    │
│         the secure buttons — input goes straight to S-ISR   │
│      d. S-world signs hash with cached `sk`                  │
│      e. S-world VERIFIES the signature before releasing it   │
│         (fault-injection guard — refuse + wipe on mismatch) │
│      f. signature returned to NS via gateway                 │
│      g. inactivity timer reset                              │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ 7. LOCK / WIPE  (any of these triggers it)                   │
│    • 120 s of true inactivity                                │
│    • TAMP event (case switch, mesh, voltage glitch)          │
│    • BOR (brownout) interrupt                                │
│    • Any NSC call panic, integrity-check failure, or         │
│      unexpected reset reason                                 │
│    • Sign verification mismatch (fault detected)             │
│                                                              │
│    Wipe ISR:                                                 │
│      zeroize { E, sk, vk, any stack region used by signing }│
│      clear caches, clear CPU registers                       │
│      loop-twice + verify (defensive against single-fault)    │
│      return to "Locked" screen → next sign needs PIN again   │
└──────────────────────────────────────────────────────────────┘
```

**The five invariants the dual-SE design hangs on:**

1. **Trusted path is contiguous from button → S-ISR → OLED → S-world.** GTZC must mark the OLED bus, the two button GPIO pins, *both* SE buses, TRNG, HASH, and SAES as Secure-only. If NS can drive the OLED, it can spoof "send 0.01 ETH to alice" while you're signing "send 100 ETH to attacker". This is non-negotiable.
2. **The PIN buffer never crosses the NSC boundary in either direction.** PIN entry happens in S-world; the gateway doesn't even have an `enter_pin(bytes)` call any more — it has `unlock()` which kicks the S-world UI loop and returns only success/failure.
3. **Activity is defined by the S-world, never the NS world.** A compromised NS image cannot keep the seed alive by spamming pings. Only physical user input on a real S-world dialog counts. (This is already enforced in `secure/src/timeout.rs:9-11`.)
4. **The PIN unlocks BOTH chips or NEITHER.** A PENDING intent log in S-flash brackets every attempt; if a power glitch lands between Tropic01 and SE050 counter writes, the boot path forces both to the post-attempt position. The wallet wipes if the two counters ever disagree.
5. **The cached active-window state is `{E, sk, vk}` and nothing else.** Half-secrets, derived keys, mnemonic, bip39_seed, slh_seed are wiped at the unlock boundary, before any signing happens. The wipe ISR for timer/TAMP/BOR has only three things to clear.

### Why two secure elements?

A single secure element is a single point of trust. Whether the failure mode is a vendor-specific firmware bug, a published power-analysis attack, or invasive die work, *one* die compromise should not be enough to extract a wallet seed.

| Attack | Single-SE wallet | Dual-SE (this design) |
|---|---|---|
| Class-break on one vendor's firmware | seed exposed | other half still secret — zero bits leaked |
| Invasive die attack on one chip | seed exposed | other half still secret |
| Backdoored RNG in one chip | biased entropy | XOR with two other RNGs preserves uniformity |
| Stolen powered-off device | bounded by one retry counter | bounded by *both* counters; wipe on divergence |
| U585 NS world compromise | no impact | no impact |
| U585 secure SRAM compromise during active unlock | full break | full break (irreducible window — minimised by short lifetime) |

The cost is one extra I²C peripheral, ~$3 BOM, and ~50 ms added unlock latency.

See [docs/architecture.md](docs/architecture.md) for the technical design, [docs/HARDENING.md](docs/HARDENING.md) for the consolidated hardening requirements, and [docs/m4-cowswap-eip712.md](docs/m4-cowswap-eip712.md) for the CowSwap EIP-712 order clear-signing handoff (deferred M4 milestone — read this before attempting that work).

## Implementation Status

**Legend**

- 🟢 **QEMU-tested** — runs and is exercised end-to-end on QEMU mps2-an505
- 🟢 **HW-tested** — runs and is exercised end-to-end on a real STM32U585 devkit via ST-LINK + probe-rs (`make e2e-hw`)
- 🟡 **QEMU + USB devkit** — runs in QEMU, driven against a real Tropic01 TS1302 USB devkit bridged in via host semihosting (i.e. *not* connected to a real STM32)
- 🔵 **Code exists, untested** — written but not exercised end-to-end
- ⏳ **Not started** — target architecture, not yet written
- 🚫 **Blocked on hardware** — cannot be implemented or validated until a real PCB exists

> STM32U585 bring-up is in progress on a B-U585I-IOT02A devkit driven via ST-LINK + probe-rs. Rows tagged 🟢 HW-tested run end-to-end under `make e2e-hw` on real silicon (TrustZone partitioning, GTZC, CMSE veneer gateway, clock/RCC, TRNG, mock SE path). Rows that are still purely 🟢 QEMU-tested describe behaviour that *should* port to silicon but has not yet been re-validated — assume it is untested on real hardware until proven otherwise.

| Component | Status | Where it runs today |
|---|---|---|
| TrustZone partitioning (SAU + IDAU + MPC/GTZC) | 🟢 QEMU-tested, 🟢 HW-tested | mps2-an505 MPC in QEMU; GTZC MPCBB1/MPCBB2 on real STM32U585 (SRAM1 secure, SRAM2 non-secure) |
| NSC gateway (6 commands, NS pointer validation) | 🟢 QEMU-tested, 🟢 HW-tested | On STM32U585: real ARMv8-M CMSE `cmse-nonsecure-entry` veneers driven by `BLXNS`/SG/`BXNS`, exercised by `make e2e-hw`. On QEMU: shared-memory mailbox + SysTick poll as a workaround for the QEMU MPC S-alias bug. |
| BIP-39 → SLH-DSA-SHA2-128f deterministic key derivation | 🟢 QEMU-tested | mps2-an505 (will migrate to 192f for production — recovery contract bump v1→v2) |
| MAC-and-Destroy PIN with 10-attempt brick (Tropic01 path) | 🟡 QEMU + USB devkit | Logic in QEMU, MACD slot ops against a TS1302 dongle on `/dev/ttyACM0` |
| Tropic01 e2e encrypted (Noise_KK1) sessions | 🟢 Real hardware | Tested on STM32U585 + Tropic01 MicroE Clicker (SPI1 via Arduino headers). Full provisioning + MACD PIN unlock verified. |
| Trusted UI: OLED draw + 2-button input | 🟢 QEMU-tested | Mock backend prints to QEMU semihosting console; the SSD1306 driver path compiles but is unrun |
| Seed wizard / PIN entry / EIP-1559 confirm dialogs | 🟢 QEMU-tested | mps2-an505, against the mock UI backend |
| `slh-dsa`, `aes-gcm`, `sha2`, `hmac`, `bip39` crate integration | 🟢 QEMU-tested | mps2-an505 |
| `#![no_std]`, no-heap, zeroize discipline | 🟢 QEMU-tested | mps2-an505 |
| Custom panic handler that wipes the master secret | 🟢 QEMU-tested | mps2-an505 |
| Inactivity timeout / activity tracking | 🟢 QEMU-tested | mps2-an505 (driven by SysTick, not the Secure-only TIM that production will use) |
| ZK clear signing — Groth16 / Poseidon over BLS12-381 (no alloc) | 🟢 QEMU-tested | mps2-an505 secure world; host-side `zk-test` crate verifies the Aave V3 supply proof end-to-end against ZKlarity's reference Poseidon |
| ZK VK DB in NS rodata + secure-world Merkle verifier | 🟢 QEMU-tested | 32-byte root embedded in S via `db_roots.rs`; NS supplies VK + proof per request; S verifies before Groth16 |
| ERC20 metadata DB in NS rodata + secure-world Merkle verifier | 🟢 QEMU-tested | 32-byte root embedded in S; `dispatch_tx` picks five trust levels per tx |
| Automated end-to-end test (`make e2e`) | 🟢 QEMU-tested | Non-interactive; exercises all four sign-dispatch levels back-to-back; no stdin input required |
| **STM32U585 silicon bring-up (any form)** | ⏳ not started | — |
| **Custom PCB with Tropic01 + SE050 + U585** | ⏳ not started | — |
| **CMSE veneer gateway (real one, not the shared-memory shim)** | 🟢 HW-tested | All six `nsc_*` `cmse-nonsecure-entry` veneers emitted into `veneers.o`, linked into the NS image, and exercised end-to-end under `make e2e-hw` on a real STM32U585. No mailbox, no poll — NS calls enter via `BLXNS` → SG → secure handler → `BXNS`. |
| **SSD1306 OLED driver on real I²C** | 🔵 code exists, untested | `secure/src/ui/oled.rs` compiles, no hardware to run it |
| **Migrate transaction signing to SLH-DSA-SHA2-192f** | ⏳ not started | — |
| **SE050 SCP03 integration** | ⏳ not started | — |
| **XOR split entropy across both SEs** | ⏳ not started | currently the full 32 B entropy lives on Tropic01 only |
| **ML-KEM-1024 inner-wrap layer for both halves** | ⏳ not started | requires `ml-kem` crate audit + HUK-SAES wrap of `sk_pq` |
| **Dual-chip retry counter sync (intent log in S-flash)** | ⏳ not started | — |
| **Boot-time attestation of both chips** | ⏳ not started | — |
| **Firmware measurement at boot (SHA-256 → 8 BIP-39 words)** | ✅ done | visual trustless verification via `fwmeasure` host tool |
| **Hash-signature firmware update model (ML-DSA-44)** | ⏳ not started | manufacturer signs measurement hash, users build from source |
| **ML-DSA-65 device identity certificate pinned in HDPL1** | ⏳ not started | — |
| **Mixed-RNG entropy generation (TRNG ⊕ TRNG ⊕ TRNG)** | ⏳ not started | currently semihosting `/dev/urandom` under QEMU |
| **STM32 TRNG, HASH, SAES, TAMP, BOR, BKPSRAM peripheral drivers** | ⏳ not started | — |
| **GTZC configuration (S/NS peripheral attribution)** | ⏳ not started | — |
| **HUK-SAES key wrapping for at-rest secrets** | 🚫 blocked on hardware | HUK only exists on real silicon |
| **TAMP / BOR / inactivity wipe ISR on real silicon** | 🚫 blocked on hardware | — |
| **RDP Level 2 burn** | 🚫 blocked on hardware | irreversible — final production step |
| **Power-loss tests, fault-injection tests, side-channel tests** | 🚫 blocked on hardware | requires real silicon + lab access |

## Firmware Update Model

The wallet uses a **hash-signature** model for firmware updates that combines open-source reproducible builds with manufacturer approval. This is the planned design — not yet implemented.

### How it works

```
Manufacturer (one-time per release):
  1. Reviews and merges source code
  2. CI builds firmware → SHA-256 hash → 8 BIP-39 words
  3. Signs the hash with manufacturer private key (ML-DSA-44)
  4. Publishes the signature (~2.4 KB) on GitHub Releases

User (can be anyone):
  1. Clones repo, builds firmware from source (reproducible build)
  2. Runs `make measure` → gets the same 8 words (same source = same binary = same hash)
  3. Downloads the manufacturer's published signature for those words
  4. Packages firmware + signature → flashes device via companion app

Device (on boot after update):
  1. SHA-256 hashes the installed firmware → computes 8 words
  2. Verifies the signature against the manufacturer's public key (stored in flash/OTP)
  3. Signature valid + hash matches → accept, display words, continue boot
  4. Signature invalid → reject update / refuse to boot / show warning
```

### Why this works

- **Signing the hash IS signing the firmware.** SHA-256 collision resistance guarantees that a valid signature on hash H proves the firmware is the exact binary that was approved. No other binary can produce the same hash.
- **Decoupled build from approval.** The manufacturer never distributes binaries — only a tiny signature. Users build from source. The manufacturer approves a hash, not a binary.
- **Neither side can cheat.** Users can't forge the signature (need the private key). The manufacturer can't sign firmware that doesn't match the public source code (anyone can reproduce the build and compare the hash).
- **Pre-installed malicious firmware is caught.** Even if a device ships with fake firmware that hardcodes the "correct" words, the first legitimate signed update invalidates it — the fake firmware can't predict the SHA-256 of a future binary that hasn't been written yet.
- **No binary distribution needed.** The signature is ~2.4 KB and can be published anywhere: GitHub release, website, QR code, companion app API. Users always build from source.

### Implementation notes

- **Signature storage:** The signature must be stored *outside* the measured flash region (otherwise it changes the hash → circular dependency). A dedicated flash page or a separate USB transfer during the update handshake.
- **Manufacturer public key:** Stored in OTP or WRP-protected flash. Supports key rotation via a signed key-update message.
- **Signature scheme:** ML-DSA-44 (FIPS 204) — post-quantum, ~2.4 KB signatures. Consistent with the wallet's PQ-only philosophy.
- **Companion app:** The companion app can embed the `fwmeasure` logic (SHA-256 + BIP-39 word encoding) to compute expected words instantly, and also support cloning + building from source for full reproducible verification.

### Future: immutable bootloader (defense-in-depth)

The current measurement code runs as part of the firmware it measures. A defense-in-depth upgrade would split the measurement into an **immutable bootloader** in WRP-locked flash pages that cannot be modified by any software update. This adds protection against a compromised update that replaces both the firmware and the measurement code simultaneously. See `docs/work-todo.md` for status.

## Bring-up Roadmap (QEMU → Real Silicon → Production)

There is no "port" — none of this code has touched a real STM32U585 yet. The path from where the repo is today to a manufacturable wallet is roughly four phases. Each phase has a hard exit criterion before the next one starts.

### Phase 0 — current state

Everything in this repo runs in QEMU mps2-an505. Tropic01 is exercised against a TS1302 USB devkit through host semihosting. SE050 is unintegrated. The core crypto, the trusted UI loop, the gateway, the seed wizard, and the Tropic01 single-SE flow all work in this environment. **None of it has executed a single instruction on a real Cortex-M33 silicon die.**

### Phase 1 — STM32U585 bring-up on a Nucleo or B-U585I-IOT02A devkit

Goal: get the existing QEMU code running on a real ST eval board, with no SE050, no custom PCB, no PQ wrap, and no RDP-2. Pure firmware bring-up.

1. Order a **B-U585I-IOT02A** discovery kit and a separate Tropic01 TS1302 devkit
2. Update `memory.x` with STM32U585 flash and SRAM addresses (768 KB SRAM, 2 MB flash)
3. Switch from the QEMU mps2-an505 runtime to **Embassy / `embassy-stm32`** for clocks, GPIO, SPI, I²C, USART
4. ~~Replace the shared-memory gateway shim with **proper CMSE veneers**~~ **DONE** — the STM32U585 build compiles out the mailbox entirely and routes all six gateway commands through `extern "cmse-nonsecure-entry"` veneers. `make e2e-hw` drives all six sign-dispatch scenarios end-to-end through the real SG stubs on a B-U585I-IOT02A.
5. Replace `host_rng` with the **STM32U585 TRNG** peripheral
6. ~~Replace `SemihostingSpi` with a real SPI driver~~ **DONE.** Bare-metal `Stm32Spi` driver (`hw/spi_hw.rs` + `hw/spi.rs`) supports SPI1 (Arduino headers, `spi1-arduino`) and SPI2 (direct wiring, default)
7. Wire the SSD1306 OLED to the U585's I²C and confirm the existing `oled.rs` backend works on real glass
8. Wire two physical buttons to GPIO pins, with a debouncer + long-press detector in the secure ISR
9. Run the existing seed wizard / PIN entry / sign confirm flow end-to-end on real hardware
10. **Exit criterion:** the existing QEMU smoke test passes on a real B-U585I-IOT02A, signing a real SLH-DSA-SHA2-128f signature against a real Tropic01

### Phase 2 — dual-SE + PQ wrap, still on the devkit

Goal: layer in SE050, the split-entropy logic, the ML-KEM inner wrap, and the bigger SLH-DSA parameter set, all on the same devkit before any custom PCB exists.

1. Add an **NXP SE050 devkit** (OM-SE050ARD or similar) on a second I²C bus
2. Add a `Se050SecureElement` driver behind a new `SplitSecureElement` trait, using the `se05x` crate or a hand-rolled SCP03 implementation
3. Implement **boot-time attestation of both chips** with pinned vendor roots and pinned UIDs
4. Implement the **mixed-RNG entropy generator**: `STM32_TRNG ⊕ Tropic01_TRNG ⊕ SE050_TRNG`
5. Migrate transaction signing from `Sha2_128f` to **`Sha2_192f`** and bump the recovery-contract domain tags to v2 (`"sphincs-slh-seed/v2"`, `"bip39-entropy/v2"`)
6. Add the **ML-KEM-1024 inner-wrap layer** in `secure/src/crypto.rs`:
   - At provisioning, generate `(pk_pq, sk_pq) ← ML-KEM-1024.KeyGen()` from the mixed RNG
   - For now (devkit phase), store `sk_pq` in plain S-flash; HUK-SAES wrapping comes in Phase 3
   - For each half: `(ct, K_share) ← Encaps(pk_pq)`, `aead ← AES-256-GCM(HKDF(K_share, "pq-wrap/v1"), half)`, store `ct ‖ aead` on the SE
   - Audit the chosen `ml-kem` crate (RustCrypto / `pqcrypto-mlkem`) for constant-time and zeroization
7. Implement the **XOR-split provisioning + unlock paths** over the new PQ wrap
8. Implement the **dual-chip retry counter sync** with the PENDING intent log in a reserved S-flash sector
9. Implement the **TAMP / BOR / inactivity wipe ISR** wired to the Secure-only TIM
10. **Exit criterion:** end-to-end unlock + sign exercises both SEs over the PQ wrap, the seed never appears in plaintext on either bus (verified by SPI/I²C trace capture), and a 9-wrong-PIN sequence destroys both halves on real chips

### Phase 3 — custom PCB, HUK-SAES, GTZC, and the production peripheral set

Goal: move from the eval boards to a real PCB layout designed for shipping, and lock down the U585 hardware peripherals to the production configuration.

1. Design and review the **custom PCB**: U585 + Tropic01 + SE050 + OLED + buttons + tamper mesh + EMI can. PCB review by an external embedded-security specialist
2. **HUK-SAES wrap** the Tropic01 pairing keys, SE050 SCP03 (or ECKey) static keys, and the ML-KEM-1024 secret key. Store only the ciphertexts in U585 secure flash. Verify a flash dump moved to a different U585 is useless
3. Configure **GTZC** to mark every Secure-only peripheral: both SE buses, the OLED bus, the button GPIOs, TRNG, HASH, SAES, TAMP, BKPSRAM
4. Configure the **MPU** in both worlds to enforce the secret-SRAM region boundaries
5. Block all DMA controllers from mastering into Secure SRAM
6. Wire the **case switch and tamper mesh** into TAMP, with hardware noise filtering
7. Wire the **internal temperature sensor** check into the boot path and a periodic poll, with the cold-boot threshold tuned on the real PCB
8. Wire **BOR** to the wipe ISR and measure (on real hardware!) the bulk-cap holdup time so the ISR provably completes before V_dd collapses
9. **Exit criterion:** every line of section A and section E of the [shipping checklist](#pre-production-shipping-checklist) is verified on the real PCB

### Phase 4 — secure boot, provisioning, and lockdown

Goal: build the immutable PQ-OEMiROT, the HSM-backed provisioning pipeline, and burn the option bytes that turn the devkit into a one-way device.

1. Build a **custom PQ-OEMiROT** by forking TF-M for STM32U5 (or MCUboot) and replacing the ECDSA verifier with **ML-DSA-65 + Ed25519 hybrid** image verification. Both signature legs must verify before boot. ST's stock OEMiROT only supports ECDSA/RSA and will not work
2. Build the **HSM-backed provisioning pipeline** (ML-DSA-65 manufacturing key, Ed25519 manufacturing key, both in separate HSM partitions, two-person rule)
3. Build the **per-device ML-DSA-65 device-identity certificate** signing flow, with the cert pinned in HDPL1 OEMiROT alongside the manufacturing public-key hashes
4. Run the entire 13-step bring-up sequence in [Locking the STM32 to your firmware only](#locking-the-stm32-to-your-firmware-only) on a sacrificial PCB unit, including the final RDP Level 2 burn
5. Verify the locked unit refuses an unsigned firmware image, refuses SWD/JTAG, refuses bootloader fallback, and still unlocks + signs correctly through the secure UI
6. **Exit criterion:** every line of section F, F2, and G of the shipping checklist is verified on the locked device, and the post-provisioning self-test pipeline is reproducible across a small batch (e.g. 10 units) before any larger production run

### Phase 5 — pre-launch validation

Goal: external review, lab testing, public scrutiny. Nothing in this phase is software-visible — it is all process.

1. External security audit (Phase H of the checklist)
2. Fault-injection lab time on the locked PCB
3. Side-channel lab time on the locked PCB
4. Public bug bounty open before any device sells
5. Gradual rollout starting with a small batch and a long observation window before scaling
6. **Exit criterion:** every line of sections H, I, and J of the shipping checklist is verified, and the "honest caveats" page is in the box of every shipping unit

## Pre-Production Shipping Checklist

Nothing in this list is optional. Each item is something that has bricked, leaked, or burned a hardware wallet vendor in the last decade. Run through the entire list **per device class**, not per software release. A green tick on every line is the bar before any wallet leaves the facility holding user funds.

### A. Hardware design & PCB

- [ ] PCB review by an embedded-security specialist (not just the original layout engineer)
- [ ] Tropic01 and SE050 on **physically separated** I²C/SPI buses, no shared signals an attacker can multiplex
- [ ] No test pads, no debug headers, no probe points exposing either SE bus, the OLED bus, the button GPIOs, or any S-world peripheral
- [ ] Tamper mesh covering all four PCB layers across the U585 + both SEs
- [ ] Case switch wired to TAMP with hardware pull and noise filter
- [ ] BOR threshold and bulk capacitance **measured on real hardware** to confirm the wipe ISR completes under worst-case current draw before V_dd collapses
- [ ] Internal temperature sensor reads correctly across the operating envelope; cold-boot threshold tested at the rated low temperature
- [ ] No exposed SWD/JTAG pads after assembly (cut traces or fill vias)
- [ ] EMI shielding can over the U585 + both SEs
- [ ] Power rail filtering sized to mitigate the obvious ripple-injection power-analysis paths
- [ ] Crystal vs internal RC oscillator decision documented; no glitchable clock paths reach S-world peripherals
- [ ] Independent reset for each SE so a fault on one cannot wedge the other
- [ ] Spec'd component lead-time and second-source for every part on the BOM (so a Tropic01 stockout does not force a vendor swap that breaks pinned attestation)

### B. Provisioning facility

- [ ] Clean-room facility with **no network**, no removable media, no personal devices
- [ ] Provisioning station OS image is reproducible, signed, and re-imaged before every batch
- [ ] HSM-backed generation of every per-device secret (or NXP EdgeLock 2GO for SE050 at volume)
- [ ] Per-device unique: SCP03 keys (or FastSCP/ECKey), Tropic01 pairing keys, Tropic01 UID pin, SE050 UID pin
- [ ] Provisioning logs **never contain secret material** (audit every log line; CI test that scans staging logs for high-entropy strings)
- [ ] Two-person rule for any operation that touches the HSM root keys
- [ ] Tamper-evident packaging between provisioning station and shipping
- [ ] Provisioning station compromise plan: how do you detect, how do you scope the blast radius, how do you notify users of devices provisioned during the window
- [ ] Quarantine + manual review for any device that fails post-provisioning verification
- [ ] Per-batch provisioning report (who, when, which station, which firmware hash, which option-byte profile) signed and archived

### C. Firmware build pipeline

- [ ] **Reproducible builds** — same git SHA on a clean machine produces a byte-identical image, verified in CI on every push
- [ ] Toolchain version pinned in `rust-toolchain.toml`, archived per release
- [ ] All git dependencies pinned to a commit hash, no version ranges
- [ ] `cargo audit` and `cargo deny` clean, fail the build on any advisory
- [ ] `cargo-geiger` report archived per release; any new `unsafe` surface in dependencies triggers manual review
- [ ] `#![deny(unsafe_op_in_unsafe_fn, clippy::indexing_slicing)]` enforced
- [ ] Every `unsafe` block has a `// SAFETY:` comment, reviewed in code review
- [ ] LTO + overflow checks enabled in release profile (already set in `Cargo.toml`)
- [ ] Debug info stripped from the production image; no semihosting strings, no `defmt` log strings, no panic message strings reach the binary
- [ ] No `debug-log` feature enabled in the production build; CI gates on it
- [ ] Bill of materials (SBOM) generated and signed per release
- [ ] Release artifacts signed by an HSM-held release key, hash published via at least two independent channels
- [ ] Production firmware compiled, signed, and provisioned on an air-gapped build host

### D. Cryptographic verification

- [ ] **NIST PQC SLH-DSA (FIPS 205) test vectors** pass for every parameter set you ship
- [ ] **Differential test** against a second SLH-DSA implementation (e.g. PQClean)
- [ ] **BIP-39 spec test vectors** pass (Trezor 24-word vectors are already in `bip39/tests/vectors.rs` — extend with the official BIP-39 vectors)
- [ ] **HKDF PIN-stretching test vectors** pass
- [ ] **HKDF-SHA256 / SHA-512 test vectors** pass
- [ ] **AES-256-GCM test vectors** pass on the SAES peripheral path, not just the software fallback
- [ ] **SCP03 negative tests** against SE050: replayed APDUs, malformed APDUs, wrong static keys, expired session, wrong UID
- [ ] **Noise_KK1 negative tests** against Tropic01: replayed handshakes, swapped pairing key, malformed handshake messages
- [ ] **Attestation negative tests on both chips**: wrong cert chain, replayed nonce, swapped UID, no response, slow response (timeout enforcement)
- [ ] **PIN brick test**: 9 wrong PINs in a row brick the device exactly once, on real hardware, verified by zeroized r-mem read-back
- [ ] **Power-loss tests at every step of every flow** (provisioning, unlock, sign, lock, wipe). Cut V_dd at random microsecond offsets and verify no secret survives in any persistent storage
- [ ] **Counter-divergence test**: simulate a glitch between Tropic01 and SE050 counter increments, verify the boot path forces both to N+1 with no free retries
- [ ] **Recovery test**: provision device A, write down the 24 words, brick device A, recover on a fresh device B, sign with the recovered key, verify it matches the device-A pubkey

### E. Side-channel & fault hardening

- [ ] **External fault-injection lab time** on real hardware: voltage glitching, EM glitching, clock glitching against PIN entry, attestation, signing, and wipe paths
- [ ] **Side-channel lab time**: SPA + DPA against PIN stretching, AES-GCM, SLH-DSA hash chains, with and without the EMI can fitted
- [ ] **Constant-time inspection** of the generated assembly for every secret-dependent inner loop in SLH-DSA (`subtle` crate is a contract, not a guarantee — verify the codegen)
- [ ] **Verify-before-release** is wired into every signing path, not just one
- [ ] **Wipe ISR loop-twice + read-back** verified to clear all listed regions on real hardware, including under brownout and TAMP
- [ ] **Stack scrub** after every signing operation; test that scans S-SRAM post-sign for the test seed and fails loudly if found
- [ ] **CPU register scrub** after returning from any S-world crypto routine
- [ ] **Cache flush** after any operation that touched secrets
- [ ] **Cold-boot attack mitigation**: temperature sensor refuses below the configured threshold; tested with freeze spray on a real unit
- [ ] **DMA-into-S-SRAM blocked** test: NS world attempts a DMA transfer into a Secure SRAM address and is denied by GTZC

### F. STM32U585 secure boot & option bytes

(See "Locking the STM32 to your firmware only" below for the how. The checklist is *what to verify* before shipping.)

- [ ] **Custom OEMiROT (or TF-M-for-STM32U5 fork) with ML-DSA-65 + Ed25519 hybrid verification** provisioned and occupying HDPL1
- [ ] **Both** signature legs (ML-DSA-65 and Ed25519) must verify before boot proceeds. CI test that flips one bit of either signature and confirms boot halt
- [ ] ML-DSA-65 manufacturing private key and Ed25519 manufacturing private key live **only** in separate HSM partitions; two-person rule for use; no copies on disk anywhere
- [ ] Image signature verification happens **before** any of your code runs (verify by trying to flash an unsigned image — it must be rejected by OEMiROT at the ML-DSA stage)
- [ ] OEMiROT's pinned hashes include both manufacturing public keys and the per-device ML-DSA device-identity certificate
- [ ] **TZEN = 1** burned in option bytes
- [ ] **RDP Level 2 (0xCC)** burned as the **final** production step; verified by attempting JTAG/SWD attach and confirming refusal
- [ ] `nBOOT0`, `nSWBOOT0`, `nBOOT_SEL`, `nBOOT_LOCK` configured to force boot from internal flash, no system bootloader, no patch RAM
- [ ] `SECBOOTADD0` points at your S-world entry point, `SECWM1`/`SECWM2` cover all of your S-flash regions
- [ ] HDPL increments wired so the bootROM (HDPL1) hands off to S-world (HDPL2), which hands off to NS-world (HDPL3); each level loses access to the previous level's secrets
- [ ] **Anti-rollback monotonic counter** (OBKEY area) advances on every signed firmware update; older signed images are rejected
- [ ] All debug option bytes set to **disable**: `DBG_AUTH`, `DBGSWEN`, JTAG-DP/SWJ-DP off
- [ ] BOOT0 pin physically tied low or removed from the package's exposed pads
- [ ] Option-byte profile burned via the same HSM-signed provisioning script for every device; no manual `STM32CubeProgrammer` clicks
- [ ] Final RDP-2 burn happens **after** the post-provisioning verification has passed and been logged
- [ ] CI test that builds an unsigned image, attempts to flash it on a non-RDP test unit, and confirms the bootROM rejects it
- [ ] Independent verification on a sample of finished units that RDP-2 is set, debug ports refuse, the pinned UIDs match, and signed-image-only is enforced

### F2. Post-quantum cryptography

- [ ] **Recovery contract frozen** in the protocol spec: SLH-DSA-SHA2-192f, BIP-39 → seed expansion `"sphincs-slh-seed/v2"`, half-mix `"bip39-entropy/v2"`. Any change is a hard fork
- [ ] **NIST PQC test vectors pass** for SLH-DSA-SHA2-192f, ML-KEM-1024, and ML-DSA-65 — on-target, not just on the host
- [ ] **Differential test** every PQ implementation against a second one (PQClean reference, RustCrypto, pqcrypto) and against the official Known Answer Tests
- [ ] **Constant-time inspection of the ML-KEM and ML-DSA inner loops** in the generated thumbv8m assembly. Lattice schemes have known timing-leak footguns (rejection sampling, NTT, modular reduction); verify the codegen
- [ ] **Fault-injection lab** specifically targets the ML-KEM Decaps path. A Decaps fault that returns a partially-correct shared secret is a classic FO-transform attack vector — verify the implementation rejects malformed ciphertexts in constant time
- [ ] **Verify-before-release** on every SLH-DSA signature (already required, doubly so for PQ — fault attacks against hash-based schemes can leak intermediate FORS / WOTS+ values)
- [ ] **ML-KEM secret key (sk_pq)** is stored only HUK-SAES-wrapped in U585 secure flash. Never lives in plain anywhere on flash. Test by flash-dumping a provisioned but locked device and confirming the dump is opaque
- [ ] **PQ wrap is end-to-end**: the SE050 binary object and Tropic01 r-mem slot only ever contain `ct ‖ aead`, never plaintext halves. CI test that scans a captured I²C/SPI trace for any byte pattern matching the test entropy
- [ ] **PQ random subsystem** uses the mixed STM32 + Tropic01 + SE050 TRNG. Never a software PRNG. Test that all three sources are reachable and that the mixing routine cannot be silently bypassed
- [ ] **Hybrid firmware-signing leg can be killed independently**: a CI test that disables the Ed25519 verification path (without modifying ML-DSA) confirms the device still boots — proving ML-DSA verification works on its own. The reverse (Ed25519-only) **must fail**, proving ML-DSA is the actual gate
- [ ] **Audit the chosen PQ Rust crates** (`ml-kem`, `ml-dsa`, `slh-dsa`) by an external cryptographer specifically for: rejection sampling correctness, constant-time decoders, zeroization of intermediate state, ciphertext malleability resistance
- [ ] **Document the PQ migration path** if any of {ML-KEM, ML-DSA, SLH-DSA} is broken: which firmware update unswaps it, signed by which key, recoverable on what timeline. The plan must be drilled before launch
- [ ] **Recovery test under PQ migration**: simulate "ML-KEM is broken, swap to classic McEliece KEM" by flashing a v2 firmware that re-wraps the halves on the SEs, and verify the same 24 BIP-39 words still produce the same SLH-DSA signing key

### G. Update mechanism

- [ ] Firmware updates signed by an HSM-held key separate from the provisioning key
- [ ] Bootloader verifies update signature **before** any of the new code runs
- [ ] Verification key stored in a region covered by RDP-2 and option bytes; modification is impossible without re-fabbing
- [ ] **Downgrade protection** via the monotonic counter
- [ ] Update process never exposes a secret over USB or any external bus
- [ ] Field-tested update path: every release is applied to a fleet of staging hardware before public rollout
- [ ] Rollback plan for a broken update that does **not** require unlocking RDP-2 (because there is no such option)
- [ ] Update over USB is rate-limited and requires physical user confirmation on the secure UI
- [ ] Recovery path documented: if an update bricks a fleet, what does the user do

### H. External validation

- [ ] **External security audit** by a firm with embedded + TrustZone + secure-element specialisation (NCC Group, Trail of Bits, Quarkslab, Kudelski, Riscure). Budget $30K-$150K. Yes, really. Audit the *signed* production image, not master.
- [ ] All audit findings either fixed or filed as a documented risk acceptance with an external sign-off
- [ ] **Public bug bounty** with meaningful rewards (≥ $25K for a seed-extraction bug)
- [ ] **Vulnerability disclosure policy** published before any device ships
- [ ] **CVE numbering authority** registration or partnership in place
- [ ] Independent fault-injection report from a lab (not just the firmware team's own bench)
- [ ] Independent attestation that the build pipeline is reproducible

### I. Operational readiness

- [ ] **Incident response plan**: who is on call, how is a vuln triaged, what is the comms template, how do you reach users
- [ ] **Out-of-band channel** to push critical advisories to users (signed announcements via at least two independent media)
- [ ] **Threat model document** committed to the repo and updated as the design evolves
- [ ] **Protocol specification** covering every APDU to each SE, every NSC call, every crypto primitive, every parameter set, every domain-separation tag — versioned, frozen per release
- [ ] **Known limitations document** listing what you do *not* protect against, published before users buy
- [ ] **Gradual rollout** plan: small batch first, hold for ≥ 60 days under public scrutiny, scale up only if nothing surfaces
- [ ] **Internal funds policy**: do not put company treasury on the device until it has been under public scrutiny for a long time
- [ ] **End-of-life plan**: when does this device stop receiving updates, how is the user notified, what is the migration path
- [ ] **Compliance**: CE / FCC / RoHS as applicable; FIPS 140-3 if claimed; EAL claim about the SE050/Tropic01 cited correctly (you do not get to inherit their cert for the whole product)

### J. The "honest caveats" page that ships with the device

- [ ] One-page document, in plain language, that lists what the device does *not* protect against (coerced unlock, lab attack on the SE die, supply-chain compromise of either vendor's silicon, your own implementation bugs)
- [ ] Recommends a *passphrase* for users whose threat model includes coercion
- [ ] Recommends a multi-sig setup for high-value funds
- [ ] States the bug bounty contact and disclosure policy
- [ ] States the firmware signing key fingerprint and where to verify it
- [ ] Translated for every market the device ships into

---

## Locking the STM32 to your firmware only

The STM32U585 has a built-in immutable boot ROM and an OEM Root of Trust (OEMiROT) feature specifically designed to enforce "this chip will only execute firmware signed by *this* key". For PQSigner OS we replace ST's stock ECDSA/RSA OEMiROT with a **custom OEMiROT that verifies an ML-DSA-65 + Ed25519 hybrid signature** before any of your code runs. ST's stock OEMiROT does not include a PQ verifier; you either fork it, fork TF-M for STM32U5, or fork MCUboot.

The chain looks like:

```
   ┌────────────────────────────────────────────────────────────┐
   │ HDPL0 — System Bootloader (immutable, in System Flash)     │
   │   • runs on every reset                                    │
   │   • dispatches to OEMiROT based on option bytes            │
   └────────────────────────────────────────────────────────────┘
                           │
                           ▼
   ┌────────────────────────────────────────────────────────────┐
   │ HDPL1 — Custom PQ-OEMiROT  (your immutable bootloader)     │
   │   • flashed once during provisioning, then locked          │
   │   • holds:                                                 │
   │       - SHA-256 hash of your ML-DSA-65 manufacturing pk    │
   │       - SHA-256 hash of your Ed25519 manufacturing pk      │
   │       - per-device ML-DSA-65 device-identity certificate   │
   │       - anti-rollback monotonic counter                    │
   │   • for each S/NS image:                                   │
   │       - parses the header {version, load_addr, len,        │
   │         ml_dsa_sig, ed25519_sig}                           │
   │       - verifies ML-DSA-65 signature against pinned pk     │
   │       - verifies Ed25519 signature against pinned pk       │
   │       - verifies version > monotonic counter               │
   │       - on ANY failure → halt                              │
   │       - on success → advance counter, jump into image      │
   └────────────────────────────────────────────────────────────┘
                           │
                           ▼
   ┌────────────────────────────────────────────────────────────┐
   │ HDPL2 — Your Secure-world firmware                         │
   │   • configures SAU / MPC / GTZC, opens SE buses,           │
   │   • verifies the NS image's hybrid signature, hands off    │
   │   • holds the HUK-SAES-wrapped ML-KEM-1024 secret key,     │
   │     Tropic01 pairing key, SE050 SCP03 / ECKey static key   │
   └────────────────────────────────────────────────────────────┘
                           │
                           ▼
   ┌────────────────────────────────────────────────────────────┐
   │ HDPL3 — Your Non-secure-world firmware                     │
   │   • UI shell, USB, etc. — has no access to S-flash, to     │
   │     the SE buses, or to any OEMiROT or HDPL2 secret        │
   └────────────────────────────────────────────────────────────┘
```

Each HDPL transition **irrevocably hides** the option bytes and OBKEYs of the previous level. By the time NS code runs, it cannot read the firmware signing public keys, the ML-KEM secret key, the SE wrap keys, or the OEMiROT itself, no matter what bug it has.

### The bring-up sequence (do this on a sacrificial dev board first — RDP-2 is irreversible)

1. **Generate two manufacturing keypairs on the HSM, in separate partitions:**
   - **ML-DSA-65** (Dilithium3, FIPS 204) — primary, post-quantum signing key
   - **Ed25519** — backup leg for the hybrid scheme
   Both private keys are non-exportable; export only the two public keys (and their SHA-256 hashes for OEMiROT pinning). Two-person rule on every signing operation.
2. **Build the custom PQ-OEMiROT.** Fork ST's OEMiROT (from `STM32CubeU5`/`X-CUBE-SBSFU`), TF-M for STM32U5, or MCUboot, and replace the ECDSA verifier with an **ML-DSA-65 verifier + Ed25519 verifier in series**. Bake in: the SHA-256 hashes of both manufacturing public keys, the secure-firmware load address, and the anti-rollback counter location. **Both** signatures must verify; either failure halts.
3. **Sign your secure-world firmware image** with both manufacturing keys, producing a header `{version, load_addr, length, ml_dsa_sig (~3309 B), ed25519_sig (64 B)}`. A custom Rust signer is the cleanest path; ST's `STM32_SigningTool_CLI` does not understand ML-DSA.
4. **Sign your non-secure-world firmware image** the same way (separate header, separate signatures).
5. **Burn the PQ-OEMiROT image** into the OEMiROT flash region using `STM32CubeProgrammer` over SWD on a non-RDP unit. This is a one-shot write — once HDPL1 is closed, you can't re-flash OEMiROT without de-provisioning the chip.
6. **Burn option bytes** with the provisioning script (HSM-signed, replayed identically per device):
   - `TZEN = 1` (TrustZone on)
   - `SECWM1_PSTRT/PEND` and `SECWM2_PSTRT/PEND` to cover the entire secure flash region
   - `SECBOOTADD0` = the OEMiROT entry point
   - `nBOOT0 = 0`, `nSWBOOT0 = 1` → always boot from internal flash, never from system bootloader
   - `nBOOT_SEL = 1` → BOOT0 pin is ignored
   - `nBOOT_LOCK = 0xC3` → boot configuration locked
   - `BOR_LEV = 4` (or higher) → brownout fires above the wipe-ISR safe voltage
   - `WRP1A` / `WRP2A` write-protect the OEMiROT region
   - `HDP1EN` / `HDP2EN` set so HDPL1 closes after OEMiROT runs
   - `DBG_AUTH = 0`, debug ports off
7. **Burn your secure and non-secure firmware images** into their respective flash regions, both with valid hybrid signatures in their headers.
8. **Generate the device's PQ inner-wrap keypair on the device itself:** the secure firmware boots once in a special "factory mode", uses the mixed `STM32_TRNG ⊕ Tropic01_TRNG ⊕ SE050_TRNG` to run `(pk_pq, sk_pq) ← ML-KEM-1024.KeyGen()`, HUK-SAES-wraps `sk_pq`, and writes it to a dedicated secure-flash region. The wrapped blob never leaves the device. `pk_pq` is exported only for the post-provisioning self-test.
9. **Generate and pin the device-identity certificate.** The HSM signs an ML-DSA-65 certificate over `{device_serial, U585_UID, Tropic01_UID, SE050_UID, pk_pq_hash}`. The certificate is pinned in HDPL1 OEMiROT alongside the manufacturing public-key hashes. This is the cryptographic root of "is this device the one we provisioned" — the SE classical attestations are downgraded to proof-of-presence only.
10. **Burn per-device secrets** in the same provisioning session: Tropic01 pairing key (TRNG-generated, stored in secure flash page 127), HUK-SAES-wrapped SE050 SCP03 (or ECKey) static keys, pinned Tropic01 UID, pinned SE050 UID, pinned vendor attestation root certificates.
11. **Run the post-provisioning self-test** over SWD: boot the device, walk through dual attestation + device-identity verification, provision a test wallet, sign a test transaction with SLH-DSA-192f, verify the signature, brick the test wallet (9 wrong PINs), confirm both SEs report destroyed state, confirm the PQ wrap blobs on both SEs are opaque ciphertext. The self-test record is signed (by the HSM) and archived.
12. **Burn `RDP = 0xCC`** (Level 2). This is the **last** option-byte write and it is **irreversible**. SWD is dead the moment the regulator settles after this write. Once a device passes through this step, you cannot debug it, you cannot re-flash it, you cannot recover it. Make sure step 11 is bulletproof.
13. **Final acceptance test** on the now-locked device: power-cycle, dual attest, verify ML-DSA device certificate, unlock with the test PIN (driving the full PQ inner-wrap path on both SEs), sign, verify, lock. If anything fails, the unit is scrap — you can't open it back up.

### What this gives you

- **Only firmware signed by both your HSM keys will run.** PQ-OEMiROT refuses any other image at HDPL1; an attacker who replaces flash contents with a different binary gets a halt at the ML-DSA verification step. A future CRQC that breaks Ed25519 still has to forge a valid ML-DSA-65 signature, which it cannot.
- **PQ confidentiality of all stored secrets.** Both halves of the entropy live on the SEs only as ML-KEM-1024 ciphertext; the secret key needed to decapsulate them is HUK-SAES-wrapped in U585 secure flash and never leaves the chip.
- **No debug access.** SWD/JTAG return nothing useful at RDP-2. There is no documented path to recover, even for ST.
- **No bootloader fallback.** With `nSWBOOT0 = 1` and `nBOOT_SEL = 1`, the system bootloader can never run, so the USART/USB/I²C boot recovery interfaces are dead.
- **No option-byte rollback.** RDP-2 cannot be downgraded to RDP-1 without a full mass erase, and a mass erase wipes everything including OEMiROT, leaving a brick.
- **No flash patching.** WRP write-protection on the OEMiROT region means even your own signed firmware cannot rewrite the bootloader.
- **HDPL hides keys from later stages.** By the time NS code runs, the firmware signing public keys, the ML-KEM secret key, the SE wrap keys, and the OEMiROT itself are unreadable from any execution context except the one that owns them.

### Sources to read before you bring this up on real silicon

- ST **AN5447** — *OEMiROT for STM32U5*
- ST **AN5054** — *Secure programming techniques for STM32 microcontrollers*
- ST **UM2851** — *Getting started with STM32CubeU5 TFM application*
- ST **RM0456** — *STM32U5 reference manual*, "Flash, RDP, OEMiROT, HDPL" chapters
- ST **AN5156** — *Introduction to STM32 microcontrollers security*
- The **TF-M for STM32U5** port (open source, audit-friendly — easiest base for the PQ-OEMiROT fork)
- **MCUboot** documentation (has experimental PQ verifier work upstream)
- **NIST FIPS 203** — ML-KEM (the inner wrap)
- **NIST FIPS 204** — ML-DSA (firmware signing)
- **NIST FIPS 205** — SLH-DSA (transaction signing)
- **NIST SP 800-208** — Stateful hash-based signatures (for context on hash-based PQ)
- **NIST IR 8413** — PQC standardisation status report
- **CNSA 2.0 transition timeline** — for your compliance posture

Read all of these before burning your first option byte. The cost of an irreversible mistake on a production line is much higher than the cost of a week of reading.

## License

Copyright (c) 2026 EthereumPhone. All rights reserved.



### From `CLAUDE.md`

# PQSigner OS -- LLM Context

Post-quantum ERC-4337 hardware wallet. Target: **STM32U585 (Cortex-M33, TrustZone) + Infineon OPTIGA Trust M V3 + NXP SE050**. Every primitive protecting the seed is PQ or symmetric with >=256-bit keys. No classical signature fallback for transactions. The wallet is an account-abstraction smart account with only post-quantum signers.

Status: dual-SE implemented. Firmware boots on real B-U585I-IOT02A + QEMU mps2-an505. OPTIGA Trust M driver (pure Rust IFX I2C stack + shielded connection) and SE050 driver both written. Dual-SE XOR entropy split wired and tested. Tropic01 driver also available as standalone backend.

## Non-Negotiable Invariants

**Every change to ANY subsystem must respect ALL five of these. Violating any one is a critical security bug.**

1. **Dual-chip seed split.** BIP-39 entropy is XOR-split: `half_O` on OPTIGA Trust M, `half_E` on SE050. Neither chip alone reveals any bit of the seed. Code that stores the full entropy on a single chip, or transmits one half to the other chip, breaks the design.

2. **Hardware-level PIN gating.** The PIN decision is made by the secure element silicon, never by MCU firmware. SE050 uses UserID auth (object `0x7B06_0000`, max 10 attempts, hardware constant-time comparison). OPTIGA Trust M uses hardware-enforced authorization references (OID `0xF1D0`, access conditions enforced by chip silicon). Firmware that compares PINs in software, or bypasses the SE's auth gate to read secrets, breaks the design.

3. **E2E encrypted tunnel between TrustZone secure world and each SE.** OPTIGA Trust M: Shielded Connection (TLS-PRF + AES-128-CCM-8) per session; Platform Binding Secret stored in secure flash page 126. SE050: SCP03 (AES-CMAC + AES-CBC) authenticated+encrypted channel. Planned: ML-KEM-1024 inner wrap so even a CRQC break of the classical channels reveals only opaque PQ ciphertext. No plaintext secret ever touches the I2C bus.

4. **All secrets live ONLY in TrustZone secure world.** Non-secure world never sees a PIN digit, entropy byte, signing key, or derived secret. The NSC gateway exposes only opaque commands (unlock, get_pubkey, sign) that return non-secret data. Pointer validation on every call. TOCTOU defense: NS buffers copied to secure stack before parsing.

5. **Post-quantum only for transaction signing.** SLH-DSA-SHA2-128f today (migrating to 192f for production). Hash-based, no lattice assumptions. The on-chain wallet contract has no secp256k1/P-256 signer -- only PQ. ML-DSA-44 is the bootstrap signer (admin ops, never rotates). Adding a classical signer path is a design violation.

## Architecture at a Glance

```
  OPTIGA Trust M --[Shielded Conn E2E]--> STM32U585 SECURE WORLD <--[SCP03 E2E]-- SE050
  (half_O, PIN-gated)                      |  PIN -> KDF -> K_O, K_E             (half_E, PIN-gated)
  I2C addr 0x30                            |  Reconstruct: E = HKDF(half_O XOR half_E)
                                           |  BIP-39(E) -> PBKDF2 -> SLH-DSA keygen -> sign
                                           |  Zeroize everything after sign
                                           |
                                           +--[NSC gateway, 6 cmds]---> NON-SECURE WORLD
                                                                         UI, USB, tx parsing
                                                                         no secrets, ever
```

**Lifecycle:** Boot -> SAU/GTZC config -> (attest both SEs) -> PIN entry in S-world -> unlock both SEs -> reconstruct seed in S-SRAM -> active signing window (120s idle timeout) -> zeroize on lock/tamper/brownout/inactivity.

## Subsystem Guides

### OPTIGA Trust M Integration

**What:** Stores `half_O` of the XOR-split entropy. Communicates over I2C via Infineon IFX I2C protocol (4-layer stack), optionally wrapped in a Shielded Connection (AES-128-CCM-8). Hardware-enforced PIN via authorization reference access conditions.
**Key files:** `secure/src/optiga/mod.rs`, `secure/src/optiga/ifx_i2c.rs`, `secure/src/optiga/apdu.rs`, `secure/src/optiga/shield.rs`, `secure/src/optiga/i2c.rs`, `secure/src/hw/flash.rs`
**Object IDs:**
- `0xE140` -- Platform Binding Secret (shielded connection root of trust)
- `0xF1D0` -- Authorization reference (PIN-derived HMAC secret, hardware-enforced)
- `0xF1D1` -- Entropy half (32 B, policy: requires Auto(0xF1D0) + Conf(0xE140))
- `0xF1D2` -- Verifying key (32 B, policy: requires Auto(0xF1D0))
- `0xF1D3` -- Bootstrap VK (32 B, policy: requires Auto(0xF1D0))
- `0xF1D4` -- Master secret (32 B, policy: requires Auto(0xF1D0) + Conf(0xE140))
- `0xF1D5` -- Attempt counter (firmware-managed, Conf(0xE140) for writes)
**Cross-cutting constraints:**
- Must store ONLY its half, never the full entropy
- PIN verification via OPTIGA authorization reference: chip compares PIN-derived secret against stored value at OID 0xF1D0 (constant-time, hardware-enforced). Firmware never decides.
- Access conditions enforced by OPTIGA silicon — `Auto(0xF1D0)` cannot be bypassed by firmware
- Every read/write wrapped in Shielded Connection (AES-128-CCM-8, plaintext never on I2C bus)
- Per-device Platform Binding Secret (PBS): generated from TRNG at first provisioning, stored in secure flash page 126 (`0x0C0FC000`, reserved in linker script). OID 0xE140 lifecycle locked to Operational (irreversible).
- Attempt counter at OID 0xF1D5: decrement-before-auth pattern, reset on success. Protected by Conf(0xE140) so only shielded connection can modify.
- ML-KEM-1024 inner wrap planned: the blob stored on-chip will be `ct || aead`, not plaintext
- I2C address 0x30 (shared bus with SE050 at 0x48, no conflict)
**Status:** Pure Rust IFX I2C stack implemented (CRC-16, framing, register I/O, chaining). Shielded Connection (TLS-PRF + AES-128-CCM-8) implemented. WalletStore trait implemented with full provisioning and PIN unlock flows. Dual-SE XOR split wired with SE050.

### Tropic01 Integration (standalone backend, not used in dual-SE)

**What:** Alternative SE backend. Stores entropy via Noise_KK1 encrypted SPI sessions. MAC-and-Destroy chain enforces PIN retry limits.
**Key files:** `secure/src/tropic01_se.rs`, `secure/src/semihosting_spi.rs`, `secure/src/hw/spi_hw.rs`
**Status:** Functional as standalone backend (`tropic01-se` feature). Not used in the dual-SE entropy split (replaced by OPTIGA Trust M).

### SE050 Integration

**What:** Stores `half_E` of the XOR-split entropy. Communicates over I2C via SCP03 authenticated+encrypted channel. UserID PIN auth with 10-attempt hardware limit.
**Key files:** `secure/src/se050/mod.rs`, `secure/src/se050/scp03.rs`, `secure/src/se050/apdu.rs`, `secure/src/se050/t1oi2c.rs`, `secure/src/se050/i2c.rs`, `docs/se050-userid-pin-auth.md`
**Object IDs:**
- `0x7B06_0000` -- UserID (hardware PIN, max 10 attempts, non-deletable)
- `0x7B06_0001` -- Raw entropy (32 B, policy: requires UserID auth)
- `0x7B06_0002` -- Main verifying key (32 B, policy: requires UserID auth)
- `0x7B06_0003` -- Bootstrap VK (32 B, policy: requires UserID auth)
**Cross-cutting constraints:**
- Must store ONLY its half, never the full entropy
- UserID auth is hardware-enforced: SE050 does constant-time PIN comparison, firmware never decides
- All APDUs inside SCP03 session (C-MAC + C-DEC), never plaintext
- ML-KEM-1024 inner wrap planned: SE050 stores PQ ciphertext, not plaintext half
- Boot-time attestation: verify SE050 cert chain against pinned NXP root + pinned UID (not yet implemented)
- NO `ALLOW_READ` for pseudo-ID `0x00000000` -- only the specific auth object
**Status:** Driver written (I2C -> T1oI2C -> APDU -> SCP03). Provisioning + unlock via UserID PIN auth implemented. Wired into the dual-SE split path with OPTIGA Trust M.

### TrustZone / NSC Gateway

**What:** ARM TrustZone-M splits the MCU into secure world (all crypto, PIN, signing) and non-secure world (UI, USB, tx parsing). The NSC gateway is the only crossing point.
**Key files:** `secure/src/main.rs`, `secure/src/sau.rs`, `secure/src/nsc/mod.rs`, `secure/src/nsc/state.rs`, `secure/src/nsc/ptr_validate.rs`, `secure/src/nsc/cmd_*.rs`, `secure/src/boot_ns.rs`, `secure/src/timeout.rs`
**Gateway commands:**

| CMD | Name | What it does |
|-----|------|-------------|
| 1 | GET_REMAINING | Return remaining PIN attempts |
| 2 | REQUEST_UNLOCK | S-world prompts PIN via trusted UI, unlocks SEs |
| 3 | GET_PUBKEY | Copy 32-byte verifying key to NS buffer |
| 5 | CLEAR_SIGN | ZK-verify calldata interpretation, display, sign |
| 6 | CLEAR_SIGN_MSG | EIP-712 message signing |
| 7 | SIGN_USEROP | Parse AA UserOp, display inner tx, sign userOpHash. Mode byte ≥ 2: auto-generate initCode (bootstrap sig + factory calldata). Returns full structured UserOp response (initCode + callData + PQSignatureWrapper). |
| 10 | SIGN_BOOTSTRAP | **DEPRECATED** — now handled by SIGN_USEROP mode ≥ 2. Kept for backward compat. |

**Cross-cutting constraints:**
- Every NS pointer validated before use (`validate_ns_read_ptr` / `validate_ns_write_ptr`)
- NS buffers copied to secure stack before parsing (TOCTOU defense)
- No panics across NSC boundary -- custom panic handler wipes secrets
- Secure-only peripherals: both SE buses, OLED, buttons, TRNG, HASH, SAES, TAMP
- On STM32U585: real CMSE `cmse-nonsecure-entry` veneers. On QEMU: shared-memory mailbox workaround
**Status:** All 6 commands implemented. CMSE veneers tested on real STM32U585. QEMU uses mailbox shim.

### SPHINCS+ / SLH-DSA Signing

**What:** Post-quantum hash-based signatures for all transactions. Two-tier key architecture.
**Key files:** `secure/src/crypto.rs`, `secure/src/nsc/sign_and_emit.rs`
**Key derivation chain (FROZEN -- changing this changes the recovery contract):**
```
32-byte BIP-39 entropy
  -> Mnemonic::from_entropy()
  -> PBKDF2-HMAC-SHA512 (2048 iters) -> 64-byte BIP-39 seed
  -> 3x SHA-256 KDF with domain separation -> 48-byte SLH-DSA seed
  -> slh_keygen_internal (FIPS 205) -> SigningKey
```
**Domain separation:**
- Bootstrap: `"pqwallet-bootstrap-sk-seed"` (global, never rotates)
- Per-chain main: `"pqwallet-main-sk-seed"` + chain_id + key_index
**Cross-cutting constraints:**
- Parameter set is part of the recovery contract: same 24 words MUST produce the same key
- Frozen domain tags: `"sphincs-slh-seed/v2"`, `"bip39-entropy/v2"`
- Signing key lives only in S-SRAM during active window, zeroized on lock
- Verify signature before releasing (fault-injection guard)
- Sig size: 17,088 bytes (SHA2-128f) or 35,664 bytes (SHA2-192f target)
**Status:** SLH-DSA-SHA2-128f fully working in QEMU. 192f migration planned for production.

### ERC-4337 Smart Contracts

**What:** On-chain account abstraction wallet with post-quantum-only signers. Fork of Coinbase Smart Wallet.
**Key files:**
- `contracts/smart-wallet/src/PQCoinbaseSmartWallet.sol` -- core wallet, `validateUserOp()`
- `contracts/smart-wallet/src/PQCoinbaseSmartWalletFactory.sol` -- CREATE2 factory
- `contracts/smart-wallet/src/PQOwnable.sol` -- two-tier signer state + OTS tracking
- `contracts/smart-wallet/src/verifiers/SLHDSAVerifier.sol` -- FIPS-205 on-chain verifier
- `contracts/smart-wallet/src/verifiers/SphincsC7Asm.sol` -- Yul-optimized verifier
- `secure/src/aa/userop.rs` -- firmware-side UserOp hash construction
**Two-tier signer model:**
- **Bootstrap** (ML-DSA-44): global, never rotates, used for deployment + admin. `bootstrapPubKeyHash` immutable in contract.
- **Main** (SLH-DSA): per-chain, per-epoch. Rotates every ~2^20 sigs. `currentKeyIndex` + `currentOTSIndex` tracked on-chain.
**Cross-cutting constraints:**
- Wallet address = CREATE2(factory, keccak256(bootstrap_pk), proxyInitCode) -- same on ALL chains
- OTS index is authoritative on-chain, not on-device (device counter is optimization only)
- No classical signer (secp256k1/P-256) anywhere in the contract
- Signature wire format: `PQSignatureWrapper{signerType, keyIndex, otsIndex, pkSeed, pkRoot, signature}`
- Safe/CowSwap integration via pre-signing pattern (UserOp calls `setPreSignature` or `Safe.signMessage`), not raw PQ signatures
**Status:** Contracts implemented. Foundry tests pass. EntryPoint v0.6 integration.

### ZK Clear Signing

**What:** Groth16 proofs over BLS12-381 certify that human-readable strings faithfully interpret raw calldata. Wallet refuses to display a decoded action unless the ZK proof verifies.
**Key files:** `secure/src/zk/groth16.rs`, `secure/src/zk/poseidon.rs`, `secure/src/zk/vk_bundle.rs`, `nonsecure/src/vk_db.rs`, `circuits/`, `dbgen/`
**Cross-cutting constraints:**
- VK pool in NS rodata, Merkle-rooted to 32-byte anchor in S-flash (`secure/src/db_roots.rs`)
- S-world re-verifies every VK against Merkle root before running Groth16
- Neither NS nor companion app can substitute a malicious VK
- BLS12-381 is classical (not PQ) -- a CRQC break lets attacker forge display proofs but CANNOT leak the seed
- Adding protocols: Circom circuit -> snarkjs -> 960-byte VK -> add to `secure/data/vks.json` -> `cargo run -p dbgen`
**Status:** Aave V3 supply/withdraw/borrow/repay circuits shipped. CowSwap EIP-712 planned (M4).

### Firmware Measurement (Measured Boot)

**What:** At every boot, the secure world SHA-256 hashes its own flash image and displays the first 88 bits as 8 BIP-39 words on the OLED. A companion host tool (`fwmeasure`) independently computes the same hash from the firmware ELF. The user visually compares — no secrets, no attestation keys, fully trustless.
**Key files:** `secure/src/measured_boot.rs`, `fwmeasure/src/main.rs`, `bip39/src/lib.rs` (`hash_to_word_indices`)
**How it works:**
- S-world reads its own flash from `FLASH_BASE` to the end of loaded content (linker symbols determine the boundary)
- On STM32U585: hashes up to `__veneer_limit` (CMSE veneers are in FLASH)
- On QEMU: hashes up to `__sidata + (__edata - __sdata)` (veneers are in the NSC region due to build.rs patching)
- First 88 bits of SHA-256 → 8 × 11-bit BIP-39 word indices → displayed on OLED (2 pages of 4 words)
- Host tool: `cargo run -p fwmeasure -- <firmware.elf>` or `make measure`
**Cross-cutting constraints:**
- Measurement runs before PIN entry — no secrets involved, pure flash read + hash
- Skipped when `e2e-test` feature is active (non-interactive automated tests)
- The firmware hashing itself is safe: flash is read-only, the hash is a read-only operation
- 88 bits = 2^88 second-preimage resistance — computationally infeasible to forge
**Status:** Implemented. Works on both QEMU (semihosting) and STM32U585 (OLED).
**Planned: hash-signature firmware update model:**
- Manufacturer signs the SHA-256 measurement hash (not the binary) with ML-DSA-44
- Users build from source (reproducible build), download the published signature (~2.4 KB), flash the device
- Device verifies: signature valid (manufacturer's public key) AND hash matches installed firmware
- Signature stored outside measured flash region (dedicated page or USB transfer) to avoid circular dependency
- Pre-installed malicious firmware caught on first legitimate update: can't predict future binary hashes
- See `README.md` "Firmware Update Model" section for full design

### BIP-39 Seed Management

**What:** 24-word mnemonic encodes 256-bit entropy. Entropy XOR-split across two SEs. Reconstructed only in S-SRAM during unlock.
**Key files:** `secure/src/crypto.rs`, `secure/src/ui/seed_wizard.rs`, `bip39/`
**Cross-cutting constraints:**
- Only 32-byte entropy stored on SEs, not the 48-byte SLH-DSA seed
- PBKDF2 (2048 iters) re-runs on every unlock (~100ms on Cortex-M33)
- Mnemonic shown to user ONCE during first-boot wizard, then never again
- Spot-check: user confirms 3 random words they wrote down
- Recovery: same 24 words on a new device must produce the same signing key (recovery contract)
**Status:** Generation, verification, restoration all working in QEMU.

## Build and Test

```bash
make play              # Interactive: drive wallet with arrow keys in QEMU
make run               # Non-interactive smoke test (QEMU, mock SE)
make run-tropic01      # Smoke test with real Tropic01 via /dev/ttyACM0
make e2e               # Automated end-to-end: all sign-dispatch levels in QEMU
make e2e-hw            # End-to-end on real STM32U585 via ST-LINK + probe-rs
cargo run -p dbgen     # Regenerate ERC20 + VK databases from JSON sources
make measure           # Build firmware + print 8 BIP-39 measurement words
```

**Feature flags** (in `secure/Cargo.toml`):
| Flag | Description |
|------|-------------|
| `mock-se` | Mock secure element in SRAM (default, QEMU) |
| `se050` | Real SE050 via I2C + SCP03 |
| `optiga-trust-m` | Real OPTIGA Trust M V3 via I2C + IFX I2C + Shielded Connection |
| `tropic01-se` | Real Tropic01 via SPI (standalone only, not used in dual-SE) |
| `spi1-arduino` | Use SPI1/PE12-PE15 (Arduino R3 headers) instead of SPI2/PB12-PB15 for TROPIC01 |
| `dual-se` | Both SEs active with XOR entropy split (implies `optiga-trust-m` + `se050`) |
| `debug-log` | Semihosting debug output (NEVER in production) |
| `e2e-test` | Non-interactive scripted test mode (NEVER ship) |
| `ui-semihosting` | Console UI (QEMU) |
| `ui-oled` | SSD1306 I2C OLED (hardware) |
| `stm32u585` | Real hardware target (vs QEMU mps2-an505) |
| `pka-accel` | BLS12-381 Fp via STM32U585 PKA hardware |

**Targets:** `thumbv8m.main-none-eabi` (both worlds). Release profile: `opt-level = "s"`, LTO, `codegen-units = 1`, `overflow-checks = true`. The `slh-dsa` crate is always `opt-level = 3`.

## Code Conventions

- `#![no_std]`, no heap, no allocator. Stack-only allocation.
- `zeroize` crate with `ZeroizeOnDrop` on every secret type. Compiler fences around zeroization.
- `subtle` crate for constant-time comparisons. No secret-dependent branches.
- Every `unsafe` block has a `// SAFETY:` comment.
- `#![deny(unsafe_op_in_unsafe_fn)]`, `#![warn(clippy::pedantic)]`
- NS pointer validation on every gateway call before any dereference.
- Shared types between worlds: `shared/src/lib.rs` with `#[repr(C)]`.
- Secret types are `!Copy` and `!Clone` (prevent silent duplication).

## Key File Map

| Path | Purpose |
|------|---------|
| `secure/src/main.rs` | Secure world entry: SAU -> provision -> unlock -> boot NS |
| `secure/src/crypto.rs` | All KDF, AES-GCM, PIN state, SLH-DSA key derivation |
| `secure/src/nsc/mod.rs` | NSC gateway dispatcher (6 commands) |
| `secure/src/nsc/state.rs` | Global secure state (pin_verified, master_secret) |
| `secure/src/nsc/sign_and_emit.rs` | Decrypt entropy -> derive key -> sign -> emit |
| `secure/src/sau.rs` | SAU + MPC/GTZC TrustZone configuration |
| `secure/src/optiga/mod.rs` | OPTIGA Trust M driver: init, PBS, provisioning, unlock, WalletStore |
| `secure/src/optiga/ifx_i2c.rs` | IFX I2C protocol: framing, CRC-16, register I/O, transceive |
| `secure/src/optiga/apdu.rs` | OPTIGA APDU builders, OID constants, metadata/access conditions |
| `secure/src/optiga/shield.rs` | Shielded Connection: TLS-PRF, AES-128-CCM-8, 4-step handshake |
| `secure/src/optiga/i2c.rs` | Bare-metal I2C1 driver for OPTIGA address 0x30 |
| `secure/src/dual_se.rs` | Dual-SE XOR entropy split: OPTIGA Trust M + SE050 combined WalletStore |
| `secure/src/tropic01_se.rs` | Tropic01 Noise_KK1 sessions + MACD PIN (standalone backend) |
| `secure/src/hw/spi_hw.rs` | SPI hardware init for TROPIC01 (standalone only) |
| `secure/src/hw/spi.rs` | Bare-metal SPI `embedded_hal::SpiDevice` impl for TROPIC01 |
| `secure/src/hw/flash.rs` | Secure flash driver: PBS storage (page 126), pairing key (page 127) |
| `secure/src/se050/mod.rs` | SE050 driver: provisioning + unlock via UserID PIN |
| `secure/src/se050/scp03.rs` | SCP03 authenticated+encrypted channel |
| `secure/src/se050/apdu.rs` | SE050 APDU command construction |
| `secure/src/measured_boot.rs` | Boot-time firmware SHA-256 hash → 8 BIP-39 words on OLED |
| `secure/src/secure_element.rs` | SecureElement trait + mock impl |
| `secure/src/ui/pin_entry.rs` | Trusted PIN entry (runs in S-world) |
| `secure/src/ui/seed_wizard.rs` | BIP-39 mnemonic generate/restore wizard |
| `secure/src/zk/groth16.rs` | Groth16 pairing verifier (no alloc) |
| `secure/src/erc20/dispatch.rs` | Tx trust-level dispatcher (ValueTransfer/Erc20Known/Blind) |
| `secure/src/aa/userop.rs` | ERC-4337 UserOp hash construction |
| `secure/src/aa/init_code.rs` | initCode construction for first-deployment UserOps (factory address placeholder, ABI encoding, keccak hash) |
| `nonsecure/src/main.rs` | Non-secure world entry |
| `nonsecure/src/nsc_api.rs` | NS-side gateway caller |
| `nonsecure/src/e2e_test.rs` | Automated end-to-end test driver |
| `shared/src/lib.rs` | Cross-world types: NscStatus, CMD constants |
| `shared/src/db_format.rs` | ERC20 + VK database binary format |
| `contracts/smart-wallet/src/PQCoinbaseSmartWallet.sol` | ERC-4337 wallet core |
| `contracts/smart-wallet/src/PQOwnable.sol` | Two-tier PQ signer state |
| `contracts/smart-wallet/src/verifiers/SLHDSAVerifier.sol` | FIPS-205 on-chain verifier |
| `dbgen/` | Host-side Merkle DB builder |
| `fwmeasure/` | Host-side firmware measurement: ELF → SHA-256 → 8 BIP-39 words |
| `Makefile` | Build orchestration |
| `docs/architecture.md` | Detailed technical architecture |
| `docs/HARDENING.md` | Side-channel + fault hardening requirements |
| `docs/pq-aa-wallet-design.md` | ERC-4337 wallet design spec |
| `docs/se050-userid-pin-auth.md` | SE050 PIN auth design |

## What NOT To Do

- **Do not add a classical (secp256k1, P-256, Ed25519) transaction signer.** The wallet is PQ-only by design. The on-chain contract has no classical verifier path.
- **Do not store secrets in non-secure world.** No PIN buffers, no entropy, no keys. Not even "temporarily".
- **Do not compare PINs in firmware.** The SE hardware does the comparison. Firmware only passes the stretched PIN to the SE's auth mechanism.
- **Do not transmit plaintext secrets over I2C/SPI.** Everything goes through the encrypted session (Shielded Connection, SCP03, or Noise_KK1). The planned ML-KEM inner wrap adds a PQ layer on top.
- **Do not store full entropy on a single chip.** Each chip gets exactly one XOR half.
- **Do not add heap allocation.** `#![no_std]`, no alloc, stack-only. No `Vec`, no `Box`, no `String`.
- **Do not use software PRNG.** All randomness from hardware TRNG (STM32 TRNG in production, semihosting `/dev/urandom` on QEMU).
- **Do not change the key derivation domain tags** (`"sphincs-slh-seed/v2"`, `"bip39-entropy/v2"`, `"pqwallet-bootstrap-*"`, `"pqwallet-main-*"`) without understanding that this changes the recovery contract: the same 24 words will produce a different key.
- **Do not let NS world control the inactivity timer.** Timer runs on Secure-only TIM. NS pings do not reset it. Only real button presses on S-world confirm dialogs count as activity.
- **Do not skip signature verification before releasing it.** The verify-before-release check is a fault-injection guard. Removing it opens a glitch attack.
- **Do not add `debug-log` or `e2e-test` features to production builds.** CI must gate on this.

## Work Tracking

After completing any implementation task, check `docs/work-todo.md` to see if the work corresponds to a tracked item. If it does, mark the relevant checkbox(es) as done and add a row to the Completion Log table at the bottom with the date and a one-line summary.

## Deep-Dive Docs

For full details beyond this summary, read:
- `README.md` -- Complete architecture, threat model, quantum threat analysis, security model, implementation status, shipping checklist, STM32 lockdown procedure
- `docs/architecture.md` -- Detailed technical architecture (1390 lines)
- `docs/HARDENING.md` -- Side-channel and fault-injection hardening requirements
- `docs/pq-aa-wallet-design.md` -- ERC-4337 wallet design with two-tier PQ signers
- `docs/se050-userid-pin-auth.md` -- SE050 UserID PIN authentication design
- `docs/dev-board-setup.md` -- B-U585I-IOT02A devkit setup
- `docs/hardware_requirements.md` -- BOM and hardware requirements
- `docs/m4-cowswap-eip712.md` -- CowSwap EIP-712 clear-signing design (future M4)
- `docs/work-todo.md` -- Gap analysis: what's missing for full E2E hardware wallet



### From `docs/architecture.md`

# SPHINCS+ Post-Quantum Hardware Wallet — TrustZone Architecture

## Overview

This project implements a post-quantum hardware wallet using **SLH-DSA (SPHINCS+)** signatures
with **ARM TrustZone** isolation on a Cortex-M33 microcontroller. Private key material never
leaves the secure world. The non-secure world (USB, display, buttons) can only request
signatures through a narrow gateway.

The firmware targets **STM32U585** (production) and runs on **QEMU mps2-an505** (development).
A desktop CLI (`sphincs-wallet`) demonstrates the full TROPIC01 flow over USB.

Two modes of operation:
- **`mock-se`** (default): Mock secure element in SRAM, no hardware needed
- **`tropic01-se`**: Real TROPIC01 chip connected via USB at `/dev/ttyACM0`, bridged to
  QEMU via semihosting file I/O. All chip communication is e2e encrypted (X25519 + AES-256-GCM).

```
┌─────────────────────────────────────────────────────────────┐
│                    QEMU mps2-an505                          │
│  ┌──────────────────────┐   ┌────────────────────────────┐  │
│  │   SECURE WORLD       │   │   NON-SECURE WORLD         │  │
│  │                      │   │                             │  │
│  │  SPHINCS+ keys       │   │  USB protocol handler      │  │
│  │  AES-GCM wrap/unwrap │   │  OLED display driver       │  │
│  │  PIN verification    │   │  Button input               │  │
│  │  TROPIC01 comms ─────│───│──── /dev/ttyACM0 ──► chip  │  │
│  │  (e2e encrypted SPI) │   │                             │  │
│  │                      │   │  Calls secure world ONLY   │  │
│  │  SysTick handler     │◄──│  through gateway            │  │
│  │  polls gateway       │──►│  Reads results              │  │
│  └──────────────────────┘   └────────────────────────────┘  │
│         0x10000000                  0x00200000               │
│       (secure flash)              (NS flash)                │
└─────────────────────────────────────────────────────────────┘
         │ (semihosting SYS_OPEN / SYS_READ / SYS_WRITE)
         ▼
   ┌─────────────┐      USB serial       ┌────────────────┐
   │ /dev/ttyACM0│◄─────────────────────►│ TROPIC01 chip  │
   │ (host)      │  115200 8N1 raw       │ (TS1302 devkit)│
   └─────────────┘                        └────────────────┘
```

## Workspace Structure

```
sphincs_rust/
├── Cargo.toml              # Workspace root
├── Makefile                # Build orchestration (secure → veneers → nonsecure → QEMU)
├── rust-toolchain.toml     # Nightly 2026-04-06, thumbv8m.main-none-eabi
│
├── desktop/                # Original USB CLI (std, runs on host)
│   ├── Cargo.toml          #   sphincs-wallet — talks to real TROPIC01 over USB
│   └── src/
│       ├── main.rs         #   enroll + sign commands
│       └── usb_dongle.rs   #   SPI-over-USB transport (embedded_hal::SpiDevice)
│
├── shared/                 # #![no_std] types shared between worlds
│   ├── Cargo.toml          #   zero dependencies
│   └── src/lib.rs          #   NscStatus, size constants, memory addresses
│
├── bip39/                  # #![no_std] BIP-39 24-word mnemonic crate
│   ├── Cargo.toml          #   sha2, hmac, zeroize
│   ├── src/lib.rs          #   Mnemonic, PBKDF2-HMAC-SHA512, prefix lookup
│   ├── src/wordlist.rs     #   Canonical 2048-word English wordlist
│   └── tests/vectors.rs    #   Trezor 24-word test vectors (host-tested)
│
├── secure/                 # TrustZone SECURE world firmware
│   ├── Cargo.toml          #   no_std crypto: slh-dsa, aes-gcm, sha2, hmac, bls12_381, bip39
│   ├── memory.x            #   FLASH 0x10000000 + NSC 0x103FF000 + RAM 0x38000000
│   ├── build.rs            #   Patches link.x to place .gnu.sgstubs in NSC region
│   └── src/
│       ├── main.rs         #   Boot: SAU → first-boot wizard → SysTick → boot NS
│       ├── sau.rs          #   SAU region config + MPC block config
│       ├── boot_ns.rs      #   VTOR_NS + MSP_NS + BXNS
│       ├── nsc.rs          #   Shared-memory gateway (5 commands)
│       ├── crypto.rs       #   KDF, AES-GCM, BIP-39→SLH-DSA seed derivation
│       ├── host_rng.rs     #   Host CSPRNG via semihosting /dev/urandom
│       ├── pin.rs          #   PIN verify via MAC-and-Destroy chain
│       ├── secure_element.rs  # trait SecureElement + MockSecureElement
│       ├── semihosting_spi.rs # SpiDevice impl via semihosting (tropic01-se)
│       ├── tropic01_se.rs     # Tropic01SecureElement with e2e encrypted sessions
│       ├── db_roots.rs        # Generated: ERC20_DB_ROOT + VK_DB_ROOT Merkle roots
│       ├── erc20/             # ERC20 dispatcher + bundle Merkle verifier
│       │   ├── mod.rs            # Public surface
│       │   ├── calldata.rs       # Strict ABI decoder (transfer/transferFrom/approve)
│       │   ├── dispatch.rs       # dispatch_tx() → TxKind trust level
│       │   ├── merkle.rs         # sha256 Merkle proof verifier (shared with VK DB)
│       │   └── bundle.rs         # NS → S metadata bundle parser + verifier
│       ├── zk/                # ZK clear-signing verifier (no_std, no alloc)
│       │   ├── mod.rs            # Module entry + size constants
│       │   ├── groth16.rs        # BLS12-381 Groth16 verifier (4 individual pairings)
│       │   ├── poseidon.rs       # Poseidon hash over BLS12-381 scalar field (alpha=5)
│       │   ├── poseidon_constants.rs  # Auto-generated round constants + MDS matrices
│       │   ├── vk_bundle.rs      # NS → S VK bundle parser + Merkle verifier
│       │   └── test_data/        # vk_bytes.bin, vk_hash.bin (Aave V3 reference VK)
│       └── ui/
│           ├── mod.rs         #   Display + Input + global singletons
│           ├── pin_entry.rs   #   2-button 8-digit PIN entry (+ confirm helper)
│           ├── confirm.rs     #   Multi-page tx confirmation navigator
│           └── seed_wizard.rs #   First-boot mnemonic display / verify / restore
│
├── secure/data/              # Curated source data for dbgen
│   ├── erc20.json            # (chain_id, address, name, symbol, decimals) rows
│   ├── vks.json              # Protocol VK manifest
│   ├── vks/*.vk.bin          # Per-protocol 960-byte Groth16 VKs
│   └── vks.review.txt        # Generated: release-review manifest (sha256 per VK)
│
├── dbgen/                    # Host-side DB + Merkle tree builder
│   ├── Cargo.toml
│   └── src/{main,erc20,vks,merkle}.rs
│
├── zk-test/                  # Host-side end-to-end test for the ZK verifier
│   ├── Cargo.toml            #   bls12_381 + sha2 (host std), no QEMU needed
│   └── src/main.rs           #   Mirrors the secure-world Poseidon + Groth16 path,
│                             #   exercises ZKlarity's proof_supply.json on the host
│
├── tools/
│   └── export_zk_constants.js # Exports Poseidon round constants from
│                              # poseidon-bls12381 (npm) into Rust source
│
└── nonsecure/                # TrustZone NON-SECURE world firmware
    ├── Cargo.toml            #   minimal: cortex-m-rt + semihosting
    ├── memory.x              #   FLASH 0x00200000 + RAM 0x28020000
    ├── build.rs              #   memory.x copy + magic-bytes validator for .bin blobs
    └── src/
        ├── main.rs           #   Interactive test harness
        ├── e2e_test.rs       #   Scripted runner for `make e2e` (feature-gated)
        ├── nsc_api.rs        #   Shared-memory gateway client
        ├── erc20_db.bin      #   Full ERC20 DB (generated by dbgen, include_bytes!d)
        ├── erc20_db.rs       #   NS-side lookup → metadata bundle builder
        ├── vk_db.bin         #   Full ZK VK DB (generated by dbgen)
        └── vk_db.rs          #   NS-side lookup → VK bundle builder
```

## Memory Map (QEMU mps2-an505)

The mps2-an505 has two SSRAM banks. The IDAU uses address bit 28 to distinguish
secure (0x1xxx/0x3xxx) and non-secure (0x0xxx/0x2xxx) aliases of the same physical memory.
The MPC (Memory Protection Controller) provides block-level S/NS attribution within each bank.

### SSRAM-0 (Code, 4 MB)

| Address Range       | Alias | MPC    | Usage                        |
|---------------------|-------|--------|------------------------------|
| `0x10000000-0x101FFFFF` | S     | Secure | Secure world code + rodata   |
| `0x103FF000-0x103FFFFF` | S     | NS     | NSC veneers (.gnu.sgstubs)   |
| `0x00200000-0x003FFFFF` | NS    | NS     | Non-secure world code        |

### SSRAM-1 (Data, 2 MB)

| Address Range       | Alias | MPC    | Usage                        |
|---------------------|-------|--------|------------------------------|
| `0x38000000-0x3801FFFF` | S     | Secure | Secure stack (128 KB)        |
| `0x28020000-0x2803FFFF` | NS    | NS     | Non-secure stack + BSS       |
| `0x2802FF00-0x2802FF14` | NS    | NS     | Shared memory gateway        |

### SAU Regions

| Region | Base         | Limit        | Type | Purpose              |
|--------|-------------|-------------|------|----------------------|
| 0      | `0x00200000` | `0x003FFFFF` | NS   | NS code flash        |
| 1      | veneer_base  | veneer_base+0xFF | NSC  | SG veneers (dynamic) |
| 2      | `0x28020000` | `0x29FFFFFF` | NS   | NS data SRAM         |
| 3      | `0x40000000` | `0x4FFFFFFF` | NS   | NS peripherals       |

Everything not covered by an SAU region defaults to Secure.

### MPC Configuration

| Controller | Register    | Blocks 0-63 | Blocks 64+ |
|-----------|-------------|-------------|------------|
| MPC0      | `0x58007000` | Secure      | NS         |
| MPC1      | `0x58008000` | Secure (0-3) | NS (4+)  |

## Secure Gateway

### Design

The gateway provides 6 operations across the TrustZone boundary:

| Command | ID | NS → S Args | S → NS Result |
|---------|-----|-------------|---------------|
| `GET_REMAINING` | 1 | — | Remaining PIN attempts (u32) |
| `REQUEST_UNLOCK` | 2 | — (PIN entered on trusted UI) | NscStatus |
| `GET_PUBKEY` | 3 | ptr to 32-byte output buf, buf_len | NscStatus |
| `SIGN` | 4 | ptr to has_bundle-wrapped EIP-1559 payload, ptr to 17088-byte sig buf, total_len | NscStatus |
| `CLEAR_SIGN` | 5 | ptr to ZK calldata payload (proof ‖ calldata ‖ string ‖ tx_len ‖ tx ‖ vk_bundle), ptr to sig buf, total_len | NscStatus |
| `CLEAR_SIGN_MSG` | 6 | ptr to EIP-712 payload (proof ‖ canonical ‖ string ‖ vk_bundle), ptr to sig buf, total_len | NscStatus |

The same six `cmd_*::run` handlers run under both transports described
below. Only the trigger differs: the QEMU build reads command + args
out of a shared mailbox in SysTick, and the STM32U585 build enters
them via CMSE SG veneers.

### Transport A: STM32U585 — CMSE veneers (production path)

On real STM32U585 silicon the gateway uses proper ARMv8-M Security
Extension veneers. `secure/src/nsc/mod.rs` exports all six entry
points with `extern "cmse-nonsecure-entry"`:

```rust
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_remaining_attempts() -> u32;
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_request_unlock() -> u32;
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_pubkey(out_ptr: u32, out_len: u32) -> u32;
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_clear_sign(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_clear_sign_msg(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
```

All six are gated on `#[cfg(feature = "stm32u585")]`. The secure
`build.rs` runs `--cmse-implib` to emit SG stubs for every one of
them into `target/veneers.o`, which the non-secure crate links
against (`-C link-arg=…/veneers.o`). On the NS side
(`nonsecure/src/nsc_api.rs`) the symbols resolve as plain
`extern "C"` functions:

```rust
extern "C" {
    fn nsc_get_remaining_attempts() -> u32;
    fn nsc_request_unlock() -> u32;
    fn nsc_get_pubkey(out_ptr: u32, out_len: u32) -> u32;
    fn nsc_sign(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
    fn nsc_clear_sign(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
    fn nsc_clear_sign_msg(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
}
```

Each call is a synchronous `BLXNS` → SG stub → secure handler →
`BXNS`. No shared memory, no polling, no SysTick involvement — the
secure `SysTick` handler only services `timeout::tick()` and the
idle-wipe check on this transport. End-to-end sign flows pass under
`make e2e-hw` driving a real ST-LINK/STM32U585AI.

### Transport B: QEMU mps2-an505 — shared-memory mailbox (workaround)

On QEMU mps2-an505 the CMSE `SG` check reads through the MPC NS
alias of the stub block and fails with `SFSR.INVEP` (see "QEMU
Limitations" below). The QEMU build therefore uses a shared mailbox
in NS SRAM driven by secure-side SysTick polling:

```
         NON-SECURE                                SECURE
    ┌───────────────────┐                  ┌──────────────────────┐
    │                   │                  │                      │
    │ 1. Write CMD+args │──────────────►   │                      │
    │    to 0x2802FF00  │  shared memory   │                      │
    │                   │                  │ 2. SysTick fires     │
    │ 3. Spin on DONE   │                  │    poll_gateway()    │
    │    flag           │                  │    reads CMD          │
    │                   │                  │    dispatches         │
    │ 4. Read RESULT    │  ◄──────────────│    writes RESULT     │
    │    from 0x2802FF10│  shared memory   │    sets DONE=1       │
    │                   │                  │                      │
    └───────────────────┘                  └──────────────────────┘
```

Shared memory layout at `0x2802FF00`:

| Offset | Name   | Size | Direction | Description     |
|--------|--------|------|-----------|-----------------|
| +0x00  | CMD    | 4    | NS→S     | Command ID      |
| +0x04  | ARG0   | 4    | NS→S     | Pointer to input data |
| +0x08  | ARG1   | 4    | NS→S     | Pointer to output buffer |
| +0x0C  | ARG2   | 4    | NS→S     | Output buffer length |
| +0x10  | RESULT | 4    | S→NS     | Return value (NscStatus) |
| +0x14  | DONE   | 4    | S→NS     | 1 = result ready |

`init_gateway`, `poll_gateway`, and `dispatch` in
`secure/src/nsc/mod.rs` are all gated
`#[cfg(not(feature = "stm32u585"))]` and exist solely for this
transport. When the `stm32u585` feature is enabled they're compiled
out entirely.

## TROPIC01 Integration

### Semihosting SPI Bridge

The real TROPIC01 chip (TS1302 devkit) connects to the host laptop via USB serial
at `/dev/ttyACM0`. The firmware accesses it through QEMU's ARM semihosting:

1. **SYS_OPEN**: Opens `/dev/ttyACM0` on the host (the host must pre-configure with `stty`)
2. **SYS_WRITE**: Sends hex-encoded SPI commands (same protocol as `desktop/src/usb_dongle.rs`)
3. **SYS_READ**: Reads hex-encoded SPI responses byte-by-byte until `\n`
4. **SPI protocol**: `"A0B1C2x\n"` → chip processes → `"D3E4F5\r\n"`
5. **CS deassert**: `"CS=0\n"` → `"OK\r\n"`

The `SemihostingSpi` struct (`secure/src/semihosting_spi.rs`) implements
`embedded_hal::spi::SpiDevice`, so the `tropic01` crate works unmodified.

### E2E Encrypted Session

Every TROPIC01 operation establishes a fresh Noise_KK1 encrypted session:

```
Secure World                          TROPIC01 Chip
────────────                          ─────────────
1. startup_req(Reboot)          ───►  Chip resets
2. Generate ephemeral X25519          
   keypair (random from               
   host /dev/urandom)                  
3. session_start(                ───►  X25519 handshake
     shpub=SH0PUB_PROD0,              3x DH exchanges
     shpriv=SH0PRIV_PROD0,            AES-GCM auth verify
     ehpub, ehpriv, slot=0)    ◄───  Session keys derived
                                       (Noise_KK1 protocol)
                                       
   === All further commands encrypted with AES-256-GCM ===
   
4. mac_and_destroy(slot, data)   ─E2E─►  HMAC + destroy
5. r_mem_data_read(slot)         ─E2E─►  Read encrypted
6. r_mem_data_write(slot, data)  ─E2E─►  Write encrypted
7. session_abort()               ───►  Zeroize keys
```

The pre-shared pairing keys (`SH0PUB_PROD0`, `SH0PRIV_PROD0`) are compiled into
the secure world firmware. The ephemeral keys are fresh for each session, generated
from `/dev/urandom` via semihosting.

### Batch Operations

The `Tropic01SecureElement` provides batch methods that perform multiple operations
in a single e2e encrypted session, avoiding the overhead of re-establishing a session
for each individual command:

| Method | Operations per session |
|--------|----------------------|
| `batch_enroll()` | N x mac_and_destroy + 3 x r_mem_write |
| `batch_verify_pin()` | r_mem_read + mac_and_destroy + N x mac_and_destroy (re-init) + r_mem_write |
| `batch_read_key_material()` | 2 x r_mem_read |
| `batch_read_pin_state()` | r_mem_read |

### Running with Real TROPIC01

```bash
# 1. Connect TROPIC01 TS1302 devkit via USB
# 2. Configure serial port + build + run:
make run-tropic01

# Or manually:
stty -F /dev/ttyACM0 115200 raw -echo cs8 -cstopb -parenb
make FEATURES=tropic01-se all
make run
```

## Cryptographic Design

### Key Hierarchy

The root of trust is a **24-word BIP-39 mnemonic** chosen on first boot
(generated from the host CSPRNG / chip TRNG, or restored from a piece of
paper). The mnemonic is **never persisted on the device** — it lives only on
the user's paper backup.

The on-device secret blob is the **32-byte BIP-39 entropy** that the 24
words encode. The 48-byte SLH-DSA seed and the SigningKey itself are
**recomputed on every unlock** by re-running the full BIP-39 → SLH-DSA
chain. They never touch persistent storage.

Everything is deterministically derived from the entropy, so the same 24
words always produce the same SPHINCS+ keypair on any device running this
firmware.

```
                  ┌────────────────────────────┐
                  │   24-word BIP-39 mnemonic  │  256 bits of entropy
                  │   (paper backup, NOT on    │  + 8-bit checksum
                  │    device after first boot)│
                  └─────────────┬──────────────┘
                                │  Mnemonic::to_entropy()
                                ▼
            ┌──────────────────────────────────────┐
            │   BIP-39 entropy (32 B)              │
            │   STORED encrypted in r-mem slot 0   │
            │   under wrap_key derived from        │
            │   PIN-gated master_secret            │
            └────────────────┬─────────────────────┘
                             │  Mnemonic::from_entropy()
                             │  + PBKDF2-HMAC-SHA512 (2048 iters)
                             ▼  ───── runs on every unlock ─────
                  ┌────────────────────────────┐
                  │      bip39_seed (64 B)     │  ephemeral, stack-only
                  └─────────────┬──────────────┘
                                │  slhdsa_seed_from_bip39():
                                │  3 × SHA256("sphincs-slh-seed" || s || i)[..16]
                                ▼
                  ┌────────────────────────────┐
                  │ SLH-DSA seed (48 B)        │  ephemeral, stack-only
                  │ sk_seed ‖ sk_prf ‖ pk_seed │
                  └─────────────┬──────────────┘
                                │  slh_keygen_internal() (FIPS-205)
                                ▼
                  ┌────────────────────────────┐
                  │  SigningKey<Sha2_128f>     │  ephemeral, stack-only
                  │  (64 B + Merkle root)      │  zeroized after sign call
                  └────────────────────────────┘

  -- Independently --
  master_secret = SHA256("sphincs-master" || entropy || 0x00)   # at provision
                = decrypted from MACD chain via PIN              # at unlock
  wrap_key      = SHA256("sphincs-wrap-key" || master_secret || 0x00)
  → unwraps the 60-byte AES-GCM blob in r-mem slot 0 to recover entropy
```

**On-device storage** (`RMEM_*` slots in the secure element):

| Slot | Name                     | Contents                                  | Size |
|------|--------------------------|-------------------------------------------|------|
| 0    | `RMEM_ENCRYPTED_ENTROPY` | AES-GCM blob of the 32-byte BIP-39 entropy | 60 B |
| 1    | `RMEM_PIN_STATE`         | next-attempt counter + 10 × per-attempt encrypted master_secret blobs | 481 B |
| 2    | `RMEM_VERIFYING_KEY`     | 32-byte SLH-DSA public key (cached so the host can read it without unlocking) | 32 B |

The mnemonic is **not** in any slot. The 48-byte SLH-DSA seed is **not** in
any slot. Only the raw 32-byte BIP-39 entropy is persisted, which means the
on-device secret is bit-for-bit identical to what the user's paper backup
encodes. PBKDF2 + the slhdsa_seed_from_bip39 KDF run fresh on every
unlock — ~tens of milliseconds, dwarfed by SPHINCS+ signing's seconds.

### PIN Protection (MAC-and-Destroy)

Each PIN attempt consumes one MACD slot (10 slots = 10 attempts max). On correct PIN,
all slots are re-initialized. On 10 wrong PINs, the key is permanently erased ("bricked").

```
Enrollment (per slot j = 0..9):
  1. mac_and_destroy(j, init_input_j)     → initialize slot
  2. mac_and_destroy(j, pin_input_j)      → w_j (slot-specific wrap key)
  3. mac_and_destroy(j, init_input_j)     → re-initialize to known state
  4. encrypted_secrets[j] = AES-GCM(w_j, master_secret)

Verification (slot j = next_index):
  1. mac_and_destroy(j, pin_input_j)      → w_j'
  2. Try AES-GCM decrypt of encrypted_secrets[j] with w_j'
  3. If decrypt succeeds → correct PIN, recover master_secret
  4. If decrypt fails → wrong PIN, increment next_index
```

### Recovery from Seed Phrase

If the device is lost, bricked (9 wrong PINs erase all MACD slots), or
otherwise unusable, the user can restore the wallet on any replacement unit
running the same firmware. The procedure:

1. Power on a fresh / wiped device. The first-boot wizard runs.
2. Choose **"Restore"** instead of **"New Wallet"**.
3. Choose a new PIN (the PIN is local to each device — it gates only the
   on-device encrypted state, not the mnemonic itself, so a recovered device
   uses whatever new PIN the user picks).
4. Type the 24 words from the paper backup using the trusted UI's letter-
   scroll widget. The first 4 letters of every BIP-39 English word are
   unique, so each word usually only needs 3 keystrokes before auto-completing.
   Short words (`act`, `add`, `art`, …) drop into a candidate-pick list when
   the prefix matches multiple longer words.
5. The wizard verifies the BIP-39 checksum and rejects bad phrases.
6. The same `slhdsa_seed_from_bip39` KDF runs and reconstructs an identical
   48-byte SLH-DSA seed. The MACD chain is re-initialized, the encrypted seed
   blob is rewritten, and the verifying key matches the original byte-for-byte.

The recovery contract is the stability of two functions:

```rust
Mnemonic::to_seed("")                       // PBKDF2-HMAC-SHA512, 2048 iters
crypto::slhdsa_seed_from_bip39(&bip39_seed) // domain-separated SHA-256 KDF
```

These are tested by host-side unit tests (`cargo test -p sphincs-tz-bip39`)
against the canonical Trezor test vectors and by an end-to-end QEMU test
that runs the Restore flow twice and confirms the verifying keys match
byte-for-byte.

### Backup Verification

After displaying the 24 words on first boot, the wizard prompts for a
spot-check of **3 randomly-selected words** (e.g. "Enter word 7", "Enter
word 14", "Enter word 21") via the same word-entry widget used for
recovery. The device only finalises provisioning if all three match. This
catches transcription errors before they become permanent — same flow as
Ledger / Trezor. The selected indices come from the host CSPRNG so the
prompts differ between runs.

### SLH-DSA Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | SLH-DSA-SHA2-128f (FIPS 205) |
| Security level | 128-bit (NIST Level 1) |
| Signing key | 64 bytes |
| Verifying key | 32 bytes |
| Signature | 17,088 bytes |
| Stack during signing | ~20-34 KB |

## Secure Element Abstraction

The `SecureElement` trait abstracts the TROPIC01 API subset used by the wallet:

```rust
pub trait SecureElement {
    fn r_mem_write(&mut self, slot: u16, data: &[u8]) -> Result<(), SeError>;
    fn r_mem_read(&mut self, slot: u16, buf: &mut [u8]) -> Result<usize, SeError>;
    fn r_mem_erase(&mut self, slot: u16) -> Result<(), SeError>;
    fn mac_and_destroy(&mut self, slot: u16, data_in: &[u8; 32]) -> Result<[u8; 32], SeError>;
}
```

| Implementation | Feature | Backend |
|---------------|---------|---------|
| `MockSecureElement` | `mock-se` (default) | In-memory arrays, HMAC-SHA256 for MACD |
| `Tropic01SecureElement` | `tropic01-se` | Real TROPIC01 chip via SPI (bare-metal SPI1/SPI2 on STM32U585, semihosting bridge on QEMU), e2e encrypted |

The mock stores up to 8 r-mem slots (512 bytes each) and 16 MACD slots (32 bytes each).
The real implementation establishes a fresh Noise_KK1 encrypted session per operation batch.

## Build System

### Prerequisites

```bash
rustup toolchain install nightly-2026-04-06
rustup target add thumbv8m.main-none-eabi --toolchain nightly
sudo apt install gcc-arm-none-eabi qemu-system-arm
```

### Build Commands

```bash
# Mock secure element (no hardware needed)
make all                          # Build both worlds with mock SE
make run                          # Build + run in QEMU

# Real TROPIC01 chip (TS1302 devkit at /dev/ttyACM0)
make run-tropic01                 # Configure serial + build + run
make FEATURES=tropic01-se all     # Build only (manual serial setup)
make setup-serial                 # Configure /dev/ttyACM0 only

# Other
make secure                       # Build only secure world
make nonsecure                    # Build only non-secure world
make clean                        # Remove build artifacts
```

### Build Pipeline

```
secure/           arm-none-eabi-ld         nonsecure/
  *.rs  ──────►  --cmse-implib  ──────►    *.rs
  memory.x        --out-implib=             memory.x
                   veneers.o                 +veneers.o
                        │                       │
                        ▼                       ▼
              sphincs-tz-secure.elf    sphincs-tz-nonsecure.elf
                        │                       │
                        └───────────┬───────────┘
                                    ▼
                          qemu-system-arm
                          -M mps2-an505
                          -kernel secure.elf
                          -device loader,file=nonsecure.elf
```

The secure world must build first because the non-secure world links against `veneers.o`
(the CMSE import library containing SG stub addresses). The Makefile uses separate
`--target-dir` for each crate to avoid linker flag conflicts.

### Linker Flags

| Crate | Linker Flags |
|-------|-------------|
| secure | `-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=veneers.o` |
| nonsecure | `-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=veneers.o` |

`arm-none-eabi-ld` is required because Rust's default linker (LLD) does not support CMSE.

## Boot Sequence

```
 1. QEMU starts in secure mode
 2. CPU fetches SP from 0x10000000, reset vector from 0x10000004
 3. cortex-m-rt Reset handler: zero BSS, copy .data
 4. main():
    a. Configure MPC0 (SSRAM-0: blocks 0-63 S, 64+ NS)
    b. Configure MPC1 (SSRAM-1: blocks 0-3 S, 4+ NS)
    c. Configure SAU (4 regions: NS code, NSC veneers, NS data, NS periph)
    d. DSB + ISB barriers
    e. Initialize trusted UI (display + buttons)
    f. is_provisioned()? → if no, run first-boot wizard:
       - User picks (and confirms) a PIN via the trusted UI
       - User chooses "New Wallet" or "Restore"
       - New: 32 B host_rng entropy → BIP-39 24-word mnemonic → display
              paginated → spot-check 3 random words against re-entry
       - Restore: word-by-word entry with 4-letter prefix narrowing
       - master_secret = KDF("sphincs-master", entropy, 0)
       - One-shot full chain (PBKDF2 + slhdsa_seed_from_bip39 + KeyGen)
         to compute the verifying key for caching in slot 2
       - MACD chain initialized, encrypted ENTROPY (not seed) and
         verifying key written to r-mem (mock or TROPIC01 e2e session)
    g. Initialize gateway transport:
         - QEMU: clear shared-memory CMD/RESULT/DONE mailbox words
         - STM32U585: no-op (CMSE veneers are statically linked)
    h. Enable secure SysTick (1 ms interval). On QEMU this drives
       poll_gateway() plus the idle-wipe check; on STM32U585 only
       the idle-wipe check runs.
    i. Set VTOR_NS = 0x00200000
    j. Set MSP_NS from NS vector table[0]
    k. BXNS to NS reset handler
 5. Non-secure world boots via cortex-m-rt
 6. NS main() exercises gateway commands
 7. debug::exit(EXIT_SUCCESS) terminates QEMU
```

## Sign Transaction Flow (End-to-End)

The diagram below uses the QEMU mailbox transport for clarity
(`CMD=…, DONE=1` etc.). On STM32U585 the transition arrows labelled
`──►` / `◄──` are CMSE `nsc_*` veneer calls instead: NS executes
`BLXNS` into the SG stub, the secure handler runs synchronously, and
control returns via `BXNS`. Everything between the two arrows is
identical.

```
NS World                          Secure World                        TROPIC01 Chip
────────                          ────────────                        ─────────────
1. Write PIN to NS SRAM
2. CMD=ENTER_PIN, ARG0=&pin  ──►  [QEMU: SysTick poll / HW: SG stub]
                                  Read PIN from NS memory
                                  [tropic01-se: open e2e session] ──► X25519 handshake
                                  mac_and_destroy(slot, pin_in) ─E2E─► HMAC + destroy
                                  AES-GCM decrypt master_secret
                                  Re-init all MACD slots ────────E2E─► Restore slots
                                  [tropic01-se: close session] ──────► Zeroize keys
                                  RESULT=Ok, DONE=1
3. Read RESULT=Ok            ◄──

4. Write tx_hash to NS SRAM
5. CMD=SIGN, ARG0=&hash,     ──►  [QEMU: SysTick poll / HW: SG stub]
   ARG1=&sig_buf, ARG2=17088     Read tx_hash from NS memory
                                  [tropic01-se: open e2e session] ──► X25519 handshake
                                  Read encrypted ENTROPY (60 B) ─E2E─► r_mem_data_read slot 0
                                  [tropic01-se: close session] ──────► Zeroize keys
                                  Derive wrap_key from master_secret
                                  AES-GCM decrypt → 32 B BIP-39 entropy
                                  Mnemonic::from_entropy(entropy)
                                  PBKDF2-HMAC-SHA512(2048) → 64 B bip39_seed
                                  slhdsa_seed_from_bip39 → 48 B SLH-DSA seed
                                  slh_keygen_internal → SigningKey
                                  slh_dsa::SigningKey::try_sign(tx_hash)
                                  Write 17,088-byte signature to NS sig_buf
                                  Wipe entropy + bip39_seed + slh_seed
                                  + signing key from RAM
                                  RESULT=Ok, DONE=1
6. Read RESULT=Ok            ◄──
   Read 17,088-byte signature
   from sig_buf
```

## ZK Clear Signing

For supported DeFi protocols (Aave V3, CowSwap `setPreSignature`, and
CowSwap EIP-712 `GPv2Order` typed-data signing), the secure world
refuses to display a "human-readable" action string on the trusted UI
unless a **Groth16 zero-knowledge proof** cryptographically certifies
that the string is a faithful interpretation of the raw bytes being
signed. This closes a long-standing trust hole in hardware wallets:
today, the companion app on the host is free to render `swap 1 ETH for
3000 USDC` while the chip is asked to sign a calldata blob that
actually drains the caller's balance to an attacker.

The architecture follows the [ZKNOX clear-signing
proposal](https://zknox.org). The Aave V3 circuit is a byte-identical copy
of [ZKNoxHQ/ZKlarity](https://github.com/ZKNoxHQ/ZKlarity) (see
`circuits/UPSTREAM.md` for provenance and the unresolved license note);
the CowSwap `setPreSignature` circuit is written in-tree under
`circuits/cowswap/set_pre_signature/`, and the M4 EIP-712 GPv2Order
circuit lives at `circuits/cowswap/eip712_order/`. Proving runs
off-device, on either a watchtower service or the user's companion;
the wallet only ever runs the **verifier**, which is small enough
(`#![no_std]`, no `alloc`) to fit inside the secure world.

The wallet supports two distinct sign-time payload shapes:

| Command | Payload | Wraps | Signed bytes |
|---|---|---|---|
| `CMD_CLEAR_SIGN` (5) | proof ‖ calldata(164) ‖ readable(64) ‖ tx_len ‖ EIP-1559 envelope ‖ vk_bundle | EIP-1559 transaction | `keccak256(unsigned_envelope)` |
| `CMD_CLEAR_SIGN_MSG` (6) | proof ‖ canonical(164) ‖ readable(64) ‖ vk_bundle | EIP-712 typed data (no on-chain tx) | `keccak256(0x1901 ‖ domain_separator ‖ struct_hash)` |

The **M4 / EIP-712 path** sidesteps keccak-in-circom by hashing the
canonical bytes with Poseidon inside the circuit and recomputing the
EIP-712 keccak digest natively in the secure world from the **same
164-byte buffer** the proof bound. The circuit only needs to certify
the human-readable summary; the firmware does the EIP-712 keccak
work at zero proving cost. The EIP-712 dispatch is generic: each
protocol implements `Eip712Protocol` in a sibling submodule under
`secure/src/tx/eip712/` and registers itself in the static
`PROTOCOLS` table; adding a second EIP-712 protocol is a sibling
file plus a VK row, no edits to `nsc.rs`. See `secure/src/tx/eip712/` and
**[docs/m4-cowswap-eip712-impl.md](./m4-cowswap-eip712-impl.md)** for
implementation notes; **[docs/m4-cowswap-eip712.md](./m4-cowswap-eip712.md)**
captures the original handoff design sketch.

### Verification chain

The full VK pool lives in **non-secure firmware rodata**
(`nonsecure/src/vk_db.bin`, `include_bytes!`d into the NS image).
The secure world only embeds a single 32-byte Merkle root in
`secure/src/db_roots.rs::VK_DB_ROOT`. At sign time the non-secure
world walks its local index by `(chain_id, contract)`, reads the
matching 960-byte VK + the pre-computed Merkle proof for its leaf
position, and forwards the bundle to the secure world.

```
NS World                                Secure World
────────                                ────────────
1. Local lookup on (chain_id, tx.to)    VK_DB_ROOT [u8; 32]
   in `nonsecure/src/vk_db.rs` →        embedded in secure image
   leaf_index, vk_bytes (960 B),
   merkle_proof[depth × 32 B]

2. Build clear-sign payload:
     [  0..384)   Groth16 proof (π.A ‖ π.B ‖ π.C)
     [384..548)   Aave V3 calldata (164 B, right-zero-padded)
     [548..612)   readable string (64 B, null-padded)
     [612..616)   tx_len (u32 LE)
     [616..)      EIP-1559 tx envelope
     then:
     [bundle_len u32 LE]
     [vk_bundle:
        chain_id (8 B) ‖ contract (20 B) ‖ vk_bytes (960 B)
        ‖ leaf_index (4 B) ‖ proof_depth (4 B)
        ‖ merkle_proof (depth × 32 B)
     ]

3. CMD=CLEAR_SIGN, ARG0=&payload  ──►  SysTick fires
   ARG1=&sig_buf, ARG2=total_len
                                       a. Validate payload pointer + length,
                                          reject overlap with shared mailbox
                                       b. Copy entire payload into a secure-stack
                                          buffer (TOCTOU defense)
                                       c. Parse the EIP-1559 envelope FIRST,
                                          extract chain_id, to, value, data
                                       d. Cross-check:
                                            tx.to.is_some()
                                            tx.value.is_zero()
                                            payload.calldata[..tx.data.len()]
                                               == tx.data
                                            payload.calldata[tx.data.len()..]
                                               == [0; ...] (padding)
                                          FAIL any → CryptoError
                                       e. Re-derive canonical leaf bytes from
                                          the bundle: (chain_id ‖ contract
                                          ‖ vk_bytes)
                                       f. leaf_hash = sha256(0x00 ‖ canonical)
                                          walk the Merkle proof, hashing
                                          pairwise with 0x01 || left || right,
                                          using bit i of leaf_index to pick
                                          left/right at each level
                                          final hash != VK_DB_ROOT → reject
                                          also cross-check bundle.chain_id +
                                          bundle.contract match parsed tx
                                       g. Deserialize the VK (now trusted) and
                                          the proof from the payload
                                       h. H_tx  = Poseidon(calldata, 164)
                                          H_str = Poseidon(readable, 64)
                                          (Poseidon over the BLS12-381 scalar
                                          field, alpha=5, Hades — matches
                                          ZKlarity's poseidon-bls12381 npm
                                          package bit-for-bit)
                                       i. vk_x = IC[0] + H_tx·IC[1] + H_str·IC[2]
                                       j. Verify Groth16 equation:
                                            e(π.A, π.B) · e(-α, β)
                                          · e(-vk_x, γ) · e(-π.C, δ) == 1 ∈ GT
                                          (4 individual pairings — no
                                          multi_miller_loop, so no alloc)
                                          FAIL → CryptoError, "ZK INVALID"
                                          OK   → continue
                                       k. Render `readable` on the trusted UI
                                          (3 pages: header, action string,
                                          confirm prompt). User long-presses
                                          R to confirm or L to cancel
                                       l. Parse + sign the EIP-1559 envelope
                                          (same flow as CMD_SIGN steps 5–10)
                                       m. RESULT=Ok, DONE=1
4. Read RESULT=Ok                ◄──
   Read 17 088-byte signature
   from sig_buf
```

### What this gives you

- **The display is cryptographically bound to the calldata.** The
  Poseidon hashes over the calldata and the readable string are the
  Groth16 public inputs. A proof exists *only* if a circuit-defined
  ABI-interpretation function maps that exact calldata to that exact
  string. Substituting either side invalidates the pairing equation.
- **The VK is authenticated against a secure-flash Merkle root.** The
  full VK pool ships in non-secure rodata, but the secure world only
  trusts a VK after re-deriving the leaf hash from the supplied bytes
  and walking the Merkle proof up to `VK_DB_ROOT`. The trust anchor
  is the firmware-signing key itself — the release reviewer compares
  `secure/data/vks.review.txt` (a build-artifact manifest of
  `(chain_id, contract, sha256(vk))` triples) against on-chain
  governance values before signing the release. Adding a new protocol
  requires a firmware update that bumps the root.
- **The NS side cannot forge a VK substitution.** If a hostile
  non-secure world sends a different VK for a pinned contract, the
  Merkle proof over the substituted bytes won't match the embedded
  root and the request is rejected before Groth16 ever runs.
- **The bundle cannot be replayed for the wrong transaction.** The
  bundle's `(chain_id, contract)` fields are cross-checked against the
  parsed envelope's `tx.chain_id` and `tx.to` after Merkle verification,
  so a valid VK for Aave V3 on Mainnet cannot be attached to a tx
  targeting a different chain or a different contract.
- **The signing key never depends on the proof's correctness.** A
  failing proof returns `CryptoError` *before* the entropy is even read
  from the secure element. The seed and SLH-DSA path are unchanged.

### Why classical, when everything else is post-quantum?

Groth16 and Poseidon over BLS12-381 are **classical** — a CRQC that
breaks the discrete log over BLS12-381's pairing-friendly curves could
forge a Groth16 proof for an arbitrary `(calldata, readable)` pair.

We accept this for now because:

1. **The ZK layer cannot leak the seed.** It only gates *what gets
   displayed before signing*. The classical assumptions are the same as
   they would be without the proof — the user is back to "trust the
   companion's display string".
2. **No PQ ZK proof system fits today.** Hash-based STARKs (Plonky3,
   Risc0) produce proofs that are O(100 KB) and verifiers that need
   alloc; lattice-based SNARKs are not yet practical for circuits the
   size of Aave V3 calldata parsing. The migration target is an
   STARK-based verifier once the proof + verifier sizes fit in the
   firmware budget.
3. **The display string is short-lived.** Even a successful forgery is
   only useful in the few seconds between the user reading the OLED and
   pressing confirm. There is no harvest-now-decrypt-later attack on a
   ZK display proof.

### Sizes (today, Aave V3 supply circuit)

| Field | Size | Notes |
|---|---|---|
| Verification key | 960 B | α(96) + β(192) + γ(192) + δ(192) + IC[0..2](288) — ships in NS rodata |
| Groth16 proof | 384 B | π.A(96) ‖ π.B(192) ‖ π.C(96), uncompressed |
| Calldata window | 164 B | matches ZKlarity circuit `MAX_CALLDATA` |
| Readable string | 64 B | matches ZKlarity circuit `STRING_LEN` |
| VK DB Merkle root | 32 B | embedded in secure flash via `db_roots::VK_DB_ROOT` |
| VK Merkle proof | depth × 32 B | ≤ 32 levels; 5 pinned Aave V3 deployments today → proof_depth ≤ 3 |
| Verify time (host) | ~3.3 ms | measured via `cargo run -p zk-test`; the `bls12_381` crate's pairing in pure Rust |
| Verify time (QEMU) | seconds | dominated by software BLS12-381 pairing on Cortex-M33 |

### Host-side parity test (`zk-test` crate)

`zk-test` is a host-only crate (`std`, real `bls12_381` from crates.io)
that imports the **same** `poseidon_constants.rs` and `test_vectors.rs`
files as the secure world, plus its own private copy of the reference
Aave V3 VK (independent of the firmware DB so it's stable across
Merkle-root changes). It runs the entire verifier chain on
`proof_supply.json` (a real Aave V3 supply proof generated by
ZKlarity's prover) and asserts:

1. Our Poseidon output for a known input matches `poseidon-bls12381`'s
   output bit-for-bit.
2. Groth16 verification of `proof_supply.json` returns true.

This catches divergence between the secure world's Poseidon
implementation and the reference circuit *without* the multi-minute
QEMU emulation cost of running BLS12-381 pairings on a soft-Cortex-M33.

```bash
cargo run -p zk-test --release
# → Poseidon: ok (matches poseidon-bls12381 reference)
# → Groth16 : ok in 3.3ms
```

### Automated end-to-end test (`make e2e`)

`make e2e` is a non-interactive test suite that builds both worlds
with a special `e2e-test` cargo feature and runs the full gateway
flow in QEMU with stdin closed. The feature:

- Replaces the first-boot wizard with deterministic provisioning from
  a fixed test mnemonic (`abandon`×23 + `art`) and PIN `00000000`
- Sets `PIN_VERIFIED` + `MASTER_SECRET` directly so the gateway is
  callable on boot
- Short-circuits every `confirm()` dialog to auto-return `Confirmed`
- Logs the chosen `TxKind` variant for every `cmd_sign` / `cmd_clear_sign`
  so the host harness can assert routing

It walks four scenarios back-to-back and greps the QEMU stdout for
both `[S][e2e] dispatch = <variant>` and `[E2E] <name> = PASS` lines
for every one:

| Scenario | Gateway | Expected TxKind |
|---|---|---|
| value_transfer | `CMD_SIGN` | `ValueTransfer` |
| erc20_known (USDC mainnet, bundle attached) | `CMD_SIGN` | `Erc20Known` |
| blind_sign (Uniswap router selector only) | `CMD_SIGN` | `ContractCall` |
| zk_clear_sign (Aave V3 supply, VK bundle attached) | `CMD_CLEAR_SIGN` | `ZkClearSign` |
| cowswap_pre_sign (GPv2Settlement.setPreSignature, in-tree circuit, VK bundle) | `CMD_CLEAR_SIGN` | `ZkClearSign` |
| cowswap_eip712_order (GPv2Order EIP-712 typed data, in-tree M4 circuit, VK bundle) | `CMD_CLEAR_SIGN_MSG` | `ZkClearSignMsg` |

The runner exits 0 only if every assertion holds. Total runtime
~20 seconds including QEMU's software BLS12-381 pairing.

The `e2e-test` feature is **never** enabled in production builds;
`secure/Cargo.toml` documents it as "NEVER ship in production: it
disables every meaningful trust gate."

### Tool: `tools/export_zk_constants.js`

Generates `secure/src/zk/poseidon_constants.rs` from the
`poseidon-bls12381` npm package's round constants and MDS matrices.
Run only when bumping the upstream package — the generated file is
checked in so the secure-world build does not require Node.js.

## Building the ERC20 + VK databases

The two on-device databases (ERC20 metadata, ZK clear-signing VKs)
are built by the `dbgen` workspace crate from JSON source files
checked into `secure/data/`. This section documents the source
schema, the tooling, the generated artifacts, the trust-anchor
workflow, and the sanity guards. For a quick-start "how do I add a
token" guide see the corresponding section in the top-level README.

### Source-data layout

```
secure/data/
├── erc20.json              # curated ERC20 metadata — sorted by (chain_id, address)
├── vks.json                # VK manifest (one block per protocol + its deployments)
├── vks/                    # raw 960-byte Groth16 verification keys
│   ├── aave_v3_pool.vk.bin
│   └── cowswap_set_pre_signature.vk.bin
└── vks.review.txt          # GENERATED — build-traceability manifest (checked in)
```

VKs are produced by the in-tree Circom pipeline under `circuits/`
(see `circuits/README.md` and `circuits/UPSTREAM.md`). The host-side
driver `tools/build_vks.sh` compiles the `.circom` sources, runs the
`snarkjs` trusted setup, and writes the 960-byte files into
`secure/data/vks/`. `cargo run -p dbgen` then folds them into the
Merkle-rooted firmware DB. The two pipelines are decoupled: `dbgen`
is cargo-only and does not shell out to Node or circom, so a clean
clone with only cargo can rebuild the firmware DB from the committed
`.vk.bin` files.

#### `secure/data/erc20.json`

A JSON array of records, one per `(chain_id, contract)` the wallet
should recognise. All fields are required except `flags`.

```json
[
  { "chain_id": 1, "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "name": "USD Coin", "symbol": "USDC", "decimals": 6 },
  { "chain_id": 8453, "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "name": "USD Coin", "symbol": "USDC", "decimals": 6 }
]
```

| Field | Type | Constraint |
|---|---|---|
| `chain_id` | u64 | EIP-155 chain id, matches what the EIP-1559 envelope encodes |
| `address` | hex string | 20 bytes, with or without `0x` prefix; case insensitive |
| `name` | UTF-8 string | 1–255 bytes. `dbgen` hard-errors if longer |
| `symbol` | UTF-8 string | 1–255 bytes |
| `decimals` | u8 | Token decimals used by `U256::format_decimal_fixed` |
| `flags` | u8 (optional, default 0) | Reserved per-entry flags |

#### `secure/data/vks.json`

A JSON array where each element describes one protocol (i.e. one
circuit + VK) plus every chain/contract deployment that shares that
VK. Dedup happens at the protocol level: the Aave V3 Pool circuit
covers four actions (supply / borrow / repay / withdraw) via an
internal `action_type` mux and is identical across
Mainnet/Base/Arbitrum/Optimism/Polygon, so all five deployments ride
on a single 960-byte entry in the VK pool. Similarly the CowSwap
`setPreSignature` VK covers every chain where `GPv2Settlement` is
deployed at the canonical CREATE2 address.

```json
[
  {
    "protocol": "aave-v3-pool-v1",
    "vk_file": "aave_v3_pool.vk.bin",
    "deployments": [
      { "chain_id": 1,     "address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        "label": "Aave V3 Pool, Mainnet" },
      { "chain_id": 8453,  "address": "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5",
        "label": "Aave V3 Pool, Base" }
    ]
  },
  {
    "protocol": "cowswap-set-pre-signature-v1",
    "vk_file": "cowswap_set_pre_signature.vk.bin",
    "deployments": [
      { "chain_id": 1,   "address": "0x9008D19f58AAbD9eD0D60971565AA8510560ab41",
        "label": "GPv2Settlement, Mainnet" }
    ]
  }
]
```

`vk_file` is a path relative to `secure/data/vks/` pointing at a raw
960-byte Groth16 VK blob. `dbgen` rejects any file that's not exactly
`VK_BLOB_LEN` bytes (960). The `label` is purely cosmetic and only
appears in the release-review manifest.

### Canonical leaf encoding

The Merkle leaf hash for each entry is `sha256(0x00 || canonical)`,
where `canonical` is the exact byte sequence reconstructed at both
ends of the wire. The dbgen writer emits these bytes into the tree;
the secure-world verifier re-emits the same bytes from the bundle
received via the gateway before hashing. Both implementations share
the layout via `sphincs_tz_shared::db_format` constants.

**ERC20 canonical leaf:**

```
chain_id      u64 LE            (8 B)
contract      [u8; 20]          (20 B)
decimals      u8                (1 B)
name_len      u8                (1 B)
name          [u8; name_len]
symbol_len    u8                (1 B)
symbol        [u8; symbol_len]
```

**VK canonical leaf:**

```
chain_id      u64 LE            (8 B)
contract      [u8; 20]          (20 B)
vk_bytes      [u8; 960]         (960 B)
```

Internal Merkle nodes use `sha256(0x01 || left || right)`. The
`0x00`/`0x01` domain separation prefix stops an attacker who controls
the entry encoding from crafting bytes that look like an
internal-node concatenation, which would otherwise break
second-preimage resistance for the tree.

### dbgen pipeline

`cargo run -p dbgen` (a new workspace member) runs a single
host-side pipeline that produces all four generated outputs:

```
secure/data/erc20.json                     ─┐
                                            ├─► erc20::build_db()
                                            │    ├─ parse + validate rows
                                            │    ├─ sort by (chain_id, contract)
                                            │    ├─ intern name + symbol into pool
                                            │    ├─ compute leaf hashes from canonical encoding
                                            │    ├─ build Merkle tree (pad to pow-2 by dup)
                                            │    └─ emit blob + per-entry proofs
                                            ▼
                                  nonsecure/src/erc20_db.bin   (include_bytes! in NS)
                                  ERC20_DB_ROOT: [u8; 32]      (→ secure/src/db_roots.rs)

secure/data/vks.json                       ─┐
secure/data/vks/*.vk.bin                    ├─► vks::build_db()
                                            │    ├─ load each VK, validate 960 B
                                            │    ├─ dedup VKs by sha256(vk_bytes)
                                            │    ├─ flatten (chain_id, contract) → vk_id
                                            │    ├─ same canonical leaf + Merkle build
                                            │    └─ emit blob + per-entry proofs + review text
                                            ▼
                                  nonsecure/src/vk_db.bin      (include_bytes! in NS)
                                  VK_DB_ROOT: [u8; 32]         (→ secure/src/db_roots.rs)
                                  secure/data/vks.review.txt   (human-reviewable manifest)
```

All four outputs are **checked into the repo** so downstream builds
need only `cargo` (no Node.js, no network access). Rerun `dbgen`
whenever the JSON source changes, and commit the regenerated
outputs alongside the source diff.

### Blob format (generated on-disk layout)

Both blobs share a 32-byte header, a sorted entry array, a
secondary pool (strings for ERC20, VK bytes for VK), and a
per-entry proofs section. Constants live in
`shared/src/db_format.rs`.

**`erc20_db.bin` (`b"ERC2"`):**

```
Header (32 B):
  magic        [u8; 4] = b"ERC2"
  version      u32 LE  = 1
  flags        u32 LE
  entry_cnt    u32 LE
  pool_off     u32 LE    // byte offset of string pool from blob start
  pool_size    u32 LE
  proof_depth  u32 LE    // sibling hashes per proof (= log2(padded n))
  proofs_off   u32 LE    // byte offset of per-entry proofs array

Entries (entry_cnt × 40 B, sorted by (chain_id, contract)):
  chain_id     u64 LE
  contract     [u8; 20]
  name_off     u32 LE     // offset into string pool
  symbol_off   u32 LE
  decimals     u8
  flags        u8
  _pad         [u8; 2]

String pool:
  Length-prefixed: [u8 len][bytes]. Strings are interned at build
  time so "USD Coin" appears once even if 10 chains have a USDC.

Proofs:
  entry_cnt × (proof_depth × 32 B). Proof[i] is the list of sibling
  hashes from leaf i up to the root, ordered leaf-up. The direction
  at each level is implicit from the bits of i.
```

**`vk_db.bin` (`b"VKDB"`):**

Same header shape with `VK_BLOB_LEN = 960`. Entries are 32 B each
(`chain_id`, `contract`, `vk_id: u8`, `vk_sha_pfx: [u8; 3]` — a
defense-in-depth SHA-256 prefix the verifier cross-checks against
the pool entry it indexes). The secondary pool holds `vk_count ×
960` bytes of unique VKs. The `vk_sha_pfx` catches any drift
between the entry's `vk_id` and the pool contents that survived
dbgen's internal checks.

### Round-trip self-test

After writing a blob, `dbgen` immediately opens it through its
host-side mirror of the runtime parser, re-derives the canonical
leaf bytes for every source row, walks the appended Merkle proof up
to the just-computed root, and asserts match. Any drift between the
writer and the reader — which would silently break the secure-world
verifier — fails `dbgen` loudly with a precise error pointing at the
specific row.

The parser mirror lives in `dbgen/src/{erc20.rs,vks.rs}` as
`HostErc20Db` and `HostVkDb`. It deliberately mimics the structure
the **non-secure-side** parser (`nonsecure/src/erc20_db.rs`,
`nonsecure/src/vk_db.rs`) uses so the two can't drift.

### Secure-side Merkle verifier

`secure/src/erc20/merkle.rs` exposes one function, shared by both
DBs:

```rust
pub fn verify_proof(
    canonical: &[u8],
    leaf_index: usize,
    proof_bytes: &[u8],
    proof_depth: usize,
    expected_root: &[u8; 32],
) -> bool;
```

It walks the supplied sibling hashes from `sha256(0x00 || canonical)`
to the root, picking left/right at each level by bit `i` of
`leaf_index`. No heap, no allocation, no panics on bad input — a
bad bundle just returns `false` and the gateway surfaces
`CryptoError` to NS.

### Stale-blob protection

`nonsecure/build.rs` panics at compile time if either of its
`include_bytes!`'d blobs doesn't start with the expected magic. The
common failure mode — "edited `erc20.json`, forgot to run `dbgen`"
— fails the build with a clear "run `cargo run -p dbgen`" message
instead of silently shipping stale data.

```rust
// nonsecure/build.rs
check_db_magic("src/erc20_db.bin", b"ERC2");
check_db_magic("src/vk_db.bin", b"VKDB");
```

The secure-side counterpart is implicit: `secure/src/db_roots.rs`
is generated by `dbgen` as regular Rust source, so any format
mismatch would be caught by the compiler rather than by magic-byte
sniffing.

### Release-review workflow (VK DB only)

`dbgen` also writes `secure/data/vks.review.txt`, a
human-readable manifest that lists the VK DB Merkle root plus every
`(protocol, chain_id, contract, sha256(vk))` triple in the DB:

```
=== ZK Clear-Signing VK Manifest (firmware build artifact) ===
...
Merkle root (VK_DB_ROOT) = 89ccb93ed5034a90b48ae07bc10694e2ab7da74b8f8cef3af840d563b943f12a

aave-v3-pool-v1
  sha256(vk) = f36a73b5bb084a9800ceff63e33e061d182af2b09f6bcef20d441c68fd80292e
  chain      1, contract 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 (Aave V3 Pool, Mainnet)
  chain   8453, contract 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5 (Aave V3 Pool, Base)
  ...
cowswap-set-pre-signature-v1
  sha256(vk) = 5114d50fc022a64aaa199dec0c130a4b27e859714d5f03ba14ef5a8406c1a236
  chain      1, contract 0x9008D19f58AAbD9eD0D60971565AA8510560ab41 (GPv2Settlement, Mainnet)
  ...
```

**This file is a pure build-traceability artifact.** It records
which `(chain_id, contract, sha256(vk))` triples were folded into
`VK_DB_ROOT` for a given release, so the release reviewer can diff
successive releases and notice any unexpected additions. The trust
chain is entirely offline:

```
firmware-signing key
      ↓  signs
firmware release (containing VK_DB_ROOT in secure flash)
      ↓  anchors
VK_DB_ROOT                          [32 bytes in secure/src/db_roots.rs]
      ↓  Merkle-proves
(chain_id, contract, vk_bytes)      [NS-supplied bundle at sign time]
      ↓  Groth16-verifies
proof π binds calldata → readable   [displayed on trusted UI]
```

There is **no** on-chain `clearSigningVKHash` comparison anywhere in
this project. The wallet trusts its own Merkle root, the reviewer
trusts the firmware-signing key, and neither the firmware nor the
tooling ever reads from an RPC. If a future plan wants to add an
optional governance-comparison script as a reviewer convenience, it
will be a strict opt-in on top of this hardware-only baseline.

Release-signing checklist simply becomes:

```
[ ] git diff secure/data/vks.review.txt
    — confirm that every added or modified row corresponds to a
      Circom circuit you actually intended to add in this release,
      authored in circuits/, and that no unexpected rows appeared.
    — no external lookups required.
```

### Putting it all together

```bash
# 1a. Edit ERC20 source data
$EDITOR secure/data/erc20.json

# 1b. OR: author a new ZK clear-signing circuit and produce its VK
$EDITOR circuits/circuits.json                         # add a row
mkdir -p circuits/myproto/myaction
$EDITOR circuits/myproto/myaction/circuit.circom       # write the circuit
head -c 32 /dev/urandom > circuits/myproto/myaction/contribution.seed
tools/build_vks.sh myproto_myaction                    # compile → .vk.bin
$EDITOR secure/data/vks.json                           # add deployment rows

# 2. Regenerate all four outputs
cargo run -p dbgen

# 3. Review the diff (build-traceability only — no external lookups)
git diff secure/data/vks.review.txt

# 4. Sanity-build both worlds (magic-bytes validator runs here)
make all

# 5. Run the scripted e2e suite
make e2e

# 6. Commit source + all regenerated outputs atomically
git add circuits/ secure/data/ nonsecure/src/{erc20,vk}_db.bin \
        secure/src/db_roots.rs secure/src/zk/vk_data.rs
git commit -m "..."
```

See `circuits/README.md` for the full circuit-authoring workflow
and `circuits/UPSTREAM.md` for the provenance of any Circom sources
imported from third-party repositories.

## QEMU Limitations

### MPC S-Alias Bug (QEMU 8.2.2)

**Symptom:** `SFSR.INVEP` (Invalid Entry Point) SecureFault when NS code branches to
an SG veneer, even though SAU correctly marks the region as NSC and the SG instruction
bytes are verified present.

**Root cause:** QEMU's mps2-an505 model does not allow S-alias reads
(`0x1xxx_xxxx`) of SSRAM blocks marked as NS by the MPC. The SG instruction verification
path reads through this broken path, so it cannot read the SG opcode and reports INVEP.
On real hardware, secure code can access both S and NS memory regardless of MPC settings.

**Workaround:** Shared memory gateway with secure SysTick polling (see
"Transport B" under "Secure Gateway" above). The CMSE veneer path
(Transport A) is used on the STM32U585 build and is exercised end-to-end
under `make e2e-hw` on real silicon — it is only absent from the QEMU
build because of the MPC bug described here.

**Note:** Secure code CAN read/write NS memory through the NS alias
(`0x0xxx_xxxx` / `0x2xxx_xxxx`). Only the S-alias of NS-MPC blocks is broken.

## Porting to STM32U585

When the STM32U585 board arrives:

1. **Memory map:** Update `memory.x` files with STM32U585 flash/SRAM addresses.
   The SAU programming model is identical (standard ARMv8-M). The MPC is replaced
   by STM32's GTZC (Global TrustZone Security Controller).

2. **Gateway:** Done. The STM32U585 build uses proper CMSE veneers
   (`extern "cmse-nonsecure-entry"`) for all six gateway commands; NS
   resolves them as `extern "C"` symbols through `veneers.o`. The
   shared-memory mailbox + SysTick poll path is compiled out on this
   target — see "Transport A" under "Secure Gateway" above.
   `make e2e-hw` runs the full sign-dispatch suite over this path on
   real silicon.

3. **SPI transport:** ~~Replace `SemihostingSpi` with a real `embedded_hal::spi::SpiDevice`
   implementation.~~ **DONE.** Bare-metal `Stm32Spi` driver (`hw/spi_hw.rs` + `hw/spi.rs`)
   implements `SpiDevice` for SPI1 (`spi1-arduino` feature, PE12-PE15 Arduino headers)
   or SPI2 (default, PB12-PB15). The `with_session!` macro auto-selects `Stm32Spi`
   on STM32U585, `SemihostingSpi` on QEMU.

4. **RNG:** Replace semihosting `/dev/urandom` reads in `secure/src/host_rng.rs`
   with the STM32U585's hardware RNG (`embassy_stm32::rng`) or the TROPIC01's
   TRNG (`session.get_random_value(32)`). The `host_rng::fill` and
   `host_rng::byte` API can stay the same — only the implementation changes.
   This RNG feeds:
   * BIP-39 mnemonic generation in the first-boot wizard (32 bytes of entropy)
   * Word indices for the 3-word backup spot check
   * Ephemeral X25519 keypairs for each TROPIC01 e2e session

5. **Key generation:** Already mnemonic-driven. The first-boot wizard
   (`secure/src/main.rs::run_first_boot_wizard`) prompts the user for a PIN
   and a 24-word BIP-39 mnemonic (generated fresh or restored from paper).
   The 48-byte SLH-DSA seed is then derived deterministically via
   `crypto::slhdsa_seed_from_bip39`. Nothing else needs to change for
   STM32U585 — the mnemonic flow runs identically on the real hardware,
   only the RNG backend differs.

6. **Embassy:** Add `embassy-stm32` for async HAL (USB, SPI, GPIO, RNG). Embassy supports
   STM32U585 via feature flag `stm32u585zi`.

## no_std Dependencies

All cryptographic crates run without heap allocation:

| Crate | Version | no_std | Notes |
|-------|---------|--------|-------|
| `slh-dsa` | 0.2.0-rc.4 | `default-features = false` | 17 KB signatures on stack |
| `aes-gcm` | 0.10 | `default-features = false, features = ["aes"]` | In-place encrypt/decrypt |
| `sha2` | 0.10 | `default-features = false` | Used for KDF + PBKDF2-HMAC-SHA512 + ZK VK hash |
| `hmac` | 0.12 | `default-features = false` | Used for mock MACD + PBKDF2 |
| `signature` | 3.0.0-rc.10 | `default-features = false` | Signer/Verifier traits |
| `bls12_381` | 0.8 | `default-features = false, features = ["groups", "pairings"]` | Groth16 ZK clear-sign verifier; 4 individual pairings, no `multi_miller_loop` so no alloc |
| `sphincs-tz-bip39` | local crate | `#![no_std]` | 24-word BIP-39 mnemonic + PBKDF2-HMAC-SHA512, host-tested against canonical Trezor vectors |
| `tropic01` | git (libtropic-rs) | `#![no_std]` | TROPIC01 driver (optional, `tropic01-se` feature) |
| `x25519-dalek` | 2.0.1 | `default-features = false` | X25519 for e2e session (optional) |

## Security Considerations

- **Key isolation:** SPHINCS+ signing key exists in secure SRAM only during the signing
  operation. It is wiped (zeroed + compiler fence) immediately after use.

- **E2E encrypted transport:** All communication between TrustZone secure world and the
  TROPIC01 chip is encrypted with AES-256-GCM over a Noise_KK1 session (X25519 key
  exchange with pre-shared pairing keys). The private key is encrypted at rest
  (AES-GCM wrap in r-mem), encrypted in transit (session encryption), and only
  plaintext in secure SRAM during signing.

- **PIN bricking:** After `MAX_ATTEMPTS` (9) wrong PINs, the encrypted signing key and
  all MACD state are erased from the secure element. Recovery is impossible by design.

- **Pointer validation:** In the gateway, NS pointers should be validated against
  `NS_SRAM_BASE..NS_SRAM_END` before dereferencing. On real hardware, use the TT
  (Test Target) instruction for proper CMSE address validation.

- **Stack budget:** SPHINCS+ signing requires ~20-34 KB of stack (17 KB for the
  `Signature` struct + working memory). The secure world linker script allocates
  128 KB of SRAM with stack growing from the top.

- **Shared memory:** The gateway command buffer is in NS SRAM and is thus writable
  by the non-secure world at any time. The secure handler treats all data read from
  shared memory as untrusted input.

- **Session freshness:** Each TROPIC01 operation batch generates a fresh ephemeral
  X25519 keypair (from `/dev/urandom` on QEMU, hardware RNG on STM32U585), preventing
  session replay attacks.



### From `docs/pq-aa-wallet-design.md`

# Post-Quantum ERC-4337 Wallet: Final Design Spec

A hardware-wallet-backed, seed-phrase-recoverable, post-quantum ERC-4337 account abstraction wallet. Built as a fork of Coinbase Smart Wallet, modified for stateful hash-based PQ signers with unlimited rotations and stable cross-chain addresses.

## Design goals

1. **Stable address across all chains**, forever, regardless of rotation history on any individual chain
2. **Unlimited rotations** of the main signer, recoverable deterministically from the BIP-39 seed phrase
3. **Zero cryptographic contamination** between chains — one chain's signing activity never weakens another's
4. **Crash-consistent state management** — losing the hardware device and recovering on a new one is always safe, with no risk of OTS index reuse
5. **Production compatibility with Gnosis Safe and CowSwap today**, without relying on ERC-6492 adoption
6. **Graceful handling of the stateful hash-based signature budget** (~2^20 signatures per keypair)

---

## Core architectural decisions

### 1. Two-tier signer architecture

The wallet has **two classes of signer**, both derived from the same BIP-39 seed:

- **Bootstrap signer**: a single, stateless PQ keypair (ML-DSA-44 recommended, ~2.4 KB signatures). Used only for administrative operations: initial deployment on each chain, and emergency rotation if state is lost. Never rotates. One key for the lifetime of the wallet.
- **Main signer**: the active signing key for day-to-day transactions on a specific chain. Stateful hash-based (XMSS h=20 or SPHINCS+ few-time 128s). Rotates every ~1M signatures. **Per-chain and per-epoch.**

### 2. Per-chain key derivation

Each chain gets its own independent sequence of main signers, derived via BIP-85 from the seed:

```
bootstrap            = BIP85(seed, m/83696968'/PQ_BOOTSTRAP'/0')
<chain>-main-key_i   = BIP85(seed, m/83696968'/PQ_MAIN'/<chainId>'/<i>')
```

For example:
- `base-main-key_0`     = `m/83696968'/PQ_MAIN'/8453'/0'`
- `base-main-key_1`     = `m/83696968'/PQ_MAIN'/8453'/1'`
- `mainnet-main-key_0`  = `m/83696968'/PQ_MAIN'/1'/0'`
- `arbitrum-main-key_0` = `m/83696968'/PQ_MAIN'/42161'/0'`

Keys on different chains are cryptographically independent. OTS indices on Base can never collide with OTS indices on mainnet because the underlying keypairs are different.

### 3. CREATE2 salt is bootstrap-only

The factory computes the CREATE2 address using **only** the bootstrap public key:

```
salt = keccak256(bootstrapPubKey)
address = keccak256(0xff ‖ factory ‖ salt ‖ keccak256(proxyInitCode))
```

The `proxyInitCode` is a constant ERC-1967 proxy pointing at a fixed implementation slot. **Nothing chain-specific or main-signer-specific goes into the initCode or salt**, so the address is identical on every chain.

### 4. On-chain state per chain

Each chain's deployed wallet stores its own state independently:

```solidity
struct PQSignerStorage {
    bytes32 bootstrapPubKeyHash;   // set at init, immutable
    uint32  currentKeyIndex;       // epoch index: 0, 1, 2, ...
    bytes32 currentMainPubKeyHash; // keccak256(current main signer pubkey)
    uint32  currentOTSIndex;       // next unused OTS leaf for current main key
    uint32  maxOTSIndex;           // 2^20 - 1 = 1,048,575
}
```

The blockchain is the **authoritative state**. The hardware wallet's local OTS counter is a convenience optimization; on any ambiguity, the on-chain value wins.

---

## Factory contract

```solidity
contract PQWalletFactory {
    address public immutable implementation;
    bytes32 public immutable proxyInitCodeHash;

    event WalletDeployed(address indexed wallet, bytes32 indexed bootstrapPubKeyHash);

    constructor(address _implementation) {
        implementation = _implementation;
        // proxy bytecode is a constant ERC-1967 minimal proxy
        proxyInitCodeHash = keccak256(_proxyInitCode());
    }

    /// @notice Deploys a wallet at a deterministic address derived from bootstrapPubKey.
    /// @dev The address is the same on every chain for the same bootstrapPubKey.
    function createAccount(
        bytes calldata bootstrapPubKey,
        bytes calldata initialMainSigner,
        bytes calldata bootstrapSig
    ) external returns (address account) {
        // Verify the bootstrap signature authorizes this initial main signer.
        // Note: no chainId in the signed message — it's intentionally replayable
        // across chains, because the user wants the same initial signer everywhere.
        bytes32 authMsg = keccak256(abi.encodePacked("PQWALLET_INIT_V1", initialMainSigner));
        require(
            _verifyBootstrapSig(bootstrapPubKey, authMsg, bootstrapSig),
            "bad bootstrap sig"
        );

        bytes32 salt = keccak256(bootstrapPubKey);
        account = _deployProxy(salt);

        IPQWallet(account).initialize(bootstrapPubKey, initialMainSigner);

        emit WalletDeployed(account, keccak256(bootstrapPubKey));
    }

    /// @notice Computes the CREATE2 address for a given bootstrap key.
    /// @dev Same inputs → same address on every chain.
    function getAddress(bytes calldata bootstrapPubKey) external view returns (address) {
        bytes32 salt = keccak256(bootstrapPubKey);
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt, proxyInitCodeHash
        )))));
    }

    function _deployProxy(bytes32 salt) internal returns (address) {
        bytes memory initCode = _proxyInitCode();
        address addr;
        assembly {
            addr := create2(0, add(initCode, 0x20), mload(initCode), salt)
        }
        require(addr != address(0), "create2 failed");
        return addr;
    }

    function _proxyInitCode() internal view returns (bytes memory) {
        // Constant ERC-1967 proxy with `implementation` baked in via immutable
        // (not storage), so the initCode depends only on `implementation`.
        // Returned bytes are identical on every chain where this factory is
        // deployed at the same address with the same implementation.
        // ... standard ERC-1967 proxy bytecode ...
    }

    function _verifyBootstrapSig(
        bytes calldata pubKey,
        bytes32 message,
        bytes calldata sig
    ) internal view returns (bool) {
        // Verify ML-DSA-44 signature (or whatever bootstrap scheme is chosen).
        // Likely a call to a verifier library or precompile (EIP-8051 when available).
    }
}
```

### Why the bootstrap signature is required and chain-agnostic

- **Required**: without it, a front-runner who sees your `bootstrapPubKey` (public, in the salt) could deploy your wallet on a chain you haven't touched yet, initialized with *their* chosen main signer. You'd recover via bootstrap-authorized rotation, but it wastes gas and creates an ugly race.
- **Chain-agnostic**: the signed message deliberately omits `chainId`. This lets the user produce *one* bootstrap signature over `initialMainSigner` and use it on every chain they ever deploy to. A replayed signature on a new chain is not a threat — it can only deploy the wallet with the *exact* main signer the user chose, which is what they wanted anyway.

---

## Wallet contract

```solidity
contract PQWallet is IPQWallet, BaseAccount {
    // ERC-7201 namespaced storage
    bytes32 private constant STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("pqwallet.storage.v1")) - 1))
        & ~bytes32(uint256(0xff));

    struct Storage {
        bytes32 bootstrapPubKeyHash;
        uint32  currentKeyIndex;
        bytes32 currentMainPubKeyHash;
        uint32  currentOTSIndex;
        bool    initialized;
    }

    uint32 constant MAX_OTS = (1 << 20) - 1;

    event MainSignerRotated(uint32 indexed newKeyIndex, bytes32 indexed newPubKeyHash);
    event OTSConsumed(uint32 indexed keyIndex, uint32 indexed otsIndex);

    modifier onlySelf() {
        require(msg.sender == address(this), "only self");
        _;
    }

    function initialize(
        bytes calldata bootstrapPubKey,
        bytes calldata initialMainSigner
    ) external {
        Storage storage s = _s();
        require(!s.initialized, "already init");
        s.initialized = true;
        s.bootstrapPubKeyHash = keccak256(bootstrapPubKey);
        s.currentKeyIndex = 0;
        s.currentMainPubKeyHash = keccak256(initialMainSigner);
        s.currentOTSIndex = 0;
    }

    /// @notice Rotate the main signer. Authorized by EITHER the current main
    /// signer (normal rotation) OR the bootstrap signer (recovery rotation).
    function rotateMainSigner(
        uint32 newKeyIndex,
        bytes calldata newMainPubKey
    ) external onlySelf {
        Storage storage s = _s();
        require(newKeyIndex == s.currentKeyIndex + 1, "sequential only");

        s.currentKeyIndex = newKeyIndex;
        s.currentMainPubKeyHash = keccak256(newMainPubKey);
        s.currentOTSIndex = 0;

        emit MainSignerRotated(newKeyIndex, s.currentMainPubKeyHash);
    }

    /// @notice ERC-4337 validation. Accepts signatures from either the current
    /// main signer or the bootstrap signer.
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256) {
        Storage storage s = _s();
        PQSignatureWrapper memory wrapper = abi.decode(userOp.signature, (PQSignatureWrapper));

        if (wrapper.signerType == SignerType.MAIN) {
            // Normal path: stateful PQ signature from current main signer
            require(wrapper.keyIndex == s.currentKeyIndex, "wrong key epoch");
            require(wrapper.otsIndex == s.currentOTSIndex, "wrong ots index");
            require(wrapper.otsIndex <= MAX_OTS, "key exhausted");
            require(
                keccak256(wrapper.pubKey) == s.currentMainPubKeyHash,
                "pubkey mismatch"
            );

            bool ok = _verifyStatefulPQ(
                wrapper.pubKey,
                userOpHash,
                wrapper.otsIndex,
                wrapper.signature
            );
            if (!ok) return SIG_VALIDATION_FAILED;

            // Consume the OTS index atomically with validation success
            s.currentOTSIndex = wrapper.otsIndex + 1;
            emit OTSConsumed(s.currentKeyIndex, wrapper.otsIndex);

            return 0;
        } else if (wrapper.signerType == SignerType.BOOTSTRAP) {
            // Admin path: stateless PQ signature from bootstrap signer
            require(
                keccak256(wrapper.pubKey) == s.bootstrapPubKeyHash,
                "bootstrap mismatch"
            );
            bool ok = _verifyStatelessPQ(wrapper.pubKey, userOpHash, wrapper.signature);
            return ok ? 0 : SIG_VALIDATION_FAILED;
        }

        return SIG_VALIDATION_FAILED;
    }

    /// @notice EIP-1271 for Safe and CowSwap compatibility (when deployed).
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external view returns (bytes4)
    {
        // Verify against current main signer OR bootstrap.
        // For large PQ signatures, prefer ZK-wrapped proofs here to keep size
        // compatible with Safe/CowSwap calldata limits.
        // ...
        return 0x1626ba7e;
    }

    function _s() private pure returns (Storage storage s) {
        bytes32 slot = STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    function _verifyStatefulPQ(
        bytes memory pubKey,
        bytes32 message,
        uint32 otsIndex,
        bytes memory sig
    ) internal view returns (bool) {
        // XMSS or SPHINCS+ few-time verification.
        // Likely wrapped as a ZK proof of validity to fit in validateUserOp's
        // gas budget — raw verification is 4.4M gas (XMSS) or 11.6M gas (SPHINCS+),
        // both over the practical bundler limit.
    }

    function _verifyStatelessPQ(
        bytes memory pubKey,
        bytes32 message,
        bytes memory sig
    ) internal view returns (bool) {
        // ML-DSA-44 verification. Cheap enough to do inline once EIP-8051
        // precompile lands; until then, use a verifier library or ZK wrapper.
    }
}
```

---

## Key derivation spec

All keys derive from a single BIP-39 seed phrase (24 words recommended for post-quantum security margin) via BIP-85.

```
Application ID: 83696968' (standard BIP-85 prefix)

Bootstrap signer (global, never rotates):
    m/83696968'/PQ_BOOTSTRAP'/0'
    → ML-DSA-44 keygen seed → (bootstrap_sk, bootstrap_pk)

Main signers (per-chain, per-epoch):
    m/83696968'/PQ_MAIN'/<chainId>'/<keyIndex>'
    → XMSS or SPHINCS+ few-time keygen seed → (main_sk_i, main_pk_i)
```

Recommended constants (pick final values before deployment; they become permanent):
- `PQ_BOOTSTRAP` = `0x50510001'` (or similar, any unused BIP-85 app code)
- `PQ_MAIN`      = `0x50510002'`

BIP-85 derivation produces 64 bytes of entropy per path; use as the seed input to the PQ scheme's deterministic KeyGen.

---

## Operational flows

### Flow A: first-time deployment on a new chain

```
User action: "Use my wallet on chain X for the first time"

1. Companion app derives:
     - bootstrap_pk (from seed)
     - chainX-main-key_0 (from seed, using chainId X)
2. Companion app computes wallet address via factory.getAddress(bootstrap_pk)
3. User confirms bootstrap-authorized deployment on hardware wallet
4. Hardware wallet produces bootstrap signature over:
     keccak256("PQWALLET_INIT_V1" ‖ chainX-main-key_0)
   (Same signature is valid on every chain, can be cached.)
5. Companion app submits UserOp on chain X:
     initCode = factory.createAccount(
         bootstrap_pk,
         chainX-main-key_0,
         bootstrapSig
     )
     callData = <optional first action, e.g. setPreSignature for CowSwap>
6. Bundler deploys + optionally executes the first action atomically
7. Wallet state on chain X:
     bootstrapPubKeyHash  = keccak256(bootstrap_pk)
     currentKeyIndex      = 0
     currentMainPubKeyHash = keccak256(chainX-main-key_0)
     currentOTSIndex      = 0
```

### Flow B: normal rotation (main signer exhausted on chain X)

```
Trigger: currentOTSIndex approaches MAX_OTS (e.g., 1,048,000 of 1,048,575)

1. Companion app reads state from chain X
2. Hardware wallet derives chainX-main-key_<i+1> from seed
3. Construct rotation UserOp signed by current main signer at the next OTS index:
     callData = rotateMainSigner(i+1, chainX-main-key_<i+1>)
     signature = stateful PQ sig from chainX-main-key_i at OTS index currentOTSIndex
4. Submit to bundler; wallet state updates to:
     currentKeyIndex      = i+1
     currentMainPubKeyHash = keccak256(chainX-main-key_<i+1>)
     currentOTSIndex      = 0
5. Old chainX-main-key_i is now permanently retired for this chain
```

### Flow C: hardware wallet lost, recover on new device, continue on same chain

```
Scenario: user was at currentKeyIndex=1, currentOTSIndex=432117 on Base

1. User enters seed phrase on new hardware wallet
2. Companion app reads Base state via eth_getStorageAt:
     currentKeyIndex=1, currentOTSIndex=432117, currentMainPubKeyHash=H
3. New device derives base-main-key_1 from seed (deterministic, same as old)
4. Sanity check: keccak256(base-main-key_1) must equal H ✓
5. Set local OTS counter to 432117
6. Resume signing; next signature uses OTS index 432118
7. (Optional paranoia rotation: if old device may be stolen, immediately
    submit a rotation UserOp to base-main-key_2 to invalidate the old device)
```

### Flow D: hardware wallet lost, recover on new device, use on a DIFFERENT chain for the first time

```
Scenario: user had Base wallet (already rotated to key_1), loses device,
           recovers, wants to transact on mainnet (never deployed there)

1. User enters seed phrase on new hardware wallet
2. Companion app checks mainnet: eth_getCode(walletAddress) = 0x → not deployed
3. Derive from seed:
     - bootstrap_pk
     - mainnet-main-key_0  (NEVER been used anywhere — fresh key)
4. Hardware wallet produces bootstrap signature over mainnet-main-key_0
5. Deploy on mainnet via factory.createAccount(
       bootstrap_pk, mainnet-main-key_0, bootstrapSig)
6. Wallet address on mainnet = wallet address on Base ✓
     (both derived from keccak256(bootstrap_pk))
7. Mainnet state initializes to:
     currentKeyIndex=0, currentMainPubKeyHash=keccak256(mainnet-main-key_0),
     currentOTSIndex=0
8. Base remains completely independent: still at key_1, still ticking along
9. Zero cross-contamination: mainnet's key_0 has never signed anything on Base,
    so there's no OTS reuse risk even in principle
```

### Flow E: emergency state recovery (on-chain state suspected corrupt)

```
Scenario: unclear what currentOTSIndex is, or suspect a race condition

1. Companion app reads on-chain state; if state looks suspicious:
2. User authorizes bootstrap-level rotation
3. Hardware wallet derives chainX-main-key_<current+1> from seed
4. Bootstrap-signed UserOp calling rotateMainSigner(current+1, new_pk)
5. Wallet advances to next key epoch, resetting currentOTSIndex to 0
6. Any ambiguity about old state is now moot — old key is retired
```

---

## Bootstrap key security properties

The bootstrap key is powerful: it can rotate the main signer on any chain without the current main signer's cooperation. Treat it accordingly:

- **Never leaves the hardware wallet**. Derived fresh from seed each use.
- **Explicit UX on every use**: "You are authorizing an administrative operation that can move your wallet to a new signer. This should only happen during first deployment on a chain or emergency recovery."
- **Stateless**, so state loss is never a bootstrap security issue — no OTS counter to corrupt.
- **Optional timelock** (recommended for high-value wallets): bootstrap-authorized rotations take effect after N hours, with a cancel-by-main-signer escape hatch. Gives you a window to notice and cancel if the seed is compromised.
- **Different crypto family from main signer** (ML-DSA vs. hash-based): a cryptanalytic break in one family doesn't compromise the other. This is a valuable hedge given the relative youth of PQ schemes.

---

## EIP-1271 / Safe / CowSwap integration

### Deployment detection

```typescript
async function isDeployed(provider: Provider, walletAddress: string): Promise<boolean> {
    const code = await provider.getCode(walletAddress);
    return code !== '0x' && code.length > 2;
}
```

Check per chain. Never rely on EntryPoint queries (deposits can exist without deployment).

### CowSwap: setPreSignature pattern (recommended)

Avoid passing PQ signatures through CowSwap entirely. When the user places a CowSwap order:

1. Ensure wallet is deployed on the chain (deploy via Flow A if not)
2. Submit a UserOp: `wallet.execute(GPv2Settlement, 0, abi.encodeCall(setPreSignature, (orderUid, true)))`
3. The UserOp's signature is a normal PQ signature (main signer), verified inside `validateUserOp` only
4. CowSwap's settlement sees a PreSign flag, not a signature — it checks `preSignature[orderUid] == PRE_SIGNED`
5. CowSwap API receives just the 20-byte wallet address as "signature"

This completely sidesteps large PQ signature compatibility issues with CowSwap.

### Gnosis Safe: signMessage pattern (recommended)

For Safe transactions where the PQ wallet is a signer on a Safe:

1. Ensure PQ wallet is deployed on the chain
2. Submit a UserOp: `wallet.execute(safeAddress, 0, abi.encodeCall(Safe.signMessage, (msgHash)))`
3. Safe marks the hash as signed in its own storage
4. When the Safe transaction executes, Safe's `checkSignatures` sees the pre-approved hash and accepts it
5. The PQ signature is verified only once, inside the PQ wallet's `validateUserOp` — never passed to the Safe

### Direct EIP-1271 (fallback, for off-chain gasless flows)

When a protocol absolutely requires `isValidSignature` to be called and there's no on-chain pre-approval path:

1. The PQ wallet must be deployed on the target chain
2. `isValidSignature` verifies a **ZK proof** of PQ signature validity, not the raw PQ signature
    - Groth16 proof: ~128–200 bytes, cheap verification
    - STARK proof: larger but post-quantum secure
3. The ZK proof fits comfortably in Safe's ~64 KB practical signature limit
4. Raw PQ signatures (7.8–50 KB) would exceed practical Safe/CowSwap signature size limits and should never be passed directly

---

## Cross-chain deployment cost summary

| Chain    | Deployment gas | Cost at typical gas price |
|----------|---------------|---------------------------|
| Mainnet  | ~200,000      | ~$1–3 at 30 gwei          |
| Base     | ~200,000      | <$0.01                    |
| Arbitrum | ~200,000      | <$0.01                    |
| Optimism | ~200,000      | <$0.01                    |

Can be bundled with the first real action (e.g., a CowSwap setPreSignature) to save a transaction.

---

## Signature scheme selection

### Main signer (stateful, rotates)

**Recommended: SPHINCS+ few-time 128s** with parameters (n=16, h=17, d=1, log(t)=20, k=8, w=16)
- Signature size: ~3.4 KB
- Public key: 32 bytes
- Signature budget: ~2^20 per keypair
- Graceful degradation on OTS overuse (safer than XMSS if state is lost)

**Alternative: XMSS with h=20**
- Signature size: ~2.75 KB
- Public key: 68 bytes
- Signature budget: exactly 2^20 per keypair
- Catastrophic failure on OTS reuse — only choose if you have high confidence in state management

On-chain verification cost is prohibitive for both (4.4M/11.6M gas). Wrap verification in a ZK-STARK proof (~200–500K gas) for `validateUserOp` compatibility.

### Bootstrap signer (stateless, global)

**Recommended: ML-DSA-44 (Dilithium2)**
- Signature size: ~2.4 KB
- Public key: ~1.3 KB
- NIST standardized (FIPS 204)
- Lattice-based (different family from main signer — hedge against hash-based breaks)
- Verification fast enough for direct on-chain use when EIP-8051 precompile lands

**Alternative: SPHINCS+-128s (standard, not few-time)**
- Signature size: ~7.8 KB
- Same hash-based family as main signer (less hedging value)
- Larger signatures but simpler crypto review

---

## Implementation checklist

- [ ] Fork Coinbase Smart Wallet (`coinbase/smart-wallet`)
- [ ] Replace `MultiOwnable` with `PQSignerStorage` layout
- [ ] Implement `_validateSignature` with dual-path (main/bootstrap) logic
- [ ] Implement `rotateMainSigner` with `onlySelf` modifier
- [ ] Implement `isValidSignature` for EIP-1271 (ZK-wrapped verification)
- [ ] Write `PQWalletFactory` with bootstrap-signature-gated `createAccount`
- [ ] Use ERC-1967 proxy with immutable implementation to keep initCode constant
- [ ] Verify CREATE2 addresses match across chains in testing (deploy to at least 3 testnets, confirm identical addresses)
- [ ] Build the PQ verifier library (or ZK circuit) for the chosen main signer scheme
- [ ] Build the ML-DSA verifier library (or wait for EIP-8051)
- [ ] Define BIP-85 app codes for `PQ_BOOTSTRAP` and `PQ_MAIN`; document them permanently
- [ ] Hardware wallet firmware: implement BIP-85 derivation, XMSS/SPHINCS+ signing, ML-DSA signing, OTS counter sync from chain
- [ ] Companion app: deployment detection per chain, factory deployment flow, rotation flow, recovery flow
- [ ] Companion app: CowSwap setPreSignature integration
- [ ] Companion app: Safe signMessage integration
- [ ] Test Flow D extensively — cross-chain first-deployment after rotation on another chain is the most subtle path
- [ ] Security audit focused on: OTS reuse scenarios, front-running on new chains, bootstrap key exposure, ZK circuit soundness
- [ ] Consider timelock on bootstrap-authorized rotations for high-value deployments

---

## Open questions to resolve before mainnet

1. **Exact main signer scheme**: final parameter selection for SPHINCS+ few-time vs. XMSS. Pending completion of the C reference implementation.
2. **ZK wrapping strategy**: Groth16 (smaller proofs, trusted setup) vs. STARK (no trusted setup, post-quantum secure, larger proofs). STARK is philosophically better aligned with a PQ wallet.
3. **EIP-8051 timing**: if ML-DSA precompile lands before mainnet, bootstrap verification becomes nearly free and the design simplifies.
4. **Timelock default**: should bootstrap-authorized rotations have a default timelock? What's the right duration? (Suggestion: 24h default, user-configurable, 0h for low-value wallets.)
5. **Chain ID collisions**: the per-chain derivation path uses `chainId` — what happens if a chain forks and creates a duplicate? (Unlikely but worth specifying: the wallet commits to a specific chainId at deploy time via its state, so a fork creates two independent states naturally.)



### From `docs/HARDENING.md`

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



### From `docs/brownout-hardening.md`

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
| **E. Dual-SE ordering** | STM32 wipes SE050 OK, then Vcc dies before `erase_pbs_page` runs. Half-wiped state survives. | Partially covered by the wipe-in-progress flag, but the flag doesn't distinguish "pre-SE050-wipe" from "post-SE050-wipe-pre-OPTIGA-erase". |
| **F. SRAM residue** | Abnormal reset before panic handler runs. Secrets linger in SRAM1 retention until next power-on. | `panic_handler` zeroizes, but any reset path that skips it leaves SRAM intact. No boot-time sanitization. |
| **G. Half-flashed firmware** | OTA / DFU interrupted by brownout. Firmware partially programmed. | Out of scope for this doc — addressed by the separate measured-boot + signed-update work (work-todo.md items 14-16). |
| **H. Option-byte write** | Bricks the chip. | We never write option bytes at runtime. Fine. |

Current design addresses **E partially** (wipe flag) and **F partially**
(panic handler zeroize). Everything else is unmitigated.

**Cross-references to the 2026-04-14 deep-research round** (see
`docs/production-security.md` for the full synthesis):

- Bundle A (fault injection) confirms: **BOR/IWDG/ECC/TAMP factory
  defaults are directly attackable**. Masaryk U 2024/2025 thesis
  (Simonik) demonstrated 76% PIN-glitch bypass on STM32U5A9 — same
  core family as our U585. Our Stage 2 plan is now a must-ship, not
  a nice-to-have.
- Bundle A also surfaces: **SLH-DSA verify-after-sign is insufficient**
  per RFC 9814 + Genêt TCHES 2023. A single fault during signing
  produces a signature that often still verifies. Double-compute on
  disjoint SRAM is mandatory. Tracked in work-todo.md #18, not in
  this doc (out of brownout scope).
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
  variant `VerifyMismatch`. Existing multi-QW writers (`write_key`,
  `write_pbs`, `write_admin_pin`, `arm_wipe_flag`) switch to verified
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
  Every persistent structure (admin PIN, PBS, future items) goes
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
- **Same pattern for PBS page 126.**
- **Migration**: detect old single-slot layout at boot, relocate to
  A/B.

Addresses: residual risk at A, B, C even if Stages 1-4 have a bug.

### Beyond Stage 5 (out of scope for this roadmap)

- **Hardware bulk capacitance** — add 22 µF decoupling cap near MCU to
  widen PVD-to-BOR window from ~94 µs to ~440 µs. PCB revision change.
- **TAMP peripheral full config** — external tamper pins, temperature
  monitor, voltage monitor. Wallet-enclosure-design-dependent.
- **Signed firmware update with brownout-safe flashing** — tracked
  separately (`docs/work-todo.md` items 14/15/16).

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
  Manual, but validated end-to-end: see `docs/se050-factory-reset.md`
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

- **Do not write option bytes from runtime firmware.** Option-byte
  writes require `OBL_LAUNCH` which resets the chip. Doing it at an
  unexpected time could brick the wallet. Runtime code only *reads*
  option bytes; all writes go through `STM32_Programmer_CLI` during
  provisioning.
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
| This doc | `docs/brownout-hardening.md` |



### From `docs/production-security.md`

# Production Security — synthesis of 2026-04-14 research round

This document consolidates findings from 4 parallel AI deep-research
sessions (bundles A, B, C, D — prompt E has not yet run) into a single
actionable reference. It is *not* the code; it is the distilled plan.
Implementation tasks track in `docs/work-todo.md` items #18-22.

Raw research results live under `docs/research-bundles/results/`. Each
finding below cites the responsible bundle plus any verification caveats.

**Scope of this doc:** threats, mitigations, and architectural decisions
that the research round surfaced. For the staged brownout-hardening
rollout see `docs/brownout-hardening.md`. For the SE050 PIN-lockout
factory-reset design see `docs/se050-factory-reset.md`.

---

## 1. Top 5 critical findings (do these before anything else)

1. **SLH-DSA verify-after-sign is inadequate**. Current code assumes
   signing the blob, re-verifying, and failing closed is enough. Per
   RFC 9814 and Genêt (TCHES 2023) a single fault during SLH-DSA
   signing produces a signature that often still verifies. Double-
   compute on disjoint SRAM regions + constant-time compare is the
   only defence. Cost: ~6 s per signature at SHA2-128f — acceptable.
   *Source: bundle A.*

2. **We are currently signing deterministically (OptRand = 0)**. This
   enables PRF(SK.seed) recovery via horizontal DPA on unprotected
   Cortex-M33 in 1-10 traces against Saarinen's 2024 TVLA baseline.
   Every signature must draw a fresh 16 B (128f) / 24 B (192f) from
   STM32 TRNG as OptRand. One-line fix with massive SCA impact.
   *Source: bundle C.*

3. **NXP SE050 SCP03 keys are the published factory defaults**. Until
   we rotate them per-device, anyone with a logic analyzer + the
   Global Platform default key list can decrypt our I2C bus. The
   research provides the published key values from AN12436 and the
   exact PUT KEY rotation sequence. Must execute at factory per
   device. *Source: bundle B.*

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

**Cost**: ~6 s per signature (double-compute), +~5 instructions per
protected boolean (FihInt). Acceptable for a wallet UX.

### 2.2 Production key management (bundle B → todo #20)

**Big picture**: Trezor Safe 5 uses single-SE + binding; we extend to
dual-SE + signed binding record + OTP anchor + monotonic counter.

**Factory provisioning — two-stage RDP flow**:

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

**Anti-rollback**: OPTIGA monotonic counter at OID `0xF1E0`,
Conf(0xE140)-protected. Reject firmware with `fw_version < counter`.

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

**Architectural decision pending — SHAKE vs SHA2-256 parameter set**:

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

See todo items #18-22 for the full work list. Suggested phasing:

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

- Not a code specification — see `docs/work-todo.md` for actionable
  tasks with file paths, and the code itself once implemented.
- Not a threat model — see `docs/HARDENING.md` and `CLAUDE.md`
  invariants. This doc documents *mitigations* surfaced by research,
  not the overall threat taxonomy.
- Not a replacement for primary-source documentation — every register
  name / protocol detail cited here should be verified against ST
  RM0456, NXP UM11225, Infineon OPTIGA Trust M User Manual, etc.
  before code lands. The research gave us direction; the primary
  sources give us correctness.



### From `docs/ai-research-briefing.md`

# AI Research Briefing — PQSigner OS

*Purpose: a self-contained project briefing suitable for pasting into
any AI research session (Claude web Deep Research, Gemini Deep Research,
ChatGPT Deep Research, etc.) so the model starts with correct
architectural facts instead of rediscovering — or worse, guessing
wrong — them. This file is kept current; treat the commit that edited
it last as the source of truth.*

---

## 1. What the project is, in five bullets

- **Post-quantum ERC-4337 smart-wallet firmware** for the STM32U585
  (Cortex-M33 with ARM TrustZone) on the B-U585I-IOT02A Discovery
  board. Target form factor is a dedicated hardware-wallet device with
  **USB-C as the only external interface** (no Bluetooth, no
  Ethernet, no UART exposed to the host).
- **Dual secure element** architecture, not single-SE:
  **NXP SE050** (I2C1, addr `0x48`) + **Infineon OPTIGA Trust M V3**
  (I2C1, addr `0x30`). Both chips are mandatory; they hold XOR-split
  entropy. Neither alone reveals any bit of the seed.
- **Signatures are post-quantum (SLH-DSA / SPHINCS+ SHA2-128f today,
  migrating to SHA2-192f for production).** Because no commercial
  secure element can currently compute SLH-DSA, signing runs on the
  Cortex-M33 core inside TrustZone secure world. The secure elements
  act as *gated storage* of the BIP-39 entropy, not as signing
  accelerators. The seed therefore must transit STM32 SRAM during the
  active signing window (~120 s idle timeout, then zeroize).
- **TrustZone partition**: secure world (flash bank 1 `0x0C000000`,
  SRAM1 `0x3000_0000`) owns all crypto, PIN verification, and
  persistent secrets. Non-secure world (flash bank 2, SRAM2) owns UI,
  USB transport, transaction parsing, and ZK-proof verification
  scaffolding. Crossings go through 6 NSC gateway commands; pointer
  validation + TOCTOU-safe copy-to-secure-stack on every entry.
- **Bootstrap signer (ML-DSA-44)** never rotates — it owns the wallet
  address via CREATE2 on the on-chain factory. **Main signer (SLH-DSA)**
  is per-chain, per-epoch, rotates every ~2^20 signatures. Both
  hashes of public keys are anchored on-chain; there's no classical
  secp256k1/P-256 fallback anywhere in the contract.

## 2. Hardware that matters for any research

| Element | Spec | Role |
|---|---|---|
| MCU | STM32U585AII6Q (LQFP144, 2 MB flash, 786 KB SRAM) | Main compute + TrustZone + supervisor |
| Cortex-M33 core | ARMv8-M at 160 MHz | Hosts SLH-DSA signing in secure world |
| SE050 | NXP EdgeLock, I2C, EAL6+ | Stores `half_E` of XOR-split entropy; hardware PIN gate |
| OPTIGA Trust M V3 | Infineon, I2C, EAL6+ | Stores `half_O` of XOR-split entropy; shielded connection |
| On-board STSAFE-A110 | On I2C2 | **Unused** today (probe-only feature) — potential future attestation root |
| OLED | SSD1306, I2C (shared bus with SE050/OPTIGA at 400 kHz) | Trusted display in secure world |
| Buttons | 2× GPIO (PI2 left, PA15 right) | Trusted input in secure world |
| USB | OTG FS peripheral, USB-C connector | Only host interface. Ledger APDU + custom framing |
| VBAT (dev board) | CR1220 holder, unpopulated by default. Dev work uses a tack-soldered 0.47 F supercap across the holder pads. | Backup domain power for Stage 4 — bounded retention (~12 h), not unbounded battery. |
| VBAT (production) | 0.47 F–1 F supercap via Schottky from Vdd. No battery in the enclosure. | Sealed-for-life BOM; bounded tamper window after unplug is acceptable given the dual-SE XOR split threat model. |

**Voltage supervision state (as of this briefing):**
- BOR, PVD, SRAM2/SRAM3/BackupSRAM ECC, IWDG, PVM all at **factory
  defaults** = effectively off/minimum. Stage 1 of the brownout
  roadmap added reset-cause classification and verified flash writes;
  Stage 2 will turn on BOR3, PVD, ECC, and wire an NMI handler. See
  `docs/brownout-hardening.md` for the full 5-stage plan.

**Reset behaviour (empirically verified on this board):**
- `probe-rs reset` = SWD SYSRESETREQ. Classified as `ResetCause::Software`
  via `RCC_CSR=0x14004400`. Does not cut USB Vbus → SE050 shield stays
  powered across the reset (separate chip, not dependent on STM32 state).
- NRST user button (B2) = hardware reset pin. Slightly more thorough
  than `probe-rs reset`. Still doesn't cut USB.
- USB unplug = true cold cycle of both MCU and SE050. Validated in the
  `se050-crash-safety-e2e` test to survive full power-loss mid-wipe.

## 3. Architectural boundaries and trade-offs we have accepted

These are load-bearing decisions — research that contradicts them is
not useful.

1. **Seed transits STM32 SRAM during signing.** Unavoidable until a
   commercial secure element supports SLH-DSA. Mitigations already in
   place: TrustZone isolation, `ZeroizeOnDrop`, signature verify-before-
   release (fault-injection guard), 120 s idle timeout. Future: SRAM2
   relocation + hardware auto-erase (Stage 2), HUK-SAES wrapping.
2. **SE050 release the seed to authenticated firmware.** SE050's value
   isn't "seed never leaves silicon" — it's hardware PIN gate + XOR
   storage. Research that says "do all signing on SE050" is a category
   error for a PQ wallet.
3. **Dual SE means split threat model.** An attacker who extracts one
   chip's contents in isolation gets nothing — only the XOR of both
   halves reveals entropy. That changes what attacks matter: single-
   chip invasive attacks are less critical than dual-chip or
   PCB-level interposer attacks.
4. **USB-C is the only host interface.** No network attack surface
   except via the host computer. USB stack hardness matters a lot; UART
   / JTAG / SWD are production-locked (RDP2, nothing exposed to the
   outside of the enclosure).
5. **We accept that "attacker with EAL6+ decapping capability" wins.**
   Out-of-scope for our threat model. In-scope: everyone with a logic
   analyzer, USB gadget, glitch generator, or purchased/stolen wallet
   who can't afford an ion-beam workstation.
6. **Bootstrap PK hash is immutable after first boot.** The wallet
   address derives from it via CREATE2; changing it breaks identity.
   Any future anti-cloning / attestation design must work around this.

## 4. Current implementation state — what exists, what's missing

**Implemented and validated on hardware (master branch):**
- Dual-SE provisioning + PIN-gated unlock with XOR entropy
  reconstruction in STM32 SRAM.
- SE050 PIN-lockout factory reset via secondary admin UserID
  (`0x7B06_00A0`), admin PIN stored in secure flash page 125,
  two-entry TAG_POLICY on every user object. Full design +
  production checklist: `docs/se050-factory-reset.md`.
- SCP03 authenticated+encrypted channel on SE050. **Using NXP default
  static keys** — not rotated per device. Production plan: rotate +
  HUK-SAES wrap, tracked as `docs/work-todo.md` item 7.
- Shielded Connection on OPTIGA Trust M with Platform Binding Secret
  (PBS) in secure flash page 126.
- SLH-DSA-SHA2-128f signing with verify-before-release.
- ZK clear-signing (Groth16 + Poseidon) for Aave v3 calldata.
- 6-command NSC gateway with pointer validation and TOCTOU-safe
  copy-in.
- Firmware measurement: SHA-256 of secure-flash region → 8 BIP-39
  words on OLED at boot. Companion host tool (`fwmeasure`) for
  reproducible-build comparison.
- **Brownout Stage 1**: reset-cause classification, verified flash
  writes, `stm32-harden-opts` option-byte target (not yet applied on
  any dev board).

**Designed but not implemented:**
- Brownout Stages 1.5–5 (see `docs/brownout-hardening.md`).
- Hash-signature firmware update model (ML-DSA-44 signs the
  measurement hash; `docs/work-todo.md` item 14).
- Immutable bootloader in WRP-locked flash (`docs/work-todo.md` item 15).
- HUK-SAES key wrapping for SCP03 and PBS keys (item 7).
- SE attestation: verifying NXP / Infineon cert chains against
  pinned roots at boot (items 8/10).
- BIP-85 path-structured multi-chain signers (implemented; not yet
  stress-tested).
- SE050 + OPTIGA attempt-counter sync (single-SE lockout is solved;
  dual-SE coordinated lockout is not yet transactional).
- Signed firmware update protocol over USB with brownout-safe
  flashing (item 14).
- Active tamper mesh on enclosure PCB (out-of-firmware).

**Explicitly decided against:**
- Any classical (secp256k1 / P-256 / Ed25519) transaction signer.
- Any secret storage in non-secure world, even transient.
- Software PRNG (all randomness from STM32 TRNG + HSI48).
- Heap allocation in secure world (`#![no_std]`, stack-only).

## 5. Facts corrected after prior research rounds

Listed here so future research doesn't re-derive them from scratch.

| Claim | Correction | Source |
|---|---|---|
| "ECC is always-on in hardware on all SRAM blocks" | Only SRAM1 has always-on ECC. SRAM2, SRAM3, Backup SRAM require option bytes `SRAM2_ECC` / `SRAM3_ECC` / `BKPSRAM_ECC`. Factory default = **off**. | AN5342 |
| Backup SRAM at `0x4002_4000` | `0x4003_6400` (NS alias) on U5. The `0x4002_4000` address is the F4xx family. | Zephyr RTOS ST commits; U5 memory map |
| Flash ECC 9 bits per 64-bit sub-word | 9 bits per **128-bit quad-word** (137 bits total). Torn QW writes double-error on the whole word, not per 64-bit half. | RM0456 |
| PVD bit field `PLS[2:0]` | `PVDLS[2:0]` on U5 (L4-era docs called it `PLS`). | RM0456 |
| BOR4 at ~3.0 V | ~2.8 V. | U5 datasheet |
| BOR3 required for flash writes | Flash supports program/erase down to V<sub>DD</sub> = 1.71 V. BOR3 is a best-practice design margin, not an ST spec. | U5 datasheet |
| B-U585I-IOT02A ships with CR2032 battery | Board has a **CR1220** holder and it is **unpopulated by default**. | B-U585I-IOT02A schematic / user manual |
| Page erase ~3-4 ms | Typical 1.5 ms (10k cycles), 1.7 ms (100k cycles). 3-4 ms is worst-case max at high temp + end-of-life. | U5 datasheet |
| SRAM2_RST erases on "every reset" | Specifically: BOR, pin, software, IWDG, WWDG, OBL. NOT standby-wakeup or backup-domain-only resets. | RM0456 |

**Relevant errata (ES0499):**
- §2.2.7/2.2.8: backup-domain reset can produce unpredictable values when VBAT + VDD share a source.
- §2.2.10: system reset during Stop 2 with SRAM power-down can permanently lock device (fixed in die rev cut 3.3).
- §2.2.23: SRAM ECC status flags only update when matching interrupt is enabled. Pure polling silently misses errors.
- IWDG Early-Wakeup Interrupt does not function in Stop modes (not fixed).
- DWC2 USB controller bugs (section numbers cited as §2.26.x in the 2026-04-14 research; *unverified* — confirm against ES0499 PDF before citing in code): TxFIFO write atomicity (CSR access between consecutive FIFO writes corrupts XFRSIZ); ZLP race condition leaking stale TX FIFO data via SNAK/CNAK/EPENA timing.

**Newly-learned (2026-04-14 research round) facts to fold into research:**
| Claim | Source | Status |
|---|---|---|
| SLH-DSA verify-after-sign is INSUFFICIENT — faulty sigs often still verify | Genêt TCHES 2023 ("Grafting Trees"); RFC 9814 (cited but unverified) | High confidence on technical claim; verify RFC number |
| OptRand = 0 (deterministic SLH-DSA) enables PRF(SK.seed) DPA recovery in ~1-10 traces | Saarinen SLotH CRYPTO 2024 (TVLA t=24.5 at 1k traces) | Plausible; verify exact numbers |
| STM32U585 HASH peripheral provides ZERO DPA protection | ST UM3370 (SESIP guidance) | High confidence |
| STM32U585 DHUK is a known constant at RDP0; "real" DHUK only activates at RDP ≥ 1 | NXP / ST documentation cited in research | Confirm before relying for production key wrap |
| NXP SE050 default SCP03 keys are publicly published (ENC=852B…6287, MAC=DB0A…6B47, DEK=4C2F…A80C) | NXP AN12436 (research cites "Rev 2.4" — unverified) | Cross-check against current AN12436 |
| Cortex-M33 verified vulnerable to USB-MIN() EMFI attack (Colin O'Flynn USENIX WOOT 2019) | Real published attack | Safe to cite |
| Masaryk U thesis (Simonik) demonstrated 76% PIN-glitch bypass on STM32U5A9 | Plausible but unverified — search Masaryk thesis repo | Treat as "presumed vulnerable" until confirmed |

**2026-04-15 verification round**: most of what was initially flagged as hallucinated turned out to be REAL. Our model's training cutoff was pre-2025 so it dismissed post-cutoff publications as fabrications. **Lesson for future research rounds: verify before flagging.** Full corrected verification table in `production-security.md` §3.

**Confirmed real (previously flagged as hallucinated — DO cite them)**:
- `CVE-2026-4179` (Zephyr USB infinite loop, 2026-03-16, advisory `GHSA-9xg7-g3q3-9prf`). Safe to cite; note advisory frames it as ISR-triggered `k_yield()`, not explicitly a malicious-host issue.
- `RFC 9814` (SLH-DSA in CMS, July 2025). Quote confirmed: "this countermeasure is not effective for SLH-DSA."
- NXP AN12436 Rev 2.4 (SE050 default SCP03 keys). All three hex values match byte-for-byte.
- Ledger Donjon March 2025 Trezor Safe 3 glitch (TRZ32F429, `ledger.com/why-secure-elements-make-a-crucial-difference-to-hardware-wallet-security`).
- Trezor Safe 7 (announced October 21, 2025, TROPIC01 + EAL6+ dual attestation).
- Masaryk U Simonik thesis on STM32U5 fault injection (~76% PIN-glitch on Trezor Safe 5).
- BlaatSchaap STM32F103 clone research (`blaatschaap.be`).
- TheCharlatan ColdCard firmware-reset attack (May 2020, `thecharlatan.ch/COLDCARD-Supply-Chain/`).

**Remaining genuinely uncertain / likely fabricated (do NOT cite without independent verification)**:
- Fluhrer ePrint 2024/500 "PRF-tree 1.7× overhead, backward-compatible" — does not appear to exist as described; technically implausible (changing PRF tree structure changes verification output). **Do not base architectural decisions on this.**
- "Extraktor" Ledger Donjon ~$100 glitch board — cannot confirm this specific tool name. Likely misremembering of SiliconToaster (which IS real). Say "published Ledger Donjon tooling" instead.
- NCC Group "CM-1-C" pattern label — NCC's multi-part FI-countermeasure series is real, but the specific "CM-1-C" identifier not locatable. Cite series by URL.
- "SLasH-DSA 2025" Boy et al. Rowhammer — post-cutoff, plausible but unconfirmed. Don't cite yet.
- Saarinen "SLotH" CRYPTO 2024 specific TVLA numerical claims (t=24.5 at 1k traces) — paper+author plausible, exact numbers unverified.
- Belenky et al. specific trace counts (275K / 30K) — unverified.
- ES0499 specific sub-section numbers (§2.26.2, §2.26.3, etc.) — ES0499 Rev 11 confirmed, but exact sub-section numbering may have shifted. Pin to Rev 11 PDF before quoting.

**Attribution correction**: "Riscure LFI on ColdCard" (Mk2 ATECC508A / Mk3 ATECC608A) was actually **Ledger Donjon (Olivier Hériveaux)**, not Riscure. Research content is correct; attribution was wrong.

## 6. Known threats already catalogued

(So research can focus on *new* threats rather than re-listing these.
Updated post-2026-04-14 research round — bundles A, B, C, D have run;
bundle E has not.)

- **Voltage glitching on RDP byte read during boot** — dominant historical STM32 attack. Ledger Donjon's March 2025 statement that no public U5 glitch bypass existed (verified real, `ledger.com/why-secure-elements-make-a-crucial-difference-to-hardware-wallet-security`) was invalidated within months by the Simonik thesis at Masaryk University (verified real) demonstrating ~76% PIN-glitch bypass on STM32U5 silicon. Defences planned: BOR4, PVD, tamper monitors, option-byte RDP Level 2 with OEM1LOCK for production. **U5 is confirmed glitch-vulnerable** at the core level — not presumed, proven.
- **EMFI** — possible against U5 core; no public attack. Defended via internal tamper (temp/voltage/clock), optional tamper mesh on production PCB.
- **Power/EM side-channel on software crypto** — SLH-DSA on Cortex-M33 emits EM. Mitigation status unclear; needs dedicated research (see Prompt C below).
- **Fault injection on signature verify / PIN compare** — partially mitigated (verify-before-release). Bundle A research found verify-after-sign is *not adequate* for SLH-DSA per Genêt TCHES 2023 + RFC 9814. **SLH-DSA double-compute on disjoint SRAM is mandatory** before production. PIN compare needs FihInt complement-storage + fail-in pattern + volatile reads. See `docs/production-security.md` §2.1 + work-todo.md #18.
- **I2C bus interposer between MCU and SE** — defended by SCP03 with auth + encrypt on every APDU. Keys need rotation for production. Bundle B research provides the concrete two-stage RDP provisioning protocol with per-device SCP03 keys derived via CMAC-KDF(FMK, "SCP03-ENC", SE050_UID), PUT KEY (KVN 0x0B → 0x11), HUK-SAES two-level wrapping. See work-todo.md #20.
- **Dark Skippy / anti-klepto nonce exfiltration** — ECDSA-specific, does not apply to SLH-DSA (stateless hash-based signatures have no nonce). **Irrelevant to us.** Stating this explicitly so future research doesn't chase it.
- **Cold boot / Volt Boot / UnTrustZone SRAM residue** — minimize seed time in SRAM; Stage 2 moves secrets to SRAM2 with hardware auto-erase.
- **USB stack** — bundle D research found two unaddressed silicon errata (DWC2 TxFIFO write atomicity; ZLP race causing stale-data leak) and surfaced FI-resistant `min()` pattern (Colin O'Flynn USENIX WOOT 2019 EMFI attack on USB control-transfer length clamp). Bounded reassembly + HID rate limiter + APDU CLA/INS allowlist also pending. See work-todo.md #19. *Note*: research cited `CVE-2026-4179` for a Zephyr USB driver — that CVE is fabricated and should be ignored.
- **Supply chain / counterfeit chips** — STM32 family heavily counterfeited. Bundle E research: U5-family clones not confirmed as of early 2025 (absence of evidence, appropriately hedged). Defences: STM32U585 CPUID + UID + DHUK + errata-fingerprint probes at boot; triple-UID SLH-DSA-128s manifest signed at factory (closes single-chip-swap attacks that have broken every existing wallet); SE050 + OPTIGA attestation against pinned NXP + Infineon root CAs; transparency log of shipped device serials; WebUSB box-opening ceremony for customers. See work-todo.md #22 + production-security.md §2.5.
- **Seed entropy collection** — currently STM32 TRNG + HSI48. Multi-source mixing (STM32 TRNG XOR SE050 TRNG XOR OPTIGA TRNG) is designed but not yet implemented.
- **SLH-DSA side-channel via PRF(SK.seed)** — bundle C research surfaced. Currently signing with `OptRand = 0` (deterministic) which makes horizontal DPA on the master secret feasible per Saarinen SLotH CRYPTO 2024 (~1-10 trace recovery on unprotected Cortex-M33). Mitigations: mandatory non-deterministic OptRand from STM32 TRNG every signature, signing rate limiter, 2^16 per-key rotation, WOTS+ chain + FORS tree shuffling, optional SHAKE migration for cleaner masking. See work-todo.md #18.

## 7. Open architectural questions we are actively researching

These are where research effort should go. Each subsection is a
**drop-in prompt** for an AI research session.

**For tools that accept only one attachment per session** (Claude web,
etc.), we've pre-built self-contained bundle files under
`docs/research-bundles/`. Each bundle combines the question + a
condensed version of this briefing + the relevant code excerpts into a
single ~50-120 KB markdown file. Upload the bundle as the only
attachment, and the session has everything it needs. See
`docs/research-bundles/README.md` for the mapping.

**Status as of last update:**
- Prompt A (fault injection): ✅ run, results in `docs/research-bundles/results/`, synthesised to `docs/production-security.md` §2.1 + work-todo.md #18.
- Prompt B (key management): ✅ run, results in same dir, synthesised §2.2 + #20 (partially superseded by E).
- Prompt C (SLH-DSA SCA): ✅ run, synthesised §2.3 + #18.
- Prompt D (USB hardening): ✅ run, synthesised §2.4 + #19.
- Prompt E (supply-chain attestation): ✅ run, synthesised §2.5 + #22. Triple-UID SLH-DSA manifest **supersedes** Bundle B's ECDSA-P256 binding record.

The prompts below are the canonical question text. After a prompt has
run, future research rounds on the same topic should reference the
existing results doc + ask incremental follow-up questions rather than
re-running the same query.

---

### Prompt A — Fault-injection resistance for PQ signing + PIN path

**Context:** See the "What the project is" + "Architectural trade-offs"
sections above. Key facts: SLH-DSA signing runs on Cortex-M33 core in
TrustZone secure world; PIN verify is delegated to SE silicon
(hardware-constant-time); seed reconstruction from XOR halves happens
in STM32 SRAM during active signing window. Stage 2 of our brownout
roadmap will add PVD + ECC, but does NOT yet add glitch countermeasures.

**Research question:**
Given the 2024-2025 state of voltage / EMFI / laser fault injection
against STM32 Cortex-M33 designs, what is the minimum set of
**software** glitch countermeasures we should add to these three flows:

1. The seed XOR-reconstruction code path in `secure/src/dual_se.rs`
   (`unlock()` function — reads half_O and half_E, reconstructs
   full entropy, derives master_secret, caches encrypted blob).
2. The SLH-DSA signature verify-before-release guard in
   `secure/src/nsc/sign_and_emit.rs` — currently a single compare;
   should be double-glitch-resistant.
3. The PIN-lockout trigger in `secure/src/nsc/cmd_request_unlock.rs`
   — single-glitch inversion of "remaining == 0" check currently
   blocks the factory reset.

Give us **concrete Rust code patterns** (redundant volatile reads,
complement-storage, magic-constant comparisons, random-delay
templates, NCC-Group-style double-check idioms). For each pattern,
identify which fault classes it defends against (single-shot voltage
glitch, double-shot, EMFI, LFI) and which it doesn't. Rank by
cost/benefit.

Out of scope: hardware countermeasures (tamper mesh, bulk cap,
external voltage supervisor) — those are tracked separately.

---

### Prompt B — Production key management for SCP03 + PBS + HUK-SAES

**Context:** See "Current implementation state" — specifically, SCP03
on SE050 uses NXP default static keys today (`0x40 0x41 0x42 …`), and
OPTIGA's Platform Binding Secret is per-device-random but stored as
raw bytes in secure flash page 126. HUK-SAES wrapping is listed as
work-todo item 7 but unimplemented. STM32U585 has the SAES peripheral
and a Hardware Unique Key per chip (not readable by firmware; only
usable as a KEK via SAES). `docs/se050-factory-reset.md` §2a has a
brief future-optimisation note.

**Research question:**
Design a production provisioning + runtime key-management protocol
that:

1. Rotates SE050 SCP03 static ENC/MAC keys from NXP defaults to
   per-device-unique at chip personalization, storing the new keys
   on the STM32 side HUK-SAES-wrapped (never in plaintext flash).
2. Wraps the OPTIGA PBS the same way.
3. Handles the PQSigner firmware upgrade / field-update case: if a
   newer firmware includes a different HUK-SAES domain tag, how does
   it recover existing users' keys without requiring chip reset?
4. Establishes a verifiable per-device attestation chain that binds
   the physical SE050 + OPTIGA UIDs to the STM32 chip-unique-ID, so
   that swap attacks (desolder the SE from a victim device, put it in
   the attacker's device) fail at boot.

Constraints: all key rotation must happen during one-time device
provisioning at the factory (no field rekey). Out-of-band key
transport channels (a secure provisioner machine) are acceptable.
Recovery from a bricked HUK (chip replacement) is NOT required — the
wallet can be treated as "dead, restore from seed backup on a new
device".

Deliverables: a concrete protocol diagram + flash-layout sketch + the
minimum STM32U585 SAES API usage pattern. Reference implementations
from other hardware wallets / secure-provisioning frameworks are
useful.

---

### Prompt C — Side-channel landscape for SLH-DSA on Cortex-M33

**Context:** See section 3 trade-off #1 — our seed transits STM32
SRAM during signing. The signing algorithm is SLH-DSA-SHA2-128f
(migrating to SHA2-192f for production). The chip has hardware AES
(SAES) and PKA, but SLH-DSA is pure hashing (thousands of SHA-256
invocations per signature). The `slh-dsa` crate runs at `opt-level=3`
with whatever its upstream constant-time story is.

**Research question:**
What side-channel attacks (power, EM, cache, timing, μarch) have been
demonstrated or are theoretically plausible against hash-based
signature schemes (SPHINCS+ / SLH-DSA) on ARM Cortex-M33-class chips?

Specifically:

1. Does the published academic literature include practical SLH-DSA
   SCA key-recovery attacks? If so, what are the noise thresholds
   (number of traces, signal-to-noise ratios, distance constraints)?
   If not, what's the closest analogue (SPHINCS-variant attacks,
   generic hash-based-sig attacks, WOTS chain extraction)?
2. Which specific operations within an SLH-DSA signature are the
   most leak-prone? (Candidates: FORS leaf computation exposing SK
   bits; WOTS chain walks exposing step counts; HT layer transitions;
   PRF evaluations consuming the master seed.)
3. Is the SHA-256 hardware accelerator on STM32U585 (HASH peripheral)
   SCA-hardened? If we route SLH-DSA's hashing through it instead of
   software SHA-256, does that eliminate the main leak surface or
   just move it?
4. What's the realistic signature cap per device before SCA traces
   make key recovery feasible? (Our design rotates the main signer
   every ~2^20 signatures; is that already too many?)

Deliverables: a catalogued threat list with severity + mitigation
per item, plus a specific recommendation on whether migration to
SHA2-192f (roughly 2× signing time, 2× signature size) meaningfully
improves the SCA posture or is orthogonal.

---

### Prompt D — USB stack hardening for a USB-C-only hardware wallet

**Context:** The device exposes USB OTG FS on USB-C as its ONLY host
interface. No UART, no BT, no NFC. The USB stack today is custom:
Ledger-compatible APDU framing over HID for compatibility with
existing wallet-host software, plus a custom PQSigner-native protocol
for our own companion app (`docs/usb-protocol-v2.md`). The host
software running on the user's computer is not trusted — it's
potentially the primary attack vector.

**Research question:**
Audit the known attack surface of USB-stack implementations on
STM32 Cortex-M MCUs and recommend hardening for our situation.

Specifically:

1. Known CVEs and proof-of-concept exploits against STM32 USB
   peripherals (STM32Cube USB libraries, RTOS USB drivers, HID
   descriptor parsers). Focus on 2023-2025. Include buffer overflows,
   double-frees, descriptor confusion, any fault-injection-on-USB
   attacks (Colin O'Flynn's EMFI-on-USB work and descendants).
2. Which USB descriptor parsing paths are highest-risk for a custom
   stack that handles both HID and a custom vendor protocol? Where
   are the usual lurking bugs (endpoint count overflow, string
   descriptor length misparse, SETUP-stage DMA corruption, etc.)?
3. What's the minimum set of sanity checks to place between the USB
   ISR and our firmware's APDU handler to resist malformed or
   adversarial host behaviour?
4. Is there an argument for implementing USB in a separate
   co-processor (e.g. on a tiny MCU beside the STM32) with a serial
   shim, to shrink the attack surface on the crypto-hosting chip?

Deliverables: a CVE catalogue with applicability notes ("this affects
our stack", "this affects STM32Cube but we don't use it", etc.), a
ranked hardening checklist, and an architectural recommendation on
co-processor USB.

---

### Prompt E — Supply-chain + provisioning attack landscape

**Context:** A PQ wallet's on-chain identity (address) is derived
from the CREATE2 hash of the bootstrap public key hash. This
bootstrap PK hash is generated at first boot via the STM32 TRNG and
stored in SE050. If an attacker swaps the SE050 between a stolen
wallet and their own at any point from manufacturing through
customer-delivery, they can compromise a user who thinks they're
receiving a fresh device.

**Research question:**
Map the supply-chain + provisioning threat model for a hardware
wallet that uses SE050 + OPTIGA in a TrustZone STM32U585, shipping
through conventional retail/e-commerce channels, and recommend a
provisioning + attestation protocol that defeats each class of
attacker.

Specifically:

1. What's known about counterfeit STM32U5 supply in 2024-2025?
   Are there reports of clones (GD32/CS32/APM32 style) in the U5
   family yet, or only older F/L-series? What boot-time probes
   reliably detect clones?
2. NXP offers a cert chain from SE050 UID up to an NXP root CA.
   How reliable is this for anti-clone? What's the threat model for
   SE050 extraction + re-implantation in a different physical wallet?
3. Same question for OPTIGA Trust M cert chain.
4. What do Ledger, Trezor, Coinkite, Foundation etc. actually do at
   provisioning to attest "this is a genuine factory-sealed device"
   to a customer opening the box? What failure modes have been
   discovered in those schemes (historical + 2024-2025)?
5. Given our dual-SE architecture, is there an additional attestation
   advantage from cross-binding SE050-UID + OPTIGA-UID + STM32-UID
   in a signed manifest that must match at every boot?

Deliverables: a ranked attacker list (opportunistic re-seller;
sophisticated interdictor; nation-state with factory access), the
attestation protocol that defeats each, and a specific
"box-opening" user ceremony that demonstrates genuine-ness to the end
customer without requiring them to run an independent tool.

---

## 8. Style guidance for research output

- **Cite specific document sections** (RM0456 §11, AN5342 §4, ES0499
  §2.2.x, NXP UM11225, Infineon documentation) — not just "per ST
  documentation." If you can't find a primary source for a claim, say
  so.
- **Flag hallucination-prone content.** If you're citing an app-note
  revision number, datasheet page number, or CVE ID and you're not
  sure of the exact value, prefer "per AN5342" over "AN5342 Rev 8 §4.1
  p.32". We'd rather not have to verify every number.
- **Say "I don't know"** on questions that aren't answerable from
  public sources. Better than guessed facts that get compiled into
  firmware.
- **Concrete code / register values** where the answer is
  implementable. Hand-wave answers ("use double-glitch resistance")
  without specifics are not useful.
- **Check architecture before giving advice.** If a recommendation
  requires us to "move signing to the secure element," that's wrong
  for our setup — the SE can't do PQ. Read the trade-offs section.

## 9. File map for navigating the repo

| Concern | Path |
|---|---|
| This briefing | `docs/ai-research-briefing.md` |
| Threat model + architecture | `README.md`, `docs/architecture.md`, `CLAUDE.md` |
| Brownout hardening (5-stage plan) | `docs/brownout-hardening.md` |
| SE050 PIN-lockout factory reset | `docs/se050-factory-reset.md` |
| SE050 native UserID PIN design | `docs/se050-userid-pin-auth.md` |
| Side-channel + FI hardening reqs | `docs/HARDENING.md` |
| Work backlog + provisioning TODOs | `docs/work-todo.md` |
| ERC-4337 wallet contract | `contracts/smart-wallet/src/` |
| Secure world entry | `secure/src/main.rs` |
| NSC gateway (6 commands) | `secure/src/nsc/` |
| Crypto primitives + SLH-DSA derivation | `secure/src/crypto.rs` |
| Dual-SE coordination | `secure/src/dual_se.rs` |
| SE050 driver (T1oI2C + SCP03 + APDUs) | `secure/src/se050/` |
| OPTIGA Trust M driver | `secure/src/optiga/` |
| Reset-cause classification (Stage 1) | `secure/src/reset_cause.rs` |
| Verified flash writes (Stage 1) | `secure/src/hw/flash.rs` |
| TrustZone SAU/GTZC config | `secure/src/sau.rs` |



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
use zeroize::Zeroize;

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
    blob_cached: bool,
}

impl DualSecureElement {
    pub const fn new() -> Self {
        Self {
            optiga: OptigaTrustM::new(),
            se050: Se050::new(),
            entropy_blob_cache: [0; crypto::ENTROPY_BLOB_LEN],
            blob_cached: false,
        }
    }

    /// Load Platform Binding Secret for OPTIGA Trust M (delegates to inner driver).
    pub fn load_pbs(&mut self) {
        self.optiga.load_pbs();
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
        // Generate a random mask for the XOR split.
        // half_O = random 32 bytes (stored on OPTIGA Trust M)
        // half_E = entropy XOR half_O (stored on SE050)
        // Reconstruction: half_O XOR half_E = entropy
        let mut half_o = [0u8; 32];
        crate::rng::fill(&mut half_o).map_err(|_| SeError::InternalError)?;
        let half_e = xor_32(entropy, &half_o);

        // Both SEs get the same master_secret (derived from full entropy).
        // This lets us cross-verify on unlock.
        //
        // OPTIGA Trust M stores half_O as its "entropy" and master_secret
        // behind the HMAC auth reference PIN gate.
        // SE050 stores half_E as its "entropy" behind hardware UserID PIN gating.
        //
        // The VK and bootstrap VK are identical on both chips.
        self.optiga.provision(&half_o, master_secret, vk, bootstrap_vk, pin)?;
        self.se050.provision(&half_e, master_secret, vk, bootstrap_vk, pin)?;

        half_o.zeroize();

        secure_log!("[DUAL] Provisioned: entropy XOR-split across OPTIGA Trust M + SE050");
        Ok(())
    }

    fn unlock(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], UnlockError> {
        // Unlock OPTIGA Trust M first (HMAC auth reference → master_secret).
        let master_o = self.optiga.unlock(pin)?;

        // Unlock SE050 (UserID PIN → master_secret).
        // If this fails, the OPTIGA has already consumed an attempt.
        // The dual-chip PIN lockout sync (intent log) is a separate
        // hardening item — for now, best-effort.
        let master_e = self.se050.unlock(pin).map_err(|e| {
            // Zeroize the OPTIGA master_secret on SE050 failure
            let mut m = master_o;
            m.zeroize();
            e
        })?;

        // Cross-verify: both SEs must return the same master_secret
        // (derived from the same full entropy at provisioning time).
        // If they disagree, one chip has been tampered with or replaced.
        let match_ok: bool = master_o.ct_eq(&master_e).into();

        let mut me = master_e;
        me.zeroize();

        if !match_ok {
            let mut mo = master_o;
            mo.zeroize();
            secure_log!("[DUAL] CRITICAL: master secret mismatch between SEs!");
            return Err(UnlockError::InternalError);
        }

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

        let mut blob_e = [0u8; 64];
        let blob_e_len = self.se050.read_entropy_blob(&mut blob_e)
            .map_err(|_| UnlockError::InternalError)?;
        let mut half_e = crypto::decrypt_entropy_blob(
            &blob_e[..blob_e_len], &master_o
        ).map_err(|_| UnlockError::InternalError)?;
        blob_e.zeroize();

        // Reconstruct the full entropy
        let mut full_entropy = xor_32(&half_o, &half_e);
        half_o.zeroize();
        half_e.zeroize();

        // Verify consistency: kdf("sphincs-master", full_entropy, 0) must
        // equal the master_secret we already got from both SEs.
        let derived_master = crypto::kdf(b"sphincs-master", &full_entropy, 0);
        let consistent: bool = derived_master.ct_eq(&master_o).into();
        if !consistent {
            full_entropy.zeroize();
            let mut mo = master_o;
            mo.zeroize();
            secure_log!("[DUAL] CRITICAL: reconstructed entropy doesn't match master!");
            return Err(UnlockError::InternalError);
        }

        // Cache the encrypted full-entropy blob for the signing flow.
        let blob = crypto::encrypt_entropy_blob(&full_entropy, &master_o);
        self.entropy_blob_cache.copy_from_slice(&blob);
        self.blob_cached = true;

        full_entropy.zeroize();

        secure_log!("[DUAL] Unlocked: entropy reconstructed from XOR split");
        Ok(master_o)
    }

    fn read_entropy_blob(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.blob_cached || buf.len() < crypto::ENTROPY_BLOB_LEN {
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

    fn zeroize_caches(&mut self) {
        self.entropy_blob_cache.zeroize();
        self.blob_cached = false;
        self.optiga.zeroize_caches();
        self.se050.zeroize_caches();
    }

    /// Delegate SE050 wipe to its WalletStore impl (handles admin PIN,
    /// wipe flag, admin-auth delete, flash erase). Then erase PBS to
    /// orphan OPTIGA from this STM32 (no shielded channel without PBS
    /// means no reads of half_O), and zeroize all SRAM state.
    fn factory_reset_admin(&mut self) -> Result<(), SeError> {
        let _ = self.se050.factory_reset_admin();

        #[cfg(feature = "stm32u585")]
        unsafe {
            let _ = crate::hw::flash::erase_pbs_page();
        }

        self.zeroize_caches();
        secure_log!("[DUAL] Factory reset complete — SE050 wiped, PBS erased");
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
//! Gateway commands (see `sphincs_tz_shared::CMD_*`):
//!
//! | ID | Name            | NS → S args                              | S behavior |
//! |----|-----------------|------------------------------------------|------------|
//! | 1  | GET_REMAINING   | —                                        | reads chip; returns u32 |
//! | 2  | REQUEST_UNLOCK  | —                                        | secure UI prompts for PIN |
//! | 3  | GET_PUBKEY      | out_ptr, out_len                         | reads slot 2 |
//! | 5  | CLEAR_SIGN      | payload_ptr, sig_out_ptr, total_len      | ZK verify → display → UserOp sign |
//! | 6  | CLEAR_SIGN_MSG  | payload_ptr, sig_out_ptr, total_len      | ZK verify → EIP-712 → sign |
//! | 7  | SIGN_USEROP     | payload_ptr, sig_out_ptr, total_len      | parse AA + inner tx → confirm → UserOp sign |
//!
//! ## Layout
//!
//! This module is split along command boundaries so each `cmd_*` handler
//! lives in its own file and the shared plumbing (state, pointer
//! validation, the decrypt→derive→sign tail) lives in its own. Adding a
//! new gateway command means creating a new `cmd_*.rs` submodule, adding
//! a match arm in [`dispatch`], and wiring up a new `CMD_*` constant in
//! `sphincs_tz_shared`. **No other file in this module needs to change.**
//!
//!   * [`state`]         — single `SecureState` singleton + `with_state`
//!     closure accessors. The one and only place `static mut` lives.
//!   * [`ptr_validate`]  — NS SRAM/flash pointer + length validators.
//!   * [`sign_and_emit`] — shared "decrypt entropy → derive SK → hedged
//!     SLH-DSA sign → write to NS" tail used by every signing command.
//!   * [`userop_tail`]  — shared "reconstruct execute() callData →
//!     compute userOpHash → decrypt_and_sign" tail used by every
//!     UserOp signing command.
//!   * [`cmd_get_remaining`], [`cmd_request_unlock`], [`cmd_get_pubkey`],
//!     [`cmd_clear_sign`], [`cmd_clear_sign_msg`], [`cmd_sign_userop`].

mod cmd_clear_sign;
mod cmd_clear_sign_msg;
mod cmd_get_bootstrap_pubkey;
mod cmd_get_main_pubkey;
mod cmd_get_pubkey;
mod cmd_get_remaining;
mod cmd_get_wallet_address;
mod cmd_is_unlocked;
mod cmd_lock;
mod cmd_request_unlock;
mod cmd_sign_bootstrap;
mod cmd_sign_message;
mod cmd_sign_userop;
mod ptr_validate;
mod sign_and_emit;
mod state;
mod userop_tail;

#[cfg(not(feature = "stm32u585"))]
use sphincs_tz_shared::{
    NscStatus, CMD_CLEAR_SIGN, CMD_CLEAR_SIGN_MSG, CMD_GET_BOOTSTRAP_PUBKEY,
    CMD_GET_MAIN_PUBKEY, CMD_GET_PUBKEY, CMD_GET_REMAINING, CMD_GET_WALLET_ADDRESS,
    CMD_IS_UNLOCKED, CMD_LOCK, CMD_NONE, CMD_REQUEST_UNLOCK, CMD_SIGN_BOOTSTRAP,
    CMD_SIGN_MESSAGE, CMD_SIGN_USEROP, SHARED_MAILBOX_BASE,
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
    state::peek_state(|s| s.pin_verified)
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

/// Zeroize all sensitive global state. Called from the panic handler,
/// the inactivity wipe, and the cancel/idle-wipe branches of every
/// interactive dialog.
pub fn zeroize_sensitive_state() {
    state::with_state(|s| s.zeroize_sensitive());
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
#[cfg(not(feature = "stm32u585"))]
unsafe fn dispatch(cmd: u32, args: &GatewayArgs) -> u32 {
    match cmd {
        CMD_GET_REMAINING => cmd_get_remaining::run(),
        CMD_REQUEST_UNLOCK => cmd_request_unlock::run(),
        CMD_GET_PUBKEY => cmd_get_pubkey::run(args),
        CMD_CLEAR_SIGN => cmd_clear_sign::run(args),
        CMD_CLEAR_SIGN_MSG => cmd_clear_sign_msg::run(args),
        CMD_SIGN_USEROP => cmd_sign_userop::run(args),
        CMD_GET_BOOTSTRAP_PUBKEY => cmd_get_bootstrap_pubkey::run(args),
        CMD_GET_MAIN_PUBKEY => cmd_get_main_pubkey::run(args),
        CMD_SIGN_BOOTSTRAP => cmd_sign_bootstrap::run(args),
        CMD_IS_UNLOCKED => cmd_is_unlocked::run(),
        CMD_LOCK => cmd_lock::run(),
        CMD_SIGN_MESSAGE => cmd_sign_message::run(args),
        CMD_GET_WALLET_ADDRESS => cmd_get_wallet_address::run(args),
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

/// CMD_GET_REMAINING — returns the remaining PIN attempts.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_remaining_attempts() -> u32 {
    unsafe { cmd_get_remaining::run() }
}

/// CMD_REQUEST_UNLOCK — secure UI prompts for PIN, never crosses NS.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_request_unlock() -> u32 {
    unsafe { cmd_request_unlock::run() }
}

/// CMD_GET_PUBKEY — copy the 32-byte verifying key into the NS buffer.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_pubkey(out_ptr: u32, out_len: u32) -> u32 {
    let args = GatewayArgs { arg0: 0, arg1: out_ptr, arg2: out_len };
    unsafe { cmd_get_pubkey::run(&args) }
}

/// CMD_CLEAR_SIGN — ZK-verified calldata clear signing (UserOp).
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_clear_sign(
    payload_ptr: u32,
    sig_out_ptr: u32,
    total_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: payload_ptr, arg1: sig_out_ptr, arg2: total_len };
    unsafe { cmd_clear_sign::run(&args) }
}

/// CMD_CLEAR_SIGN_MSG — EIP-712 typed-data clear signing.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_clear_sign_msg(
    payload_ptr: u32,
    sig_out_ptr: u32,
    total_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: payload_ptr, arg1: sig_out_ptr, arg2: total_len };
    unsafe { cmd_clear_sign_msg::run(&args) }
}

/// CMD_SIGN_USEROP — wrap inner EIP-1559 tx as ERC-4337 UserOp, sign userOpHash.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_userop(
    payload_ptr: u32,
    sig_out_ptr: u32,
    total_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: payload_ptr, arg1: sig_out_ptr, arg2: total_len };
    unsafe { cmd_sign_userop::run(&args) }
}

/// CMD_GET_BOOTSTRAP_PUBKEY — return the bootstrap signer's VK.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_bootstrap_pubkey(out_ptr: u32, out_len: u32) -> u32 {
    let args = GatewayArgs { arg0: 0, arg1: out_ptr, arg2: out_len };
    unsafe { cmd_get_bootstrap_pubkey::run(&args) }
}

/// CMD_GET_MAIN_PUBKEY — derive and return per-chain main VK.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_main_pubkey(
    payload_ptr: u32,
    out_ptr: u32,
    out_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: payload_ptr, arg1: out_ptr, arg2: out_len };
    unsafe { cmd_get_main_pubkey::run(&args) }
}

/// CMD_SIGN_BOOTSTRAP — sign with bootstrap key (admin ops).
/// **DEPRECATED**: bootstrap signing is now handled automatically by
/// CMD_SIGN_USEROP when mode byte ≥ 2 (not-deployed). Kept for backward compat.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_bootstrap(
    payload_ptr: u32,
    sig_out_ptr: u32,
    total_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: payload_ptr, arg1: sig_out_ptr, arg2: total_len };
    unsafe { cmd_sign_bootstrap::run(&args) }
}

/// CMD_IS_UNLOCKED — return 1 if unlocked, 0 if locked.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_is_unlocked() -> u32 {
    unsafe { cmd_is_unlocked::run() }
}

/// CMD_LOCK — zeroize secrets and lock the device.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_lock() -> u32 {
    unsafe { cmd_lock::run() }
}

/// CMD_SIGN_MESSAGE — EIP-191 personal_sign.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_message(
    payload_ptr: u32,
    sig_out_ptr: u32,
    total_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: payload_ptr, arg1: sig_out_ptr, arg2: total_len };
    unsafe { cmd_sign_message::run(&args) }
}

/// CMD_GET_WALLET_ADDRESS — CREATE2 address computation + OLED display.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_wallet_address(
    payload_ptr: u32,
    out_ptr: u32,
    total_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: payload_ptr, arg1: out_ptr, arg2: total_len };
    unsafe { cmd_get_wallet_address::run(&args) }
}

```
