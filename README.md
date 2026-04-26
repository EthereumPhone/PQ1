# PQSigner OS

A **post-quantum hardware wallet** designed so that *every* cryptographic primitive that protects the seed — at rest, in transit between chips, in firmware updates, in transaction signing — is either a NIST PQC standard or a symmetric primitive at a key size that survives Grover's algorithm. The classical secure channels of the secure elements (which we cannot replace) wrap only opaque ciphertext; a planned ML-KEM-1024 inner wrap will add a PQ confidentiality layer so even a CRQC break of the SE channels reveals only opaque PQ ciphertext.

The design target is a **STM32U585 (Cortex-M33, TrustZone) + Infineon OPTIGA Trust M V3 + NXP EdgeLock SE050**. No single die, no single vendor, and no future cryptographically-relevant quantum computer should be able to recover the seed from harvested traffic or extracted ciphertext.

> **Status: all-C10 cutover complete.** The wallet signs every user transaction with **SPHINCS+C10** (W+C_F+C, `h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205, sig=4008`) — hash-based, no lattice assumptions, no number-theoretic assumptions. *The same primitive signs both Type 1 (bootstrap slot registration) and Type 2 (per-slot user transaction)*; there is no FORS+C, no ECDSA, no classical fallback, no separate slot scheme. The C10 hypertree holds 2^18 = 262,144 signing positions per key; on-chain monotonic counters cap real-world usage at `MAX_BOOTSTRAP_USES = 65_536` and `MAX_SLOT_USES = 65_536` per chain (combined ≈ 2^32 user transactions per chain before that chain is permanently frozen — well inside the birthday-style safety margin). The single `CMD_SIGN_USEROP` returns a `[type1_len|t1|type2_len|t2]` bundle (4073 bytes per Type, plus the optional 4280-byte initCode for first-deploy on a new chain). The firmware is **stateless** with respect to slot selection — the companion supplies `(chain_id, slot_index, flags)` on every call; no `next_q`-in-flash, no per-signature flash writes, no recovery state machine inside the secure world. The TrustZone firmware boots and runs on a real **B-U585I-IOT02A** dev board (STM32U585, Cortex-M33). Both production-target secure-element drivers are working: **OPTIGA Trust M V3** (pure Rust IFX I2C stack + AES-128-CCM Shielded Connection + E120 Lifetime Usage Counter PIN gate) and **NXP SE050** (T1oI2C + SCP03 + admin-UserID-derived-from-OTP for crash-safe factory reset). The dual-SE XOR entropy split is wired, the three-way MCU + OPTIGA + SE050 PIN counter sync is validated end-to-end on real silicon, and Tier-1 of the three-tier DHUK / BHK / OTP key hierarchy is landed (`secret_keys::derive_into` re-rooted on `SAES-CMAC(DHUK, label‖counter)`). The on-chain contracts (`PQSmartWallet` + `PQSmartWalletFactory` + `PQMultiOwnable`) target EntryPoint v0.6 and deploy via cheap ERC-1967 proxies (~50 k gas per user wallet) at a deterministic CREATE2 address keyed on `sha256(masterPkSeed || masterPkRoot)` — the whole signing stack uses SHA-256 (routed to the STM32U585 HASH peripheral on device), with Keccak-256 kept only for the EVM-mandated hashes inside the EntryPoint's own `userOpHash`, EIP-712 clear-sign digests, and the CREATE2 address formula itself. Read the [Implementation Status](#implementation-status) table for what actually exists and where it actually runs today.
>
> **Tropic01** is supported only as a *standalone* secure-element option (single-SE bring-up); the production dual-SE path uses OPTIGA Trust M + SE050. The README's older Tropic01-centric examples (Noise_KK1, MAC-and-Destroy) describe the standalone path and have not been updated to match the dual-SE production target.
>
> **Pre-production status.** No devices have shipped and no on-chain wallets hold funds. Anything below described as "frozen", "part of the recovery contract", or "a hard fork to change" is the shape the team intends to commit to *at launch* — it is not a constraint imposed by a deployed user base. Domain tags, the C10 parameter set, the CREATE2 salt formula, and the EntryPoint version can all still be changed cleanly before first shipment.

```
                  ┌──────────────────────────────────────────────────┐
                  │              STM32U585  (Cortex-M33)              │
                  │                                                   │
                  │  ┌───────────────── SECURE WORLD ───────────────┐ │   ┌──── NON-SECURE WORLD ────┐
                  │  │                                                │ │   │                          │
                  │  │  PIN → gated_unlock (page-124 pre-commit)      │ │   │  USB HID / OLED forward  │
                  │  │     → SE-derived auth via hw::secret_keys      │ │   │  Companion app drives    │
   ┌──────────┐   │  │     → SAES-CMAC(DHUK, label) [Tier 1]          │ │   │  (chain_id, slot_index,  │
   │ OPTIGA   │◄──┼──┤                                                │ │   │   flags) per sign call   │
   │Trust M V3│   │  │  OPTIGA.unlock(K_O)  → half_O                  │◄┼───┼──►┌──────────────────┐  │
   │(Shielded │   │  │  (Shielded Conn AES-128-CCM-8;                 │ │   │   │ NSC gateway      │  │
   │  Conn,   │   │  │   E120 LUC + F1D0 AuthRef silicon-gated)       │ │   │   │ 12 commands      │  │
   │ E120 LUC)│   │  │                                                │ │   │   └──────────────────┘  │
   └──────────┘   │  │  SE050.unlock(K_E)   → half_E                  │ │   │                          │
   ┌──────────┐   │  │  (SCP03 AES-CMAC + AES-CBC; admin UserID       │ │   │  no secrets, ever        │
   │  SE050   │◄──┼──┤   derived from OTP master via secret_keys)     │ │   │                          │
   │  (SCP03  │   │  │                                                │ │   └──────────────────────────┘
   │  outer + │   │  │  E       = HKDF(half_O ⊕ half_E)               │ │
   │  admin-  │   │  │  bip39_seed ← PBKDF2-SHA512(BIP-39(E))         │ │
   │  UID)    │   │  │  master = HMAC-SHA512("sphincs-c6-v1", seed)   │ │
   └──────────┘   │  │  master_sk ← sphincs_c10::SigningKey::keygen   │ │
                  │  │  slot_sk   ← sphincs_c10::SigningKey::keygen   │ │
                  │  │              over (slot_entropy, slot_index)   │ │
                  │  │  type1_sig ← C10.sign(master_sk, userOpHash)   │ │
                  │  │  type2_sig ← C10.sign(slot_sk,   userOpHash)   │ │
                  │  │  verify-before-release (FI guard, both sigs)   │ │
                  │  │  zeroize on lock/timeout/tamper/brownout       │ │
                  │  │                                                │ │
                  │  │  TRNG / HASH / SAES (DHUK) / TAMP / BOR        │ │
                  │  │  Inactivity timer (Secure-only TIM)            │ │
                  │  │  MCU PIN counter (page 124, FI-hardened)       │ │
                  │  └────────────────────────────────────────────────┘ │
                  └──────────────────────────────────────────────────┘
                                          ▲
                                          │  FSBL (HDPL1, immutable, WRP1A-locked)
                                          │  verifies firmware via SPHINCS+C10
                                          │  + SHA-256 — no classical fallback
                                          │  before any of your code runs
```

## Design Properties

This is the *target architecture* for the production wallet. Every bullet here is either implemented today (QEMU and/or real STM32U585), partially implemented, or planned for the production-hardening branch. See [Implementation Status](#implementation-status) for the per-item state.

- **Post-quantum transaction signatures, single primitive everywhere** — SPHINCS+C10 (hash-based, `h=18 d=2 a=11 k=13 w=8 l=43 target_sum=205 sig=4008`) for both Type 1 (bootstrap slot registration) and Type 2 (per-slot user tx). No FORS+C, no classical signer (secp256k1, P-256, Ed25519), no number-theoretic assumptions, no known quantum speedup beyond Grover. The on-chain contract has a single `c10Verifier` immutable wired to both dispatch paths. *(Implemented; on-chain bench `forge test -vv` covers both paths. Per-chain caps `MAX_BOOTSTRAP_USES = MAX_SLOT_USES = 65_536` are immutable in the contract.)*
- **Post-quantum firmware signing, single primitive end-to-end** — vendor signs a 75-byte preimage `"PQFW_V1" || fw_version_be || secure_hash || nonsecure_hash` with a SPHINCS+C10 vendor key; the immutable FSBL at `0x0C00_0000` verifies the same preimage against the compiled-in vendor pubkey and picks the higher-version valid A/B slot. Auditors can rebuild + re-verify any release from `(version, secure.elf, nonsecure.elf)` alone — no manifest parsing required (`fwsign verify-release`). Argon2id + XChaCha20-Poly1305 appear *only* in the at-rest vendor SK blob on the signing machine, never in what the device evaluates. *(Implemented: `fsbl/`, `fwsign/`, `fw-manifest/`. See [docs/firmware-update.md](docs/firmware-update.md) and [docs/reproducible-builds.md](docs/reproducible-builds.md).)*
- **Post-quantum confidentiality of all SE traffic (planned)** — both halves of the entropy will be **ML-KEM-1024-encapsulated + AES-256-GCM-sealed** *before* they ever touch the I²C bus, so the classical OPTIGA Shielded Connection (AES-128-CCM-8) and SE050 SCP03 (AES-CMAC + AES-CBC) layers carry only opaque PQ ciphertext. *(Inner-wrap layer not yet implemented — target for the production-hardening branch. Today the SE channels carry plaintext halves under their classical authenticated-encryption layer.)*
- **TrustZone isolation** — signing key, PIN state, secret-key derivation, and crypto ops confined to the secure world. The 12-command NSC gateway is the only crossing point, with NS pointer validation on every call and TOCTOU defense (NS buffers copied to secure stack before parsing). *(On real STM32U585 silicon the gateway runs through proper ARMv8-M CMSE `cmse-nonsecure-entry` veneers — exercised end-to-end under `make e2e-hw`. The QEMU mps2-an505 build uses a shared-memory mailbox + SysTick poll instead, as a workaround for a QEMU 8.2.2 MPC S-alias bug that breaks the SG instruction check.)*
- **Dual secure elements (split entropy)** — BIP-39 entropy is XOR-split across an Infineon OPTIGA Trust M V3 (`half_O`) and an NXP SE050 (`half_E`). Compromising either chip in isolation reveals **zero** bits of the seed. Reconstruction `E = HKDF(half_O XOR half_E)` happens only in S-SRAM during unlock, for microseconds, then zeroized. *(Implemented; both chips on I2C1 at addresses 0x30 (OPTIGA) and 0x48 (SE050). Validated end-to-end on real silicon.)*
- **Three-way PIN counter sync (MCU + OPTIGA + SE050)** — silicon-monotonic counters on all three: MCU page 124 (FI-hardened pre-commit; charges the attempt before the SE driver is touched, so a power glitch mid-verify cannot give a free retry), OPTIGA E120 Lifetime Usage Counter bound to F1D0's Execute access (Trezor-parity, immune to Platform Binding Secret extraction), and SE050 silicon UserID retry counter. `MAX_ATTEMPTS = 10` on any one of them dispatches `factory_reset_admin` + page-124 erase. `CMD_GET_REMAINING` returns the minimum of all three. *(Validated end-to-end on real silicon: `make pin-gate-hw-counter-e2e` and `make pin-gate-wipe-e2e`.)*
- **Three-tier DHUK + BHK + OTP key hierarchy** — Trezor-parity per-purpose subkey derivation. Tier 1 (DHUK, `SAES-CMAC(DHUK, label‖counter)`) is **landed** behind the `saes-dhuk` feature flag — `secret_keys::derive_into` flips on a single cfg gate from the dev `HKDF(OTP_master)` path to the production SAES-DHUK path with no caller change. RDP0 leaves DHUK as an ST-substituted constant shared across all bench boards (validated by cross-board `saes-self-test-hw` finding the identical 8-byte fingerprint at RDP0); per-die uniqueness only kicks in once a board is stepped to RDP ≥ 1. Tier 2 (BHK) and the OTP-salt-only repurpose are planned. *(Tier 1: implemented + validated. Tier 2: planned. See `docs/work-todo.md §7`.)*
- **Boot-time firmware self-test** — `hw::hash::init_clock()` runs `SHA-256("abc")` as a known-answer test and halts the CPU in `loop { wfe() }` on mismatch. `make saes-self-test-hw` runs the SAES driver's full software-key + DHUK round-trip self-test and prints an 8-byte DHUK fingerprint for cross-boot consistency. *(Implemented; production builds gate the self-test feature out of the binary.)*
- **Boot-time attestation of both chips** — fresh nonce signed by each SE's factory attestation key, verified against pinned vendor roots and pinned per-device UIDs. The classical SE attestation is treated as *proof of presence*; the cryptographic root of device identity will be a SPHINCS+C10 device certificate pinned at provisioning. *(Not yet implemented — target for the production-hardening branch.)*
- **Firmware measurement at boot** — SHA-256 of the secure-world flash image is computed at every boot and displayed as 8 BIP-39 words on the trusted OLED. A companion host tool (`fwmeasure`) computes the same words from a reproducible build of the open-source firmware. The user visually compares — no secrets, no attestation keys, fully trustless. *(Implemented. Run `make measure` on the host to get the expected words.)*
- **Mixed-RNG generation** — wallet entropy mixes `STM32_TRNG ⊕ OPTIGA_TRNG ⊕ SE050_TRNG`. All three are post-quantum (Grover offers no meaningful speedup against true randomness). *(Partially implemented — STM32 TRNG is wired; SE-side TRNG mixing is target.)*
- **PQ-safe symmetric crypto throughout** — AES-256-GCM, SHA-256, SHA-512, HMAC-SHA256, HKDF-SHA256, PBKDF2-HMAC-SHA512, AES-CMAC. Every key, MAC tag, and hash is sized so that Grover's algorithm leaves ≥ 128-bit effective security.
- **TAMP / consumption-mask / UI-capture hardening hooks** — STM32U585 TAMP driver (Trezor-port; log-only on the bring-up branch, production must flip to `trigger_lockout_wipe()`); TIM2 CH1 PWM consumption mask on PA5 (randomised duty cycle, defeats correlated power-side-channel observation); UI-fixture capture for screenshot-hash regression testing. All gated behind dedicated feature flags; CI must keep them out of production builds.
- **No heap** — `#![no_std]`, stack-only allocation, no allocator attack surface, no `Vec` / `Box` / `String`.
- **Hardened gateway** — NS pointer validation, TOCTOU defense, sensitive memory zeroization, custom panic handler that clears secrets before halting. The same `cmd_*::run` handlers are shared across both transports — only the entry point differs.
- **ZK clear signing** — for supported DeFi protocols (Aave V3 today), the wallet refuses to display a human-readable action string unless a Groth16 proof over BLS12-381 cryptographically certifies that the string is a faithful ABI interpretation of the raw calldata. The full VK pool lives in non-secure firmware rodata; the secure world only embeds a 32-byte Merkle root of the VK DB and re-verifies every supplied VK against that root before running Groth16, so neither the companion app nor a compromised non-secure world can substitute a malicious VK. *(Implemented in QEMU via `CMD_CLEAR_SIGN`; host-side `zk-test` crate verifies the Aave V3 supply proof in ~3.3 ms.)*
- **ERC20-aware trusted display** — for transactions whose recipient contract is in the firmware's pinned ERC20 DB, the trusted UI renders "Send 100.000000 USDC to 0xabc..." with symbol and decimals from a Merkle-verified metadata bundle. Unknown contracts fall through to a Ledger-style "⚠ BLIND SIGNING" warning. The ERC20 DB is in non-secure rodata (Merkle-anchored the same way as the VK DB), so adding tokens does not cost any secure flash. *(Implemented; `dbgen` crate builds the Merkle trees at build time.)*

## Prerequisites

- Rust nightly (see `rust-toolchain.toml`)
- `arm-none-eabi-ld` (ARM bare-metal linker)
- QEMU with `mps2-an505` machine support (`qemu-system-arm`)
- For real hardware: B-U585I-IOT02A discovery kit + Infineon OPTIGA Trust M V3 Shield (`TRUSTMV3SHIELDTOBO1`) + NXP OM-SE050ARD on Arduino R3 headers, driven via ST-LINK + `probe-rs`
- For Tropic01 standalone bring-up: a TROPIC01 TS1302 devkit (or MicroE Clicker on SPI1 via the `spi1-arduino` feature)

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
make run                # mock-SE smoke test in QEMU
make e2e                # automated end-to-end unified C10 sign in QEMU (mock SE)
make e2e-hw             # automated end-to-end on real STM32U585 (dual-SE) via probe-rs
make test-key-speed     # DWT-timed signing bench on real hardware
```

Expected real-hardware key-speed numbers under `hw-sha256` (auto-implied by `stm32u585`):

```
first-sign           ≈ 13 s        # master C10 keygen + slot C10 keygen + 2× C10 sign
type-2 cached slot   ≈ 1.1 s
2nd-chain first-sign ≈ 7.5 s       # master keygen + 2× sign, slot cache hit
```

Any number substantially higher than these means the HASH peripheral isn't being used.

## Project Structure

```
sphincs_rust/
+-- Cargo.toml                  # Workspace root
+-- Makefile                    # Build orchestration
+-- secure/                     # TrustZone SECURE world firmware
|   +-- src/
|   |   +-- main.rs              # Boot: SAU → RCC → SAES self-test → provision → unlock → boot NS
|   |   +-- crypto.rs            # BIP-39, C10 bootstrap derivation, C10 slot derivation, JARDÍN master entropy
|   |   +-- sau.rs               # SAU + GTZC configuration
|   |   +-- nsc/                 # NSC gateway: dispatcher, ptr_validate, gated_unlock, per-cmd handlers
|   |   |   +-- mod.rs           #   Dispatcher + gated_unlock (page-124 pre-commit + FI guard)
|   |   |   +-- cmd_sign_userop.rs       # The unified Type 1 / Type 2 all-C10 sign handler
|   |   |   +-- cmd_get_init_code.rs     # Pre-computed initCode for companion gas-estimation
|   |   |   +-- cmd_get_wallet_address.rs # CREATE2-predicted ERC-1967 proxy address
|   |   |   +-- cmd_request_unlock.rs    # PIN entry + dual-SE unlock through gated_unlock
|   |   |   +-- cmd_fw_*.rs              # Five firmware-update handlers
|   |   +-- aa/                  # ERC-4337 v0.6 UserOperation hashing + initCode construction
|   |   +-- tx/                  # EIP-1559 envelope parser + trusted-UI page renderers
|   |   +-- erc20/               # ERC20 dispatcher + bundle Merkle verifier
|   |   +-- zk/                  # Groth16 + Poseidon over BLS12-381 (no alloc)
|   |   +-- optiga/              # OPTIGA Trust M driver: IFX I2C, APDU, Shielded Connection, reset
|   |   +-- se050/               # SE050 driver: T1oI2C, APDU, SCP03
|   |   +-- dual_se.rs           # XOR entropy split across OPTIGA + SE050; admin-wipe orchestration
|   |   +-- tropic01_se.rs       # TROPIC01 standalone path (non-dual-SE)
|   |   +-- fw_update/           # Streaming firmware-update state machine
|   |   +-- measured_boot.rs     # Boot-time SHA-256 → 8 BIP-39 words on OLED
|   |   +-- ui/                  # OLED + button trusted-UI loop
|   |   +-- hw/                  # STM32U585 bare-metal peripheral drivers
|   |       +-- saes.rs          #   SAES driver (DHUK-keyed AES-256-ECB)
|   |       +-- saes_cmac.rs     #   SAES-CMAC adaptor for the DHUK KDF
|   |       +-- secret_keys.rs   #   Per-purpose subkey API (Tier 1 SAES-CMAC(DHUK), Tier 2 BHK planned)
|   |       +-- hash.rs          #   STM32U585 HASH peripheral driver (pqsigner_sha256_*)
|   |       +-- flash.rs         #   Bank-2 writes + page-124 PIN counter + page-125 admin
|   |       +-- otp.rs           #   OTP rollback counter + OTP master
|   |       +-- tamp.rs          #   Tamper-detection driver (Trezor port; log-only on bring-up)
|   |       +-- consumption_mask.rs # TIM2 CH1 PWM power-side-channel mask
|   |       +-- huk.rs           #   Per-die wrap key (HKDF over UID + OTP master)
|   |       +-- buttons.rs, rng.rs, rcc.rs, pka.rs, spi*.rs, i2c*.rs, uart.rs, usb_hw.rs
|   +-- memory.x                 # Linker script
+-- nonsecure/                   # TrustZone NON-SECURE world firmware
|   +-- src/
|   |   +-- main.rs              # NS entry (USB or interactive demo)
|   |   +-- nsc_api.rs           # NS-side gateway caller
|   |   +-- usb/                 # USB HID + APDU v2 command router
|   |   +-- e2e_test.rs          # Non-interactive e2e runner (make e2e)
|   |   +-- erc20_db.bin / .rs   # ERC20 DB (generated by dbgen)
|   |   +-- vk_db.bin / .rs      # ZK VK DB (generated by dbgen)
+-- shared/                      # Cross-world types: NscStatus, CMD constants, wire-format sizes
+-- sphincs-c10/                 # SPHINCS+C10 signing library (no_std, SHA-256)
+-- bip39/                       # 24-word English BIP-39 (no_std)
+-- bls12_381_pka/               # BLS12-381 fork with `pka` feature for STM32U585
+-- contracts/smart-wallet/      # Foundry project for the on-chain ERC-4337 v0.6 wallet
|   +-- src/PQSmartWallet.sol            # Implementation behind ERC-1967 proxy
|   +-- src/PQSmartWalletFactory.sol     # CREATE2 ERC-1967 proxy factory + squat-defence
|   +-- src/PQMultiOwnable.sol           # ERC-7201 storage helper (ownerAtIndex + counters)
|   +-- src/verifiers/SPHINCsC10Asm.sol  # Stateless Yul C10 verifier
+-- fsbl/                        # Immutable first-stage bootloader (PQ A/B selector)
+-- fwsign/                      # Host-side release signer + verifier
+-- fwmeasure/                   # Host-side firmware-measurement tool
+-- fw-manifest/                 # no_std manifest format + verify chain
+-- dbgen/                       # Host-side ERC20/VK DB + Merkle tree builder
+-- zk-test/                     # Host-side E2E test for the ZK verifier
+-- circuits/                    # In-tree Circom circuits + VK build pipeline
+-- tools/                       # webhid_test.html, wallet_run_hw.py, ui_fixture.py, …
+-- docs/                        # architecture.md, HARDENING.md, work-todo.md, trezor-comparison.md, …
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
| Firmware measurement / signed updates | `docs/firmware-update.md`, `docs/reproducible-builds.md`, README §"Firmware Update Model" |
| USB protocol on the wire | `docs/usb-protocol-v2.md`, `docs/usb-hid-setup.md` |
| OLED mirror / dev tooling | `docs/oled-mirror.md` |

### Per-domain quick map (which doc covers each concern)

The four "live" planning docs split responsibilities like this — if it's
not in the doc you opened, check the right one:

| Concern | Lives in |
|---|---|
| BOR / PVD / IWDG / SRAM-ECC / TAMP / CSS / supercap on VBAT | `brownout-hardening.md` |
| Wipe-in-progress flag + crash-safe factory-reset | `brownout-hardening.md` (mechanism) + `se050-factory-reset.md` (SE050-side) |
| SPHINCS+C10 double-compute + verify-before-release + PIN fail-in | `production-security.md` §2.1 + `work-todo.md` #18 |
| SCP03 key rotation + HUK-SAES wrapping + binding record | `production-security.md` §2.2 + `work-todo.md` #20 |
| SPHINCS+C10 side-channel mitigations (rate limit, shuffling, SHA-256-only decision) | `production-security.md` §2.3 + `work-todo.md` #18 |
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
| `optiga-trust-m` | Real OPTIGA Trust M V3 via I2C1 + IFX I2C + Shielded Connection (TRUSTMV3SHIELDTOBO1 on Arduino R3 headers) |
| `optiga-hw-counter` | Silicon-enforced OPTIGA PIN counter via E120 LUC bound to F1D0 Execute (Trezor-parity, immune to PBS extraction). **Destructive on first provisioning.** |
| `se050` | Real SE050 via I2C1 + SCP03 (OM-SE050ARD on Arduino R3 headers) |
| `dual-se` | Both production SEs active with XOR entropy split (implies `optiga-trust-m` + `se050`) |
| `tropic01-se` | Real TROPIC01 chip via SPI — *standalone-only*, not used in dual-SE |
| `spi1-arduino` | Use SPI1/PE12-PE15 (Arduino R3 headers) instead of default SPI2/PB12-PB15 for TROPIC01 |
| `saes-dhuk` | Re-root `secret_keys::derive_into` on `SAES-CMAC(DHUK, label‖counter)`. RDP0 leaves DHUK as an ST-substituted constant; per-die uniqueness only at RDP ≥ 1. |
| `saes-self-test` | Boot self-test of the SAES driver — software-key + DHUK round-trips + 8-byte fingerprint print + SYS_EXIT |
| `otp-hardcoded-master-key` | Dev-only: replace the per-die TRNG OTP-burn with a fixed ASCII constant so re-flashed bench boards keep the same admin UserID / SCP03 / PBS bytes |
| `tamp` | STM32U585 TAMP (tamper detection). Trezor-port; log-only on this branch (production must flip to `trigger_lockout_wipe()`) |
| `consumption-mask` | Power-side-channel mask via TIM2 CH1 PWM on PA5 (randomised duty cycle) |
| `ui-capture` | UI regression-test harness — emits SHA-256 fingerprint of every displayed frame (implies `debug-log`) |
| `usb` | Enable USB OTG hardware init for host communication |
| `pka-accel` | Route BLS12-381 Fp arithmetic through the STM32U585 PKA |
| `stm32u585` | Real STM32U585 hardware target (vs QEMU mps2-an505). **Implies `hw-sha256`** |
| `hw-sha256` | Route `sphincs-c10` SHA-256 calls through the HASH peripheral. Pulled in transitively by `stm32u585`. |
| `ui-semihosting` | Console UI (QEMU; `SYS_READC` only works under QEMU, not probe-rs) |
| `ui-oled` | SSD1306 I2C OLED (hardware) |
| `ui-noop` | Silent no-op UI for standalone USB operation |
| `debug-log` | Enable semihosting debug output (remove for production) |
| `e2e-test` | Non-interactive scripted test mode — **never ship in production** |

Build a dual-SE production-target firmware:
```bash
make FEATURES="dual-se,stm32u585,ui-oled,saes-dhuk,usb" all
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

Every primitive that touches a secret is listed below with its post-quantum status. Anything marked **classical** is either a planned migration target, a residual SE-vendor surface that we wrap with PQ confidentiality (planned), or a non-seed-reaching surface (display-only).

| Where | Primitive | Key / output size | PQ status | Notes |
|---|---|---|---|---|
| **Transaction signing (Type 1 + Type 2)** | SPHINCS+C10 (W+C_F+C, h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205) | sig 4 008 B, pk 32 B | ✅ PQ | Hash-based, no number-theoretic assumptions. Same primitive for bootstrap *and* per-slot signing. Frozen as part of the recovery contract. Verifier `SPHINCsC10Asm.sol` runs in the EVM via the SHA-256 precompile |
| **Firmware signing** | SPHINCS+C10 (same parameters as above) | sig 4 008 B, pk 32 B | ✅ PQ | Vendor signs the 75-byte preimage `"PQFW_V1"‖fw_version_be‖secure_hash‖nonsecure_hash`; FSBL verifies against compiled-in vendor pubkey. **No classical fallback** — single PQ algorithm in the verification path |
| **Inner PQ wrap (both halves) — planned** | ML-KEM-1024 (Kyber, FIPS 203) | ct 1568 B, pk 1568 B, sk 3168 B | ✅ PQ | Encapsulates a 32-byte AES-256-GCM key per stored half. The PQ secret key will live HUK-SAES-wrapped in U585 secure flash. *Not yet implemented — target for the production-hardening branch* |
| **Inner wrap AEAD — planned** | AES-256-GCM | key 32 B, tag 16 B | ✅ PQ | Grover halves to 2^128, still well above the 2^80 brute-force barrier |
| **OPTIGA Trust M wire channel (outer)** | Shielded Connection: TLS-PRF + AES-128-CCM-8, root: Platform Binding Secret in U585 secure flash | tag 8 B | ⚠️ mixed | Symmetric cipher is PQ-safe; key derivation is HMAC-SHA-256 / TLS-PRF. Once the ML-KEM inner wrap lands, this layer carries only opaque PQ ciphertext |
| **OPTIGA Trust M PIN gate** | Authorization reference (OID `0xF1D0`) + E120 Lifetime Usage Counter (silicon-monotonic) | — | ✅ PQ | E120 LUC binding is Trezor-parity; immune to PBS extraction (the legacy soft `F1E1` counter was not). Hardware-cleared by `Change=Auto(F1D0)` over a transient-auth session on every successful PIN |
| **SE050 wire channel (outer)** | SCP03 (AES-CMAC + AES-CBC) | k 16 / 32 B | ⚠️ mixed | SCP03 symmetric cipher is PQ-safe. Once the ML-KEM inner wrap lands, this layer also carries only opaque PQ ciphertext |
| **SE050 PIN gate** | UserID auth (silicon constant-time comparison; max 10 attempts) | — | ✅ PQ | Hardware-enforced retry counter; surfaces only via `SW=0x63Cx` after wrong PIN |
| **SE050 admin-UserID derivation** | `HKDF-Expand(OTP_master, "pqsigner/se050-admin-pin-v1")` (dev) → `SAES-CMAC(DHUK, …)` (production via Tier 1) | 16 B | ✅ PQ | Replaces page-125-stored random PIN; survives flash erase, so cross-test contamination cannot brick a chip |
| **MCU PIN-attempt counter** | Page-124 quad-word programs; `pin_attempts_{read,bump,reset}` | 32-attempt capacity, 10-attempt cap | ✅ PQ | FI-hardened pre-commit in `nsc::gated_unlock`: bump the MCU counter *before* calling the SE driver, with post-bump readback that must show count advanced by exactly 1, else `InternalError` |
| **SE chip attestation (factory)** | ECDSA over a vendor curve | — | ❌ classical | Treated as proof of presence; cryptographic root of device identity will be a SPHINCS+C10 device certificate (planned) |
| **Tier 1 root key** | STM32U585 silicon DHUK, used only via the SAES peripheral's `KEYSEL=001` selector. KDF is `SAES-CMAC(DHUK, label‖counter)` (simplified SP 800-108 counter mode). | 16 B per output block | ✅ PQ | DHUK bytes never appear in CPU-visible memory. At RDP0 the DHUK is an ST-substituted constant shared across boards (validated by cross-board fingerprint match); per-die uniqueness only at RDP ≥ 1 |
| **Tier 2 root key (planned)** | BHK — TRNG-burnt at first boot, DHUK-wrapped at rest, loaded into TAMP backup registers + `SECCFGR` locked at boot | 32 B | ✅ PQ | Defense-in-depth on top of DHUK. Planned to host SE050 SCP03 + Tropic01 pairing; OPTIGA PBS stays under DHUK |
| **Tier 3 root key** | OTP-master 32-byte TRNG burn at first boot (`0x0BFA_0080..0x0BFA_00A0`) | 32 B | ✅ PQ | Today: dev fallback for the per-purpose KDF. Post-Tier-2: repurposed to PBKDF2 salt for any future MCU-side PIN-gated wrap |
| **Auth-key derivation (per SE)** | `hw::secret_keys` API (`optiga_pairing_secret`, `se050_scp03_*`, `se050_admin_pin`, `tropic01_pairing_key`) | 16 / 32 / 64 B | ✅ PQ | Stable caller API across all three tiers; underlying KDF flips between Tier 1 / Tier 3 on a single feature flag |
| **BIP-39 → C10 master expansion** | PBKDF2-HMAC-SHA512 (2048 iters) → `HMAC-SHA512("sphincs-c6-v1", bip39_seed)` (account 0) or `…("sphincs-c6-v1-acct", bip39_seed‖account_index_be)` (accounts 1..=255) | 64 B | ✅ PQ | The `"sphincs-c6-v1"` tag is historical (carried through the all-C10 cutover). Account 0 reproduces the legacy single-account derivation byte-for-byte; accounts 1..=255 use the `-acct` variants |
| **JARDÍN slot derivation** | `slot_entropy = sha256(master‖"jardin_slot"‖slot_index_be)`; `slot_sk_seed = sha256("jardin_slot_c10_sk_seed"‖slot_entropy)`; `slot_pk_seed = sha256("jardin_slot_c10_pk_seed"‖slot_entropy) & N_MASK` | 32 B sk, 16 B pk | ✅ PQ | Stateless within the C10 tree's 2^18 capacity. Cached in SRAM across the unlock session only |
| **Anti-rollback monotonic counter** | OTP fuses (1024 bits = 1024 commits, RDP-regression-resistant) | — | ✅ PQ | Survives RDP regression; one-way by design (no reset path) |
| **TRNG entropy mixing** | STM32 TRNG today; planned mixing with OPTIGA + SE050 TRNG | 32 B | ✅ PQ | Quantum mechanics offers nothing against true randomness |
| **Recovery encoding** | BIP-39 24 words ↔ 256-bit entropy | 32 B | ✅ PQ | 256 bits ≥ 128-bit PQ security |
| **ZK clear-sign verifier** | Groth16 over BLS12-381 (4 pairings, no alloc) | proof 384 B, vk 960 B | ❌ classical | Display-only — gates *what gets shown before signing*, never reaches the seed. CRQC break would let an attacker forge a proof for a misleading display string, but cannot leak the seed |
| **ZK public-signal binding** | Poseidon over BLS12-381 scalar field (alpha=5, Hades) | digest 32 B | ❌ classical | Same threat model as the verifier |
| **ZK VK authentication** | SHA-256 Merkle tree over pinned `(chain_id, contract, vk)` leaves; 32-byte root in secure flash | root 32 B | ✅ PQ | Trust anchor is the firmware-signing key itself: release reviewer diffs `secure/data/vks.review.txt` against the previous release. Fully offline — no on-chain governance lookups |
| **ERC20 metadata authentication** | SHA-256 Merkle tree over pinned `(chain_id, contract, name, symbol, decimals)` leaves; 32-byte root in secure flash | root 32 B | ✅ PQ | Same Merkle anchor as the VK DB |

**Choices we plan to freeze at launch** (changing any of these means the same 24 words produce a different keypair / a different on-chain wallet address; today, with no shipped devices and no funded wallets, that's a re-provisioning cost on bench boards rather than a user-impacting hard fork):

| Parameter | Value | Why |
|---|---|---|
| Signing parameter set | SPHINCS+C10 (W+C_F+C, h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205) | 4008-byte sig fits a comfortable SRAM budget; 2^18 hypertree positions per key, capped on-chain at 65 536 to stay deep in the birthday-style safety margin |
| BIP-39 → C10 master expansion | `HMAC-SHA512("sphincs-c6-v1", bip39_seed)` (account 0) / `HMAC-SHA512("sphincs-c6-v1-acct", bip39_seed‖account_index_be)` (accounts 1..=255) | "C6" is historical — the underlying scheme is C10 today; the tag was written when we were on a different parameter set. Pre-production, this CAN still be cleaned up before launch (no shipped users to break); we just don't want silent drift inside an unrelated PR. |
| Master pubkey shape | `masterPkSeed = sha256("pk_seed"‖master[..32]) & N_MASK` (top 16 B kept, bottom 16 B zero), `masterSkSeed = sha256("sk_seed"‖master[..32])` | The N_MASK shape matches the on-chain `bytes32` packing |
| CREATE2 salt | `sha256(masterPkSeed ‖ masterPkRoot)` | Defines the on-chain wallet address; same on every chain *for a given* `account_index` |
| Slot tags | `"jardin_slot"`, `"jardin_r"`, `"jardin_slot_c10_sk_seed"`, `"jardin_slot_c10_pk_seed"`, `"pqwallet-jardin-master"` (acct 0) / `"pqwallet-jardin-master-acct"` (accts 1..=255) | All carried through the all-C10 cutover; the JARDÍN domain tags are KDF labels only — the underlying signing scheme is C10 |

## Quantum Threat Model

This section names exactly which quantum threats we defend against and which ones we honestly cannot.

### The dominant threat: Harvest Now, Decrypt Later (HNDL)

An adversary records every byte of I²C traffic between U585, OPTIGA Trust M, and SE050 today, archives it for 10–20 years, and decrypts it once a cryptographically-relevant quantum computer (CRQC) exists. For a hardware wallet that holds long-term funds, **this is the dominant quantum threat** — the adversary doesn't need to be near the device when they decrypt, only when the device was used.

**How this design defeats HNDL (target — once the planned ML-KEM inner wrap lands):**

1. The classical Shielded Connection / SCP03 layer will carry only **ML-KEM-1024-encapsulated AES-256-GCM ciphertext**, never plaintext halves. When a CRQC breaks the AES-128-CCM-8 / SCP03 outer key derivation and decrypts the captured outer layer, the result is still an opaque ML-KEM ciphertext.
2. Decapsulating that requires the ML-KEM-1024 secret key, which will live only inside a HUK-SAES-wrapped blob in U585 secure flash. Recovering it requires physical extraction of the *specific* U585 die, plus a working attack on STM32U5 RDP-2, plus extraction of the per-die HUK from the SAES peripheral.
3. Even granted all of that, the attacker has only one half. The other half is on the *other* SE, encrypted under a *different* ML-KEM ciphertext, gated by the *other* SE's PIN-bound retry counter, which destroys the chip's auth gate after 10 wrong PIN attempts.

In short, post-inner-wrap: HNDL recovers ML-KEM ciphertext, not seeds. **Until then, the SE channels carry plaintext halves under the classical SE-vendor authenticated-encryption layers** — see the "currently classical" entries in the table above.

### The residual classical surface

We are honest about what we cannot make PQ:

| Residual surface | What it lets a CRQC attacker do | Why we accept it |
|---|---|---|
| **OPTIGA Shielded Connection key derivation (TLS-PRF, HMAC-SHA-256)** | Symmetric KDF — Grover halves the work but stays well above brute-force; no asymmetric authentication leg today (the PBS root is symmetric) | Symmetric-only KDF; the worst case is Grover-accelerated brute force of the PBS, which still leaves > 128-bit PQ security |
| **SE050 secure-channel authentication** (SCP03 with classical static-key auth, or FastSCP/ECDH if we ever switch) | After breaking ECDH (FastSCP only), an active attacker with physical I²C access could MITM the SE050 channel | MITM requires *real-time* physical bus tampering on a powered device. The planned PQ inner-wrap means even a successful MITM of the outer channel cannot read the half. The attacker can at best deny service |
| **SE factory attestation chains (both ECDSA)** | A CRQC attacker with the manufacturer's silicon could mint a forged attestation that survives boot-time verification | We treat factory attestation as proof of presence only. The cryptographic identity of the device will be a SPHINCS+C10 device certificate pinned at provisioning |
| **OPTIGA / SE050 internal firmware** uses classical primitives we cannot inspect or replace | A CRQC class-break of OPTIGA or SE050 could expose the contents of one chip's storage | The other chip still holds the other half. Single-chip compromise reveals zero bits of the seed |
| **U585 RDP-2 + HUK-SAES** depends on the security of an AES-256 wrap and STM32 hardware countermeasures, which are not formally PQ-certified | A CRQC + invasive die work could in theory recover the HUK and unwrap the ML-KEM secret key (post-inner-wrap) | This is the irreducible "physically extract the specific U585 die" attack. Tamper mesh, BOR-fired wipe, and the inactivity timer are the mitigations. Same threat as today minus the quantum part |

### What we explicitly do *not* defend against

- **Coerced unlock.** No PIN-gated wallet survives the user being forced to enter the PIN. PQ does not change this.
- **Active CRQC adversary with sustained physical access to a powered, unlocked device.** Same answer as today: the irreducible attack window is the active session in S-SRAM.
- **A future cryptanalytic break of SPHINCS+ / SHA-256.** Hash-based signatures depend on collision/preimage resistance of the underlying hash; a fundamental break of SHA-256 is the same kind of civilization-scale event that would break the wider PKI. The chosen parameter set leaves a comfortable margin; if a class break appears, the recovery path is a firmware update to a hash-based scheme using SHA-3 / SHAKE.
- **A future cryptanalytic break of ML-KEM (planned inner wrap).** ML-KEM is *only* used for confidentiality of stored halves; the seed itself never depends on lattice hardness. If lattices fall, ship a firmware update that swaps ML-KEM for a hash-based KEM (e.g. classic McEliece or HQC). The wallet's signing key — and therefore the funds — are never at risk because the transaction-signing key never depended on lattices.
- **Side-channel and fault attacks against the U585 silicon.** PQ is orthogonal. Mitigated by the TAMP / consumption-mask / verify-before-release / FI-hardened `gated_unlock` measures, plus the production hardening in `docs/HARDENING.md`.

### Why hash-based signatures for the actual money

Lattice schemes (ML-DSA, ML-KEM) rely on the hardness of LWE / Module-LWE. These are believed to resist quantum attacks, but the security reduction is much less mature than the half-century of cryptanalysis behind hash functions. **For the wallet's signing key — the thing that authorises moving funds — and for firmware signing, we use SPHINCS+C10, whose only assumption is the security of SHA-256.** If a lattice break ever appears, your transaction signatures and the firmware-update verification are both unaffected; only the planned ML-KEM inner-wrap layer would need to migrate.

## Security Model

| Layer | Protection |
|-------|------------|
| **Seed at rest (OPTIGA half)** | `half_O` lives in OPTIGA Trust M object `0xF1D1` (32 B), with policy `Read = Auto(0xF1D0) + Conf(0xE140)` — readable only after an Auth-Reference HMAC-SHA-256 challenge against the PIN-derived `0xF1D0` *and* through a Shielded Connection (AES-128-CCM-8) confidentiality layer. Once the planned ML-KEM inner wrap lands, the byte payload becomes opaque PQ ciphertext at rest |
| **Seed at rest (SE050 half)** | `half_E = E ⊕ half_O` lives in an SE050 binary object whose `ALLOW_READ` policy is bound to a UserID auth object opened only inside an SCP03 session. The admin-UserID PIN is now derived from the OTP master via `hw::secret_keys::se050_admin_pin()` (replacing a flash-stored random PIN) so a partial flash erase no longer bricks the chip |
| **PQ inner-wrap secret key (planned)** | ML-KEM-1024 secret key (3168 B) will live in U585 secure flash, HUK-SAES-wrapped. Never decapsulates unless an unlock is in progress |
| **Seed reconstruction** | `E = HKDF(half_O ⊕ half_E)` happens *only* in U585 secure SRAM, for microseconds, then zeroized. The mnemonic, BIP-39 seed, master, and slot C10 keys are recomputed on demand and dropped on lock / idle / panic |
| **Key transport (OPTIGA, outer)** | OPTIGA Trust M Shielded Connection: TLS-PRF + AES-128-CCM-8, root-of-trust is the Platform Binding Secret stored in U585 secure flash page 126. The PBS is derived per-device from `hw::secret_keys::optiga_pairing_secret()` — Tier 1 SAES-CMAC(DHUK) under `saes-dhuk`, dev fallback `HKDF(OTP_master)` otherwise |
| **Key transport (SE050, outer)** | SCP03 (AES-CMAC + AES-CBC), static keys derived per-device via `hw::secret_keys::se050_scp03_{enc,mac}_key()`. A flash dump moved to a different U585 is useless once Tier 1 (DHUK at RDP ≥ 1) is the active root |
| **PIN handling** | Raw PIN never leaves S-world. The trusted UI runs entirely in S-world; NS never sees a digit, a cursor position, or a confirm decision. The SE auth challenges are derived from the PIN via `hw::secret_keys` so neither chip stores the PIN in plaintext |
| **Retry counters** | Three-way lockstep: MCU page 124 (FI-hardened pre-commit in `gated_unlock`), OPTIGA E120 LUC bound to F1D0 Execute (silicon-monotonic, immune to PBS extraction), SE050 silicon UserID. `MAX_ATTEMPTS = 10` on any one of them dispatches `factory_reset_admin` + page-124 erase. Validated end-to-end: `make pin-gate-hw-counter-e2e`, `make pin-gate-wipe-e2e` |
| **Boot attestation** | Fresh U585-TRNG nonce signed by each SE's factory attestation key, verified against pinned vendor roots and pinned per-device UIDs. Any failure ⇒ no PIN entry. *(Planned — not yet wired.)* |
| **Boot SHA-256 self-test** | `hw::hash::init_clock` runs `SHA-256("abc")` as a known-answer test and halts the CPU on mismatch. Always logs `PASS`/`FAIL — HALT` early in boot |
| **Boot SAES self-test** | `make saes-self-test-hw` runs the SAES driver's full software-key + DHUK round-trip self-test plus an 8-byte DHUK fingerprint print for cross-boot consistency checks. Production builds gate the self-test feature out of the binary |
| **TAMP** | STM32U585 TAMP driver (Trezor-port, log-only on the bring-up branch) monitors backup-domain voltage (ITAMP1), LSE clock security (ITAMP3), JTAG/SWD when RDP > 0 (ITAMP6), crypto peripheral fault (ITAMP9), IWDG-with-tamper (ITAMP11). Production must flip the IRQ from log-only to `trigger_lockout_wipe()` |
| **Power-side-channel mask** | TIM2 CH1 PWM on PA5 with randomised duty cycle (`hw::consumption_mask::randomize()`); the mask-pin power draw is uncorrelated with the crypto work happening elsewhere on the die |
| **Memory isolation** | TrustZone (SAU + IDAU + MPC + GTZC), DMA mastering into secure SRAM blocked, NS pointer validation on every gateway call, TOCTOU defense via NS buffers copied to S stack before parsing, no panics across NSC |
| **Inactivity / power loss** | Secure-only TIM enforces a 2-minute idle wipe. TAMP and BOR fire the same wipe ISR. Bulk cap sized so the ISR completes under brownout |
| **Crash safety** | Custom panic handler zeroizes secrets and resets before halting; idempotent `wipe-for-wizard` recovery path for dev provisioning iteration |
| **Build hardening** | LTO, overflow checks, debug info stripped (production), git deps pinned to a 40-char rev hash, `make verify-pins` hard-fails on `branch=`/`tag=` deps, `cargo audit` + `cargo deny` in CI |
| **Production** | RDP Level 2 burned as the final provisioning step (irreversible). Both SE auth-object policies frozen in the same provisioning session. WRP1A locks pages 0–3 (FSBL) before RDP-2 burn |

### Boot → Unlock → Sign → Lock lifecycle

Every step below runs in the **secure world**. The non-secure world drives nothing more sensitive than "show this string" and "user pressed a button"; the gateway is an opaque request channel and never sees a secret, a PIN digit, or a confirm decision.

```
   POWER ON
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ 1. SECURE BOOT                                               │
│    • FSBL (HDPL1, immutable) verifies SPHINCS+C10 signature  │
│      of the secure + non-secure images before any of your    │
│      code runs                                               │
│    • Configure SAU / IDAU / MPC / GTZC                       │
│    • Mark OLED bus, button GPIOs, both SE buses, TRNG, HASH, │
│      SAES, TAMP, BKPSRAM as Secure-only                      │
│    • SHA-256 self-test (KAT on "abc"); halt on FAIL          │
│    • SAES self-test under saes-self-test feature             │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ 2. DUAL-CHIP PRESENCE / ATTESTATION  (planned)               │
│    nonce ← STM32_TRNG                                        │
│                                                              │
│    ── OPTIGA Trust M ─────────────────                       │
│       open Shielded Connection with derived PBS              │
│       request cert chain → verify pinned Infineon root       │
│       verify pinned UID                                      │
│                                                              │
│    ── SE050 ──────────────────────                           │
│       open SCP03 session with derived static keys            │
│       request attestation signature over nonce               │
│       verify chain against pinned NXP root, pinned UID       │
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
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ 4. gated_unlock — FI-HARDENED PRE-COMMIT + DUAL-SE UNLOCK    │
│    pre := pin_attempts_read()                                │
│    pin_attempts_bump()              // one QW programmed     │
│    if pin_attempts_read() != pre + 1: return InternalError   │
│       (FI guard — refuses to call SE driver on glitch)       │
│                                                              │
│    pbs    = secret_keys::optiga_pairing_secret()             │
│    se_enc = secret_keys::se050_scp03_enc_key()               │
│    se_mac = secret_keys::se050_scp03_mac_key()               │
│    admin  = secret_keys::se050_admin_pin()                   │
│         (Tier 1: SAES-CMAC(DHUK,…); Tier 3: HKDF(OTP,…))     │
│                                                              │
│    ── OPTIGA Trust M ────────────────                        │
│    open Shielded Connection (TLS-PRF + AES-128-CCM-8, PBS)   │
│    PIN AuthRef on F1D0 (silicon-gated by E120 LUC)           │
│    half_O = read F1D1 over Shielded Connection               │
│                                                              │
│    ── SE050 ─────────────────────────                        │
│    open SCP03 session (AES-CMAC + AES-CBC, derived keys)     │
│    UserID auth (silicon-gated; max 10 attempts)              │
│    half_E = read binary over SCP03                           │
│                                                              │
│    On correct PIN:                                           │
│      • OPTIGA E120 reset to (0, limit) via Trezor transient- │
│        auth pattern                                          │
│      • SE050 UserID counter cleared by silicon               │
│      • MCU page 124 erased                                   │
│    On 10th wrong PIN on ANY counter:                         │
│      • factory_reset_admin (both SEs admin-wipe)             │
│      • page-124 erase, page-125 wipe-flag set                │
│      • cold boot enters first-boot wizard                    │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ 5. RECONSTRUCT IN SECURE SRAM ONLY                           │
│    E          = HKDF(half_O ⊕ half_E)                        │
│    zeroize(half_O) ; zeroize(half_E)                         │
│    mnemonic   ← BIP-39(E)                                    │
│    bip39_seed ← PBKDF2-HMAC-SHA512(mnemonic, "", 2048)       │
│    master     = HMAC-SHA512("sphincs-c6-v1", bip39_seed)     │
│      [accounts ≥ 1: …-acct‖account_index_be]                 │
│    masterPkSeed = sha256("pk_seed"‖master[..32]) & N_MASK    │
│    masterSkSeed = sha256("sk_seed"‖master[..32])             │
│    master_sk    = sphincs_c10::SigningKey::keygen(...)       │
│    jardin_master_entropy = sha256("pqwallet-jardin-master"   │
│                                   ‖ bip39_seed)              │
│                                                              │
│    Cached for the active window:                             │
│      { E, master_sk, master_pk, jardin_master, slot cache }  │
│    Slot keys are derived deterministically per-call from     │
│    (jardin_master, slot_index) and cached in SRAM only.      │
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
│    For each CMD_SIGN_USEROP from NS:                         │
│      a. NS posts (chain_id, slot_index, flags, AA header,   │
│         inner EIP-1559 envelope) via gateway                 │
│      b. S-world parses tx, draws decoded fields on the      │
│         secure OLED (chain, to, value, gas, nonce)           │
│      c. (re)keygen slot C10 if not cached on slot_index     │
│      d. User presses CONFIRM (long-press both buttons) on    │
│         the secure buttons — input goes straight to S-ISR   │
│      e. C10.sign(master_sk, type1_hash) if FLAG_REGISTER     │
│         C10.sign(slot_sk,   type2_hash)                      │
│      f. S-world VERIFIES each signature before releasing it  │
│         (fault-injection guard — refuse + wipe on mismatch) │
│      g. emits [type1_len|t1|type2_len|t2] bundle to NS       │
│      h. inactivity timer reset                              │
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
│      zeroize { E, master_sk, master_pk, slot cache,          │
│                jardin_master, any stack region used by sign }│
│      clear caches, clear CPU registers                       │
│      loop-twice + verify (defensive against single-fault)    │
│      return to "Locked" screen → next sign needs PIN again   │
└──────────────────────────────────────────────────────────────┘
```

**The invariants the dual-SE design hangs on:**

1. **Trusted path is contiguous from button → S-ISR → OLED → S-world.** GTZC must mark the OLED bus, the two button GPIO pins, *both* SE buses, TRNG, HASH, SAES, PKA, and TAMP as Secure-only. If NS can drive the OLED, it can spoof "send 0.01 ETH to alice" while you're signing "send 100 ETH to attacker".
2. **The PIN buffer never crosses the NSC boundary in either direction.** PIN entry happens in S-world; the gateway doesn't have an `enter_pin(bytes)` call — it has `request_unlock()` which kicks the S-world UI loop and returns only success/failure.
3. **Activity is defined by the S-world, never the NS world.** A compromised NS image cannot keep the seed alive by spamming pings. Only physical user input on a real S-world dialog counts.
4. **PIN counter sync is three-way.** MCU page 124 (FI-hardened pre-commit) + OPTIGA E120 LUC + SE050 silicon UserID. `MAX_ATTEMPTS = 10` on any one of them dispatches `factory_reset_admin` + page-124 erase. Boot reconciliation accepts the strictest of the three.
5. **Firmware is stateless with respect to slot selection.** No `next_q`-in-flash, no per-signature flash writes. The companion supplies `(chain_id, slot_index, flags)` on every sign call; slot keys are deterministically re-derived from `(jardin_master_entropy, slot_index)` and cached in SRAM across the unlock session only. SPHINCS+C10 is stateless within its 2^18 tree capacity, so flash state would be a regression.

### Why two secure elements?

A single secure element is a single point of trust. Whether the failure mode is a vendor-specific firmware bug, a published power-analysis attack, or invasive die work, *one* die compromise should not be enough to extract a wallet seed. The production target picks **Infineon OPTIGA Trust M V3** (Common Criteria EAL6+ AVA_VAN.5, Shielded Connection root of trust) and **NXP EdgeLock SE050** (CC EAL6+ AVA_VAN.5, SCP03 + UserID auth) so a vendor-level break of either has to overlap with a vendor-level break of the other to recover the seed.

| Attack | Single-SE wallet | Dual-SE (this design) |
|---|---|---|
| Class-break on one vendor's firmware | seed exposed | other half still secret — zero bits leaked |
| Invasive die attack on one chip | seed exposed | other half still secret |
| Backdoored RNG in one chip | biased entropy | XOR with the other SE's TRNG + STM32 TRNG preserves uniformity |
| Stolen powered-off device | bounded by one retry counter | bounded by **three** counters (MCU + OPTIGA E120 + SE050 UserID); any single counter hitting MAX_ATTEMPTS triggers full admin-wipe of both SEs |
| U585 NS world compromise | no impact | no impact |
| U585 secure SRAM compromise during active unlock | full break | full break (irreducible window — minimised by 120 s inactivity timeout + TAMP/BOR wipe ISR) |

The cost is one extra I²C peripheral, ~$3 BOM, and ~50 ms added unlock latency.

See [docs/architecture.md](docs/architecture.md) for the technical design, [docs/HARDENING.md](docs/HARDENING.md) for the consolidated hardening requirements, and [docs/m4-cowswap-eip712.md](docs/m4-cowswap-eip712.md) for the CowSwap EIP-712 order clear-signing handoff (deferred M4 milestone — read this before attempting that work).

## Implementation Status

**Legend**

- 🟢 **QEMU-tested** — runs and is exercised end-to-end on QEMU mps2-an505
- 🟢 **HW-tested** — runs and is exercised end-to-end on a real STM32U585 devkit via ST-LINK + probe-rs (e.g. `make e2e-hw`, `make pin-gate-hw-counter-e2e`, `make pin-gate-wipe-e2e`, `make optiga-hw-counter-e2e`, `make saes-self-test-hw`)
- 🔵 **Code exists, untested or partial** — written but not exercised end-to-end
- ⏳ **Not started** — target architecture, not yet written
- 🚫 **Blocked on hardware / lab access** — cannot be validated until a real PCB exists, or a board has been stepped to RDP-2 / a side-channel lab is engaged

> STM32U585 bring-up is happening on a B-U585I-IOT02A devkit driven via ST-LINK + probe-rs, with an Infineon OPTIGA Trust M V3 Shield (TRUSTMV3SHIELDTOBO1) and an NXP OM-SE050ARD on the Arduino R3 headers. Rows tagged 🟢 HW-tested run end-to-end under `make e2e-hw`, `make pin-gate-hw-counter-e2e`, `make pin-gate-wipe-e2e`, `make optiga-hw-counter-e2e`, or `make saes-self-test-hw` on real silicon. Rows that are 🟢 QEMU-tested describe behaviour exercised under QEMU mps2-an505 — assume it is untested on real hardware until proven otherwise.

| Component | Status | Where it runs today |
|---|---|---|
| TrustZone partitioning (SAU + IDAU + MPC/GTZC) | 🟢 QEMU-tested, 🟢 HW-tested | mps2-an505 MPC in QEMU; GTZC MPCBB1/MPCBB2 on real STM32U585 (SRAM1 secure, SRAM2 non-secure). Note: pre-production regression on GTZC2 USB OTG attribution — see CLAUDE.md "Development Posture". |
| NSC gateway (12 commands, NS pointer validation) | 🟢 QEMU-tested, 🟢 HW-tested | On STM32U585: real ARMv8-M CMSE `cmse-nonsecure-entry` veneers driven by `BLXNS`/SG/`BXNS`. On QEMU: shared-memory mailbox + SysTick poll as a workaround for the QEMU MPC S-alias bug. |
| BIP-39 → SPHINCS+C10 deterministic key derivation | 🟢 QEMU-tested, 🟢 HW-tested | Master + per-slot C10 keygen, validated against test vectors and on real hardware. Domain tags `"sphincs-c6-v1"` (account 0) and `"sphincs-c6-v1-acct"` (accounts 1..=255) frozen in the recovery contract. |
| Multi-account derivation (256 accounts per seed) | 🟢 QEMU-tested, 🟢 HW-tested | Account 0 reproduces the legacy single-account derivation byte-for-byte; accounts 1..=255 use the `-acct` variants. |
| OPTIGA Trust M V3: IFX I2C + APDU + Shielded Connection | 🟢 HW-tested | Pure-Rust 4-layer IFX I2C stack + AES-128-CCM-8 Shielded Connection, PBS in flash page 126. Provisioning + PIN unlock through Shielded Connection validated end-to-end. |
| OPTIGA E120 LUC silicon PIN counter (Trezor-parity) | 🟢 HW-tested | Bound to F1D0's Execute access; validated by `make optiga-hw-counter-e2e`. Auto-increments on every `authenticate_and_read`, hardware-cleared by transient-auth `Change=Auto(F1D0)` on success. |
| OPTIGA F1D0 / E120 reset via transient-auth | 🟢 HW-tested | Trezor-style transient-auth pattern; validated by `make pin-gate-hw-counter-e2e`. |
| SE050: T1oI2C + APDU + SCP03 | 🟢 HW-tested | Authenticated+encrypted SCP03 channel; admin-UserID + user-UserID separation; admin PIN derived from OTP master via `secret_keys::se050_admin_pin()` for crash-safe factory reset. |
| SE050 admin-wipe e2e (`factory_reset_admin`) | 🟢 HW-tested | `policy_roundtrip_selftest` with 6-canary admin session; `make pin-gate-wipe-e2e` exercises the full lockout-wipe dispatch. |
| Dual-SE XOR entropy split | 🟢 HW-tested | `secure/src/dual_se.rs` over `optiga-trust-m + se050`. Provisioning, unlock, and full admin-wipe roundtrip validated on real silicon. |
| MCU PIN-attempt counter (page 124, FI-hardened) | 🟢 HW-tested | `pin_attempts_{read,bump,reset}` in `secure/src/hw/flash.rs`; `nsc::gated_unlock` pre-commit pattern. ICACHE invalidation after every flash mutation. |
| Three-way PIN counter sync (MCU + OPTIGA + SE050) | 🟢 HW-tested | `make pin-gate-hw-counter-e2e` + `make pin-gate-wipe-e2e`. Boot-time re-sync of SE cache vs MCU counter; MAX_ATTEMPTS dispatch into `factory_reset_admin`. |
| Tier 1 SAES-CMAC(DHUK) KDF | 🟢 HW-tested | `secret_keys::derive_into` flips on `saes-dhuk` from `HKDF(OTP_master)` to `SAES-CMAC(DHUK, label‖counter)`. Cross-board fingerprint match at RDP0 (ST-substituted constant); per-die uniqueness pending RDP1 step. |
| SAES driver self-test (RDP0 boot harness + UART VCP) | 🟢 HW-tested | `make saes-self-test-hw` runs software-key + DHUK-vs-SW + DHUK round-trip + 8-byte fingerprint print, then SYS_EXITs. |
| `sphincs-c10` library (no_std, SHA-256) | 🟢 QEMU-tested, 🟢 HW-tested | Powers both bootstrap and slot keys; output matches `SPHINCsC10Asm.sol` byte-for-byte. |
| HW SHA-256 routing (STM32U585 HASH peripheral) | 🟢 HW-tested | `pqsigner_sha256_*` extern fns under `hw-sha256` (auto-implied by `stm32u585`). Boot-time KAT on `"abc"` halts on mismatch. |
| Standalone Tropic01 path (Noise_KK1 + MACD) | 🟢 HW-tested | Tested on STM32U585 + Tropic01 MicroE Clicker (SPI1 via Arduino headers). Not used in dual-SE production target. |
| Trusted UI: OLED draw + 2-button input | 🟢 QEMU-tested, 🟢 HW-tested | SSD1306 driver runs on real hardware; arrow-key forwarding via `tools/wallet_run_hw.py` for `make play-hw-display`. |
| Seed wizard / PIN entry / EIP-1559 confirm dialogs | 🟢 QEMU-tested, 🟢 HW-tested | mps2-an505 + B-U585I-IOT02A. Wizard idempotent under `wipe-for-wizard` for dev provisioning iteration. |
| `aes-gcm`, `sha2`, `hmac`, `cmac`, `bip39` crate integration | 🟢 QEMU-tested, 🟢 HW-tested | All `#![no_std]`. SAES-CMAC math validated by 4 NIST SP 800-38B AES-256-CMAC KATs against the software backend. |
| `#![no_std]`, no-heap, zeroize discipline | 🟢 QEMU-tested, 🟢 HW-tested | All workspace crates. |
| Custom panic handler that wipes secrets | 🟢 QEMU-tested, 🟢 HW-tested | mps2-an505 + B-U585I-IOT02A. |
| Inactivity timeout / activity tracking | 🟢 QEMU-tested, 🟢 HW-tested | mps2-an505 (SysTick) + B-U585I-IOT02A; 120 s idle wipe. |
| ZK clear signing — Groth16 / Poseidon over BLS12-381 (no alloc) | 🟢 QEMU-tested | mps2-an505 secure world; host-side `zk-test` crate verifies the Aave V3 supply proof; PKA acceleration available under `pka-accel`. |
| ZK VK DB in NS rodata + secure-world Merkle verifier | 🟢 QEMU-tested | 32-byte root embedded in S via `db_roots.rs`; NS supplies VK + proof per request; S verifies before Groth16. |
| ERC20 metadata DB in NS rodata + secure-world Merkle verifier | 🟢 QEMU-tested | 32-byte root embedded in S; `dispatch_tx` picks trust levels per tx. |
| Automated end-to-end test (`make e2e`) | 🟢 QEMU-tested | Non-interactive; exercises sign-dispatch back-to-back. |
| Automated end-to-end on real silicon (`make e2e-hw`) | 🟢 HW-tested | Limited by `probe-rs`'s lack of `SYS_READC` — `make e2e-hw` works only when the e2e-test feature pre-provisions PIN; interactive flows need `make play-hw-display`. |
| Hash-signature firmware update model (SPHINCS+C10 + SHA-256) | 🟢 implemented, 🔵 hardware integration in progress | `fsbl/`, `fwsign/`, `fw-manifest/` all PQ end-to-end. Streaming state machine (BEGIN → CHUNK → COMMIT) in `secure/src/fw_update/`. |
| Firmware measurement at boot (SHA-256 → 8 BIP-39 words) | 🟢 implemented | Visual trustless verification via `fwmeasure` host tool. |
| OTP rollback counter (1024 bits, RDP-regression-resistant) | 🟢 HW-tested | `secure/src/hw/otp.rs`; survives RDP regression by design. |
| ERC-1967 proxy wallet contracts (PQSmartWallet + Factory) | 🟢 implemented | EntryPoint v0.6 fork of Coinbase Smart Wallet; CREATE2 salt = `sha256(masterPkSeed‖masterPkRoot)`; squat-defence factory sig over `addSlot0Digest(...)`. Foundry test suite passes. |
| TAMP driver (Trezor-port) | 🟢 implemented (log-only) | `tamp` feature; production must flip the IRQ to `trigger_lockout_wipe()`. |
| Consumption-mask power-side-channel hook | 🟢 implemented | TIM2 CH1 PWM on PA5 with randomised duty cycle; caller-driven via `consumption_mask::randomize()`. |
| **ML-KEM-1024 inner-wrap layer for both halves** | ⏳ not started | Requires `ml-kem` crate audit + HUK-SAES wrap of `sk_pq`. Production-hardening branch target. |
| **Tier 2 BHK key hierarchy** | ⏳ not started | DHUK-wrapped at rest, loaded into TAMP backup registers + `SECCFGR`-locked at boot. See `docs/work-todo.md §7`. |
| **Boot-time attestation of both chips against pinned vendor roots** | ⏳ not started | — |
| **SPHINCS+C10 device identity certificate pinned at provisioning** | ⏳ not started | — |
| **Mixed-RNG entropy generation (STM32 TRNG ⊕ OPTIGA TRNG ⊕ SE050 TRNG)** | 🔵 partial | STM32 TRNG wired; SE-side TRNG mixing planned. |
| **PIN entry digit scrambling** | ⏳ not started | Anti-shoulder-surfing measure; see `docs/work-todo.md #6`. |
| **TZSC GTZC2 USB-OTG attribution** | 🔵 known regression | Pre-production regression of CLAUDE.md invariant #4 to unblock USB bring-up; tracked TODO. |
| **Custom PCB with U585 + OPTIGA Trust M + SE050** | ⏳ not started | Currently using B-U585I-IOT02A + OPTIGA Shield + OM-SE050ARD on Arduino headers. |
| **HUK-SAES wrap for at-rest secrets** | 🚫 blocked on RDP-2 burn | HUK only meaningfully unique at RDP ≥ 1; full production lifecycle requires the irreversible RDP-2 step. |
| **TAMP-fired lockout wipe (production behaviour)** | 🚫 blocked on hardening branch | Bring-up branch keeps TAMP IRQ log-only; production must flip. |
| **RDP Level 2 burn** | 🚫 blocked on hardware | irreversible — final production step |
| **Power-loss / fault-injection / side-channel lab tests** | 🚫 blocked on hardware | Requires lab access on RDP-2 silicon. |

## Firmware Update Model

The wallet uses a **hash-signature** model for firmware updates that combines open-source reproducible builds with manufacturer approval. End-to-end SPHINCS+C10 + SHA-256 — single PQ algorithm in the verification path, no classical fallback.

### How it works

```
Manufacturer (one-time per release):
  1. Reviews and merges source code
  2. CI builds firmware → SHA-256(secure.elf), SHA-256(nonsecure.elf)
  3. Constructs the 75-byte preimage:
       "PQFW_V1" ‖ fw_version_be ‖ secure_hash ‖ nonsecure_hash
  4. Signs the preimage with manufacturer SPHINCS+C10 private key
  5. Publishes the .pqfw release artifact (manifest + body + 4008-byte sig)

User (can be anyone):
  1. Clones repo, builds firmware from source (reproducible build)
  2. Runs `fwsign verify-release` → independently rebuilds the preimage
     from (version, secure.elf, nonsecure.elf) and verifies the signature
  3. Streams the .pqfw to the device via the companion's USB HID stack

Device (FSBL, immutable, on every boot):
  1. Walks A/B slots, picks the higher-version valid one
  2. Reconstructs the same 75-byte preimage from the slot's body
  3. Verifies the SPHINCS+C10 signature against the compiled-in vendor pubkey
  4. ANY failure → halt; otherwise jump into the verified image

Device (runtime, during update):
  1. Streaming state machine BEGIN → CHUNK* → COMMIT writes bank 2
  2. On COMMIT: re-hash the staged image, show the new measurement
     words on the OLED, wait for long-right confirm, bump OTP
     rollback floor, reset
```

### Why this works

- **Single PQ algorithm in the verification path.** The FSBL has one pubkey and one algorithm — SPHINCS+C10. A "just in case PQ is broken" classical fallback would defeat the PQ property; we explicitly do not have one.
- **Signing the preimage IS signing the firmware.** SHA-256 collision resistance guarantees that a valid signature on the 75-byte preimage proves the firmware is the exact binary that was approved.
- **Decoupled build from approval.** Users build from source. The manufacturer approves a 75-byte preimage. The trust chain is fully reconstructable from `(version, secure.elf, nonsecure.elf)` — `fwsign verify-release` rebuilds the preimage and checks the signature with no manifest parsing.
- **Anti-rollback via OTP fuses, not flash.** 32 × 32-bit tally = 1024 increments; survives RDP regression by design. No reset path anywhere — devices that exhaust the 1024-bit OTP budget are end-of-life for updates, that's the contract.
- **PIN unlock required on every CMD_FW_\*.** The wallet seed is never accessed during update, but the unlock gate prevents silent re-flashing of a stolen locked device.
- **At-rest vendor SK is wrapped under Argon2id + XChaCha20-Poly1305.** That wrapping appears only on the signing machine — never in what the device evaluates.

### Implementation status

- **`fsbl/`** — 18 KB immutable bootloader (no_std, SPHINCS+C10 verifier, A/B slot selector). Shares the verify chain with `fwsign` and the secure-world streaming state machine via `fw-manifest/`.
- **`fwsign/`** — host-side `keygen` / `pubkey` / `sign` / `verify` / `verify-release` / `extract-sig` / `inspect`. Argon2id + XChaCha20-Poly1305 at-rest wrap of the SK on the signing machine.
- **`secure/src/fw_update/`** — streaming state machine (BEGIN → CHUNK* → COMMIT) gated by PIN unlock.
- **`secure/src/hw/{flash,otp,boot_state}.rs`** — bank-2 writes, 1024-bit OTP rollback fuse tally, boot-state page for try-once slot tracking.

See [docs/firmware-update.md](docs/firmware-update.md) for the full spec and [docs/reproducible-builds.md](docs/reproducible-builds.md) for the verification recipe.

## Bring-up Roadmap (QEMU → Real Silicon → Production)

The path from a working dual-SE bring-up to a manufacturable wallet is roughly four phases. Each phase has a hard exit criterion before the next one starts.

### Phase 0 — bring-up complete (where we are today)

The all-C10 firmware boots on a B-U585I-IOT02A discovery kit driven via ST-LINK + probe-rs, with the OPTIGA Trust M V3 Shield + OM-SE050ARD on Arduino R3 headers. Dual-SE XOR entropy split is wired and validated. Three-way PIN counter sync (MCU + OPTIGA E120 LUC + SE050 silicon UserID) is validated end-to-end. The Tier-1 SAES-CMAC(DHUK) KDF is landed (no per-die uniqueness at RDP0 by ST design). The OPTIGA Shielded Connection PIN unlock path runs through real silicon. SE050 admin-wipe runs end-to-end. The hash-signature firmware-update path (FSBL + `fwsign` + `fw-manifest` + streaming `fw_update/`) is implemented end-to-end in source. **The bring-up branch is a development branch — it has known production-invariant regressions documented in CLAUDE.md "Development Posture".**

### Phase 1 — close the bring-up regressions (in progress on this branch)

Goal: bring back the production invariants that the breadth-first bring-up traded off, while keeping the dual-SE + USB stack working.

1. Restore the GTZC `TZSC_SECCFGR` allowlist (currently zeroed on this branch); identify the GTZC2 base for USB OTG FS and reattach.
2. Strip `debug-log` / `e2e-test` / `mock-se` from production-build feature sets and restore the `compile_error!` fence in `secure/src/nsc/mod.rs`.
3. Remove the pre-USB register dumps and `secure_log!` calls from the wizard / boot path.
4. Wire the TAMP IRQ to `trigger_lockout_wipe()` (currently log-only on this branch).
5. Wire the BOR / inactivity-timer ISR through the Secure-only TIM (currently SysTick).
6. Land Tier 2 (BHK) so SE050 SCP03 + Tropic01 pairing move under a second SAES selector.
7. Step a board to RDP1, validate per-die DHUK uniqueness via `make saes-self-test-hw`, then re-run the dual-SE + three-way PIN tests against a non-RDP0 root.
8. **Exit criterion:** the production-feature firmware boots on real silicon, refuses NS access to the Secure-only peripheral set, fires the wipe ISR under TAMP / BOR / idle, and the SAES self-test fingerprint differs across two boards.

### Phase 2 — PQ inner wrap + boot-time attestation, still on the devkit

Goal: layer in the planned PQ confidentiality layer for stored entropy halves and the boot-time SE attestation, all on the same devkit before any custom PCB exists.

1. Add the **ML-KEM-1024 inner-wrap layer** in `secure/src/crypto.rs`:
   - At provisioning, generate `(pk_pq, sk_pq) ← ML-KEM-1024.KeyGen()` from the mixed RNG
   - HUK-SAES wrap `sk_pq` (Tier 1 / Tier 2) and store the wrapped blob in U585 secure flash
   - For each half: `(ct, K_share) ← Encaps(pk_pq)`, `aead ← AES-256-GCM(HKDF(K_share, "pq-wrap/v1"), half)`, store `ct ‖ aead` on the SE
   - Audit the chosen `ml-kem` crate (RustCrypto / `pqcrypto-mlkem`) for constant-time and zeroization
2. Migrate the existing OPTIGA F1D1 / SE050 binary-object reads to consume the PQ-wrapped blob
3. Implement **boot-time attestation of both chips** with pinned vendor roots and pinned UIDs (SPHINCS+C10 device certificate signed at provisioning, pinned in HDPL1)
4. Implement the **mixed-RNG entropy generator**: `STM32_TRNG ⊕ OPTIGA_TRNG ⊕ SE050_TRNG`
5. Add **PIN entry digit scrambling** (anti-shoulder-surfing)
6. **Exit criterion:** end-to-end unlock + sign exercises both SEs over the PQ wrap, the seed never appears in plaintext on either I²C bus (verified by trace capture), and a 10-wrong-PIN sequence destroys both halves on real chips and clears the MCU page-124 counter via the lockout-wipe path.

### Phase 3 — custom PCB, HUK-SAES, GTZC, and the production peripheral set

Goal: move from the eval boards to a real PCB layout designed for shipping, and lock down the U585 hardware peripherals to the production configuration.

1. Design and review the **custom PCB**: U585 + OPTIGA Trust M V3 + SE050 + OLED + buttons + tamper mesh + EMI can. PCB review by an external embedded-security specialist
2. **HUK-SAES wrap** the OPTIGA Platform Binding Secret derivation root, SE050 SCP03 static keys, and the ML-KEM-1024 secret key. Store only the ciphertexts in U585 secure flash. Verify a flash dump moved to a different U585 is useless (Tier 1 + Tier 2 keys remain DHUK/BHK-derived; no caller-visible change)
3. Configure **GTZC** to mark every Secure-only peripheral: I2C1 (both SE buses; the production target shares I2C1 between OPTIGA + SE050), the OLED bus, the button GPIOs, TRNG, HASH, SAES, PKA, TAMP, BKPSRAM
4. Configure the **MPU** in both worlds to enforce the secret-SRAM region boundaries
5. Block all DMA controllers from mastering into Secure SRAM
6. Wire the **case switch and tamper mesh** into TAMP, with hardware noise filtering, and flip the IRQ from log-only (this branch) to `trigger_lockout_wipe()`
7. Wire the **internal temperature sensor** check into the boot path and a periodic poll, with the cold-boot threshold tuned on the real PCB
8. Wire **BOR** to the wipe ISR and measure (on real hardware!) the bulk-cap holdup time so the ISR provably completes before V_dd collapses
9. **Exit criterion:** every line of section A and section E of the [shipping checklist](#pre-production-shipping-checklist) is verified on the real PCB

### Phase 4 — secure boot, provisioning, and lockdown

Goal: build the immutable FSBL, the HSM-backed provisioning pipeline, and burn the option bytes that turn the devkit into a one-way device.

1. Finalise the **immutable FSBL at `0x0C00_0000`** with WRP1A locking pages 0–3 before the RDP-2 burn. The FSBL holds one SPHINCS+C10 vendor public key and one algorithm — no classical fallback, no hybrid leg
2. Build the **HSM-backed provisioning pipeline** (SPHINCS+C10 vendor signing key in an air-gapped HSM partition, two-person rule, Argon2id + XChaCha20-Poly1305 at-rest wrap of the SK blob — never reaches the device)
3. Build the **per-device SPHINCS+C10 device-identity certificate** signing flow, with the cert pinned in the FSBL region alongside the vendor public key
4. Run the entire 13-step bring-up sequence in [Locking the STM32 to your firmware only](#locking-the-stm32-to-your-firmware-only) on a sacrificial PCB unit, including the final RDP Level 2 burn
5. Verify the locked unit refuses an unsigned firmware image (the FSBL halts at the C10 verification step), refuses SWD/JTAG, refuses bootloader fallback, and still unlocks + signs correctly through the secure UI
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
- [ ] OPTIGA Trust M and SE050: today they share I2C1 (addresses 0x30 and 0x48); for production, evaluate moving SE050 to a second I²C peripheral so a fault on one cannot wedge the other (independent reset already required below)
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
- [ ] Spec'd component lead-time and second-source for every part on the BOM (so an OPTIGA / SE050 stockout does not force a vendor swap that breaks pinned attestation)

### B. Provisioning facility

- [ ] Clean-room facility with **no network**, no removable media, no personal devices
- [ ] Provisioning station OS image is reproducible, signed, and re-imaged before every batch
- [ ] HSM-backed generation of every per-device secret (or NXP EdgeLock 2GO for SE050 at volume)
- [ ] Per-device unique: SE050 SCP03 keys, OPTIGA Trust M Platform Binding Secret, OPTIGA UID pin, SE050 UID pin (all derived from the SAES-DHUK Tier 1 root via `hw::secret_keys`)
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

- [ ] **SPHINCS+ test vectors** pass for the C10 parameter set, on-target. Output bytes match the on-chain `SPHINCsC10Asm.sol` verifier byte-for-byte
- [ ] **Differential test** against a second hash-based-signature implementation and against the recovery-contract test vectors in `sphincs-c10/tests/gen_test_vectors.rs`
- [ ] **BIP-39 spec test vectors** pass (Trezor 24-word vectors are already in `bip39/tests/vectors.rs` — extend with the official BIP-39 vectors)
- [ ] **HKDF PIN-stretching test vectors** pass
- [ ] **HKDF-SHA256 / SHA-512 test vectors** pass
- [ ] **AES-256-GCM test vectors** pass on the SAES peripheral path, not just the software fallback
- [ ] **SCP03 negative tests** against SE050: replayed APDUs, malformed APDUs, wrong static keys, expired session, wrong UID
- [ ] **Shielded Connection negative tests** against OPTIGA Trust M: replayed nonces, swapped Platform Binding Secret, malformed handshake messages
- [ ] **Attestation negative tests on both chips**: wrong cert chain, replayed nonce, swapped UID, no response, slow response (timeout enforcement)
- [ ] **PIN brick test**: 9 wrong PINs in a row brick the device exactly once, on real hardware, verified by zeroized r-mem read-back
- [ ] **Power-loss tests at every step of every flow** (provisioning, unlock, sign, lock, wipe). Cut V_dd at random microsecond offsets and verify no secret survives in any persistent storage
- [ ] **Three-way counter-divergence test**: simulate a glitch between MCU page-124, OPTIGA E120, and SE050 silicon-counter increments; verify boot reconciliation accepts the strictest counter and refuses unlock on disagreement (`make pin-gate-hw-counter-e2e` is the in-tree starting point)
- [ ] **Recovery test**: provision device A, write down the 24 words, brick device A, recover on a fresh device B, sign with the recovered key, verify it matches the device-A pubkey

### E. Side-channel & fault hardening

- [ ] **External fault-injection lab time** on real hardware: voltage glitching, EM glitching, clock glitching against PIN entry, attestation, signing, and wipe paths
- [ ] **Side-channel lab time**: SPA + DPA against PIN stretching, AES-GCM, SPHINCS+C10 hash chains (WOTS+, FORS), with and without the EMI can + consumption-mask fitted
- [ ] **Constant-time inspection** of the generated assembly for every secret-dependent inner loop in SPHINCS+C10 (`subtle` crate is a contract, not a guarantee — verify the codegen)
- [ ] **Verify-before-release** is wired into every signing path, not just one
- [ ] **Wipe ISR loop-twice + read-back** verified to clear all listed regions on real hardware, including under brownout and TAMP
- [ ] **Stack scrub** after every signing operation; test that scans S-SRAM post-sign for the test seed and fails loudly if found
- [ ] **CPU register scrub** after returning from any S-world crypto routine
- [ ] **Cache flush** after any operation that touched secrets
- [ ] **Cold-boot attack mitigation**: temperature sensor refuses below the configured threshold; tested with freeze spray on a real unit
- [ ] **DMA-into-S-SRAM blocked** test: NS world attempts a DMA transfer into a Secure SRAM address and is denied by GTZC

### F. STM32U585 secure boot & option bytes

(See "Locking the STM32 to your firmware only" below for the how. The checklist is *what to verify* before shipping.)

- [ ] **Custom immutable FSBL (`fsbl/`) with SPHINCS+C10 verification** provisioned and occupying HDPL1; WRP1A locks pages 0–3 before the RDP-2 burn
- [ ] FSBL refuses to boot any slot whose 75-byte preimage signature doesn't verify against the pinned vendor pubkey. CI test that flips one bit of the signature and confirms boot halt
- [ ] SPHINCS+C10 vendor private key lives **only** in an air-gapped HSM partition; Argon2id + XChaCha20-Poly1305 at-rest wrap of the SK blob; two-person rule for use; no copies on disk anywhere
- [ ] Image signature verification happens **before** any of your code runs (verify by trying to flash an unsigned image — it must be rejected by the FSBL)
- [ ] FSBL's pinned material includes the vendor public key and the per-device SPHINCS+C10 device-identity certificate
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

- [ ] **Recovery contract committed at launch** in the protocol spec: SPHINCS+C10 (W+C_F+C, h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205, sig=4008), BIP-39 → C10 master expansion (whatever tag the team finalises — the in-tree placeholder is `"sphincs-c6-v1"` / `"sphincs-c6-v1-acct"`), CREATE2 salt `sha256(masterPkSeed‖masterPkRoot)`, slot tags (currently `"jardin_slot"` / `"jardin_r"` / `"jardin_slot_c10_sk_seed"` / `"jardin_slot_c10_pk_seed"`). After the first device ships, any change to these is a user-visible hard fork. Before launch this is a coordination cost only.
- [ ] **SPHINCS+ test vectors pass** for the C10 parameter set on-target, not just on the host. Output bytes match `SPHINCsC10Asm.sol` byte-for-byte (the verifier and signer are co-engineered)
- [ ] **Differential test** the in-tree `sphincs-c10` crate against a second hash-based-signature implementation and against the recovery-contract test vectors in `sphincs-c10/tests/gen_test_vectors.rs`
- [ ] **NIST PQC test vectors pass** for ML-KEM-1024 (planned inner-wrap) — on-target, not just on the host
- [ ] **Constant-time inspection of the ML-KEM inner loops** in the generated thumbv8m assembly (planned). Lattice schemes have known timing-leak footguns (rejection sampling, NTT, modular reduction); verify the codegen
- [ ] **Fault-injection lab** specifically targets the ML-KEM Decaps path (planned). A Decaps fault that returns a partially-correct shared secret is a classic FO-transform attack vector — verify the implementation rejects malformed ciphertexts in constant time
- [ ] **Verify-before-release** on every Type 1 and Type 2 SPHINCS+C10 signature, double-evaluated with a sentinel (fault-injection guard against hash-tree intermediate leakage)
- [ ] **ML-KEM secret key (sk_pq)** (once landed) is stored only HUK-SAES-wrapped in U585 secure flash. Never lives in plain anywhere on flash. Test by flash-dumping a provisioned but locked device and confirming the dump is opaque
- [ ] **PQ wrap is end-to-end** (post inner-wrap landing): the SE050 binary object and OPTIGA F1D1 only ever contain `ct ‖ aead`, never plaintext halves. CI test that scans a captured I²C trace for any byte pattern matching the test entropy
- [ ] **PQ random subsystem** uses the mixed STM32 + OPTIGA + SE050 TRNG. Never a software PRNG. Test that all three sources are reachable and that the mixing routine cannot be silently bypassed
- [ ] **No classical-fallback verifier in the firmware-update path.** The FSBL has one pubkey and one algorithm. CI test that confirms there is no ECDSA / Ed25519 / RSA code path under any feature flag in the FSBL build
- [ ] **Audit the in-tree `sphincs-c10` crate** by an external cryptographer specifically for: hash-tree address encoding, WOTS chain correctness, zeroization of intermediate state, side-channel resistance of the SHA-256 inner loop
- [ ] **Audit the chosen ML-KEM crate** (RustCrypto / `pqcrypto-mlkem`) when the inner-wrap layer lands, with the same review scope
- [ ] **Document the PQ migration path** if SHA-256 is broken (theoretical): which firmware update swaps to a SHAKE-based hash, signed by which key, recoverable on what timeline. The plan must be drilled before launch
- [ ] **Recovery test under PQ migration**: simulate "ML-KEM is broken, swap to classic McEliece KEM" by flashing a vN firmware that re-wraps the halves on the SEs, and verify the same 24 BIP-39 words still produce the same SPHINCS+C10 signing key

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
- [ ] **Compliance**: CE / FCC / RoHS as applicable; FIPS 140-3 if claimed; EAL claim about the SE050 / OPTIGA Trust M cited correctly (you do not get to inherit their cert for the whole product)

### J. The "honest caveats" page that ships with the device

- [ ] One-page document, in plain language, that lists what the device does *not* protect against (coerced unlock, lab attack on the SE die, supply-chain compromise of either vendor's silicon, your own implementation bugs)
- [ ] Recommends a *passphrase* for users whose threat model includes coercion
- [ ] Recommends a multi-sig setup for high-value funds
- [ ] States the bug bounty contact and disclosure policy
- [ ] States the firmware signing key fingerprint and where to verify it
- [ ] Translated for every market the device ships into

---

## Locking the STM32 to your firmware only

The STM32U585 has a built-in immutable boot ROM and an OEM Root of Trust (OEMiROT) feature specifically designed to enforce "this chip will only execute firmware signed by *this* key". For PQSigner OS we replace ST's stock ECDSA/RSA OEMiROT with a **custom immutable FSBL that verifies a SPHINCS+C10 signature** before any of your code runs. ST's stock OEMiROT does not include a PQ verifier; we ship our own (`fsbl/`).

The chain looks like:

```
   ┌────────────────────────────────────────────────────────────┐
   │ HDPL0 — System Bootloader (immutable, in System Flash)     │
   │   • runs on every reset                                    │
   │   • dispatches to FSBL based on option bytes               │
   └────────────────────────────────────────────────────────────┘
                           │
                           ▼
   ┌────────────────────────────────────────────────────────────┐
   │ HDPL1 — Our FSBL  (immutable, in `fsbl/`, ~18 KB)          │
   │   • flashed once during provisioning, WRP1A-locked before  │
   │     RDP-2 burn                                             │
   │   • holds:                                                 │
   │       - 32-byte SPHINCS+C10 vendor verifying key           │
   │       - per-device SPHINCS+C10 device-identity certificate │
   │       - 1024-bit OTP rollback floor                        │
   │   • for each A/B slot, in version order:                   │
   │       - parses the manifest {version, secure_hash,         │
   │         nonsecure_hash, sig (4008 B)}                      │
   │       - reconstructs the 75-byte preimage:                 │
   │           "PQFW_V1" ‖ version_be ‖ secure_hash ‖ nonsecure │
   │       - verifies SPHINCS+C10 signature against vendor pk   │
   │       - verifies version > OTP rollback floor              │
   │       - on ANY failure → try the other slot, else halt     │
   │       - on success → jump into image                       │
   └────────────────────────────────────────────────────────────┘
                           │
                           ▼
   ┌────────────────────────────────────────────────────────────┐
   │ HDPL2 — Your Secure-world firmware                         │
   │   • configures SAU / MPC / GTZC, opens SE buses,           │
   │   • holds the (planned) HUK-SAES-wrapped ML-KEM-1024 sk,   │
   │     OPTIGA Trust M PBS, SE050 SCP03 static keys, derived   │
   │     on demand via `hw::secret_keys` (Tier 1 SAES-CMAC-DHUK)│
   └────────────────────────────────────────────────────────────┘
                           │
                           ▼
   ┌────────────────────────────────────────────────────────────┐
   │ HDPL3 — Your Non-secure-world firmware                     │
   │   • UI shell, USB, etc. — has no access to S-flash, to     │
   │     the SE buses, or to any FSBL or HDPL2 secret           │
   └────────────────────────────────────────────────────────────┘
```

Each HDPL transition **irrevocably hides** the option bytes and OBKEYs of the previous level. By the time NS code runs, it cannot read the vendor verifying key, the (planned) ML-KEM secret key, the SE wrap keys, or the FSBL itself, no matter what bug it has.

### The bring-up sequence (do this on a sacrificial dev board first — RDP-2 is irreversible)

1. **Generate the vendor SPHINCS+C10 keypair** in an air-gapped HSM partition. The private key is non-exportable; export only the 32-byte verifying key (and its SHA-256 hash) for FSBL pinning. The at-rest blob is wrapped under Argon2id + XChaCha20-Poly1305 — never reaches the device. Two-person rule on every signing operation.
2. **Build the immutable FSBL** (`fsbl/`). It bakes in the 32-byte vendor verifying key (or its SHA-256 hash, depending on the layout chosen at provisioning), the A/B slot addresses, and the 1024-bit OTP rollback floor location. Verifies a SPHINCS+C10 signature over the 75-byte preimage; **any** failure halts.
3. **Sign your secure-world + non-secure-world firmware images** with `fwsign sign` against the HSM-held vendor key, producing a `.pqfw` artifact whose body holds `{version, secure_hash, nonsecure_hash, sig (4008 B)}` plus unsigned metadata.
4. **Burn the FSBL image** into its flash region using `STM32CubeProgrammer` over SWD on a non-RDP unit. This is a one-shot write — once HDPL1 is closed and WRP1A is locked, you can't re-flash the FSBL without de-provisioning the chip.
5. **Burn option bytes** with the provisioning script (HSM-signed, replayed identically per device):
   - `TZEN = 1` (TrustZone on)
   - `SECWM1_PSTRT/PEND` and `SECWM2_PSTRT/PEND` to cover the entire secure flash region
   - `SECBOOTADD0` = the FSBL entry point
   - `nBOOT0 = 0`, `nSWBOOT0 = 1` → always boot from internal flash, never from system bootloader
   - `nBOOT_SEL = 1` → BOOT0 pin is ignored
   - `nBOOT_LOCK = 0xC3` → boot configuration locked
   - `BOR_LEV = 4` (or higher) → brownout fires above the wipe-ISR safe voltage
   - `WRP1A` write-protects the FSBL region (pages 0–3)
   - `HDP1EN` / `HDP2EN` set so HDPL1 closes after FSBL runs
   - `DBG_AUTH = 0`, debug ports off
6. **Burn your secure and non-secure firmware images** into their respective flash regions with valid SPHINCS+C10 signatures in the manifest.
7. **Generate the device's planned PQ inner-wrap keypair on the device itself:** the secure firmware boots once in a special "factory mode", uses the mixed `STM32_TRNG ⊕ OPTIGA_TRNG ⊕ SE050_TRNG` to run `(pk_pq, sk_pq) ← ML-KEM-1024.KeyGen()`, HUK-SAES-wraps `sk_pq`, and writes it to a dedicated secure-flash region. The wrapped blob never leaves the device. (Inner-wrap is on the production-hardening branch; bring-up devices skip this step.)
8. **Generate and pin the device-identity certificate.** The HSM signs a SPHINCS+C10 certificate over `{device_serial, U585_UID, OPTIGA_UID, SE050_UID, pk_pq_hash}`. Pinned in HDPL1 alongside the vendor public key. This is the cryptographic root of "is this device the one we provisioned" — the SE factory ECDSA attestations are downgraded to proof-of-presence only.
9. **Burn per-device secrets** in the same provisioning session: derive OPTIGA Platform Binding Secret + SE050 SCP03 static keys + SE050 admin UserID PIN via `hw::secret_keys` (Tier 1 SAES-CMAC(DHUK) production path), pin OPTIGA + SE050 UIDs, pin vendor attestation root certificates.
10. **Run the post-provisioning self-test** over SWD: boot the device, walk through dual attestation + device-identity verification, provision a test wallet, sign a test transaction with SPHINCS+C10, verify the signature, brick the test wallet (10 wrong PINs), confirm both SEs report destroyed state, confirm the MCU page-124 counter is at MAX and the lockout-wipe path fires. The self-test record is signed (by the HSM) and archived.
11. **Burn `RDP = 0xCC`** (Level 2). This is the **last** option-byte write and it is **irreversible**. SWD is dead the moment the regulator settles after this write. Once a device passes through this step, you cannot debug it, you cannot re-flash it, you cannot recover it. Make sure step 10 is bulletproof.
12. **Final acceptance test** on the now-locked device: power-cycle, dual attest, verify SPHINCS+C10 device certificate, unlock with the test PIN (driving the full Shielded Connection + SCP03 path on both SEs), sign, verify, lock. If anything fails, the unit is scrap — you can't open it back up.

### What this gives you

- **Only firmware signed by your vendor SPHINCS+C10 key will run.** The FSBL refuses any other image at HDPL1; an attacker who replaces flash contents with a different binary gets a halt at the C10 verification step. A class-break of SHA-256 — the only assumption — is the only way past this gate.
- **PQ confidentiality of all stored secrets** (post inner-wrap landing). Both halves of the entropy will live on the SEs only as ML-KEM-1024 ciphertext; the secret key needed to decapsulate them is HUK-SAES-wrapped in U585 secure flash and never leaves the chip.
- **No debug access.** SWD/JTAG return nothing useful at RDP-2. There is no documented path to recover, even for ST.
- **No bootloader fallback.** With `nSWBOOT0 = 1` and `nBOOT_SEL = 1`, the system bootloader can never run, so the USART/USB/I²C boot recovery interfaces are dead.
- **No option-byte rollback.** RDP-2 cannot be downgraded to RDP-1 without a full mass erase, and a mass erase wipes everything including the FSBL, leaving a brick.
- **No flash patching.** WRP1A on the FSBL region means even your own signed firmware cannot rewrite the bootloader.
- **HDPL hides keys from later stages.** By the time NS code runs, the vendor verifying key, the ML-KEM secret key, the SE wrap keys, and the FSBL itself are unreadable from any execution context except the one that owns them.

### Sources to read before you bring this up on real silicon

- ST **AN5447** — *OEMiROT for STM32U5*
- ST **AN5054** — *Secure programming techniques for STM32 microcontrollers*
- ST **UM2851** — *Getting started with STM32CubeU5 TFM application*
- ST **RM0456** — *STM32U5 reference manual*, "Flash, RDP, OEMiROT, HDPL" chapters
- ST **AN5156** — *Introduction to STM32 microcontrollers security*
- The **TF-M for STM32U5** port (open source, audit-friendly — useful reference even though our FSBL is a fresh implementation)
- **MCUboot** documentation (has experimental PQ verifier work upstream — also a reference, not a base)
- **NIST FIPS 203** — ML-KEM (the planned inner wrap)
- **NIST FIPS 205** — SLH-DSA (closely related to our C10 parameterisation — but note we use the SPHINCs+ W+C_F+C variant, not stock SLH-DSA)
- The in-tree `sphincs-c10/` crate + the on-chain `SPHINCsC10Asm.sol` verifier — the authoritative spec for our exact C10 parameter set
- **NIST SP 800-208** — Stateful hash-based signatures (for context on hash-based PQ)
- **NIST IR 8413** — PQC standardisation status report
- **CNSA 2.0 transition timeline** — for your compliance posture

Read all of these before burning your first option byte. The cost of an irreversible mistake on a production line is much higher than the cost of a week of reading.

## License

Copyright (c) 2026 EthereumPhone. All rights reserved.
