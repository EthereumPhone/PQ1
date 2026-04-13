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
**Gateway commands (6 total):**

| CMD | Name | What it does |
|-----|------|-------------|
| 1 | GET_REMAINING | Return remaining PIN attempts |
| 2 | REQUEST_UNLOCK | S-world prompts PIN via trusted UI, unlocks SEs |
| 3 | GET_PUBKEY | Copy 32-byte verifying key to NS buffer |
| 5 | CLEAR_SIGN | ZK-verify calldata interpretation, display, sign |
| 6 | CLEAR_SIGN_MSG | EIP-712 message signing |
| 7 | SIGN_USEROP | Parse AA UserOp, display inner tx, sign userOpHash |

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
| `secure/src/secure_element.rs` | SecureElement trait + mock impl |
| `secure/src/ui/pin_entry.rs` | Trusted PIN entry (runs in S-world) |
| `secure/src/ui/seed_wizard.rs` | BIP-39 mnemonic generate/restore wizard |
| `secure/src/zk/groth16.rs` | Groth16 pairing verifier (no alloc) |
| `secure/src/erc20/dispatch.rs` | Tx trust-level dispatcher (ValueTransfer/Erc20Known/Blind) |
| `secure/src/aa/userop.rs` | ERC-4337 UserOp hash construction |
| `nonsecure/src/main.rs` | Non-secure world entry |
| `nonsecure/src/nsc_api.rs` | NS-side gateway caller |
| `nonsecure/src/e2e_test.rs` | Automated end-to-end test driver |
| `shared/src/lib.rs` | Cross-world types: NscStatus, CMD constants |
| `shared/src/db_format.rs` | ERC20 + VK database binary format |
| `contracts/smart-wallet/src/PQCoinbaseSmartWallet.sol` | ERC-4337 wallet core |
| `contracts/smart-wallet/src/PQOwnable.sol` | Two-tier PQ signer state |
| `contracts/smart-wallet/src/verifiers/SLHDSAVerifier.sol` | FIPS-205 on-chain verifier |
| `dbgen/` | Host-side Merkle DB builder |
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
