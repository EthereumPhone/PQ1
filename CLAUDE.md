# PQSigner OS -- LLM Context

Post-quantum ERC-4337 hardware wallet. Target: **STM32U585 (Cortex-M33, TrustZone) + Infineon OPTIGA Trust M V3 + NXP SE050**. Every primitive protecting the seed is PQ or symmetric with >=256-bit keys. Signing is **JARDÍN FORS+C only** — pure post-quantum, no ECDSA, no classical fallback. The wallet is an account-abstraction smart account that talks to EntryPoint v0.9.

Status: JARDÍN cutover complete. Firmware boots on real B-U585I-IOT02A + QEMU mps2-an505. Both SE drivers (OPTIGA Trust M, SE050) working. Dual-SE XOR entropy split wired and tested. The `PQJardinWallet` smart-wallet is deployed via a deterministic CREATE2 factory whose salt is `sha256(masterPkSeed || masterPkRoot)`, so the same 24 words produce the same address on every chain. **SHA-256 cutover:** every hash inside the PQ signing stack (SPHINCS+C11, JARDÍN FORS+C, slot-key derivation, KDF, CREATE2 salt) is now SHA-256, routed through the STM32U585 HASH peripheral on hardware. `sha3::Keccak256` is retained only for the external-standard hashes the EVM demands (EIP-4337 userOpHash, EIP-712, EIP-1559 envelope, ERC-7201 namespace, the CREATE2 address formula itself).

## Non-Negotiable Invariants

**Every change to ANY subsystem must respect ALL seven of these. Violating any one is a critical security bug.**

1. **Dual-chip seed split.** BIP-39 entropy is XOR-split: `half_O` on OPTIGA Trust M, `half_E` on SE050. Neither chip alone reveals any bit of the seed. Code that stores the full entropy on a single chip, or transmits one half to the other chip, breaks the design.

2. **Hardware-level PIN gating.** The PIN decision is made by the secure element silicon, never by MCU firmware. SE050 uses UserID auth (object `0x7B06_0000`, max 10 attempts, hardware constant-time comparison). OPTIGA Trust M uses hardware-enforced authorization references (OID `0xF1D0`, access conditions enforced by chip silicon). Firmware that compares PINs in software, or bypasses the SE's auth gate to read secrets, breaks the design.

3. **E2E encrypted tunnel between TrustZone secure world and each SE.** OPTIGA Trust M: Shielded Connection (TLS-PRF + AES-128-CCM-8) per session; Platform Binding Secret stored in secure flash page 126. SE050: SCP03 (AES-CMAC + AES-CBC) authenticated+encrypted channel. Planned: ML-KEM-1024 inner wrap so even a CRQC break of the classical channels reveals only opaque PQ ciphertext. No plaintext secret ever touches the I2C bus.

4. **All secrets live ONLY in TrustZone secure world.** Non-secure world never sees a PIN digit, entropy byte, signing key, or derived secret. The NSC gateway exposes only opaque commands (unlock, sign, status) that return non-secret data. Pointer validation on every call. TOCTOU defense: NS buffers copied to secure stack before parsing.

5. **Post-quantum only for transaction signing.** JARDÍN FORS+C. No classical signer (secp256k1, P-256, Ed25519) anywhere. The master identity that gates slot registration is SPHINCS+C11 — still hash-based, no lattice assumptions. The on-chain wallet contract has NO classical verifier path.

6. **`next_q` persistence before release.** Every FORS+C signature increments `next_q` in secure flash BEFORE the Type 2 bytes are released to NS. A rollback after sign-but-before-flash would otherwise allow q reuse and FORS+C security collapses under reuse (128 → 105 bits at q=2, lower with more).

7. **Master C11 keys are immutable.** The on-chain CREATE2 salt is `sha256(masterPkSeed || masterPkRoot)`. Rotating master keys would change the wallet address — seed recovery would land users at a different account. The factory has no `rotateMasterKeys` function, and there is no on-chain ownership model that could introduce one.

## Architecture at a Glance

```
  OPTIGA Trust M --[Shielded Conn E2E]--> STM32U585 SECURE WORLD <--[SCP03 E2E]-- SE050
  (half_O, PIN-gated)                      |  PIN -> KDF -> K_O, K_E             (half_E, PIN-gated)
  I2C addr 0x30                            |  Reconstruct: E = HKDF(half_O XOR half_E)
                                           |
                                           |  BIP-39(E) -> PBKDF2(2048) -> bip39_seed (64B)
                                           |       |
                                           |       +--- HMAC-SHA512("sphincs-c6-v1") -> master
                                           |       |       |  +-- sha256("pk_seed"||master[..32]) & N_MASK    -> masterPkSeed
                                           |       |       |  +-- sha256("sk_seed"||master[..32])              -> masterSkSeed
                                           |       |       +-- sphincs_c7::SigningKey::keygen(...)              -> masterPkRoot
                                           |       |              (C11 hypertree, built on-demand for Type 1)
                                           |       |
                                           |       +--- sha256("pqwallet-jardin-master" || bip39_seed)  -> jardin_master_entropy
                                           |                                                                        |
                                           |       jardin_slot_entropy(master, slot_idx) = sha256(master||"jardin_slot"||slot_idx)
                                           |       jardin_slot_r(master, slot_idx)        = sha256(master||"jardin_r"||slot_idx)
                                           |                                                                        |
                                           |       jardin_fosc::JardinSlot::keygen(entropy) -> sub_pk_seed, sub_pk_root, 94-node spine
                                           |                                                                        |
                                           |       Type 1: C11-sign(master_sk, userOpHash_t1) -> 3976-byte C11 sig
                                           |       Type 2: FORS+C-sign(slot, userOpHash_t2)    -> 2452+q*16-byte sig
                                           |
                                           +--[NSC gateway, 6 cmds]---> NON-SECURE WORLD
                                                                         UI, USB, APDU routing
                                                                         no secrets, ever
```

**Gateway commands** (see `sphincs_tz_shared::CMD_*`):

| CMD | Name | What it does |
|-----|------|--------------|
| 1 | GET_REMAINING | Return remaining PIN attempts |
| 2 | REQUEST_UNLOCK | S-world prompts PIN via trusted UI, unlocks both SEs |
| 7 | SIGN_USEROP | **The one sign command.** Parses input header + inner tx, decides FirstSign/Normal/Rotate from flash state, emits `[type1_len | t1 | type2_len | t2]` bundle. `type1_len == 0` means slot already registered on this chain. |
| 11 | IS_UNLOCKED | Returns 1/0 |
| 12 | LOCK | Zeroize cached secrets |
| 17 | GET_JARDIN_SLOT_INFO | Read persisted `SlotState` for a given `chain_id` |

**Lifecycle:** Boot → SAU/GTZC config → (attest both SEs) → PIN entry in S-world → unlock both SEs → reconstruct seed in S-SRAM → active signing window (120s idle timeout) → zeroize on lock/tamper/brownout/inactivity.

## Signing state machine (post-cutover)

```
                  ┌─────────────────────────────┐
                  │ read SlotState from flash   │ (nsc::jardin_flash::read_latest)
                  └─────────────┬───────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
  no record / chain      registered, next_q       registered, next_q
  mismatch / not-reg.    <= Q_MAX=95              > Q_MAX
        │                       │                       │
        ▼                       ▼                       ▼
  FirstSign                 Normal                  Rotate
  slot_index = hint         slot_index stays        slot_index += 1
  keygen new slot           rebuild slot if         keygen new slot
  Type 1 + Type 2           state not cached        Type 1 + Type 2
  type1_len = 4041          Type 2 only             type1_len = 4041
                            type1_len = 0           (Type 1 registers
                                                     the NEW sub-key)
```

## Wire formats (frozen — on-chain verifier depends on them)

### Unified sign input (NSC + USB)

```
offset  size  field
---------------------------------------------------------
  0     8    chain_id (u64 BE)
  8     4    slot_index_hint (u32 BE, usually 0)
 12    20    sender (PQJardinWallet address)
 32    20    entry_point (EntryPoint v0.9 address)
 52    32    nonce (u256 BE, base nonce for the first UserOp in the bundle)
 84    32    account_gas_limits (bytes32, (verGas<<128)|callGas)
116    32    pre_verification_gas (u256 BE)
148    32    gas_fees (bytes32, (maxPrio<<128)|maxFee)
180    32    paymaster_and_data_hash (keccak256, KECCAK_EMPTY when empty)
212    20    to_address (inner tx recipient)
232    32    value (u256 BE)
264     2    data_len (u16 BE, 0..=4096)
266     N    data
```

### Unified sign output

```
[type1_len(4 BE)][type1_bytes...][type2_len(4 BE)][type2_bytes...]
```

- `type1_bytes` (exactly 4041 bytes when present):
  `[0x01][r(32)][subPkSeed(16)][subPkRoot(16)][C11_sig(3976)]`

- `type2_bytes` (2533..4037 bytes):
  `[0x02][H(r)(32)][subPkSeed(16)][subPkRoot(16)][FORS+C_sig(2452 + q·16)]`

### On-chain validation

`PQJardinWallet.validateUserOp` dispatches on `sig[0]`:
- `0x01` → verify master C11 sig over `userOpHash`, record `slots[sha256(r)] = sha256(subPkSeed || subPkRoot)`.
- `0x02` → look up `slots[slotKey]`, check sub-key commitment matches, verify FORS+C sig.

## Subsystem Guides

### JARDÍN FORS+C signing (`jardin-fosc/`)

**Parameters** (frozen by the on-chain verifier): N=16, K=26, A=5, Q_MAX=95, FORSC_BODY=2452. ADRS types: 3=FORS_TREE, 4=FORS_ROOTS, 6=UNBALANCED.

**Key files:**
- `jardin-fosc/src/lib.rs` — `JardinSlot::keygen(entropy)`, `JardinSlot::sign(msg_hash)`, stateless `verify(pk_seed, pk_root, msg_hash, sig)`.
- `jardin-fosc/src/hash.rs` — tweakable hashes, FORS secret derivation, `jardin_slot_entropy`, `jardin_slot_r`, 192-byte `jardin_h_msg`.
- `jardin-fosc/src/unbalanced.rs` — unbalanced Merkle tree for `q ∈ [1..95]`.

**Cross-cutting invariants:**
- `jardin_fosc::verify` is a pure function, matches `JardinForsCVerifier.sol` byte-for-byte.
- `slot.next_q` advances monotonically; flash persistence happens BEFORE the signature is released to NS.
- The H_msg is 192 bytes: `pkSeed(32) || pkRoot(32) || R(32) || msg(32) || counter_u256(32) || 0xFF..FF(32)`.

### SPHINCS+C11 master signing (`sphincs-c7/`)

The crate name is historical — it implements **C11** (W+C_F+C, h=16, d=2, a=11, k=13, w=8, l=43, sig=3976). Used only for Type 1 slot registration; FORS+C handles every user tx.

**Key files:**
- `sphincs-c7/src/lib.rs` — `SigningKey::keygen`, `SigningKey::sign`, `verify`.
- `sphincs-c7/src/hypertree.rs`, `wots.rs`, `fors.rs`, `merkle.rs`, `address.rs`, `hash.rs`, `params.rs`.

**Cross-cutting invariants:**
- Output matches `SPHINCsC11Asm.sol` (Yul-optimised Solidity verifier) byte-for-byte.
- 3,976-byte signature. Verify time on-chain ≈ 116K gas.
- `SigningKey` is `ZeroizeOnDrop`; never leaves secure SRAM.

### OPTIGA Trust M Integration

**What:** Stores `half_O` of the XOR-split entropy. Communicates over I2C via Infineon IFX I2C protocol (4-layer stack), wrapped in a Shielded Connection (AES-128-CCM-8). Hardware-enforced PIN via authorization reference access conditions.

**Key files:** `secure/src/optiga/mod.rs`, `secure/src/optiga/ifx_i2c.rs`, `secure/src/optiga/apdu.rs`, `secure/src/optiga/shield.rs`, `secure/src/optiga/i2c.rs`, `secure/src/hw/flash.rs`.

**Object IDs:**
- `0xE140` -- Platform Binding Secret (shielded connection root of trust)
- `0xF1D0` -- Authorization reference (PIN-derived HMAC secret, hardware-enforced)
- `0xF1D1` -- Entropy half (32 B, policy: requires Auto(0xF1D0) + Conf(0xE140))
- `0xF1D4` -- Master secret (32 B, policy: requires Auto(0xF1D0) + Conf(0xE140))

### SE050 Integration

**What:** Stores `half_E` of the XOR-split entropy. Communicates over I2C via SCP03 authenticated+encrypted channel. UserID PIN auth with 10-attempt hardware limit.

**Key files:** `secure/src/se050/mod.rs`, `secure/src/se050/scp03.rs`, `secure/src/se050/apdu.rs`, `secure/src/se050/t1oi2c.rs`, `secure/src/se050/i2c.rs`, `docs/se050-userid-pin-auth.md`.

### Flash-backed slot state (`secure/src/nsc/jardin_flash.rs`)

Double-buffered, sequence-numbered `SlotStateRecord` in secure flash pages 123-124 on STM32U585 (RAM-mirrored on QEMU). Every Type 2 sign bumps `next_q` and commits a fresh record BEFORE the sig bytes leave the secure world.

Public API:
```rust
pub fn read_latest() -> Option<SlotState>;
pub fn write(state: &SlotState) -> Result<(), FlashError>;
```

### TrustZone / NSC Gateway

**What:** ARM TrustZone-M splits the MCU into secure world (all crypto, PIN, signing) and non-secure world (UI, USB, tx parsing). The NSC gateway is the only crossing point.

**Key files:** `secure/src/main.rs`, `secure/src/sau.rs`, `secure/src/nsc/mod.rs`, `secure/src/nsc/state.rs`, `secure/src/nsc/ptr_validate.rs`, `secure/src/nsc/cmd_*.rs`, `secure/src/boot_ns.rs`, `secure/src/timeout.rs`.

On STM32U585: real CMSE `cmse-nonsecure-entry` veneers. On QEMU: shared-memory mailbox workaround.

### BIP-39 Seed Management

24-word mnemonic encodes 256-bit entropy. Entropy XOR-split across two SEs. Reconstructed only in S-SRAM during unlock.

**Key files:** `secure/src/crypto.rs`, `secure/src/ui/seed_wizard.rs`, `bip39/`.

### Firmware Measurement (Measured Boot)

At every boot, the secure world SHA-256 hashes its own flash image and displays the first 88 bits as 8 BIP-39 words on the OLED. Host companion tool: `cargo run -p fwmeasure -- <firmware.elf>`.

**Key files:** `secure/src/measured_boot.rs`, `fwmeasure/src/main.rs`.

### ERC-4337 Smart Contracts (`contracts/smart-wallet/`)

Pure-PQ account-abstraction wallet on EntryPoint v0.9.

**Key files:**
- `src/PQJardinWallet.sol` — validates Type 1 + Type 2 signatures, stores `jardinSlots` mapping.
- `src/PQJardinWalletFactory.sol` — CREATE2 factory. Salt = `sha256(masterPkSeed || masterPkRoot)` (the CREATE2 opcode itself still keccak256-hashes `0xff || addr || salt || keccak256(initCode)`; we only control the salt preimage).
- `src/PQOwnable.sol` — minimal storage helper (`jardinSlots` mapping only).
- `src/verifiers/SPHINCsC11Asm.sol` — stateless Yul C11 verifier.
- `src/verifiers/JardinForsCVerifier.sol` — stateless Yul FORS+C verifier.

**Cross-cutting invariants:**
- No classical signer path anywhere in the contract.
- Master C11 keys immutable after construction.
- Wire formats consumed here MUST match the firmware's output byte-for-byte.

## Build and Test

```bash
make play              # Interactive: drive wallet with arrow keys in QEMU
make run               # Non-interactive smoke test (QEMU, mock SE)
make e2e               # Automated end-to-end: unified JARDÍN sign (QEMU)
make e2e-hw            # End-to-end on real STM32U585 via ST-LINK + probe-rs
make measure           # Build firmware + print 8 BIP-39 measurement words
cd contracts/smart-wallet && forge test -vv
cargo test -p sphincs-tz-secure --tests --release
```

**Feature flags** (in `secure/Cargo.toml`):
| Flag | Description |
|------|-------------|
| `mock-se` | Mock secure element in SRAM (default, QEMU) |
| `se050` | Real SE050 via I2C + SCP03 |
| `optiga-trust-m` | Real OPTIGA Trust M V3 via I2C + IFX I2C + Shielded Connection |
| `tropic01-se` | Real Tropic01 via SPI (standalone only, not used in dual-SE) |
| `dual-se` | Both SEs active with XOR entropy split (implies `optiga-trust-m` + `se050`) |
| `debug-log` | Semihosting debug output (NEVER in production) |
| `e2e-test` | Non-interactive scripted test mode (NEVER ship) |
| `ui-semihosting` | Console UI (QEMU) |
| `ui-oled` | SSD1306 I2C OLED (hardware) |
| `stm32u585` | Real hardware target (vs QEMU mps2-an505) |

**Targets:** `thumbv8m.main-none-eabi` (both worlds). Release profile: `opt-level = "s"`, LTO, `codegen-units = 1`, `overflow-checks = true`. The `sphincs-c7`, `jardin-fosc`, `sha2`, and `hmac` crates are always `opt-level = 3` (SHA-256 is the hot inner loop).

## Code Conventions

- `#![no_std]`, no heap, no allocator. Stack-only allocation.
- `zeroize` crate with `ZeroizeOnDrop` on every secret type. Compiler fences around zeroization.
- `subtle` crate for constant-time comparisons. No secret-dependent branches.
- Every `unsafe` block has a `// SAFETY:` comment.
- `#![deny(unsafe_op_in_unsafe_fn)]`, `#![warn(clippy::pedantic)]`.
- NS pointer validation on every gateway call before any dereference.
- Shared types between worlds: `shared/src/lib.rs` with `#[repr(C)]`.
- Secret types are `!Copy` and `!Clone` (prevent silent duplication).

## Recovery contract (post-SHA-256 cutover)

- **BIP-39 → seed**: PBKDF2-HMAC-SHA512, 2048 iters, empty passphrase (standard).
- **Seed → C11 master**: `HMAC-SHA512("sphincs-c6-v1", bip39_seed)` (note the C6 tag — historical, do NOT modernise), then:
  - `masterPkSeed = sha256("pk_seed" || master[0..32]) & N_MASK` (top 16 bytes kept, bottom 16 zero)
  - `masterSkSeed = sha256("sk_seed" || master[0..32])`
  - `masterPkRoot = sphincs_c7::SigningKey::keygen(masterSkSeed, masterPkSeed[..16]).pk_root()`
- **Seed → JARDÍN master entropy**: `sha256("pqwallet-jardin-master" || bip39_seed)`.
- **Master entropy → slot entropy**: `sha256(master || "jardin_slot" || slot_index_be)`.
- **Master entropy → r**: `sha256(master || "jardin_r" || slot_index_be)`.
- **Slot entropy → sub-key**: `jardin_fosc::hash::jardin_derive_keys(slot_entropy)` (domain tags `"jardin_sub_v1"`, `"jardin_pk_seed"`, `"jardin_sk_seed"`).
- **On-chain wallet address**: `CREATE2(factory, salt = sha256(masterPkSeed || masterPkRoot), creationCode_hash)`. Same on every chain. (The CREATE2 opcode itself hashes `0xff || factory || salt || keccak256(initCode)` with keccak256 — that's fixed by the EVM and cannot change; we only control the salt preimage.)

## Key File Map

| Path | Purpose |
|------|---------|
| `secure/src/main.rs` | Secure world entry: SAU → provision → unlock → boot NS |
| `secure/src/crypto.rs` | BIP-39, C11 master derivation, JARDÍN master entropy, AES-GCM wrap, PIN state |
| `secure/src/nsc/mod.rs` | NSC gateway dispatcher (6 commands) |
| `secure/src/nsc/state.rs` | SecureState singleton (pin_verified, master_secret, JARDIN slot cache) |
| `secure/src/nsc/cmd_sign_userop.rs` | **The unified JARDÍN Type 1 / Type 2 state machine** |
| `secure/src/nsc/cmd_request_unlock.rs` | PIN entry + dual-SE unlock |
| `secure/src/nsc/cmd_get_jardin_slot_info.rs` | Query the latest persisted `SlotState` |
| `secure/src/nsc/jardin_flash.rs` | Slot-state persistence in secure flash pages 123-124 |
| `secure/src/aa/userop.rs` | EntryPoint v0.9 PackedUserOperation hashing + v0.6 legacy |
| `secure/src/aa/init_code.rs` | First-deploy initCode construction |
| `secure/src/tx/eip1559.rs` | EIP-1559 envelope parser (used only for trusted-UI display) |
| `secure/src/tx/display/` | Trusted-UI page renderers |
| `secure/src/erc20.rs` | Minimal ERC-20 calldata decoder for display |
| `secure/src/optiga/*` | OPTIGA Trust M driver + Shielded Connection |
| `secure/src/se050/*` | SE050 driver + SCP03 |
| `secure/src/dual_se.rs` | XOR entropy split across OPTIGA + SE050 |
| `secure/src/measured_boot.rs` | Boot-time firmware SHA-256 hash → 8 BIP-39 words on OLED |
| `nonsecure/src/main.rs` | Non-secure world entry (USB or interactive demo) |
| `nonsecure/src/nsc_api.rs` | NS-side gateway caller (6 commands) |
| `nonsecure/src/usb/commands.rs` | APDU v2 command router (7 INS codes) |
| `nonsecure/src/e2e_test.rs` | Non-interactive end-to-end test runner |
| `shared/src/lib.rs` | Cross-world types: NscStatus, CMD constants, wire-format sizes |
| `jardin-fosc/*` | FORS+C signing library (no_std, SHA-256) |
| `sphincs-c7/*` | C11 master-key signing library (no_std, SHA-256; name historical) |
| `secure/src/hw/hash.rs` | STM32U585 HASH peripheral driver — `pqsigner_sha256_*` extern fns consumed by the signing crates under `hw-sha256` |
| `bip39/*` | 24-word English BIP-39 (no_std) |
| `fwmeasure/*` | Host-side firmware measurement tool |
| `contracts/smart-wallet/src/PQJardinWallet.sol` | On-chain ERC-4337 v0.9 account |
| `contracts/smart-wallet/src/PQJardinWalletFactory.sol` | CREATE2 factory |
| `contracts/smart-wallet/src/verifiers/SPHINCsC11Asm.sol` | Type 1 verifier |
| `contracts/smart-wallet/src/verifiers/JardinForsCVerifier.sol` | Type 2 verifier |
| `tools/webhid_test.html` | Browser companion: sign via WebHID |
| `Makefile` | Build orchestration |
| `docs/architecture.md` | Detailed technical architecture |
| `docs/HARDENING.md` | Side-channel + fault hardening requirements |
| `docs/se050-userid-pin-auth.md` | SE050 PIN auth design |
| `docs/rewrite_phases/` | Phase-by-phase cutover notes |

## What NOT To Do

- **Do not add a classical (secp256k1, P-256, Ed25519) transaction signer.** The wallet is PQ-only by design. The on-chain contract has no classical verifier path.
- **Do not store secrets in non-secure world.** No PIN buffers, no entropy, no keys. Not even "temporarily".
- **Do not compare PINs in firmware.** The SE hardware does the comparison. Firmware only passes the stretched PIN to the SE's auth mechanism.
- **Do not transmit plaintext secrets over I2C/SPI.** Everything goes through the encrypted session (Shielded Connection, SCP03, or Noise_KK1). The planned ML-KEM inner wrap adds a PQ layer on top.
- **Do not store full entropy on a single chip.** Each chip gets exactly one XOR half.
- **Do not add heap allocation.** `#![no_std]`, no alloc, stack-only. No `Vec`, no `Box`, no `String`.
- **Do not use software PRNG.** All randomness from hardware TRNG (STM32 TRNG in production, semihosting `/dev/urandom` on QEMU).
- **Do not change the key derivation domain tags** (`"sphincs-c6-v1"`, `"pk_seed"`, `"sk_seed"`, `"pqwallet-jardin-master"`, `"jardin_slot"`, `"jardin_r"`, `"jardin_sub_v1"`, `"jardin_pk_seed"`, `"jardin_sk_seed"`) — they are part of the recovery contract.
- **Do not release Type 2 bytes to NS before flash-writing the incremented `next_q`.** Rollback attack defense: FORS+C security degrades sharply under q reuse.
- **Do not skip the verify-before-release check** on Type 1 or Type 2 signatures. Fault-injection guard.
- **Do not add a `rotateMasterKeys` function** to the wallet contract — would break the recovery contract.
- **Do not let NS world control the inactivity timer.** Timer runs on Secure-only TIM. NS pings do not reset it. Only real button presses on S-world confirm dialogs count as activity.
- **Do not add `debug-log` or `e2e-test` features to production builds.** CI must gate on this.

## Work Tracking

After completing any implementation task, check `docs/work-todo.md` to see if the work corresponds to a tracked item. If it does, mark the relevant checkbox(es) as done and add a row to the Completion Log table at the bottom with the date and a one-line summary.

## Deep-Dive Docs

- `README.md` — Complete architecture, threat model, quantum threat analysis, security model, implementation status, shipping checklist.
- `docs/architecture.md` — Detailed technical architecture.
- `docs/HARDENING.md` — Side-channel and fault-injection hardening requirements.
- `docs/se050-userid-pin-auth.md` — SE050 UserID PIN authentication design.
- `docs/dev-board-setup.md` — B-U585I-IOT02A devkit setup.
- `docs/hardware_requirements.md` — BOM and hardware requirements.
- `docs/rewrite_phases/` — Phase-by-phase cutover notes (this refactor).
