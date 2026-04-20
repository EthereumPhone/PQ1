# PQSigner OS -- LLM Context

Post-quantum ERC-4337 hardware wallet. Target: **STM32U585 (Cortex-M33, TrustZone) + Infineon OPTIGA Trust M V3 + NXP SE050**. Every primitive protecting the seed is PQ or symmetric with >=256-bit keys. Signing is **SPHINCS+C10 only, everywhere** — pure post-quantum, no ECDSA, no classical fallback, no FORS+C. The wallet is an account-abstraction smart account that talks to EntryPoint v0.6 (Coinbase-Smart-Wallet-compatible).

Status: all-C10 cutover complete. Firmware boots on real B-U585I-IOT02A + QEMU mps2-an505. Both SE drivers (OPTIGA Trust M, SE050) working. Dual-SE XOR entropy split wired and tested. The `PQJardinWallet` smart-wallet is deployed via a deterministic CREATE2 factory whose salt is `sha256(masterPkSeed || masterPkRoot)`, so the same 24 words produce the same address on every chain. **SHA-256 everywhere:** every hash inside the PQ signing stack (bootstrap SPHINCS+C10, slot SPHINCS+C10, slot derivation, KDF, CREATE2 salt) is SHA-256, routed through the STM32U585 HASH peripheral on hardware. `sha3::Keccak256` is retained only for the external-standard hashes the EVM demands (EIP-4337 userOpHash, EIP-712, EIP-1559 envelope, ERC-7201 namespace, the CREATE2 address formula itself). **All-C10 slot cutover:** the per-slot user-tx signing key is now SPHINCS+C10 (same `h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205, sig=4008` parameter set as the bootstrap key). The stateful FORS+C slot scheme and its `next_q`-in-flash rollback guard are gone — C10 is stateless within its 2^18 signing-position capacity. Per-chain usage is capped by two monotonic on-chain counters on `PQJardinWallet`: `MAX_BOOTSTRAP_USES = 65_536` Type 1 slot registrations and `MAX_SLOT_USES = 65_536` Type 2 signatures per slot. Combined: each chain can service up to 65,536 × 65,536 ≈ 2^32 user transactions before it becomes permanently frozen — well inside the C10 birthday-style safety margin. **Firmware is stateless with respect to slot selection** (the companion app supplies `(chain_id, slot_index, flags)` on every sign); no flash slot store, no recovery state machine inside the secure world.

## Development Posture (read first)

**The project is in pre-production development, not hardening.** The end-to-end system — wizard, unlock, SPHINCS+C10 signing, JARDÍN slot derivation, NS USB HID, on-chain contracts — is being brought up on real STM32U585 hardware for the first time on this branch. Breadth-first bring-up takes priority over tightening every security boundary on every commit. The eventual hardening pass will happen later on a separate branch; until then:

- **Known regressions from hardening are acceptable** when they block bring-up. For example, `secure/src/sau.rs` currently clears GTZC1_TZSC_SECCFGR{1,2,3} to 0 (everything NS) because the "CRIT-4 all-secure baseline" patch mis-identified which controller governs USB OTG FS on STM32U585 — USB OTG FS is AHB2, governed by a separate **GTZC2_TZSC** block whose base address we have not yet confirmed (our first guess at `0x5203_4400` bus-faulted). This makes peripherals like I2C1 / AES / HASH / PKA / SAES / RNG reachable from NS — a **pre-production regression of invariant #4 below**. Restoring the invariant is a tracked TODO, not a reason to revert working USB bring-up.
- **Debug instrumentation may ship in this branch.** `debug-log` is allowed on hardware release builds (the `compile_error!` gate in `secure/src/nsc/mod.rs` was removed), `hw::hash::init_clock`'s semihosting prints are `DHCSR.C_DEBUGEN`-gated rather than removed, `secure_log!` calls litter the first-boot wizard, and the NS `main()` emits pre-USB register dumps. These are kept for continued bring-up and must be cleaned up before production. CI must still gate shipped firmware on `debug-log` / `e2e-test` / `mock-se` being OFF.
- **Invariants below describe the eventual production contract, not the current branch state.** When a task touches an invariant-adjacent subsystem (TZSC allowlist, gateway command surface, SE provisioning, key derivation), respect the invariant; when a task is pure bring-up wiring (clocks, GPIO, peripheral-init order, TCPP03 / UCPD pin config), prioritise getting the stack to light up over invariant preservation and note the regression here.

## Non-Negotiable Invariants

**Production contract — every shipping build must respect ALL of these. Violating any one is a critical security bug in production; pre-production bring-up may violate individual items with an entry in the "Development Posture" section above.**

1. **Dual-chip seed split.** BIP-39 entropy is XOR-split: `half_O` on OPTIGA Trust M, `half_E` on SE050. Neither chip alone reveals any bit of the seed. Code that stores the full entropy on a single chip, or transmits one half to the other chip, breaks the design.

2. **Hardware-level PIN gating.** The PIN decision is made by the secure element silicon, never by MCU firmware. SE050 uses UserID auth (object `0x7B06_0000`, max 10 attempts, hardware constant-time comparison). OPTIGA Trust M uses hardware-enforced authorization references (OID `0xF1D0`, access conditions enforced by chip silicon). Firmware that compares PINs in software, or bypasses the SE's auth gate to read secrets, breaks the design.

3. **E2E encrypted tunnel between TrustZone secure world and each SE.** OPTIGA Trust M: Shielded Connection (TLS-PRF + AES-128-CCM-8) per session; Platform Binding Secret stored in secure flash page 126. SE050: SCP03 (AES-CMAC + AES-CBC) authenticated+encrypted channel. Planned: ML-KEM-1024 inner wrap so even a CRQC break of the classical channels reveals only opaque PQ ciphertext. No plaintext secret ever touches the I2C bus.

4. **All secrets live ONLY in TrustZone secure world.** Non-secure world never sees a PIN digit, entropy byte, signing key, or derived secret. The NSC gateway exposes only opaque commands (unlock, sign, status) that return non-secret data. Pointer validation on every call. TOCTOU defense: NS buffers copied to secure stack before parsing.

5. **One signature primitive, post-quantum only.** SPHINCS+C10 signs both Type 1 (bootstrap slot registration) and Type 2 (per-slot user tx) — no FORS+C, no classical signer (secp256k1, P-256, Ed25519) anywhere. The on-chain wallet contract has a single `c10Verifier` wired to both dispatch paths; there is no classical verifier path.

6. **Bootstrap C10 keys are immutable.** The on-chain CREATE2 salt is `sha256(masterPkSeed || masterPkRoot)`. Rotating the bootstrap key would change the wallet address — seed recovery would land users at a different account. The factory has no `rotateMasterKeys` function, and there is no on-chain ownership model that could introduce one.

7. **Per-chain usage capped by two monotonic counters.** `PQJardinWallet.bootstrapUses` is bumped on every accepted Type 1 and checked against `MAX_BOOTSTRAP_USES = 65_536`; `slotUses[slotKey]` is bumped on every accepted Type 2 and checked against `MAX_SLOT_USES = 65_536`. Both caps are well inside the C10 `h=18` tree's 2^18 = 262,144 signing positions, leaving a conservative birthday-style safety margin. A chain that hits the bootstrap cap can still sign Type 2 on already-registered slots (until each slot hits its own cap); once a slot's `slotUses` is at the cap, the companion rotates to `slot_index + 1` via a new Type 1. A chain whose bootstrap cap is exhausted AND whose last-registered slot is also exhausted is permanently frozen — the companion surfaces this as an irrecoverable per-chain freeze. There is no `resetBootstrapUses` / `resetSlotUses` path anywhere in the contract.

8. **Firmware is stateless with respect to slot selection.** The companion app supplies `(chain_id, slot_index, flags)` on every `CMD_SIGN_USEROP`; the secure world keeps zero flash state about which chain has registered which slot. Slot keys are deterministically re-derived from `(master_entropy, slot_index)` on demand and cached in SRAM across the unlock session only. This replaces the pre-cutover FORS+C `next_q` persistence invariant — SPHINCS+C10 is stateless within its tree capacity, so per-signature flash writes are not required.

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
                                           |       |       +-- sphincs_c10::SigningKey::keygen(...)             -> masterPkRoot
                                           |       |              (C10 hypertree, rebuilt on every Type 1)
                                           |       |
                                           |       +--- sha256("pqwallet-jardin-master" || bip39_seed)  -> jardin_master_entropy
                                           |                                                                        |
                                           |       jardin_slot_entropy(master, slot_idx) = sha256(master||"jardin_slot"||slot_idx)
                                           |       jardin_slot_r(master, slot_idx)        = sha256(master||"jardin_r"||slot_idx)
                                           |                                                                        |
                                           |       slot_sk_seed = sha256("jardin_slot_c10_sk_seed" || slot_entropy)
                                           |       slot_pk_seed = sha256("jardin_slot_c10_pk_seed" || slot_entropy) & N_MASK
                                           |       sphincs_c10::SigningKey::keygen(slot_sk_seed, slot_pk_seed)      -> slot C10 keypair
                                           |              (cached in SRAM across the unlock session; no flash state)
                                           |                                                                        |
                                           |       Type 1: C10-sign(master_sk, userOpHash_t1) -> 4008-byte C10 sig
                                           |       Type 2: C10-sign(slot_sk,   userOpHash_t2) -> 4008-byte C10 sig
                                           |
                                           +--[NSC gateway, 5 cmds]---> NON-SECURE WORLD
                                                                         companion drives
                                                                         (chain_id, slot_index, flags)
                                                                         UI, USB, APDU routing
                                                                         no secrets, ever
```

**Gateway commands** (see `sphincs_tz_shared::CMD_*`):

| CMD | Name | What it does |
|-----|------|--------------|
| 1 | GET_REMAINING | Return remaining PIN attempts |
| 2 | REQUEST_UNLOCK | S-world prompts PIN via trusted UI, unlocks both SEs |
| 7 | SIGN_USEROP | **The one sign command.** Parses input header + inner tx, reads flags for `FLAG_INCLUDE_INIT_CODE` and `FLAG_REGISTER_SLOT`, emits `[init_code_len | ic | type1_len | t1 | type2_len | t2]` bundle. `type1_len == 0` means the companion did not request a slot registration this call. |
| 11 | IS_UNLOCKED | Returns 1/0 |
| 12 | LOCK | Zeroize cached secrets |

**Lifecycle:** Boot → SAU/GTZC config → (attest both SEs) → PIN entry in S-world → unlock both SEs → reconstruct seed in S-SRAM → active signing window (120s idle timeout) → zeroize on lock/tamper/brownout/inactivity.

## Signing state machine (post-all-C10 cutover)

Companion-driven — the firmware inspects the flags field and nothing else:

```
                ┌──────────────────────────────────────┐
                │ parse flags, chain_id, slot_index    │
                └──────────────────┬───────────────────┘
                                   │
               ┌───────────────────┴────────────────────┐
               ▼                                        ▼
      FLAG_REGISTER_SLOT = 1                FLAG_REGISTER_SLOT = 0
      │                                     │
      ▼                                     ▼
  (re)keygen slot C10 if not cached     (re)keygen slot C10 if not cached
  C10-sign(master_sk, t1_hash)          C10-sign(slot_sk,   t2_hash)
  C10-sign(slot_sk,   t2_hash)          emit Type 2 only (4073 bytes)
  emit Type 1 (4073) + Type 2 (4073)
```

No flash I/O. No `next_q`. No mode enum. The SRAM slot cache is keyed
purely on `slot_index` (slot derivation is chain-agnostic), so hopping
between chains with the same slot index skips re-keygen.

## Wire formats (frozen — on-chain verifier depends on them)

### Unified sign input (NSC + USB)

```
offset  size  field
---------------------------------------------------------
  0     8    chain_id (u64 BE)
  8     4    flags (u32 BE: bit 31 = FLAG_INCLUDE_INIT_CODE,
                              bit 30 = FLAG_REGISTER_SLOT,
                              bits 29..22 = account_index (8 bits, 0..=255),
                              bits 21..0  = slot_index    (22 bits))
 12    20    sender (PQSmartWallet address)
 32    20    entry_point (EntryPoint v0.6 address)
 52    32    nonce (u256 BE, base nonce for the first UserOp in the bundle)
 84    32    call_gas_limit (u256 BE)
116    32    verification_gas_limit (u256 BE)
148    32    pre_verification_gas (u256 BE)
180    32    max_fee_per_gas (u256 BE)
212    32    max_priority_fee_per_gas (u256 BE)
244    32    paymaster_and_data_hash (sha256, SHA256_EMPTY when empty)
276    20    to_address (inner tx recipient)
296    32    value (u256 BE)
328     2    data_len (u16 BE, 0..=4096)
330     N    data
```

### Unified sign output

```
[type1_len(4 BE)][type1_bytes...][type2_len(4 BE)][type2_bytes...]
```

- `type1_bytes` (exactly 4073 bytes when present):
  `[0x01][r(32)][subPkSeed(16)][subPkRoot(16)][C10_sig(4008)]`

- `type2_bytes` (fixed 4073 bytes):
  `[0x02][H(r)(32)][subPkSeed(16)][subPkRoot(16)][C10_sig(4008)]`

### On-chain validation

`PQJardinWallet.validateUserOp` dispatches on `sig[0]`:
- `0x01` → check `bootstrapUses < MAX_BOOTSTRAP_USES` (= 65,536), verify bootstrap C10 sig over `userOpHash`, record `slots[sha256(r)] = sha256(subPkSeed || subPkRoot)`, then bump the counter and emit `BootstrapKeyUsed(newCount)`.
- `0x02` → look up `slots[slotKey]`, check sub-key commitment matches, check `slotUses[slotKey] < MAX_SLOT_USES` (= 65,536), verify slot C10 sig via the same `c10Verifier`, bump `slotUses[slotKey]` and emit `SlotKeyUsed(slotKey, newCount)`. (Does NOT touch `bootstrapUses` — Type 2 keeps working after the bootstrap cap is hit, up to each slot's own `MAX_SLOT_USES`.)

## Subsystem Guides

### SPHINCS+C10 signing (`sphincs-c10/`)

Implements **C10** (W+C_F+C, h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205, sig=4008). Same primitive for bootstrap Type 1 *and* per-slot Type 2 after the all-C10 cutover. The 2^18-leaf hypertree holds ~262K positions per key; the on-chain counters (`MAX_BOOTSTRAP_USES` + `MAX_SLOT_USES`, both 65,536) cap real-world usage so every key stays deep inside its birthday-style safety margin.

**Key files:**
- `sphincs-c10/src/lib.rs` — `SigningKey::keygen`, `SigningKey::sign`, `verify`.
- `sphincs-c10/src/hypertree.rs`, `wots.rs`, `fors.rs`, `merkle.rs`, `address.rs`, `hash.rs`, `params.rs`.
- `sphincs-c10/tests/gen_test_vectors.rs` — emits `contracts/smart-wallet/test/c10_test_vectors.json` for the Foundry smoketest.

**Cross-cutting invariants:**
- Output matches `SPHINCsC10Asm.sol` (Yul-optimised Solidity verifier) byte-for-byte.
- 4,008-byte signature.
- `SigningKey` is `ZeroizeOnDrop`; never leaves secure SRAM. Slot keys are cached in the `JARDIN_SLOT: Option<CachedSlot>` static (SRAM only) and dropped on lock / idle-wipe / panic.
- Slot-key derivation: `slot_entropy = sha256(master_entropy || "jardin_slot" || slot_index_be)`, then `(sk_seed, pk_seed) = (sha256("jardin_slot_c10_sk_seed" || slot_entropy), sha256("jardin_slot_c10_pk_seed" || slot_entropy) & N_MASK)`, then `SigningKey::keygen(sk_seed, pk_seed[..16])`.

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

### Firmware Update (Hash-Signature PQ Model)

End-to-end firmware-update pipeline: vendor signs a 75-byte preimage (`"PQFW_V1" || fw_version_be || secure_hash || nonsecure_hash`) with their SPHINCS+C10 private key; an immutable FSBL at `0x0C00_0000` verifies the same preimage against the compiled-in vendor public key and picks the higher-version valid A/B slot to boot. Companion updater app streams the new release to the device over USB HID; on COMMIT the device re-hashes what it wrote, shows the new measurement words on the OLED, waits for long-right confirm, bumps the OTP rollback floor, and resets. **Signature chain is PQ end-to-end** (SPHINCS+C10 + SHA-256) — a CRQC that breaks ECDSA does not forge updates. Sign preimage is reconstructable from `(version, secure.elf, nonsecure.elf)` alone, so any auditor can rebuild + verify via `fwsign verify-release` without parsing a manifest. See `docs/firmware-update.md` for the full spec and `docs/reproducible-builds.md` for the verification recipe.

**Key files:**
- `fw-manifest/src/lib.rs` — wire-format + parser + CRC + verify chain (shared by FSBL, secure, fwsign)
- `fsbl/src/*.rs` — 18 KB immutable bootloader (no_std, PQ verify, slot selector)
- `fwsign/src/*.rs` — host-side signer + independent verifier
- `secure/src/fw_update/*.rs` — streaming state machine (BEGIN → CHUNK* → COMMIT)
- `secure/src/hw/{flash,otp,boot_state}.rs` — bank-2 writes, OTP rollback fuses, boot-state page
- `secure/src/nsc/cmd_fw_*.rs` — five NSC commands + CMSE veneers

**Cross-cutting invariants:**
- **PIN unlock required on every CMD_FW_\*.** Wallet seed never accessed during update, but the unlock gate prevents silent re-flashing of a stolen locked device.
- **FSBL is immutable after provisioning** (WRP1A on pages 0–3 before RDP-2 burn). Any FSBL bug → device replacement.
- **Anti-rollback via OTP fuses**, not flash. 32 × 32-bit tally = 1024 increments, survives RDP regression.
- **Signed preimage binds version + two image hashes; nothing else.** Slot identifier, vendor fingerprint, build_id, lengths are unsigned metadata — one `.pqfw` installs into either A or B.
- **No classical crypto in the signature path.** SPHINCS+C10 + SHA-256 only. Argon2id + XChaCha20-Poly1305 appear only in the vendor's at-rest SK blob, never in the verification path.

### ERC-4337 Smart Contracts (`contracts/smart-wallet/`)

Pure-PQ account-abstraction wallet on EntryPoint v0.6.

**Key files:**
- `src/PQJardinWallet.sol` — validates Type 1 + Type 2 signatures, stores `jardinSlots` + `slotUses` mappings, enforces `MAX_BOOTSTRAP_USES = 65_536` and `MAX_SLOT_USES = 65_536`.
- `src/PQJardinWalletFactory.sol` — CREATE2 factory. Salt = `sha256(masterPkSeed || masterPkRoot)` (the CREATE2 opcode itself still keccak256-hashes `0xff || addr || salt || keccak256(initCode)`; we only control the salt preimage).
- `src/PQOwnable.sol` — minimal storage helper (`jardinSlots` mapping + `bootstrapUses` counter + `slotUses` mapping) plus `_bumpBootstrapUses(cap)` and `_bumpSlotUses(slotKey, cap)`.
- `src/verifiers/SPHINCsC10Asm.sol` — stateless Yul C10 verifier (SHA-256 precompile). Used for both Type 1 and Type 2 verification; the wallet holds a single `c10Verifier` immutable and calls it with different `(pk_seed, pk_root)` for each dispatch path.

**Cross-cutting invariants:**
- No classical signer path anywhere in the contract.
- Bootstrap C10 keys immutable after construction.
- `bootstrapUses` and every `slotUses[slotKey]` monotonically increase; no reset path anywhere in the contract or factory.
- Wire formats consumed here MUST match the firmware's output byte-for-byte.

## Build and Test

```bash
make play              # Interactive: drive wallet with arrow keys in QEMU
make run               # Non-interactive smoke test (QEMU, mock SE)
make e2e               # Automated end-to-end: unified JARDÍN sign (QEMU)
make e2e-hw            # End-to-end on real STM32U585 via ST-LINK + probe-rs
make play-hw-display   # Interactive OLED + arrow-key forwarding on hardware
make test-key-speed    # Fully-automated DWT-timed signing bench on hardware
make measure           # Build firmware + print 8 BIP-39 measurement words
cd contracts/smart-wallet && forge test -vv
cargo test -p sphincs-tz-secure --tests --release
```

### Hardware testing under probe-rs — what actually works

`probe-rs` does **not** implement semihosting op `0x07` (`SYS_READC`). Any
firmware build that reaches a `ui-semihosting` keyboard prompt on real
hardware will hang in the polling loop, with probe-rs emitting a storm of
`Target wanted to run semihosting operation 0x7 ... but probe-rs does not
support this operation yet` warnings. This hits `make e2e-hw` because the
NS-side test driver still calls `CMD_REQUEST_UNLOCK` even when the secure
world has already been pre-unlocked by the `e2e-test` feature — and the
PIN entry dialog uses `SYS_READC`. QEMU doesn't trip this because
`qemu-system-arm`'s semihosting chardev is wired to stdin.

Three ways around it, in order of usefulness:

1. **`make test-key-speed`** — the automated signing benchmark. Does no
   semihosting reads, prints `=== PASS ===` on completion. With
   `hw-sha256` active (implied by `stm32u585`), after the all-C10 slot
   cutover expect roughly: first-sign ≈ 13 s (master C10 keygen + slot
   C10 keygen + two C10 signs), Type-2-only on cached slot ≈ 1.1 s,
   second-chain first-sign with cached slot ≈ 7.5 s (master keygen + two
   signs, slot cache hit). Any number substantially higher than these
   means the HASH peripheral isn't being used.
2. **`make play-hw-display`** — interactive wallet on real OLED. Uses
   `tools/wallet_run_hw.py` to forward arrow keys through a probe-rs
   `print`-based handshake, not `SYS_READC`. Works end-to-end.
3. **QEMU**: `make e2e` or `make play`. Fully exercised by CI and the
   default dev loop; only real hardware has the probe-rs gap.

### HW SHA-256 self-test (boot-time)

`hw::hash::init_clock()` runs `SHA-256("abc")` as a known-answer test
and halts the CPU in `loop { wfe() }` on mismatch. You'll always see
one of two lines early in boot:

```
[S] hash: HW SHA-256 self-test PASS   ← accelerator healthy, signing proceeds
[S] hash: HW SHA-256 self-test FAIL — HALT   ← CPU parks; no signing will happen
```

Silent failure is impossible — if the `PASS` line is there, the HASH
peripheral is producing correct digests, so any downstream hang is
unrelated to the cutover.

**Feature flags** (in `secure/Cargo.toml`):
| Flag | Description |
|------|-------------|
| `mock-se` | Mock secure element in SRAM (default, QEMU) |
| `se050` | Real SE050 via I2C + SCP03 |
| `optiga-trust-m` | Real OPTIGA Trust M V3 via I2C + IFX I2C + Shielded Connection |
| `tropic01-se` | Real Tropic01 via SPI (standalone only, not used in dual-SE) |
| `dual-se` | Both SEs active with XOR entropy split (implies `optiga-trust-m` + `se050`) |
| `debug-log` | Semihosting debug output (NEVER in production) |
| `e2e-test` | Non-interactive scripted test mode (NEVER ship). Pre-provisions a fixed mnemonic + PIN, short-circuits every secure-side `confirm()` / `enter_pin()`. NS-side runners may still call `CMD_REQUEST_UNLOCK` — harmless in QEMU, stalls under probe-rs. |
| `ui-semihosting` | Console UI (QEMU or probe-rs `print`-forwarded; `SYS_READC` only works under QEMU) |
| `ui-oled` | SSD1306 I2C OLED (hardware) |
| `stm32u585` | Real STM32U585 hardware (vs QEMU mps2-an505). **Implies `hw-sha256`** — every hardware build routes SHA-256 through the HASH peripheral automatically. |
| `hw-sha256` | Route `sphincs-c10` SHA-256 calls through the `pqsigner_sha256_*` extern fns in `secure/src/hw/hash.rs`. Pulled in transitively by `stm32u585`; never needed by itself on host/QEMU. |

**Targets:** `thumbv8m.main-none-eabi` (both worlds). Release profile: `opt-level = "s"`, LTO, `codegen-units = 1`, `overflow-checks = true`. The `sphincs-c10`, `sha2`, and `hmac` crates are always `opt-level = 3` (SHA-256 is the hot inner loop on host / fallback builds; on device the HASH peripheral handles it in one cycle/byte).

## Code Conventions

- `#![no_std]`, no heap, no allocator. Stack-only allocation.
- `zeroize` crate with `ZeroizeOnDrop` on every secret type. Compiler fences around zeroization.
- `subtle` crate for constant-time comparisons. No secret-dependent branches.
- Every `unsafe` block has a `// SAFETY:` comment.
- `#![deny(unsafe_op_in_unsafe_fn)]`, `#![warn(clippy::pedantic)]`.
- NS pointer validation on every gateway call before any dereference.
- Shared types between worlds: `shared/src/lib.rs` with `#[repr(C)]`.
- Secret types are `!Copy` and `!Clone` (prevent silent duplication).

## Recovery contract (post-all-C10 cutover, multi-account)

A single seed phrase produces **256 independent on-chain wallets**, indexed
by `account_index ∈ [0, 255]` (BIP-44-style accounts). Account 0 reproduces
the legacy single-account derivation **byte-for-byte** so pre-multi-account
seeds keep their existing wallet address. Accounts 1..=255 use new
domain-tagged KDFs that fold the index into the master entropy.

- **BIP-39 → seed**: PBKDF2-HMAC-SHA512, 2048 iters, empty passphrase (standard).
- **Seed → C10 bootstrap master** (per `account_index`):
  - `account_index == 0`: `master = HMAC-SHA512("sphincs-c6-v1", bip39_seed)` (note the C6 tag — historical, do NOT modernise).
  - `account_index > 0`: `master = HMAC-SHA512("sphincs-c6-v1-acct", bip39_seed || account_index_be4)`.
  - In both cases, then:
    - `masterPkSeed = sha256("pk_seed" || master[0..32]) & N_MASK` (top 16 bytes kept, bottom 16 zero)
    - `masterSkSeed = sha256("sk_seed" || master[0..32])`
    - `masterPkRoot = sphincs_c10::SigningKey::keygen(masterSkSeed, masterPkSeed[..16]).pk_root()` (C10: h=18 top-layer subtree, 512 WOTS leaves)
- **Seed → JARDÍN master entropy** (per `account_index`):
  - `account_index == 0`: `sha256("pqwallet-jardin-master" || bip39_seed)`.
  - `account_index > 0`: `sha256("pqwallet-jardin-master-acct" || bip39_seed || account_index_be4)`.
- **Master entropy → slot entropy**: `sha256(master || "jardin_slot" || slot_index_be)`.
- **Master entropy → r**: `sha256(master || "jardin_r" || slot_index_be)`.
- **Slot entropy → slot C10 seeds**:
  - `slot_sk_seed = sha256("jardin_slot_c10_sk_seed" || slot_entropy)` (32 B, passed directly to `SigningKey::keygen`)
  - `slot_pk_seed_32 = sha256("jardin_slot_c10_pk_seed" || slot_entropy) & N_MASK` (top 16 B populated, bottom 16 B zero — the on-chain `bytes32` shape)
  - `slot_sk = sphincs_c10::SigningKey::keygen(slot_sk_seed, slot_pk_seed_32[..16])`; `slot_pk_root = slot_sk.pk_root()`
- **On-chain wallet address**: `CREATE2(factory, salt = sha256(masterPkSeed || masterPkRoot), creationCode_hash)`. Same on every chain *for a given `account_index`*. Different `account_index` ⇒ different `(masterPkSeed, masterPkRoot)` ⇒ different `salt` ⇒ different on-chain wallet — that's how one seed yields 256 wallets. (The CREATE2 opcode itself hashes `0xff || factory || salt || keccak256(initCode)` with keccak256 — that's fixed by the EVM and cannot change; we only control the salt preimage.) `account_index = 0` keeps the **same** wallet address as before the multi-account cutover.

## Key File Map

| Path | Purpose |
|------|---------|
| `secure/src/main.rs` | Secure world entry: SAU → provision → unlock → boot NS |
| `secure/src/crypto.rs` | BIP-39, C10 bootstrap derivation, C10 slot derivation, JARDÍN master entropy, AES-GCM wrap, PIN state |
| `secure/src/nsc/mod.rs` | NSC gateway dispatcher (5 commands) |
| `secure/src/nsc/state.rs` | SecureState singleton (pin_verified, master_secret, JARDIN slot C10 cache keyed on `slot_index`) |
| `secure/src/nsc/cmd_sign_userop.rs` | **The unified Type 1 / Type 2 all-C10 sign handler (stateless, companion-driven)** |
| `secure/src/nsc/cmd_request_unlock.rs` | PIN entry + dual-SE unlock |
| `secure/src/aa/userop.rs` | EntryPoint v0.6 `UserOperation` hashing + SHA-256 sphincs digest |
| `secure/src/aa/init_code.rs` | First-deploy initCode construction |
| `secure/src/tx/eip1559.rs` | EIP-1559 envelope parser (used only for trusted-UI display) |
| `secure/src/tx/display/` | Trusted-UI page renderers |
| `secure/src/erc20.rs` | Minimal ERC-20 calldata decoder for display |
| `secure/src/optiga/*` | OPTIGA Trust M driver + Shielded Connection |
| `secure/src/se050/*` | SE050 driver + SCP03 |
| `secure/src/dual_se.rs` | XOR entropy split across OPTIGA + SE050 |
| `secure/src/measured_boot.rs` | Boot-time firmware SHA-256 hash → 8 BIP-39 words on OLED |
| `nonsecure/src/main.rs` | Non-secure world entry (USB or interactive demo) |
| `nonsecure/src/nsc_api.rs` | NS-side gateway caller (5 commands) |
| `nonsecure/src/usb/commands.rs` | APDU v2 command router |
| `nonsecure/src/e2e_test.rs` | Non-interactive end-to-end test runner |
| `shared/src/lib.rs` | Cross-world types: NscStatus, CMD constants, wire-format sizes |
| `sphincs-c10/*` | SPHINCS+C10 signing library — powers both bootstrap and slot keys (no_std, SHA-256) |
| `secure/src/hw/hash.rs` | STM32U585 HASH peripheral driver — `pqsigner_sha256_*` extern fns consumed by `sphincs-c10` under `hw-sha256` |
| `bip39/*` | 24-word English BIP-39 (no_std) |
| `fwmeasure/*` | Host-side firmware measurement tool |
| `fw-manifest/*` | no_std firmware-update manifest format + verify chain (shared by FSBL, secure, fwsign) |
| `fwsign/*` | Host-side release-signing tool — `keygen`/`pubkey`/`sign`/`verify`/`verify-release`/`extract-sig`/`inspect` |
| `fsbl/*` | Immutable first-stage bootloader — vendor-C10-verified A/B slot selector |
| `secure/src/fw_update/*` | Firmware-update streaming state machine (BEGIN → CHUNK → COMMIT) |
| `secure/src/hw/otp.rs` | OTP rollback counter (1024 bits = 1024 commits, RDP-regression-resistant) |
| `secure/src/hw/boot_state.rs` | Boot-state page for try-once slot tracking |
| `secure/src/nsc/cmd_fw_*.rs` | Five NSC firmware-update handlers (begin / chunk / commit / status / abort) |
| `contracts/smart-wallet/src/PQSmartWallet.sol` | On-chain ERC-4337 v0.6 account (bootstrap ownerIndex 0 + slot ownerIndex ≥ 1 dispatch) |
| `contracts/smart-wallet/src/PQJardinWalletFactory.sol` | CREATE2 factory |
| `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol` | Stateless Yul C10 verifier — the wallet's single signature primitive |
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
- **Do not change the key derivation domain tags** (`"sphincs-c6-v1"`, `"sphincs-c6-v1-acct"`, `"pk_seed"`, `"sk_seed"`, `"pqwallet-jardin-master"`, `"pqwallet-jardin-master-acct"`, `"jardin_slot"`, `"jardin_r"`, `"jardin_slot_c10_sk_seed"`, `"jardin_slot_c10_pk_seed"`) — they are part of the recovery contract. The `-acct` variants are used only for `account_index > 0`; account 0 must continue to use the original tags so legacy seeds keep their on-chain address.
- **Do not skip the verify-before-release check** on Type 1 or Type 2 signatures. Fault-injection guard, double-evaluated with a sentinel.
- **Do not add a `rotateMasterKeys` function** to the wallet contract — would break the recovery contract.
- **Do not add a `resetBootstrapUses` / `resetSlotUses` / `increaseMax*` path** to the wallet or factory. Both counters are immutable monotonic and capped at 65,536 each by design. Once a chain fully exhausts its bootstrap cap AND all currently-registered slots, the chain stays exhausted — that is the invariant. A companion-side notice of impending exhaustion is fine; anything that touches the counters in the contract is not.
- **Do not reintroduce per-signature flash state.** The all-C10 slot cutover made the firmware stateless with respect to slot selection; any code that writes `next_q`-like counters to flash is a regression.
- **Do not let NS world control the inactivity timer.** Timer runs on Secure-only TIM. NS pings do not reset it. Only real button presses on S-world confirm dialogs count as activity.
- **Do not add `debug-log` or `e2e-test` features to production builds.** CI must gate on this.
- **Do not expand the signed firmware-update preimage.** It's intentionally the 75 bytes `"PQFW_V1" || fw_version_be || secure_hash || nonsecure_hash` so any auditor can reconstruct it from source. Adding slot/vendor-fpr/build_id into the preimage would break that property; if you think you need a new input in there, first question whether it can instead be derived or checked independently.
- **Do not introduce classical signatures into the firmware-update path.** Signer + verifier are SPHINCS+C10 end-to-end; SHA-256 is the only hash. Argon2id + XChaCha20-Poly1305 appear only in the *at-rest* vendor SK blob on the signing machine — never in what the device evaluates.
- **Do not add a classical-fallback firmware-update verifier.** The FSBL has one pubkey and one algorithm. A "just in case PQ is broken" fallback defeats the PQ property.
- **Do not add a "reset rollback floor" path.** OTP is one-way by design; exposing a reset would break anti-rollback. Devices that exhaust the 1024-bit OTP budget are end-of-life for updates — that's the contract.
- **Do not write to FSBL flash pages from runtime firmware.** Pages 0–3 are WRP1A-locked in production. Any code that attempts to program them silently fails (WRPERR) and is a regression to delete.

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
