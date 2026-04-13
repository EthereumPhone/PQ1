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
- **Post-quantum firmware signing** — A custom OEMiROT verifies every secure-world and non-secure-world image with **ML-DSA-65 (FIPS 204) + Ed25519 hybrid**. Both signatures must verify; the classical leg is a transitional safety net while ML-DSA matures. *(Not yet implemented — target for STM32 bring-up.)*
- **Post-quantum confidentiality of all SE traffic** — both halves of the entropy are **ML-KEM-1024-encapsulated + AES-256-GCM-sealed** *before* they ever touch the I²C bus. The classical Shielded Connection / SCP03 layers carry only opaque ciphertext. *(Inner-wrap layer not yet implemented — target for STM32 bring-up.)*
- **TrustZone isolation** — signing key, PIN state, ML-KEM secret key, and crypto ops confined to the secure world. *(On real STM32U585 silicon the six-command gateway runs through proper ARMv8-M CMSE `cmse-nonsecure-entry` veneers — exercised end-to-end under `make e2e-hw`. The QEMU mps2-an505 build uses a shared-memory mailbox + SysTick poll instead, as a workaround for a QEMU 8.2.2 MPC S-alias bug that breaks the SG instruction check.)*
- **Dual secure elements (split entropy)** — BIP-39 entropy is XOR-split across an Infineon OPTIGA Trust M V3 and an NXP SE050. Compromising either chip in isolation reveals **zero** bits of the seed. *(Fully implemented with dual-SE XOR split across OPTIGA Trust M and SE050. Both chips share I2C1 at addresses 0x30 and 0x48.)*
- **Boot-time attestation of both chips** — fresh nonce signed by each SE's factory attestation key, verified against pinned vendor roots and pinned per-device UIDs. The classical SE attestation is treated as *proof of presence*; the cryptographic root of device identity is the ML-DSA-signed device certificate pinned in HDPL1 OEMiROT at provisioning. *(Not yet implemented — both attestation paths and the ML-DSA device cert are target.)*
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
| **ML-DSA-65 + Ed25519 hybrid firmware signing OEMiROT** | ⏳ not started | requires custom OEMiROT (ST stock is RSA/ECDSA only) |
| **ML-DSA-65 device identity certificate pinned in HDPL1** | ⏳ not started | — |
| **Mixed-RNG entropy generation (TRNG ⊕ TRNG ⊕ TRNG)** | ⏳ not started | currently semihosting `/dev/urandom` under QEMU |
| **STM32 TRNG, HASH, SAES, TAMP, BOR, BKPSRAM peripheral drivers** | ⏳ not started | — |
| **GTZC configuration (S/NS peripheral attribution)** | ⏳ not started | — |
| **HUK-SAES key wrapping for at-rest secrets** | 🚫 blocked on hardware | HUK only exists on real silicon |
| **TAMP / BOR / inactivity wipe ISR on real silicon** | 🚫 blocked on hardware | — |
| **RDP Level 2 burn** | 🚫 blocked on hardware | irreversible — final production step |
| **Power-loss tests, fault-injection tests, side-channel tests** | 🚫 blocked on hardware | requires real silicon + lab access |

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
