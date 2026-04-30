# OPTIGA Trust M -- Rust Ecosystem & Driver Implementation Plan

> **Note:** The pure Rust driver described in this plan has been **implemented** at `secure/src/optiga/`. See `optiga/mod.rs` (WalletStore), `optiga/ifx_i2c.rs` (IFX I2C protocol), `optiga/apdu.rs` (APDU commands), `optiga/shield.rs` (Shielded Connection), `optiga/i2c.rs` (I2C driver). This document is retained as a design reference.

## Current Rust Ecosystem

**No published crate exists on crates.io** for OPTIGA Trust M.

### Existing Repos

#### 1. `octylFractal/infineon-trust-m-rs` (FFI Wrapper)
- **URL:** https://github.com/octylFractal/infineon-trust-m-rs
- **Approach:** FFI bindings wrapping Infineon's official C host library via `bindgen`/`cbindgen`/`cc`
- **Structure:** Two crates: `optiga-m-sys` (C FFI) + `optiga-m` (safe Rust API)
- **Status:** 73 commits, no releases, no crates.io publication, zero stars
- **API surface:** Very incomplete -- only SHA-256 exposed at high level
- **Dependencies:** `embedded-hal` 0.2.x (outdated), `defmt`, `hashbrown`
- **Architecture:** Uses global static mutex for hardware peripherals (FFI callback requirement). Only one instance can exist.
- **Assessment:** Useful as reference for understanding the C library API, but not suitable for production use. The FFI approach carries the full C library weight and the async callback model doesn't fit well with bare-metal Rust.

#### 2. BitBox02 Firmware (Production Hardware Wallet)
- **URL:** https://github.com/BitBoxSwiss/bitbox02-firmware
- **File:** `src/rust/bitbox-securechip/src/optiga.rs`
- **Approach:** Thin Rust FFI wrappers around C functions
- **API:** `attestation_sign`, `random`, `kdf`, `stretch_password`, `init_new_password`, `monotonic_increments_remaining`
- **Security patterns:** Extensive use of `Zeroizing` types
- **Assessment:** Production-proven API design, but still relies on C underneath. Good reference for what operations a wallet needs.

#### 3. Trezor Firmware (Production Hardware Wallet)
- **URL:** https://github.com/trezor/trezor-firmware
- **Context:** Trezor Safe 3/5/7 use OPTIGA Trust M. **Safe 7 combines OPTIGA Trust M + Tropic01** (dual SE, like our project!)
- **Driver:** C/Python, not Rust. Rust code only handles protobuf messages.
- **OID layout:** Well-documented PIN stretching scheme using 3 phases (CMAC + ECDH + HMAC)
- **Assessment:** Best reference for OID allocation and PIN hardening strategies on OPTIGA Trust M. The dual-SE architecture (OPTIGA + Tropic01) is directly relevant.

### No Pure Rust `no_std` Driver Exists

All existing implementations wrap the C library via FFI. No one has implemented the IFX I2C protocol stack in pure Rust.

## Recommended Approach: Pure Rust Driver

Given this project's constraints (`no_std`, no alloc, TrustZone, existing pattern from SE050 and Tropic01), a **pure Rust driver from scratch** is the right approach. The SE050 driver in this codebase already demonstrates the pattern.

### Protocol Complexity Comparison

| Layer | SE050 (T=1 over I2C) | OPTIGA Trust M (IFX I2C) |
|-------|----------------------|--------------------------|
| Physical | Direct I2C read/write | Register-based (0x80-0x89) |
| Data Link | T=1 blocks (3-byte header, LRC/CRC) | FCTR frames (5-byte header, CRC-16) |
| Transport | T=1 chaining (S-block, I-block) | PCTR chaining (0x00/0x01/0x02/0x04) |
| Presentation | SCP03 (AES-CMAC + AES-CBC) | Shielded Connection (AES-128-CCM) |
| Application | ISO 7816-4 APDUs | Custom TLV APDUs |

The OPTIGA protocol is **slightly more complex** than T=1 over I2C (4 distinct layers with negotiation, custom CRC, sequence numbers), but follows a similar pattern.

### Driver Module Structure

```
secure/src/optiga_trust_m/
    mod.rs              -- Public API: OptigaTrustM struct, init, transceive
    phy.rs              -- Physical layer: register read/write over I2C
    dl.rs               -- Data link layer: framing, CRC-16, sequence management
    tl.rs               -- Transport layer: fragmentation/reassembly
    pl.rs               -- Presentation layer: shielded connection (optional)
    apdu.rs             -- APDU command builder / response parser
    oids.rs             -- OID constants and metadata types
    error.rs            -- Error types
```

### Implementation Order

**Phase 1: Basic Communication**
1. `phy.rs` -- Register read/write, I2C_STATE polling, reset sequence
2. `dl.rs` -- Frame construction, CRC-16, ACK/NACK, sequence tracking
3. `tl.rs` -- Single-frame transport (no chaining initially)
4. `apdu.rs` -- OpenApplication, GetDataObject, GetRandom
5. `mod.rs` -- Init sequence, basic read/write API
6. **Milestone:** Read chip UID (OID `0xE0C2`) and generate random bytes

**Phase 2: Full Command Set**
1. `tl.rs` -- Add fragmentation/reassembly for large messages
2. `apdu.rs` -- CalcSign, VerifySign, GenKeyPair, CalcHash, CalcSSec, DeriveKey
3. `apdu.rs` -- SetDataObject, metadata read/write
4. `oids.rs` -- Complete OID map with types and access condition helpers
5. **Milestone:** Generate ECC key pair, sign a hash, verify signature

**Phase 3: Shielded Connection**
1. `pl.rs` -- TLS PRF SHA-256 key derivation
2. `pl.rs` -- AES-128-CCM encrypt/decrypt
3. `pl.rs` -- 4-step handshake state machine
4. `pl.rs` -- Session save/restore
5. **Milestone:** Full encrypted communication

**Phase 4: Wallet Integration**
1. Implement `WalletStore` trait for OPTIGA Trust M
2. PIN hardening scheme (reference Trezor's 3-phase approach)
3. Entropy half storage with access condition protection
4. Integration into dual-SE or triple-SE entropy split
5. **Milestone:** OPTIGA Trust M participating in wallet operations

### Key Design Decisions

**Synchronous/blocking driver** -- Match the SE050 and Tropic01 driver patterns in this codebase. The C library's async callback model is unnecessary for bare-metal single-threaded operation.

**Stack-allocated buffers** -- Max frame size 277 bytes. Max I2C transfer 1557 bytes. All buffers on stack, no heap.

**Buffer sizing:**
```rust
const MAX_FRAME_SIZE: usize = 277;
const MAX_APDU_SIZE: usize = 1557;
const DL_HEADER_SIZE: usize = 5;  // FCTR + FLEN + CRC
const TL_HEADER_SIZE: usize = 1;  // PCTR
const PL_HEADER_SIZE: usize = 5;  // SCTR + SeqNum (when shielded)
const PL_MAC_SIZE: usize = 8;     // AES-CCM tag
```

**CRC-16** -- Infineon's custom nibble-based algorithm (not standard). Must match exactly. See `ifx-i2c-protocol.md` for the algorithm.

### Host-Side Crypto Dependencies

For the Shielded Connection, the driver needs:

| Primitive | Crate Option | Hardware Option |
|-----------|-------------|-----------------|
| HMAC-SHA256 | `hmac` + `sha2` | STM32U585 HASH peripheral |
| AES-128-CCM | `aes` + `ccm` | STM32U585 CRYP/AES peripheral |
| Random | -- | STM32U585 TRNG |

The `sha2` and `aes` crates are already used in this project for SLH-DSA and SCP03.

### PIN Hardening Without UserID Auth

Unlike SE050's UserID hardware PIN auth, OPTIGA Trust M uses a different approach. Based on Trezor's production implementation:

1. **AES-CMAC key** at OID `0xE200`: Use for symmetric PIN verification
2. **ECDH key** at OID `0xE0F3`: Use for PIN stretching (DH-based key hardening)
3. **HMAC verification** via OID `0xF1D8`: Final PIN check
4. **Monotonic counters** at `0xE120`--`0xE122`: Attempt limiting
5. **Access conditions** on secret OIDs: Require authorization reference match

This achieves hardware-backed PIN gating, but through crypto operations rather than a dedicated PIN-check command. The SE hardware still enforces the policy -- firmware cannot bypass the access conditions.

> **🟡 What actually shipped (audit, 2026-04-30).** PQSigner did not adopt the
> full 4-OID Trezor stretching scheme above. The shipping design is simpler:
>
> - **AuthRef secret** at `0xF1D0` (holds the user-PIN-derived 64-byte secret)
> - **Lifetime Usage Counter** at `0xE120` provisioned as the attempt-counter
>   ceiling, bound via `Auto(LUC(0xE120))` to the `0xF1D0` access condition
> - HMAC-SHA-256 verify via the standard SetAuthScheme/Auth APDUs
>
> Together these give hardware-enforced attempt limiting that is immune to PBS
> extraction (because the LUC is monotonic on-chip silicon state, not derivable
> from any host secret). Provisioning is gated behind the `optiga-hw-counter`
> Cargo feature and is **destructive on first run** (rewrites F1D0 metadata,
> burns LUC ticks). See `secure/src/optiga/mod.rs` and
> `docs/optiga-bringup-status.md` for the as-shipped flow.

### Estimated Effort

| Phase | Effort | Dependencies |
|-------|--------|-------------|
| Phase 1 (basic comms) | 2-3 days | I2C HAL, GPIO |
| Phase 2 (full commands) | 2-3 days | Phase 1 |
| Phase 3 (shielded conn) | 3-4 days | Phase 2, AES-CCM, HMAC-SHA256 |
| Phase 4 (wallet integration) | 3-5 days | Phase 3, WalletStore trait |

### References for Implementation

1. **Protocol spec:** `Infineon_I2C_Protocol_v2.03.pdf` (in `optiga-trust-m-overview/docs/pdf/`)
2. **C source code:** https://github.com/Infineon/optiga-trust-m/tree/master/optiga/comms/ifx_i2c/
3. **Solution Reference Manual:** https://github.com/Infineon/optiga-trust-m-overview/blob/main/docs/OPTIGA%E2%84%A2%20Trust%20M%20Solution%20Reference%20Manual.md
4. **Existing SE050 driver in this repo:** `secure/src/se050/` (similar pattern to follow)
5. **Existing Tropic01 driver:** `secure/src/tropic01_se.rs` (similar pattern)
6. **BitBox02 API:** https://github.com/BitBoxSwiss/bitbox02-firmware/blob/master/src/rust/bitbox-securechip/src/optiga.rs
7. **Trezor OID layout:** https://github.com/trezor/trezor-firmware (for PIN hardening reference)
