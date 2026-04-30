# TROPIC01 Reference Guide for PQSigner Hardware Wallet

> **🟠 Status (2026-04-30 audit) — historical / standalone-only.**
>
> When this doc was written (2026-04-15), TROPIC01 was being evaluated as a
> secondary SE in a dual-SE configuration (alongside OPTIGA Trust M). That
> path has since been retired:
>
> - The shipping dual-SE is **OPTIGA Trust M V3 + SE050**. `secure/src/dual_se.rs`
>   does not import `tropic01_se` (verified 2026-04-30).
> - TROPIC01 support remains only as a **standalone SE option** behind the
>   `tropic01-se` Cargo feature; the driver lives at `secure/src/tropic01_se.rs`
>   but is not part of the primary product.
> - The cryptographic parameter references in this doc are pre-cutover.
>   The codebase moved C7 → C11 → **C10** during April 2026; current sigs are
>   4008 bytes (SHA-256), not the C11 sizes implied here.
>
> The chip-level reference material (pinout, L1/L2/L3 protocol stack, Noise_KK1
> session, R-Memory layout, command set) is still accurate as TROPIC01
> documentation. Treat this file as a TROPIC01 datasheet companion, not as
> "this is how PQSigner uses two SEs."
>
> For current dual-SE architecture see `docs/OPTIGATRUSTM/`,
> `docs/se050-userid-pin-auth.md`, `docs/se050-factory-reset.md`.

## What is TROPIC01?

TROPIC01 is an **openly auditable secure element** by Tropic Square, built on a RISC-V core with a custom cryptographic coprocessor called **SPECT**. Used in the Trezor Safe 7. Open-source hardware RTL, firmware, and security architecture.

**Package:** QFN32, 4x4mm, 0.4mm pitch  
**Voltage:** 3.0V (3V0)  
**Interface:** 4-wire SPI (SDI, SDO, SCK, CSN) + GPO  
**Recommended part number:** **TR01-C2P-T301** (ships with App FW 1.0.0, SPECT FW 1.0.0)  
**Latest firmware:** App FW 2.0.0, API 1.4.0 (updateable via libtropic)

---

## Pin Description (QFN32)

| Pin # | Name    | Type           | Description                     |
|-------|---------|----------------|---------------------------------|
| 1     | VCC     | Power          | VCC                             |
| 2     | GND     | Ground         | Ground                          |
| 4     | GPO     | Digital Output | General Purpose Output          |
| 5     | SPI_SDI | Digital Input  | Serial Data Input (MOSI)        |
| 6     | SPI_SDO | Digital Output | Serial Data Output (MISO)       |
| 7     | SPI_SCK | Digital Input  | Serial Clock                    |
| 8     | SPI_CSN | Digital Input  | Chip Select (active low)        |

SPI Mode 0 (CPOL=0, CPHA=0), MSB first, recommended clock: **5 MHz**.

---

## Communication Protocol Layers

### Layer 1 (L1) - Physical: SPI
- 4-wire SPI, chip status byte returned on first byte of each transfer
- Status bits: `ready` (bit 0), `alarm` (bit 1), `start` (bit 2)
- `Get_Response` command (0xAA) polls for chip response
- 25ms delay between retries, max 50 retries

### Layer 2 (L2) - Data Link: Framed Commands
Request IDs:
- `0x01` Get_Info_Req (certificate, chip ID, FW version)
- `0x02` Handshake_Req (start Noise_KK1 session)
- `0x04` Encrypted_Cmd_Req (send encrypted L3 command)
- `0x08` Encrypted_Session_Abt (abort session)
- `0x10` Resend_Req
- `0x20` Sleep_Req
- `0xA2` Get_Log_Req
- `0xB3` Startup_Req (reboot/maintenance reboot)

Frame format: `[REQ_ID][LEN][DATA...][CRC16]`  
Response: `[CHIP_STATUS][RESP_STATUS][LEN][DATA...][CRC16]`  
Max chunk data: 252 bytes

### Layer 3 (L3) - Secure Session: Encrypted Commands
All L3 commands are AES-256-GCM encrypted within the Noise_KK1 session.

**Protocol:** `Noise_KK1_25519_AESGCM_SHA256`  
- Mutual authentication via X25519 key exchange
- Perfect forward secrecy
- Up to 4 pairing key slots (each with an X25519 keypair)

L3 packet format: `[CMD_SIZE(2B LE)][ENCRYPTED_DATA...][TAG(16B)]`

---

## L3 Command Reference

| CMD ID | Name                | Description                              |
|--------|---------------------|------------------------------------------|
| 0x01   | Ping                | Echo test (up to 4096 bytes)             |
| 0x10   | Pairing_Key_Write   | Write X25519 public key to pairing slot  |
| 0x11   | Pairing_Key_Read    | Read X25519 public key from pairing slot |
| 0x12   | Pairing_Key_Invalidate | Invalidate a pairing key slot         |
| 0x20   | R_Config_Write      | Write to reversible config address       |
| 0x21   | R_Config_Read       | Read from reversible config address      |
| 0x22   | R_Config_Erase      | Erase all reversible config              |
| 0x30   | I_Config_Write      | Write bit to irreversible config         |
| 0x31   | I_Config_Read       | Read from irreversible config            |
| 0x40   | R_Mem_Data_Write    | Write data to user data slot (up to 475B)|
| 0x41   | R_Mem_Data_Read     | Read data from user data slot            |
| 0x42   | R_Mem_Data_Erase    | Erase user data slot                     |
| 0x50   | Random_Value_Get    | Get random bytes from TRNG              |
| 0x60   | ECC_Key_Generate    | Generate ECC key in slot                 |
| 0x61   | ECC_Key_Store       | Store external ECC key in slot           |
| 0x62   | ECC_Key_Read        | Read ECC public key from slot            |
| 0x63   | ECC_Key_Erase       | Erase ECC key slot                       |
| 0x70   | ECDSA_Sign          | Sign 32-byte hash with P-256 key        |
| 0x71   | EdDSA_Sign          | Sign message with Ed25519 key           |
| 0x80   | MCounter_Init       | Initialize monotonic counter             |
| 0x81   | MCounter_Update     | Decrement monotonic counter by 1         |
| 0x82   | MCounter_Get        | Read monotonic counter value             |
| 0x90   | Mac_And_Destroy     | MAC-and-Destroy operation                |

L3 Result Status Codes:
- `0xC3` OK
- `0x3C` Fail (generic)
- `0x01` Unauthorized
- `0x02` Invalid_Cmd
- `0x10` Slot_Not_Empty
- `0x11` Slot_Expired
- `0x12` Invalid_Key
- `0x13` Update_Err
- `0x14` Counter_Invalid
- `0x15` Slot_Empty
- `0x16` Slot_Invalid
- `0x17` Hardware_Fail

---

## Memory & Storage

| Resource              | Count/Size       | Notes                                    |
|-----------------------|------------------|------------------------------------------|
| ECC Key Slots         | 32 (0-31)        | P-256 or Ed25519 keys                    |
| R_Mem_Data Slots      | 512 (0-511)      | Up to 475 bytes each (FW 2.0.0)         |
| Pairing Key Slots     | 4 (0-3)          | X25519 public keys for host auth        |
| MAC-and-Destroy Slots | 128 (0-127)      | For PIN verification scheme             |
| Monotonic Counters    | 16 (0-15)        | 32-bit, decrement only, max 0xFFFFFFFE  |
| Total User Storage    | **238 kB**       | ~4.5x more than NXP SE050C (50 kB)      |
| X.509 Certificate     | 3840 bytes       | Factory-provisioned, signed by TS CA    |

---

## MAC-and-Destroy PIN Verification

This is the core PIN-gating mechanism for your hardware wallet.

### How It Works
- Uses MACANDD slots (up to 128) as one-time-use PIN attempt tokens
- Each failed PIN attempt **destroys** one slot (irreversible by design)
- Correct PIN re-initializes all slots (reset attempt counter)
- No firmware comparison -- the chip's Keccak-based MACANDD primitive does the work
- Eliminates branching/comparison, resistant to fault injection

### New PIN Setup (Algorithm)
1. Generate random 32-byte master secret `s`
2. Derive tag `t = KDF(s, 0x00)`, init value `u = KDF(s, 0x01)`
3. Derive verification value `v = KDF(0, PIN||A)` (A = additional data)
4. For each slot `i` in 0..n-1:
   - MACANDD(i, u) to initialize slot
   - w_i = MACANDD(i, v) to get slot-specific output
   - k_i = KDF(w_i, PIN||A) to derive encryption key
   - c_i = ENC(k_i, s) to encrypt master secret
   - MACANDD(i, u) to re-initialize slot
   - Store c_i in NVM
5. Final key `k = KDF(s, 0x02)`

### PIN Entry Check
1. Derive `v = KDF(0, PIN||A)` from entered PIN
2. Read remaining attempts `i` from NVM
3. Decrement `i`, store to NVM
4. MACANDD(i, v) to get w_i
5. k_i = KDF(w_i, PIN||A)
6. Try DEC(k_i, c_i) to recover master secret `s`
7. Verify with stored tag `t`
8. If correct: re-initialize all slots (reset counter), return k = KDF(s, 0x02)
9. If wrong: slot i is destroyed, decrement remaining attempts

### Requirements
- KDF: KMAC256 or HMAC-SHA256
- Symmetric cipher: AES-256 or ChaCha20 (or simple XOR for exact scheme)
- MCU NVM: stores ciphertexts c_i, tag t, remaining attempts counter

---

## Cryptographic Capabilities

| Algorithm       | Purpose                              | Notes                    |
|----------------|--------------------------------------|--------------------------|
| X25519 (ECDH)  | Secure channel key exchange          | Noise_KK1 handshake     |
| Ed25519 (EdDSA)| Signing (messages up to 4096 bytes)  | Hardware accelerated     |
| P-256 (ECDSA)  | Signing (32-byte hash)               | Hardware accelerated     |
| AES-256-GCM    | Secure channel encryption            | Authenticated encryption |
| SHA-256/SHA-512| Hashing, key derivation              |                          |
| Keccak         | PIN verification (MACANDD)           | Hardware engine          |
| ISAP            | Memory encryption at rest           | Authenticated encryption |

**TRNG:** 2x NIST800-90b, AIS31 compliant, up to 128 kbit/s each  
**PUF:** 256-bit per-chip unique fingerprint

---

## Physical Security

- Voltage glitch detector
- Temperature sensor  
- Electromagnetic pulse detector
- Laser detector
- Active shield
- On-the-fly NVM encryption (ISAP)
- Error Correction Codes on all memory
- Memory address scrambling

---

## Secure Channel Handshake Flow

```
Host MCU                                    TROPIC01
   |                                            |
   |  1. Generate ephemeral X25519 keypair       |
   |     E_HPRIV, E_HPUB                        |
   |                                            |
   |  Handshake_Req(E_HPUB, PKEY_INDEX) ------> |
   |                                            |
   |     <--- Handshake_Resp(E_TPUB, T_TAUTH) - |
   |                                            |
   |  2. Both sides compute:                     |
   |     - DH(E_HPRIV, S_TPUB) [static-ephemeral]|
   |     - DH(S_HPRIV, E_TPUB) [ephemeral-static]|
   |     - DH(E_HPRIV, E_TPUB) [ephemeral-ephemeral]|
   |                                            |
   |  3. Derive session keys via HKDF:           |
   |     k_CMD (encrypt commands)                |
   |     k_RES (encrypt results)                 |
   |                                            |
   |  Encrypted_Cmd_Req(ciphertext) ----------> |
   |     <--- Encrypted_Cmd_Resp(ciphertext) -- |
```

---

## STM32 Wiring (for your B-U585I-IOT02A)

The STM32U5 is explicitly supported by libtropic. Wiring for SPI:

| TROPIC01 Pin | STM32 Pin     | Function    |
|-------------|---------------|-------------|
| SPI_SDI (5) | SPI MOSI      | Data to chip|
| SPI_SDO (6) | SPI MISO      | Data from chip|
| SPI_SCK (7) | SPI CLK       | Clock       |
| SPI_CSN (8) | GPIO (output) | Chip select |
| GPO (4)     | GPIO (input)  | Interrupt (optional)|
| VCC (1,11,24)| 3.3V         | Power       |
| GND (2,12,23)| GND          | Ground      |

---

## Rust SDK (libtropic-rs)

The `tropic01` crate provides an `embedded-hal` driver. Key types:

```rust
use tropic01::{Tropic01, NoSession, ActiveSession};

// Create driver with SPI device
let mut tropic = Tropic01::new(spi);
// Optionally add CS pin management
let mut tropic = tropic.with_cs_pin(cs_pin)?;

// Start secure session (L2 handshake)
let mut tropic: Tropic01<_, _, ActiveSession> = tropic.handshake(
    &x25519_impl,
    &host_private_key,
    pkey_index,
)?;

// Now use L3 commands
let random = tropic.get_random_value(32)?;
let mac_result = tropic.mac_and_destroy(slot, &input_data)?;
tropic.r_mem_data_write(slot, &data)?;
let data = tropic.r_mem_data_read(slot)?;
tropic.ecc_key_generate(slot, EccCurve::Ed25519)?;
let sig = tropic.eddsa_sign(slot, &message)?;
let sig = tropic.ecdsa_sign(slot, &hash)?;
```

Dependencies (all `no_std`): `embedded-hal 1.x`, `aes-gcm`, `x25519-dalek`, `sha2`, `hmac`, `zeroize`

**Pairing Keys (for testing):**
- Engineering sample: `keys::SH0PRIV_ENG_SAMPLE` / `keys::SH0PUB_ENG_SAMPLE`
- Production slot 0: `keys::SH0PRIV_PROD0` / `keys::SH0PUB_PROD0`

---

## Development Boards

| Board                  | Interface      | TROPIC01 Part   | Notes                     |
|------------------------|---------------|-----------------|---------------------------|
| USB Devkit (TS1302)    | USB-C (via STM32 USB-to-SPI) | TR01-C2P-T301 | Best for desktop testing |
| Secure Tropic Click    | mikroBUS SPI   | TR01-C2P-T101   | By MikroE, MIKROE-6559   |
| Arduino Shield         | Arduino SPI    | various         | For Nucleo boards         |
| Raspberry Pi Shield    | Linux SPI      | various         | TS1501                    |
| Mini Board             | Bare SPI       | TR01-C2P-T101   | Minimal breakout          |

---

## Firmware Compatibility Matrix

| Libtropic | App FW       | SPECT FW | Bootloader FW |
|-----------|-------------|----------|---------------|
| 3.2.0     | 1.0.0-2.0.0 | 1.0.0    | 2.0.1         |
| 3.1.0     | 1.0.0-2.0.0 | 1.0.0    | 2.0.1         |
| 3.0.0     | 1.0.0-2.0.0 | 1.0.0    | 2.0.1         |
| 2.0.1     | 1.0.0-1.0.1 | 1.0.0    | 2.0.1         |

---

## What This Means for PQSigner

For your dual-SE hardware wallet:

1. **half_T storage:** Use an R_Mem_Data slot (0-511, up to 475 bytes each) to store the XOR half of entropy
2. **PIN gating:** Use the MAC-and-Destroy scheme with N slots (your CLAUDE.md says 13 slots)
3. **Noise_KK1 session:** Already implemented in the Rust SDK -- provides E2E encrypted SPI bus
4. **TRNG contribution:** Use `Random_Value_Get` to XOR with STM32 TRNG + SE050 TRNG
5. **Pairing key protection:** Store host-side pairing keys HUK-SAES-wrapped (as noted in CLAUDE.md)
6. **Attestation:** Verify X.509 certificate chain against pinned Tropic Square CA root

---

## Downloaded Resources in This Folder

### PDFs
- `TROPIC01_datasheet.pdf` -- Full datasheet (Rev A.6, 65 pages)
- `TROPIC01_Data_Brief.pdf` -- Data brief / marketing overview

### Repos (cloned)
- `libtropic-rs/` -- **Rust SDK** (embedded-hal driver, the most relevant for your codebase)
- `libtropic/` -- Official C SDK (reference implementation, tutorials, STM32 HAL)
- `tropic01/` -- Main product page (datasheets, API PDFs, application notes, part numbers)
- `devboards/` -- Hardware design files for all dev boards (schematics, gerbers, BOMs)
- `ts13-dev-kit/` -- TS13 devkit firmware/docs
- `tropic01-stm32u5-usb-devkit-hw/` -- USB devkit hardware design (STM32U5-based)
- `libtropic-util/` -- CLI utility for interfacing TROPIC01

### Key PDFs inside repos
- `tropic01/doc/api/ODU_TR01_user_api_v1_4_0.pdf` -- Latest API reference (66 pages)
- `tropic01/doc/datasheet/ODD_TR01_datasheet_vA_11.pdf` -- Latest datasheet
- `tropic01/doc/application_notes/ODN_TR01_app_002_pin_verif_1v2.pdf` -- **PIN Verification** (critical for wallet)
- `tropic01/doc/application_notes/ODN_TR01_app_003_pki_1v3.pdf` -- PKI / certificate chain
- `tropic01/doc/application_notes/ODN_TR01_app_005_first_pairing_key_1v2.pdf` -- First pairing key setup
- `tropic01/doc/application_notes/ODN_TR01_app_006_config_obj_1v2.pdf` -- Configuration objects
- `tropic01/doc/application_notes/ODN_TR01_app_007_fw_update_1v3.pdf` -- Firmware update
