# Infineon OPTIGA Trust M V3 -- Integration Reference

Reference documentation for integrating the **OPTIGA Trust M V3** (SLS32AIA) secure element into the PQSigner OS wallet, targeting STM32U585 with a bare-metal Rust (`no_std`) driver.

**Hardware:** TRUSTMV3SHIELDTOBO1 Arduino shield + B-U585I-IOT02A dev board.

## Document Index

| Document | Contents |
|----------|----------|
| [hardware-specs.md](hardware-specs.md) | Chip capabilities, crypto algorithms, pinout, electrical specs, shield board details |
| [ifx-i2c-protocol.md](ifx-i2c-protocol.md) | Complete IFX I2C protocol stack: physical, data link, transport, presentation layers |
| [commands-and-oids.md](commands-and-oids.md) | APDU command reference, OID map, access conditions, metadata format |
| [shielded-connection.md](shielded-connection.md) | Encrypted I2C channel: handshake, key derivation, AES-128-CCM, pairing |
| [stm32-integration.md](stm32-integration.md) | Wiring to B-U585I-IOT02A, GPIO config, initialization sequence, timing |
| [rust-driver-plan.md](rust-driver-plan.md) | Rust ecosystem assessment, existing repos, driver architecture plan |

## Quick Facts

| Property | Value |
|----------|-------|
| Chip | SLS32AIA010MS (V3, CC EAL6+) |
| Interface | I2C, slave address `0x30` |
| Protocol | IFX I2C v2.03 (4-layer stack over standard I2C) |
| I2C Speed | 100 KHz default, up to 1 MHz (FM+) |
| VCC | 1.62V -- 5.5V |
| Package | USON-10, 3x3mm |
| ECC | P-256, P-384, P-521, Brainpool P-256r1/P-384r1/P-512r1 |
| RSA | 1024, 2048 bit |
| AES | 128, 192, 256 bit (ECB, CBC, CBC-MAC, CMAC, CCM) |
| Hash | SHA-256, SHA-384, SHA-512 |
| HMAC | SHA-256, SHA-384, SHA-512 |
| KDF | TLS v1.2 PRF, HKDF (SHA-256/384/512) |
| Key slots | 4 ECC + 2 RSA + 1 AES |
| User NVM | ~10 KB |
| Monotonic counters | 4 (up to 600K updates each) |
| Encrypted channel | Shielded Connection (AES-128-CCM, TLS-PRF key derivation) |
| Cert chain | Infineon ECC P-256 factory-provisioned |

## Comparison with SE050 (for dual-SE context)

| Feature | OPTIGA Trust M V3 | NXP SE050 |
|---------|-------------------|-----------|
| Interface | I2C (IFX I2C protocol) | I2C (T=1 over I2C) |
| I2C Address | 0x30 | 0x48 |
| Encrypted Channel | Shielded Connection (TLS-PRF + AES-128-CCM) | SCP03 (AES-CMAC + AES-CBC) |
| ECC Curves | P-256/384/521, Brainpool 256/384/512 | P-256/384, Brainpool, Ed25519 |
| RSA | Up to 2048 | Up to 4096 |
| AES | 128/192/256 | 128/192/256 |
| Certification | CC EAL6+ | CC EAL6+ |
| Key Slots | 4 ECC + 2 RSA | Many (flexible object system) |
| User Memory | ~10KB | ~50KB |
| HMAC | SHA-256/384/512 | SHA-256 |
| PIN Auth | Access conditions + auth OID | UserID auth object (hardware PIN) |
| Monotonic Counters | 4 (600K updates) | Limited |

**Key difference for wallet use:** OPTIGA Trust M does not have SE050's direct UserID hardware PIN authentication. Access control uses metadata access conditions with authorization reference secrets (OID-based). This is conceptually different but can achieve similar PIN-gating results using the authorization reference OID (`0xF1D0`) combined with access condition metadata.

## Key Documentation URLs

**Official Infineon:**
- Product page: https://www.infineon.com/part/OPTIGA-TRUST-M-SLS32AIA
- Datasheet v3.70 PDF (in overview repo below)
- Solution Reference Manual v3.70 PDF (in overview repo below)
- I2C Protocol v2.03 PDF (in overview repo below)

**GitHub Repositories:**
- C Host Library: https://github.com/Infineon/optiga-trust-m
- Overview (docs + PDFs): https://github.com/Infineon/optiga-trust-m-overview
- Solution Reference Manual (Markdown): https://github.com/Infineon/optiga-trust-m-overview/blob/main/docs/OPTIGA%E2%84%A2%20Trust%20M%20Solution%20Reference%20Manual.md
- Arduino library: https://github.com/Infineon/arduino-optiga-trust-m
- Linux tools: https://github.com/Infineon/linux-optiga-trust-m
- I2C protocol utilities: https://github.com/Infineon/i2c-utils-optiga-trust
- Personalization guide: https://github.com/Infineon/personalize-optiga-trust
- Getting started: https://github.com/Infineon/getstarted-optiga-trust-m

**Essential PDFs (in `optiga-trust-m-overview/docs/pdf/`):**
- `Infineon_I2C_Protocol_v2.03.pdf` -- IFX I2C protocol spec (essential for driver)
- `OPTIGA_Trust_M_Solution_Reference_Manual_v3.70.pdf` -- authoritative command/OID reference
- `OPTIGA_Trust_M_ConfigGuide_v2.2.pdf` -- configuration guide
- `OPTIGA_Trust_M_Keys_And_Certificates_v3.10.pdf` -- PKI/certificate details
- `OPTIGA_Trust_M_Datasheet_v3.70.pdf` -- full datasheet

**Wiki pages:**
- Shielded Connection 101: https://github.com/Infineon/optiga-trust-m/wiki/Shielded-Connection-101
- Crypto Performance: https://github.com/Infineon/optiga-trust-m/wiki/Crypto-Performance
- Porting Guide: https://github.com/Infineon/optiga-trust-m/wiki/Porting-Guide
- Protected Update: https://github.com/Infineon/optiga-trust-m/wiki/Protected-Update-for-Data-Objects
- Data and Key Store Overview: https://github.com/Infineon/optiga-trust-m/wiki/Data-and-Key-Store-Overview

**API documentation (Doxygen):**
- https://infineon.github.io/optiga-trust-m/
