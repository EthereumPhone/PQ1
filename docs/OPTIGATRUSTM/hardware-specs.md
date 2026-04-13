# OPTIGA Trust M V3 -- Hardware Specifications

## Chip Overview

| Property | Value |
|----------|-------|
| Part Number Family | SLS32AIA |
| Silicon | Infineon SLx security controller |
| Certification | Common Criteria EAL6+ (high) |
| PSA | Level 3 certified (SLS32AIA010MK variant) |
| Package | PG-USON-10-2,-4 (3x3mm, 0.6mm height) |
| User NVM | ~10 KB |
| Data retention | 20 years |
| Monotonic counters | 4, each up to 600,000 updates |

### Variants

| Part | Temp Range | Notes |
|------|-----------|-------|
| SLS32AIA010MS | -25C to +85C | Standard |
| SLS32AIA010MH | -40C to +105C | Industrial |
| SLS32AIA010MK | -40C to +105C | PSA Level 3 certified |

### Provisioning Configurations (all V3 silicon)

| Config | Description |
|--------|-------------|
| V3 (standard) | Factory-provisioned with Infineon ECC P-256 certificate |
| Express | Pre-provisioned with 3 certificates/keys, downloadable via CIRRENT Cloud ID |
| MTR | Matter-focused, Kudelski keySTREAM certificate management |
| Fit | Custom provisioning on demand |

## Cryptographic Capabilities

### Asymmetric

| Algorithm | Details |
|-----------|---------|
| ECC NIST | P-256, P-384, P-521 |
| ECC Brainpool | P-256r1, P-384r1, P-512r1 |
| RSA | 1024, 2048 bit |
| ECDSA | FIPS 186-3 signature/verify |
| ECDH | Shared secret computation |
| RSA PKCS#1 v1.5 | Sign, verify, encrypt, decrypt |
| RSA OAEP | SHA-256 padding |
| RSA PSS | Probabilistic signature scheme |

### Symmetric (V3 only)

| Algorithm | Key Sizes | Modes |
|-----------|-----------|-------|
| AES | 128, 192, 256 bit | ECB, CBC, CBC-MAC, CMAC, CCM |

### Hash and MAC

| Algorithm | Details |
|-----------|---------|
| SHA | 256, 384, 512 |
| HMAC | SHA-256, SHA-384, SHA-512 |

### Key Derivation

| Algorithm | Details |
|-----------|---------|
| TLS v1.2 PRF | SHA-256, SHA-384, SHA-512 |
| HKDF | SHA-256, SHA-384, SHA-512 |

### RNG

Hardware TRNG and DRNG on-chip.

## Crypto Performance

| Operation | Time |
|-----------|------|
| ECC P-256 key generation | ~55 ms |
| ECC P-256 sign | ~65 ms |
| ECC P-256 verify | ~85 ms |
| ECC P-256 ECDH | ~55 ms |
| RSA-2048 key generation | ~2900 ms |
| RSA-2048 sign | ~310 ms |
| RSA-2048 verify | ~40 ms |
| RSA-2048 encrypt | ~40 ms |
| RSA-2048 decrypt | ~315 ms |
| AES-128 encrypt (256 B) | ~28 ms |
| AES-128 decrypt (256 B) | ~35 ms |
| SHA-256 throughput | ~15 KB/s |
| HKDF-SHA256 | ~130 ms |
| HMAC-SHA256 (128 B) | ~90 ms |
| Data write (100 B) | ~18 ms |
| Data read (100 B) | ~9 ms |

## Electrical Specifications

| Parameter | Value |
|-----------|-------|
| VCC range | 1.62V -- 5.5V |
| Absolute max VCC | 6.0V |
| I2C pull-ups | 4.7k--10k ohm to VCC |
| I2C speeds | 100 KHz (SM), 400 KHz (FM), 1 MHz (FM+) |
| Active current | 6--15 mA (configurable in 1 mA steps via OID 0xE0C4) |

### Power Modes

| Mode | Description |
|------|-------------|
| Active | Full crypto operation, max current per Current Limitation setting |
| Idle | Reduced power, auto-entered when no computation pending |
| Sleep | Low power, wakes on I2C address detection (auto after configurable delay) |
| Hibernation | Zero power consumption, I2C bus stays connected |

## USON-10 Package Pinout

Pin 1 is marked by the black dot on the chip.

| Pin | Signal | Notes |
|-----|--------|-------|
| 1 | GND | Ground |
| 2 | NC | No connect |
| 3 | NC | No connect |
| 4 | NC | No connect |
| 5 | NC | No connect |
| 6 | SDA | I2C data (bidirectional, open-drain) |
| 7 | SCL | I2C clock (input) |
| 8 | RST | Reset (active LOW) |
| 9 | VCC | Supply voltage (1.62V--5.5V) |
| 10 | NC | No connect |
| EP | GND | Exposed pad (thermal ground) |

## TRUSTMV3SHIELDTOBO1 Shield Board

The **TRUSTMV3SHIELDTOBO1** is an Arduino-compatible shield that plugs into boards with Arduino R3 headers (including STM32 Nucleo boards and the B-U585I-IOT02A).

### Connections via Arduino R3 Headers

| Signal | Arduino Pin | STM32 Nucleo Mapping | Notes |
|--------|-------------|---------------------|-------|
| SDA | A4 / SDA | Varies by board (see stm32-integration.md) | I2C data, pull-ups on shield |
| SCL | A5 / SCL | Varies by board | I2C clock, pull-ups on shield |
| RST | Digital pin | GPIO output needed | Active LOW reset |
| VCC | 3.3V | 3.3V rail | From board regulator |
| GND | GND | GND | Common ground |

The shield includes:
- Level shifting (3.3V/5V compatible)
- Decoupling capacitors
- I2C pull-up resistors
- Reset line routing
- VCC enable control

### Reference Circuit (Minimal)

```
STM32                OPTIGA Trust M
-----                ---------------
I2C_SDA  ---[4.7k]--- VCC
         ------------- SDA (pin 6)

I2C_SCL  ---[4.7k]--- VCC
         ------------- SCL (pin 7)

GPIO_RST ------------- RST (pin 8)    [active LOW]

3.3V     ------------- VCC (pin 9)

GND      ------------- GND (pin 1, EP)
```

## Factory-Provisioned Content

Each OPTIGA Trust M V3 ships with:

| OID | Content |
|-----|---------|
| 0xE0E0 | Infineon pre-provisioned ECC P-256 device certificate |
| 0xE0F0 | Corresponding ECC P-256 private key |
| 0xE0C2 | Unique chip identifier (UID) |
| 0xE140 | Platform Binding Secret (64 bytes, chip-unique -- Express/MTR variants) |
| 0xF1D0 | Authorization Reference (64 bytes -- Express/MTR variants) |

### Certificate Chain

```
Root: "Infineon OPTIGA(TM) ECC Root CA 2"
  |
  +-- Intermediate: "Infineon OPTIGA(TM) Trust M CA 300"
        |
        +-- End-entity: Device certificate (ECC NIST P-256, in OID 0xE0E0)
```

## Memory Footprint (Host-Side Driver)

| Configuration | RAM | Code |
|--------------|-----|------|
| Without Shielded Connection | ~5 KB | ~15 KB |
| With Shielded Connection | ~15 KB | ~30 KB |

Max I2C buffer: 1557 bytes (`TRUSTX_I2C_MAX_BUF_LEN = 0x0615`).
