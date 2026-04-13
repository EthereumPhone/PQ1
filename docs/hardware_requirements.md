# Hardware Requirements

## Microcontroller

- **STM32U5** series (e.g. STM32U585)
  - ARM Cortex-M33 with TrustZone (CMSE)
  - Hardware AES, SHA-256, PKA accelerators
  - Secure boot via TZEN and RDP level 2
  - JTAG/SWD permanently disabled in production

## Secure Elements

Entropy of the seed phrase is split across two independent secure elements to eliminate single points of compromise.

### Infineon OPTIGA Trust M V3

- Holds one share of the seed entropy (XOR-split half)
- Common Criteria EAL6+ certified (SLS32AIA)
- IFX I2C protocol (4-layer stack) at address 0x30
- Shielded Connection (TLS-PRF + AES-128-CCM-8) for encrypted I2C
- Authorization reference PIN protection (hardware-enforced access conditions)
- Platform Binding Secret for per-device pairing (stored in secure flash page 126)

### NXP SE050

- Holds one share of the seed entropy
- Common Criteria EAL6+ certified
- SCP03 secure channel for host communication
- UserID PIN authentication

Neither secure element alone is sufficient to reconstruct the seed. Both must be available and authenticated to derive keys.

## Display

- **Longevity display**
  - Must remain fully functional after extended periods of inactivity (e.g. stored for 10+ years between uses)

## User Input

- **2 hardware buttons**
  - Physical confirm / reject for transaction signing
  - No touchscreen — reduces attack surface
  - Buttons directly wired to MCU GPIO (no controller IC in path)
