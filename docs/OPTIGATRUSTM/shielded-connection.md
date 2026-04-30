# OPTIGA Trust M -- Shielded Connection (Encrypted I2C)

The Shielded Connection provides integrity and confidentiality protection between the host MCU and the OPTIGA Trust M over I2C. It operates at the Presentation Layer of the IFX I2C protocol stack.

## Overview

- Uses a **Platform Binding Secret (PBS)** stored at OID `0xE140` (minimum 32 bytes, 64 recommended)
- Key derivation via **TLS PRF SHA-256**
- Encryption via **AES-128-CCM** with 8-byte MAC
- 4-step handshake establishes session keys
- Session can be saved/restored across power cycles

## Protection Levels

| Level | Hex | Description |
|-------|-----|-------------|
| No Protection | `0x00` | Plaintext I2C |
| Slave Protection | `0x01` | Encrypt responses only (chip -> host) |
| Master Protection | `0x02` | Encrypt commands only (host -> chip) |
| Full Protection | `0x03` | Encrypt both directions |
| Re-establish | `0x80` | Force new session handshake |

## Handshake Protocol

### SCTR (Security Control Transport Record) Byte

```
Bits 5-6 : Protocol Type
  0x00 = Handshake
  0x20 = Record (data transfer)
  0x40 = Alert
Bits 3-4 : Message Type (for handshake)
  0x00 = Hello
  0x08 = Finished
Bits 0-1 : Protection Level
  0x00 = None
  0x01 = Slave
  0x02 = Master
  0x03 = Full
```

### 4-Step Handshake

```
Host (Master)                          OPTIGA Trust M (Slave)
     |                                        |
     |  1. Master Hello                       |
     |  [SCTR=0x00] [ProtocolVersion]         |
     |--------------------------------------->|
     |                                        |
     |  2. Slave Hello                        |
     |  [SCTR=0x00] [Random_S(32B)]           |
     |  [SeqNum_S(4B)]                        |
     |<---------------------------------------|
     |                                        |
     |  3. Master Finished                    |
     |  [SCTR=0x08] [Encrypted:               |
     |   Random_M(32B) + SeqNum_S(4B)]        |
     |--------------------------------------->|
     |                                        |
     |  4. Slave Finished                     |
     |  [SCTR=0x08] [Encrypted:               |
     |   verification data]                   |
     |<---------------------------------------|
     |                                        |
     |  === Session established ===           |
```

## Key Derivation

Uses **TLS PRF SHA-256** with:
- **Secret:** Platform Binding Secret from OID `0xE140`
- **Label:** `"Platform Binding"` (ASCII)
- **Seed:** `Random_M (32 bytes) || Random_S (32 bytes)`
- **Output:** 40 bytes (0x28), split as:

```
Bytes 0x00-0x0F : Master Encryption Key  (AES-128, 16 bytes)
Bytes 0x10-0x1F : Master Decryption Key  (AES-128, 16 bytes)
Bytes 0x20-0x23 : Master Encryption Nonce (static part, 4 bytes)
Bytes 0x24-0x27 : Master Decryption Nonce (static part, 4 bytes)
```

Note: "Master Encryption Key" encrypts host->chip traffic. "Master Decryption Key" decrypts chip->host traffic. From the chip's perspective, these roles are reversed.

## AES-128-CCM Encryption

| Parameter | Value |
|-----------|-------|
| Key size | 128 bits (16 bytes) |
| MAC tag size | 8 bytes |
| Nonce size | 8 bytes total |
| Nonce structure | Static part (4 bytes from KDF) + Sequence number (4 bytes) |

### Nonce Construction

```
[Static nonce (4 bytes)] [Sequence number (4 bytes, big-endian)]
```

- Sequence number starts at 0 after handshake
- Incremented after each encrypted message
- Separate counters for master and slave directions
- **Renegotiation threshold:** `0xFFFFFFF0` -- when sequence number reaches this value, a new handshake is required

### Associated Authenticated Data (AAD)

8 bytes for each encrypted message:
```
[SCTR (1 byte)] [SeqNum (4 bytes BE)] [ProtocolVersion (1 byte)] [PlaintextLen (2 bytes BE)]
```

### Encrypted Message Format

```
[SCTR (1 byte)] [SeqNum (4 bytes BE)] [Ciphertext...] [MAC tag (8 bytes)]
```

**Overhead per message:** 5-byte header (SCTR + SeqNum) + 8-byte MAC = **13 bytes**.

## Pairing Procedure (One-Time Setup)

Pairing binds the host MCU to a specific OPTIGA Trust M chip. This is a **one-time, irreversible** operation.

### Steps

1. **Check current state:** Read metadata of OID `0xE140` to verify lifecycle is still in Creation/Initialization state

2. **Generate shared secret:** Create 32--64 bytes of random data
   - Best: mix OPTIGA TRNG output + host TRNG output
   - Minimum: 32 bytes, recommended: 64 bytes

3. **Write to OPTIGA:** Use SetDataObject to write the secret to OID `0xE140`

4. **Store on host:** Save the identical secret in the host's secure persistent storage
   - For STM32U585: SAES-wrapped in secure flash
   - This is the Platform Binding Secret (PBS)

5. **Do NOT lock lifecycle by default.** Earlier revisions of this doc instructed bumping
   `E140.LcsO` to Operational (`0x07`) here. That step is **wrong** for the PRL handshake
   and should not be taken on bench boards.
   - The Infineon reference example
     (`example_pair_host_and_optiga_using_pre_shared_secret.c`) uses
     `#define FINAL_LCSO_STATE (LCSO_STATE_CREATION)` — it leaves E140 at `Creation`.
   - The SRM "Pairing Use Case Pre-conditions" requires `LcsO < operational`, not `=`.
   - The PRL dispatcher (`ifx_i2c_presentation_layer.c:820-829`) has no LcsO check on
     the handshake path; the channel works fine with E140 at `Creation`.
   - The bump is irreversible (OPTIGA lifecycle states are one-way) and was
     responsible for the brick incident documented in `optiga-brick-postmortem.md`.
   - In `secure/src/optiga/mod.rs::ensure_shield`, the bump is now skipped by
     default. It is only attempted under the `optiga-lock-operational` Cargo feature,
     which production builds enable as a deliberate gate (see commit `fa06a4f`
     and the comments at `secure/src/optiga/mod.rs:380-392, 502, 528-530`).
   - For dev/bring-up: leave E140 at `Creation`. For production provisioning: enable
     `optiga-lock-operational` only after every other gate (RDP, OTP burn, SCP03 rotation)
     has been validated, and only on chips that have already paired successfully.

6. **Verify:** Attempt a Shielded Connection handshake to confirm pairing works.

### Security Considerations

- Each Shielded Connection establishment increments the Security Event Counter (OID `0xE0C5`)
- If the counter exceeds its threshold, the chip will reject further handshakes temporarily
- The PBS is the root of trust for the encrypted channel -- if leaked, an attacker can MITM the I2C bus
- For production: store PBS with same protection level as other entropy halves (SAES-wrapped in secure flash)

## Session Save/Restore

Sessions can be persisted across power cycles:

| Operation | SCTR Code | Description |
|-----------|-----------|-------------|
| Save | `0x60` | Export session context for persistent storage |
| Restore | `0x68` | Import previously saved session context |

This avoids repeating the handshake on every power cycle, which saves time and Security Event Counter increments.

## Implementation Notes for Rust Driver

### Required Crypto Primitives (Host-Side)

1. **TLS PRF SHA-256** -- for key derivation from PBS
   - Can be implemented using HMAC-SHA256 (P_hash function from TLS 1.2 RFC 5246)
   - `P_hash(secret, seed) = HMAC(secret, A(1) + seed) || HMAC(secret, A(2) + seed) || ...`
   - `A(0) = seed`, `A(i) = HMAC(secret, A(i-1))`

2. **AES-128-CCM** -- for message encryption/decryption
   - Available in the `aes` + `ccm` crates, or `aes-gcm` ecosystem
   - Or use STM32U585 CRYP hardware accelerator

3. **Random number generation** -- for master random in handshake
   - STM32 TRNG

### Buffer Sizes

| Buffer | Size |
|--------|------|
| Platform Binding Secret | 64 bytes (max) |
| Session key material | 40 bytes |
| Handshake random (each side) | 32 bytes |
| Sequence number | 4 bytes |
| MAC tag per message | 8 bytes |
| Presentation layer header | 5 bytes (SCTR + SeqNum) |

### Memory Impact

Adding Shielded Connection to the driver increases:
- RAM: +10 KB (session keys, nonces, encryption buffers)
- Code: +15 KB (TLS PRF, AES-CCM, handshake state machine)
