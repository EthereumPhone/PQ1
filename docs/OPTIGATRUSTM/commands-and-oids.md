# OPTIGA Trust M -- Commands and OID Reference

## Command Set

### APDU Format

**Command:**
```
[Command Code: 1 byte] [Param: 1 byte] [InData Length: 2 bytes BE] [TLV data...]
```

**Response:**
```
[Status: 1 byte] [OutData Length: 2 bytes BE] [TLV data...]
```

Status `0x00` = success, `0xFF` = failure. On failure, read OID `0xF1C2` for detailed error code.

### TLV Encoding

All InData/OutData fields use Tag-Length-Value encoding:
```
[Tag: 1 byte] [Length: 2 bytes big-endian] [Value: N bytes]
```

### Command Reference

| Command | Code | Response Code | Description |
|---------|------|---------------|-------------|
| OpenApplication | `0x70` | `0xF0` | Open application context after reset |
| CloseApplication | `0x71` | `0xF1` | Close application, release resources |
| GetDataObject | `0x01` | `0x81` | Read data/metadata from OID |
| SetDataObject | `0x02` | `0x82` | Write data/metadata to OID |
| SetObjectProtected | `0x03` | `0x83` | Write integrity-protected object fragments |
| GetRandom | `0x0C` | `0x8C` | Generate random data (TRNG/DRNG) |
| CalcHash | `0x30` | `0xB0` | Calculate SHA hash |
| CalcSign | `0x31` | `0xB1` | Calculate signature (ECC/RSA) |
| VerifySign | `0x32` | `0xB2` | Verify signature |
| CalcSSec | `0x33` | `0xB3` | Calculate shared secret (ECDH) |
| DeriveKey | `0x34` | `0xB4` | Derive key (TLS PRF / HKDF) |
| GenKeyPair | `0x38` | `0xB8` | Generate ECC/RSA key pair |
| EncryptAsym | `0x1E` | `0x9E` | RSA public key encryption |
| DecryptAsym | `0x1F` | `0x9F` | RSA private key decryption |
| EncryptSym | `0x14` | `0x94` | AES symmetric encryption (V3 only) |
| DecryptSym | `0x15` | `0x95` | AES symmetric decryption (V3 only) |
| GenSymKey | `0x39` | `0xB9` | Generate AES key (V3 only) |

---

## Command Details

### OpenApplication (0x70)

Opens the OPTIGA application. Must be called after every reset before any other command.

```
CMD: 0x70
Param: 0x00
InData: [Tag 0x01] [Len 0x0010] [AID: D2 76 00 00 04 47 65 6E 41 75 74 68 41 70 70 6C]
```

The Application ID is the "GenAuthAppl" application: `D2 76 00 00 04 47 65 6E 41 75 74 68 41 70 70 6C`.

### GetDataObject (0x01)

Read data or metadata from an OID.

```
CMD: 0x01
Param: 0x00 (read data) or 0x01 (read metadata)
InData:
  [Tag 0x01] [Len 0x0002] [OID: 2 bytes BE]       -- Object ID
  [Tag 0x02] [Len 0x0002] [Offset: 2 bytes BE]     -- Read offset
  [Tag 0x03] [Len 0x0002] [Length: 2 bytes BE]      -- Bytes to read

Response:
  [Status: 0x00]
  [Tag 0x01] [Len] [Data...]
```

### SetDataObject (0x02)

Write data or metadata to an OID.

```
CMD: 0x02
Param: 0x00 (write data) or 0x01 (write metadata) or 0x40 (erase + write)
InData:
  [Tag 0x01] [Len 0x0002] [OID: 2 bytes BE]        -- Object ID
  [Tag 0x02] [Len 0x0002] [Offset: 2 bytes BE]      -- Write offset
  [Tag 0x03] [Len] [Data...]                         -- Data to write

Response:
  [Status: 0x00]
```

### GetRandom (0x0C)

Generate random bytes from hardware TRNG/DRNG.

```
CMD: 0x0C
Param: 0x00 (TRNG) or 0x01 (DRNG)
InData:
  [Tag 0x01] [Len 0x0002] [Length: 2 bytes BE]     -- Number of random bytes

Response:
  [Status: 0x00]
  [Tag 0x01] [Len] [Random data...]
```

### CalcSign (0x31)

Calculate an ECDSA or RSA signature.

```
CMD: 0x31
Param: Algorithm identifier (see Algorithm IDs below)
InData:
  [Tag 0x01] [Len] [Digest...]                      -- Hash/digest to sign
  [Tag 0x03] [Len 0x0002] [OID: 2 bytes BE]         -- Key OID (0xE0F0-E0F3 or 0xE0FC-E0FD)

Response:
  [Status: 0x00]
  [Tag 0x01] [Len] [Signature...]
```

### VerifySign (0x32)

Verify a signature.

```
CMD: 0x32
Param: Algorithm identifier
InData:
  [Tag 0x01] [Len] [Digest...]                      -- Hash/digest
  [Tag 0x02] [Len] [Signature...]                    -- Signature to verify
  [Tag 0x03] [Len 0x0002] [OID: 2 bytes BE]         -- Key OID (public key)
  -- OR --
  [Tag 0x04] [Len] [Public key data...]              -- Inline public key

Response:
  [Status: 0x00]   -- signature valid
  [Status: 0xFF]   -- signature invalid
```

### CalcSSec (0x33)

ECDH shared secret computation.

```
CMD: 0x33
Param: Algorithm identifier
InData:
  [Tag 0x01] [Len 0x0002] [Private key OID: 2 bytes BE]
  [Tag 0x05] [Len] [Peer public key...]
  [Tag 0x06] [Len 0x0002] [Export target OID: 2 bytes BE]  -- where to store shared secret

Response:
  [Status: 0x00]
```

### GenKeyPair (0x38)

Generate an ECC or RSA key pair.

```
CMD: 0x38
Param: Algorithm identifier
InData:
  [Tag 0x01] [Len 0x0002] [Private key OID: 2 bytes BE]
  [Tag 0x07] [Len 0x0002] [Key usage: 2 bytes]
  -- Optional: --
  [Tag 0x02] [Len 0x0001] [0x01]                    -- Export public key in response

Response:
  [Status: 0x00]
  [Tag 0x02] [Len] [Public key...]                   -- If export requested
```

### DeriveKey (0x34)

Key derivation using TLS PRF or HKDF.

```
CMD: 0x34
Param: Algorithm identifier (TLS PRF SHA-256, HKDF, etc.)
InData:
  [Tag 0x01] [Len 0x0002] [Secret OID: 2 bytes BE]
  [Tag 0x02] [Len] [Seed/Info...]
  [Tag 0x03] [Len 0x0002] [Derived key length: 2 bytes BE]
  [Tag 0x04] [Len 0x0002] [Export OID: 2 bytes BE]  -- where to store derived key

Response:
  [Status: 0x00]
```

### CalcHash (0x30)

SHA hash computation (supports streaming for large data).

```
CMD: 0x30
Param: Hash algorithm

For single-shot:
InData:
  [Tag 0x01] [Len 0x0001] [0x00]                    -- Start and Finalize
  [Tag 0x02] [Len] [Data...]

For streaming:
  First call:  [Tag 0x01] [Len 0x0001] [0x01]       -- Start
               [Tag 0x02] [Len] [Data chunk 1...]
  Middle calls: [Tag 0x01] [Len 0x0001] [0x02]      -- Continue
                [Tag 0x02] [Len] [Data chunk N...]
  Final call:  [Tag 0x01] [Len 0x0001] [0x03]       -- Finalize
               [Tag 0x02] [Len] [Data chunk last...]

Response (on finalize):
  [Status: 0x00]
  [Tag 0x01] [Len] [Hash...]
```

### EncryptSym / DecryptSym (0x14 / 0x15, V3 only)

AES symmetric encryption/decryption.

```
CMD: 0x14 (encrypt) or 0x15 (decrypt)
Param: Algorithm (AES-ECB, AES-CBC, AES-CBC-MAC, AES-CMAC)
InData:
  [Tag 0x01] [Len 0x0002] [Key OID: 2 bytes BE]     -- 0xE200
  [Tag 0x02] [Len] [IV/Nonce...]                     -- For CBC modes
  [Tag 0x03] [Len] [Plaintext/Ciphertext...]

Response:
  [Status: 0x00]
  [Tag 0x01] [Len] [Ciphertext/Plaintext...]
```

---

## Algorithm Identifiers

### ECC Algorithms

| Algorithm | ID | Curve |
|-----------|----|-------|
| ECDSA P-256 | `0x11` | NIST P-256 |
| ECDSA P-384 | `0x13` | NIST P-384 |
| ECDSA P-521 | `0x14` | NIST P-521 |
| ECDSA BP-256 | `0x15` | Brainpool P-256r1 |
| ECDSA BP-384 | `0x16` | Brainpool P-384r1 |
| ECDSA BP-512 | `0x17` | Brainpool P-512r1 |

### RSA Algorithms

| Algorithm | ID |
|-----------|----|
| RSA 1024 PKCS#1 v1.5 | `0x41` |
| RSA 2048 PKCS#1 v1.5 | `0x42` |

### Hash Algorithms

| Algorithm | ID |
|-----------|----|
| SHA-256 | `0xE2` |
| SHA-384 | `0xE3` |
| SHA-512 | `0xE4` |

### Key Agreement

| Algorithm | ID |
|-----------|----|
| ECDH P-256 | `0x01` |
| ECDH P-384 | `0x02` |
| ECDH P-521 | `0x03` |

---

## Object ID (OID) Map

### Certificate Objects (up to 1728 bytes each)

| OID | Name | Description |
|-----|------|-------------|
| `0xE0E0` | Device_Cert_IFX | Infineon pre-provisioned device cert (ECC P-256) |
| `0xE0E1` | Project_Cert_1 | Project-specific certificate slot 1 |
| `0xE0E2` | Project_Cert_2 | Project-specific certificate slot 2 |
| `0xE0E3` | Project_Cert_3 | Project-specific certificate slot 3 |

### Trust Anchor Objects (up to 1200 bytes, single cert)

| OID | Description |
|-----|-------------|
| `0xE0E8` | Trust Anchor 1 (root CA for verification) |
| `0xE0EF` | Trust Anchor 2 |

### ECC Private Key Objects

| OID | Name | Supported Curves |
|-----|------|-----------------|
| `0xE0F0` | Device_PriKey_1 | P-256, P-384, P-521, Brainpool |
| `0xE0F1` | Device_PriKey_2 | P-256, P-384, P-521, Brainpool |
| `0xE0F2` | Device_PriKey_3 | P-256, P-384, P-521, Brainpool |
| `0xE0F3` | Device_PriKey_4 | P-256, P-384, P-521, Brainpool |

### RSA Private Key Objects

| OID | Name | Key Sizes |
|-----|------|-----------|
| `0xE0FC` | RSA_PriKey_1 | 1024, 2048 bit |
| `0xE0FD` | RSA_PriKey_2 | 1024, 2048 bit |

### Symmetric Key Object (V3 only)

| OID | Name | Key Sizes |
|-----|------|-----------|
| `0xE200` | Symmetric_Key | AES-128, AES-192, AES-256 |

### Session Context Objects (volatile)

| OID | Description |
|-----|-------------|
| `0xE100` | Session context 1 |
| `0xE101` | Session context 2 |
| `0xE102` | Session context 3 |
| `0xE103` | Session context 4 |

### Monotonic Counter Objects

| OID | Description | Max Updates |
|-----|-------------|-------------|
| `0xE120` | Counter 1 | 600,000 |
| `0xE121` | Counter 2 | 600,000 |
| `0xE122` | Counter 3 | 600,000 |
| `0xE123` | Counter 4 | 600,000 |

### Platform Binding Secret

| OID | Description |
|-----|-------------|
| `0xE140` | Pre-shared secret for Shielded Connection (32--64 bytes) |

### Arbitrary Data Objects -- Type 3 (up to 140 bytes each)

| OID | Description |
|-----|-------------|
| `0xF1D0` | Auth reference secret / arbitrary data |
| `0xF1D1` -- `0xF1DB` | Arbitrary data (11 slots) |

### Arbitrary Data Objects -- Type 2 (up to 1500 bytes each, 100 NVM writes)

| OID | Description |
|-----|-------------|
| `0xF1E0` | Arbitrary data / public key storage |
| `0xF1E1` | Arbitrary data / public key storage |

### System Data Objects (read-only)

| OID | Name | Description |
|-----|------|-------------|
| `0xE0C0` | LCS_G | Global Life Cycle State |
| `0xE0C1` | Security_Status_G | Global Security Status |
| `0xE0C2` | Coprocessor_UID | Unique Identifier / chip info |
| `0xE0C3` | Sleep_Mode_Delay | Sleep mode activation delay |
| `0xE0C4` | Current_Limitation | Power consumption limit (6--15 mA) |
| `0xE0C5` | Security_Event_Counter | Security event counter |
| `0xF1C0` | LCS_A | Application Life Cycle State |
| `0xF1C1` | Security_Status_A | Application Security Status |
| `0xF1C2` | Error_Codes | Last error code |

---

## Metadata System

### Metadata Format

Metadata is TLV-encoded with root tag `0x20`:
```
[0x20] [Total length] [Tag1] [Len1] [Val1] [Tag2] [Len2] [Val2] ...
```

### Metadata Tags

| Tag | Name | Description |
|-----|------|-------------|
| `0xC0` | LcsO | Life Cycle State of data object |
| `0xC4` | MaxSize | Maximum size of data object (read-only after creation) |
| `0xC5` | UsedSize | Current used size (auto-updated) |
| `0xD0` | Change | Write access condition |
| `0xD1` | Read | Read access condition |
| `0xD2` | Delete | Delete access condition |
| `0xD3` | Execute | Execute access condition |
| `0xE0` | Algorithm | Algorithm associated with key container |
| `0xE1` | KeyUsage | Key usage flags for key container |

### Access Condition Identifiers

| Condition | Hex | Meaning |
|-----------|-----|---------|
| ALW | `0x00` | Always permitted, no restriction |
| NEV | `0xFF` | Never permitted (internal only) |
| LcsG(X) | `0x70` | Requires global lifecycle state match |
| LcsA(X) | `0xE0` | Requires application lifecycle state match |
| LcsO(X) | `0xE1` | Requires data object lifecycle state match |
| Auto(OID) | OID bytes | Requires authorization via specified auth OID |

### Comparison Operators

| Operator | Hex | Symbol |
|----------|-----|--------|
| Equal | `0xFA` | `==` |
| Greater than | `0xFB` | `>` |
| Less than | `0xFC` | `<` |
| AND | `0xFD` | `&&` |
| OR | `0xFE` | `\|\|` |

### Life Cycle States

Progression is forward-only (irreversible):

| State | Value | Description |
|-------|-------|-------------|
| Creation | `0x01` | Initial state, metadata changeable |
| Initialization | `0x03` | Being provisioned, metadata changeable |
| Operational | `0x07` | Normal operation, metadata locked, access conditions enforced |
| Termination | `0x0F` | End of life, permanently locked |

### Key Usage Flags

| Flag | Hex | Purpose |
|------|-----|---------|
| Authentication | `0x01` | Signature for authentication |
| Encryption | `0x02` | Encrypt/decrypt |
| HFWU | `0x04` | Host Firmware Update |
| DevM | `0x08` | Device Management |
| Sign | `0x10` | General signature generation |
| Key Agreement | `0x20` | ECDH operations |

---

## Trezor's OID Usage (Reference: production hardware wallet)

Trezor Safe 3/5/7 use OPTIGA Trust M in production. Their OID assignments:

| OID | Name | Purpose |
|-----|------|---------|
| `0xE0E0` | CERT_INF | Infineon factory certificate |
| `0xE0E1` | CERT_DEV | Device certificate |
| `0xE0E2` | CERT_FIDO | FIDO certificate |
| `0xE0F0` | KEY_DEV | Device ECC P-256 key |
| `0xE0F2` | KEY_FIDO | FIDO ECC P-256 key |
| `0xE0F3` | PIN_ECDH | ECDH key for PIN stretching |
| `0xE140` | KEY_PAIRING | 32-byte platform binding secret |
| `0xE200` | PIN_CMAC | AES-CMAC key for PIN |
| `0xF1D0` | PIN_SECRET | Final PIN secret |
| `0xF1D4` | STRETCHED_PIN | Stretched PIN intermediate |
| `0xF1D8` | PIN_HMAC | HMAC-based PIN verification |
| `0xE120`--`0xE122` | Counters | PIN attempt limits (16/16/600K) |

Their PIN stretching uses 3 phases:
1. AES-CMAC + ECDH symmetric hardening (2 iterations)
2. HMAC-SHA256 strengthening
3. PIN_SECRET finalization

This demonstrates that OPTIGA Trust M can provide hardware-backed PIN gating via access conditions + crypto operations, even without SE050-style UserID auth.
