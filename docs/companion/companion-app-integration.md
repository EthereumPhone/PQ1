# PQSigner Companion App Integration Guide

> **STOP: legacy architecture reference, not an implementation specification.**
> Nothing below overrides the two normative documents linked here. Historical
> byte layouts and workflows are context only and must not be copied into a
> companion. Implement transport and response parsing from
> [`usb-protocol-v2.md`](usb-protocol-v2.md), and ERC-7730 lookup/framing from
> [`companion-erc7730-implementation-guide.md`](companion-erc7730-implementation-guide.md).
> Seedless slot rotation is executable from protocol **0x0203** (#353): the
> rotation response carries the new slot's 64-byte owner bytes. Against a device
> reporting `< 0x0203`, keep `FLAG_REGISTER_SLOT` clear and reject a nonzero
> Type-1 response. See §11.4 for the procedure.

This is retained as historical architecture context for companion apps. It is
not self-contained, and its detailed byte layouts and worked workflows have not
all been reconciled with the current firmware. The WebHID tool is a bring-up
utility, not a production protocol authority. Use the two normative documents
linked in the warning above and the constants in `pqsigner-proto`.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [USB HID Transport](#2-usb-hid-transport)
3. [APDU Protocol](#3-apdu-protocol)
4. [Command Reference](#4-command-reference)
5. [SIGN_USEROP Wire Format](#5-sign_userop-wire-format)
6. [Signature Wrapper (Coinbase-Style)](#6-signature-wrapper-coinbase-style)
7. [initCode Format (First Deploy)](#7-initcode-format-first-deploy)
8. [Smart Contract ABIs](#8-smart-contract-abis)
9. [On-Chain Counters & Caps](#9-on-chain-counters--caps)
10. [Multi-Account Derivation](#10-multi-account-derivation)
11. [Companion App Workflows](#11-companion-app-workflows)
12. [Current clear-sign trailers (normative redirect)](#12-current-clear-sign-trailers-normative-redirect)
13. [Error Handling](#13-error-handling)
14. [Security Invariants](#14-security-invariants)
15. [Constants Reference](#15-constants-reference)

---

## 1. Architecture Overview

```
 Companion App                              PQSigner Device
 ============                              ===============
                                           +-----------------+
  Build unsigned tx                        | NON-SECURE      |
  Query chain state  ---- USB HID APDU --> | USB HID + APDU  |
  Encode UserOp                            | route to gateway |
  Submit to bundler                        +------+----------+
                                                  | NSC gateway
                                           +------v----------+
                                           | SECURE WORLD    |
                                           | PIN entry (LCD) |
                                           | Tx display      |
                                           | SPHINCS+C10 sign|
                                           | Native decode   |
                                           +------+----------+
                                                  |
                                     +------------+------------+
                                     |                         |
                               OPTIGA Trust M             NXP SE050
                               (entropy half_O)          (entropy half_E)
```

**Trust boundary.** The companion app is untrusted. The device independently:

- Prompts for PIN on its own trusted LCD — the PIN never crosses USB.
- Displays transaction details on its trusted LCD.
- Waits for physical button confirmation.
- Computes the SPHINCS+C10 signing digest natively.
- Verifies authenticated metadata/descriptors and natively binds decoded bytes
  before displaying actions.

The companion never sees the PIN, seed, or signing key. It sends opaque
commands and receives public data + signatures.

**One signing command.** After the all-C10 / multi-owner cutover, there is
exactly one signing instruction (`INS 0x30 SIGN_USEROP`). Every flow —
first deploy, normal transaction, slot rotation, ERC-20 transfer, native
clear-signed action — is expressed as flags + optional trailers on the
same payload.

**Stateless slots, companion-driven.** The firmware keeps zero flash state
about which chain has registered which slot. The companion supplies
`(chain_id, account_index, slot_index, flags)` on every sign; the secure
world derives slot keys deterministically from the master seed, caches them
in SRAM across the unlock session, and zeroises on lock / idle timeout.

**Per-chain usage caps.** `PQSmartWallet` enforces two monotonic counters:
- `bootstrapUses < 65_536` — Type 1 slot registrations per chain
- `slotUses[ownerIndex] < 65_536` — Type 2 signatures per registered slot

Combined ceiling: ~2³² user transactions per chain. Well inside the
SPHINCS+C10 birthday margin. There is no reset path.

**Multi-account.** A single 24-word seed yields **256 independent CREATE2
wallets**, indexed by `account_index ∈ [0, 255]`. Account 0 reproduces
the legacy single-account address byte-for-byte; accounts 1..=255 use
domain-tagged KDFs. See [§10](#10-multi-account-derivation).

---

## 2. USB HID Transport

| Property       | Value                                       |
|----------------|---------------------------------------------|
| USB class      | Custom HID                                  |
| VID / PID      | `0x1209` / `0x7051`                         |
| Report size    | 64 bytes (interrupt EP1 IN/OUT)             |
| Framing        | Ledger-compatible APDU-over-HID             |
| Tag            | `0x05` (APDU)                               |

### HID Frame Format

```
First frame (payload ≤ 57 bytes):
  [0..2)  channel_id   u16 BE (any constant; 0x0101 is conventional)
  [2]     tag          0x05 = APDU
  [3..5)  sequence     u16 BE = 0x0000
  [5..7)  total_len    u16 BE (full APDU length)
  [7..64) data         up to 57 bytes

Continuation frames (payload ≤ 59 bytes):
  [0..2)  channel_id   u16 BE (same as first)
  [2]     tag          0x05
  [3..5)  sequence     u16 BE (1, 2, 3, …)
  [5..64) data         up to 59 bytes
```

### Platform Notes

- **Linux:** Requires a udev rule for non-root access:
  ```
  SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1209", ATTRS{idProduct}=="7051", MODE="0666"
  ```
- **Browser (WebHID):**
  `navigator.hid.requestDevice({ filters: [{ vendorId: 0x1209, productId: 0x7051 }] })`
- **macOS / Windows:** hidapi or node-hid work without extra config.

---

## 3. APDU Protocol

### Envelope

```
Request:   CLA(1) INS(1) P1(1) P2(1) [Lc(1) Data(Lc)]
Response:  [Data] SW1(1) SW2(1)
```

| Field | Value                                          |
|-------|------------------------------------------------|
| CLA   | `0xF0` (v2 — current, and the only CLA your new companion should target) |
| P1    | `0x00` = last/only block, `0x80` = more blocks follow |
| P2    | Must be `0x00` for all current commands        |
| Lc    | 0–255 data bytes per APDU                      |

### Command Chaining (Large Requests)

The `SIGN_USEROP` payload is ~300–800 bytes (larger when trailers are
present), so it exceeds the 255-byte per-APDU limit. Send multiple APDUs
with the same `INS`:

- **P1 = 0x80** — more blocks follow, device ACKs with `SW=0x9000`
- **P1 = 0x00** — last or only block; device executes the command

The device accumulates payload data across blocks, then dispatches on the
final block. A new `INS` mid-chain is a protocol error.

### Response Chaining (GET_RESPONSE)

Large responses (sign bundle can be up to ~8.4 KB) are drained
incrementally. The device returns the first chunk (≤ 253 bytes) with
`SW = 0x61FF` (more available), and the companion sends `INS 0xC0`
(`GET_RESPONSE`) until `SW = 0x9000`.

```
Host → Device:  SIGN_USEROP (chained, final block P1=0x00)
Device → Host:  [≤253 bytes] SW=0x61FF
Host → Device:  GET_RESPONSE
Device → Host:  [≤253 bytes] SW=0x61FF
… (≈35 round-trips for a full 8.4 KB response)
Host → Device:  GET_RESPONSE
Device → Host:  [remaining bytes] SW=0x9000
```

### Status Words

| SW       | Meaning                                                      |
|----------|--------------------------------------------------------------|
| `0x9000` | Success                                                      |
| `0x61XX` | More data available — call `GET_RESPONSE`                    |
| `0x6700` | Wrong length                                                 |
| `0x6982` | Security not satisfied (wrong PIN, user rejected on device)  |
| `0x6984` | Idle timeout — device auto-locked mid-operation              |
| `0x6985` | Conditions not satisfied (device locked, not provisioned)    |
| `0x6A80` | Wrong data (malformed payload, invalid metadata/descriptor binding or trailer) |
| `0x6D00` | `INS` not supported                                          |
| `0x6E00` | `CLA` not supported                                          |
| `0x6F00` | Internal error                                               |

---

## 4. Command Reference

After the cutover there are only **six** instructions plus the
`GET_RESPONSE` drain helper.

| INS    | Name                | Unlock? | Chaining? |
|--------|---------------------|---------|-----------|
| `0x01` | GET_DEVICE_INFO     | no      | no        |
| `0x02` | GET_STATUS          | no      | no        |
| `0x10` | UNLOCK              | no      | no        |
| `0x11` | LOCK                | yes     | no        |
| `0x30` | SIGN_USEROP         | yes     | **yes**   |
| `0x60` | GET_WALLET_ADDRESS  | yes     | no        |
| `0xC0` | GET_RESPONSE        | n/a     | n/a       |

Any other INS returns `SW=0x6D00` (INS not supported). If you find
documentation referring to `GET_BOOTSTRAP_VK` (0x20), `GET_MAIN_VK` (0x21),
`SIGN_CLEAR_USEROP` (0x31), `SIGN_MESSAGE` (0x40), `SIGN_EIP712` (0x41),
`SIGN_BOOTSTRAP` (0x50), or the legacy slot triplet (0x70 / 0x71 / 0x72), it
predates the unified-sign cutover — those instructions are gone. ZK
clear-sign, ERC-20 display, EIP-712, and EIP-191 all now ride as optional
trailers on `SIGN_USEROP`.

---

### INS 0x01 — GET_DEVICE_INFO

Capability discovery. **Always call first.**

**Request:** empty

**Response (40 bytes + SW):**

| Offset | Size | Field             | Notes                                  |
|--------|------|-------------------|----------------------------------------|
| 0      | 2    | protocol_version  | u16 BE, currently `0x0203`             |
| 2      | 3    | fw_version        | placeholder bytes; do not gate features |
| 5      | 16   | device_uid        | STM32 UID96; zeros on dev builds       |
| 21     | 4    | capabilities      | u32 BE bitmap (see below)              |
| 25     | 1    | sig_param_set     | `2` = SPHINCS+C10 (128-bit)            |
| 26     | 2    | sig_size          | u16 BE = `SIG_TYPE2_LEN` (4128)     |
| 28     | 4    | legacy_reserved_0 | u32 BE, always zero                    |
| 32     | 4    | legacy_reserved_1 | u32 BE, always zero                    |
| 36     | 2    | ep_version        | u16 BE = `0x0006` (EntryPoint v0.6)    |
| 38     | 2    | wrapper_overhead  | u16 BE = `SIG_TYPE2_HEADER_LEN`     |

**Capability bitmap:**

| Bit | Constant | Meaning |
|----:|----------|---------|
| 0 | `CAP_SIGN_USEROP` | unified UserOperation signing is available |
| 1 | retired | must remain clear; do not reuse the former slot flag |
| 2 | `CAP_ERC7730_PROOF_SET` | contract-call ERC-7730 trailers accept the version-1 two-bundle proof-set envelope |

Gate proof-set emission on bit 2 exactly. With the bit clear, send only the
legacy one-bundle payload even if `fw_version` appears newer. The current
`fw_version` bytes are a hard-coded placeholder, not the running image's
identity. Ignore unknown capability bits; continue to branch independently on
`ep_version` and `sig_param_set` for their respective semantics.

---

### INS 0x02 — GET_STATUS

Check device state. No unlock required.

**Request:** empty

**Response (2 bytes + SW):**

| Offset | Field         | Values                                  |
|--------|---------------|-----------------------------------------|
| 0      | locked        | 0 = unlocked, 1 = locked                |
| 1      | pin_remaining | 0–10 attempts remaining                 |

There is deliberately NO `provisioned` byte: the old 3-byte layout led
with one derived as `pin_remaining <= MAX_ATTEMPTS`, which is always
true, so it reported "provisioned" even on a blank device. The byte was
removed (finding X17-UC2). A blank device runs the on-device first-boot
wizard; detect that state from the wizard UI, not from GET_STATUS.

---

### INS 0x10 — UNLOCK

Triggers PIN entry on the device's trusted OLED. The PIN never crosses USB.

**Request:** empty
**Response:** SW only

| SW       | Meaning                                 |
|----------|-----------------------------------------|
| `0x9000` | Unlocked                                |
| `0x6982` | Wrong PIN                               |
| `0x6985` | Permanently locked (0 attempts left)    |
| `0x6984` | User took too long on PIN entry         |

**Blocks until user finishes PIN entry.** Set USB read timeout ≥ 60 s.

---

### INS 0x11 — LOCK

Zeroizes all cached secrets and returns to locked state.

**Request:** empty
**Response:** `SW 0x9000`

---

### INS 0x60 — GET_WALLET_ADDRESS

Return the 20-byte CREATE2-predicted wallet address for a given
`account_index`. Requires unlock. First call for a given index triggers
<1 s of SPHINCS+C10 hypertree keygen inside the secure world; subsequent
calls hit the firmware's SRAM LRU cache (capacity 16) and return in < 1 ms.

**Request (0, 4, or 5 bytes):**

| Offset | Size | Field         | Notes                                    |
|--------|------|---------------|------------------------------------------|
| 0      | 4    | account_index | u32 BE, `0..=255`                        |
| 4      | 1    | show          | optional; `0` = silent, `1` = display + confirm on device (protocol `0x0202`+) |

An **empty body is accepted as `account_index = 0`** for companions that
pre-date multi-account support; a 4-byte body means `show = 0`.

The optional `show` flag (new in protocol `0x0202`): when `1`, the device
paints the full EIP-55 address — bound to `account_index` — on its OLED
behind a physical confirm BEFORE the address bytes are returned, so the
user can verify a receive address against the companion UI (Trezor
receive-address parity). A user cancel fails closed: `SW=0x6982`, no
address bytes. Flag values above 1 are rejected (`SW=0x6A80`). Firmware
reporting `< 0x0202` rejects the 5-byte body with `SW=0x6700`, so gate
the flag on the GET_DEVICE_INFO version.

**Response (20 bytes + SW):** Ethereum-style address. Same on every chain
for a given `(seed, account_index)`.

**Computation inside firmware:**
```
master = KDF(bip39_seed, account_index)   // see §10
salt   = sha256(masterPkSeed || masterPkRoot)
addr   = CREATE2(factory, salt, keccak256(LibClone ERC1967 proxy init))
```
(The CREATE2 opcode itself hashes with keccak256 — only the salt preimage
is SHA-256. `LibClone.predictDeterministicAddressERC1967` is the concrete
formula.)

---

### INS 0x30 — SIGN_USEROP

The single signing command. Every flow is expressed by setting flags in
the payload header. See [§5](#5-sign_userop-wire-format) for the full wire
format.

**Unlock required. Command-chaining required.**

Sub-flows selected by flag bits:

| Flag combination                         | What the device emits              |
|------------------------------------------|------------------------------------|
| none (normal signing)                    | Type 2 wrapper only                |
| `FLAG_INCLUDE_INIT_CODE` + slot_index=0  | initCode + Type 2 (first deploy)   |
| `FLAG_REGISTER_SLOT` + slot_index ≥ 1    | new owner bytes + Type 1 + Type 2 (rotation, protocol 0x0203+; §11.4) |

`FLAG_INCLUDE_INIT_CODE` and `FLAG_REGISTER_SLOT` are **mutually
exclusive**. Firmware rejects both set.

**Response: one count plus three length-framed chunks**, drained via
`GET_RESPONSE`:

```
[new_offchain_count (8 BE)]
[init_code_len (4 BE)][init_code    (0 or 4280 B)]
[type1_len     (4 BE)][new_owner_bytes(64 B) || type1_wrapper(4128 B)]  — 0 or 4192 B
[type2_len     (4 BE)][type2_wrapper(4128 B)]        — abi.encode(uint256,bytes)
```

Chunks are present **iff their length prefix is non-zero**. The Type 2
wrapper is always present on a successful sign. See
[§6](#6-signature-wrapper-coinbase-style) and [§7](#7-initcode-format-first-deploy).

---

### INS 0xC0 — GET_RESPONSE

Drain the next chunk of a large response.

**Request:** empty
**Response:** next ≤ 253 bytes + SW

---

## 5. SIGN_USEROP Wire Format

### Request header (330 bytes fixed)

| Offset | Size | Field                     | Description                                      |
|-------:|-----:|---------------------------|--------------------------------------------------|
|      0 |    8 | `chain_id`                | u64 BE                                           |
|      8 |    4 | `flags`                   | u32 BE — see below                               |
|     12 |   20 | `sender`                  | Must equal `GET_WALLET_ADDRESS(accountIndex)`; firmware recomputes and rejects mismatches |
|     32 |   20 | `entry_point`             | EntryPoint v0.6 address                          |
|     52 |   32 | `nonce`                   | u256 BE — base nonce of the first UserOp         |
|     84 |   32 | `call_gas_limit`          | u256 BE                                          |
|    116 |   32 | `verification_gas_limit`  | u256 BE                                          |
|    148 |   32 | `pre_verification_gas`    | u256 BE                                          |
|    180 |   32 | `max_fee_per_gas`         | u256 BE                                          |
|    212 |   32 | `max_priority_fee_per_gas`| u256 BE                                          |
|    244 |   32 | `paymaster_and_data_hash` | **SHA-256** (not keccak). Use `SHA256_EMPTY` when no paymaster. |
|    276 |   20 | `to_address`              | inner tx recipient                               |
|    296 |   32 | `value`                   | u256 BE                                          |
|    328 |    2 | `data_len`                | u16 BE, `0..=8192` (4096 without cap bit 5)      |
|    330 |    N | `data`                    | inner tx calldata                                |

> ⚠️ `paymaster_and_data_hash` is SHA-256 of `paymasterAndData`. This
> matches `PQSmartWallet.sphincsDigest`, which re-hashes the UserOp's
> paymaster field with SHA-256 rather than keccak. When `paymasterAndData`
> is empty, use the constant
> `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
> (`sha256("")`).

### Trailer layout (normative redirect)

The former two-trailer recipe was retired and has been removed from this legacy
guide. Current `SIGN_USEROP` uses seven positional `u16` slots (including a
zero-only reserved compatibility slot), followed by the special names framing;
batch uses routed TLVs. The non-secure USB handler performs no database lookup
or metadata injection. Implement the exact current grammar from
[`companion-erc7730-implementation-guide.md` §6](companion-erc7730-implementation-guide.md#6-where-the-trailer-goes-in-each-command).

### Flags field (u32 BE)

```
 bit  31           30            29..22                    21..0
     INIT_CODE    REG_SLOT     account_index (8 bits)    slot_index (22 bits)
```

| Constant                  | Value         |
|---------------------------|---------------|
| `FLAG_INCLUDE_INIT_CODE`  | `0x8000_0000` |
| `FLAG_REGISTER_SLOT`      | `0x4000_0000` |
| `ACCOUNT_INDEX_MASK`      | `0x3FC0_0000` |
| `ACCOUNT_INDEX_SHIFT`     | `22`          |
| `MAX_ACCOUNT_INDEX`       | `0xFF` (255)  |
| `SLOT_INDEX_MASK`         | `0x003F_FFFF` |

Rules (firmware enforces all three):
1. `FLAG_INCLUDE_INIT_CODE` and `FLAG_REGISTER_SLOT` cannot both be set.
2. `FLAG_INCLUDE_INIT_CODE` requires `slot_index == 0`.
3. `FLAG_REGISTER_SLOT` requires `slot_index ≥ 1`.

Encoding pseudocode:
```javascript
let flags = slotIndex & SLOT_INDEX_MASK;
flags |= (accountIndex << ACCOUNT_INDEX_SHIFT) & ACCOUNT_INDEX_MASK;
if (registerSlot)    flags |= FLAG_REGISTER_SLOT;
if (includeInitCode) flags |= FLAG_INCLUDE_INIT_CODE;
```

### Response bundle

Parsing (mirrors `parseSignResponse` in the WebHID tool):

```typescript
let off = 0;
const newOffchainCount = readU64BE(resp, off); off += 8;
const icLen = readU32BE(resp, off); off += 4;
const initCode = icLen > 0 ? resp.slice(off, off + icLen) : null; off += icLen;

const t1Len = readU32BE(resp, off); off += 4;
if (t1Len !== 0 && t1Len !== 4192) throw new Error('bad Type-1 section');
const newOwnerBytes = t1Len > 0 ? resp.slice(off, off + 64) : null;
const type1 = t1Len > 0 ? resp.slice(off + 64, off + t1Len) : null; off += t1Len;

const t2Len = readU32BE(resp, off); off += 4;
const type2 = resp.slice(off, off + t2Len);  // always present
```

Chunk sizes are fixed when present: `initCode` is exactly **4280 B**, the
Type-1 section is exactly **4192 B** (64 B new owner bytes + 4128 B wrapper,
protocol 0x0203+), and the Type-2 wrapper is exactly **4128 B**.

---

## 6. Signature Wrapper (Coinbase-Style)

Both `type1` and `type2` from the response are **already ABI-encoded** as
`abi.encode(uint256 ownerIndex, bytes c10Sig)` and are ready to be dropped
straight into the UserOp's `signature` field. No additional wrapping is
needed on the companion side.

### Wire layout (4128 bytes)

```
[  0..32)  ownerIndex (uint256 BE)
[ 32..64)  offset to `bytes` = 0x40
[ 64..96)  bytes length = 4008
[ 96..4128) C10 signature (4008 B + 24 B zero pad to 32-B multiple)
```

### Solidity struct

```solidity
// In PQSmartWallet.sol
struct SignatureWrapper {
    uint256 ownerIndex;
    bytes   signatureData;   // raw 4008-byte SPHINCS+C10 signature
}
```

The wallet's `_validateSignature` decodes the wrapper, looks up
`ownerAtIndex[ownerIndex]`, bumps either `bootstrapUses` (ownerIndex == 0)
or `slotUses[ownerIndex]` (ownerIndex ≥ 1), and calls `c10Verifier.verify`
with the 64-byte owner (pkSeed ‖ pkRoot) and the 4008-byte raw signature.

### Decoding the owner index

The first 32 bytes of either wrapper are the `ownerIndex`. Parse as
uint256 BE:

```typescript
function wrapperOwnerIndex(wrapper: Uint8Array): bigint {
  let n = 0n;
  for (let i = 0; i < 32; i++) n = (n << 8n) | BigInt(wrapper[i]);
  return n;
}
```

- `type1` always has `ownerIndex == 0` (the bootstrap key).
- `type2` has `ownerIndex == k` where `k ≥ 1` identifies the slot owner.
  On first deploy the device always registers slot index → owner index 1
  before it can be used; subsequent slots occupy owner indices 2, 3, …

---

## 7. initCode Format (First Deploy)

Present only when the companion set `FLAG_INCLUDE_INIT_CODE` **and** the
firmware accepted it. Exactly **4280 bytes**:

| Offset | Size | Field          |
|-------:|-----:|----------------|
|      0 |   20 | `factory`      |
|     20 |    4 | `selector` (createAccount) |
|     24 |   32 | `masterPkSeed` |
|     56 |   32 | `masterPkRoot` |
|     88 |   32 | `slot0PkSeed`  |
|    120 |   32 | `slot0PkRoot`  |
|    152 |   32 | `chainId` (u256 BE) |
|    184 |   32 | ABI offset to `factorySig` = `0x140` |
|    216 |   32 | `factorySig` length = `4008` |
|    248 | 4032 | `factorySig` (4008 B + 24 B zero pad) |

Copy this blob verbatim into the UserOp's `initCode` field — the layout
is already the concatenation that `EntryPoint.handleOps` expects
(`factory_addr || factory_calldata`).

The `factorySig` is a SPHINCS+C10 signature by the **master** (bootstrap)
key over the digest
```
sphincsDigest_factory(chainId, slot0PkSeed, slot0PkRoot)
```
which `PQSmartWalletFactory.addSlot0Digest(chainId, slot0PkSeed, slot0PkRoot)`
returns on-chain; the factory uses it to authenticate the initial slot-0
owner before deploying.

### Deriving the sender address from the initCode

```typescript
function parseInitCode(initCode: Uint8Array) {
  return {
    factory:      '0x' + bytesToHex(initCode.slice(0, 20)),
    masterPkSeed: '0x' + bytesToHex(initCode.slice(24, 56)),
    masterPkRoot: '0x' + bytesToHex(initCode.slice(56, 88)),
    slot0PkSeed:  '0x' + bytesToHex(initCode.slice(88, 120)),
    slot0PkRoot:  '0x' + bytesToHex(initCode.slice(120, 152)),
  };
}

// For verification / display:
const predicted = await factory.getAddress(parsed.masterPkSeed, parsed.masterPkRoot);
// Must equal `sender` the firmware signed over.
```

---

## 8. Smart Contract ABIs

### PQSmartWalletFactory

```solidity
interface IPQSmartWalletFactory {
    function implementation() external view returns (address);
    function c10Verifier() external view returns (address);

    // CREATE2-deploys an ERC1967 proxy bound to `implementation`,
    // initialised with (bootstrapOwnerBytes, slot0OwnerBytes).
    // `factorySig` is a master-key C10 sig over addSlot0Digest(…).
    function createAccount(
        bytes32 masterPkSeed,
        bytes32 masterPkRoot,
        bytes32 slot0PkSeed,
        bytes32 slot0PkRoot,
        uint256 chainId,
        bytes calldata factorySig
    ) external payable returns (address);

    function getAddress(
        bytes32 masterPkSeed,
        bytes32 masterPkRoot
    ) external view returns (address);

    function addSlot0Digest(
        uint64 chainId,
        bytes32 slot0PkSeed,
        bytes32 slot0PkRoot
    ) external pure returns (bytes32);
}
```

**Salt preimage:** the factory uses `_salt(masterPkSeed, masterPkRoot) =
sha256(masterPkSeed || masterPkRoot)`. LibClone then feeds that salt into
the EVM's keccak-based CREATE2 formula.

### PQSmartWallet

Coinbase-style multi-owner account. Owner index 0 is the immutable
bootstrap key; indices 1, 2, 3, … are slot keys added via `addOwnerBytes`.

```solidity
interface IPQSmartWallet {
    // ── ERC-4337 ────────────────────────────────────────────────────
    function entryPoint() external view returns (address);
    function validateUserOp(
        UserOperation06 calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256);
    function sphincsDigest(UserOperation06 calldata userOp)
        external view returns (bytes32);

    // ── Execution (EntryPoint only; consumes the credit a slot-key
    //    validation stamped for the same ownerIndex) ─────────────────
    function executeWithOffchainCount(
        uint256 ownerIndex, uint256 newOffchainCount,
        address target, uint256 value, bytes calldata data
    ) external returns (bytes memory);
    function executeBatchWithOffchainCount(
        uint256 ownerIndex, uint256 newOffchainCount,
        address[] calldata targets, uint256[] calldata values,
        bytes[] calldata datas
    ) external;

    // ── Owners (append-only; there is no removal) ───────────────────
    function addOwnerBytes(bytes calldata newOwner) external; // EntryPoint only, bootstrap-signed op
    function ownerAtIndex(uint256 index) external view returns (bytes memory);
    function nextOwnerIndex() external view returns (uint256);
    function ownerCount() external view returns (uint256);    // == nextOwnerIndex
    function isOwnerBytes(bytes memory owner) external view returns (bool);

    // ── Usage counters ──────────────────────────────────────────────
    function bootstrapUses() external view returns (uint256);
    function slotUses(uint256 ownerIndex) external view returns (uint256);
    function offchainSigCount(uint256 ownerIndex) external view returns (uint256);

    // ── EIP-1271 ────────────────────────────────────────────────────
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external view returns (bytes4);            // 0x1626ba7e
    function isValidSignature(bytes calldata data, bytes calldata signature)
        external view returns (bytes4);            // 0x20c13b0b (Safe v1.3.0 / v1.4.1)

    // ── Token receivers (always accept) ─────────────────────────────
    function onERC721Received(address, address, uint256, bytes calldata)
        external pure returns (bytes4);
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external pure returns (bytes4);
    function onERC1155BatchReceived(
        address, address, uint256[] calldata, uint256[] calldata, bytes calldata
    ) external pure returns (bytes4);
    function supportsInterface(bytes4 interfaceId) external pure returns (bool);

    // ── Convenience views ───────────────────────────────────────────
    function masterPkSeed() external view returns (bytes32);
    function masterPkRoot() external view returns (bytes32);
}
```

**Key selectors:**

| Selector     | Function                                                                  |
|--------------|---------------------------------------------------------------------------|
| `0x14443c57` | `executeWithOffchainCount(uint256,uint256,address,uint256,bytes)`         |
| `0x7a389933` | `executeBatchWithOffchainCount(uint256,uint256,address[],uint256[],bytes[])` |
| `0x101490cb` | `addOwnerBytes(bytes)`                                                    |
| `0x1626ba7e` | `isValidSignature(bytes32,bytes)`                                         |
| `0x20c13b0b` | `isValidSignature(bytes,bytes)`                                           |

The UserOp `callData` is built and signed by the device (it is part of the
signed `sphincsDigest`); the companion reproduces it byte for byte from the
request and the device's response. There is no plain `execute(...)` entry
point (UPDATE 2026-10-20: this table used to list Coinbase's
`execute(address,uint256,bytes)`, `0xb61d27f6`, which the wallet does not
have).

### Dispatch rules (enforced inside `_validateSignature`)

| `ownerIndex` | Required inner call        | Counter bumped                  |
|--------------|----------------------------|---------------------------------|
| `0`          | `addOwnerBytes(bytes)`     | `bootstrapUses` (cap 65_536)    |
| `≥ 1`        | `executeWithOffchainCount` / `executeBatchWithOffchainCount`, first argument `== ownerIndex` | `slotUses[ownerIndex]` (cap 65_536, combined with `offchainSigCount[ownerIndex]`) |

Any other selector from a slot owner is rejected. The bootstrap owner
(index 0) can **only** add new owners — never move funds directly. There is
no owner removal (deleted 2026-10-20): the owner set is append-only, and a key
that was ever installed can never be installed again.

### EntryPoint v0.6

Canonical singleton address (same on every major chain):
`0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`.

```solidity
struct UserOperation06 {
    address sender;
    uint256 nonce;
    bytes   initCode;
    bytes   callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes   paymasterAndData;
    bytes   signature;
}
```

---

## 9. On-Chain Counters & Caps

```solidity
// In PQMultiOwnable.sol
struct PQMultiOwnableStorage {
    uint256                          nextOwnerIndex;
    uint256                          removedOwnersCount;
    mapping(uint256 => bytes)        ownerAtIndex;
    mapping(bytes => bool)           isOwner;
    uint256                          bootstrapUses;
    mapping(uint256 => uint256)      slotUses;
}

uint256 constant MAX_BOOTSTRAP_USES = 65_536;   // Type 1 cap per chain
uint256 constant MAX_SLOT_USES      = 65_536;   // Type 2 cap per owner
```

**Companion responsibilities:**

- Always read on-chain state before choosing which slot to sign with.
  The firmware will happily keygen any requested slot; it is the
  companion's job to avoid a slot index whose `slotUses` is already at cap.
- When `slotUses[currentSlot] + offchainSigCount[currentSlot]` approaches
  `MAX_SLOT_USES`, rotate to the next slot (§11.4). Each rotation spends one
  of the chain's `MAX_BOOTSTRAP_USES`.
- When `bootstrapUses` approaches `MAX_BOOTSTRAP_USES`, warn the user:
  once all currently-registered slots are also exhausted, the chain is
  permanently frozen for that wallet. There is no reset path by design.

---

## 10. Multi-Account Derivation

A single 24-word seed produces 256 independent wallets. `account_index = 0`
reproduces the pre-multi-account legacy address byte-for-byte.

```
BIP-39 entropy (32 B, XOR-split across OPTIGA + SE050)
  └─ PBKDF2-HMAC-SHA512(2048 iters, empty passphrase) → bip39_seed (64 B)

For each account_index ∈ [0, 255]:

  if account_index == 0:
      master = HMAC-SHA512("sphincs-c6-v1", bip39_seed)
  else:
      master = HMAC-SHA512("sphincs-c6-v1-acct", bip39_seed || account_index_BE4)

  masterPkSeed = sha256("pk_seed" || master[0..32]) & N_MASK    // top 16B kept
  masterSkSeed = sha256("sk_seed" || master[0..32])
  masterPkRoot = sphincs_c10::SigningKey::keygen(masterSkSeed, masterPkSeed).pk_root()

  if account_index == 0:
      slot_master = sha256("pqwallet-slot-master" || bip39_seed)
  else:
      slot_master = sha256("pqwallet-slot-master-acct" || bip39_seed || account_index_BE4)

  salt    = sha256(masterPkSeed || masterPkRoot)
  address = LibClone.predictDeterministicAddressERC1967(impl, salt, factory)
```

Per-slot derivation from `slot_master`, `chain_id`, and `slot_index`:
```
slot_entropy = sha256(slot_master || "slot_entropy" || chain_id_BE8 || slot_index_BE4)
slot_r       = sha256(slot_master || "slot_r"       || chain_id_BE8 || slot_index_BE4)
slot_sk_seed = sha256("slot_c10_sk_seed" || slot_entropy)
slot_pk_seed = sha256("slot_c10_pk_seed" || slot_entropy) & N_MASK
slot_sk      = sphincs_c10::SigningKey::keygen(slot_sk_seed, slot_pk_seed)
```

**Recovery contract.** The domain tags above are load-bearing and frozen. This
formula is retained only as firmware/test-tool compatibility context;
companions do not receive the seed or slot secrets and must not re-derive keys.

### Companion UI pattern (from the WebHID tool)

- Lazy-derive addresses one page at a time.
- Page size: 10 accounts → 26 total pages for 256 accounts.
- First derivation of any `account_index` costs <1 s on real STM32U585
  hardware (one master C10 hypertree keygen per address).
- Subsequent hits on the same index are < 1 ms (firmware SRAM LRU,
  capacity 16).
- Cache in the companion UI too, so revisiting a page is instant.
- Drop the companion-side cache on `LOCK` — the device wipes its LRU on
  lock and a seed reload would make cached addresses stale.

---

## 11. Companion App Workflows

### 11.1 First Connection

```
GET_DEVICE_INFO                    → protocol, sig_size, EntryPoint version
GET_STATUS                         → locked? pin_remaining?
if locked:
    UNLOCK                         → user enters PIN on device
GET_WALLET_ADDRESS(account_index=0) → <1 s first time, then wallet address
```

### 11.2 First Deploy on a New Chain

```
1. accountIndex ← user's choice (default 0)
2. sender ← GET_WALLET_ADDRESS(accountIndex)
   The device hard-binds this field to the mnemonic-derived CREATE2 address;
   a stale, cross-account, or substituted sender is rejected before signing.
3. Confirm off-chain: eth_getCode(sender) == "0x"
4. nonce = 0  (first UserOp for this sender)
5. Build SIGN_USEROP payload:
     flags            = FLAG_INCLUDE_INIT_CODE | (accountIndex << 22)  // slot_index = 0
     paymaster_hash   = SHA256_EMPTY
     gas              = bundler estimate (budget ≥ 800K verGas — factory deploy + C10 verify)
     to/value/data    = the inner tx you want to execute on deploy

6. Send chained APDU. Device displays:
     a. "First deploy on chain N?"
     b. `Signer acct #N` plus the full mnemonic-derived EIP-55 wallet address
     c. For a non-zero EntryPoint nonce key, `Nonce lane key:` plus all 48
        hexadecimal key characters (lane zero omits this page)
     d. Inner tx preview
     Request signing after button confirm.

7. Parse response:
     newOffchainCount, initCode (4280 B), type1=null, type2 (4128 B)
8. Build UserOperation06:
     sender, nonce=0, initCode,
     callData = executeWithOffchainCount(1,newOffchainCount,to,value,data),
     callGasLimit, verificationGasLimit, preVerificationGas,
     maxFeePerGas, maxPriorityFeePerGas,
     paymasterAndData = "0x",
     signature = type2
9. Submit via eth_sendUserOperation
   → EntryPoint.createSender → factory.createAccount
   → wallet.executeWithOffchainCount(...)
```

Gas defaults that worked on Base Sepolia in the reference tool:
```
verGas               = 800_000    // factory 547K + validate 214K + headroom
callGas              = 50_000
preVerificationGas   = 150_000
maxPriorityFeePerGas = 0.1 gwei
maxFeePerGas         = 1   gwei
```

### 11.3 Normal Transaction (Deployed Wallet)

```
1. sender  ← GET_WALLET_ADDRESS(accountIndex)  (cache it)
   The cached address must correspond to the same `accountIndex` encoded in
   `flags`; the device recomputes and hard-rejects any mismatch.
2. slotIdx ← whichever slot ownerIndex ≥ 1 is active and has budget
3. nonceKey ← chosen uint192 parallel lane (default 0)
   nonce    ← entryPoint.getNonce(sender, nonceKey)
   For nonceKey != 0 the device shows the full 192-bit key; the ordinary
   `Nonce:` row continues to show the low-64 sequence.
4. flags   = (accountIndex << 22) | slotIdx    // no flag bits set

5. SIGN_USEROP(…) → initCode=null, type1=null, type2 (4128 B)
6. Build UserOperation06 with signature = type2.
7. Submit via bundler.
```

### 11.4 Slot Rotation (current slot nearing cap)

Requires a device reporting protocol **0x0203+** (GET_DEVICE_INFO bytes 0–1),
and a deployed wallet on this chain. Each slot has its own 65,536-signature
budget (`slotUses + offchainSigCount`); rotating moves the wallet to a fresh
slot whose budget starts at zero. Each rotation spends one bootstrap use.

Always derive `newSlot` from `nextOwnerIndex` as in step 1. `addOwnerBytes`
installs at `nextOwnerIndex` whatever slot the device signed for, and the
owner set is append-only, so a key installed at the wrong index can never
sign on that chain and its bootstrap use is spent. Re-read `nextOwnerIndex`
right before submitting the Type-1 UserOp and abort if it changed.

```
1. nextOwner ← wallet.nextOwnerIndex()
   newSlot   = nextOwner - 1          // the contract appends the new owner at
                                      // nextOwnerIndex, which is slot newSlot
                                      // (ownerIndex = slot + 1)
2. base ← entryPoint.getNonce(sender, nonceKey)
3. flags = (accountIndex << 22) | FLAG_REGISTER_SLOT | newSlot
   SIGN_USEROP(…, nonce = base, the user's tx) — the device shows a
   "rotate slot" consent, then the user's transaction (nonce base+1)
4. Parse: type1_len MUST be 4192.
     newOwnerBytes = section[0..64]   (pkSeed(32) || pkRoot(32))
     type1         = section[64..4192]
5. Verify before submitting (recommended; `tools/verify-c10-sig rotation`
   is a reference implementation):
     - pkSeed[16..32] == 0 (N-masked);
     - the bootstrap signature in type1 verifies, under the wallet's
       bootstrap key (ownerAtIndex(0), or GET_INIT_CODE bytes 24..88), over
       sphincsDigest(Type-1 UserOp from step 6);
     - the Type-2 signature verifies under newOwnerBytes.
     At minimum, simulate both UserOps (eth_call / bundler simulation).
6. Type-1 UserOp:
     nonce = base, initCode = 0x, paymasterAndData = 0x,
     callData = addOwnerBytes(newOwnerBytes)
              = 0x101490cb || uint256(0x20) || uint256(0x40) || newOwnerBytes
     the five gas words exactly as sent in the request,
     signature = type1
   Submit it ALONE and wait for inclusion.
7. Type-2 UserOp: nonce = base + 1, ownerIndex = newSlot + 1,
     callData = executeWithOffchainCount(newSlot + 1, new_offchain_count, …),
     signature = type2. Submit after step 6 is mined.
```

The two UserOps cannot share a bundle: EntryPoint v0.6 runs every op's
validation before any execution, and the new slot's key is installed only when
`addOwnerBytes` executes. If the Type-1 fails to land, do not blindly re-request
— each request releases another bootstrap signature. Check `nextOwnerIndex`
first; if the slot was installed, sign the Type 2 again with no flag.

The firmware binds both halves: the rotation confirmation and Type-1 signature
use `base`, the transaction confirmation and Type-2 signature use `base+1`; both
display the same exact high-192 nonce lane when nonzero, and sequence overflow
is refused before it can change lanes. The returned owner bytes are copied out
of the exact signed `addOwnerBytes` calldata and FI-checked against the new
slot's key before release; a fail-initialised consent receipt proves the
rotation dialog was confirmed before the bootstrap key is derived and again
before it signs.

### 11.4a Signature-count sync (`INS 0x64 OFFCHAIN_SYNC`)

After a restore, or when the same seed runs on a second device, the device's
per-slot off-chain count can be behind the chain's `offchainSigCount[i]`.
Send the true on-chain value; the device shows *Update signature count?* with
its own count, the app's count and the signatures left. A jump of more than
1,000, or fewer than 1,000 left, adds a **! CAREFUL** page. A target that
would leave the slot 0 signatures is refused (`SW 0x6985`) with no dialog and
no write — rotate (§11.4) instead.

### 11.5 Receive Address Verification

```
addr ← GET_WALLET_ADDRESS(accountIndex, show = 1)   // show flag: protocol 0x0202+
Device OLED shows the full EIP-55 address behind a physical confirm; the user
visually verifies it against the companion UI, then approves on device.
Companion compares `addr` against any cached value and surfaces a warning on mismatch.
```

The OLED display happens ONLY when the companion passes `show = 1`
(firmware reporting `< 0x0202` has no display path and rejects the flag);
without the flag the address is returned silently.

### 11.6 Recovery on a New Device

```
1. User enters the same 24 words into the new device's first-boot wizard.
2. UNLOCK
3. For each account_index the user wants to restore:
     addr ← GET_WALLET_ADDRESS(account_index)
   All addresses match their originals (deterministic from seed).
4. For each (chain, account) pair, read on-chain state:
     nextOwner = wallet.nextOwnerIndex()
     recover the active slot_index from persisted companion state or historical
     registration records; the companion must not derive wallet secrets.
5. If the active slot mapping cannot be recovered, rotate into a fresh slot
   (§11.4): `slot_index = nextOwner - 1` has never been registered on-chain.
```

### 11.7 Contract Interactions (DeFi, ERC-20, etc.)

Same as §11.3. The companion builds the inner `(to, value, data)` triple and
supplies every metadata/descriptor proof explicitly; the non-secure handler
does not inject database entries. ERC-7730, ERC-20, Safe, and CoW routes decode
and render only after their current authenticated trailers verify. A tuple in
the firmware-pinned known-call filter refuses when its required descriptor is
missing or invalid; genuinely unknown calls may use the loud generic ladder.
Follow the normative ERC-7730 guide rather than the retired trailer section
that used to live here.

### 11.8 Off-chain Signing (EIP-1271 / ERC-6492)

For signature requests that **don't** turn into a UserOp — dapp logins
(SIWE), order signing (Cowswap, Permit2), gasless off-chain receipts —
the companion calls `INS_V2_SIGN_OFFCHAIN` (0x62). Two output modes
are selected by the input `flags` byte:

```
Header (17 bytes):
  [ 0..  1)  account_index    (u8)
  [ 1..  9)  chain_id         (u64 BE)
  [ 9.. 13)  slot_index       (u32 BE)
  [13.. 14)  kind             (u8: 0 = RAW32, 1 = PERSONAL_SIGN,
                                    2 = EIP712_TYPED, 3 = EIP712_TYPED_V3)
  [14.. 16)  payload_len      (u16 BE)
  [16.. 17)  flags            (u8 — bit 0 = OFFCHAIN_FLAG_ACCOUNT_DEPLOYED)
  [17..   )  payload          (32 B for RAW32, raw message bytes ≤700 for PERSONAL_SIGN)
```

**PERSONAL_SIGN display budget (2026-10-19).** The device shows the whole
message or refuses it (before any state write). A message whose bytes are all
printable ASCII (`0x20..=0x7E`) or line feed is text: each line feed starts a
new row, each line wraps at 16 columns, and the message may take at most
`MAX_OFFCHAIN_PERSONAL_SIGN_TEXT_ROWS` (72) rows. Anything else (CR, TAB, other
control bytes, DEL, any byte ≥ 0x80 — so all non-ASCII UTF-8) is shown as hex
under a `! NOT TEXT` warning and may be at most
`MAX_OFFCHAIN_PERSONAL_SIGN_HEX_LEN` (512) bytes. A companion that would
exceed either budget sends the message's EIP-191 digest as RAW32 instead
(the device then shows only the hash).

**RAW32 sends the dapp's *raw* hash, not a pre-wrapped one.** For
`kind = RAW32` the 32-byte payload is the exact `rawHash` the dapp passes
to `wallet.isValidSignature(rawHash, …)`. The firmware itself applies the
Solady replay-safe EIP-712 nesting before signing — the companion MUST
NOT pre-nest. (This is a security requirement: the on-chain UserOp path
verifies a bare SHA-256 `sphincsDigest`, so a firmware that signed a
companion-chosen 32-byte value verbatim would be a UserOp-forgery oracle.
Fixed 2026-06-11.)

**RAW32 is a loud blind tier, not a typed-data fallback.** Replay-safe nesting
prevents a UserOp-forgery oracle, but the firmware cannot determine whether the
companion obtained `rawHash` by hashing otherwise-supported EIP-712 data. A
hostile companion can suppress those semantic pages by submitting the final
hash as RAW32; the device warns `! BLIND RAW32` and shows the complete hash.
Preserve the dapp-requested signing method. Production should disable RAW32
unless an explicit compatibility decision accepts this residual.

**Companion responsibility — set the `account_deployed` bit:** before
each call, the companion checks `eth_getCode(predicted_address)` on
the target chain. If the response is non-empty, set bit 0
(`OFFCHAIN_FLAG_ACCOUNT_DEPLOYED = 0x01`); otherwise clear it.

#### Deployed path (bit set) — 4016 B response

```
[new_local_offchain_count (8 B BE)]
[C10 sig (4008 B)]
```

The companion wraps as `abi.encode(uint256 ownerIndex, bytes c10Sig)`
with `ownerIndex = slot_index + 1`, and the dapp calls
`wallet.isValidSignature(rawHash, wrappedSig)`. Byte-identical to the
pre-EIP-6492 wire format.

#### Counterfactual path (bit clear) — 8616 B response

```
[new_local_offchain_count (8 B BE)]
[ERC-6492 wrapped sig (8608 B)]
   = abi.encode(
       address factory,           // PQ_SMART_WALLET_FACTORY
       bytes   factoryCalldata,   // = initCode[20..]  (4260 B)
       bytes   signatureWrapper)  // abi.encode(1, c10Sig) (4128 B)
   || 0x6492649264926492649264926492649264926492649264926492649264926492
```

The companion passes the 8608-byte blob to the dapp as the signature.
Any EIP-6492-aware verifier (viem `verifyMessage`, Solady
`SignatureCheckerLib.isValidERC6492SignatureNow`, Ambire
`UniversalSigValidator`) detects the magic suffix, ABI-decodes the
tuple, deploys the wallet via the factory call inside a single
`eth_call`, and then runs `isValidSignature` against the freshly-
deployed account — all in one round trip, no on-chain state change.

**Constraints on the counterfactual path:**

- `slot_index` MUST be `0`. The factory's `createAccount(...)` only
  seeds bootstrap (ownerIndex 0) + slot 0 (ownerIndex 1); a wrapped
  sig on any other slot is unverifiable after the factory call runs.
  The firmware rejects with `InvalidPointer` otherwise.
- On a never-used wallet the firmware auto-registers slot 0 with
  `local_offchain = last_userop = 0` before bumping. Subsequent calls
  follow the normal gap (≤ `MAX_OFFCHAIN_GAP`) and combined-cap
  (≤ `MAX_SLOT_USES`) logic.
- The off-chain counter still bumps. Once the wallet is eventually deployed by
  the slot-0 Type-2 UserOp carrying the factory `initCode`, the existing
  `executeWithOffchainCount(...)` publish path overwrites the
  on-chain `offchainSigCount[1]` to reflect any 6492-signed off-chain
  history.

**Workflow:**

```
1. accountDeployed ← (eth_getCode(predicted) != "0x")
2. flags = accountDeployed ? 0x01 : 0x00
3. SIGN_OFFCHAIN(account=N, chain=C, slot=accountDeployed ? K : 0,
                 kind=PERSONAL_SIGN, msg, flags)
   → response: 4016 B (deployed) | 8616 B (counterfactual)
4. Strip the leading 8 B count; the remainder is the dapp-shaped sig.
   - Deployed: wrap as abi.encode(slot+1, c10Sig) before passing to the dapp.
   - Counterfactual: pass the 8608 B blob through unchanged — it is
     already EIP-6492-compatible.
```

#### ERC-6492 verifier requirements (dapp side) — audit I-3

The PQSmartWallet contract inherits Solady's ERC-6492 unwrap, but the
**deploy-then-verify simulation** for counterfactual sigs lives on the
dapp's side (Solady's `SignatureCheckerLib.isValidERC6492SignatureNow*`,
Ambire's `UniversalSigValidator`, viem's `verifyMessage`).

A naive 6492 verifier (`call factory.create(factoryCalldata); then
signer.isValidSignature(hash, sig)`) is **fool-able by an attacker**
who supplies:

- An arbitrary `factory` address (an attacker-controlled contract),
- `factoryCalldata` that deploys a "wallet" at any address the attacker
  chooses,
- A sig that the attacker's "wallet" accepts unconditionally.

CREATE2 prevents this **only if** the dapp checks that the deployed
address matches the **predicted** address — and the standard 6492
envelope does NOT carry the predicted address, so the dapp must
compute it externally.

**Rule for dapps integrating PQSmartWallet:** When verifying a
counterfactual PQSmartWallet signature, the dapp MUST check that the
signer address it is verifying against equals
`PQSmartWalletFactory.getAddress(masterPkSeed, masterPkRoot)` for the
user's bootstrap key. Do NOT trust the `factory` field inside the 6492
envelope to determine the signer's identity — that field is
attacker-controlled. Use a 6492 verifier that takes the signer address
as an explicit input (Solady's `isValidERC6492SignatureNow`, viem's
`verifyMessage`) and rejects any envelope whose factory call produces
a different address.

The PQSmartWallet contract itself imposes no constraint here: it only
sees the unwrapped inner signature once the dapp's verifier has
authenticated the factory call, so the threat is purely client-side.

---

## 12. Current clear-sign trailers (normative redirect)

CoW, Aave, and ERC-7730 shapes are decoded natively on-device. The companion must explicitly supply current
Merkle-authenticated metadata/descriptor bundles; the non-secure USB layer does
no database or display-text injection.

Implement only the layouts in:

- [`companion-erc7730-implementation-guide.md` §6](companion-erc7730-implementation-guide.md#6-where-the-trailer-goes-in-each-command) for the seven positional single-UserOp slots, names framing, batch kind-7 routing, and off-chain typed-data trailers;
- [`companion-batch-sign-integration.md`](companion-batch-sign-integration.md) for all batch TLV kinds and their current caps;
- [`companion-safe-cowswap-presign.md`](companion-safe-cowswap-presign.md) for the native CoW canonical and Safe/MultiSend binding;
- [`usb-protocol-v2.md`](usb-protocol-v2.md) for transport and response framing.

---

## 13. Error Handling

### Device state machine

```
UNPROVISIONED --[first-boot wizard]--> LOCKED
LOCKED        --[UNLOCK + correct PIN]--> UNLOCKED
UNLOCKED      --[LOCK or 120s inactivity]--> LOCKED (auto-zeroise)
```

### Common error scenarios

| Scenario                      | SW       | Companion action                              |
|-------------------------------|----------|-----------------------------------------------|
| Device locked                 | `0x6985` | Prompt `UNLOCK`                                |
| Wrong PIN on device           | `0x6982` | Show `pin_remaining` from `GET_STATUS`         |
| User rejected on device       | `0x6982` | Surface "Transaction rejected on device"       |
| Idle timeout mid-sign         | `0x6984` | Re-`UNLOCK`, re-send sign command              |
| Missing/malformed required clear-sign bundle | `0x6A80` | Hard catalogue/proof error; never retry without the proof |
| `data_len` out of range       | `0x6700` | Cap inner `data` at 4096 bytes                 |
| Both flag bits set            | `0x6A80` | Internal bug — INIT_CODE and REG_SLOT exclusive|
| `slot_index ≠ 0` with INIT    | `0x6A80` | INIT_CODE requires `slot_index = 0`            |
| `slot_index == 0` with REG    | `0x6A80` | REGISTER requires `slot_index ≥ 1`             |
| Not provisioned               | `0x6985` | Run first-boot wizard on the device            |
| USB disconnect mid-sign       | —        | Reconnect, `GET_STATUS`, retry                 |

### Timeout recommendations

| Operation            | Timeout | Reason                                 |
|----------------------|---------|----------------------------------------|
| GET_DEVICE_INFO      | 5 s     | Fast, no user interaction              |
| GET_STATUS           | 5 s     | Same                                   |
| UNLOCK               | 90 s    | User entering PIN on device            |
| GET_WALLET_ADDRESS   | 30 s    | <1 s keygen on cache miss              |
| SIGN_USEROP          | 120 s   | User reviewing tx + physical confirm   |
| GET_RESPONSE         | 5 s     | Data already buffered on device        |

---

## 14. Security Invariants

The companion app must respect these invariants. Violating them is either
impossible (enforced by the device) or creates a user-facing security
issue.

1. **PIN never crosses USB.** `UNLOCK` triggers on-device PIN entry. The
   companion has no way to send a PIN and must never prompt for one in
   its own UI.
2. **The device displays transaction details independently.** The LCD
   is driven entirely from the payload the device parsed — a compromised
   companion cannot fake a confirmation screen. Every UserOp confirmation
   also shows the exact zero-based `account_index` and the full EIP-55 signer
   address derived in secure world; the companion-supplied `sender` is never
   used as display authority. EntryPoint v0.6 nonce lane zero stays compact;
   every non-zero high-192 nonce key is rendered in full on a dedicated
   `Nonce lane key:` page, so two parallel-lane operations with the same
   low-64 sequence cannot produce identical trusted-display confirmations.
3. **Slot selection is the companion's responsibility.** Firmware is
   stateless with respect to `(chain_id, slot_index)`. Always read
   on-chain `nextOwnerIndex` / `slotUses[i]` before choosing an existing slot
   to sign with. Seedless rotation is blocked on wire v2.
4. **Bootstrap key never signs user transactions.** The contract dispatch
   rules reject any `ownerIndex = 0` signature on selectors other than
   `addOwnerBytes`. This is enforced on-chain, not by the companion — but
   the companion should never try to construct such a UserOp.
5. **Counters are one-way.** Neither `bootstrapUses` nor `slotUses[i]`
   can be reset. Prompt the user well before exhaustion.
6. **Address verification requires device confirmation — opt in with the
   `show` flag.** Always direct users to re-verify receive addresses on the
   device's LCD: pass `show = 1` with `GET_WALLET_ADDRESS` (protocol
   `0x0202`+), so the address appears on the trusted display behind a
   physical confirm. Without the flag the device shows nothing and the
   companion UI is the only display — do not rely on it alone.
7. **Clear-sign data must match the pinned roots.** The companion supplies
   ERC-7730, ERC-20, names, Safe, and CoW bundles explicitly. A root/version
   mismatch fails closed; there is no NS-side lookup or display-text injection.
8. **A compiled-catalogue miss is not an unknown-call proof.** Calls present in
   the firmware-pinned known-call filter still require their verified
   descriptor and refuse if it is absent.

---

## 15. Constants Reference

### Sizes (all bytes)

| Constant                         | Value  |
|----------------------------------|--------|
| SPHINCS+C10 raw signature        | 4,008  |
| Type 1 / Type 2 wrapper (ABI-encoded) | 4,128  |
| Type-1 rotation section (owner ‖ wrapper, 0x0203) | 4,192 |
| Max SIGN_USEROP response         | 12,620 |
| initCode (first deploy)          | 4,280  |
| SIGN_USEROP request header       | 330    |
| Max inner tx `data`              | 8,192 (4,096 without GET_DEVICE_INFO bit 5) |
| SHA-256 digest                   | 32     |
| Owner bytes (pkSeed ‖ pkRoot)    | 64     |
| pk_seed (raw)                    | 16     |
| pk_root (raw)                    | 16     |

### Flag masks (u32 BE)

| Constant                   | Value         |
|----------------------------|---------------|
| `FLAG_INCLUDE_INIT_CODE`   | `0x8000_0000` |
| `FLAG_REGISTER_SLOT`       | `0x4000_0000` |
| `ACCOUNT_INDEX_MASK`       | `0x3FC0_0000` |
| `ACCOUNT_INDEX_SHIFT`      | `22`          |
| `SLOT_INDEX_MASK`          | `0x003F_FFFF` |
| `MAX_ACCOUNT_INDEX`        | `0xFF`        |

### On-chain caps

| Constant              | Value   |
|-----------------------|---------|
| `MAX_BOOTSTRAP_USES`  | 65_536  |
| `MAX_SLOT_USES`       | 65_536  |
| Practical tx ceiling  | ~2³²    |

### Selectors

| Selector     | Function                                                                  |
|--------------|---------------------------------------------------------------------------|
| `0x14443c57` | `executeWithOffchainCount(uint256,uint256,address,uint256,bytes)`         |
| `0x101490cb` | `addOwnerBytes(bytes)`                                                    |

### Addresses (deterministic CREATE2; audit-freeze set)

UPDATE 2026-10-21: deployed on Ethereum Mainnet (1), Base Mainnet (8453)
and Base Sepolia (84532), on-chain codehashes compared with the pins
(`contracts/smart-wallet/deployments/`). The 2026-10-20 note below is kept
for history.

UPDATE 2026-10-20: the contracts were changed for the audit freeze, which
moved every address. Firmware built from that date predicts wallet addresses
from this set only. It is not deployed on any chain yet, so on-chain flows
(deploy, sign, EIP-1271 against a live wallet) fail until the owner deploys
it. Do not use the superseded 2026-06-12 Base Mainnet set
(`0xe8ce78cd…d452` factory): the firmware no longer predicts its addresses.

| Contract                 | Address                                      |
|--------------------------|----------------------------------------------|
| EntryPoint v0.6          | `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` |
| SPHINCsC10Asm verifier   | `0x7Ab9Abd09ef8A5D2ca06d9509BB295e637FA6aB4` |
| PQSmartWallet impl       | `0xEb64deaD5Ca0C433365EABC1AB6eBdeb28f53011` |
| PQSmartWalletFactory     | `0xE3dbA404dCeC30093DE26764965a51689C1607BD` |
| proxy init-code hash     | `0x17ca674095afe9dc82aa6f396ee01bd837449a127b6be59a0d947329f29b2570` |

The addresses are the same on every chain where this exact set is deployed
(Arachnid CREATE2 deployer, salt 0); on any other chain the predicted wallet
address has no code and cannot be deployed. `contracts/smart-wallet/deployments/`
records what is actually on which chain.

### Hash constants

| Constant              | Value                                                                |
|-----------------------|----------------------------------------------------------------------|
| `SHA256_EMPTY`        | `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `KECCAK_EMPTY`        | `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` |

Use `SHA256_EMPTY` for `paymaster_and_data_hash` when no paymaster is
attached. `KECCAK_EMPTY` is only needed when interacting with on-chain
artefacts that the EVM hashes with keccak (CREATE2, userOpHash).

### Chain IDs

Reference values only. A chain is usable when the audit-freeze set above is
deployed on it; as of 2026-10-21 that is Ethereum, Base and Base Sepolia
(see `contracts/smart-wallet/deployments/`). The chain also needs Cancun or later,
EntryPoint v0.6 at its canonical address and the Arachnid deployer.

| Chain          | chain_id |
|----------------|----------|
| Ethereum       | 1        |
| Base           | 8453     |
| Base Sepolia   | 84532    |
| Arbitrum One   | 42161    |
| Optimism       | 10       |
| Polygon        | 137      |

---

## Appendix A — Minimal WebHID transport (pseudocode)

```typescript
const VID = 0x1209;
const PID = 0x7051;
const REPORT_SIZE = 64;
const TAG_APDU = 0x05;
const CLA = 0xF0;
const INS_GET_RESPONSE = 0xC0;

async function connect(): Promise<HIDDevice> {
  const [dev] = await navigator.hid.requestDevice({
    filters: [{ vendorId: VID, productId: PID }],
  });
  if (!dev.opened) await dev.open();
  return dev;
}

function frameApdu(apdu: Uint8Array, channel = 0x0101): Uint8Array[] {
  const frames: Uint8Array[] = [];
  const first = new Uint8Array(REPORT_SIZE);
  first[0] = channel >> 8;  first[1] = channel & 0xFF;
  first[2] = TAG_APDU;
  first[5] = apdu.length >> 8; first[6] = apdu.length & 0xFF;
  const firstChunk = Math.min(57, apdu.length);
  first.set(apdu.subarray(0, firstChunk), 7);
  frames.push(first);

  let off = firstChunk, seq = 1;
  while (off < apdu.length) {
    const f = new Uint8Array(REPORT_SIZE);
    f[0] = channel >> 8; f[1] = channel & 0xFF;
    f[2] = TAG_APDU; f[3] = seq >> 8; f[4] = seq & 0xFF;
    const c = Math.min(59, apdu.length - off);
    f.set(apdu.subarray(off, off + c), 5);
    frames.push(f); off += c; seq++;
  }
  return frames;
}

async function receiveApdu(dev: HIDDevice): Promise<Uint8Array> {
  const buf: number[] = [];
  let expected = 0, seq = 0;
  for (;;) {
    const r = await new Promise<Uint8Array>((resolve) => {
      dev.addEventListener('inputreport', (e) =>
        resolve(new Uint8Array(e.data.buffer)), { once: true });
    });
    if (r[2] !== TAG_APDU) continue;
    if (seq === 0) {
      expected = (r[5] << 8) | r[6];
      buf.push(...r.slice(7, 7 + Math.min(57, expected)));
    } else {
      buf.push(...r.slice(5, 5 + Math.min(59, expected - buf.length)));
    }
    seq++;
    if (buf.length >= expected) return new Uint8Array(buf.slice(0, expected));
  }
}

async function sendApdu(dev: HIDDevice, ins: number, p1: number, p2: number, data?: Uint8Array) {
  const lc = data?.length ?? 0;
  const apdu = new Uint8Array(5 + lc);
  apdu[0] = CLA; apdu[1] = ins; apdu[2] = p1; apdu[3] = p2; apdu[4] = lc;
  if (data) apdu.set(data, 5);
  for (const f of frameApdu(apdu)) await dev.sendReport(0, f);

  const collected: number[] = [];
  let resp = await receiveApdu(dev);
  for (;;) {
    const sw = (resp[resp.length - 2] << 8) | resp[resp.length - 1];
    collected.push(...resp.slice(0, resp.length - 2));
    if ((sw >> 8) !== 0x61) return { sw, data: new Uint8Array(collected) };
    const more = new Uint8Array([CLA, INS_GET_RESPONSE, 0, 0, 0]);
    for (const f of frameApdu(more)) await dev.sendReport(0, f);
    resp = await receiveApdu(dev);
  }
}

async function sendChainedApdu(dev: HIDDevice, ins: number, payload: Uint8Array) {
  const MAX = 255;
  let off = 0, last: {sw: number, data: Uint8Array} | null = null;
  while (off < payload.length) {
    const c = Math.min(MAX, payload.length - off);
    const isLast = off + c >= payload.length;
    last = await sendApdu(dev, ins, isLast ? 0x00 : 0x80, 0x00, payload.slice(off, off + c));
    if (!isLast && last.sw !== 0x9000) return last;
    off += c;
  }
  return last!;
}
```

## Appendix B — SIGN_USEROP payload construction

```typescript
const FLAG_INCLUDE_INIT_CODE = 0x80000000 >>> 0;
const FLAG_REGISTER_SLOT     = 0x40000000;
const ACCOUNT_INDEX_SHIFT    = 22;
const ACCOUNT_INDEX_MASK     = 0x3FC00000;
const SLOT_INDEX_MASK        = 0x003FFFFF;

const SHA256_EMPTY = new Uint8Array([
  0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
  0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55,
]);

function buildSignPayload(p: {
  chainId: bigint,
  accountIndex: number,
  slotIndex: number,
  registerSlot: boolean,
  includeInitCode: boolean,
  sender: string, entryPoint: string,
  nonce: bigint,
  verGas: bigint, callGas: bigint,
  preVerificationGas: bigint,
  maxPriorityFeePerGas: bigint, maxFeePerGas: bigint,
  paymasterAndDataHash?: Uint8Array,
  to: string, value: bigint, data?: Uint8Array,
  erc20Bundle?: Uint8Array,
}): Uint8Array {
  if (p.registerSlot && p.includeInitCode) throw new Error('mutually exclusive flags');
  if (p.includeInitCode && p.slotIndex !== 0) throw new Error('INIT_CODE requires slotIndex=0');
  if (p.registerSlot && p.slotIndex === 0)     throw new Error('REG_SLOT requires slotIndex>=1');

  let flags = p.slotIndex & SLOT_INDEX_MASK;
  flags |= ((p.accountIndex & 0xFF) << ACCOUNT_INDEX_SHIFT) & ACCOUNT_INDEX_MASK;
  if (p.registerSlot)    flags |= FLAG_REGISTER_SLOT;
  if (p.includeInitCode) flags |= FLAG_INCLUDE_INIT_CODE;

  const head = concatBytes([
    u64be(p.chainId), u32be(flags >>> 0),
    hexToBytes(p.sender), hexToBytes(p.entryPoint),
    u256be(p.nonce),
    concatBytes([u128be(p.verGas), u128be(p.callGas)]),
    u256be(p.preVerificationGas),
    concatBytes([u128be(p.maxPriorityFeePerGas), u128be(p.maxFeePerGas)]),
    p.paymasterAndDataHash ?? SHA256_EMPTY,
    hexToBytes(p.to), u256be(p.value),
    u16be(p.data?.length ?? 0),
    p.data ?? new Uint8Array(0),
  ]);

  const erc20 = p.erc20Bundle ?? new Uint8Array(0);
  if (erc20.length === 0) return head;

  // Frozen reserved slot after ERC-20 metadata; firmware requires length 0.
  return concatBytes([head, u16be(erc20.length), erc20, u16be(0)]);
}
```

---

**Further reading**

- [`tools/webhid_test.html`](../../tools/webhid_test.html) — canonical
  reference implementation (transport, multi-account picker, publish-ready
  UserOp JSON + cast-send one-liner).
- [`CLAUDE.md`](../../CLAUDE.md) — project-wide invariants, derivation
  contract, signing state machine.
- [`contracts/smart-wallet/src/PQSmartWallet.sol`](../../contracts/smart-wallet/src/PQSmartWallet.sol),
  [`…/PQSmartWalletFactory.sol`](../../contracts/smart-wallet/src/PQSmartWalletFactory.sol),
  [`…/PQMultiOwnable.sol`](../../contracts/smart-wallet/src/PQMultiOwnable.sol) —
  on-chain contract ABIs that validate the wrappers above.
- [`shared/src/lib.rs`](../../shared/src/lib.rs) — single source of truth
  for sizes, flag masks, and wire-format offsets.
