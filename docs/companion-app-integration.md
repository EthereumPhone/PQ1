# PQSigner Companion App Integration Guide

Self-contained reference for building a companion app (desktop, mobile, or
browser extension) that drives the PQSigner post-quantum hardware wallet.

The canonical reference implementation is
[`tools/webhid_test.html`](../tools/webhid_test.html) — a single-file WebHID
browser tool that exercises the full transport, sign flow, multi-account
picker, and publish-ready UserOp construction. Everything in this document
mirrors what that tool does; when in doubt, read its source.

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
12. [ERC-20 & ZK Clear-Sign Trailers](#12-erc-20--zk-clear-sign-trailers)
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
                                           | PIN entry (OLED)|
                                           | Tx display      |
                                           | SPHINCS+C10 sign|
                                           | ZK verify       |
                                           +------+----------+
                                                  |
                                     +------------+------------+
                                     |                         |
                               OPTIGA Trust M             NXP SE050
                               (entropy half_O)          (entropy half_E)
```

**Trust boundary.** The companion app is untrusted. The device independently:

- Prompts for PIN on its own trusted OLED — the PIN never crosses USB.
- Displays transaction details on its trusted OLED.
- Waits for physical button confirmation.
- Computes the SPHINCS+C10 signing digest natively.
- Verifies ZK proofs before displaying decoded actions.

The companion never sees the PIN, seed, or signing key. It sends opaque
commands and receives public data + signatures.

**One signing command.** After the all-C10 / multi-owner cutover, there is
exactly one signing instruction (`INS 0x30 SIGN_USEROP`). Every flow —
first deploy, normal transaction, slot rotation, ERC-20 transfer, ZK
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
| `0x6A80` | Wrong data (malformed payload, invalid ZK proof, bad trailer)|
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
| 0      | 2    | protocol_version  | u16 BE, currently `0x0200`             |
| 2      | 3    | fw_version        | major, minor, patch (currently 3.0.0)  |
| 5      | 16   | device_uid        | STM32 UID96; zeros on dev builds       |
| 21     | 4    | capabilities      | u32 BE bitmap (see below)              |
| 25     | 1    | sig_param_set     | `2` = SPHINCS+C10 (128-bit)            |
| 26     | 2    | sig_size          | u16 BE = `SIG_TYPE2_LEN` (4128)     |
| 28     | 4    | erc20_db_version  | u32 BE, zero if unset                  |
| 32     | 4    | vk_db_version     | u32 BE, zero if unset                  |
| 36     | 2    | ep_version        | u16 BE = `0x0006` (EntryPoint v0.6)    |
| 38     | 2    | wrapper_overhead  | u16 BE = `SIG_TYPE2_HEADER_LEN`     |

**Capability bitmap** — currently advertises `CAP_SIGN_USEROP` only.
All other legacy flags are zero. Do not rely on individual bits beyond
this; instead branch on `ep_version` and `sig_param_set`.

---

### INS 0x02 — GET_STATUS

Check device state. No unlock required.

**Request:** empty

**Response (3 bytes + SW):**

| Offset | Field         | Values                                  |
|--------|---------------|-----------------------------------------|
| 0      | provisioned   | 0 = not provisioned, 1 = provisioned    |
| 1      | locked        | 0 = unlocked, 1 = locked                |
| 2      | pin_remaining | 0–10 attempts remaining                 |

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

**Request (0 or 4 bytes):**

| Offset | Size | Field         | Notes                                    |
|--------|------|---------------|------------------------------------------|
| 0      | 4    | account_index | u32 BE, `0..=255`                        |

An **empty body is accepted as `account_index = 0`** for companions that
pre-date multi-account support.

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
| `FLAG_REGISTER_SLOT` + slot_index ≥ 1    | Type 1 (bootstrap) + Type 2 (slot) |

`FLAG_INCLUDE_INIT_CODE` and `FLAG_REGISTER_SLOT` are **mutually
exclusive**. Firmware rejects both set.

**Response: 3-chunk bundle**, drained via `GET_RESPONSE`:

```
[init_code_len (4 BE)][init_code    (0 or 4280 B)]
[type1_len     (4 BE)][type1_wrapper(0 or 4128 B)]   — abi.encode(uint256,bytes)
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
|     12 |   20 | `sender`                  | PQSmartWallet address                            |
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
|    328 |    2 | `data_len`                | u16 BE, `0..=4096`                               |
|    330 |    N | `data`                    | inner tx calldata                                |

> ⚠️ `paymaster_and_data_hash` is SHA-256 of `paymasterAndData`. This
> matches `PQSmartWallet.sphincsDigest`, which re-hashes the UserOp's
> paymaster field with SHA-256 rather than keccak. When `paymasterAndData`
> is empty, use the constant
> `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
> (`sha256("")`).

### Optional trailers (after calldata)

Send **neither** or **both** length prefixes. If either is present, both
must be present (even if one length is zero).

```
[erc20_bundle_len (2 BE)][erc20_bundle …]
[zk_bundle_len    (2 BE)][zk_bundle    …]
```

See [§12](#12-erc-20--zk-clear-sign-trailers) for trailer contents. The
non-secure USB handler will **opportunistically inject** an ERC-20
bundle when the companion omits all trailers and `(chain_id, to)` matches
the NS-side token DB, and likewise a VK bundle when the companion supplied
only the fixed ZK block without one. That mechanism is transparent to
the companion — if you need deterministic behaviour (e.g. for tests),
construct the bundles yourself.

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
const icLen = readU32BE(resp, off); off += 4;
const initCode = icLen > 0 ? resp.slice(off, off + icLen) : null; off += icLen;

const t1Len = readU32BE(resp, off); off += 4;
const type1 = t1Len > 0 ? resp.slice(off, off + t1Len) : null; off += t1Len;

const t2Len = readU32BE(resp, off); off += 4;
const type2 = resp.slice(off, off + t2Len);  // always present
```

Chunk sizes are fixed when present: `initCode` is exactly **4280 B**,
Type 1 and Type 2 wrappers are each exactly **4128 B**.

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

    // ── Execution (self-call only, via EntryPoint) ──────────────────
    function execute(address target, uint256 value, bytes calldata data)
        external returns (bytes memory);
    function executeBatch(Call[] calldata calls) external;

    // ── Multi-owner management ──────────────────────────────────────
    function addOwnerBytes(bytes calldata newOwner) external;
    function removeOwnerAtIndex(uint256 index, bytes calldata owner) external;
    function ownerAtIndex(uint256 index) external view returns (bytes memory);
    function nextOwnerIndex() external view returns (uint256);
    function ownerCount() external view returns (uint256);
    function isOwnerBytes(bytes memory owner) external view returns (bool);

    // ── Usage counters ──────────────────────────────────────────────
    function bootstrapUses() external view returns (uint256);
    function slotUses(uint256 ownerIndex) external view returns (uint256);

    // ── Convenience views ───────────────────────────────────────────
    function masterPkSeed() external view returns (bytes32);
    function masterPkRoot() external view returns (bytes32);
}
```

**Key selectors:**

| Selector     | Function                                     |
|--------------|----------------------------------------------|
| `0xb61d27f6` | `execute(address,uint256,bytes)`             |
| `0x101490cb` | `addOwnerBytes(bytes)`                       |

The companion builds inner-tx `callData` for `execute(...)` by ABI-encoding
directly — see `encodeExecuteCalldata` in the WebHID tool.

### Dispatch rules (enforced inside `_validateSignature`)

| `ownerIndex` | Required inner call        | Counter bumped                  |
|--------------|----------------------------|---------------------------------|
| `0`          | `addOwnerBytes(bytes)`     | `bootstrapUses` (cap 65_536)    |
| `≥ 1`        | `execute` / `executeBatch` / `removeOwnerAtIndex` | `slotUses[ownerIndex]` (cap 65_536) |

Any other selector from a slot owner is rejected. The bootstrap owner
(index 0) can **only** add new owners — never move funds directly.

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
- When `slotUses[currentSlot]` approaches `MAX_SLOT_USES`, register the
  next slot (`FLAG_REGISTER_SLOT`, `slot_index + 1`) ahead of time.
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

Per-slot derivation from `slot_master` + `slot_index`:
```
slot_entropy = sha256(slot_master || "slot_entropy" || slot_index_BE4)
slot_r       = sha256(slot_master || "slot_r"    || slot_index_BE4)
slot_sk_seed = sha256("slot_c10_sk_seed" || slot_entropy)
slot_pk_seed = sha256("slot_c10_pk_seed" || slot_entropy) & N_MASK
slot_sk      = sphincs_c10::SigningKey::keygen(slot_sk_seed, slot_pk_seed)
```

**Recovery contract.** The domain tags above are load-bearing and
frozen. Any companion that re-derives keys locally (for proofs,
attestation, etc.) must use the exact same tags, and must use the
`-acct` variants **only** when `account_index > 0`.

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
GET_STATUS                         → provisioned? locked?
if locked:
    UNLOCK                         → user enters PIN on device
GET_WALLET_ADDRESS(account_index=0) → <1 s first time, then wallet address
```

### 11.2 First Deploy on a New Chain

```
1. accountIndex ← user's choice (default 0)
2. sender ← GET_WALLET_ADDRESS(accountIndex)
3. Confirm off-chain: eth_getCode(sender) == "0x"
4. nonce = 0  (first UserOp for this sender)
5. Build SIGN_USEROP payload:
     flags            = FLAG_INCLUDE_INIT_CODE | (accountIndex << 22)  // slot_index = 0
     paymaster_hash   = SHA256_EMPTY
     gas              = bundler estimate (budget ≥ 800K verGas — factory deploy + C10 verify)
     to/value/data    = the inner tx you want to execute on deploy

6. Send chained APDU. Device displays:
     a. "First deploy on chain N?"
     b. Inner tx preview
     Request signing after button confirm.

7. Parse response:
     initCode (4280 B), type1=null, type2 (4128 B)
8. Build UserOperation06:
     sender, nonce=0, initCode, callData = execute(to,value,data),
     callGasLimit, verificationGasLimit, preVerificationGas,
     maxFeePerGas, maxPriorityFeePerGas,
     paymasterAndData = "0x",
     signature = type2
9. Submit via eth_sendUserOperation
   → EntryPoint.createSender → factory.createAccount → wallet execute(...)
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
2. slotIdx ← whichever slot ownerIndex ≥ 1 is active and has budget
3. nonce   ← entryPoint.getNonce(sender, 0)
4. flags   = (accountIndex << 22) | slotIdx    // no flag bits set

5. SIGN_USEROP(…) → initCode=null, type1=null, type2 (4128 B)
6. Build UserOperation06 with signature = type2.
7. Submit via bundler.
```

### 11.4 Slot Rotation (current slot nearing cap)

Triggered when `wallet.slotUses(currentOwnerIndex)` approaches 65_536,
or as a defensive re-roll after suspected key exposure.

```
1. slotIdx ← current slot index
2. newSlotIdx ← slotIdx + 1
3. flags = FLAG_REGISTER_SLOT | (accountIndex << 22) | newSlotIdx
4. SIGN_USEROP(…)
   → initCode=null
   → type1 (4128 B, ownerIndex=0 — bootstrap signs addOwnerBytes)
   → type2 (4128 B, ownerIndex=N+1 — new slot signs the intended user tx)

5. Submit TWO UserOps to the bundler, in order:
   a. UserOp #1 (type1):  sender, nonce=base,   callData = addOwnerBytes(newOwnerBytes)
   b. UserOp #2 (type2):  sender, nonce=base+1, callData = execute(to,value,data)

```

> ⚠️ **Open item.** The 64-byte `newOwnerBytes = pkSeed‖pkRoot` needed to
> build UserOp #1's calldata is **not** currently emitted in the
> `SIGN_USEROP` response. The WebHID reference tool logs a TODO and
> skips Type 1 submission. Until the firmware wire format is extended
> to include the new slot's public key, production companions should
> either (a) re-derive the slot keypair locally from the seed (requires
> holding the seed in the companion — generally unacceptable) or
> (b) add a dedicated companion-visible getter and bump the protocol
> version.

### 11.5 Receive Address Verification

```
addr ← GET_WALLET_ADDRESS(accountIndex)
Device OLED shows "Your wallet address: 0x…"; user visually verifies.
Companion compares `addr` against any cached value and surfaces a warning on mismatch.
```

### 11.6 Recovery on a New Device

```
1. User enters the same 24 words into the new device's first-boot wizard.
2. UNLOCK
3. For each account_index the user wants to restore:
     addr ← GET_WALLET_ADDRESS(account_index)
   All addresses match their originals (deterministic from seed).
4. For each (chain, account) pair, read on-chain state:
     nextOwner = wallet.nextOwnerIndex()
     for each ownerIndex in [0, nextOwner):
         owner = wallet.ownerAtIndex(ownerIndex)
         // Compare against the companion's slot-derivation to find
         // which slot_index this ownerIndex corresponds to.
5. Pick a fresh slot index (> any currently-registered one) and
   rotate into it on first sign — the safest recovery posture.
```

### 11.7 Contract Interactions (DeFi, ERC-20, etc.)

Same as §11.3. The companion builds the inner `(to, value, data)` triple;
the device shows a human-friendly confirmation page when:

- `data` matches `transfer(address,uint256)` on a token from the ERC-20
  DB (NS-side opportunistic inject, or companion-supplied).
- The `zk_bundle` trailer validates a Groth16 clear-sign attestation for
  the target protocol.

Otherwise the device shows raw `(to, value, calldata hex)` so the user
can still reason about the call. See [§12](#12-erc-20--zk-clear-sign-trailers).

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
  [13.. 14)  kind             (u8: 0 = RAW32, 1 = PERSONAL_SIGN)
  [14.. 16)  payload_len      (u16 BE)
  [16.. 17)  flags            (u8 — bit 0 = OFFCHAIN_FLAG_ACCOUNT_DEPLOYED)
  [17..   )  payload          (32 B for RAW32, raw message bytes ≤700 for PERSONAL_SIGN)
```

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
- The off-chain counter still bumps. Once the wallet is eventually
  deployed by a Type 1 UserOp, the existing
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

## 12. ERC-20 & ZK Clear-Sign Trailers

The SIGN_USEROP payload supports two optional trailers that replace the
pre-cutover `SIGN_CLEAR_USEROP` / `SIGN_MESSAGE` / EIP-712 instructions.

### Layout recap

```
<header 266 B>
<data data_len>
[erc20_bundle_len (2 BE)][erc20_bundle]
[zk_bundle_len    (2 BE)][zk_bundle]
```

- Either both length prefixes are present, or neither.
- An empty section is encoded as `[0x00 0x00]` (length prefix, no body).
- Maximum combined trailer length bounded by `CHAIN_BUF_LEN` (≈ 8 KB).

### ERC-20 metadata bundle

Merkle-verified record that lets the device render
"Send 1 USDC to 0x…" instead of "Call 0x… with 36-byte calldata":

```
sha256(0x00 || chain_id[8 LE] || contract[20] || decimals[1] ||
       name_len[1] || name_bytes || symbol_len[1] || symbol_bytes)
```

Internal Merkle nodes: `sha256(0x01 || left[32] || right[32])`.

The secure world holds a 32-byte Merkle root; the bundle is the leaf
record plus the sibling path. The NS-side companion ships a matching
copy of this DB and looks up entries by `(chain_id, contract_addr)`.

If the companion omits the trailer entirely, the NS-side handler will
look the token up in its own NS flash DB and inject the bundle on the
companion's behalf — the secure world re-verifies every byte regardless.

### ZK clear-sign bundle

Used for protocol actions that don't map to an ERC-20 transfer:

```
zk_bundle = proof(384) || calldata_attested(164) || readable(64) [|| vk_bundle]
```

- `proof` — Groth16 proof over BLS12-381, generated off-device with
  snarkjs or equivalent.
- `calldata_attested` — the full inner calldata the circuit committed to,
  zero-padded to 164 bytes. The first 132 bytes (selector + 4×32 args)
  must match the `data` field in the header; bytes 132..164 are the
  circuit's zero-padding.
- `readable` — the human-readable string the proof attests to, null-padded
  to 64 bytes.
- `vk_bundle` (optional) — the protocol VK plus its Merkle authentication
  path against the on-device VK DB root. If omitted, the NS-side handler
  looks up `(chain_id, to)` in the NS VK DB and injects the bundle.

The device Merkle-verifies the VK, runs the Groth16 verifier, displays
the readable string on the OLED, and only then proceeds to the PIN-gated
signing step.

The reference WebHID tool exposes this via the "Test: ZK clear-sign
(Aave V3 supply)" button — see the `AAVE_*` constants and
`$('testZkAaveBtn')` handler for a complete worked example.

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
| Malformed ZK proof            | `0x6A80` | Bug in circuit / prover                        |
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
2. **The device displays transaction details independently.** The OLED
   is driven entirely from the payload the device parsed — a compromised
   companion cannot fake a confirmation screen.
3. **Slot selection is the companion's responsibility.** Firmware is
   stateless with respect to `(chain_id, slot_index)`. Always read
   on-chain `nextOwnerIndex` / `slotUses[i]` before choosing a slot to
   sign with or to rotate to.
4. **Bootstrap key never signs user transactions.** The contract dispatch
   rules reject any `ownerIndex = 0` signature on selectors other than
   `addOwnerBytes`. This is enforced on-chain, not by the companion — but
   the companion should never try to construct such a UserOp.
5. **Counters are one-way.** Neither `bootstrapUses` nor `slotUses[i]`
   can be reset. Prompt the user well before exhaustion.
6. **Address verification requires device confirmation.** Always direct
   users to re-verify receive addresses on the device's OLED via
   `GET_WALLET_ADDRESS`, not just in the companion UI.
7. **ZK proofs are generated off-device.** The companion runs snarkjs (or
   equivalent) to produce Groth16 proofs for clear-signed actions. The
   device only verifies.
8. **VK and ERC-20 databases must match the device.** Version mismatch
   causes Merkle verification failure on the device (`SW = 0x6A80`).
   Check versions via `GET_DEVICE_INFO`.

---

## 15. Constants Reference

### Sizes (all bytes)

| Constant                         | Value  |
|----------------------------------|--------|
| SPHINCS+C10 raw signature        | 4,008  |
| Type 1 / Type 2 wrapper (ABI-encoded) | 4,128  |
| initCode (first deploy)          | 4,280  |
| SIGN_USEROP request header       | 266    |
| Max inner tx `data`              | 4,096  |
| Groth16 proof                    | 384    |
| ZK attested calldata             | 164    |
| ZK readable (EIP-1559)           | 64     |
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

### Addresses (deterministic CREATE2 — same on Base Sepolia and Base Mainnet)

| Contract                 | Address                                      |
|--------------------------|----------------------------------------------|
| EntryPoint v0.6          | `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` |
| SPHINCsC10Asm verifier   | `0xb32e32a532d03a160ceb35af39b4a95ba4881fc7` |
| PQSmartWallet impl       | `0x155d7da5feef1811214a1271335a19fb3fce8f1e` |
| PQSmartWalletFactory     | `0x67943487e9e41a9ee5f5f7a10f18aa82fe19e03b` |

Run-the-tool defaults (RPC: `https://sepolia.base.org`, beneficiary:
`0x00137482d6b37eBb235A463D748191D925D92eB3`). Mainnet / other L2
deployments are tracked in the project README.

### Hash constants

| Constant              | Value                                                                |
|-----------------------|----------------------------------------------------------------------|
| `SHA256_EMPTY`        | `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `KECCAK_EMPTY`        | `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` |

Use `SHA256_EMPTY` for `paymaster_and_data_hash` when no paymaster is
attached. `KECCAK_EMPTY` is only needed when interacting with on-chain
artefacts that the EVM hashes with keccak (CREATE2, userOpHash).

### Chain IDs

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
  erc20Bundle?: Uint8Array, zkBundle?: Uint8Array,
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
  const zk    = p.zkBundle    ?? new Uint8Array(0);
  if (erc20.length === 0 && zk.length === 0) return head;

  return concatBytes([head, u16be(erc20.length), erc20, u16be(zk.length), zk]);
}
```

---

**Further reading**

- [`tools/webhid_test.html`](../tools/webhid_test.html) — canonical
  reference implementation (transport, multi-account picker, publish-ready
  UserOp JSON + cast-send one-liner).
- [`CLAUDE.md`](../CLAUDE.md) — project-wide invariants, derivation
  contract, signing state machine.
- [`contracts/smart-wallet/src/PQSmartWallet.sol`](../contracts/smart-wallet/src/PQSmartWallet.sol),
  [`…/PQSmartWalletFactory.sol`](../contracts/smart-wallet/src/PQSmartWalletFactory.sol),
  [`…/PQMultiOwnable.sol`](../contracts/smart-wallet/src/PQMultiOwnable.sol) —
  on-chain contract ABIs that validate the wrappers above.
- [`shared/src/lib.rs`](../shared/src/lib.rs) — single source of truth
  for sizes, flag masks, and wire-format offsets.
