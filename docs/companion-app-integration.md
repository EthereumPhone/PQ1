# PQSigner Companion App Integration Guide

Self-contained reference for building a companion app (desktop, mobile, or
browser extension) that drives the PQSigner post-quantum hardware wallet.
Everything the companion needs is in this document -- no firmware source access
required.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [USB HID Transport](#2-usb-hid-transport)
3. [APDU Protocol (v2)](#3-apdu-protocol-v2)
4. [Command Reference](#4-command-reference)
5. [PQSignatureWrapper](#5-pqsignaturewrapper)
6. [Smart Contract ABIs](#6-smart-contract-abis)
7. [On-Chain State](#7-on-chain-state)
8. [Multi-Chain Key Architecture](#8-multi-chain-key-architecture)
9. [Companion App Workflows](#9-companion-app-workflows)
10. [ZK Clear Signing](#10-zk-clear-signing)
11. [ERC20 & VK Database Bundles](#11-erc20--vk-database-bundles)
12. [Safe & CowSwap Integration](#12-safe--cowswap-integration)
13. [Error Handling](#13-error-handling)
14. [Security Invariants](#14-security-invariants)
15. [JARDIN Compact Signing](#15-jardin-compact-signing)
16. [Constants Reference](#16-constants-reference)

---

## 1. Architecture Overview

```
 Companion App                              PQSigner Device
 ============                              ===============
                                           +-----------------+
  Build unsigned tx                        | NON-SECURE      |
  Query chain state  ---- USB HID APDU --> | USB HID + APDU  |
  ABI-encode wrapper                       | route to gateway |
  Submit to bundler                        +------+----------+
                                                  | NSC gateway
                                           +------v----------+
                                           | SECURE WORLD    |
                                           | PIN entry (OLED)|
                                           | Tx display      |
                                           | SLH-DSA sign    |
                                           | ZK verify       |
                                           +------+----------+
                                                  |
                                     +------------+------------+
                                     |                         |
                               OPTIGA Trust M             NXP SE050
                               (entropy half_O)          (entropy half_E)
```

**Trust boundary:** The companion app is untrusted. The device independently:
- Displays transaction details on its trusted OLED
- Waits for physical button confirmation
- Reconstructs `execute()` calldata from the inner tx (never trusts companion's calldata)
- Computes the `userOpHash` natively
- Verifies ZK proofs before displaying decoded actions

The companion **never** sees the PIN, seed, or signing key. It sends opaque
commands and receives public data + signatures.

---

## 2. USB HID Transport

| Property       | Value                                       |
|----------------|---------------------------------------------|
| USB class      | Custom HID (usage page `0xFFA0`)            |
| VID / PID      | `0x1209` / `0x7051`                         |
| Report size    | 64 bytes (interrupt EP1 IN/OUT)             |
| Framing        | Ledger-compatible APDU-over-HID             |
| Max reassembly | 8,192 bytes                                 |

### HID Frame Format

```
First frame (57 bytes payload):
  [0..2)  channel_id   u16 BE
  [2]     tag          0x05 = APDU
  [3..5)  sequence     u16 BE = 0x0000
  [5..7)  total_len    u16 BE (full APDU length)
  [7..64) data         up to 57 bytes

Continuation frames (59 bytes payload):
  [0..2)  channel_id   u16 BE
  [2]     tag          0x05
  [3..5)  sequence     u16 BE (1, 2, 3, ...)
  [5..64) data         up to 59 bytes
```

### Platform Notes

- **Linux:** Requires udev rule for non-root access:
  ```
  SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1209", ATTRS{idProduct}=="7051", MODE="0666"
  ```
- **Browser (WebHID):** `navigator.hid.requestDevice({ filters: [{ vendorId: 0x1209, productId: 0x7051 }] })`
- **macOS/Windows:** hidapi or node-hid work without extra config.

---

## 3. APDU Protocol (v2)

### APDU Envelope

```
Request:   CLA(1) INS(1) P1(1) P2(1) [Lc(1) Data(Lc)]
Response:  [Data] SW1(1) SW2(1)
```

| Field | Value                                          |
|-------|------------------------------------------------|
| CLA   | `0xF0` (v2 native)                             |
| P1    | `0x00` = last/only block, `0x80` = more follow |
| P2    | Command-specific (usually `0x00`)              |
| Lc    | 0-255 data bytes per APDU                      |

### Protocol Detection

Send any command with `CLA = 0xF0`. If the device returns `SW = 0x6E00`
(CLA not supported), fall back to `CLA = 0xE0` (v1 legacy, Keycard Shell
compatible). All new companion apps should target v2.

### Command Chaining (Large Requests)

For payloads exceeding 255 bytes (signing commands), send multiple APDUs
with the same INS:

- **P1 = 0x80**: more blocks follow
- **P1 = 0x00**: last or only block

The device accumulates data until it receives a final block (P1 = 0x00),
then executes the command.

### Response Chaining (GET_RESPONSE)

Signing responses can be thousands of bytes. The device returns the first
253 bytes with `SW = 0x61FF` (more data). The companion drains the rest
by repeatedly sending `INS 0xC0` (GET_RESPONSE) until `SW = 0x9000`.

```
Host -> Device:  SIGN_USEROP (chained)
Device -> Host:  [253 bytes] SW=0x61FF
Host -> Device:  GET_RESPONSE
Device -> Host:  [253 bytes] SW=0x61FF
... (~15 round-trips for 3,777-byte wrapper)
Host -> Device:  GET_RESPONSE
Device -> Host:  [remaining bytes] SW=0x9000
```

### Status Words

| SW       | Meaning                                                    |
|----------|------------------------------------------------------------|
| `0x9000` | Success                                                    |
| `0x61XX` | More data available (call GET_RESPONSE)                    |
| `0x6700` | Wrong length                                               |
| `0x6982` | Security not satisfied (wrong PIN, user rejected on device)|
| `0x6984` | Idle timeout -- device locked itself mid-operation         |
| `0x6985` | Conditions not satisfied (device locked, not provisioned)  |
| `0x6A80` | Wrong data (malformed payload, invalid ZK proof)           |
| `0x6D00` | INS not supported                                          |
| `0x6E00` | CLA not supported (use 0xE0 for v1 fallback)              |
| `0x6501` | Feature not supported (capability not present)             |
| `0x6F00` | Internal error                                             |

---

## 4. Command Reference

### INS 0x01 -- GET_DEVICE_INFO

Capability discovery. **Always call first.** No unlock required.

**Request:** empty

**Response (40 bytes):**

| Offset | Size | Field              | Description                          |
|--------|------|--------------------|--------------------------------------|
| 0      | 2    | protocol_version   | u16 BE, currently `0x0200`           |
| 2      | 1    | fw_major           | Firmware version major               |
| 3      | 1    | fw_minor           | Firmware version minor               |
| 4      | 1    | fw_patch           | Firmware version patch               |
| 5      | 16   | device_uid         | STM32 UID96 (zeros on dev builds)    |
| 21     | 4    | capabilities       | u32 BE bitmap (see below)            |
| 25     | 1    | sig_param_set      | 0 = C7-keccak256                     |
| 26     | 2    | sig_size           | u16 BE, raw signature bytes (3704)   |
| 28     | 4    | erc20_db_version   | u32 BE, YYYYMMDD                     |
| 32     | 4    | vk_db_version      | u32 BE, YYYYMMDD                     |
| 36     | 2    | ep_version         | u16 BE, EntryPoint version (0x0006)  |
| 38     | 2    | wrapper_overhead   | u16 BE, PQSignatureWrapper header (73)|

**Capability bitmap:**

| Bit | Feature                                      |
|-----|----------------------------------------------|
| 0   | UserOp signing (SIGN_USEROP)                 |
| 1   | ZK clear-sign calldata (SIGN_CLEAR_USEROP)   |
| 2   | EIP-712 typed-data signing (SIGN_EIP712)     |
| 3   | Personal message signing (SIGN_MESSAGE)      |
| 4   | Bootstrap signer (SIGN_BOOTSTRAP)            |
| 5   | Per-chain main key derivation (GET_MAIN_VK)  |
| 6   | CowSwap EIP-712 v3                           |
| 7   | Address verification (GET_WALLET_ADDRESS)    |
| 8   | Device attestation (reserved)                |
| 9   | EntryPoint v0.7 (reserved)                   |
| 10  | JARDIN compact signing (SIGN_JARDIN)         |

**Companion logic:**
```
total_wrapper_size = wrapper_overhead + sig_size  // 73 + 3704 = 3777
```

---

### INS 0x02 -- GET_STATUS

Check device state. No unlock required.

**Request:** empty

**Response (3 bytes):**

| Offset | Field         | Values                                  |
|--------|---------------|-----------------------------------------|
| 0      | provisioned   | 0 = not provisioned, 1 = provisioned    |
| 1      | locked        | 0 = unlocked, 1 = locked                |
| 2      | pin_remaining | 0-10 attempts remaining                 |

---

### INS 0x10 -- UNLOCK

Trigger PIN entry on the device's trusted OLED display. The PIN **never
crosses USB** -- the device handles everything internally.

**Request:** empty

**Response:** SW only

- `0x9000` -- unlocked successfully
- `0x6982` -- wrong PIN entered on device
- `0x6985` -- permanently locked (0 attempts remaining)
- `0x6984` -- user took too long, idle timeout

**Note:** This blocks until the user finishes PIN entry (~5-30 seconds).
Set USB timeout accordingly (recommend 60s).

---

### INS 0x11 -- LOCK

Explicitly lock the device, zeroizing all cached secrets.

**Request:** empty
**Response:** `SW 0x9000`

---

### INS 0x20 -- GET_BOOTSTRAP_VK

Return the bootstrap signer's 32-byte verifying key. This key is global
(not per-chain), set at provisioning, and never changes.

**No unlock required** -- the VK is public data.

**Request:** empty

**Response (32 bytes):**

```
[0..16)   pk_seed    16 bytes
[16..32)  pk_root    16 bytes
```

The bootstrap VK determines the wallet's CREATE2 address on all chains.

---

### INS 0x21 -- GET_MAIN_VK

Derive and return the per-chain main signer's verifying key.

**Unlock required.**

**Request (12 bytes):**

| Offset | Size | Field     | Description                                |
|--------|------|-----------|--------------------------------------------|
| 0      | 8    | chain_id  | u64 BE (e.g., 1 for Ethereum, 8453 for Base)|
| 8      | 4    | key_index | u32 BE (signer epoch, usually 0)           |

**Response (32 bytes):**

```
[0..16)   pk_seed    16 bytes
[16..32)  pk_root    16 bytes
```

Each `(chain_id, key_index)` pair produces a cryptographically independent
keypair.

---

### INS 0x30 -- SIGN_USEROP

Sign an EIP-1559 transaction as an ERC-4337 UserOperation. The device
displays the inner transaction on its trusted OLED, independently
reconstructs the `execute()` calldata, computes the `userOpHash`, and
signs it with SPHINCS+C7.

**Unlock required. Command chaining required.**

**P2 values:**

| P2     | Mode                                                       |
|--------|------------------------------------------------------------|
| `0x00` | Deployed -- normal signing                                 |
| `0x01` | Not deployed -- firmware auto-generates initCode + bootstrap sig |

When P2 = 0x01, the firmware internally:
- Derives the bootstrap keypair
- Derives the main keypair for the given chain_id + key_index
- Signs `keccak256("PQWALLET_INIT_V1" || mainPkSeed_padded || mainPkRoot_padded)` with the bootstrap key
- Builds the full initCode (factory address + `createAccount(...)` ABI encoding)
- Computes `keccak256(initCode)` -- the host-supplied `init_code_hash` field is ignored

**Request payload (command-chained):**

| Offset | Size   | Field                    | Description                          |
|--------|--------|--------------------------|--------------------------------------|
| 0      | 4      | key_index                | u32 BE -- from `wallet.currentKeyIndex()` |
| 4      | 4      | ots_index                | u32 BE -- from `wallet.currentOTSIndex()` |
| 8      | 20     | sender                   | wallet contract address              |
| 28     | 20     | entry_point              | EntryPoint address                   |
| 48     | 8      | chain_id                 | u64 BE                               |
| 56     | 32     | nonce                    | u256 BE -- from EntryPoint           |
| 88     | 32     | call_gas_limit           | u256 BE                              |
| 120    | 32     | verification_gas_limit   | u256 BE                              |
| 152    | 32     | pre_verification_gas     | u256 BE                              |
| 184    | 32     | max_fee_per_gas          | u256 BE                              |
| 216    | 32     | max_priority_fee_per_gas | u256 BE                              |
| 248    | 32     | init_code_hash           | keccak256(initCode), ignored when P2=0x01 |
| 280    | 32     | paymaster_and_data_hash  | keccak256(paymasterAndData)          |
| 312    | 2      | tx_len                   | u16 BE                               |
| 314    | tx_len | tx_data                  | unsigned EIP-1559 RLP envelope       |
| +0     | 2      | bundle_len               | u16 BE (0 = no ERC20 bundle)         |
| +2     | bundle_len | bundle_data            | Merkle-verified ERC20 metadata       |

**Response: structured UserOp response**

When P2 = 0x01 (not deployed):
```
[0..4)           init_code_len   u32 BE
[4..4+N)         initCode        N bytes (factory + createAccount ABI)
[4+N..8+N)       call_data_len   u32 BE
[8+N..8+N+M)     callData        M bytes (reconstructed execute(...))
[8+N+M..)        PQSignatureWrapper (3,777 bytes)
```

When P2 = 0x00 (deployed):
```
[0..4)           init_code_len   u32 BE = 0
[4..8)           call_data_len   u32 BE
[8..8+M)         callData        M bytes
[8+M..)          PQSignatureWrapper (3,777 bytes)
```

Drained via GET_RESPONSE. See [PQSignatureWrapper](#5-pqsignaturewrapper).

**Constants:**
```
keccak256("")    = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
EntryPoint v0.6  = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
```

---

### INS 0x31 -- SIGN_CLEAR_USEROP

ZK clear-signed UserOp. A Groth16 proof attests that a human-readable
string faithfully represents the calldata. The device Merkle-verifies
the VK, runs the Groth16 verifier, displays the readable string on the
OLED, then signs the userOpHash.

**Unlock required. Command chaining required.**

**Request:**

| Offset        | Size       | Field       | Description                    |
|---------------|------------|-------------|--------------------------------|
| 0             | 4          | key_index   | u32 BE                         |
| 4             | 4          | ots_index   | u32 BE                         |
| 8             | 384        | proof       | Groth16 proof (pi_A \|\| pi_B \|\| pi_C) |
| 392           | 164        | calldata    | zero-padded to 164 bytes       |
| 556           | 64         | readable    | null-padded to 64 bytes        |
| 620           | 20         | sender      |                                |
| 640           | 20         | entry_point |                                |
| 660           | 8          | chain_id    | u64 BE                         |
| 668           | 32         | nonce       | u256 BE                        |
| ...           | ...        | *(remaining AA fields same as SIGN_USEROP)* | |
| ...           | 2          | tx_len      | u16 BE                         |
| ...           | tx_len     | tx_data     |                                |
| ...           | 2          | vk_bundle_len | u16 BE                       |
| ...           | vk_bundle_len | vk_bundle | Merkle-verified VK bundle    |

**Response:** Structured UserOp response (same as SIGN_USEROP).

---

### INS 0x40 -- SIGN_MESSAGE

EIP-191 personal_sign. The device displays the message on its OLED and
signs `keccak256("\x19Ethereum Signed Message:\n" + len + msg)`.

**Unlock required. Command chaining for messages > ~230 bytes.**

**Request:**

| Offset | Size    | Field     | Description                      |
|--------|---------|-----------|----------------------------------|
| 0      | 4       | key_index | u32 BE                           |
| 4      | 4       | ots_index | u32 BE                           |
| 8      | 8       | chain_id  | u64 BE (for display only)        |
| 16     | 2       | msg_len   | u16 BE                           |
| 18     | msg_len | message   | raw bytes (max 1024)             |

**Response:** PQSignatureWrapper (3,777 bytes via GET_RESPONSE).

---

### INS 0x41 -- SIGN_EIP712

EIP-712 typed data signing with ZK clear-sign verification. Used for
CowSwap GPv2 orders and future off-chain signature protocols.

**Unlock required. Command chaining required.**

**Request:**

| Offset | Size           | Field          | Description                  |
|--------|----------------|----------------|------------------------------|
| 0      | 4              | key_index      | u32 BE                       |
| 4      | 4              | ots_index      | u32 BE                       |
| 8      | 384            | proof          | Groth16 proof                |
| 392    | 204            | canonical      | packed GPv2Order (v3 layout) |
| 596    | 128            | readable       | null-padded to 128 bytes     |
| 724    | 2              | vk_bundle_len  | u16 BE                       |
| 726    | vk_bundle_len  | vk_bundle      | Merkle-verified VK bundle    |

**Canonical GPv2Order v3 layout (204 bytes):**

| Offset   | Size | Field              |
|----------|------|--------------------|
| 0..8     | 8    | chain_id (u64 BE)  |
| 8..28    | 20   | sellToken          |
| 28..48   | 20   | buyToken           |
| 48..68   | 20   | receiver           |
| 68..100  | 32   | sellAmount (u256 BE)|
| 100..132 | 32   | buyAmount          |
| 132..164 | 32   | feeAmount          |
| 164..168 | 4    | validTo (u32 BE)   |
| 168      | 1    | kind               |
| 169      | 1    | partiallyFillable  |
| 170      | 1    | sellTokenBalance   |
| 171      | 1    | buyTokenBalance    |
| 172..204 | 32   | appData (bytes32)  |

**Response:** PQSignatureWrapper (3,777 bytes via GET_RESPONSE).

---

### INS 0x50 -- SIGN_BOOTSTRAP (deprecated)

**DEPRECATED.** Bootstrap signing is now handled automatically by
SIGN_USEROP with P2 = 0x01. Kept for backward compatibility only.

**Unlock required.**

**Request (37 bytes):**

| Offset | Size | Field       | Description                              |
|--------|------|-------------|------------------------------------------|
| 0      | 4    | ots_index   | u32 BE -- from `wallet.bootstrapOTSIndex()` |
| 4      | 1    | context_tag | 0x00=DEPLOY, 0x01=ROTATE, 0x02=GENERIC  |
| 5      | 32   | msg_hash    | the bytes32 to sign                      |

**Response:** PQSignatureWrapper (3,777 bytes, signer_type=0x01).

---

### INS 0x60 -- GET_WALLET_ADDRESS

Compute the CREATE2 wallet address from the device's stored bootstrap VK
plus factory parameters. The device independently computes and **displays
the address on the OLED** for visual verification against clipboard attacks.

**No unlock required.**

**Request (60 bytes):**

| Offset | Size | Field            | Description                            |
|--------|------|------------------|----------------------------------------|
| 0      | 8    | chain_id         | u64 BE (displayed on OLED)             |
| 8      | 20   | factory_address  | PQCoinbaseSmartWalletFactory address   |
| 28     | 32   | init_code_hash   | from `factory.initCodeHash()`          |

The device computes:
```
salt = keccak256(pk_seed_padded || pk_root_padded)
address = keccak256(0xFF || factory || salt || init_code_hash)[12..32]
```

Where `pk_seed_padded = bootstrap_vk[0..16] ++ zeros[16]` and
`pk_root_padded = bootstrap_vk[16..32] ++ zeros[16]`.

**Response (20 bytes):** the Ethereum address, after user confirms on device.
`SW = 0x6982` if the user cancels.

---

### INS 0xC0 -- GET_RESPONSE

Drain remaining bytes of a large response. See
[Response Chaining](#response-chaining-get_response).

**Request:** empty
**Response:** next chunk (up to 253 bytes) + SW

---

## 5. PQSignatureWrapper

All signing commands return this structured binary response. The companion
app ABI-encodes it for on-chain submission in the UserOp's `signature` field.

### Wire Format (3,777 bytes)

```
[0]          signer_type    u8     0x00=MAIN, 0x01=BOOTSTRAP
[1..5)       key_index      u32 BE
[5..9)       ots_index      u32 BE
[9..41)      pk_seed        32 bytes (16-byte value right-padded to bytes32)
[41..73)     pk_root        32 bytes (16-byte value right-padded to bytes32)
[73..3777)   signature      3,704 bytes (SPHINCS+C7 keccak256-based)
```

**Total: 3,777 bytes** (73 header + 3,704 signature)

### ABI Encoding for On-Chain Submission

The on-chain `PQCoinbaseSmartWallet.validateUserOp()` expects the UserOp's
`signature` field to be:

```solidity
abi.encode(PQSignatureWrapper({
    signerType:  SignerType(wrapper[0]),        // MAIN or BOOTSTRAP
    keyIndex:    uint32(wrapper[1..5]),
    otsIndex:    uint32(wrapper[5..9]),
    pkSeed:      bytes32(wrapper[9..41]),       // already right-padded
    pkRoot:      bytes32(wrapper[41..73]),       // already right-padded
    signature:   bytes(wrapper[73..3777])       // 3,704 bytes
}))
```

The `PQSignatureWrapper` Solidity struct:

```solidity
struct PQSignatureWrapper {
    SignerType signerType;   // enum: MAIN=0, BOOTSTRAP=1
    uint32    keyIndex;
    uint32    otsIndex;
    bytes32   pkSeed;
    bytes32   pkRoot;
    bytes     signature;     // 3,704 bytes
}
```

ABI-encode with `abi.encode(wrapper)` -- the `bytes signature` field
becomes a dynamic type with offset pointer + length prefix + data padded
to 32-byte boundary.

---

## 6. Smart Contract ABIs

### PQCoinbaseSmartWalletFactory

Deployed at the same address on every supported chain. The companion
needs the factory address + the `initCodeHash()` for address computation.

```solidity
interface PQCoinbaseSmartWalletFactory {
    function implementation() external view returns (address);
    function verifier() external view returns (address);
    function initCodeHash() external view returns (bytes32);

    function createAccount(
        bytes32 bootstrapPkSeed,
        bytes32 bootstrapPkRoot,
        bytes32 mainPkSeed,
        bytes32 mainPkRoot,
        bytes calldata bootstrapSig
    ) external payable returns (address account);

    function getAddress(
        bytes32 bootstrapPkSeed,
        bytes32 bootstrapPkRoot
    ) external view returns (address);
}
```

**CREATE2 salt:** `keccak256(abi.encodePacked(bootstrapPkSeed, bootstrapPkRoot))`

The companion can compute the wallet address locally:
```
salt = keccak256(bootstrapPkSeed || bootstrapPkRoot)
address = keccak256(0xFF || factory_address || salt || initCodeHash)[12..32]
```

### PQCoinbaseSmartWallet (per-chain instance)

```solidity
interface PQCoinbaseSmartWallet {
    // Read-only state queries
    function bootstrapPubKeyHash() external view returns (bytes32);
    function currentKeyIndex() external view returns (uint32);
    function currentMainPubKeyHash() external view returns (bytes32);
    function currentOTSIndex() external view returns (uint32);
    function bootstrapOTSIndex() external view returns (uint32);
    function isInitialized() external view returns (bool);
    function entryPoint() external view returns (address);

    // Key validation helpers
    function isBootstrapKey(bytes32 pkSeed, bytes32 pkRoot) external view returns (bool);
    function isMainKey(bytes32 pkSeed, bytes32 pkRoot) external view returns (bool);

    // Execution (via EntryPoint only)
    function execute(address target, uint256 value, bytes calldata data) external payable;
    function executeBatch(Call[] calldata calls) external payable;
    function rotateMainSigner(uint32 newKeyIndex, bytes32 newMainPkSeed, bytes32 newMainPkRoot) external;

    // ERC-1271 (for Safe / CowSwap compatibility)
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}
```

### ISPHINCSVerifier

Shared keccak256-based SPHINCS+C7 verifier used by both factory and wallet:

```solidity
interface ISPHINCSVerifier {
    function verify(
        bytes32 pkSeed,
        bytes32 pkRoot,
        bytes32 message,
        bytes calldata sig
    ) external view returns (bool valid);
}
```

### EntryPoint v0.6

Standard ERC-4337 EntryPoint at `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`.

```solidity
interface IEntryPoint {
    function handleOps(UserOperation[] calldata ops, address payable beneficiary) external;
    function getNonce(address sender, uint192 key) external view returns (uint256);
    function getUserOpHash(UserOperation calldata userOp) external view returns (bytes32);
}
```

---

## 7. On-Chain State

Each chain's deployed wallet stores independent state:

```solidity
struct PQSignerStorage {
    bytes32 bootstrapPubKeyHash;   // keccak256(pkSeed || pkRoot), immutable
    uint32  currentKeyIndex;       // main signer epoch: 0, 1, 2, ...
    bytes32 currentMainPubKeyHash; // keccak256 of current main signer VK
    uint32  currentOTSIndex;       // next unused OTS leaf for current main key
    uint32  bootstrapOTSIndex;     // next unused OTS leaf for bootstrap key
    bool    initialized;
}
```

**The blockchain is the authoritative state.** The device's local OTS
counter is an optimization. On any ambiguity, always re-read on-chain
state.

### Reading State

```typescript
// Check if deployed on this chain
const code = await provider.getCode(walletAddress);
const isDeployed = code !== '0x' && code.length > 2;

// Read signing state
const keyIndex = await wallet.currentKeyIndex();
const otsIndex = await wallet.currentOTSIndex();
const bootstrapOtsIndex = await wallet.bootstrapOTSIndex();

// EntryPoint nonce
const nonce = await entryPoint.getNonce(walletAddress, 0);
```

### OTS Budget

Each keypair has a budget of **2^20 - 1 = 1,048,575** signatures. When
`currentOTSIndex` approaches this limit, the companion should prompt the
user to rotate to the next key epoch.

---

## 8. Multi-Chain Key Architecture

```
BIP-39 entropy (32 bytes, stored encrypted across dual secure elements)
  |
  +-- Bootstrap signer (global, never rotates)
  |     Domain: "pqwallet-bootstrap-sk-seed"
  |     Used for: deployment on new chains, emergency rotation
  |     Determines wallet address on all chains (via CREATE2)
  |     OTS-tracked per-wallet (bootstrapOTSIndex)
  |
  +-- Main signer (chain_id=1, key_index=0)
  |     Domain: "pqwallet-main-sk-seed" + chain_id + key_index
  |     Used for: Ethereum mainnet transactions
  |     Rotates every ~1M signatures
  |
  +-- Main signer (chain_id=8453, key_index=0)
  |     Used for: Base transactions
  |     Cryptographically independent
  |
  +-- Main signer (chain_id=42161, key_index=0)
        Used for: Arbitrum transactions
```

**Same 24-word recovery phrase produces the same keys on any PQSigner
device running this firmware.** The key derivation chain is frozen -- it
is part of the recovery contract.

---

## 9. Companion App Workflows

### 9.1 First Connection

```
GET_DEVICE_INFO                -> capabilities, sig_size, versions
GET_STATUS                     -> provisioned? locked?
if locked:
    UNLOCK                     -> user enters PIN on device
GET_BOOTSTRAP_VK               -> 32-byte VK -> compute wallet addresses
GET_MAIN_VK(chain_id, 0)       -> main signer VK for active chain
```

### 9.2 Sending ETH (Wallet Already Deployed)

```
1. Build unsigned EIP-1559 envelope (RLP-encoded)
2. Query bundler for gas estimates (callGasLimit, verificationGasLimit,
   preVerificationGas, maxFeePerGas, maxPriorityFeePerGas)
3. Query on-chain:
     wallet.currentKeyIndex()  -> key_index
     wallet.currentOTSIndex()  -> ots_index
4. Query EntryPoint: getNonce(sender, 0) -> nonce
5. Compute hashes:
     init_code_hash = keccak256("")   // already deployed
     paymaster_hash = keccak256("")   // no paymaster
6. RLP-encode the unsigned inner tx

SIGN_USEROP(P2=0x00, key_index, ots_index, sender, entry_point,
            chain_id, nonce, gas_params, init_code_hash,
            paymaster_hash, tx_len, tx_data, bundle_len=0)
  -> user confirms "Send X ETH to 0x..." on device
  -> GET_RESPONSE loop -> structured response
  -> extract callData + PQSignatureWrapper

7. Build UserOp:
     sender, nonce, initCode="",
     callData (from device response),
     callGasLimit, verificationGasLimit, preVerificationGas,
     maxFeePerGas, maxPriorityFeePerGas,
     paymasterAndData="",
     signature = abi.encode(PQSignatureWrapper)

8. Submit UserOp to bundler via eth_sendUserOperation
```

### 9.3 Deploy Wallet on New Chain

```
1. GET_BOOTSTRAP_VK -> (pk_seed, pk_root)
2. Compute expected address:
     salt = keccak256(pk_seed_padded || pk_root_padded)
     address = keccak256(0xFF || factory || salt || initCodeHash)[12..]

3. Check: eth_getCode(address) == "0x"  (not yet deployed)

4. GET_MAIN_VK(chain_id, 0) -> initial main signer VK

5. Prepare signing:
     Query bundler for gas estimates
     nonce = 0  (first UserOp for this sender)

6. SIGN_USEROP(P2=0x01, key_index=0, ots_index=0, sender=address,
               entry_point, chain_id, nonce, gas_params,
               init_code_hash=ignored, paymaster_hash,
               tx_len, tx_data, bundle_len=0)
     -> user confirms "Deploy wallet?" on device
     -> device auto-generates initCode + bootstrap sig internally
     -> GET_RESPONSE loop -> response includes initCode + callData + wrapper

7. Build UserOp:
     initCode = response.initCode,
     callData = response.callData,
     signature = abi.encode(response.PQSignatureWrapper)

8. Submit to bundler
   -> EntryPoint deploys via factory.createAccount() + executes inner tx
```

### 9.4 DeFi Interaction (ZK Clear-Signed)

```
1. Build calldata (e.g., aave.supply(USDC, 1000))
2. Generate Groth16 proof OFF-DEVICE:
     proof binds (calldata -> "Aave V3: Supply 1000 USDC")
3. Look up VK bundle from local Merkle DB
     (chain_id + contract_address -> VK entry + Merkle proof)

SIGN_CLEAR_USEROP(key_index, ots_index, proof, calldata,
                  "Aave V3: Supply 1000 USDC", sender, entry_point,
                  chain_id, nonce, gas_params, tx_data, vk_bundle)
  -> device verifies Groth16 proof, shows "Aave V3: Supply 1000 USDC"
  -> PQSignatureWrapper

4. Build and submit UserOp to bundler
```

### 9.5 CowSwap EIP-712 Order

```
1. Pack GPv2Order into 204-byte canonical encoding (v3 layout)
2. Generate Groth16 proof:
     canonical -> "Sell 100 USDC for >= 80 DAI"

SIGN_EIP712(key_index, ots_index, proof, canonical, readable, vk_bundle)
  -> device verifies proof, shows "Sell 100 USDC for >= 80 DAI"
  -> PQSignatureWrapper

3. Submit signed order to CowSwap API
```

### 9.6 Receive Funds (Address Verification)

```
GET_WALLET_ADDRESS(chain_id, factory_addr, init_code_hash)
  -> device computes address, displays on OLED
  -> user visually verifies, presses confirm
  -> returns 20-byte address

Compare returned address with locally computed address.
Protects against clipboard attacks and compromised displays.
```

### 9.7 Recovery on New Device

```
Scenario: user lost device, enters 24-word seed on new hardware

1. GET_BOOTSTRAP_VK -> same VK as old device (deterministic from seed)
2. Compute wallet address -> same address (CREATE2 from bootstrap VK)

For each chain the user had a wallet on:
3. Read on-chain state:
     key_index = wallet.currentKeyIndex()
     ots_index = wallet.currentOTSIndex()
4. GET_MAIN_VK(chain_id, key_index) -> must match on-chain hash
5. Verify: keccak256(pk_seed_padded || pk_root_padded) == currentMainPubKeyHash
6. Resume signing from ots_index

Optional paranoia rotation:
7. If old device may be compromised, immediately rotate to next key epoch
   via SIGN_USEROP calling rotateMainSigner(key_index+1, new_pk_seed, new_pk_root)
```

### 9.8 Key Rotation (OTS Budget Approaching Limit)

```
Trigger: currentOTSIndex > 1,000,000  (approaching 1,048,575 max)

1. GET_MAIN_VK(chain_id, current_key_index + 1) -> new main VK
2. Build rotation UserOp:
     callData = wallet.rotateMainSigner(
         current_key_index + 1,
         new_pk_seed_padded,
         new_pk_root_padded
     )
3. SIGN_USEROP(current_key_index, current_ots_index, ..., rotation_tx)
4. Submit to bundler

Post-rotation state:
  currentKeyIndex = key_index + 1
  currentOTSIndex = 0
  currentMainPubKeyHash = keccak256(new VK)
```

---

## 10. ZK Clear Signing

The device refuses to display decoded DeFi actions unless a Groth16 proof
certifies that the human-readable string faithfully interprets the raw
calldata. This prevents a compromised companion from showing "Send 1 USDC"
while the actual calldata transfers the user's entire balance.

### How It Works

1. **Companion** generates a Groth16 proof binding `(calldata, readable_string)`.
   The circuit enforces that the string is a correct interpretation of the calldata.
2. **Companion** looks up the protocol's Verification Key (VK) from the firmware's
   Merkle database, building a VK bundle (VK bytes + Merkle proof).
3. **Device** receives `(proof, calldata, readable, vk_bundle)`.
4. **Device** Merkle-verifies the VK against its embedded root (32 bytes in secure flash).
5. **Device** runs the Groth16 verifier over BLS12-381.
6. On success, **device** displays the readable string on the OLED.
7. User confirms -> device signs.

### Proof Generation

Proofs are generated off-device using snarkjs (or equivalent). Each
supported protocol has a Circom circuit:

| Protocol           | Circuit               | Calldata | Readable |
|--------------------|-----------------------|----------|----------|
| Aave V3 supply     | `aave_v3_pool.circom` | 164 B    | 64 B     |
| Aave V3 withdraw   | `aave_v3_pool.circom` | 164 B    | 64 B     |
| Aave V3 borrow     | `aave_v3_pool.circom` | 164 B    | 64 B     |
| Aave V3 repay      | `aave_v3_pool.circom` | 164 B    | 64 B     |
| CowSwap EIP-712 v3 | `cowswap_eip712.circom` | 204 B  | 128 B    |

### VK Bundle Format

The companion must send the VK plus its Merkle authentication path:

```
vk_bundle:
  [0..960) or [0..1056)   VK bytes (depends on circuit: 2 or 3 public signals)
  [vk_len..vk_len+N*32)   Merkle sibling hashes (leaf-up, proof_depth * 32 bytes)
```

The proof depth and entry index are derived from the `(chain_id, contract_address)`
lookup in the VK database index. The device re-hashes the VK and walks the
Merkle proof up to its embedded root.

---

## 11. ERC20 & VK Database Bundles

The device's non-secure flash contains two Merkle-indexed databases. The
secure world holds only the 32-byte Merkle root of each. The companion
should ship matching copies of these databases for bundle construction.

### ERC20 Metadata DB

Used for displaying token names/symbols on known ERC20 transfers. The
companion looks up `(chain_id, contract_address)` and sends the matching
entry + Merkle proof as a bundle alongside the signing request.

**Canonical leaf hash:**
```
sha256(0x00 || chain_id[8 LE] || contract[20] || decimals[1] ||
       name_len[1] || name_bytes || symbol_len[1] || symbol_bytes)
```

**Internal nodes:** `sha256(0x01 || left[32] || right[32])`

### VK DB

Used for ZK clear-signed transactions. Same Merkle structure, keyed by
`(chain_id, contract_address)`.

**Canonical leaf hash:**
```
sha256(0x00 || chain_id[8 LE] || contract[20] || vk_bytes[960 or 1056])
```

### Database Versioning

`GET_DEVICE_INFO` returns `erc20_db_version` and `vk_db_version` as
`u32 BE` dates (YYYYMMDD format). The companion should check its local
DB versions match the device's. If mismatched, prompt a firmware update.

---

## 12. Safe & CowSwap Integration

### CowSwap: setPreSignature Pattern (Recommended)

Avoid passing PQ signatures through CowSwap's API. Instead, pre-sign
on-chain:

```
1. Ensure wallet is deployed on the target chain
2. Build UserOp:
     callData = wallet.execute(
         GPv2Settlement_address,
         0,
         abi.encodeCall(setPreSignature, (orderUid, true))
     )
3. Sign via SIGN_USEROP or SIGN_CLEAR_USEROP
4. Submit UserOp to bundler
5. CowSwap's settlement sees a PreSign flag -- no PQ signature needed
6. Submit the 20-byte wallet address as "signature" to CowSwap API
```

### Gnosis Safe: signMessage Pattern (Recommended)

When the PQ wallet is a signer on a Safe:

```
1. Ensure PQ wallet is deployed on the target chain
2. Build UserOp:
     callData = wallet.execute(
         safe_address,
         0,
         abi.encodeCall(Safe.signMessage, (msgHash))
     )
3. Sign via SIGN_USEROP
4. Submit UserOp to bundler
5. Safe sees the pre-approved hash in its storage
```

### Direct EIP-1271 (Fallback)

For protocols that require `isValidSignature`:
- The wallet must be deployed
- `isValidSignature` verifies the PQSignatureWrapper directly
- The 3.7 KB signature fits comfortably in most calldata limits

---

## 13. Error Handling

### Device State Machine

```
UNPROVISIONED --[first boot wizard]--> LOCKED
LOCKED --[UNLOCK + correct PIN]--> UNLOCKED
UNLOCKED --[LOCK or idle timeout]--> LOCKED
UNLOCKED --[120s inactivity]--> LOCKED (auto-zeroize)
```

### Common Error Scenarios

| Scenario                  | SW     | Companion Action                           |
|---------------------------|--------|--------------------------------------------|
| Device locked             | 0x6985 | Prompt user to UNLOCK first                |
| Wrong PIN on device       | 0x6982 | Show remaining attempts from GET_STATUS    |
| User rejected on device   | 0x6982 | Show "Transaction rejected on device"      |
| Idle timeout mid-sign     | 0x6984 | Retry: UNLOCK -> re-send signing command   |
| Invalid ZK proof          | 0x6A80 | Bug in proof generation; check circuit     |
| OTS index mismatch        | 0x6A80 | Re-read on-chain state, retry with correct index |
| Not provisioned           | 0x6985 | Direct user to run first-boot wizard       |
| Feature not supported     | 0x6501 | Check capabilities bitmap, disable UI      |
| JARDIN slot exhausted     | 0x6501 | Register next slot, retry with slot_index+1|
| USB disconnect mid-sign   | --     | Re-connect, check GET_STATUS, retry        |

### Timeout Recommendations

| Operation        | Recommended Timeout | Reason                            |
|------------------|--------------------|------------------------------------|
| GET_DEVICE_INFO  | 5s                 | Fast, no user interaction          |
| UNLOCK           | 60s                | User entering PIN on device        |
| SIGN_USEROP      | 120s               | User reviewing tx + button confirm |
| GET_RESPONSE     | 5s                 | Data already buffered on device    |
| GET_WALLET_ADDRESS | 30s              | User verifying address on OLED     |
| SIGN_JARDIN      | 30s                | Fast if slot active, +4s if keygen |
| REGISTER_JARDIN  | 30s                | May trigger keygen (~3-4s)         |
| GET_JARDIN_INFO  | 5s                 | Pure read, no crypto               |

---

## 14. Security Invariants

The companion app must respect these invariants. Violating them is either
impossible (enforced by the device) or creates a user-facing security issue.

1. **PIN never crosses USB.** The UNLOCK command triggers on-device PIN
   entry. The companion has no way to send a PIN and must never prompt for
   one in its own UI.

2. **The device displays transaction details independently.** The device
   reconstructs `execute()` calldata from the inner tx and displays the
   actual money flow. A malicious companion that sends different calldata
   vs. inner tx will cause a mismatch and the device will show the real
   values.

3. **OTS index is authoritative on-chain.** The device accepts whatever
   `ots_index` the companion sends in the signing request, but the
   on-chain contract rejects any value other than `currentOTSIndex`. The
   companion **must** read on-chain state before every signing request.

4. **Address verification requires device confirmation.** Always direct
   users to verify receive addresses on the device's OLED via
   `GET_WALLET_ADDRESS`, not just in the companion UI.

5. **ZK proofs are generated off-device.** The companion is responsible
   for running snarkjs to produce Groth16 proofs for clear-signed
   transactions. The device only verifies.

6. **VK and ERC20 databases must match the device.** Version mismatch
   causes Merkle verification failure on the device (SW = 0x6A80).
   Check versions via `GET_DEVICE_INFO`.

---

## 15. JARDIN Compact Signing

JARDIN FORS+C is a compact signature scheme that produces 2.5-4 KB
signatures (vs. 3.8 KB for SPHINCS+C7), saving ~40-80 KB gas per
transaction on Ethereum L1.  Each JARDIN **slot** holds 95 signatures.
After exhaustion, a new slot must be registered on-chain.

### 15.1 Key Architecture

```
BIP-39 entropy (32 bytes)
  |
  +-- JARDIN master entropy (deterministic, domain "pqwallet-jardin-master")
        |
        +-- Slot 0 (chain-independent)
        |     slot_entropy = KDF(master, 0)
        |     (pk_seed, sk_seed) = derive_keys(slot_entropy)
        |     pk_root = unbalanced_tree(fors_pks[0..95])
        |     slot_key = keccak256(jardin_slot_r(master, 0))
        |     sub_vk_hash = keccak256(pk_seed[..16] || pk_root[..16])
        |     Signatures: q=1..95 (variable size: 2468..3972 bytes)
        |
        +-- Slot 1
        |     ...same derivation with slot_index=1...
        |
        +-- Slot N
              ...deterministic: same 24 words + slot_index -> same slot...
```

**Recovery contract:** The same 24-word mnemonic always produces the same
slot keys.  The companion can re-derive `slot_key` and `sub_vk_hash` for
any slot index and verify them against on-chain state.

### 15.2 APDU Commands

#### INS 0x70 -- SIGN_JARDIN

Sign a 32-byte message hash using JARDIN FORS+C compact signing.
Triggers keygen (~3-4 s) on first use of a new slot.

**Unlock required.  Command chaining for payloads > 255 bytes: not needed
(payload is exactly 44 bytes).**

**Request (44 bytes):**

| Offset | Size | Field       | Description                    |
|--------|------|-------------|--------------------------------|
| 0      | 8    | chain_id    | u64 BE                         |
| 8      | 4    | slot_index  | u32 BE (0, 1, 2, ...)         |
| 12     | 32   | msg_hash    | the userOpHash or EIP-191 hash |

**Response (variable, 2569-4073 bytes):**

```
[0..4)     response_len   u32 BE (see rotation flag below)
[4..5)     signer_type    0x02 (SIGNER_JARDIN)
[5..37)    slot_key       32 bytes — H(r), the on-chain slot identifier
[37..69)   sub_pk_seed    32 bytes (16-byte value right-padded to bytes32)
[69..101)  sub_pk_root    32 bytes (16-byte value right-padded to bytes32)
[101..)    raw_signature  2452 + q*16 bytes (q = signature index within slot)
```

**Rotation-soon flag (bit 31 of response_len):**

When fewer than 15 signatures remain on the active slot, the firmware sets
bit 31 of `response_len`.  The companion must mask it:

```typescript
const raw = readU32BE(response, 0);
const rotationSoon = (raw & 0x80000000) !== 0;
const actualLen    = raw & 0x7FFFFFFF;
```

When `rotationSoon` is true, the companion should immediately call
REGISTER_JARDIN_SLOT for `slot_index + 1` and submit the on-chain
registration before the current slot runs out.

**Status words:**

| SW     | Meaning                                     |
|--------|---------------------------------------------|
| 0x9000 | Success                                     |
| 0x6985 | Device locked                               |
| 0x6984 | Idle timeout                                |
| 0x6501 | Slot exhausted (all 95 signatures used)     |

On `0x6501` (slot exhausted), the signature was **not** produced.
Register the next slot and retry with `slot_index + 1`.

---

#### INS 0x71 -- REGISTER_JARDIN_SLOT

Derive and return the public parameters needed to register a JARDIN slot
on-chain.  The companion builds and submits the
`registerJardinSlot(slotKey, subVkHash)` transaction.

Triggers keygen (~3-4 s) if the requested slot is not already active.

**Unlock required.**

**Request (12 bytes):**

| Offset | Size | Field       | Description                    |
|--------|------|-------------|--------------------------------|
| 0      | 8    | chain_id    | u64 BE                         |
| 8      | 4    | slot_index  | u32 BE                         |

**Response (128 bytes):**

| Offset | Size | Field         | Description                          |
|--------|------|---------------|--------------------------------------|
| 0      | 32   | slot_key      | keccak256(r) -- on-chain identifier  |
| 32     | 32   | sub_vk_hash   | keccak256(pkSeed[..16] \|\| pkRoot[..16]) |
| 64     | 16   | sub_pk_seed   | raw 16-byte public seed (N bytes)    |
| 80     | 16   | sub_pk_root   | raw 16-byte public root (N bytes)    |
| 96     | 32   | r             | raw randomizer (verify: keccak256(r) == slot_key) |

The companion uses `slot_key` and `sub_vk_hash` for the on-chain
`registerJardinSlot(bytes32 slotKey, bytes32 subVkHash)` call, and
`sub_pk_seed` / `sub_pk_root` for constructing the ABI-encoded
PQSignatureWrapper when signing with this slot.

---

#### INS 0x72 -- GET_JARDIN_SLOT_INFO

Query the state of a JARDIN slot.  Pure read -- no keygen, no crypto.

**Unlock required.**

**Request (12 bytes):**

| Offset | Size | Field       | Description                    |
|--------|------|-------------|--------------------------------|
| 0      | 8    | chain_id    | u64 BE                         |
| 8      | 4    | slot_index  | u32 BE                         |

**Response (7 bytes):**

| Offset | Size | Field       | Values                                 |
|--------|------|-------------|----------------------------------------|
| 0      | 4    | slot_index  | u32 BE (echo)                          |
| 4      | 1    | next_q      | 1-95, or 0 if not active               |
| 5      | 1    | remaining   | 0-95                                   |
| 6      | 1    | slot_active | 1 if this slot is loaded in memory     |

If the queried (chain_id, slot_index) does not match the currently active
slot, the response shows `next_q=0, remaining=0, slot_active=0`.

---

### 15.3 JARDIN PQSignatureWrapper

JARDIN signatures use a different wrapper format from SPHINCS+C7:

#### Firmware Wire Format (variable, 2565-4069 bytes)

```
[0]          signer_type    0x02 (SIGNER_JARDIN)
[1..33)      slot_key       32 bytes — H(r), identifies the registered slot
[33..65)     sub_pk_seed    32 bytes (16-byte value right-padded to bytes32)
[65..97)     sub_pk_root    32 bytes (16-byte value right-padded to bytes32)
[97..)       signature      2468-3972 bytes (FORS+C, variable by q)
```

#### ABI Encoding for On-Chain Submission

```solidity
abi.encode(PQSignatureWrapper({
    signerType:  SignerType.JARDIN,          // = 2
    keyIndex:    0,                          // unused for JARDIN
    otsIndex:    0,                          // unused for JARDIN
    pkSeed:      bytes32(wrapper[33..65]),   // subPkSeed
    pkRoot:      bytes32(wrapper[65..97]),   // subPkRoot
    slotKey:     bytes32(wrapper[1..33]),    // on-chain slot identifier
    signature:   bytes(wrapper[97..])        // variable-length FORS+C sig
}))
```

The on-chain verifier (`JardinForsCVerifier.sol`) extracts the signature
length to determine `q`, verifies the FORS+C opening, and checks
`jardinSlots[slotKey] == keccak256(pkSeed[..16] || pkRoot[..16])`.

---

### 15.4 On-Chain Slot State

```solidity
// In PQOwnable.sol:
mapping(bytes32 => bytes32) public jardinSlots;
// jardinSlots[slotKey] = subVkHash

event JardinSlotRegistered(bytes32 indexed slotKey, bytes32 subVkHash);

function registerJardinSlot(bytes32 slotKey, bytes32 subVkHash) external;
```

**Registration** requires a C7 main-signer signature (the wallet owner must
sign a UserOp calling `registerJardinSlot`).

**Validation flow** (in `validateUserOp`):
1. Extract `signerType == JARDIN` from wrapper
2. Look up `jardinSlots[slotKey]` -- must equal `keccak256(pkSeed[..16] || pkRoot[..16])`
3. Forward `(pkSeed, pkRoot, userOpHash, signature)` to `JardinForsCVerifier`
4. Verifier checks FORS+C proof -- no on-chain q counter, no SSTORE per signature

**Gas costs:**

| Operation         | Gas (approx)  | Notes                          |
|-------------------|---------------|--------------------------------|
| Slot registration | ~225K         | One-time per 95 txs            |
| JARDIN sign q=1   | ~101K total   | 62K verify + 39K calldata      |
| JARDIN sign q=50  | ~127K total   | 75K verify + 52K calldata      |
| JARDIN sign q=95  | ~153K total   | 89K verify + 64K calldata      |
| Amortized per-tx  | +2.4K         | 225K / 95 signatures           |

---

### 15.5 Companion Workflows

#### First Slot Registration

```
1. REGISTER_JARDIN_SLOT(chain_id, slot_index=0)
     -> device runs keygen (~3-4 s), returns slot_key + sub_vk_hash + params
     -> wait for device response (set USB timeout to 30s)

2. Build registration UserOp:
     callData = wallet.execute(
         wallet_address,     // self-call
         0,
         abi.encodeCall(registerJardinSlot, (slot_key, sub_vk_hash))
     )

3. SIGN_USEROP(P2=0x00, key_index, ots_index, ..., registration_tx)
     -> user confirms on device
     -> PQSignatureWrapper (C7 main signer, 3777 bytes)

4. Submit UserOp to bundler
     -> on-chain: jardinSlots[slot_key] = sub_vk_hash

5. Slot 0 is now registered -- ready for compact signing
```

#### Compact Signing (Steady State)

```
1. Read on-chain state (no key_index/ots_index needed for JARDIN)
2. Compute userOpHash (or EIP-191 hash) off-device
3. SIGN_JARDIN(chain_id, slot_index, msg_hash)
     -> response: length-prefixed JARDIN wrapper
     -> CHECK rotation_soon flag (bit 31 of response_len)

4. Parse response:
     rotation_soon = (response_len_raw >> 31) & 1
     actual_len    = response_len_raw & 0x7FFFFFFF
     wrapper       = response[4..4+actual_len-4]

5. ABI-encode PQSignatureWrapper with signerType=JARDIN
6. Build UserOp with the JARDIN signature
7. Submit to bundler

8. IF rotation_soon:
     -> proactively register next slot (see Rotation below)
```

#### Slot Rotation

```
Trigger: rotation_soon flag from SIGN_JARDIN, or remaining < 15
         from GET_JARDIN_SLOT_INFO, or SlotExhausted (SW 0x6501)

1. current_slot = last slot_index used for signing
2. next_slot = current_slot + 1

3. REGISTER_JARDIN_SLOT(chain_id, next_slot)
     -> keygen for new slot (~3-4 s)
     -> returns slot_key, sub_vk_hash

4. Build registration UserOp (signed by C7 main signer)
5. Submit to bundler -- wait for on-chain confirmation

6. Switch to next_slot for all subsequent SIGN_JARDIN calls
7. Current slot continues working until exhausted (grace period)
```

**Timeline optimization:** Steps 3-5 can happen while the current slot
still has signatures remaining (the 15-signature warning window).  This
means there is no downtime between slots -- the new slot is ready before
the old one runs out.

#### Recovery After Power Loss

```
Scenario: device powered off/locked, session state lost

1. UNLOCK (user enters PIN)
2. Read on-chain: which slots are registered?
     for slot_index in 0, 1, 2, ...:
         slot_key = keccak256(jardin_slot_r(master, slot_index))
         if jardinSlots[slot_key] != 0:
             last_registered = slot_index
         else:
             break

3. Safe approach: register fresh slot (last_registered + 1), start q=1
   - The firmware re-derives the slot deterministically from the seed
   - No risk of q reuse (new slot starts at q=1)

4. Alternative: use GET_JARDIN_SLOT_INFO to check if the slot is still
   active in memory (it won't be after power loss -- slot_active=0)

Note: the companion CANNOT determine the current q from on-chain state
(q is not tracked on-chain). Always register a fresh slot after any
session loss to avoid security degradation from accidental q reuse.
```

#### Verifying Slot Registration

```typescript
// Verify slot_key = keccak256(r)
const r = response.slice(96, 128);
const computedSlotKey = keccak256(r);
assert(computedSlotKey === response.slice(0, 32));

// Verify sub_vk_hash
const pkSeed = response.slice(64, 80);
const pkRoot = response.slice(80, 96);
const computedVkHash = keccak256(concat(pkSeed, pkRoot));
assert(computedVkHash === response.slice(32, 64));

// After on-chain registration:
const onChainVkHash = await wallet.jardinSlots(slotKey);
assert(onChainVkHash === computedVkHash);
```

### 15.6 Security Notes

1. **No JARDIN secret crosses USB.** The device returns only public values
   (`slot_key = H(r)`, `sub_vk_hash`, `sub_pk_seed`, `sub_pk_root`) and
   signatures.  The raw randomizer `r` is returned by REGISTER_JARDIN_SLOT
   for companion verification only -- knowing `r` does not reveal `sk_seed`
   or `master_entropy` (one-way KDF).

2. **No on-chain q counter.** JARDIN's security is 128 bits per unique q.
   Accidental double-signing of the same q (e.g., after power loss)
   degrades to 105 bits but does not break the protocol.  This eliminates
   SSTORE gas on every compact signature.

3. **Deterministic derivation.** Same 24 words + slot_index always
   produces the same slot.  This is the recovery contract.

4. **Domain separation.** All JARDIN hash calls use tags distinct from
   SPHINCS+C7 (`"jfors"`, `"jardin_sentinel"`, `"jardin_sub_v1"`,
   `"jardin_pk_seed"`, `"jardin_sk_seed"`, `"jardin_R"`, `"jardin_slot"`,
   `"jardin_r"`, `"pqwallet-jardin-master"`).  No collision with C7 tags.

5. **Slot registration is gated by C7 main signer.** Only the wallet owner
   can register new slots -- the `registerJardinSlot` function requires a
   valid main-signer UserOp, preventing rogue slot injection.

---

## 16. Constants Reference

### Sizes

| Constant                        | Value      |
|---------------------------------|------------|
| SPHINCS+C7 signature            | 3,704 bytes|
| PQSignatureWrapper header       | 73 bytes   |
| PQSignatureWrapper total        | 3,777 bytes|
| Verifying key (pk_seed+pk_root) | 32 bytes   |
| initCode (first deployment)     | 3,928 bytes|
| Max inner tx length             | 4,096 bytes|
| Max message length (EIP-191)    | 1,024 bytes|
| ZK proof (Groth16)              | 384 bytes  |
| ZK calldata field               | 164 bytes  |
| ZK readable field (EIP-1559)    | 64 bytes   |
| ZK readable field (EIP-712)     | 128 bytes  |
| EIP-712 canonical field (v3)    | 204 bytes  |
| VK (2 public signals)           | 960 bytes  |
| VK (3 public signals)           | 1,056 bytes|
| VK pool slot (padded)           | 1,056 bytes|
| JARDIN FORS+C sig (q=1, min)   | 2,468 bytes|
| JARDIN FORS+C sig (q=95, max)  | 3,972 bytes|
| JARDIN wrapper header           | 97 bytes   |
| JARDIN wrapper total (max)      | 4,069 bytes|
| JARDIN sign response (max)      | 4,073 bytes|
| JARDIN register response        | 128 bytes  |
| JARDIN slot info response       | 7 bytes    |
| Signatures per JARDIN slot      | 95         |
| Rotation warning threshold      | 15 remaining|

### APDU Limits

| Constant                        | Value      |
|---------------------------------|------------|
| Max APDU data per chunk (Lc)    | 255 bytes  |
| Max APDU response per chunk     | 253 bytes  |
| HID report size                 | 64 bytes   |
| Max APDU reassembly             | 8,192 bytes|
| GET_RESPONSE round-trips        | ~15 for full wrapper |

### Addresses

| Constant              | Value                                        |
|-----------------------|----------------------------------------------|
| EntryPoint v0.6       | `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` |
| Factory address       | *TBD -- not yet deployed to mainnet*         |
| SPHINCS+C7 Verifier   | *TBD -- not yet deployed to mainnet*         |
| JARDIN FORS+C Verifier| *TBD -- not yet deployed to mainnet*         |

### Hash Constants

| Constant              | Value                                        |
|-----------------------|----------------------------------------------|
| keccak256("")         | `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` |
| PQWALLET_INIT_V1 tag  | `"PQWALLET_INIT_V1"` (17 bytes ASCII)       |
| createAccount selector | `0x1964c4dd`                                |
| OTS budget per key    | 1,048,575 (2^20 - 1)                        |

### Chain IDs

| Chain      | chain_id (u64 BE)  |
|------------|-------------------|
| Ethereum   | 1                 |
| Base       | 8453              |
| Arbitrum   | 42161             |
| Optimism   | 10                |
| Polygon    | 137               |

---

## Appendix A: Pseudocode -- APDU-over-HID Transport

```typescript
class HIDTransport {
  private channel: number = 0x0101;

  async sendAPDU(cla: number, ins: number, p1: number, p2: number,
                 data?: Uint8Array): Promise<{ data: Uint8Array, sw: number }> {
    // 1. Build APDU
    const apdu = new Uint8Array(4 + (data ? 1 + data.length : 0));
    apdu[0] = cla; apdu[1] = ins; apdu[2] = p1; apdu[3] = p2;
    if (data) { apdu[4] = data.length; apdu.set(data, 5); }

    // 2. Frame into 64-byte HID reports
    const frames = this.frameAPDU(apdu);
    for (const frame of frames) {
      await this.device.sendReport(0, frame);
    }

    // 3. Read response frames
    return this.readResponse();
  }

  async sendChainedAPDU(cla: number, ins: number, p2: number,
                        payload: Uint8Array): Promise<{ data: Uint8Array, sw: number }> {
    const CHUNK = 255;
    let offset = 0;
    while (offset < payload.length) {
      const remaining = payload.length - offset;
      const chunkSize = Math.min(CHUNK, remaining);
      const isLast = offset + chunkSize >= payload.length;
      const p1 = isLast ? 0x00 : 0x80;
      const chunk = payload.slice(offset, offset + chunkSize);

      const resp = await this.sendAPDU(cla, ins, p1, p2, chunk);

      if (!isLast) {
        // Intermediate chunks return SW=0x9000 (ack)
        if (resp.sw !== 0x9000) throw new Error(`Chain error: ${resp.sw}`);
      } else {
        return this.drainGetResponse(resp);
      }
      offset += chunkSize;
    }
    throw new Error("unreachable");
  }

  async drainGetResponse(initial: { data: Uint8Array, sw: number })
      : Promise<{ data: Uint8Array, sw: number }> {
    const chunks: Uint8Array[] = [initial.data];
    let sw = initial.sw;

    while ((sw >> 8) === 0x61) {
      const resp = await this.sendAPDU(0xF0, 0xC0, 0x00, 0x00);
      chunks.push(resp.data);
      sw = resp.sw;
    }

    // Concatenate all chunks
    const totalLen = chunks.reduce((sum, c) => sum + c.length, 0);
    const result = new Uint8Array(totalLen);
    let pos = 0;
    for (const c of chunks) { result.set(c, pos); pos += c.length; }

    return { data: result, sw };
  }
}
```

## Appendix B: Pseudocode -- UserOp Construction

```typescript
async function signAndSubmitETHTransfer(
  transport: HIDTransport,
  provider: Provider,
  bundler: Bundler,
  walletAddress: string,
  to: string,
  valueWei: bigint,
  chainId: bigint,
) {
  const wallet = new Contract(walletAddress, WALLET_ABI, provider);
  const entryPoint = new Contract(ENTRY_POINT_ADDR, ENTRY_POINT_ABI, provider);

  // 1. Read on-chain state
  const keyIndex = await wallet.currentKeyIndex();
  const otsIndex = await wallet.currentOTSIndex();
  const nonce = await entryPoint.getNonce(walletAddress, 0);

  // 2. Build unsigned EIP-1559 inner tx (RLP)
  const innerTx = buildUnsignedEIP1559({
    chainId, to, value: valueWei, data: "0x",
    maxFeePerGas: 0n, maxPriorityFeePerGas: 0n,  // placeholders
    gasLimit: 21000n, nonce: 0,  // inner nonce irrelevant for AA
  });
  const txBytes = rlpEncode(innerTx);

  // 3. Estimate gas via bundler
  const gasEstimate = await bundler.estimateUserOpGas({ ... });

  // 4. Build SIGN_USEROP payload
  const payload = new Uint8Array(312 + 2 + txBytes.length + 2);
  let p = 0;
  writeU32BE(payload, p, keyIndex); p += 4;
  writeU32BE(payload, p, otsIndex); p += 4;
  payload.set(hexToBytes(walletAddress), p); p += 20;
  payload.set(hexToBytes(ENTRY_POINT_ADDR), p); p += 20;
  writeU64BE(payload, p, chainId); p += 8;
  writeU256BE(payload, p, nonce); p += 32;
  writeU256BE(payload, p, gasEstimate.callGasLimit); p += 32;
  writeU256BE(payload, p, gasEstimate.verificationGasLimit); p += 32;
  writeU256BE(payload, p, gasEstimate.preVerificationGas); p += 32;
  writeU256BE(payload, p, gasEstimate.maxFeePerGas); p += 32;
  writeU256BE(payload, p, gasEstimate.maxPriorityFeePerGas); p += 32;
  writeU256BE(payload, p, keccak256("")); p += 32;  // init_code_hash (deployed)
  writeU256BE(payload, p, keccak256("")); p += 32;  // paymaster_hash
  writeU16BE(payload, p, txBytes.length); p += 2;
  payload.set(txBytes, p); p += txBytes.length;
  writeU16BE(payload, p, 0); p += 2;  // bundle_len = 0

  // 5. Send to device (command-chained)
  const response = await transport.sendChainedAPDU(0xF0, 0x30, 0x00, payload);

  // 6. Parse structured response
  const initCodeLen = readU32BE(response.data, 0);
  let off = 4 + initCodeLen;
  const callDataLen = readU32BE(response.data, off); off += 4;
  const callData = response.data.slice(off, off + callDataLen); off += callDataLen;
  const wrapper = response.data.slice(off, off + 3777);

  // 7. ABI-encode the PQSignatureWrapper for on-chain submission
  const signature = abiEncode(
    ["uint8", "uint32", "uint32", "bytes32", "bytes32", "bytes"],
    [wrapper[0], readU32BE(wrapper, 1), readU32BE(wrapper, 5),
     wrapper.slice(9, 41), wrapper.slice(41, 73), wrapper.slice(73)]
  );

  // 8. Build and submit UserOp
  const userOp = {
    sender: walletAddress,
    nonce,
    initCode: "0x",
    callData: bytesToHex(callData),
    callGasLimit: gasEstimate.callGasLimit,
    verificationGasLimit: gasEstimate.verificationGasLimit,
    preVerificationGas: gasEstimate.preVerificationGas,
    maxFeePerGas: gasEstimate.maxFeePerGas,
    maxPriorityFeePerGas: gasEstimate.maxPriorityFeePerGas,
    paymasterAndData: "0x",
    signature: bytesToHex(signature),
  };

  return bundler.sendUserOperation(userOp, ENTRY_POINT_ADDR);
}
```
