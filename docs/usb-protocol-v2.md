# PQSigner USB Protocol v2

Companion app integration guide for the PQSigner post-quantum hardware wallet.

## Transport Layer

| Property | Value |
|----------|-------|
| USB class | Custom HID (usage page 0xFFA0) |
| VID / PID | 0x1209 / 0x7051 |
| Report size | 64 bytes (interrupt EP1 IN/OUT) |
| Framing | Ledger-compatible APDU-over-HID |
| CLA byte | **0xF0** (v2 native) |
| Max APDU reassembly | 8192 bytes |

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

### APDU Format

```
Request:   CLA(1) INS(1) P1(1) P2(1) [Lc(1) Data(Lc)]
Response:  [Data] SW1(1) SW2(1)
```

### Command Chaining

For payloads exceeding 255 bytes (signing commands), the companion sends
multiple APDUs with the same INS:

- **P1 = 0x00**: last or only block
- **P1 = 0x80**: more blocks follow

The device accumulates data until it receives a block with `Lc < 255`
(the short-last-chunk sentinel), then executes the command.

### Response Chaining (GET_RESPONSE)

Signing responses are 17,161 bytes. The device returns the first 253
bytes with `SW = 0x61FF` (more data). The companion drains the rest by
repeatedly sending `INS 0xC0` (GET_RESPONSE) until `SW = 0x9000`.

```
Host → Device:  SIGN_USEROP (chained)
Device → Host:  [253 bytes] SW=0x61FF
Host → Device:  GET_RESPONSE
Device → Host:  [253 bytes] SW=0x61FF
... (~68 round-trips)
Host → Device:  GET_RESPONSE
Device → Host:  [remaining bytes] SW=0x9000
```

---

## Status Words

| SW | Meaning |
|------|---------|
| 0x9000 | Success |
| 0x61XX | More data available (call GET_RESPONSE) |
| 0x6700 | Wrong length |
| 0x6982 | Security not satisfied (wrong PIN, user rejected on device) |
| 0x6984 | Idle timeout — device locked itself mid-operation |
| 0x6985 | Conditions not satisfied (device locked, not provisioned) |
| 0x6A80 | Wrong data (malformed payload, invalid ZK proof) |
| 0x6D00 | INS not supported |
| 0x6E00 | CLA not supported |
| 0x6F00 | Internal error |

---

## Command Reference

### INS 0x01 — GET_DEVICE_INFO

Capability discovery. **Always call this first.** No unlock required.

**Request:** empty

**Response (41 bytes):**

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 2 | protocol_version | u16 BE, currently `0x0200` |
| 2 | 1 | fw_major | |
| 3 | 1 | fw_minor | |
| 4 | 1 | fw_patch | |
| 5 | 16 | device_uid | STM32 UID96 (zeros on dev builds) |
| 21 | 4 | capabilities | u32 BE bitmap (see below) |
| 25 | 1 | sig_param_set | 0 = SHA2-128f, 1 = SHA2-192f |
| 26 | 2 | sig_size | u16 BE, raw signature bytes (17088) |
| 28 | 4 | erc20_db_version | u32 BE, YYYYMMDD |
| 32 | 4 | vk_db_version | u32 BE, YYYYMMDD |
| 36 | 2 | ep_version | u16 BE, EntryPoint version (0x0006) |
| 38 | 2 | wrapper_overhead | u16 BE, PQSignatureWrapper header (73) |

**Capability bitmap:**

| Bit | Feature |
|-----|---------|
| 0 | UserOp signing (SIGN_USEROP) |
| 1 | ZK clear-sign calldata (SIGN_CLEAR_USEROP) |
| 2 | EIP-712 typed-data signing (SIGN_EIP712) |
| 3 | Personal message signing (SIGN_MESSAGE) |
| 4 | Bootstrap signer (SIGN_BOOTSTRAP) |
| 5 | Per-chain main key derivation (GET_MAIN_VK) |
| 6 | CowSwap EIP-712 v3 |
| 7 | Address verification (GET_WALLET_ADDRESS) |
| 8 | Device attestation (reserved) |
| 9 | EntryPoint v0.7 (reserved) |

**Companion logic:**
```
total_wrapper_size = wrapper_overhead + sig_size  // 73 + 17088 = 17161
```

---

### INS 0x02 — GET_STATUS

Check device state before operations. No unlock required.

**Request:** empty

**Response (3 bytes):**

| Offset | Field | Values |
|--------|-------|--------|
| 0 | provisioned | 0 = not provisioned, 1 = provisioned |
| 1 | locked | 0 = unlocked, 1 = locked |
| 2 | pin_remaining | 0-10 attempts remaining |

---

### INS 0x10 — UNLOCK

Trigger PIN entry on the device's trusted OLED display. The PIN never
crosses USB — the device handles everything internally.

**Request:** empty

**Response:** SW only

- `0x9000` — unlocked successfully
- `0x6982` — wrong PIN entered
- `0x6985` — permanently locked (0 attempts remaining)
- `0x6984` — user took too long, idle timeout

**Note:** This blocks until the user finishes PIN entry on the device
(~5-30 seconds). Set your USB timeout accordingly.

---

### INS 0x11 — LOCK

Explicitly lock the device, zeroizing all cached secrets.

**Request:** empty  
**Response:** `SW 0x9000`

---

### INS 0x20 — GET_BOOTSTRAP_VK

Return the bootstrap signer's 32-byte verifying key. This key is global
(not per-chain), set at provisioning, and never changes.

**No unlock required** — the VK is public data.

**Request:** empty

**Response (32 bytes):**

```
[0..16)   pk_seed    16 bytes
[16..32)  pk_root    16 bytes
```

The bootstrap VK determines the wallet's CREATE2 address on all chains.

---

### INS 0x21 — GET_MAIN_VK

Derive and return the per-chain main signer's verifying key.

**Unlock required.**

**Request (12 bytes):**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | chain_id — u64 BE (e.g., 1 for Ethereum, 8453 for Base) |
| 8 | 4 | key_index — u32 BE (signer epoch, usually 0) |

**Response (32 bytes):**

```
[0..16)   pk_seed    16 bytes
[16..32)  pk_root    16 bytes
```

Each `(chain_id, key_index)` pair produces a cryptographically
independent keypair.

---

### INS 0x30 — SIGN_USEROP

Sign an EIP-1559 transaction as an ERC-4337 UserOperation. The device
displays the inner transaction on its trusted OLED, independently
reconstructs the `execute()` calldata, computes the `userOpHash`, and
signs it with SLH-DSA.

**Unlock required. Command chaining required.**

**Request:**

| Offset | Size | Field | Source |
|--------|------|-------|--------|
| 0 | 4 | key_index | u32 BE — from `wallet.currentKeyIndex()` |
| 4 | 4 | ots_index | u32 BE — from `wallet.currentOTSIndex()` |
| 8 | 20 | sender | wallet contract address |
| 28 | 20 | entry_point | EntryPoint address |
| 48 | 8 | chain_id | u64 BE |
| 56 | 32 | nonce | u256 BE — from EntryPoint |
| 88 | 32 | call_gas_limit | u256 BE — from bundler estimate |
| 120 | 32 | verification_gas_limit | u256 BE |
| 152 | 32 | pre_verification_gas | u256 BE |
| 184 | 32 | max_fee_per_gas | u256 BE |
| 216 | 32 | max_priority_fee_per_gas | u256 BE |
| 248 | 32 | init_code_hash | keccak256(initCode), or keccak256("") |
| 280 | 32 | paymaster_and_data_hash | keccak256(paymasterAndData), or keccak256("") |
| 312 | 2 | tx_len | u16 BE |
| 314 | tx_len | tx_data | unsigned EIP-1559 RLP envelope |
| 314+tx_len | 2 | bundle_len | u16 BE (0 = no ERC20 bundle) |
| +2 | bundle_len | bundle_data | Merkle-verified ERC20 metadata |

**Response: PQSignatureWrapper (17,161 bytes via GET_RESPONSE)**

See [PQSignatureWrapper](#pqsignaturewrapper-response-format) below.

**Constants:**
```
keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
EntryPoint v0.6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
```

---

### INS 0x31 — SIGN_CLEAR_USEROP

ZK clear-signed UserOp. A Groth16 proof attests that a human-readable
string faithfully represents the calldata. The device Merkle-verifies
the VK, runs the Groth16 verifier, displays the readable string on the
OLED, then signs the userOpHash.

**Unlock required. Command chaining required.**

**Request:**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | key_index | u32 BE |
| 4 | 4 | ots_index | u32 BE |
| 8 | 384 | proof | Groth16 proof (pi_A \|\| pi_B \|\| pi_C) |
| 392 | 164 | calldata | zero-padded to 164 bytes |
| 556 | 64 | readable | null-padded to 64 bytes |
| 620 | 20 | sender | |
| 640 | 20 | entry_point | |
| 660 | 8 | chain_id | u64 BE |
| 668 | 32 | nonce | u256 BE |
| ... | ... | *(remaining AA fields same as SIGN_USEROP)* | |
| ... | 2 | tx_len | u16 BE |
| ... | tx_len | tx_data | |
| ... | 2 | vk_bundle_len | u16 BE |
| ... | vk_bundle_len | vk_bundle | Merkle-verified VK |

**Response:** PQSignatureWrapper (17,161 bytes)

---

### INS 0x40 — SIGN_MESSAGE

EIP-191 personal_sign. The device displays the message on its trusted
OLED and signs `keccak256("\x19Ethereum Signed Message:\n" + len + msg)`.

**Unlock required. Command chaining for messages > ~230 bytes.**

**Request:**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | key_index | u32 BE |
| 4 | 4 | ots_index | u32 BE |
| 8 | 8 | chain_id | u64 BE (for display) |
| 16 | 2 | msg_len | u16 BE |
| 18 | msg_len | message | raw bytes (max 1024) |

**Response:** PQSignatureWrapper (17,161 bytes)

---

### INS 0x41 — SIGN_EIP712

EIP-712 typed data signing with ZK clear-sign verification. Used for
CowSwap GPv2 orders and future off-chain signature protocols.

**Unlock required. Command chaining required.**

**Request:**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | key_index | u32 BE |
| 4 | 4 | ots_index | u32 BE |
| 8 | 384 | proof | Groth16 proof |
| 392 | 204 | canonical | protocol-specific packed encoding |
| 596 | 128 | readable | null-padded to 128 bytes |
| 724 | 2 | vk_bundle_len | u16 BE |
| 726 | vk_bundle_len | vk_bundle | Merkle-verified VK |

**Response:** PQSignatureWrapper (17,161 bytes)

---

### INS 0x50 — SIGN_BOOTSTRAP

Sign a 32-byte hash with the bootstrap key. Used for wallet deployment
and emergency signer rotation.

**Unlock required.**

**Request (37 bytes):**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | ots_index | u32 BE — from `wallet.bootstrapOTSIndex()` |
| 4 | 1 | context_tag | 0x00=DEPLOY, 0x01=ROTATE, 0x02=GENERIC |
| 5 | 32 | msg_hash | the bytes32 to sign |

The context_tag controls what the device displays:
- `0x00`: "Deploy wallet?" + hash preview
- `0x01`: "Rotate signer?" + hash preview
- `0x02`: "Bootstrap sign?" + hash preview (warning banner)

**Response:** PQSignatureWrapper (17,161 bytes, signer_type=0x01)

---

### INS 0x60 — GET_WALLET_ADDRESS

Compute the CREATE2 wallet address from the device's stored bootstrap VK
plus factory parameters. The device independently computes the address
and displays it on the OLED for the user to verify visually.

**No unlock required.**

**Request (60 bytes):**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | chain_id | u64 BE (displayed on OLED) |
| 8 | 20 | factory_address | PQCoinbaseSmartWalletFactory |
| 28 | 32 | init_code_hash | from `factory.initCodeHash()` |

The device computes:
```
pk_seed_padded = bootstrap_vk[0..16] ++ zeros[16]
pk_root_padded = bootstrap_vk[16..32] ++ zeros[16]
salt = keccak256(pk_seed_padded ++ pk_root_padded)
address = keccak256(0xFF ++ factory ++ salt ++ init_code_hash)[12..32]
```

**Response (20 bytes):** the Ethereum address.

The user must confirm on the device before the response is sent. If the
user cancels, SW = 0x6982.

---

### INS 0xC0 — GET_RESPONSE

Drain remaining bytes of a large response. See
[Response Chaining](#response-chaining-get_response).

**Request:** empty  
**Response:** next chunk (up to 253 bytes) + SW

---

## PQSignatureWrapper Response Format

All signing commands return this structured response. The companion app
ABI-encodes it for on-chain submission in the UserOp's `signature` field.

```
[0]        signer_type    u8     0x00=MAIN, 0x01=BOOTSTRAP
[1..5)     key_index      u32 BE
[5..9)     ots_index      u32 BE
[9..41)    pk_seed        32 bytes (16 bytes right-padded to bytes32)
[41..73)   pk_root        32 bytes (16 bytes right-padded to bytes32)
[73..17161) signature     17088 bytes (SLH-DSA-SHA2-128f)
```

**Total: 17,161 bytes** (73 header + 17,088 signature)

### ABI Encoding for On-Chain

The on-chain `PQCoinbaseSmartWallet.validateUserOp()` expects:

```solidity
abi.encode(PQSignatureWrapper({
    signerType:  SignerType(wrapper[0]),        // MAIN or BOOTSTRAP
    keyIndex:    uint32(wrapper[1..5]),
    otsIndex:    uint32(wrapper[5..9]),
    pkSeed:      bytes32(wrapper[9..41]),       // already padded
    pkRoot:      bytes32(wrapper[41..73]),       // already padded
    signature:   bytes(wrapper[73..17161])
}))
```

---

## Companion App Workflows

### First Connection

```
GET_DEVICE_INFO                → capabilities, sig_size, versions
GET_STATUS                     → provisioned? locked?
if locked:
    UNLOCK                     → user enters PIN on device
GET_BOOTSTRAP_VK               → 32-byte VK → compute wallet addresses
GET_MAIN_VK(chain_id, 0)       → main signer VK for this chain
```

### Sending ETH

```
1. Build unsigned EIP-1559 envelope
2. Query bundler for gas estimates
3. Query on-chain: wallet.currentKeyIndex(), wallet.currentOTSIndex()
4. Query EntryPoint nonce

SIGN_USEROP(key_index, ots_index, aa_header, tx)
  → user confirms "Send X ETH to 0x..." on device
  → GET_RESPONSE loop → 17161-byte PQSignatureWrapper

5. ABI-encode wrapper → UserOp.signature
6. Submit UserOp to bundler
```

### DeFi Interaction (ZK Clear-Signed)

```
1. Build calldata (e.g., aave.supply(USDC, 1000))
2. Generate Groth16 proof off-device: proof binds calldata → readable
3. Look up VK bundle from local Merkle DB

SIGN_CLEAR_USEROP(key_index, ots_index, proof, calldata,
                  "Aave V3: Supply 1000 USDC", aa_header, tx, vk_bundle)
  → device verifies proof, shows "Aave V3: Supply 1000 USDC"
  → PQSignatureWrapper

4. Submit to bundler
```

### Deploy Wallet on New Chain

```
1. GET_BOOTSTRAP_VK → (pk_seed, pk_root)
2. GET_MAIN_VK(chain_id, 0) → initial main signer (pk_seed, pk_root)
3. Compute auth_msg:
     keccak256("PQWALLET_INIT_V1" ++ mainPkSeed_padded ++ mainPkRoot_padded)

4. SIGN_BOOTSTRAP(bootstrap_ots_index, 0x00, auth_msg)
     → user confirms "Deploy wallet?"
     → PQSignatureWrapper (bootstrap sig)

5. Construct initCode:
     factory_addr ++ abi.encodeCall(createAccount,
       (bootstrapPkSeed_padded, bootstrapPkRoot_padded,
        mainPkSeed_padded, mainPkRoot_padded, bootstrap_sig))

6. Build deployment UserOp with initCode
7. SIGN_USEROP(0, 0, aa_header, inner_tx)
     → PQSignatureWrapper (main sig)
8. Submit to bundler
```

### CowSwap EIP-712 Order

```
1. Pack GPv2Order into 204-byte canonical encoding
2. Generate Groth16 proof: canonical → "Sell 100 USDC for >= 80 DAI"

SIGN_EIP712(key_index, ots_index, proof, canonical, readable, vk_bundle)
  → device verifies proof, shows "Sell 100 USDC for >= 80 DAI"
  → PQSignatureWrapper

3. Submit signed order to CowSwap API
```

### Receive Funds (Address Verification)

```
GET_WALLET_ADDRESS(chain_id, factory_addr, init_code_hash)
  → device computes address, displays on OLED
  → user verifies, presses confirm
  → returns 20-byte address

Compare with locally computed address. Protects against clipboard
attacks and compromised companion displays.
```

---

## Multi-Chain Key Architecture

```
BIP-39 entropy (32 bytes, stored encrypted on dual secure elements)
  │
  ├─► Bootstrap signer (global, never rotates)
  │     domain: "pqwallet-bootstrap-*"
  │     Used for: deployment, emergency rotation
  │     Determines wallet address on all chains (via CREATE2)
  │
  ├─► Main signer (chain_id=1, key_index=0)
  │     domain: "pqwallet-main-*" + chain_id + key_index
  │     Used for: Ethereum mainnet transactions
  │     Rotates every ~1M signatures
  │
  ├─► Main signer (chain_id=8453, key_index=0)
  │     Used for: Base transactions
  │     Cryptographically independent from other chains
  │
  └─► Main signer (chain_id=42161, key_index=0)
        Used for: Arbitrum transactions
```

Same 24-word recovery phrase produces the same keys on any PQSigner
device running this firmware.

---

## Constants

```
Signature size (SHA2-128f):     17,088 bytes
Wrapper header:                 73 bytes
Total wrapper:                  17,161 bytes
Max message length:             1,024 bytes
Max inner tx length:            4,096 bytes
APDU max data per chunk:        255 bytes
APDU max response per chunk:    253 bytes
GET_RESPONSE round-trips:       ~68 for a full signature
VK size (2-public-signal):      960 bytes
VK size (3-public-signal):      1,056 bytes
ZK proof size:                  384 bytes
ZK calldata field:              164 bytes (zero-padded)
ZK readable field:              64 bytes (EIP-1559) / 128 bytes (EIP-712)
EIP-712 canonical field:        204 bytes (CowSwap GPv2Order v3)
```
