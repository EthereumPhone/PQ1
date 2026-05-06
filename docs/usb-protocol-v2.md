# PQSigner USB Protocol v2 (post-all-C10 cutover)

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

Signing responses are up to 8086 bytes. The device returns the first 253
bytes with `SW = 0x61FF` (more data). The companion drains the rest by
repeatedly sending `INS 0xC0` (GET_RESPONSE) until `SW = 0x9000`.

```
Host → Device:  SIGN_USEROP (chained)
Device → Host:  [253 bytes] SW=0x61FF
Host → Device:  GET_RESPONSE
Device → Host:  [253 bytes] SW=0x61FF
...
Host → Device:  GET_RESPONSE
Device → Host:  [remaining bytes] SW=0x9000
```

## Instruction Set

> **Source of truth.** Authoritative INS values live in `proto/src/lib.rs`
> (search for `INS_V2_*`). This table is a convenience snapshot — when in
> doubt, check the constants.

After the all-C10 cutover, the v2 protocol exposes the following commands:

| INS  | Name                   | Chained? | P1         |
|------|------------------------|----------|------------|
| 0x01 | GET_DEVICE_INFO        | No       | 0          |
| 0x02 | GET_STATUS             | No       | 0          |
| 0x10 | UNLOCK                 | No       | 0          |
| 0x11 | LOCK                   | No       | 0          |
| 0x30 | SIGN_USEROP (unified)  | Yes      | 0x00/0x80  |
| 0x32 | SIGN_USEROP_BATCH      | Yes      | 0x00/0x80  |
| 0x60 | GET_WALLET_ADDRESS     | No       | 0          |
| 0x61 | GET_INIT_CODE          | No       | 0          |
| 0x62 | SIGN_OFFCHAIN          | Yes      | 0x00/0x80  |
| 0x63 | OFFCHAIN_STATUS        | No       | 0          |
| 0x70 | FW_BEGIN               | Yes      | 0x00/0x80  |
| 0x71 | FW_CHUNK               | Yes      | 0x00/0x80  |
| 0x72 | FW_COMMIT              | No       | 0          |
| 0x73 | FW_STATUS              | No       | 0          |
| 0x74 | FW_ABORT               | No       | 0          |
| 0xC0 | GET_RESPONSE           | No       | 0          |

### 0x30 SIGN_USEROP — unified sign

**This is the only signing command in the post-cutover wallet.** The
firmware's state machine decides whether the response also needs a Type 1
slot-registration UserOp; the companion just parses the two-chunk
bundle and submits to the bundler in order.

**Input payload (`SIGN_USEROP_HEADER_LEN = 330` bytes of header + inner
calldata):**

```
offset  size  field
---------------------------------------------------------
  0     8    chain_id (u64 BE)
  8     4    flags (u32 BE — see shared/src/lib.rs)
 12    20    sender (PQSmartWallet address)
 32    20    entry_point (EntryPoint v0.6 address)
 52    32    nonce (u256 BE, base nonce for Type 1 if needed else Type 2)
 84    32    call_gas_limit (u256 BE)
116    32    verification_gas_limit (u256 BE)
148    32    pre_verification_gas (u256 BE)
180    32    max_fee_per_gas (u256 BE)
212    32    max_priority_fee_per_gas (u256 BE)
244    32    paymaster_and_data_hash (sha256, SHA256_EMPTY when empty)
276    20    to_address (inner tx recipient)
296    32    value (u256 BE)
328     2    data_len (u16 BE, 0..=4096)
330     N    data
```

**Response (post-2026-04-29 layout):**

```
[new_offchain_count   u64 BE]               (8 bytes — for Type 2 calldata)
[init_code_len        u32 BE]
[init_code            init_code_len bytes]  (4280 B when FLAG_INCLUDE_INIT_CODE, else 0)
[type1_len            u32 BE]
[type1_wrapper        type1_len bytes]      (4128 B when FLAG_REGISTER_SLOT, else 0)
[type2_len            u32 BE]
[type2_wrapper        type2_len bytes]      (always 4128 B)
```

- `type1_len == 0` means the slot is already registered on this chain
  and the companion should submit only the Type 2 UserOp.
- `type1_len == 4128` means a fresh slot must be registered on-chain
  first. Submit Type 1 at `nonce`, wait for confirmation, then submit
  Type 2 at `nonce + 1`.

**Type 1 / Type 2 wrapper (each exactly 4128 bytes):**

Both are `abi.encode(uint256 ownerIndex, bytes c10Sig)` where
`c10Sig` is a raw 4008-byte SPHINCS+C10 signature
(`C10_SIG_LEN = 4008`, `OWNER_BYTES_LEN = 64`). The wallet contract
ABI-decodes them as `SignatureWrapper(uint256 ownerIndex, bytes signatureData)`
in `validateUserOp`:

- `ownerIndex == 0` → Type 1 (bootstrap-key sig); installs the slot pubkey
  at the wrapper's destination index.
- `ownerIndex >= 1` → Type 2 (slot-key sig); executes the user's call
  via `executeWithOffchainCount(...)` which atomically updates
  `offchainSigCount[i]` to `new_offchain_count`.

The companion wraps each in a `PackedUserOperation` with the appropriate
`callData`:

- **Type 1 UserOp**: `callData = execute(sender, 0, "")` (a no-op call
  to self; its only purpose is to attach the Type 1 sig whose validation
  side-effect registers the slot on chain).
- **Type 2 UserOp**: `callData = executeWithOffchainCount(ownerIndex,
  new_offchain_count, to, value, data)` — the wallet bumps the EIP-1271
  off-chain counter and dispatches the user's call atomically.

### 0x10 UNLOCK

No arguments. The secure world takes over the trusted UI, prompts the
user for their PIN via buttons, and (on success) unlocks both secure
elements. The PIN never crosses the gateway.

Response is a status word only (no data).

### 0x02 GET_STATUS

Returns:
```
[provisioned u8] [locked u8] [pin_remaining u8]
```

### 0x01 GET_DEVICE_INFO

Returns a versioning + capability header. Reports `ep_version = 0x0006`
(EntryPoint v0.6) and `sig_param_set = 10` (SPHINCS+C10, `C10_SIG_LEN = 4008`).

### 0x60 GET_WALLET_ADDRESS

Input: `[chain_id u64 BE] [account_index u8]`.
Output: 20-byte CREATE2-predicted ERC-1967 proxy address.
First call after unlock takes <1 s (master keygen); cached afterwards.

### 0x61 GET_INIT_CODE

Pre-computed 4280-byte `initCode` for `(account_index, chain_id)` so the
companion can run gas estimation against the EntryPoint without
round-tripping through `0x30 SIGN_USEROP`.

### 0x62 SIGN_OFFCHAIN

EIP-1271 sig over a 32-B hash, returned as
`[new_local_offchain_count u64 BE][C10 sig (4008 B)]` (4016 bytes total).
Companion wraps as `abi.encode(uint256 ownerIndex, bytes c10Sig)` and the
dapp calls `wallet.isValidSignature(rawHash, wrappedSig)`. Refuses if the
slot is unregistered, the gap exceeds `MAX_OFFCHAIN_GAP = 5`, or the
combined cap is exhausted. Bootstrap key (`ownerIndex == 0`) is
**forbidden** for EIP-1271.

### 0x63 OFFCHAIN_STATUS

Per-slot `(local_offchain_count, last_userop_count, registered)` readback.

### 0x70..0x74 FW_BEGIN/CHUNK/COMMIT/STATUS/ABORT

Streaming firmware update. PIN unlock required on every call. See
`docs/firmware-update.md`.

## Reserved / unused INS values

These INS values exist as constants in `proto/src/lib.rs` but are no
longer dispatched (or are reserved for backwards-compat probing):

- `0x20 GET_BOOTSTRAP_VK`, `0x21 GET_MAIN_VK` — superseded by
  `GET_WALLET_ADDRESS` (slot keys are derived on demand and not exposed)
- `0x31 SIGN_CLEAR_USEROP` — clear-sign is now an in-line side-effect of
  `0x30 SIGN_USEROP` when calldata is recognised (ERC-20, Safe, CowSwap…)
- `0x40 SIGN_MESSAGE`, `0x41 SIGN_EIP712` — EIP-191 / generic EIP-712 are
  served via `0x62 SIGN_OFFCHAIN` (Solady-nested EIP-712 / EIP-1271)
- `0x50 SIGN_BOOTSTRAP` — folded into `0x30 SIGN_USEROP` with
  `FLAG_REGISTER_SLOT`

## Status words

| SW     | Meaning |
|--------|---------|
| 0x9000 | OK |
| 0x6100..0x61FF | More data available; send GET_RESPONSE |
| 0x6501 | Slot exhausted (rotation path failed) |
| 0x6700 | Wrong length |
| 0x6982 | Security condition not satisfied (bad PIN, cancelled sign) |
| 0x6984 | Session expired (idle wipe) |
| 0x6985 | Device locked |
| 0x6A80 | Wrong data |
| 0x6D00 | INS not supported |
| 0x6E00 | CLA not supported |
| 0x6F00 | Internal error |
