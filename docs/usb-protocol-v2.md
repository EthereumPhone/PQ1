# PQSigner USB Protocol v2 (post-JARDÍN cutover)

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

After the JARDÍN cutover, the v2 protocol exposes a small, focused set
of commands:

| INS  | Name                   | Chained? | P1         |
|------|------------------------|----------|------------|
| 0x01 | GET_DEVICE_INFO        | No       | 0          |
| 0x02 | GET_STATUS             | No       | 0          |
| 0x10 | UNLOCK                 | No       | 0          |
| 0x11 | LOCK                   | No       | 0          |
| 0x30 | SIGN_USEROP (unified)  | Yes      | 0x00/0x80  |
| 0x72 | GET_JARDIN_SLOT_INFO   | No       | 0          |
| 0xC0 | GET_RESPONSE           | No       | 0          |

### 0x30 SIGN_USEROP — unified JARDÍN sign

**This is the only signing command in the post-cutover wallet.** The
firmware's state machine decides whether the response also needs a Type 1
slot-registration UserOp; the companion just parses the two-chunk
bundle and submits to the bundler in order.

**Input payload (`SIGN_USEROP_HEADER_LEN = 266` bytes of header + inner
calldata):**

```
offset  size  field
---------------------------------------------------------
  0     8    chain_id (u64 BE)
  8     4    slot_index_hint (u32 BE, usually 0)
 12    20    sender (PQJardinWallet address)
 32    20    entry_point (EntryPoint v0.9 address)
 52    32    nonce (u256 BE, base nonce for Type 1 if needed else Type 2)
 84    32    account_gas_limits (bytes32, (verGas<<128)|callGas)
116    32    pre_verification_gas (u256 BE)
148    32    gas_fees (bytes32, (maxPrio<<128)|maxFee)
180    32    paymaster_and_data_hash (keccak256, KECCAK_EMPTY when empty)
212    20    to_address (inner tx recipient)
232    32    value (u256 BE)
264     2    data_len (u16 BE, 0..=4096)
266     N    data
```

**Response:**

```
[type1_len u32 BE] [type1_bytes ...] [type2_len u32 BE] [type2_bytes ...]
```

- `type1_len == 0` means the slot is already registered on this chain
  and the companion should submit only the Type 2 UserOp.
- `type1_len == 4041` means a fresh slot must be registered on-chain
  first. The companion submits the Type 1 UserOp at `nonce` and waits
  for confirmation, then submits the Type 2 UserOp at `nonce + 1`.

**Type 1 bytes (exactly 4041):**
```
[0x01] [r(32)] [subPkSeed(16)] [subPkRoot(16)] [C11_sig(3976)]
```

**Type 2 bytes (2533..4037):**
```
[0x02] [H(r)(32)] [subPkSeed(16)] [subPkRoot(16)] [FORS+C_sig(2452 + q·16)]
```

The companion wraps each of these in a `PackedUserOperation` with the
appropriate `callData`:

- **Type 1 UserOp**: `callData = execute(sender, 0, "")` (a no-op call
  to self; its only purpose is to attach the Type 1 sig whose validation
  side-effect registers the slot on chain).
- **Type 2 UserOp**: `callData = execute(to, value, data)` (the user's
  actual tx).

### 0x72 GET_JARDIN_SLOT_INFO

Query the persisted slot state for a given chain. Useful for the
companion to display "slot N, next_q=M, 95-M signatures remaining".

**Input (8 bytes):**
```
chain_id (u64 BE)
```

**Response (45 bytes):**
```
[slot_index u32 BE] [next_q u32 BE] [flags u32 BE] [active u8] [h_r 32B]
```

- `active == 0` means no record exists for this `chain_id` (including
  the fresh-wallet case).
- `flags & 1` is the `FLAG_SLOT_REGISTERED` bit.
- `h_r` is the on-chain slotKey (all zeros when `active == 0`).

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

Returns a versioning + capability header. Reports `ep_version = 0x0009`
(EntryPoint v0.9) and `sig_param_set = 1` (JARDÍN FORS+C).

## Removed commands (pre-cutover)

The following pre-cutover commands no longer exist:

- `0x20 GET_BOOTSTRAP_VK` — no bootstrap signer
- `0x21 GET_MAIN_VK` — no per-chain main signer
- `0x31 SIGN_CLEAR_USEROP` — no ZK clear-signing
- `0x40 SIGN_MESSAGE` — EIP-191 removed with the rest
- `0x41 SIGN_EIP712` — no EIP-712 path
- `0x50 SIGN_BOOTSTRAP` — no bootstrap signer
- `0x60 GET_WALLET_ADDRESS` — companion derives via factory CREATE2
- `0x70 SIGN_JARDIN` (split) — folded into 0x30
- `0x71 REGISTER_JARDIN_SLOT` (split) — folded into 0x30

## Status words

| SW     | Meaning |
|--------|---------|
| 0x9000 | OK |
| 0x6100..0x61FF | More data available; send GET_RESPONSE |
| 0x6501 | JARDÍN slot exhausted (rotation path failed) |
| 0x6700 | Wrong length |
| 0x6982 | Security condition not satisfied (bad PIN, cancelled sign) |
| 0x6984 | Session expired (idle wipe) |
| 0x6985 | Device locked |
| 0x6A80 | Wrong data |
| 0x6D00 | INS not supported |
| 0x6E00 | CLA not supported |
| 0x6F00 | Internal error |
