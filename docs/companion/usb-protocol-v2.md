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
| Max APDU reassembly | 4096 bytes (`shared::apdu_framing::MAX_APDU_RX`) |

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

The device accumulates data while P1 bit 7 is set and executes only when it
receives a block with **P1 = 0x00**. `Lc` does not terminate a chain: a short
intermediate block is legal with P1=0x80, and an exact-multiple-of-255 payload
still needs its final data block marked P1=0x00.

### Response Chaining (GET_RESPONSE)

Signing responses are up to `MAX_SIGN_RESPONSE_LEN = 12,620` bytes (12,556 before protocol 0x0203). The device returns the first 253
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

### Hard bounds: chain lifetime, drain deadlines, reassembly timeout

The firmware bounds every multi-frame exchange so a stalled or hostile
host cannot pin the single-session router lease (findings X17-UC1, F2,
F11). All clocks tick at the USB SOF cadence (1 frame ≈ 1 ms).

- **Command-chain total lifetime — 30 s**
  (`ChainState::CHAIN_TIMEOUT_FRAMES = 30_000`,
  `shared/src/apdu_framing.rs`). A chained upload (P1=0x80 … P1=0x00)
  must complete within 30 s of its first block. This is a
  total-exchange deadline, NOT an idle timeout: sending more blocks
  does not extend it. On expiry the device silently resets the chain
  and releases the session lease. A late P1=0x80 block is then accepted
  as the FIRST block of a brand-new chain, and a following P1=0x00
  block executes the truncated accumulation — the secure parsers reject
  truncated payloads, so the host sees a late error SW (e.g. 0x6700 /
  0x6A80) from the final block rather than a chain-abort signal at the
  moment of expiry. Retry guidance: finish a chain well inside 30 s;
  after any long pause or late failure, resend the entire chain from
  block 0 — never try to resume a stale chain.

- **GET_RESPONSE drain idle timeout — 30 s**
  (`PENDING_TIMEOUT_FRAMES`, `nonsecure/src/usb/commands.rs`). Each
  successful GET_RESPONSE resets this clock; 30 s of host silence
  scrubs the pending response and releases the lease. Host-visible
  effect: the next GET_RESPONSE returns SW 0x6985. Retry guidance:
  re-issue the original command and drain without long pauses.

- **GET_RESPONSE drain absolute deadline — 120 s**
  (`PENDING_ABS_TIMEOUT_FRAMES`, same file). NOT reset by drain
  activity: a drain must complete within 120 s of its first chunk
  regardless of keepalives. Host-visible effect on expiry is the same
  as the idle timeout (pending data scrubbed; next GET_RESPONSE →
  0x6985). A worst-case legitimate drain (17 initCode chunks; a full
  12,620-byte signing response) needs far less even at seconds per
  round-trip, so 0x6985 mid-drain means the exchange is dead — restart
  the command from scratch.

- **Single-session router lease (F11)**
  (`router_lease_allows`, `shared/src/apdu_framing.rs`). While any
  chain or drain is live, APDUs arriving on a different HID channel are
  refused with SW 0x6985 without disturbing the owning channel's state.
  The lease releases when the exchange completes or one of the
  deadlines above fires. Guidance: one host session at a time — a
  second app or channel must wait out at most the bounds above.

- **Transport RX reassembly timeout — 5 s**
  (`RX_REASSEMBLY_TIMEOUT_FRAMES = 5000`,
  `nonsecure/src/usb/transport.rs`). Once the first HID frame of an
  APDU arrives, its continuation frames must complete within 5 s or the
  partial reassembly is scrubbed. Host-visible effect: no response at
  all — the device silently drops the partial APDU. Retry guidance:
  send an APDU's HID frames back-to-back; after any gap over 5 s,
  resend the whole APDU starting at sequence 0.

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
| 0x71 | FW_CHUNK               | No       | 0          |
| 0x72 | FW_COMMIT              | No       | 0          |
| 0x73 | FW_STATUS              | No       | 0          |
| 0x74 | FW_ABORT               | No       | 0          |
| 0xC0 | GET_RESPONSE           | No       | 0          |

### 0x30 SIGN_USEROP — unified sign

**This is the only single-UserOp signing command in the post-cutover wallet.**
The companion's flags request initCode or Type 1 output; firmware does not infer
registration state. Against a device reporting protocol **0x0203 or later**,
companions may request the slot-0 factory-deploy path, Type 2 only, or a slot
rotation (`FLAG_REGISTER_SLOT`, slot N ≥ 1): the 0x0203 response carries the
new slot's 64-byte owner bytes (#353). Never set `FLAG_REGISTER_SLOT` against
a device reporting `< 0x0203`.

**Input payload (`SIGN_USEROP_HEADER_LEN = 330` bytes of header + inner
calldata):**

```
offset  size  field
---------------------------------------------------------
  0     8    chain_id (u64 BE)
  8     4    flags (u32 BE — see shared/src/lib.rs)
 12    20    sender (MUST equal GET_WALLET_ADDRESS(account_index); mismatch is refused)
 32    20    entry_point (EntryPoint v0.6 address)
 52    32    nonce (u256 BE: high 192-bit v0.6 lane key | low 64-bit sequence;
                   base nonce for Type 1 if needed else Type 2)
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

Before any signature is released, every confirmation set includes a mandatory
`Signer acct #N` page followed by the full EIP-55 address independently derived
for `account_index` in secure world. The wire `sender` must match that address,
but is not trusted as the source of the displayed identity. Batch signing shows
the same identity for each member confirmation and again at the final batch
authorization gate.

EntryPoint v0.6 parallel nonce lanes remain supported. The normal renderer's
`Nonce:` row shows the low-64 sequence. If the high-192 lane key is non-zero,
every applicable confirmation set additionally includes one exact
`Nonce lane key:` page containing all 48 lowercase hexadecimal characters.
Lane zero omits the page. The page is reconstructed from the same full nonce
that enters the respective transaction/batch `userOpHash` and is independently
FI-proved before confirmation. With `FLAG_REGISTER_SLOT`, the rotation signature
uses the Type-1 base nonce and its displayed high-192 lane is shared with the
transaction; transaction/batch confirmations show the exact Type-2 `base + 1`
sequence. CRIT-17 rejects low-64 overflow before it can change lanes.

**Response (post-2026-04-29 layout):**

```
[new_offchain_count   u64 BE]               (8 bytes — for Type 2 calldata)
[init_code_len        u32 BE]
[init_code            init_code_len bytes]  (4280 B when FLAG_INCLUDE_INIT_CODE, else 0)
[type1_len            u32 BE]
[type1_section        type1_len bytes]      (4192 B when FLAG_REGISTER_SLOT, else 0)
    = [new_owner_bytes 64 B]                pkSeed(32) || pkRoot(32) of the new slot
      [type1_wrapper   4128 B]              abi.encode(0, bootstrapC10Sig)
[type2_len            u32 BE]
[type2_wrapper        type2_len bytes]      (always 4128 B)
```

- `type1_len == 0` means only that no Type 1 was requested/emitted. Except for
  slot 0 installed atomically by the factory path, the companion must verify
  the selected slot is already registered on-chain before requesting Type 2.
- `type1_len == 4192` (`TYPE1_ROTATION_SECTION_LEN`, protocol 0x0203+) means
  firmware signed a rotation to slot N ≥ 1. `new_owner_bytes` is copied by the
  firmware out of the exact `addOwnerBytes(bytes)` calldata the bootstrap key
  signed, and FI-checked against the new slot's key before release. Any other
  non-zero `type1_len` (including the pre-0x0203 bare 4128) MUST be rejected.
  The full companion procedure is
  `docs/companion/companion-app-integration.md` §11.4.

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

The companion wraps an available wrapper in an EntryPoint v0.6 `UserOperation`
(`UserOperation06`) with the appropriate
`callData`:

- **Type 1 UserOp (rotation):** `callData = addOwnerBytes(new_owner_bytes)`
  (`0x101490cb || 0x20 || 0x40 || new_owner_bytes`, 132 bytes), `nonce = base`,
  empty `initCode` and `paymasterAndData`, and the same five gas words as the
  request. Submit it first and wait for inclusion; only then submit the Type 2
  UserOp (`nonce = base + 1`). They cannot share a bundle: EntryPoint v0.6
  validates every op before executing any, and the new slot's key is installed
  only when `addOwnerBytes` executes. First deployment is not Type 1: set
  `FLAG_INCLUDE_INIT_CODE`, use slot 0, and keep `FLAG_REGISTER_SLOT` clear;
  the factory installs slot 0.
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
[locked u8] [pin_remaining u8]
```

There is deliberately NO `provisioned` byte: the firmware once emitted
one derived as `pin_remaining <= MAX_ATTEMPTS`, which is always true,
so the byte was a constant-1 that reported "provisioned" even on a
blank device (finding X17-UC2). Rather than lie, the byte was removed.
A blank device runs the on-device first-boot wizard; detect that state
from the wizard UI, not from GET_STATUS.

### 0x01 GET_DEVICE_INFO

Returns a versioning + capability header. Bytes 0–1 are
`protocol_version` (u16 BE) = `PROTOCOL_VERSION` from `proto/src/lib.rs`,
currently **0x0203** (see §Protocol version history below). Reports
`ep_version = 0x0006` (EntryPoint v0.6) and `sig_param_set = 2`
(SPHINCS+C10, `C10_SIG_LEN = 4008`). Capability bit 0 is
`CAP_SIGN_USEROP`; bit 1 is retired and remains clear; bit 2 is
`CAP_ERC7730_PROOF_SET`. A companion may emit the versioned two-bundle
ERC-7730 envelope only when bit 2 is set. Bit 3 is `CAP_OFFCHAIN_SAFE_TX` and
bit 4 is `CAP_OFFCHAIN_COW_ORDER` (UPDATE 2026-10-19): `0x62 SIGN_OFFCHAIN`
accepts kinds 4 / 5 only when the matching bit is set. The capability word is
bytes 21–24 (u32 BE) of the response, after `protocol_version` (2),
`fw_version` (3) and the 16-byte `device_uid` placeholder. Do not infer that support from the
three `fw_version` bytes: they are currently a fixed placeholder rather than
the running image identity.

### 0x60 GET_WALLET_ADDRESS

Input: empty for legacy `account_index = 0`, or `[account_index u32 BE]` for
accounts `0..=255`. No chain id is accepted; wallet addresses are chain-
independent by design. Protocol 0x0202+ additionally accepts a trailing
`[show u8]` flag: `0` behaves as absent; `1` paints the full EIP-55 address
on the device OLED behind a physical confirm before the bytes are returned
(#472 — user cancel yields `0x6982` and no address); any flag above 1 is
rejected with `0x6A80`. Firmware < 0x0202 rejects the 5-byte body with
`0x6700`, so gate the flag on the GET_DEVICE_INFO report.
Output: 20-byte CREATE2-predicted ERC-1967 proxy address.
First call after unlock takes <1 s (master keygen); cached afterwards.

### 0x61 GET_INIT_CODE

Pre-computed 4280-byte `initCode` for `(account_index, chain_id)` so the
companion can run gas estimation against the EntryPoint without
round-tripping through `0x30 SIGN_USEROP`.

### 0x62 SIGN_OFFCHAIN

EIP-1271 signature response with two layouts selected by the input `flags`
byte:

- `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED = 1`:
  `[new_local_offchain_count u64 BE][C10 sig (4008 B)]` (4016 bytes total).
  Wrap the raw signature as `abi.encode(uint256 ownerIndex, bytes c10Sig)` and
  call `wallet.isValidSignature(rawHash, wrappedSig)`.
- `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED = 0`:
  `[new_local_offchain_count u64 BE][ERC-6492 blob (8608 B)]` (8616 bytes
  total). The payload is already the complete ERC-6492 wrapper; pass it through
  unchanged to an ERC-6492-aware verifier and do not ABI-wrap it again. This
  counterfactual path is restricted to slot 0.

The deployed-wallet path refuses an unregistered slot. The undeployed
counterfactual path has one narrow exception: a never-used slot 0 is
auto-registered locally so its ERC-6492 deploy-then-verify blob can be produced.
Both paths refuse when the gap exceeds `MAX_OFFCHAIN_GAP = 100` or the combined
cap is exhausted. Bootstrap key (`ownerIndex == 0`) is **forbidden** for
EIP-1271.

The input header is 17 B (`account(1) | chain(8) | slot(4) | kind(1) |
payload_len(2) | flags(1)`). The `kind` byte selects the payload
format:

| `kind`                          | Value | Payload                                                                                       |
|---------------------------------|-------|-----------------------------------------------------------------------------------------------|
| `OFFCHAIN_KIND_RAW32`           | 0     | 32 companion-supplied opaque bytes; firmware wraps via Solady nested EIP-712 and displays `! BLIND RAW32`. Never translate a typed-data request into this kind. |
| `OFFCHAIN_KIND_PERSONAL_SIGN`   | 1     | UTF-8 message ≤ `MAX_OFFCHAIN_PERSONAL_SIGN_LEN`; firmware applies EIP-191 prefix + wraps.    |
| `OFFCHAIN_KIND_EIP712_TYPED`    | 2     | EIP-712 typed-data (see below) — Phase 4 of the ERC-7730 rollout.                              |
| `OFFCHAIN_KIND_EIP712_TYPED_V3` | 3     | EIP-712 typed-data plus descriptor-selected nested/string display witnesses; see the canonical companion guide §6.5. |
| `OFFCHAIN_KIND_SAFE_TX`         | 4     | EIP-712 `SafeTx` (Safe ≥ v1.3.0) this wallet co-signs as an owner; see below. Gated by `CAP_OFFCHAIN_SAFE_TX`. |
| `OFFCHAIN_KIND_COW_ORDER`       | 5     | CoW `GPv2Order` under CoW's `eip1271` scheme (owner = this wallet); see below. Gated by `CAP_OFFCHAIN_COW_ORDER`. |

`RAW32` is a deliberately loud blind-sign tier, not evidence that the device
understands a user's intent. A hostile companion can submit the final hash of
otherwise structured typed data through this kind and suppress its semantic
pages. Production companions MUST NOT downgrade structured requests to
`RAW32`; production firmware should disable the kind unless the product owner
explicitly accepts this residual.

#### `kind = OFFCHAIN_KIND_EIP712_TYPED` (2) wire format

Payload layout (immediately after the 17-byte header):

```
[u16 BE = 1]                  // domain_sep_present (must be 1)
[u8; 32] domain_separator     // EIP-712 EIP712Domain final hash
[u8; 32] primary_type_hash    // keccak256(encodeType(primaryType, types))
[u16 BE] encoded_data_len     // ≤ MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN
[u8; encoded_data_len] encoded_data
                              // canonical EIP-712 encodeData body (NOT
                              // including the type hash). Plain ABI encoding
                              // matches only flat static scalar members;
                              // dynamic/composite members use hash words.
[u16 BE] trailer_len          // ERC-7730 descriptor trailer length
[u8; trailer_len] trailer     // ERC-7730 bundle (see docs/companion/erc7730-integration.md)
```

The minimum payload length is `2 + 32 + 32 + 2 + 2 = 70` bytes (empty
`encoded_data` + zero-length trailer reaches the strict framing parser but is
rejected with `empty trailer`). The maximum payload length is
`MAX_OFFCHAIN_EIP712_TYPED_LEN`.

Secure-side processing:

1. Verify the trailer bundle against `ERC7730_DESCRIPTORS_ROOT`.
2. `cross_check_eip712(descriptor.ir, chain_id, domain_separator)` — exact,
   FI-hardened binding. The descriptor compiler forced the deployment
   `verifyingContract` into this domain separator; firmware does not receive a
   second independent contract argument on this path.
3. Constant-time select the authenticated descriptor format using the complete
   32-byte `primary_type_hash`; a four-byte prefix or catalogue hint is never
   sufficient.
4. Compute `struct_hash = keccak256(primary_type_hash || encoded_data)`.
5. Compute the EIP-712 final hash:
   `final = keccak256(0x1901 || domain_separator || struct_hash)`.
6. Render the descriptor's matching format via
   `display::erc7730::render_erc7730_eip712_pages`; render the
   ERC-8213 fingerprint with the `final` hash as the displayed value.
7. Wrap `final` through Solady's nested PersonalSign envelope (no new
   typehash, no on-chain change).
8. Sign with the slot key + bump the per-slot off-chain counter.

Output format is selected by the same deployed/counterfactual flag as kinds 0
and 1: 4016-byte count+C10 for deployed wallets, or 8616-byte
count+ERC-6492 blob for counterfactual slot 0.

#### `kind = OFFCHAIN_KIND_SAFE_TX` (4) and `OFFCHAIN_KIND_COW_ORDER` (5)

UPDATE 2026-10-19. Typed data whose meaning the firmware already decodes on the
UserOp path, clear-signed off-chain: the device renders the Safe transaction /
the order instead of a blind hash. **The signed value is unchanged from RAW32**:
the device recomputes `H` (the `safeTxHash` under the Safe ≥ v1.3.0 domain
`{chainId, verifyingContract}`, or the GPv2 order digest under the
`"Gnosis Protocol"` / `"v2"` / GPv2Settlement domain) from the bytes it shows
and signs `replay_safe_hash(chain, wallet, H)` — byte-identical to what kind 0
signs when given `H`. The companion's own hash is never used. Golden vectors:
`tools/companion-stub/structured_offchain_goldens.json` (generator
`tools/companion-stub/structured_offchain.py`, pinned against the firmware by
`secure/src/tx/eip712/offchain_structured.rs`).

Kind 4 payload (all lengths `u16` BE), consumed exactly:

```
[safe_len][canonical SafeTx (281) || raw_len (2) || raw_data]   the on-chain approveHash safe_v1 trailer;
                                                                 raw_len must end exactly at safe_len;
                                                                 safe_len ≤ SAFE_V1_PAYLOAD_MAX (4379)
[erc20_len][ERC-20 bundle]        ≤ 1120, may be 0   token metadata for the inner call / a MultiSend record
[cow_len][CoW order trailer]      ≤ 2448, may be 0   REQUIRED iff the SafeTx inner call is GPv2
                                                      setPreSignature (direct or one MultiSendCallOnly record,
                                                      owner = the Safe); MUST be 0 otherwise
[names_count u8]{[len][name bundle]}×n   n ≤ 4, 0 < len ≤ 1093
```

`MIN_OFFCHAIN_SAFE_TX_LEN = 290`, `MAX_OFFCHAIN_SAFE_TX_LEN = 12,334`. The
device refuses: chain ≠ `canonical.chain_id`, a zero Safe address,
`keccak(raw_data) ≠ dataHash`, a DELEGATECALL to anything but a pinned
MultiSendCallOnly deployment (each record `operation = 0`, the usual record
cap), a missing or unexpected CoW section, any framing error.

Kind 5 payload: `canonical GPv2Order (204) || sell_len || sell_bundle ||
buy_len || buy_bundle` — byte-identical to the on-chain CoW order trailer,
consumed exactly (`208 ≤ len ≤ 2,448`). A leg bundle that is absent or does
not verify renders that leg as address + raw amount; an amount that cannot be
rendered exactly is refused. A zero `receiver` is shown as this wallet (the
order owner).

Both kinds require `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED = 1` (refused before any
flash write otherwise: neither Safe's `checkSignatures` nor GPv2Settlement
unwraps ERC-6492) and use the same page-123 gap/cap gate, confirmation gate and
4016-byte response as the other kinds.

Consumers: **SafeTx signatures verify only on Safe ≥ v1.5.0**, whose
`checkSignatures` calls the bytes32 `isValidSignature`; Safe v1.3.0 / v1.4.1
call the legacy `isValidSignature(bytes,bytes)`, which `PQSmartWallet` does not
implement (true of a RAW32 signature over the same hash too). Older Safes
(< v1.3.0, domain without `chainId`) produce a different hash and cannot use
kind 4. Companions MUST gate kinds 4 / 5 on the capability bits and MUST NOT
fall back to RAW32 after a kind-4/5 refusal — that would turn every structured
refusal into a blind signature.

### 0x63 OFFCHAIN_STATUS

Per-slot `(local_offchain_count, last_userop_count, registered)` readback.

### 0x64 OFFCHAIN_SYNC

Raise a slot's `last_userop_count` floor to the on-chain `offchainSigCount`
(after a restore, or when the same seed is used on a second device). Body:
`account(1) | chain_id(8 BE) | slot_index(4 BE) | target(8 BE)`; SW only.
"Set if greater": a lower target is a no-op.

- A new slot, or a target above the stored floor, needs a trusted-display
  confirm, worded for users: *Update signature count?* — the device's count,
  the app's count and the signatures left after the update.
- If the update would skip more than 1,000 signatures, or leave fewer than
  1,000, the confirm carries an extra **! CAREFUL** page.
- If it would leave the slot **0** signatures, the device refuses without a
  dialog and without writing (`SW 0x6985`). Rotate to the next slot instead
  (§0x30, `FLAG_REGISTER_SLOT`).

Send the true on-chain value only. A companion that inflates the target
spends the user's per-slot budget.

### 0x70..0x74 FW_BEGIN/CHUNK/COMMIT/STATUS/ABORT

Streaming firmware update. PIN unlock required on every call. See
`docs/firmware/firmware-update.md`.

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

## Protocol version history

Current `PROTOCOL_VERSION` (GET_DEVICE_INFO bytes 0–1): **0x0203**
(`proto/src/lib.rs`).

- **0x0203 — slot-rotation response (#353):** with `FLAG_REGISTER_SLOT` the
  `SIGN_USEROP` / `SIGN_USEROP_BATCH` Type-1 section is 4192 bytes,
  `new_owner_bytes(64) || type1_wrapper(4128)`, so a seedless companion can
  rebuild and submit the bootstrap `addOwnerBytes` UserOp. Responses without
  a Type 1 are byte-identical to 0x0202; `MAX_SIGN_RESPONSE_LEN` grows to
  12,620. Companions gate `FLAG_REGISTER_SLOT` on a >= 0x0203 report.
- **0x0202 — GET_WALLET_ADDRESS `show` flag (#472):** INS 0x60 accepts
  an optional trailing flag byte; `show = 1` displays the derived
  address on the device OLED behind a physical confirm before it is
  returned (see §0x60 GET_WALLET_ADDRESS).
- **0x0201 — GET_STATUS layout bump (#440):** the 0x02 GET_STATUS
  response shrank from 5 bytes on the wire (3 data bytes + SW) to
  4 bytes (2 data bytes + SW). The leading `provisioned` byte was
  removed (finding X17-UC2) because it was a constant-1 that reported
  even blank devices as provisioned. Firmware reporting 0x0201 or
  later always speaks the 2-byte `[locked][pin_remaining]` layout
  (see §0x02 GET_STATUS).
- **0x0200 ambiguity window:** the layout change originally shipped
  WITHOUT a `PROTOCOL_VERSION` bump, so a 0x0200 report cannot
  distinguish pre- from post-change firmware. Pre-production only,
  with the companion shipped in lockstep. Companions MUST parse the
  current 2-byte layout and SHOULD treat any 0x0200 device as
  ambiguous vintage.
