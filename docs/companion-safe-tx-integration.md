# Safe-Tx clear-signing — companion app integration

This document specifies the contract between the PQSigner firmware and a
companion app/extension when the user is asked to approve a Gnosis Safe
multisig transaction through the AA wallet. Read this end-to-end before
writing any companion code — every rule listed in
[Verifier rules the companion must satisfy](#verifier-rules-the-companion-must-satisfy)
is enforced on-device and fails closed; getting one wrong does not
silently downgrade, it bricks the sign attempt with a status line.

It assumes you already understand the broader companion-app surface
([`companion-app-integration.md`](companion-app-integration.md) and
[`companion-batch-sign-integration.md`](companion-batch-sign-integration.md)).
What is new here is the `safe_v1` trailer that converts an opaque
`approveHash(bytes32)` UserOp into a clear-signing experience.

## Why this flow exists

The Gnosis Safe Web Dapp does **not** request an EIP-712 typed-data
signature from an AA wallet. Instead it builds a UserOp whose inner call
is

```solidity
Safe(safeAddress).approveHash(bytes32 safeTxHash)
```

and asks the AA wallet to sign that UserOp. The `bytes32` argument is
the EIP-712 `safeTxHash` per Safe v1.3.0+, but the rich SafeTx fields it
commits to (`to`, `value`, `data`, `operation`, `safeTxGas`, `baseGas`,
`gasPrice`, `gasToken`, `refundReceiver`, `nonce`, `chainId`,
`safeAddress`) are nowhere in the calldata. Without those fields the
firmware can only show a 32-byte hash — exactly the blind-signing
failure mode hardware wallets exist to prevent.

The companion app closes that gap by fetching the canonical SafeTx
fields out of band (Safe Transaction Service, your own backend, or a
local cache) and shipping them to the firmware as a `safe_v1` trailer
on the UserOp. The firmware then **recomputes** `safeTxHash` from those
fields and byte-compares against `inner_data[4..36]`. A match is the
cryptographic anchor that converts untrusted JSON into trusted SafeTx
fields with no key material added — just two keccak chains.

## What the firmware will not trust

**Everything** coming over USB-HID. Read that again: every byte of the
`safe_v1` trailer is hostile until proven otherwise. The firmware does
not call the Safe Transaction Service; it does not parse JSON; it does
not believe any field the companion claims. The only thing it trusts is
the `safeTxHash` it derived itself from the bytes you sent, and it only
uses the canonical fields to drive the OLED *after* that derivation
matches the on-chain `bytes32` from the calldata.

Concretely, this means companion bugs that:

- swap `to` and `gasToken`,
- lie about `chainId`,
- repackage a Mainnet SafeTx as a Polygon one,
- modify a digit in the `value` field,
- supply a `raw_data` that doesn't hash to `data_hash`,

all **self-fail** at the verifier stage. The firmware refuses to sign,
displays `Safe sign: bind failed` (or similar), and returns the
companion a non-zero NSC status.

This is the point. There is no path through the companion that can
trick the OLED into showing one tx while the on-chain Safe records
another.

## Wire format

The `safe_v1` trailer rides on `CMD_SIGN_USEROP` (`CMD = 7`) using TLV
kind `TRAILER_KIND_SAFE_V1 = 4`, per the unified-sign trailer chain
documented in [`usb-protocol-v2.md`](usb-protocol-v2.md). The payload is:

```
offset  size            field
  0     281             canonical SafeTx fields (fixed layout, see below)
281     2 (u16 BE)      raw_data_len  (0..=4096)
283     raw_data_len    raw_data — exact inner-call calldata
```

### Canonical SafeTx layout (281 bytes)

Mirrors `secure/src/tx/eip712/safe/mod.rs::decode_canonical`. All
multi-byte integers are big-endian.

| Range       | Field             | Type            | Notes |
|-------------|-------------------|-----------------|-------|
| `[0..8)`    | `chain_id`        | u64 BE          | Must equal the outer UserOp `chain_id` (header offset 0) |
| `[8..28)`   | `safe_address`    | 20 B            | Must equal the outer UserOp `to` (header offset 12) |
| `[28..48)`  | `to`              | 20 B            | The SafeTx target (the contract the Safe will call) |
| `[48..80)`  | `value`           | uint256 BE      | ETH value of the inner call |
| `[80..112)` | `data_hash`       | bytes32         | `keccak256(raw_data)` — firmware re-derives |
| `[112]`     | `operation`       | u8              | `0 = Call`, `1 = DelegateCall`. **`1` rejected**, see below |
| `[113..145)`| `safe_tx_gas`     | uint256 BE      | EIP-712 field; firmware only uses it for the typehash |
| `[145..177)`| `base_gas`        | uint256 BE      | EIP-712 field |
| `[177..209)`| `gas_price`       | uint256 BE      | EIP-712 field |
| `[209..229)`| `gas_token`       | 20 B            | EIP-712 field |
| `[229..249)`| `refund_receiver` | 20 B            | EIP-712 field |
| `[249..281)`| `nonce`           | uint256 BE      | SafeTx nonce — incrementing per-Safe counter |

Constants exposed by `pqsigner_proto` / `sphincs_tz_shared`:

- `SAFE_V1_CANONICAL_LEN = 281`
- `SAFE_V1_RAW_DATA_MAX = MAX_TX_LEN` (4096 bytes)
- `SAFE_V1_PAYLOAD_MAX = 281 + 2 + 4096 = 4379`
- `SAFE_OFF_CHAIN_ID = 0`, `SAFE_OFF_SAFE_ADDRESS = 8`, … (full list in
  `proto/src/lib.rs:1467`)

### `raw_data` semantics

`raw_data` is the **exact bytes** the Safe will pass to `execTransaction`
as its `data` argument once threshold approvals collect. No
pre-processing, no JSON wrapping, no leading length prefix — just the
calldata for the inner call. If the Safe is about to send ETH, this is
empty. If it is about to call `transfer(address,uint256)` on USDC, this
is the 68-byte ABI-encoded selector + args. If it is about to call
`addOwnerWithThreshold` on itself, this is the 68-byte selector + args.

## Verifier rules the companion must satisfy

Every rule below is checked by
[`tx/eip712/safe/verify.rs::verify_and_bind_trailer`](../secure/src/tx/eip712/safe/verify.rs)
and fails closed (the trailer is treated as absent; the symmetric
"`approveHash` requires `safe_v1`" gate then refuses to sign):

1. **Trailer framing**:
   `safe_bundle.len() >= 281 + 2`, declared `raw_data_len <= 4096`,
   `raw_data_end <= safe_bundle.len()`.
2. **Selector**: `inner_data[0..4] == APPROVE_HASH_SELECTOR =
   0xd4d9bdcd` (`keccak256("approveHash(bytes32)")[..4]`).
3. **Calldata length**: `inner_data.len() == 36`.
4. **Chain pinning**: `canonical.chain_id == userop.chain_id`.
5. **Safe address pinning**: `canonical.safe_address == userop.to`.
6. **Operation gate**: `canonical.operation == 0` (Call). DelegateCall
   (`1`) is **rejected for now** — see [DelegateCall and MultiSend](#delegatecall-and-multisend)
   below.
7. **Data-hash bind**: `keccak256(raw_data) == canonical.data_hash`.
8. **SafeTxHash bind**: `compute_safe_tx_hash(canonical) ==
   inner_data[4..36]`.

`compute_safe_tx_hash` follows Safe v1.3.0+ EIP-712:

```
domainSeparator = keccak256(abi.encode(
    SAFE_DOMAIN_TYPEHASH,         // keccak("EIP712Domain(uint256 chainId,address verifyingContract)")
    chain_id,
    safe_address
))

safeTxStructHash = keccak256(abi.encode(
    SAFE_TX_TYPEHASH,             // keccak("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")
    to,
    value,
    keccak256(data),              // data_hash
    operation,
    safeTxGas,
    baseGas,
    gasPrice,
    gasToken,
    refundReceiver,
    nonce
))

safeTxHash = keccak256(0x19 0x01 || domainSeparator || safeTxStructHash)
```

Reference Solidity: `Safe.sol::encodeTransactionData` /
`Safe.sol::getTransactionHash` in
[gnosis/safe-contracts](https://github.com/safe-global/safe-contracts).

If your companion computes `safeTxHash` itself before forwarding (to
sanity-check what the Safe API returned), use the *same* domain — Safe
**v1.1.x** used a chain-agnostic domain that produces a different hash
and will self-reject on this firmware. The firmware only supports v1.3.0
and later.

## On-device rendering

Once the bind passes, the firmware lays out the SafeTx on a 16-col × 4-row
OLED. Page count is variable and capped at `MAX_PAGES = 22` (well above
anything Safe rendering needs).

### Header (always 3 pages)

```
P0: "Approve Safe TX"     P1: "Safe:"            P2: "SafeTx Nonce: N"
    Chain: <n>                <addr full or         Op: Call
    <chain name>              ENS name>             <inner kind hint>
    > next                                          > next
```

### Inner-tx render

The renderer classifies the inner call and dispatches:

| Trigger                                          | Renderer            | Page count |
|--------------------------------------------------|---------------------|------------|
| empty `raw_data`, `value == 0`                   | empty call          | 1          |
| empty `raw_data`, `value > 0`                    | plain ETH transfer  | 2          |
| `parse_erc20_calldata` succeeds, ERC-20 bundle present + address-matches | ERC-20 known   | 4          |
| `parse_erc20_calldata` succeeds, no metadata match | ERC-20 unknown    | 4          |
| `canonical.to == canonical.safe_address` + recognised selector | **Safe-mgmt** (per-op) | 1–3 |
| `canonical.to == canonical.safe_address` + unrecognised selector | **Unknown Safe op** (loud blind) | 3 |
| anything else                                    | Blind sign          | 3          |

Final page: long-press confirm prompt.

### Safe-native operations (`to == safe_address`)

The firmware recognises the following Safe v1.3.0+ singleton selectors
and decodes each into a per-op intent banner. All other selectors hitting
the Safe contract itself render as **"Unknown Safe op"** with a loud
warning row so the user can refuse if the dapp did not actually ask for a
Safe-mgmt op.

| Selector     | Signature                                    | Pages | Risk banner |
|--------------|----------------------------------------------|-------|-------------|
| `0x0d582f13` | `addOwnerWithThreshold(address,uint256)`     | 2     | `! MULTISIG OFF` if new threshold = 1 |
| `0xf8dc5dd9` | `removeOwner(address,address,uint256)`       | 3     | `! MULTISIG OFF` if new threshold = 1 |
| `0xe318b52b` | `swapOwner(address,address,address)`         | 3     | — |
| `0x694e80c3` | `changeThreshold(uint256)`                   | 1     | `! MULTISIG OFF` (=1), `! THRSHLD = 0` (=0) |
| `0x610b5925` | `enableModule(address)`                      | 2     | `! ENABLE MODULE` always |
| `0xe009cfde` | `disableModule(address,address)`             | 2     | — |
| `0xe19a9dd9` | `setGuard(address)`                          | 2     | `! CHANGE GUARD` always; `REMOVING GUARD` when `0x0` |
| `0xf08a0323` | `setFallbackHandler(address)`                | 2     | `! CHG FALLBACK` always; `REMOVING FB` when `0x0` |

The classifier additionally enforces:

- **Strict length match** per selector (truncation or trailing junk →
  "Unknown Safe op").
- **Address-word canonicalness**: every address parameter must come
  encoded as 12 zero bytes + 20-byte address. Non-canonical padding →
  "Unknown Safe op".
- **Threshold-word canonicalness**: `_threshold` words must fit in
  `u16`. Anything larger surfaces as `! >2^16` on the threshold row
  (the op is still classified, the user just sees an unmistakable
  overflow marker rather than a silently-truncated number).

`prev_owner` / `prev_module` are Safe's singly-linked-list internals.
They are rendered as a single compact row (`prv:0xAABB..CCDD`, or the
literal label `prev: SENTINEL` when the special `0x000…001` start-of-list
marker is supplied). The user does not need to memorise list positions
to verify the op; the *real* address (the owner being removed, the
module being disabled) is shown full on its own page with ENS
resolution.

### Address-name bundle reuse

The outer trailer's `TRAILER_KIND_NAME` (kind 8) Merkle-bundle resolver
is consumed by the Safe-mgmt renderer for free. If your companion
supplies a Merkle-verified name for the new-owner address on
`addOwnerWithThreshold`, the user sees

```
+ alice.eth
0x1234…abcd
```

instead of raw hex. **Use this for the high-signal addresses** — new
owners, modules being enabled, guards being installed — so the user can
match what they're approving against a name they recognise rather than
hex they can't.

The resolver is authoritative only for names that pass the Merkle
proof against the firmware-pinned `NAMES_DB_ROOT`. Your companion
cannot smuggle in arbitrary labels.

### DelegateCall and MultiSend

`canonical.operation == 1` (DelegateCall) is **rejected at the
verifier**, *for now*. The Safe Transaction Service routinely returns
MultiSend-wrapped txs (`SafeMultiSendCallOnly` as the inner `to`,
operation `1`) when the user is performing a batched op in the Safe
UI — owner add+threshold change, multiple token transfers in one
SafeTx, etc.

The firmware does **not** support these in this release.

Your options as a companion:

1. **Refuse to forward** and surface a clear UX error pointing the user
   at the Safe app to perform each step as its own SafeTx. This is the
   recommended path until Phase-2 support lands.
2. **Hold the UserOp** and retry once a firmware update with the
   per-chain MultiSend allowlist + packed sub-tx walker ships.

Do **not** try to "fix" the MultiSend by mangling the canonical — the
EIP-712 `safeTxHash` rebind will fail and the firmware will refuse
anyway.

## Error catalogue

The firmware surfaces failures via `ui::show_status("Safe sign", ...)`
and returns a non-zero `NscStatus` to the companion. The strings the
companion is most likely to encounter:

| OLED status                            | Cause                                                                | Recovery |
|----------------------------------------|----------------------------------------------------------------------|----------|
| `Safe sign: safe_v1 required`          | Inner calldata is `approveHash(bytes32)` but no `safe_v1` trailer.   | Add the trailer; do not call `approveHash` without it. |
| (trailer silently dropped) → blind-sign refused | Any of the eight verifier rules failed — bad framing, wrong chain, wrong safe address, op != 0, data_hash mismatch, safeTxHash mismatch. | Re-derive `safeTxHash` from your canonical fields and confirm it matches `inner_data[4..36]`. |
| (rendered as `! Inner: opaque`)        | `to != safe_address`; inner calldata did not decode as ERC-20 or recognised Safe-mgmt op. | Expected for arbitrary contract calls; user must verify off-device. Consider supplying an ERC-7730 descriptor (`TRAILER_KIND_ERC7730 = 7`). |
| (rendered as `! Unkn self-call`)       | `to == safe_address` but selector is not one of the eight recognised Safe-mgmt ops. | If this is a new Safe singleton method, file a firmware ticket — the supported set is pinned at compile time. |

(The "trailer silently dropped" path is intentional: a single
`bind failed` status would tell an attacker which of the eight checks
failed, which is gratuitous signal. The downgrade-mitigation gate
catches it next.)

## Putting it together — minimum companion implementation

```ts
async function buildSignRequest(safeAddress, safeTxHash, signer) {
  // 1. Fetch SafeTx fields from your trusted source.
  const tx = await safeService.fetchTransaction(safeTxHash);
  if (tx.operation !== 0) {
    throw new Error(
      "MultiSend / DelegateCall not yet supported by firmware; " +
      "ask the user to sign sub-actions individually in the Safe app."
    );
  }

  // 2. Pack the 281-byte canonical (big-endian, fixed offsets).
  const canonical = packCanonical(tx);   // see proto/src/lib.rs:1467

  // 3. Pack raw_data — exactly what the Safe will pass to execTransaction.
  const rawData = hexToBytes(tx.data);   // may be empty (0 bytes)
  assert(rawData.length <= 4096);

  // 4. Build the safe_v1 trailer.
  const trailer = concat([
    canonical,
    u16be(rawData.length),
    rawData,
  ]);

  // 5. Build the outer UserOp: inner call is approveHash(safeTxHash).
  const innerCalldata = concat([
    APPROVE_HASH_SELECTOR,   // 0xd4d9bdcd
    safeTxHash,              // 32 bytes
  ]);
  // userop.to       = safeAddress
  // userop.chain_id = tx.chainId
  // userop.data     = innerCalldata
  // userop.value    = 0
  // ... attach trailer with kind=TRAILER_KIND_SAFE_V1 (4)
}
```

That's the entire happy path. Everything else is the firmware's
problem.

## Phase 2 preview

The following are not implemented today; mention them in your roadmap
so your wire shape doesn't need to change when they ship:

- **MultiSend / DelegateCall**: per-chain allowlist of canonical
  `MultiSendCallOnly` addresses (~`0x40A2…130D` on most v1.3.0
  deployments) + on-device packed sub-tx walker that recurses each
  inner call through the existing classify ladder. Your fetch
  pipeline should preserve the original MultiSend payload so you can
  forward it unmodified once support lands.
- **Safe `signMessage` EIP-712**: some integrations sign EIP-712
  messages by first wrapping them in `signMessage(bytes)` and then
  approving the resulting hash. This works as a `RAW32` off-chain sig
  today, but the on-device prompt reads `"Sign hash"`, not "Sign Safe
  EIP-712 message". A future trailer will carry the original typed
  data so the prompt can be semantic.

When in doubt about whether a Safe surface is in scope, check the
selector table above and the companion test fixtures in
[`secure/src/tx/eip712/safe/extra_tests.rs`](../secure/src/tx/eip712/safe/extra_tests.rs).
Anything not represented there is not yet supported.
