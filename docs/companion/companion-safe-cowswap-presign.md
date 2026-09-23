# Safe-wrapped CoW presign — native companion integration

This is the live wire and binding contract for direct CoW orders, Safe
`approveHash`, decoded Safe `execTransaction`, and allowlisted
`MultiSendCallOnly` batches. Numeric kind 3 and its wire position are frozen;
current APIs call it the native CoW order trailer.

## CoW order trailer (kind 3)

```text
canonical GPv2Order                      204 bytes
[sell_bundle_len:u16 BE | sell_bundle]   optional
[buy_bundle_len:u16 BE  | buy_bundle]    optional
```

- Total length is `204..=2448` bytes.
- Each ERC-20 bundle is at most 1120 bytes.
- The bare 204-byte canonical is valid. Without metadata, the device displays
  the exact token contract and raw 256-bit amount for each leg.
- A verified `(chain, token)` bundle adds authenticated symbol/decimals for its
  own leg only. Missing, invalid, or mismatched metadata cannot label another
  token and degrades that leg to the exact-address/raw-amount presentation.
- Every non-native leg displays its full 20-byte contract even when metadata is
  valid. Metadata improves readability; it never replaces token identity.

Firmware natively recomputes the GPv2Order EIP-712 digest and
binds it to `orderUid`, `validTo`, the owner, the calldata shape, and
`signed == true`.

## Direct CoW

For a direct `GPv2Settlement.setPreSignature(orderUid, true)` call, attach one
kind-3 trailer to the same transaction. The full render is ten pages: two
context pages plus the shared eight-page order body. Page overflow refuses.

## Safe binding

The CoW `orderUid.owner` is the Safe, because the Safe will be the settlement
caller.

- Safe `approveHash(bytes32)` requires a valid kind-4 `safe_v1` payload:
  `canonical SafeTx[281] || raw_data_len:u16 BE || raw_data`. The outer hash,
  canonical fields, and raw data are recomputed and cross-checked in secure
  world.
- A decoded Safe `execTransaction` does not carry a kind-4 trailer; its full
  canonical fields are already present in the signed calldata and are decoded
  directly.
- Invalid or unverified Safe trailer bytes grant no ERC-20 metadata authority
  and are never scanned for nested token targets.

The order trailer is verified only after the Safe context is resolved. The
same order-body renderer is used for direct, Safe, and batch paths.

## MultiSendCallOnly batches

Only `operation=1` against one of the four firmware-pinned canonical
`MultiSendCallOnly` deployments (v1.3.0 canonical `0x40A2…130D`, v1.3.0 eip155
`0xA1da…102B`, v1.4.1 `0x9641…02e2`, v1.5.0 `0xA83c…1836`) is accepted as the
Safe UI batch shape. The packed records must be canonical, each record must use
`op=0`, no record may target `0x0` (`msend rec to=0`), and there may be at most
six records.

UPDATE 2026-09-23: v1.5.0 added (Safe 1.5.0 wallets route batches through it).
Its record loop rewrites `to == 0x0` to `address(this)` — the Safe itself under
the outer DELEGATECALL — so the firmware refuses zero-`to` records for every
target; the revm differential runs against both the v1.3.0 and v1.5.0
bytecode.

For a CoW presign record, attach kind 3 (and kind 4 only when the outer Safe
route is `approveHash`) to the same batch `tx_idx`. The usual Safe UI flow is an
ERC-20 approval record followed by the presign record. Metadata is usable only
for the verified Safe direct target or for a target found inside this already
verified, pinned MultiSend context.

The complete confirmation is capped at 31 pages. Malformed framing, a record
delegatecall, a non-allowlisted outer delegatecall, a mismatched order, a
known/Bloom-positive opaque record without authenticated semantics, or page
overflow refuses the whole sign. An `operation=0` CALL to a MultiSend address
uses the generic ladder only when its exact tuple is genuinely absent from the
firmware known-call filter; it is not an unconditional blind-sign route.

## Batch TLV framing

```text
trailer_count:u8
repeat trailer_count times:
    kind:u8 | tx_idx:u8 | len:u16 BE | payload[len]
```

Relevant kinds are 1 (ERC-20 metadata), 3 (native CoW canonical), 4 (Safe v1),
7 (ERC-7730), and 8 (batch-wide names). The firmware rejects duplicate or
mutually-exclusive records and enforces per-kind and aggregate length caps.

## Failure contract

- Invalid canonical/order binding: refuse, no signature.
- Missing/mismatched optional leg metadata: render that leg by exact address
  and raw amount; never borrow another token's metadata.
- Missing required Safe context or wrong `orderUid.owner`: refuse.
- Known opaque call without its required authenticated semantics: refuse.
- Genuinely unknown opaque call: loud generic display may be offered.

The status text may still say `CoW sign / v3 required`; “v3” denotes the frozen
wire generation.
