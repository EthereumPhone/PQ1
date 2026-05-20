# Batch-sign trailer parity — extension migration guide

> Delta against `companion-batch-sign-integration.md`. Read that first
> for the full v2 wire format; this doc is the "what you need to change
> in the extension and why" companion.

## The bug we just fixed

Batch sign rendered `! Unknown token` for any inner tx that needed
clear-signing metadata (USDC `approve` on Base, Lido `submit`, etc.).
Root cause: pre-parity, `CMD_SIGN_USEROP_BATCH` only accepted a single
optional ERC-7730 trailer at the tail of the payload. Every other
clear-signing kind the single-tx path consumes — ERC-20 metadata, ZK
v1, ZK v3 CoW, Safe v1, selector curated, selector self-attest, name
bundles — was silently dropped, so the firmware fell through the
priority ladder to the unsigned `render_erc20_unknown_pages` renderer.

Worse, the batch path also missed the **downgrade-mitigation gates**
that refuse to sign a CoW `setPreSignature` without a verified ZK v3
trailer, or a Safe `approveHash` without a verified Safe v1 trailer.
A hostile NS could strip those trailers and coerce blind-signing.

## What changed in the firmware

1. **Wire-version byte at offset 276 of the batch header.** Old layout
   placed `batch_count` there; new layout inserts a `wire_version` byte
   set to `2` and shifts `batch_count` to offset 277. Firmware refuses
   any payload where `wire_version != SIGN_USEROP_BATCH_WIRE_VERSION`.
2. **TLV-tagged trailer list** replaces the single ERC-7730 slot.
   Records carry `(kind, tx_idx, len, bytes)`; eight kinds map 1:1 to
   the single-tx trailer surface; per-tx routing is explicit (companion
   declares which inner tx a trailer binds to via `tx_idx`).
3. **Per-tx downgrade gates** mirroring single-tx: CoW v3 mandatory
   when calldata is `setPreSignature` on GPv2 settlement; Safe v1
   mandatory when calldata is `approveHash(bytes32)`.
4. **FI hardening parity:** flags double-parse at handler entry,
   trailer count double-read, `(kind, tx_idx)` re-validation,
   per-verifier `wait_random + check_true_into_sentinel` envelope.
5. **Hard cutover.** No fallback path — old companions sending v1
   layouts get rejected with `InvalidPointer / "bad wire_version"`.

## What the extension needs to change

Three files in
`~/Documents/PQ1/AmbireExtension/src/web/modules/hardware-wallet/libs/pq1/`:

### 1. `config.ts` — new constants

Already landed in this branch:

```ts
export const SIGN_USEROP_BATCH_WIRE_VERSION = 2

export const TRAILER_KIND_ERC20         = 1
export const TRAILER_KIND_ZK_V1         = 2
export const TRAILER_KIND_ZK_V3         = 3
export const TRAILER_KIND_SAFE_V1       = 4
export const TRAILER_KIND_SEL_CURATED   = 5
export const TRAILER_KIND_SEL_SELFATTEST = 6
export const TRAILER_KIND_ERC7730       = 7
export const TRAILER_KIND_NAME          = 8

export const TRAILER_TX_IDX_BATCH_WIDE  = 0xff
export const MAX_TRAILERS_PER_BATCH     = 32
export const TRAILERS_TOTAL_MAX_LEN     = 24 * 1024
export const MAX_NAME_BUNDLES           = 4
```

### 2. `transport/signRequest.ts` — new `BatchInnerCall` shape

`BatchSignRequestParams.calls` is now `BatchInnerCall[]`:

```ts
export type BatchInnerCall = {
  to: `0x${string}`
  value: bigint | number | string
  data?: Uint8Array

  // Per-call optional trailers — every kind the single-tx path
  // accepts. Attach the one(s) you want clear-signed for this call.
  erc20Bundle?:      Uint8Array    // kind 1 — token metadata
  zkBundle?:         Uint8Array    // kind 2 — ZK v1 clear-sign
  zkV3Bundle?:       Uint8Array    // kind 3 — ZK v3 CoW (mandatory for setPreSig)
  safeV1Bundle?:     Uint8Array    // kind 4 — Safe approveHash (mandatory for approveHash calldata)
  selectorBundle?:   Uint8Array    // kind 5 — curated selector → text-sig
  selfAttestBundle?: Uint8Array    // kind 6 — self-attest selector (mutually exclusive with kind 5)
  erc7730Bundle?:    Uint8Array    // kind 7 — ERC-7730 descriptor
}

export type BatchSignRequestParams = /* … existing … */ & {
  calls: BatchInnerCall[]
  nameBundles?: Uint8Array[]       // kind 8 — batch-wide, ≤ 4
}
```

`buildSignBatchPayload` was rewritten to emit v2 — already done in this
branch's edit. The encoder:

* Inserts `wire_version=2` at offset 276 of the header.
* Walks `calls`, emitting per-call inner-tx blocks as before.
* Collects per-call optional trailers + batch-wide names into a flat
  TLV record list, emits `[u8 count]` then `[u8 kind, u8 tx_idx, u16 BE len, bytes]*`.
* Enforces every cap client-side (per-kind length, total bytes,
  mutual exclusion, record count, name-bundle count).

### 3. Caller sites — attach trailers per call

The actual leverage point for fixing the demo. Wherever the extension
today calls `buildSignBatchPayload`, attach the bundle alongside the
matching inner call. For the USDC-approve case:

```ts
const payload = buildSignBatchPayload({
  ...batchParams,
  calls: [
    {
      to: USDC_BASE_ADDRESS,
      value: 0n,
      data: approveCalldata,
      // attach the ERC-20 metadata bundle so the firmware renders
      // "Approve <amount> USDC" instead of "! Unknown token".
      erc20Bundle: lookupErc20Bundle({ chainId: 8453, contract: USDC_BASE_ADDRESS }),
    },
    {
      to: uniswapRouter,
      value: 0n,
      data: exactInputSingleCalldata,
      // ERC-7730 descriptor for Uniswap V3 swap clear-signing
      erc7730Bundle: lookupErc7730Bundle({ chainId: 8453, contract: uniswapRouter }),
    },
    {
      to: anotherTarget,
      value: 0n,
      data: someCalldata,
    },
  ],
})
```

The firmware verifies each bundle, FI-cross-checks the `(chain_id, to)`
binding, and routes the verified output into `pick_sign_pages` for
that inner tx only.

## Routing semantics — quick reference

| `kind` | Binds to | Failure behaviour |
|-------:|----------|-------------------|
| 1 ERC-20 | inner tx at `tx_idx`; `meta.contract == call.to` | drop silently; "Unknown token" page |
| 2 ZK v1 | inner tx at `tx_idx`; calldata-prefix bound | drop silently |
| 3 ZK v3 | inner tx at `tx_idx`; sentinel + chain bound | **refuse if downgrade gate fires** |
| 4 Safe v1 | inner tx at `tx_idx`; Safe addr + EIP-712 bound | **refuse if downgrade gate fires** |
| 5 Selector curated | inner tx at `tx_idx`; `meta.selector == data[..4]` | drop silently |
| 6 Selector self-attest | same; mutually exclusive with kind 5 per `tx_idx` | drop silently |
| 7 ERC-7730 | inner tx at `tx_idx`; `(chain_id, contract)` bound | drop silently; falls through ladder |
| 8 Name | batch-wide (`tx_idx = 0xff`); resolver keyed on `(chain_id, address)` | drop silently |

## Per-kind length caps (client-side enforcement)

Mirrors the firmware's `MAX_LEN_PER_KIND` table. The encoder refuses
client-side so the firmware never sees a malformed payload. Bundle
sizes are bounded by the bundle's own format — companion catalog
lookups should always emit something within cap.

| Kind | Max bytes |
|------|----------:|
| 1 ERC-20         | 1120 |
| 2 ZK v1          | 2660 |
| 3 ZK v3          | 2764 |
| 4 Safe v1        | 4379 |
| 5 Sel curated    | 1156 |
| 6 Sel self-attest|   68 |
| 7 ERC-7730       | 5130 |
| 8 Name           | 1156 |

Aggregate cap: `Σ len ≤ TRAILERS_TOTAL_MAX_LEN (24 576 B)`.
Per-batch record count: `≤ MAX_TRAILERS_PER_BATCH (32)`.

## Downgrade-mitigation gates — what the extension must guarantee

Two cases where the firmware refuses to sign the entire batch unless
the matching trailer is routed:

* **CoW v3 `setPreSignature`.** If `call.data[0..4] == 0xec6cb13f` AND
  `call.to == GPV2_SETTLEMENT_ADDRESS` AND no `zkV3Bundle` is routed
  to that call, the firmware aborts with `InvalidPointer / "CoW sign: v3 required (batch)"`.
* **Safe `approveHash`.** If `call.data[0..4] == 0xd4d9bdcd` AND
  `call.data.length == 36` AND no `safeV1Bundle` is routed, the
  firmware aborts with `InvalidPointer / "Safe sign: safe_v1 required (batch)"`.

The extension's batch builder should refuse to send a payload that
omits the mandatory trailer — better to fail fast at the keystroke
than at the device.

## Device-version handshake

Firmware advertises `protocol_version` via `INS_GET_DEVICE_INFO`. The
extension should:

1. Read the device protocol version at session start (once per device).
2. Refuse to send batch sign payloads if the device version is below
   the v2 cutover. Show a clear "device firmware requires update for
   batch signing" message.

This prevents users on stale firmware from seeing opaque
`InvalidPointer / bad wire_version` rejections.

## Verifying the fix locally

After building both worlds (`make secure && make nonsecure`) and
deploying to a board:

1. Single-tx USDC approve on Base — already works, should keep
   rendering "Approve <amount> USDC".
2. Batch with USDC approve as inner tx 0 (with `erc20Bundle` attached)
   plus two other inner txs — should now render `Approve <amount>
   USDC` on inner tx 0 instead of `! Unknown token`.
3. Same batch with the `erc20Bundle` omitted — should render
   `! Unknown token` (the gate isn't triggered for ERC-20; only CoW
   v3 and Safe v1 are mandatory).
4. Batch with a CoW `setPreSignature` inner tx but no `zkV3Bundle` —
   firmware aborts with `InvalidPointer` and the OLED shows
   `CoW sign: v3 required (batch)`.

## Files touched in this branch

Firmware side:

* `proto/src/lib.rs` — wire constants (version byte, kind enum, caps).
* `secure/src/nsc/batch_trailers.rs` — new TLV parser.
* `secure/src/nsc/cmd_sign_userop_batch.rs` — handler integration.
* `nonsecure/src/e2e_test.rs::build_batch_payload` — emits v2.
* `docs/companion-batch-sign-integration.md` — wire-format reference.

Companion side
(`~/Documents/PQ1/AmbireExtension/src/web/modules/hardware-wallet/libs/pq1/`):

* `config.ts` — new constants.
* `transport/signRequest.ts` — `BatchInnerCall` type + v2 encoder.

Caller sites in the extension that today build a batch payload need
to be threaded through with per-call trailers; the encoder itself is
already done.
