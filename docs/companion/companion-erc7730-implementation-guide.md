# Companion App / Extension Guide — Make Clear Signing Actually Work

This is the **canonical, single-source-of-truth implementation guide**
for any companion that wants to make ERC-7730 clear signing work
end-to-end against the current PQSigner OS `master` line. Production remains
blocked by the independent firmware-rollback and ERC-7730 provenance gates.

It is the doc to follow if you're building:

- A browser extension (MetaMask-style) that talks to PQSigner over
  WebHID and proxies dapp `eth_sendTransaction` /
  `eth_signTypedData_v4` / `personal_sign` requests.
- A native companion (Electron / Tauri / mobile WebUSB) that does
  the same.
- An RPC bridge that batches sign requests for a server-side signer.

Wire v2 is the frozen format for the flows that it currently supports. It
intentionally cannot complete seedless slot rotation; that needs the reviewed,
versioned response extension described in §7.5. Firmware provenance and rollback
gates also remain, so this is not a claim that only companion-side code is
missing. This guide is normative. The similarly named documents below are
redirects or historical provenance, not additional implementation specs:

- `docs/companion/erc7730-integration.md` — short current-status redirect and
  code-source map; it intentionally does not duplicate the wire format.
- `docs/archive/companion-erc7730-integration.md` — earlier draft,
  narrower scope; **folded into this guide and archived** 2026-06-18
  (its two unique pitfalls — kind=2 for a contract-context descriptor,
  and the off-chain `flags` byte — are now §9 rows; its `E73D` catalog
  schema was superseded by §3's authoritative `P730` schema). Kept in
  `docs/archive/` for provenance only.

Read this top-to-bottom before writing code. Most pitfalls below were
discovered the hard way during bring-up; the order they appear is the
order they will bite you.

## Table of contents

1. [Mental model](#1-mental-model)
2. [What the companion must ship](#2-what-the-companion-must-ship)
3. [Catalog file format (`erc7730_db.bin`)](#3-catalog-file-format-erc7730_dbbin)
4. [Lookup algorithm](#4-lookup-algorithm)
5. [Bundle assembly](#5-bundle-assembly)
6. [Where the trailer goes in each command](#6-where-the-trailer-goes-in-each-command)
   - [6.1 CMD_SIGN_USEROP (0x30)](#61-cmd_sign_userop-0x30)
   - [6.2 CMD_SIGN_USEROP_BATCH (0x32)](#62-cmd_sign_userop_batch-0x32)
   - [6.3 CMD_SIGN_OFFCHAIN (0x62) — kind=2 EIP-712 typed](#63-cmd_sign_offchain-0x62--kind2-eip-712-typed)
   - [6.4 CMD_SIGN_OFFCHAIN — kind=0 / kind=1 fingerprint pages](#64-cmd_sign_offchain--kind0--kind1-fingerprint-pages)
   - [6.5 CMD_SIGN_OFFCHAIN — kind=3 EIP-712 typed with NESTED structs (Permit2 / UniswapX)](#65-cmd_sign_offchain--kind3-eip-712-typed-with-nested-structs-permit2--uniswapx)
7. [Worked examples](#7-worked-examples)
   - [7.1 USDT transfer on mainnet](#71-usdt-transfer-on-mainnet)
   - [7.2 USDT approve max (exact, not unlimited)](#72-usdt-approve-max-exact-not-unlimited)
   - [7.3 WETH deposit (zero-arg, value from envelope)](#73-weth-deposit-zero-arg-value-from-envelope)
   - [7.4 USDC TransferWithAuthorization (currently refused)](#74-usdc-transferwithauthorization-currently-refused)
   - [7.5 Batch signing and the current slot-rotation blocker](#75-batch-signing-and-the-current-slot-rotation-blocker)
   - [7.6 UniswapX orders (currently refused)](#76-uniswapx-orders-currently-refused)
   - [7.7 1inch aggregation calls (currently refused)](#77-1inch-aggregation-calls-currently-refused)
8. [Firmware response handling](#8-firmware-response-handling)
9. [Failure modes and how to test them](#9-failure-modes-and-how-to-test-them)
10. [Versioning and root rotation](#10-versioning-and-root-rotation)
11. [Pre-flight checklist before shipping](#11-pre-flight-checklist-before-shipping)
12. [Known bugs / blockers](#12-known-bugs--blockers)

## 1. Mental model

The firmware can blind-sign genuinely unknown calls that the user approves on
its own LCD. A firmware-known ERC-7730 call is different: its
`(chain_id, contract, selector)` is also committed into a pinned Bloom filter,
so the companion must supply the matching Merkle proof. **Clear signing
replaces raw calldata review with a human-readable rendering** ("Send 100 USDT
to alice.eth") whose correctness is anchored in the firmware-built catalogue.

There is exactly one trust transfer in this design: **the firmware
trusts the Merkle root**. Everything else flows from that:

- The root commits to a set of ERC-7730 descriptors that passed the host-side
  structural compiler policy. The current catalogue is explicitly
  `dev-unattested`: it has no ERC-8176 semantic/provenance authority and cannot
  enter a production build.
- During pre-production bring-up, the companion ships the same descriptor set
  as a `*.bin` blob and pins the expected root out of band to the exact
  development firmware build (`secure/src/db_roots.rs`). There is no separately
  authenticated release-metadata channel or root-reporting command today.
  Signed release metadata is the intended post-quarantine mechanism (§10), not
  a current security boundary.
- For each sign request, the companion picks the matching descriptor,
  produces a Merkle proof against the root, and ships it in the trailer slot.
  The slot is optional in the wire grammar. A firmware-known tuple requires
  independently authenticated semantics: normally the exactly bound
  descriptor; the narrow Safe exception is strict native ERC-20 decoding with
  exact chain/contract-bound Merkle metadata, re-attributed to the direct call
  or individual MultiSend record.
- The firmware re-verifies the proof and binds a contract descriptor via exact
  `(chain_id, to_address)`. For EIP-712 it binds exact
  `(chain_id, domain_separator)`, then selects the authenticated format by the
  complete 32-byte `primary_type_hash`. The descriptor compiler folded the
  deployment `verifyingContract` into that exact domain separator; firmware does
  not receive a second independent contract field on this path.

If the companion supplies neither an exactly bound descriptor nor the narrow
authenticated Safe ERC-20 capability, a firmware-known call **hard-refuses**
with `"7730 proof needed"`; it never downgrades that tuple to typed or blind
signing. Direct non-Safe known calls still require the descriptor. Only a tuple
absent from the pinned membership filter may use the generic display ladder.
Bloom false positives can refuse an otherwise-unknown call, which is the safe
failure direction.

ERC-20 metadata is a scoped capability, not a global fact. Handler verification
establishes only Merkle membership plus chain binding; final use must also match
the signed surface: the direct ERC-20 target, the exact ERC-7730 `tokenPath`, a
verified Safe direct target, or a record inside a verified pinned
`MultiSendCallOnly` batch. Raw or invalid Safe trailer bytes are never scanned
for authority. A bound non-native scalar `tokenAmount`, token array, or
`tokenTicker` always adds a full contract-address page even when symbol and
decimals authenticate successfully. If that injective identity page does not
fit, rendering refuses rather than omitting it.

`tokenAmount.nativeCurrencyAddress` accepts the registry's scalar or array
form. IR tag `0x42` keeps the scalar encoding byte-identical at 20 bytes and
encodes the current registry-complete list as two descriptor-order 20-byte
addresses. Empty, duplicate, malformed, or longer lists are compiler- and
device-rejected; no entry is truncated. Only an exact member match uses the
chain-pinned native ticker/scale. A miss remains an ERC-20 candidate and, when
metadata cannot bind it, renders the exact raw amount plus the full
`Token (UNVERIFIED)` address page.

`nftName` likewise carries injective collection identity. IR tag `0x44` binds
a literal 20-byte collection and `0x45` binds a compiled static-address path;
exactly one is required. Only the frozen `@.to` envelope field is accepted as a
container-root path, so an ABI argument named `to` cannot shadow it. The device
always shows the exact token ID and complete collection address. A friendly
name is additional display metadata: descriptor `contractName` applies only to
the authenticated descriptor contract, while any external collection requires
an exact `(chain, address)` lookup. Wildcard names never qualify.

<!-- BEGIN XTASK-VERIFIED ERC7730 SEMANTIC CONTRACT -->
### Device semantic manifest (generated)

- The host compiler and device require **IR schema v5 (`0x05`)**; this value is generated from `pqsigner_erc7730::ir::SCHEMA_VER`, and older schemas hard-refuse.
- Schema v5 authenticates every `uintN`/`intN` width as `1..=32` bytes. Before any trusted ERC-7730 page is published, the device requires exact ABI zero extension for `uintN` and sign extension for `intN`; full-width `uint256`/`int256` retain every 32-byte word unchanged.

| Wire opcode | Registry `format` | Device route |
|------------:|-------------------|--------------|
| `0x01` | `raw` | implemented renderer (fail closed on invalid input) |
| `0x02` | `amount` | implemented renderer (fail closed on invalid input) |
| `0x03` | `tokenAmount` | implemented renderer (fail closed on invalid input) |
| `0x04` | `nftName` | implemented renderer (fail closed on invalid input) |
| `0x05` | `date` | implemented renderer (fail closed on invalid input) |
| `0x06` | `duration` | implemented renderer (fail closed on invalid input) |
| `0x07` | `addressName` | implemented renderer (fail closed on invalid input) |
| `0x08` | `enum` | implemented renderer (fail closed on invalid input) |
| `0x09` | `unit` | implemented renderer (fail closed on invalid input) |
| `0x0A` | `calldata` | hard refusal (nested calldata unsupported) |
| `0x0B` | `chainId` | implemented renderer (fail closed on invalid input) |
| `0x0C` | `tokenTicker` | implemented renderer (fail closed on invalid input) |
| `0x0D` | `interoperableAddressName` | implemented renderer (fail closed on invalid input) |
| `0x0E` | `encrypted` | hard refusal (signed operand hidden) |

- For a verified, request-bound descriptor, **every `RenderErr` variant is a hard refusal** through an exhaustive production match. A new variant cannot compile until it receives that policy; no variant authorizes typed-call, selector-label, or blind-sign fallback.
- ERC-8213 is mandatory and atomic for every companion/dapp-supplied signed payload: exactly 2 pages (banner + hash) surface the complete 32-byte digest at 8 bytes per display row. If both pages do not fit, the signing caller refuses; it never leaves an orphan banner or signs without the complete hash. The sole current exemption is the firmware-constructed Type-1 slot-rotation operation: its calldata combines firmware constants with seed-derived slot-owner material that is intentionally unavailable before the rotation consent boundary, so that dialog instead renders the complete slot index and bootstrap-use consequence.
- Confirmation transcripts use the pinned append-only order. A single UserOp shows renderer pages first; the dispatcher may append native-value/legacy-fee pages, then the handler appends paymaster (when present), signer, target, non-zero nonce lane, exact UserOp gas and ERC-8213 fingerprint pages. When `FLAG_INCLUDE_INIT_CODE` is set, one final `DEPLOY FACTORY:` page shows the complete factory address; the ordinary path proves that page was skipped. A batch member prepends its exact `BATCH SIGN / Tx i of N` banner to the renderer/dispatcher pages, then appends signer, target, nonce lane, gas and fingerprint pages. The batch-final summary appends paymaster, signer, nonce lane, gas, the whole-batch fingerprint, and the same conditional deployment page. A full buffer refuses; no mandatory page is inserted by shifting or overwriting an earlier page.
<!-- END XTASK-VERIFIED ERC7730 SEMANTIC CONTRACT -->

## 2. What the companion must ship

Three things in the companion bundle:

1. **The catalog blob** at `tools/companion-stub/erc7730_db.bin`
   produced by `cargo run -p dbgen` from the vendored registry corpus,
   `secure/data/erc7730/policy.toml`, and the reviewed in-place curations
   recorded by the registry rotation policy. It is not built from the small
   hand-authored seed corpus used by older bring-up snapshots.

   <!-- BEGIN XTASK-VERIFIED ERC7730 CATALOGUE SUMMARY -->
   - Development catalogue: 366,361 B, 437 compiled leaves, 4,544
     exact registry-declared known-call tuples, provenance `dev-unattested`.
     The tuple-set SHA-256 receipt is
     `593a8c77ccb5323cdd2fc2830af32916722dfc3fb570aa33ca94b7fcdf8dd781`.
   - E2E fixture: 3,968 B, 8 compiled leaves.
   <!-- END XTASK-VERIFIED ERC7730 CATALOGUE SUMMARY -->

   The blob does **not** embed its Merkle root. Bytes 0..31 are the catalogue
   header. For the current development line, pin the blob and expected root out
   of band to the exact firmware build, or independently recompute the tree
   root. Do not claim signed release-metadata authentication until the
   post-quarantine release flow in §10 exists, and never interpret the header
   as a root.

2. **A descriptor lookup function** keyed on `(chain_id, contract)` for
   contract calls, and on `(chain_id, verifying_contract,
   domain_separator, full_primary_type_hash)` for EIP-712. See §4.

3. **A bundle assembler** that produces the exact inner byte layout the
   firmware's `verify_erc7730_bundle` consumes; the command encoder adds
   exactly one length frame. See §5.

You can copy the executable Python reference at
`tools/companion-stub/erc7730_trailer.py`, or port its selection and assembly
rules directly to TypeScript / Rust / Swift. Always pass the expected context:
use `--context contract` for calldata/UserOp lookup. Typed-data lookup requires
both `--context eip712 --domain-separator 0x<64 hex>` and
`--primary-type-hash 0x<64 hex>`. The helper parses every candidate's
authenticated IR and matches both complete 32-byte values. The catalogue
entry's diagnostic hash may contain only the first surviving format in a
multi-format IR; never filter by that hint or fall back to the first
`(chain, contract)` match.

## 3. Catalog file format (`erc7730_db.bin`)

```
offset  size  field
---------------------------------------------------------
  0      4    magic                "P730"  (ASCII)
  4      4    version              u32 LE (currently 1)
  8      4    flags                u32 LE (currently 0)
 12      4    entry_cnt            u32 LE
 16      4    ir_pool_off          u32 LE
 20      4    ir_pool_size         u32 LE
 24      4    proof_depth          u32 LE
 28      4    proofs_off           u32 LE

 32    72×N    entries[N]           (one 72-byte record per leaf):
                  chain_id           u64 LE
                  contract           [u8; 20]
                  primary_type_hash  [u8; 32]  (first-surviving-format hint;
                                                zero for contract-context)
                  context_kind       u8        (1 = CTX_CONTRACT,
                                                2 = CTX_EIP712)
                  _pad               [u8; 3]   (all zero)
                  ir_off             u32 LE    (offset into IR pool)
                  ir_len             u32 LE

 ir_pool_off    IR pool bytes        (concatenated IR records)
 proofs_off     proof pool bytes     (entry_cnt × proof_depth × 32 bytes,
                                      laid out in leaf-index order)
```

`leaf_index` is the entry's array position; it is not stored in the entry.
There is no root field anywhere in this blob.

Endian note: this file is **little-endian** because it's produced by a
host-side tool and consumed only by other host-side tools (the
companion). The on-the-wire trailer flips to **big-endian** because
that's what the firmware verifier expects (matches every other
on-device protocol field in PQSigner OS).

Sanity-check at companion startup:

- `magic == "P730"`
- `version == 1`
- `flags == 0`
- `entry_cnt ≥ 1`
- `proof_depth ≤ 32` (firmware `ERC7730_PROOF_MAX_DEPTH`)
- `ir_pool_off == 32 + entry_cnt * 72`
- `ir_pool_off + ir_pool_size == proofs_off`
- File size == `proofs_off + entry_cnt * proof_depth * 32` (trailing bytes are
  non-canonical and rejected)
- Every entry has a supported context kind, three zero reserved bytes, and a
  non-empty in-bounds IR slice; validate the IR header and complete format table
  before using its lookup fields
- The separately supplied/recomputed expected root is pinned to the exact
  firmware release. No current gateway command reports the root; such an API is
  a roadmap item, not an available startup check.

If any of these fail, treat the catalogue/firmware pair as incompatible and
stop known-call signing until the companion data is repaired or updated.
Disabling trailers is not a compatibility fallback: firmware-known calls will
refuse by design. Genuinely unknown calls may still use the generic ladder.

## 4. Lookup algorithm

For a UserOp on chain `chain_id` calling contract `to`:

```pseudo
entry = entries.find(e =>
  e.context_kind == CTX_CONTRACT
  && e.chain_id == chain_id
  && e.contract == to)
```

For an EIP-712 typed-data sign whose canonical message is:

```
domain         = { name, version, chainId, verifyingContract, ?salt }
primaryType    = "TransferWithAuthorization"
message        = { from, to, value, ... }
```

```pseudo
domain_separator = keccak256(
  encodeData("EIP712Domain", domain, present_domain_fields)
)
primary_type_hash = keccak256(encodeType(primaryType, types))

candidates = entries.filter(e =>
  e.context_kind == CTX_EIP712
  && e.chain_id == chainId
  && e.contract == verifyingContract)

entry = candidates.find(e => {
  ir = parse_and_validate_complete_ir(e)
  return ir.domain_separator == domain_separator
    && ir.formats.any(f => f.full_type_hash == primary_type_hash)
})
```

Notes:

- `encodeType` recursively appends referenced struct definitions in canonical
  alphabetical order. `encodeData` hashes dynamic `string`/`bytes`, arrays,
  and nested structs according to EIP-712 before placing their 32-byte words.
  Use only domain fields actually present in the request, in the standard
  EIP-712 field order, and require `chainId` plus `verifyingContract` to equal
  the requested deployment. Do not accept a companion-supplied precomputed
  separator without independently recomputing it from the typed-data domain.
- The four-byte prefix can narrow runtime format candidates, but the firmware
  constant-time compares the complete 32-byte `primary_type_hash` before
  rendering. A prefix or entry-level-hint match grants no display authority.
- A descriptor with two formats (e.g. tokens with both
  `Permit` and `TransferWithAuthorization`) appears as ONE catalog
  entry per `(chain_id, contract)` — the format-table-walk inside the
  on-device IR resolves which format applies. So for EIP-712, your
  match starts with `(chain_id, verifyingContract)` and the firmware does the
  full-hash per-primaryType dispatch inside the authenticated IR. The catalog
  entry's `primary_type_hash` carries the **first surviving** compiled format's hash for
  sorting/diagnostics; it is not a sufficient security decision for a
  multi-format descriptor.
- On a compiled-catalogue miss, do not infer that the firmware considers the
  call unknown. Its pinned known-call Bloom filter includes raw declarations
  that were rejected or omitted from the compiled catalogue. Pair/version that
  filter with the companion release, or surface the firmware's fail-closed
  refusal; never retry a refused call without a proof as a downgrade.

## 5. Bundle assembly

Build the **inner ERC-7730 bundle** first. Each command then places that bundle
in exactly one command-specific `[u16 BE len][payload]` slot. Do not prefix it
here and then add another length at the command site. The bundle is what
`pqsigner_erc7730::bundle::verify_erc7730_bundle`
parses byte-for-byte:

```
bundle =
  u16_be(ir_len)
  || ir[ir_len]
  || u32_be(leaf_index)
  || u32_be(proof_depth)
  || proof[proof_depth * 32]
```

Where:

- `ir` is the IR bytes for the entry (extracted from
  `erc7730_db.bin[ir_pool_off + e.ir_off .. + e.ir_len]`).
- `leaf_index` is the entry's zero-based array position in `entries[]`. It is
  implicit and is not stored in either the catalogue header or the 72-byte
  entry record; assign it while parsing the array.
- `proof_depth` is the catalog's `proof_depth` value (same for every
  leaf).
- `proof` is the entry's proof, extracted from
  `erc7730_db.bin[proofs_off + leaf_index * proof_depth * 32 ..
   + proof_depth * 32]`.

Trailer size bounds:

- `ir_len` ≤ 4096 (firmware `ERC7730_IR_MAX`)
- `proof_depth` ≤ 32
- Total bundle ≤ 4096 + 10 + 32 × 32 = 5130 (firmware
  `ERC7730_MAX_TRAILER_LEN`)

If your assembled bundle is longer than 5130 B, you've packed the
wrong thing — re-check `ir_len` against the catalog entry.

TypeScript reference (≈ 30 lines):

```typescript
function assembleErc7730Bundle(blob: Uint8Array, entry: CatalogEntry): Uint8Array {
  const proofDepth = readU32LE(blob, 24);
  const proofsOff  = readU32LE(blob, 28);
  const irPoolOff  = readU32LE(blob, 16);

  const ir = blob.subarray(irPoolOff + entry.irOff, irPoolOff + entry.irOff + entry.irLen);
  const proofBase = proofsOff + entry.leafIndex * proofDepth * 32;
  const proof = blob.subarray(proofBase, proofBase + proofDepth * 32);

  const bundleLen = 2 + ir.length + 4 + 4 + proof.length;
  const bundle = new Uint8Array(bundleLen);
  let p = 0;
  writeU16BE(bundle, p, ir.length); p += 2;
  bundle.set(ir, p); p += ir.length;
  writeU32BE(bundle, p, entry.leafIndex); p += 4;
  writeU32BE(bundle, p, proofDepth); p += 4;
  bundle.set(proof, p);

  return bundle;
}
```

## 6. Where the trailer goes in each command

This is the part most companions get wrong on the first try, because
each of the three sign commands has a different trailer position. The
single and off-chain layouts use fixed positional slots. Batch is the explicit
exception: it carries a counted TLV list keyed by `(tx_idx, kind)`. Never apply
the single-command positional parser to the batch tail.

### 6.1 CMD_SIGN_USEROP (0x30)

The unified Type 1 / Type 2 sign command. Header is 330 fixed bytes
(see `docs/companion/usb-protocol-v2.md §0x30`); after the inner calldata, a
chain of optional trailers follows. All trailers use the same `[u16
BE len][payload]` framing; absent trailers go in as `[u16 BE 0]`.

The trailer chain in order, with the ERC-7730 trailer slot
**bolded**:

```
sign_userop_payload =
    base_header[330]
 || data[data_len]                                       // inner calldata
 || u16_be(erc20_bundle_len)         || erc20_bundle     // optional
 || u16_be(reserved_v1_len)                               // reserved; MUST be 0
 || u16_be(cow_order_bundle_len)         || cow_order_bundle     // optional
 || u16_be(safe_v1_bundle_len)       || safe_v1_bundle   // optional
 || u16_be(selector_bundle_len)      || selector_bundle  // optional
 || u16_be(self_attest_bundle_len)   || self_attest      // optional
 || **u16_be(erc7730_bundle_len)     || erc7730_bundle** // wire-optional; mandatory for direct/non-exempt known calls
 || names_section                                        // 1-B count + bundles
```

If the companion sends nothing for slot N but a non-empty slot N+1,
slot N MUST still be `[u16 BE 0]`. There is no "skip" — the parser
walks the chain sequentially.

If the companion has no `u16` trailers and no names to attach, the chain
collapses to end-of-payload immediately after calldata:

```
sign_userop_payload = base_header[330] || data[data_len]
```

All seven `u16_be(...)` slots and the names count are omitted in this
shorthand. The parser defines `cursor == total_len` as an empty names set; an
explicit trailing `0x00` is rejected as trailing data because the zero-count
path does not consume a byte. A non-empty names section MUST NOT use the
shorthand: emit all seven preceding trailer slots explicitly as `[u16 BE 0]`,
then the non-zero names count and its bundles. Otherwise the first names bytes
are consumed as an earlier positional trailer.

That zero-trailer form is signable only for tuples absent from the
firmware-paired known-call filter. It is not a way to opt out of clear-signing
for a compiled descriptor.

**Important:** a non-empty `names_section` after the last trailer is
`[u8 count][bundle_0 ... bundle_{count-1}]`, `1 ≤ count ≤ 4`, each bundle
`[u16 BE len][payload]`. If there are no names, end the payload after the last
present trailer; do not append a zero count byte. When `count > 0`, the seven
earlier `u16` slots must all be present (zero-length where unused) before the
names count.

### 6.2 CMD_SIGN_USEROP_BATCH (0x32)

The atomic multi-UserOp sign command uses the wire-v2 TLV trailer list described
in [`companion-batch-sign-integration.md`](companion-batch-sign-integration.md).
Attach one kind-7 `TRAILER_KIND_ERC7730` record per matching member, with that
member's `tx_idx`. Every firmware-known member needs its own verified proof;
omitting any one aborts the whole atomic batch. Emit a zero `trailer_count` byte
only when the batch has no trailer of any kind; ERC-20, CoW, Safe, selector, or
name records still count even when no member has an ERC-7730 descriptor.

Wire tail (the full batch header and record layout is in the linked guide):

```
[u8 trailer_count]
[trailer_count × {
    u8 kind        // 7 = TRAILER_KIND_ERC7730
    u8 tx_idx
    u16_be(len)
    u8[len] payload
}]
```

The firmware cross-checks each kind-7 descriptor against the specifically
routed member's `(chain_id, to)`. A mismatched proof leaves that member without
a verified descriptor; if its exact selector tuple is firmware-known, dispatch
then refuses the whole batch.

### 6.3 CMD_SIGN_OFFCHAIN (0x62) — kind=2 EIP-712 typed

EIP-712 typed signs have their OWN dedicated payload shape — the
trailer is the LAST element, not interleaved with anything:

```
header[17] = u8(account) | u64_be(chain_id) | u32_be(slot) | u8(kind=2) | u16_be(payload_len) | u8(flags)
                                                                                             ^ bit 0 = account_deployed

payload =
    u16_be(1)                          // domain_sep_present (must be 1)
 || u8[32] domain_separator             // EIP-712 EIP712Domain hash
 || u8[32] primary_type_hash            // keccak256(encodeType(primaryType, types))
 || u16_be(encoded_data_len)            // ≤ 512 (MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN)
 || u8[encoded_data_len] encoded_data   // canonical EIP-712 encodeData body, without typeHash
 || u16_be(trailer_len)                 // ≤ 5130 (ERC7730_MAX_TRAILER_LEN)
 || u8[trailer_len] erc7730_bundle      // inner bundle (§5)
```

Constraints the firmware enforces:

- `domain_sep_present` must be `1`. The pre-EIP-712 codepath (sign
  the bare 32-byte `primaryType` hash without a domain) is rejected.
- `encoded_data` is the **struct body only**. Do NOT prepend
  `primary_type_hash` — the firmware concatenates it internally.
  Construct canonical EIP-712 `encodeData(primaryType, message, types)` and
  remove its leading type hash, or ABI-encode already-transformed member words.
  Plain `encodeAbiParameters(types, message)` is equivalent only for a flat
  struct of static scalar members. Dynamic `bytes`/`string`, structs, and
  arrays occupy their EIP-712 hash words, not ordinary ABI dynamic tails.
- `trailer_len > 0`. Sending kind=2 without a trailer fails with
  `"empty trailer"`. The kind=2 codepath has no blind-sign fallback
  inside the firmware — it expects clear-sign info or it bails.

If a dapp requested EIP-712 typed signing and no compatible descriptor exists,
return an unsupported/catalogue error. **Do not silently translate it to
`kind=0` (raw32) or `kind=1` (personal_sign)**: those are distinct user-visible
signature semantics and are not a fallback around a typed-data refusal. Use
kind 0/1 only when that is the operation the dapp actually requested and the
companion preserves the corresponding firmware-side replay-safe nesting.

This is currently a **companion policy, not a firmware-enforced equivalence
check**. The firmware cannot infer whether a 32-byte `RAW32` payload was
originally the final hash of a supported typed-data request. A hostile
companion can therefore suppress semantic pages by relabelling such a hash as
RAW32; the device warns `! BLIND RAW32` and shows the complete hash. Production
should disable RAW32 unless compatibility explicitly accepts that residual.

### 6.4 CMD_SIGN_OFFCHAIN — kind=0 / kind=1 fingerprint pages

For `kind=0` (raw32) and `kind=1` (personal_sign), no ERC-7730
trailer slot exists in the payload. The firmware renders fixed banner pages plus
a user-cross-check fingerprint: raw `H` for RAW32, or
`calldata_digest(message)` for PERSONAL_SIGN. These are deliberately not the
firmware-internal replay-safe nested digest that the C10 signature covers. No
companion-side clear-sign or names-bundle section exists for these kinds.
Appending bytes either makes RAW32 invalid or changes the PERSONAL_SIGN message.

### 6.5 CMD_SIGN_OFFCHAIN — kind=3 EIP-712 typed with NESTED structs (Permit2 / UniswapX)

Kind 3 is a wire capability, not proof that a named protocol is currently in
the compiled catalogue. The checked-in `secure/data/erc7730.review.txt` is
authoritative. At this snapshot the UniswapX order descriptors are rejected by
the strict all-signed-operands-visible policy, so companions must refuse them;
the framing below is retained for future safely-curated descriptors and tests.

Some EIP-712 messages have a **nested-struct member** — a struct (or an
array-of-struct) inside the signed struct. On-chain EIP-712 encodes each such
member as a single opaque word (`hashStruct` for a struct, `keccak(∥ hashStruct)`
for an array), so `encoded_data` alone can only show that 32-byte hash, not what
is inside. Permit2 `PermitSingle`/`PermitBatch`/`PermitTransferFrom` and all six
UniswapX order variants (`DutchOrder`, `ExclusiveDutchOrder`, `LimitOrder`,
`V2DutchOrder`, …) are of this shape.

**When to use kind=3:** iff the descriptor's format for this `primary_type_hash`
declares nested members — i.e. its pinned format header has
`nested_descent_count > 0`. (If it is `0`, use kind=2 §6.3; kind=3 with an empty
`nested_blob` also works but kind=2 is simpler.) A format that has nested members
MUST be signed via kind=3 — kind=2 provides no `nested_blob`, so the device finds
no record to bind the nested `hashStruct` word and declines the whole render.

The payload is kind=2's, with a `nested_blob` section inserted **between**
`encoded_data` and the trailer:

```
header[17] = u8(account) | u64_be(chain_id) | u32_be(slot) | u8(kind=3) | u16_be(payload_len) | u8(flags)

payload =
    u16_be(1)                          // domain_sep_present (must be 1)
 || u8[32] domain_separator
 || u8[32] primary_type_hash            // keccak256(encodeType(primaryType, types))
 || u16_be(encoded_data_len)            // ≤ 512
 || u8[encoded_data_len] encoded_data   // canonical EIP-712 encodeData body, without typeHash
 || u16_be(nested_blob_len)             // ≤ 2048 (MAX_OFFCHAIN_EIP712_NESTED_LEN); 0 if no nested member
 || u8[nested_blob_len] nested_blob     // DFS records, see below — DISPLAY-ONLY, not signed
 || u16_be(trailer_len)                 // ERC-7730 bundle (§5)
 || u8[trailer_len] erc7730_bundle
```

The **signed digest is UNCHANGED** — the firmware still signs
`keccak(0x1901 ∥ domain_separator ∥ keccak(primary_type_hash ∥ encoded_data))`.
The `nested_blob` feeds ONLY the on-device display binding, which proves the shown
nested content equals the opaque words already inside `encoded_data`. A wrong
`nested_blob` can therefore only cause a **decline**, never a wrong signature.

#### Building `nested_blob` — DFS record order

`nested_blob` is a **depth-first** concatenation of one record per nested descent
point, in the **exact order the device descends the descriptor's fields**. The
descent order is: walk the format's fields top-to-bottom; each nested-struct or
array-of-struct member is a descent point; recurse **into** a nested struct
depth-first (its own nested members' records come immediately after its record,
before the parent's later sibling records). This is deterministic and computable
from the descriptor alone — build your records by mirroring that walk.

Two record shapes, chosen by whether the member is an array:

```
single nested struct  (a struct member):
    u16_be(len) || u8[len] nested_ed              // len == member_count × 32

array-of-struct       (a T[] member):
    u16_be(elem_count)                            // 1..=6 (MAX_NESTED_ARRAY); 0 is REJECTED
 || u16_be(len) || u8[len] elem0_ed               // each len == member_count × 32
 || u16_be(len) || u8[len] elem1_ed
 || …                                             // elem_count records
```

- `nested_ed` (and each `elem_i_ed`) is the **EIP-712 `encodeData` of that nested
  struct** — exactly `member_count × 32` bytes, where `member_count` is the nested
  struct's OWN member count (from its EIP-712 type). It is the canonical EIP-712
  member-word encoding: `address`/`uintN`/`bytesN`/`bool` in their natural
  ABI word; a **dynamic** `bytes`/`string` member as its `keccak256(value)` word; a
  **nested struct** member as its `hashStruct` word; a **T[]** member as its
  `keccak(∥ hashStruct)` word. (Same rules as the on-chain `encodeData` — the device
  re-hashes it and checks `keccak(pinned_typeHash ∥ nested_ed)` equals the parent's
  committed word, so it must be byte-identical to what the contract would hash.)
- Include **every** member's word (shown or hidden) — `member_count` pins the length
  and the device hashes the whole record. Omitting the hidden words breaks the binding.
- Depth: a nested struct that itself has a nested member produces its own record,
  then recurses (its child's record follows). Up to `MAX_NESTED_DEPTH = 8`.

**Reconciliation the firmware enforces (get any of these wrong → decline):**
- exactly one record per pinned descent point (records consumed == `nested_descent_count`);
- the DFS cursor ends EXACTLY at `nested_blob_len` (no trailing/padding bytes);
- each `nested_ed` length == the pinned `member_count × 32`;
- `elem_count` in `1..=6`;
- the chained `keccak(typeHash ∥ ed) == committed word` at every level.

None of these is a security risk if wrong (the blob is display-only), but the order
will not clear-sign — so mirror the device's field-descent order precisely.

## 7. Worked examples

These examples assume:

- `chain_id = 1` (Ethereum mainnet).
- Wallet is already deployed (no `FLAG_INCLUDE_INIT_CODE`).
- Slot 0 is already registered (no `FLAG_REGISTER_SLOT`).
- `flags = 0` for the outer userop header.

### 7.1 USDT transfer on mainnet

Dapp request:

```javascript
eth_sendTransaction({
  from: walletAddr,
  to:   "0xdAC17F958D2ee523a2206206994597C13D831ec7",  // USDT mainnet
  value: "0x0",
  data: "0xa9059cbb" +                                  // transfer(address,uint256)
        "0000000000000000000000003333333333333333333333333333333333333333" +
        "0000000000000000000000000000000000000000000000000000000005f5e100",  // 100.00 USDT
})
```

Companion-side flow:

1. **Lookup.** Walk `entries[]`:
   ```
   find e where e.context_kind == 1 && e.chain_id == 1
              && e.contract == 0xdAC17F958D2ee523a2206206994597C13D831ec7
   ```
   Found: `registry/tether/calldata-usdt.json` mainnet entry.

2. **Assemble the inner bundle** per §5.

3. **Build the SIGN_USEROP payload:**
   ```
   header (330 B)
   data (68 B = 4-byte selector + 32-byte to + 32-byte amount)
   u16_be(0)         // erc20 (absent)
   u16_be(0)         // reserved compatibility slot (MUST be zero)
   u16_be(0)         // cow_order (absent)
   u16_be(0)         // safe_v1 (absent)
   u16_be(0)         // selector (absent)
   u16_be(0)         // self_attest (absent)
   u16_be(len) || erc7730_bundle   // exactly one frame; end payload here (no names)
   ```

4. **Send.** Because this worked example deliberately sends no ERC-20 metadata
   proof in the first trailer slot, the descriptor authenticates the intent and
   operands but does not authenticate USDT's decimals or ticker. The current
   `dev-unattested` firmware will show:
   ```
   Page 0: "** DEV BUILD **" / "Unattested" / "descriptor" / "> next"
   Page 1: "Send" / "Tether Limited" / "Tether USD" / "> next"
   Page 2: "Amount" / "100000000" / "" / "! raw, dec=?"
   Page 3: "Token (UNVERIFIED)" + the exact USDT contract address
   Page 4: "To" / "0x333333…" / "..." / "> next"
   Then: renderer-owned network and exact fee/nonce envelope pages.
   Append-only handler suffix: "Signer acct #0" + full derived address;
            "Target contract:" + full USDT address; non-zero nonce-lane
            key when applicable; call, verification, and pre-verification
            gas separately; complete fingerprint pages.
   Page N: "8213 Fingerprint" / "CalldataDigest" / "> verify off-dev"
   Page N+1: <full 32-byte hex hash>
   Page N+2: "Cancel / Confirm"
   ```

   The envelope is intentionally not a lossy EIP-1559 summary. On known
   18-decimal chains fee operands render exactly in gwei/native units; unknown
   chains use exact raw base units. Values that do not fit the exact sinks
   refuse. The three EntryPoint v0.6 gas words and all 32 nonce bytes remain
   independently visible, so equal sums or equal low 64 bits cannot alias.

   To obtain a scaled `100 USDT` page instead, supply the exact matching
   Merkle-verified ERC-20 metadata bundle in the first trailer slot. This guide
   does not embed or invent those proof bytes.

5. **Receive** the response and place the already ABI-encoded
   `type2_wrapper` directly into an EntryPoint v0.6 `UserOperation`
   (`UserOperation06`) with
   `callData = executeWithOffchainCount(1, new_offchain_count, USDT, 0, data)`,
   then ship it to the bundler.

### 7.2 USDT approve max (exact, not unlimited)

Dapp request:

```javascript
eth_sendTransaction({
  to:   "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  data: "0x095ea7b3" +                                  // approve(address,uint256)
        "0000000000000000000000004444444444444444444444444444444444444444" +
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  // U256::MAX
})
```

Lookup hits the same `registry/tether/calldata-usdt.json` entry. That descriptor
is shared by the Ethereum and Polygon deployments and intentionally carries no
`threshold` for the approval amount. Ethereum USDT treats the exact maximum as
a non-decrementing allowance, while Polygon USDT decrements it. A shared
descriptor therefore cannot safely call that value unlimited on both chains,
and the renderer makes no infinity assumption for it. Because this example
still supplies no ERC-20 metadata bundle, the token cannot be authenticated and
no ticker is claimed.

Expected display:

```
Page 0: "** DEV BUILD **" / "Unattested" / "descriptor" / "> next"
Page 1: "Approve" / "Tether Limited" / "Tether USD" / "> next"
Page 2: "Spender" / "0x444444…" / "..." / "> next"
Page 3: "Amount" / "ffffffffffffffff" / "ffffffffffffffff" / "1/2 > next"
Page 4: "Amount" / "ffffffffffffffff" / "ffffffffffffffff" / "2/2 > next"
Page 5+: exact "Token (UNVERIFIED)" identity and renderer envelope, followed
         append-only by signer, target, conditional nonce lane, exact gas,
         fingerprint and confirm
```

Supplying matching Merkle-verified USDT metadata authenticates the token
identity and ticker, but it does not add infinity semantics. The maximum
allowance remains exact raw data and is never labelled unlimited by this shared
descriptor.

### 7.3 WETH deposit (zero-arg, value from envelope)

Dapp request:

```javascript
eth_sendTransaction({
  to:    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  // WETH9 mainnet
  value: "0x6f05b59d3b20000",   // 0.5 ETH
  data:  "0xd0e30db0",          // deposit()
})
```

Lookup: `registry/weth/calldata-weth.json` mainnet entry.

This is the **`@.value` container path** case. The descriptor's
single "Amount" field has `"path": "@.value"`, which the firmware
resolves to the UserOp envelope's `value` field — NOT the calldata
(there's no calldata, deposit() is zero-arg).

Expected display:

```
Page 0: "** DEV BUILD **" / "Unattested" / "descriptor" / "> next"
Page 1: "Wrap" / "WETH" / "WETH" / "> next"
Page 2: "Amount" / "0.5 ETH" / "" / "> next"
Page 3+: renderer envelope, then the dispatcher-appended "! NATIVE ETH"
         exact 0.5 ETH value page, followed append-only by signer, target,
         conditional nonce lane, exact gas, fingerprint and confirm
```

### 7.4 USDC TransferWithAuthorization (currently refused)

The upstream Circle `TransferWithAuthorization` descriptors are present in the
vendored security corpus but are not compiled into trusted-display leaves at
this snapshot. Their hidden nonce/replay operands violate the strict rule that
every signed non-address operand must be surfaced. A companion must treat the
catalogue miss as unsupported and return an error; it must not relabel the
request as raw32/personal-sign or claim the clear-sign pages shown in older
drafts. Re-enable this example only after the descriptor compiles, the root is
reviewedly rotated, and the generated review receipt lists the exact leaf.

### 7.5 Batch signing and the current slot-rotation blocker

`CMD_SIGN_USEROP_BATCH` supports per-transaction kind-7 ERC-7730 TLVs and can
clear-sign an ordinary batch on an already-registered slot. Attach each bundle
to its `tx_idx` in the TLV list described in §6.2.

Do **not** describe first deployment as Type 1 registration. First deployment
uses `FLAG_INCLUDE_INIT_CODE`, `slot_index = 0`, and
`FLAG_REGISTER_SLOT = 0`; the factory installs slot 0 atomically and the device
emits only the slot-0 Type 2 signature. Before signing, the final trusted
confirmation includes `DEPLOY FACTORY:` and the complete factory address; a
companion must treat that page as mandatory deployment consent.

Rotation to slot N≥1 is currently blocked for seedless companions. Firmware
can emit a Type 1 signature over `addOwnerBytes(newSlotPk)`, but wire v2 does
not return the 64-byte `newSlotPk = pkSeed || pkRoot` needed to reconstruct that
exact signed calldata. A no-op `execute(sender,0,"")` is invalid and hashes to
a different UserOp. Until a reviewed wire bump exposes the public key (or the
complete Type-1 calldata), production companions MUST keep
`FLAG_REGISTER_SLOT` clear, treat any nonzero `type1_len` as unsupported, and
must not retry the request: every retry releases another fresh bootstrap C10
signature without a successful on-chain counter increment.

### 7.6 UniswapX orders (currently refused)

The vendored UniswapX `DutchOrder`, `ExclusiveDutchOrder`, and `LimitOrder`
descriptors are not compiled into the current trusted catalogue. They hide
signed nonce/replay or other effect-bearing operands, so the strict compiler
records a visible skip and the typed request must be refused. Kind 3 nested
framing support does not override that policy. Do not construct the historical
nested blob described in older drafts unless a future reviewed descriptor is
present in the exact firmware catalogue and its generated receipt confirms all
signed operands are rendered.

### 7.7 1inch aggregation calls (currently refused)

All current 1inch AggregationRouter descriptors are retained in the security
corpus but emit no trusted render leaf. The compiler rejects hidden executor /
routing addresses, flags and other signed operands, multi-dynamic framing, and
packed pool encodings. Consequently these firmware-known tuples hard-refuse;
they do not show the former three-field "Send / Minimum receive / Beneficiary"
screen and do not fall through to loud blind signing. A companion must surface
an unsupported-catalogue error until a future descriptor safely renders every
effect-bearing operand and the firmware root is reviewedly rotated.

## 8. Firmware response handling

The firmware's `CMD_SIGN_USEROP` response is identical regardless of
whether a trailer was attached:

```
[new_offchain_count u64 BE]
[init_code_len u32 BE] [init_code]      // 4280 B if FLAG_INCLUDE_INIT_CODE
[type1_len u32 BE]     [type1_wrapper]  // 4128 B if FLAG_REGISTER_SLOT
[type2_len u32 BE]     [type2_wrapper]  // always 4128 B
```

Both signature wrappers are already `abi.encode(uint256 ownerIndex, bytes
c10Sig)`. Use `type2_wrapper` directly as `UserOperation.signature`; do not
ABI-encode it a second time.

Wire v2 does not return the new slot public key needed to reconstruct a
rotation Type-1 `addOwnerBytes(bytes)` call. A production companion must
therefore request first deployment with `FLAG_INCLUDE_INIT_CODE` on slot 0 and
no Type 1, and must reject a nonzero `type1_len` until the rotation wire is
reviewedly extended (see §7.5).

The `new_offchain_count` is what `executeWithOffchainCount(...)` will
write to `offchainSigCount[i]` on-chain — bake it into the Type 2
callData.

The `CMD_SIGN_OFFCHAIN` response depends on the input header's
`OFFCHAIN_FLAG_ACCOUNT_DEPLOYED` bit:

```
[new_local_offchain_count u64 BE]
[c10_sig u8; 4008]                       // deployed: total 4016 B
// OR
[erc6492_blob u8; 8608]                  // counterfactual: total 8616 B
```

For a deployed wallet, wrap only the raw C10 signature as:

```
abi.encode(uint256 ownerIndex, bytes c10Sig)
```

where `ownerIndex = slot + 1` (slot 0 = ownerIndex 1, since
ownerIndex 0 is reserved for the bootstrap key). For a counterfactual wallet,
the 8608-byte payload is already the complete ERC-6492 blob; pass it through
unchanged to an ERC-6492-aware verifier. Do not ABI-wrap it again.

## 9. Failure modes and how to test them

Build a test corpus of one tx per category and assert what the user
sees on the screen. The firmware's host-test suite at
`secure/src/display_under_test/erc7730_render_pure_tests.rs` does
exactly this — read it for the test-pattern reference; mirror it
companion-side.

| Scenario                                          | Expected outcome                                                                                                                                                |
|---------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Descriptor matches, well-formed bundle            | Clear-sign pages + fingerprint + confirm.                                                                                                                       |
| Firmware-known call, tampered proof               | Status: `"7730 bundle fail"`, then hard refusal (`"7730 proof needed"`). No signature.                                                                         |
| Firmware-known call, wrong chain_id in trailer    | Status: `"7730 binding fail"`, then hard refusal.                                                                                                               |
| Firmware-known call, wrong contract in trailer    | Status: `"7730 binding fail"`, then hard refusal.                                                                                                               |
| EIP-712 sign with mismatched domain_separator     | Status: `"7730 binding fail"`. NO blind-sign fallback for kind=2 — error returned to dapp.                                                                      |
| No descriptor for firmware-known contract call    | Hard refusal: `"7730 proof needed"`, unless this is the explicitly supported Safe native ERC-20 path with exact chain/contract-bound Merkle metadata and strict ABI decode. Direct known calls require the descriptor. |
| No trailer for genuinely unknown contract call    | Generic value/ERC-20/typed/blind ladder remains available (Bloom false positives may conservatively refuse).                                                    |
| Bundle > 5130 bytes                               | No generic `"erc7730 too big"` status exists. Single-UserOp positional framing reports `"bad erc7730"`; batch reports `"trailer len>cap"`; off-chain typed framing may report a framing or bundle-verification failure. Treat every path as a hard companion error. |
| Verified descriptor lacks the calldata selector   | `RenderErr::NoFormat` → hard refusal. This is a companion/catalog mismatch, never downgrade permission.                                                         |
| Blob/expected-root pairing differs from firmware's pinned root | EVERY trailer fails `"7730 bundle fail"`. The blob contains no root; release metadata or independent recomputation must establish the expected pairing. |
| EIP-712 (kind=2) trailer sent for a **contract-context** descriptor | The descriptor cannot render that typed message and the sign refuses. Use kind=2 ONLY for a matching `eip712` descriptor/deployment.                              |
| Off-chain header `flags` byte set wrong            | `flags = 1` = deployed output; `flags = 0` = counterfactual ERC-6492 output. Firmware cannot query chain deployment state: the bit selects semantics and response length. Counterfactual slot ≠ 0 deterministically returns `"6492 needs slot 0"`; other lies can return a semantically unusable signature rather than a dedicated error. Derive the bit from `eth_getCode` and surface the device's pre-deploy warning. |

Test the failure modes too. A companion must surface a clear catalogue/proof
error and stop retrying; silently resubmitting without the trailer is
intentionally ineffective for firmware-known calls except for the documented,
independently authenticated Safe native ERC-20 capability.

## 10. Versioning and root rotation

The `ERC7730_DESCRIPTORS_ROOT` is a firmware-build constant. Every
firmware update can change it — when descriptors are added, removed,
or modified, the root changes deterministically.

**Current development roots** (this integration snapshot; production
provenance remains blocked):

<!-- BEGIN XTASK-VERIFIED ERC7730 CATALOGUE ROOTS -->
| Variant | Root | Catalog blob bytes | Compiled leaves |
|---------|------|-------------------:|----------------:|
| development (non-e2e) | `0x99e4b2556f5a77d6e7d9b8f07b067e9b87a4187b3e472375e602877a2810bcfe` | 366 361 | 437 |
| e2e | `0xa2bde3ae909a23a1ab45c533ffcbcdfb35345101ee750da96a3cd6f890040cb4` | 3 968 | 8 |
<!-- END XTASK-VERIFIED ERC7730 CATALOGUE ROOTS -->

Source of truth: fresh compiler output checked against `secure/src/db_roots.rs`
and the companion blobs. `cargo run -p pqsigner-xtask --
gen-erc7730-descriptors --check` verifies all marked documentation blocks as
well as the generated artifacts.

**Companion update flow** when the firmware rolls a new root:

1. After the firmware-release quarantine closes, a reviewed firmware release
   ships with a new `ERC7730_DESCRIPTORS_ROOT`.
2. Companion release pipeline regenerates `erc7730_db.bin` via
   `cargo run -p dbgen` from the same vendored registry baseline, reviewed
   curation set, and policy as the firmware build.
3. Companion package ships with the new blob plus the expected root in signed
   release metadata (or enough authenticated material to recompute it).
4. No current gateway command reports the root. Until a reviewed
   `GET_ERC7730_ROOT`-style endpoint exists, bind the companion catalogue to an
   exact firmware release/version. Once such an endpoint exists, compare the
   reported root to the separately expected/recomputed root and:
   - **Match:** use clear-sign normally.
   - **Mismatch:** block affected signing and require a compatible companion /
     catalogue update. Do not disable trailers and retry: tuples in the
     firmware's known-call filter hard-refuse without their proof.

The companion MUST NOT ship trailers that won't verify — every
mis-rooted trailer is a wasted USB chunk + a status banner the user
sees as noise.

For development against bring-up firmware built with
`erc7730-dev-unattested`: the descriptor on every render adds a
`** DEV BUILD ** Unattested` page so the user can't miss the
absence of verified provenance. There is no relaxed verifier: no ERC-8176
verifier exists yet, and production rejects the dev root. The generated
provenance fences also reject a future verified root if the warning remains;
that root rotation must remove the temporary debug/mock/e2e feature coupling
in `secure/Cargo.toml` in the same reviewed change.

## 11. Pre-flight checklist before shipping

Companion-side pre-release:

- [ ] Catalogue expected/recomputed root is bound to the exact firmware
      release. Bytes 0..31 of the blob are the header, not a root.
- [ ] Every entry in the catalog is reachable via the lookup
      function — round-trip every leaf through assemble-and-verify
      against the bundle parser at companion-side test time. Mirror
      the firmware's `dbgen/tests/erc7730_roundtrip.rs` flow on the
      companion language.
- [ ] Wire ordering matches §6 for all three commands. QEMU covers single
      UserOp (5m/5n), batch kind-7 routing and misbinding
      (5e-7730/5e-7730-mismatch), and off-chain typed data (5p). These tests
      call the NSC API directly; separately test USB/APDU framing and the
      production-language catalogue helper.
- [ ] Trailer assembly produces ≤ 5130 B for every catalog entry.
- [ ] Treat `"7730 bundle fail"`, `"7730 binding fail"`, or
      `"7730 proof needed"` as a hard catalogue/proof error; never retry a
      direct/non-exempt firmware-known call without the trailer. The only
      exception is the explicitly supported Safe native-ERC20 route with
      exact chain/contract-bound Merkle metadata and strict ABI decoding.
- [ ] A compiled-catalogue miss is not proof of absence from the firmware
      known-call Bloom filter. Use a version-paired filter/manifest or accept a
      fail-closed refusal; don't retry without a trailer as a downgrade.
- [ ] Empty names are represented by end-of-payload (no `0x00` byte). If the
      names section is non-empty, all seven preceding `u16` trailer slots are
      explicit, with a zero length for every unused slot.
- [ ] EIP-712 kind=2 passes canonical `encodeData` struct-body words only
      (no leading type hash). Plain `encodeAbiParameters(types, message)` is
      valid only for flat static members; dynamic/composite members must first
      be transformed to EIP-712 hash words. A final `hashStruct()` digest is
      not the required body.

Firmware-side smoke (run on QEMU before each release):

- [ ] `make e2e` — Scenarios 5m + 5n + 5e-7730 +
      5e-7730-mismatch + 5p all green.
- [ ] `cargo test -p sphincs-tz-secure --tests --no-default-features
      --features mock-se,debug-log,ui-semihosting,erc7730-dev-unattested`
      — run the full secure host suite; use filters only for iteration.
- [ ] `cargo test --locked -p dbgen --tests` — policy/includes, compiler, and
      round-trip suites.
- [ ] `cargo run --locked -p pqsigner-xtask --
      gen-erc7730-descriptors --check` — catalog parity
      against checked-in artifacts.

## 12. Known bugs / blockers

These are historical and current issues tracked on the `master` integration
line. Renderer limitations normally decline or hard-refuse, but the current
catalogue/provenance and slot-rotation blockers require the explicit
companion-side fail-closed behavior described above. Read each item's status;
do not assume graceful fallback or retry is safe.

### 12.1 `path_off == 0` collision — FIXED (root rotation required)

**Status**: fixed on master in commit `eef09386` (PR #2). Companion
apps consuming the catalog blob need to refresh `erc7730_db.bin` and
re-pin the new root. Companions that ship trailers against the OLD
root will hit `"7730 bundle fail"`; firmware-known tuples then hard-refuse.

What changed:

- `dbgen::erc7730::Pool::new` now pushes a 1-byte `0xFF` filler so
  pool offset 0 stays unreachable by `intern`. The on-device walker's
  `path_off == 0` "no path" sentinel and the param parser's
  `param_off == 0` "default params" sentinel are unchanged — the host
  pipeline now respects them instead of stepping on them. The catalog
  IR pool grows by 1 byte per descriptor.
- In that historical PR snapshot, `ERC7730_DESCRIPTORS_ROOT` rotated:
  - prod:
    `0x4b8adbb75193a7fd5fe15581cb17f5d016015a89e6ff8d2f52f58f493a7e8ff3`
    →
    `0x650d46a2445e1a5490822a84b6e97d267eefe8d2b4ba7517e83e45289395dc19`
  - e2e:
    `0x43243e272cc023c3fd5f83b837ac6fb5cbabb1e984d12eb1127ef725991bc15f`
    →
    `0xcef0ce215baf061a08be24aba9764160eec8c44672ead549535d89a7e4a39934`
- Historical catalog blob size: development `tools/companion-stub/erc7730_db.bin`
  10919 → 10939 B, e2e `erc7730_db_e2e.bin` 1444 → 1448 B.

**Companion checklist** (post-fix):

1. Copy the new `tools/companion-stub/erc7730_db.bin` (or rebuild from the same
   vendored registry baseline + reviewed curations + policy via
   `cargo run -p dbgen`).
2. Update the build-time root constant pinned next to the blob.
3. Re-run companion integration tests against firmware built from
   master.

Previously-affected descriptors now render full clear-sign pages instead of
refusing at the verified-descriptor render gate:

- `registry/weth/calldata-weth.json` / `deposit()` — Amount field renders.
- `registry/tether/calldata-usdt.json` / `transfer` and `approve` — To / Spender +
  Amount fields render.
- `registry/aave/calldata-lpv3.json` — currently accepted `withdraw`/`repay`
  formats render; incomplete formats such as `supply`/`borrow` are known-call
  refusals until every signed operand is visible.
- Fixture-only `circle-usdc-twa.json` / `circle-usdc-rwa.json` render tests —
  From + To + Amount fields exercise the renderer mechanics. This is not a
  production-catalogue claim: the current vendored Circle
  `TransferWithAuthorization` descriptor is refused for its hidden nonce, as
  described in §7.4.

`render_token_amount` still honors an authenticated `params.threshold`: values
at or above it use the descriptor's message, or the default `unlimited`
wording. Threshold meaning is contract-specific, however, and is never inferred
from the generic ERC-20 operation:

- WalletConnect WCT and FlyingTulip `approveEngine` set the threshold to exact
  `uint256.MAX`, so only that value receives the unlimited label.
- FlyingTulip `approveBorrow` and the shared Ethereum/Polygon USDT descriptor
  carry no threshold, so even `uint256.MAX` remains an exact allowance value.
- The generic ERC-20 descriptor carries no threshold and makes no infinity
  assumption for arbitrary token contracts.

Because the renderer's comparison is `value >= threshold`, a maximum-value
threshold is equality over `uint256`. The existing threshold TLV (tag `0x32`)
needs no new wire field; authenticated ticker/decimals still require the
existing ERC-20 trailer.

### 12.2 `interpolatedIntent` has a constrained scalar-amount path

The host compiler supports a deliberately smaller contract-calldata subset. A
catalogue format is enrolled only when the template has one terminal
placeholder naming an always-visible, static unsigned scalar field formatted as
`amount` or `tokenAmount`. `#.amount` and the registry's root-relative
`amount` spelling are the only accepted path alias. Arrays, container paths,
EIP-712 values, address/NFT/raw fields, threshold/message shorthand and the
canonical ERC-20 `approve(address,uint256)` flow remain outside this slice.
Valid unsupported templates retain the descriptor's separate static `intent`;
they are not printed with braces and do not cause an otherwise safe format to
drop from the catalogue.

Eligibility is deployment-specific, not descriptor-global. A non-native
`tokenAmount` placeholder is enrolled only when its statically resolved exact
`(chainId, token)` identity is present in the generated ERC-20 metadata set and
that metadata row fits every device-verifier bound, including proof depth and
the complete 1,120-byte wire limit. A runtime calldata token path cannot borrow
authority from another deployment or from a dormant token literal. A native
placeholder instead requires one of the descriptor-authenticated native
sentinels and a firmware-pinned chain scale/ticker. The current reviewed source
set contains 78 candidate deployment formats: six meet these conditions and 72
retain only their static intent. Catalogue expansion requires that explicit
enrollment test to change.

The compiler resolves the placeholder to the final emitted field ordinal and
stores program version 1 in authenticated parameter TLV `0x46`, canonically on
field zero. This is a root-pinned authenticated parameter extension within the
current schema. The device deep-validates the TLV in every format, including
unselected suffixes: unique canonical placement, in-range ordinal, `Always` visibility,
an `Amount`/`TokenAmount` opcode, no threshold/message, and a static structured
scalar path are mandatory.

Rendering remains derived presentation. PQ1 first renders and retains every
ordinary field and token-identity page. Only a formatter that completely paints
the signed 32-byte amount using an authenticated scale/unit may mint the private
substitution witness. A non-native `tokenAmount` additionally requires exact
metadata chain and contract binding. Raw/unverified/unlimited/overflow,
zero-collapse, hidden/skipped or missing-witness paths reject. The derived title
then repaints the already-reserved intent page, so page count and ordering do not
change; it must fit all 32 OLED cells and never uses the static title's `~`
clipping.

The value witness is exact at the displayed precision. In particular, the
native-value path displays at most six fractional digits and refuses a non-zero
amount whose signed 256-bit value cannot be reconstructed exactly at that
precision; it never certifies rounded copy as the signed amount. Native
rendering and interpolation share the same exactness predicate.

This intentionally differs from Ambire's companion-side implementation, which
interpolates decoded path values directly. PQ1 substitutes the value its trusted
field renderer actually showed, including the authenticated unit/ticker. For
that reason the first catalogue slice accepts only a terminal placeholder and
does not enroll upstream templates that append their own unit copy. Once TLV
`0x46` is present, any runtime interpolation failure is a hard refusal rather
than a downgrade to the static title. The separately derived exact-zero
`"Revoke approval"` banner and interpolation cannot coexist.

### 12.3 Nested calldata stubs out

`Calldata` formatter (0x0A) rejects with `Reject("7730 nested
calldata p5")`; a verified/known generic call therefore refuses. Safe v1's `execTransaction` uses
this in the registry but is handled by a dedicated `safe_display`
renderer; generic descriptors that use `nestedSelector` will not sign until a
complete native rendering path exists.

### 12.4 NFT collection identity is bounded and injective

`NftName` formatter (`0x04`; `0x09` is `Unit`) requires exactly one
authenticated collection source: a literal 20-byte address in IR tag `0x44`,
or a compiled static-address path in tag `0x45`. Container-root paths are
limited to the frozen `@.to` envelope field; calldata argument names cannot
shadow the `@` namespace. Missing, duplicate, mutually specified, malformed,
non-address, dynamic, or unsupported container paths reject.

The device renders the exact token ID as decimal only when lossless, otherwise
as all 32 raw bytes, and always adds a page containing the complete collection
address. A friendly name is optional: descriptor `contractName` qualifies only
when the collection equals the authenticated descriptor contract; any other
collection requires exact `(chain, address)` metadata. Chain-zero wildcard
metadata never qualifies. A missing name retains the complete raw identity and
does not authorize blind signing.

### 12.5 Dynamic ABI framing is deliberately narrow

`render_erc7730_pages` accepts exact all-static calldata and one narrow
dynamic shape: a **sole top-level C1 tail** containing a `string`/`bytes`,
a supported primitive array, or a dynamic `tokenPath`. The dynamic offset
must equal the static-head length; its declared data, zero ABI
right-padding, and padded end must consume the entire calldata body.
This format-level preflight runs before visibility, so hiding a dynamic
field does not bypass its framing checks.

C2 dynamic-tuple descent, C3/multiple dynamic tails, aliased offsets,
gaps, non-zero padding, and trailing bytes are not trusted shapes.
`dbgen` omits those formats and the runtime rejects them independently.
For a firmware-known/verified call, any such render failure is a hard
refusal, never a typed- or blind-sign fallback. The legacy walker was
removed and therefore cannot expand this policy through a second runtime
decoder.

## See also

- `docs/companion/erc7730-integration.md` — what the firmware does after
  receiving the trailer (verify → bind → render → fingerprint →
  confirm).
- `docs/companion/usb-protocol-v2.md` — full USB-HID wire layout, all
  commands, all kinds.
- `docs/companion/companion-app-integration.md` — broader companion
  architecture (PIN entry, unlock, slot management).
- `docs/companion/companion-batch-sign-integration.md` — batch sign per-tx
  record format.
- `tools/companion-stub/erc7730_trailer.py` — Python reference
  implementation of §4–§5; pass `--context contract`, or
  `--context eip712 --domain-separator 0x<64 hex>` and
  `--primary-type-hash 0x<64 hex>` for typed data.
- `dbgen/tests/erc7730_roundtrip.rs` — host-side round-trip test
  showing the catalog → trailer → on-device verifier flow
  byte-for-byte.
- `secure/src/display_under_test/erc7730_render_pure_tests.rs` —
  host-side render-string tests. Mirror these companion-side.
