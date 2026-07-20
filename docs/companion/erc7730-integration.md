# ERC-7730 firmware integration — current status

This path is retained for old links, but it is **not the normative companion
implementation guide**. Use
[`companion-erc7730-implementation-guide.md`](companion-erc7730-implementation-guide.md)
for the current `P730` catalogue, trailer framing, lookup rules, and command
examples. Historical phase documents under `docs/archive/` describe retired
wire layouts and fallback policies and must not be implemented.

Current security contract:

- The host compiler emits the schema named in the xtask-verified facts below.
  Its fixed header is 134 bytes; the authoritative layout and caps are in
  `pqsigner-erc7730/src/ir.rs`.
- The verifier, binding logic, ABI resolver, page substrate, and full renderer
  are host-linkable pure logic in `pqsigner-erc7730/`. Secure world calls that
  same implementation through thin re-exports.
- Every supplied bundle is Merkle-verified against the firmware-pinned root and
  bound to the signed chain/deployment/domain before rendering.
- ERC-20 metadata is consumed only after a second, surface-specific attribution
  check against the signed direct target, exact ERC-7730 `tokenPath`, verified
  Safe target, or verified pinned MultiSend record. Unverified Safe bytes grant
  no authority. Bound non-native token amounts, arrays, and tickers always show
  the full contract address; identity-page exhaustion refuses.
- Allowance-threshold wording is descriptor-authenticated and
  contract-specific, never inferred from the generic ERC-20 operation. WCT and
  FlyingTulip `approveEngine` use an exact-`uint256.MAX` threshold, so only max
  is labelled unlimited. FlyingTulip `approveBorrow`, the shared
  Ethereum/Polygon USDT descriptor, and the generic ERC-20 descriptor carry no
  threshold; their signed allowance remains exact and receives no infinity
  label.
- The vendored security corpus also produces a pinned known-call filter over
  every parsable registry-declared contract tuple, including declarations from
  descriptors rejected by the strict renderer. Such a tuple needs independently
  authenticated semantics: normally a valid, bound, completely renderable
  descriptor; the explicitly enumerated Safe exception is strict native ERC-20
  decoding with exact chain/contract-bound Merkle metadata, re-attributed per
  direct call or MultiSend record. Without either, signing hard-refuses and
  never downgrades to typed or blind signing. Only a genuinely absent tuple may
  use the generic display ladder; Bloom false positives conservatively refuse.
<!-- BEGIN XTASK-VERIFIED ERC7730 INTEGRATION FACTS -->
- The host compiler and device require **IR schema v5 (`0x05`)**; this value is
  generated from `pqsigner_erc7730::ir::SCHEMA_VER`, and older schemas hard-refuse.
- Schema v5 authenticates every `uintN`/`intN` width and hard-refuses dirty ABI
  zero/sign extension before publishing trusted clear-signing pages; full-width
  `uint256`/`int256` words remain unchanged.
- The current regenerated development catalogue has **437 leaves**, root
  `99e4b2556f5a77d6e7d9b8f07b067e9b87a4187b3e472375e602877a2810bcfe`,
  and **4,544 exact known-call tuples**. The tuple-set receipt is SHA-256
  `593a8c77ccb5323cdd2fc2830af32916722dfc3fb570aa33ca94b7fcdf8dd781`;
  Bloom occupancy is 28,248 / 131,072 bits under the compiler-enforced generation cap.
- The current compiler report records **259** omitted descriptor/formats.
<!-- END XTASK-VERIFIED ERC7730 INTEGRATION FACTS -->
- These receipts detect input/artifact drift. They do not turn Bloom insertion
  into a proof of parser completeness. The current independent types-only ABI
  parser, raw/resolved declaration tests, tuple-array witnesses, and
  fail-closed selector derivation are separately reviewed evidence and must be
  re-evaluated when those implementations change.
- The current omission report classifies endpoint-only array/packed-route token
  paths, runtime-dead opaque semantic bytes, hidden operands, and unsupported
  framing. Those categories are reviewed prose, not facts derived by xtask;
  omissions cannot acquire trusted-display authority merely by being listed.
- Known/verified render errors—including no matching format, non-canonical ABI
  framing, unsupported dynamics, or page-budget exhaustion—hard-refuse.
  `MAX_PAGES` is currently 31; code constants, not old prose, are authoritative.
- `tokenAmount.nativeCurrencyAddress` is an authenticated one-or-two-address
  list under IR tag `0x42` (legacy scalar bytes unchanged). Exact membership
  alone selects the chain-native ticker/scale; malformed, duplicate, oversized,
  or unmatched lists never acquire native-currency semantics.
- `nftName` binds exactly one collection source under IR tag `0x44` (literal
  20-byte address) or `0x45` (compiled static-address path). Container paths are
  limited to the frozen `@.to` envelope field; ABI arguments cannot shadow the
  `@` namespace. The device always renders the exact token ID and complete
  collection address. Descriptor `contractName` is usable only when that
  address equals the authenticated descriptor contract; otherwise a friendly
  name requires exact `(chain, address)` metadata. Chain-zero wildcard names do
  not qualify.
- `enum` accepts authenticated unsigned integers and ABI booleans. A boolean
  enum renders only exact ABI words `0` and `1`; any other 256-bit word
  hard-refuses before a trusted page is published.
- Contract selector preflight is independent of renderer field-name policy. It
  canonicalizes Solidity ABI aliases (`uint`, `int`, `byte`, `fixed`,
  `ufixed`), accepts legal `$` identifiers, whitespace, and nested tuple-array
  suffixes, and aborts catalogue generation on any deployed format whose
  selector cannot be derived confidently (including selector-only hex keys).
- EIP-712 lookup is an exact four-part match: chain, verifying contract,
  recomputed domain separator, and full 32-byte primary type hash found inside
  authenticated IR. The entry-level type hash is only the first-surviving
  format's sorting/diagnostic hint; multi-format leaves require scanning their
  complete format tables.
- The renderer's local stack sentinel is only a corruption tripwire. It is not
  proof that arbitrary stack overrun is detected; ARM link/resource reporting
  and reviewed worst-case stack analysis remain separate evidence.

Provenance is deliberately pre-production:

- No ERC-8176/EAS attestation verifier is implemented today. The generated
  catalogue provenance is `dev-unattested`.
- Non-test development firmware that embeds that root must show the
  `DEV UNATTESTED` warning page. Production-shaped builds reject the root at
  compile time and `make prod-erc7730-provenance-check` independently refuses
  it. A future verified root must remove the dev-warning feature coupling in
  the same reviewed rotation.
- There is no gateway command that reports the current root and no separately
  authenticated release-metadata channel yet. During bring-up, bind the
  companion blob to the exact firmware build out of band. Production remains
  blocked by both the provenance gate and the independent firmware-rollback
  quarantine.
- Wire v2 slot rotation remains quarantined: it may return a Type-1 signature
  without the exact 64-byte public key needed to construct its signed calldata.
  Seedless companions keep `FLAG_REGISTER_SLOT` clear, reject any nonzero
  Type-1 result, and do not retry. Initial slot-0 deployment is the separate
  factory path.

Sources of truth:

- `docs/companion/companion-erc7730-implementation-guide.md`
- `pqsigner-erc7730/src/{ir,bundle,binding,known_calls}.rs`
- `pqsigner-erc7730/src/display/`
- `dbgen/src/erc7730.rs`
- `secure/src/tx/erc7730.rs`
- `secure/src/db_roots.rs`
- `secure/data/erc7730.review.txt`
