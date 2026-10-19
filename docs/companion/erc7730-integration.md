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
- The companion release pairing is authenticated separately from each
  sign-time proof. `dbgen` emits a canonical 256-byte `P73S` receipt; the
  selected bytes live in final secure-ELF section
  `.pqsigner.erc7730_status`, are covered by the signed secure-image hash, and
  are packaged as `erc7730-status.bin`. The companion authenticates the release
  and exact/minimum firmware version first, then hashes the paired P730/Bloom,
  rebuilds the complete tree, and byte-compares every proof before enabling
  clear signing. This is compatibility evidence, not ERC-8176 attestation.
- ERC-20 metadata is consumed only after a second, surface-specific attribution
  check against the signed direct target, exact ERC-7730 `tokenPath`, verified
  Safe target, or verified pinned MultiSend record. Unverified Safe bytes grant
  no authority. Bound non-native token amounts, arrays, and tickers always show
  the full contract address; identity-page exhaustion refuses.
- Allowance-threshold wording is descriptor-authenticated and
  contract-specific, never inferred from the generic ERC-20 operation. WCT and
  FlyingTulip `approveEngine` use an exact-`uint256.MAX` threshold, so only max
  is labelled unlimited. The shared USDT descriptor carries the same threshold,
  but `_pqsigner.thresholdOmissions` removes it from the Polygon IR, so only
  Ethereum USDT labels exact max unlimited (2026-10-19). FlyingTulip
  `approveBorrow`, Polygon USDT, and the generic ERC-20 descriptor carry no
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
- The owner-selected, default-off forced-blind extension partitions exact
  contract-call tuples into `K` (the complete registry-known inventory), `C`
  (tuples recovered from accepted contract-context formats in the final
  `P730`), and `F = K \ C` (refused-known tuples). Its canonical `P73K` artifact
  encodes only `F`. The signed secure image must co-authenticate `P73K` and
  `P73S`; generation and companion preflight recover `C`, strictly decode `F`,
  prove `C ∩ F = ∅` and `C ∪ F = K`, and reproduce the P73S `K`
  count/hash plus Bloom relation. A companion-selected, missing, malformed, or
  mismatched artifact grants no authority.
- Forced blind is separate from clear signing and remains unimplemented at
  this owner-amendment snapshot. Once its implementation and merge gates land,
  only an exact `F` member with a structurally cleanly absent complete trailer
  may enter its on-device ceremony, and only in a build that explicitly enables
  `erc7730-forced-blind`. A `C` tuple with an omitted descriptor remains fatal;
  malformed/nonempty/bad/misbound evidence and every verified render failure
  remain fatal. All other existing refusal and generic-unknown routing stays
  unchanged. Default and rollback behavior is refusal.
<!-- BEGIN XTASK-VERIFIED ERC7730 INTEGRATION FACTS -->
- The host compiler and device require **IR schema v6 (`0x06`)**; this value is
  generated from `pqsigner_erc7730::ir::SCHEMA_VER`, and older schemas hard-refuse.
- Schema v5 authenticates every `uintN`/`intN` width and hard-refuses dirty ABI
  zero/sign extension before publishing trusted clear-signing pages; full-width
  `uint256`/`int256` words remain unchanged.
- Schema v6 binds explicitly enrolled top-level EIP-712 string preimages to their
  exact signed words and hard-refuses missing, reordered, mismatched, non-ASCII,
  over-128-byte, trailing, or page-overflow display evidence without fallback.
- The current regenerated development catalogue has **365 leaves**, root
  `8c3dc4b2b1789106a1043aed08114b7827d56052dd920eb0dd6671a84db643e6`,
  and **4,615 exact known-call tuples**. The tuple-set receipt is SHA-256
  `50dfa0f52c76efc27c7110e9703595d8e1afc2195ffeb847b3567817ced421e6`;
  Bloom occupancy is 28,646 / 131,072 bits under the compiler-enforced generation cap.
- The current compiler report records **943** omitted descriptor/formats.
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
- Catalogue drift must report every `C -> F` movement as a signing-authority
  expansion and obtain an explicit owner decision before the paired root/set
  rotation is accepted.
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

- The host build has a pinned-draft, bounded offline ERC-8176/EAS-v2 verifier,
  but the canonical policy has no approved snapshot or real trusted-auditor
  population. The generated catalogue provenance therefore remains
  `dev-unattested`; see `docs/erc8176-attestation-status.md`.
- Non-test development firmware that embeds that root must show the
  `DEV UNATTESTED` warning page. Production-shaped builds reject the root at
  compile time and `make prod-erc7730-provenance-check` independently refuses
  it. A future verified root must remove the dev-warning feature coupling in
  the same reviewed rotation.
- Production configurations omit `erc7730-forced-blind` until its implementation
  review and the independent watchdog-attribution, physical trusted-UI/FI,
  resource, ERC-8176, rollback, provenance, and release gates close. The
  feature is positive and default-off; no dev/test alias or missing flag may
  enable it.
- There is deliberately no gateway command that reports the current root. The
  authenticated signed-image receipt now supplies the release metadata without
  expanding the USB/CMSE surface. With no authenticated running-device query,
  automatic readiness is scoped to a signed release the companion installed
  and recorded; an unknown or externally changed installed identity is
  incompatible. Production remains blocked by both the provenance gate and the
  independent firmware-release/rollback quarantine.
- Wire v2 slot rotation remains quarantined: it may return a Type-1 signature
  without the exact 64-byte public key needed to construct its signed calldata.
  Seedless companions keep `FLAG_REGISTER_SLOT` clear, reject any nonzero
  Type-1 result, and do not retry. Initial slot-0 deployment is the separate
  factory path.

Sources of truth:

- `docs/companion/companion-erc7730-implementation-guide.md`
- `pqsigner-erc7730/src/{ir,bundle,binding,known_calls,catalogue_status}.rs`
- `pqsigner-erc7730/src/display/`
- `dbgen/src/erc7730.rs`
- `secure/src/tx/erc7730.rs`
- `secure/src/db_roots.rs`
- `secure/data/erc7730.review.txt`
- `fwsign/src/{artifact_key,bundle,subcommands/verify}.rs`
- `tools/companion-stub/erc7730_trailer.py`
