# ERC-7730 Integration — PQSigner OS

Full spec of the on-device ERC-7730 clear-signing pipeline. Phases 1–5
(commits `eb775140` through `clear-sign-rebased` tip) shipped the
host-side IR compiler, the firmware-side IR parser + walker + Merkle
bundle verifier + binding cross-checks, the renderer + ERC-8213
fingerprint pages + EIP-712 typed sign completion, and the Phase 5
audit-polish layer (production attestation gate, FI-hardened binding
gates, compact-mode toggle, stack canary).

## Threat model

ERC-7730 descriptors are PUBLIC registry data (not secrets) but they
drive what the user sees on the trusted-path display before signing.
A hostile companion that controls descriptor delivery could:

1. **Spoof a descriptor.** Forge "Send 0.01 ETH to Alice" while the
   inbound calldata actually transfers 1000 ETH to Mallory. Defence:
   every descriptor is Merkle-verified against the firmware-pinned
   `ERC7730_DESCRIPTORS_ROOT`. The host-side `dbgen` pipeline accepts
   only descriptors that pass the attestation policy
   (`secure/data/erc7730/policy.toml`); the firmware trusts the root.
2. **Pair a real descriptor with an unrelated tx.** Forge "USDC
   approve $100" pages while the calldata authorises a Uniswap swap
   draining the entire wallet. Defence: binding cross-checks —
   `cross_check_contract(descriptor.ir, chain_id, to_address)` for
   contract-context, `cross_check_eip712(descriptor.ir, chain_id,
   contract, domain_separator)` for EIP-712 typed-data. Phase 5
   item 6 wraps both gates in the `fi::check_true_into_sentinel`
   idiom so a single-fault glitch on the binding gate also has to
   defeat a Hamming-distant sentinel compare.
3. **Smuggle untrusted display strings.** Defence: every text field
   on-device (intent / owner / contractName / format strings) is
   ASCII-clean + length-bounded at host emission time.

What we do NOT defend against on-device:

- **ERC-8176 verification** (signature attestations on the descriptor
  itself). The attestation chain uses secp256k1 + ERC-1271. Verifying
  it on-device would violate the firmware-wide "no classical signer"
  invariant (#5 in CLAUDE.md). All attestation verification happens
  HOST-SIDE in the `dbgen` pipeline before the descriptor reaches the
  Merkle root. The firmware trusts the root.
- **Pre-attestation drift.** A new descriptor that hasn't yet been
  Merkle-rooted in a firmware release cannot be rendered with
  clear-signing pages — it falls through to blind-sign. Firmware
  upgrades bring new descriptors.

## On-device IR

Pure-logic primitives live in the workspace crate
`pqsigner-erc7730/src/{ir,walker,bundle,binding,abi}.rs`. The firmware
re-exports them via `secure/src/tx/erc7730.rs`.

### Header

Wire-format (12-byte fixed header + variable sections; see
`pqsigner-erc7730/src/ir.rs::SCHEMA_VER` + `HEADER_LEN`).

```
schema_ver (u8 = 1)
chain_id   (u64 BE)
owner_off  (u16 BE)
contract_name_off (u16 BE)
contract_addr     ([u8; 20])
deployments_off   (u16 BE)
formats_off       (u16 BE)
pool_off          (u16 BE)
```

All `*_off` fields are offsets into the IR's flat byte array.
`pool` is the shared interning area for ASCII strings + path bytecode
programs.

### Formats

Each format describes one (selector OR EIP-712 primaryTypeHash[..4])
key + its field list:

```
selector       [u8; 4]
field_count    u8       (≤ MAX_FIELDS_PER_FORMAT = 24)
intent_len     u8       (≤ 254, printable ASCII)
intent         [u8; intent_len]
[field_count × FieldEntry]
```

Each `FieldEntry`:

```
format_op    u8       (one of 0x01..0x0E)
label_off    u16 BE   (pool offset for the field's label string)
param_off    u16 BE   (pool offset for the TLV-encoded ParamSet)
path_off     u16 BE   (pool offset for the path bytecode program)
```

`FormatOp` values (see `pqsigner-erc7730::ir::FormatOp`):

| Opcode | Variant         | Purpose                              |
|--------|-----------------|--------------------------------------|
| 0x01   | Address         | Render a 20-byte address             |
| 0x02   | Uint            | Render an unsigned integer           |
| 0x03   | Int             | Render a signed integer              |
| 0x04   | Bool            | Render a boolean                     |
| 0x05   | Bytes           | Render bytes / fixed bytesN          |
| 0x06   | String          | Render a UTF-8 string                |
| 0x07   | Amount          | Render a token amount (uses tokenRef)|
| 0x08   | TokenAmount     | Render with looked-up decimals       |
| 0x09   | Duration        | Render a duration (seconds → h/m/s)  |
| 0x0A   | Date            | Render a date (block height or unix) |
| 0x0B   | Enum            | Render an enum value                 |
| 0x0C   | Calldata        | Render nested calldata (recurses)    |
| 0x0D   | NftName         | Render an NFT name                   |
| 0x0E   | Raw             | Render raw hex                       |

### Visibility

Each field carries a `Visibility` byte:

| Variant    | Renderer behaviour                                   |
|------------|------------------------------------------------------|
| Always     | Render unconditionally.                              |
| Never      | Skip; walker NOT invoked.                            |
| Optional   | Render in full mode, skip under `COMPACT_MODE`.      |
| IfNotIn    | Render. Value list not yet wire-encoded by `dbgen`.  |
| MustMatch  | Reject. Value list not yet wire-encoded by `dbgen`.  |

Phase 5 item 10 added the `COMPACT_MODE` toggle in
`secure/src/tx/display/erc7730/mod.rs` so a future settings page can
flip the const to skip Optional fields without a descriptor reflash.

## Trailer format

Wire-format: `[u16 BE len][payload]`. Payload is the bundle format
consumed by `pqsigner_erc7730::bundle::verify_erc7730_bundle`:

```
ir_len(2 BE) || ir || leaf_index(4 BE) || proof_depth(4 BE) || proof
```

The trailer sits between the `self_attest` trailer and the names section
in the sign-input wire layout (see `docs/usb-protocol-v2.md`). It is
NOT mutually exclusive with the selector / self-attest trailers — the
renderer dispatch picks the best one per the priority ladder in
`secure/src/tx/display/mod.rs::pick_sign_pages`.

## Formatter coverage

All 14 FormatOps + intent banner + ERC-8213 fingerprint pages are
implemented (Phase 4 — `secure/src/tx/display/erc7730/formatters.rs`).
Phase 5 didn't add new formatters; it added:

- `COMPACT_MODE` toggle that distinguishes `Visibility::Optional` from
  `Visibility::Always` at render time.
- Stack canary at both entry points (`render_erc7730_pages` and
  `render_erc7730_eip712_pages`) as belt-and-braces against a defeated
  depth cap.
- "DEV UNATTESTED" warning page under the `erc7730-dev-unattested`
  Cargo feature so a bring-up developer cannot miss that the host-side
  attestation policy was relaxed.

### Path resolution

Phase 4 ships a direct path walker rather than going through
`pqsigner_erc7730::walker::resolve_path`. The reason: Phase 3's walker
requires an `AbiView` tree describing the runtime ABI shape, and the
on-device IR does not carry ABI type information. Static types (uint*,
int*, address, bytes32, bool, static tuples) work via the direct
walker; dynamic types (bytes, string, dynamic arrays, dynamic tuples)
are out of scope until a shape-descriptor byte lands in the IR header
(Phase 5+ wire-format extension — Cf. the handoff item 5).

### Nested calldata

`secure/src/tx/display/erc7730/calldata_nested.rs` currently stubs to
`Reject("nested calldata p5")` and falls through to blind-sign. The
recursion is depth-capped at 4 in the renderer + 8 in the walker
proper (see `pqsigner_erc7730::walker::MAX_NESTING`). Phase 5+ wires
the bounded recursion once the shape-descriptor extension lands.

## What is verified on-device

Per signing pass with an ERC-7730 trailer:

1. **Bundle structure.** Re-parse `ir_len`, validate `ir` parses as a
   well-formed `Erc7730Ir`, validate `leaf_index < (1 << proof_depth)`.
2. **Merkle root.** Re-compute the leaf hash via
   `pqsigner_erc7730::bundle::leaf_hash`, walk the proof, assert the
   computed root equals `ERC7730_DESCRIPTORS_ROOT`.
3. **Binding.** For contract-context: assert `descriptor.chain_id ==
   chain_id && descriptor.contract == to_address`. For EIP-712 typed:
   assert `descriptor.chain_id == chain_id && descriptor.contract ==
   verifying_contract && descriptor.deployments[i].domain_separator
   == domain_separator`. Phase 5 wraps the gate in
   `fi::check_true_into_sentinel`.
4. **Format dispatch.** Locate the format header whose
   `selector == calldata[..4]` (contract) or
   `selector == primary_type_hash[..4]` (EIP-712). Refuse to render if
   no match (renderer returns `RenderErr::NoFormat`, dispatcher falls
   through to the next ladder rung).
5. **Per-field render.** Walk each field's path program, dispatch to
   the matching `FormatOp` renderer, append pages to the `Pages`
   buffer (capped at `MAX_PAGES = 22`).
6. **Stack canary.** Phase 5 item 11: a `STACK_CANARY = 0xDEAD_BEEF`
   written at entry and checked at exit asserts no stack overrun
   defeated the depth cap.

## What is NOT verified on-device

- ERC-8176 attestation signatures (host-only — see threat model
  §"What we do NOT defend against").
- The descriptor's content matches what the dapp ACTUALLY intended.
  The user is still the trust anchor on the confirm dialog.
- Cross-chain replay — the firmware pins (chain_id, to_address) into
  the binding gate; a descriptor for chain A renders nothing on chain
  B.

## Common gotchas

1. **`personal_sign_replay_safe_hash` double-wrap.** When a dapp
   pre-wraps an EIP-712 hash and calls
   `wallet.isValidSignature(replaySafeHash(H), sig)`, the on-chain
   Solady will re-wrap it → double-wrap → verification fails. That's
   a dapp bug. The firmware always wraps inside the secure world
   (under `kind = RAW32` the companion MUST pass the un-wrapped hash;
   PersonalSign mode does the nesting inside the secure world).
2. **Bundle root changes invalidate every companion `erc7730_db.bin`.**
   Adding shape-descriptor bytes to the IR header changes the per-
   leaf hash → `ERC7730_DESCRIPTORS_ROOT` changes → every existing
   companion-side `erc7730_db.bin` needs regeneration. The `dbgen
   --check` gate catches this at host-build time.
3. **Test gating.** `secure/src/tx/display/*` is `#[cfg(not(test))]`
   because production-side modules depend on hardware-only
   `crate::ui::*` bindings. The host-test scaffold in
   `secure/src/display_under_test/` re-mounts the per-renderer source
   files under a parallel `Pages` shim. The ERC-7730 renderer is NOT
   yet mounted in that scaffold; coverage lives in the QEMU `make
   e2e` Scenarios 5m + 5n + 5p, the fuzz harnesses, and the
   `nsc_erc7730_*_pure_tests` source-text regression tests.

## See also

- `docs/erc8213-fingerprints.md` — cross-device verification recipe for
  the fingerprint hashes.
- `docs/companion-erc7730-integration.md` — trailer assembly from the
  companion side.
- `docs/handoff-erc7730-phase5.md` — the audit-grade polish handoff
  (most of which is what this doc summarises).
- `docs/HARDENING.md §12.4` — ERC-7730 timing channels +
  stack-canary defence-in-depth.
