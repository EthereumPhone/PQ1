# Calldata decoding — Phase 2 handoff

**Status:** design / handoff. Phase 1 has shipped: the firmware now
verifies a host-supplied `(selector, text_sig)` bundle and surfaces the
function name above the BLIND SIGN screen. Phase 2 turns that verified
text signature into a typed render of the calldata's arguments.

## Phase 1 recap (already in tree)

- `shared/src/db_format.rs` — `SELECTOR_DB_*` schema constants,
  `SELECTOR_TEXT_SIG_MAX_LEN = 63`.
- `dbgen/src/selectors.rs` — host-side blob writer + round-trip checker.
- `secure/src/db_roots.rs` — `SELECTOR_DB_ROOT` (32 B, vendor-signed).
- `secure/src/selectors/{mod.rs, bundle.rs}` —
  `verify_selector_bundle()` walks the Merkle proof to the embedded
  root, ASCII-gates the text, length-caps it, then returns
  `SelectorMeta { selector, text_sig }`.
- `secure/src/nsc/cmd_sign_userop.rs` — new `[u16 BE len][bundle]`
  trailer slot between `safe_v1` and the names section.
  Cross-checks `bundle.selector == calldata[0..4]` after Merkle verify;
  threads the survivor into `pick_sign_pages`.
- `secure/src/tx/display/blind_sign.rs` — when `selector_meta.is_some()`
  prepends a "FUNCTION: <text_sig>" page; when absent, behaviour is
  bit-identical to pre-Phase-1.
- `tools/build_selectors_json.py` — curates ~/Documents/4bytes-db into
  `secure/data/selectors.json`. The selectors blob lives at
  `tools/companion-stub/selectors_db.bin`; the production firmware
  image does NOT bake it in.

The trust property carried by Phase 1: *the displayed function name
was vendor-curated and signed into this firmware build*. It does not
attest what the contract does with that name. The BLIND SIGN banner
above the FUNCTION page stays loud for that reason.

## Phase 2 goal

Given a verified `text_sig` like `transfer(address,uint256)`, decode
`inner_data[4..]` according to Solidity ABI rules and render it
typed — `to: 0xRECIPIENT (or alice.eth), amount: 1000` — instead of
the hex word dump that Phase 1 still shows.

Phase 2 keeps the Phase 1 trust model unchanged: the type list comes
from the same bundle that has already been Merkle-verified +
cross-checked, and the BLIND SIGN banner stays unless / until
upgraded to per-contract attestation (see § Migration to ERC-7730).

## Where Phase 2 hooks in

- `secure/src/tx/display/blind_sign.rs::render_blind_sign_pages`
  already takes `selector: Option<&SelectorMeta>`. Phase 2 replaces
  the existing "FUNCTION: …" page (and the raw calldata word-dump
  pages that follow) with a typed-args render whenever the calldata
  passes the new strict-shape check.
- `secure/src/erc20/calldata.rs::parse_erc20_calldata` is the
  prior-art reference for a strict, per-selector decoder. Phase 2
  generalises that pattern to any `(text_sig, calldata)` pair.

## Sub-component 1 — Text-signature parser

A no-std, no-alloc tokenizer that splits `name(typelist)` into
`(name: &str, types: SmallVec<TypeRef, MAX_ARGS>)`.

Suggested type registry (fixed-shape enum):

```rust
enum TypeRef {
    Uint(u16),       // bits 8..=256, multiple of 8 (or 0 = bare "uint")
    Int(u16),
    Address,
    Bool,
    Bytes,           // dynamic
    BytesN(u8),      // 1..=32
    String,          // dynamic
    Array { elem: TypeId, fixed_len: Option<u32> },
    Tuple { first_elem: TypeId, len: u8 },
}
```

Where `TypeId` is an index into a stack-allocated `[TypeRef; 32]`
arena built per sign-userop. Recursive types (tuples / arrays) live
in the same arena, indexed by id, so the structure remains
heap-free.

Parser whitelist (anything outside falls back to "raw word"
rendering, never to a panic):

- `uint8`, `uint16`, …, `uint256` (every multiple of 8)
- `int8` … `int256`
- `address`
- `bool`
- `bytes`, `bytes1` … `bytes32`
- `string`
- `<type>[]`, `<type>[N]` (any single-bracket suffix repeating)
- `(<type>,<type>,…)` tuples

`tools/build_selectors_json.py` already runs the **same** validator
(in Python) so the curation set never includes a text_sig the
firmware-side parser would reject.

Hard caps: 16 args, 32 entries in the arena, 8 levels of array/tuple
nesting. Any exceedance returns `None` from the parser, which the
caller treats as "fall back to Phase 1 behaviour".

## Sub-component 2 — Calldata walker

Standard Solidity ABI decoder, mirroring the layout used in
`erc20/calldata.rs`:

- Each static-typed arg consumes 32 bytes (one ABI word) at the
  current head offset.
- Each dynamic-typed arg (`bytes`, `string`, `T[]`, tuple-with-dynamic-
  inner) reads a 32-byte offset word at the head, jumps to that offset
  in the calldata, reads a 32-byte length, then reads the payload
  (padded to a 32-byte boundary).
- Address words MUST have their top 12 bytes zero. Bool words MUST be
  exactly `0x00…00` or `0x00…01`. uintN words MUST have their top
  `(32-N/8)` bytes zero (top-zero-bit check). Anything else returns
  `None`.

Implementation guidance: write the walker in two passes —

1. **Length / shape pass.** Compute the total expected static-head
   size, follow each dynamic offset, validate every offset and length
   is in range. Refuse on any overflow / out-of-range / unaligned hit.
   No bytes rendered yet.

2. **Render pass.** Iterate the validated arg list and emit display
   rows for each via the per-type renderers below.

Fault-injection hardening: keep the strict-shape check first, render
only after it passes. Any single-bit glitch that flips a `pass` flag
late in pass 2 is bounded by the page buffer's already-validated
geometry.

## Sub-component 3 — Per-type renderers

| Type | Render strategy |
|---|---|
| `uintN` | decimal via existing `write_eth_two_rows` / `write_gwei` helpers when the type is recognized as an amount; otherwise plain decimal with thousand separators. |
| `intN` | two's-complement decode → decimal with sign. |
| `address` | hex via existing `write_addr_full_or_name`, which already runs the `NameResolver` substitution path. |
| `bool` | literal "true" / "false". |
| `bytesN` | hex (0x-prefixed) on one row when `2N+2 <= DISPLAY_COLS`, else two rows. |
| `bytes` / `string` | length on row 1 ("len: 1234"), printable-ASCII preview on row 2 (first 14 chars + "…"), SHA-256 fingerprint on row 3 for cross-check against the dapp. |
| `T[]` | "[N items]" on row 1, "first: …" preview on row 2. |
| Tuples | recurse into a sub-page. |

All renderers are `no_std`, no-alloc, and write into pre-allocated
`row_mut(page, row)` buffers via the existing `display::primitives`
helpers.

## Cross-check pyramid

Phase 2 keeps every check Phase 1 already enforces:

1. Merkle proof against `SELECTOR_DB_ROOT` — bundle is vendor-curated.
2. `bundle.selector == calldata[0..4]` — the verified name applies to
   THIS calldata, not some other.

…and adds:

3. **Static-shape match:** the parsed type list's fixed head footprint
   plus every declared dynamic-section length must sum to exactly
   `calldata.len() - 4`. Any residual or shortfall → fall back to
   Phase 1's word dump with a "shape mismatch" banner row.

If (3) fails, do NOT silently render partial args. Always surface the
mismatch on screen so the user knows the function name they see is
the curated mapping for `0xa9059cbb` but the calldata payload doesn't
match the curated argument shape (a real risk: an attacker could craft
weird calldata that selectorically matches `transfer` but breaks ABI
shape, e.g. by appending junk bytes).

## Threat-model evolution

Phase 1 trusts the *name*. Phase 2 trusts the *types*. Both still
treat the contract as untrusted — neither attests semantics. The
remaining gap (e.g. a malicious contract that implements
`transfer(address,uint256)` with non-standard semantics) is closed
only by per-contract metadata, which is Phase 3 territory.

## Migration to per-contract attestation (Phase 3, not in scope here)

The natural next step is a fourth Merkle-rooted DB keyed on
`(chain_id, contract, selector)` carrying ERC-7730-flavoured display
rules: which arg is "amount" (with a decimals-OID into the existing
ERC-20 DB), which is "recipient" (eligible for `NameResolver`),
which display string to use for the function as a whole, etc.

This re-uses every primitive already in the codebase:
`merkle::verify_proof`, the bundle wire format, the gateway trailer
slot. The leaf encoding is just richer:

```text
chain_id      u64 LE
contract      [u8; 20]
selector      [u8; 4]
display_name  len-prefix ASCII
arg_hints     [ArgRole; n]   // 1 byte per arg
flags         u8
```

Curation source: hand-authored ERC-7730 v2 JSON files in
`secure/data/abi/<contract>.json`, flattened into the binary leaf by
a new `dbgen/src/abi.rs` module. The on-device parser stays a
fixed-shape binary reader — never a JSON parser.

When per-contract attestation fires, the BLIND SIGN banner is
replaced by a "VERIFIED CONTRACT — <display_name>" header. That's the
moment the wallet can drop the warning entirely for the covered
surface.

## Pointers into existing code (reuse, do not rewrite)

| Existing | Reuse for |
|---|---|
| `secure/src/erc20/calldata.rs::Erc20Call` | Per-selector strict decoder pattern; copy/specialize. |
| `secure/src/erc20/calldata.rs::decode_address_word`, `decode_u256_word` | Address top-12-zero gate, big-endian U256 decode. |
| `secure/src/tx/display/primitives::*` | All on-screen formatters (decimal, gwei, ETH, address-with-name, hex, calldata hash rows). |
| `secure/src/names/resolver::NameResolver::lookup` | (chain_id, address) → display name with two-phase wildcard match. |
| `secure/src/erc20/merkle::verify_proof` | If/when Phase 3 adds the per-contract DB. |
| `secure/src/selectors/bundle::SelectorMeta` | Already plumbed into `pick_sign_pages` and `render_blind_sign_pages`. |
| `secure/src/tx/display/blind_sign.rs` | Container for the new typed-args render path; the FUNCTION page from Phase 1 is the placeholder it replaces. |

## Out-of-scope risks worth flagging

- **Adversarial selector collisions.** Curation drops them at JSON
  time so the Merkle root only commits one canonical text_sig per
  selector. Any future expansion of the curation set must keep that
  invariant — re-running `tools/build_selectors_json.py` is the
  audit.
- **Root rotation across firmware versions.** The companion-app blob
  must hash-pin to the in-firmware `SELECTOR_DB_ROOT`. A wallet
  update that bumps the root needs a coordinated companion refresh.
  If we ever want to support a small ring of recent roots in secure
  flash, that's a one-line `db_roots.rs` extension (`pub static
  SELECTOR_DB_ROOTS: [[u8; 32]; N]`) plus a per-bundle root-index
  field.
- **Unknown types.** The Phase 2 parser falls back to raw-word render
  on any out-of-whitelist type. That's safe (never panics, always
  shows raw bytes plus the function NAME) but means coverage is a
  curation knob — adding `int128` / a new fixed-bytesN / a tuple-of-
  arrays etc. must be done in lockstep across the Python validator
  and the firmware-side parser.

## Verification checklist for Phase 2

- [ ] Round-trip test: every `secure/data/selectors.json` row whose
      `text_sig` parses (per Python validator) parses identically by
      the firmware-side parser. Add to `cargo test -p sphincs-tz-secure`.
- [ ] Negative ABI test: malformed calldata (bad address pad, length
      shortfall, offset overflow) is rejected by the shape check
      before any arg is rendered.
- [ ] Display fixture: extend `make e2e` Scenario 5b to assert the
      typed render appears (via `ui-capture` SHA-256 page fingerprint
      golden files).
- [ ] No code in Phase 2 calls into NS rodata for the selectors
      blob — the bundle remains the only source of the text_sig.
