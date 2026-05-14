# Handoff — ERC-7730 / ERC-8213 Clear-Signing, Phase 3 (wire format + walker)

Date written: 2026-05-14. Last firmware status: Phase 1 + 2 complete on `master`.

This is the "start here" doc for the next implementer (human or future Claude session) picking up Phase 3 of the clear-signing initiative. The full implementation plan now lives at `~/.claude/plans/carefully-read-understand-this-transient-feigenbaum.md` as a **5-phase** roadmap (consolidated 2026-05-14 from the original 9). Phase 2's handoff is at `docs/handoff-erc7730-phase2.md`; read it for the IR layout and host pipeline details — both are inputs to Phase 3 and must not drift.

## Why we're doing this

Phase 1 shipped the on-device IR parser + Merkle bundle verifier + context-binding cross-check in `pqsigner-erc7730/`. Phase 2 shipped the host-side IR compiler (`dbgen::erc7730`), the seed corpus under `secure/data/erc7730/`, the catalog blob at `tools/companion-stub/erc7730_db.bin`, and the firmware-pinned `ERC7730_DESCRIPTORS_ROOT` in `secure/src/db_roots.rs`.

The firmware now *knows* what to verify against, but nothing on the sign path actually invokes that machinery yet. Phase 3 wires the trailer end-to-end: the companion ships `[ir_len(2) || ir || leaf_idx(4) || proof_depth(4) || proof]` in a new sign-input slot; the secure-world dispatcher parses it, calls `pqsigner_erc7730::bundle::verify_erc7730_bundle` against the pinned root, runs the binding cross-check, fleshes out the **walker** (the path-bytecode interpreter — currently a Phase-1 stub), and exposes a `VerifiedDescriptor` handle for Phase 4's renderer.

End state of Phase 3: a Tether USDT transfer signed through QEMU produces a secure-world log line proving the descriptor was matched, verified, and walked — *without* rendering pages yet. Phase 4 picks up at the renderer.

## Architectural choices already locked

These are inherited from Phases 1 + 2 and are NOT up for debate:

1. **No on-device ERC-8176 verification** (preserves invariant #5). 8176 enforcement is host-only via `secure/data/erc7730/policy.toml`. See Phase 2 handoff §"Why we're doing this".
2. **Hybrid distribution.** The firmware pins `ERC7730_DESCRIPTORS_ROOT` (32 B); the companion ships per-tx IR + Merkle proof. Updates rotate via signed firmware (SPHINCS+C10).
3. **134-byte big-endian IR header.** Frozen wire format. The Phase 1 parser at `pqsigner-erc7730/src/ir.rs` is canonical; Phase 2 emits it byte-for-byte; **Phase 3 must not alter it**. Bumping `SCHEMA_VER` would invalidate every entry in the host pipeline's checked-in `erc7730_db.bin`.
4. **The catalog blob format and `ERC7730_DESCRIPTORS_ROOT` are also frozen.** Phase 3 consumes them; do not change them. See `dbgen/src/erc7730.rs` module doc for the on-disk shape.
5. **Sign-input wire format extensions are the **only** way to ship ERC-7730 data to the secure world.** No new NSC command; the existing `CMD_SIGN_USEROP` / `CMD_SIGN_USEROP_BATCH` / `CMD_SIGN_OFFCHAIN` paths grow a new trailer slot.

## What Phases 1 + 2 already shipped

### Phase 1 (`pqsigner-erc7730/`, committed `d6beefb`)

| File | Purpose | Phase 3 status |
|------|---------|----------------|
| `src/ir.rs` | Zero-copy IR header parser, opcode enums, caps | **untouched** (frozen) |
| `src/bundle.rs` | `verify_erc7730_bundle(&[u8], &[u8;32]) -> VerifiedDescriptor` | **untouched** (Phase 3 just calls it) |
| `src/binding.rs` | `cross_check_contract` / `cross_check_eip712` | **untouched** (Phase 3 just calls it) |
| `src/walker.rs` | Path-bytecode interpreter — **STUB** | **Phase 3 fleshes out** |
| `src/abi.rs` | Thin surface over `secure::tx::typed_call::abi` — **STUB** | **Phase 3 fleshes out** |

### Phase 2 (host pipeline, committed 2026-05-14)

- `dbgen/src/erc7730.rs` (~1300 LOC) — JSON → IR compiler, JCS canonicaliser, ERC-8176 policy gate, per-deployment IR emission.
- `dbgen/src/lib.rs` — `dbgen` is now bin+lib so tests reach `dbgen::erc7730::*`.
- `dbgen/tests/erc7730_roundtrip.rs` — 5 integration tests; round-trips every IR back through the on-device verifier.
- `secure/data/erc7730/{policy.toml, *.json}` — 8 self-contained seed descriptors.
- `secure/data/erc7730-e2e/*.json` — small e2e variant (WETH + USDT only).
- `tools/companion-stub/erc7730_db.bin` — 10,919 B catalog (20 leaves; prod root `0x4b8adb…8ff3`).
- `tools/companion-stub/erc7730_db_e2e.bin` — 1,444 B (4 leaves; e2e root `0x43243e…c15f`).
- `secure/src/db_roots.rs` — `ERC7730_DESCRIPTORS_ROOT` (cfg-gated for prod/e2e).
- `xtask` `gen-erc7730-descriptors [--check]` subcommand + `make check-erc7730-descriptors` CI gate.

**Treat all Phase 2 outputs as inputs.** If `cargo run -p dbgen` no longer emits byte-identical artifacts after your Phase 3 work, you've introduced drift — `make check-erc7730-descriptors` will catch it.

## Canonical wire formats Phase 3 owns

### 1. The new sign-input trailer slot

Existing sign-input trailers (in order, post Phase 3) sitting between the inner tx and the address-name bundles:

```
erc20 → zk_v1 → zk_v3 → safe_v1 → selector → self_attest → erc7730 (NEW) → names
```

Wire framing: same `[u16 BE len][payload]` pattern as every other trailer. `len == 0` means absent. Implemented via the existing `secure/src/nsc/trailer::read_optional_u16_prefixed` helper.

The payload itself is exactly what `pqsigner_erc7730::bundle::verify_erc7730_bundle` expects (this is already frozen in Phase 1):

```text
  ir_len        u16 BE                  (2 B)
  ir            [u8; ir_len]            (≤ MAX_IR_LEN = 4096)
  leaf_index    u32 BE                  (4 B)
  proof_depth   u32 BE                  (4 B)
  proof         [u8; proof_depth * 32]  (≤ 32 × 32 = 1024 B)
```

Cap: `MAX_ERC7730_BUNDLE_LEN = 2 + 4096 + 4 + 4 + 32 * 32 = 5130` bytes (defined in `pqsigner-erc7730/src/bundle.rs`).

### 2. The `OFFCHAIN_KIND_EIP712_TYPED = 2` payload

Adds a third `kind` to `CMD_SIGN_OFFCHAIN` (existing kinds are `RAW32 = 0` and `PERSONAL_SIGN = 1`, defined in `proto/src/lib.rs:912-913`). New layout:

```text
  domainSep_present  u16 BE (1 = present, 0 = absent)
  domainSeparator    [u8; 32]   (only when domainSep_present == 1)
  primaryTypeHash    [u8; 32]
  encoded_data_len   u16 BE
  encoded_data       [u8; encoded_data_len]
  trailer            (same ERC-7730 trailer layout as above)
```

Cross-check at parse time:
- `verify_erc7730_bundle(trailer, &ERC7730_DESCRIPTORS_ROOT)` against the firmware-pinned root.
- `cross_check_eip712(&ir, domain.chainId, &domain.verifyingContract, &domainSeparator)` against the descriptor's binding.

**The `domainSeparator` MUST be the value the companion supplied in the new field, NOT recomputed in the secure world** — the descriptor's `domain_separator` slot was computed host-side from the same domain at host build time, and the cross-check binds them. (See "Open questions" — recomputation is reasonable defense-in-depth that future hardening can revisit; not needed for soundness given the cross-check.)

### 3. New proto constants

In `proto/src/lib.rs`:

```rust
pub const ERC7730_TRAILER_VERSION: u8 = 0x01;
pub const ERC7730_IR_MAX: usize = 4096;
pub const ERC7730_PROOF_MAX_DEPTH: usize = 32;
pub const ERC7730_MAX_TRAILER_LEN: usize =
    2                           // ir_len prefix
    + ERC7730_IR_MAX
    + 4 + 4                     // leaf_index + proof_depth
    + ERC7730_PROOF_MAX_DEPTH * 32;
pub const OFFCHAIN_KIND_EIP712_TYPED: u8 = 2;
```

These get pulled into Solidity via `xtask gen-solidity-constants` if any Solidity caller eventually references them — for now they're firmware-internal. The CI `--check` diff must still pass.

## Phase 3 — what to build

### 3.1 — `proto/src/lib.rs` constants (≈30 min)

Add the constants above. Bump aggregate `MAX_SIGN_INPUT_LEN` (or whatever the codebase calls the aggregate sign-input cap — grep for the existing `SNAP_LEN` definition in `secure/src/nsc/cmd_sign_userop.rs:95`; the proto-side aggregate is conceptually the same value).

### 3.2 — `cmd_sign_userop.rs` trailer parse (≈half day)

Edit `secure/src/nsc/cmd_sign_userop.rs`:

1. **Grow `SNAP_LEN`** (line 95): add a `+ 2 + ERC7730_MAX_TRAILER_LEN` term to the constant. The trailer slot sits between `self_attest` (line 102: `+ 2 + MAX_SELF_ATTEST_BUNDLE_LEN`) and `names` (line 103: `+ 1 + MAX_NAME_BUNDLES * (2 + MAX_NAME_BUNDLE_LEN)`).
2. **Parse the trailer** between line 427 (`cursor = self_attest_trailer.next_cursor;`) and line 429 (`// ── 5b. Optional address-name bundles ───`):

```rust
// 5a-quinquies. Optional ERC-7730 clear-signing descriptor trailer.
//
// Wire layout: `[u16 BE len][payload]`, where payload is the trailer
// format documented in `pqsigner_erc7730::bundle`:
//   ir_len(2) || ir || leaf_index(4) || proof_depth(4) || proof
//
// Verified inline against the firmware-pinned `ERC7730_DESCRIPTORS_ROOT`
// (Phase 2 emits the root via `dbgen`). Cross-checked against
// `(chain_id, to_address)` so a hostile companion cannot pair a USDC
// descriptor with a transfer to an attacker-controlled contract.
//
// Sits BEFORE the names section so the names `[count:u8]` framing
// remains the very last thing in the payload.
let erc7730_trailer = match super::trailer::read_optional_u16_prefixed(
    snap,
    cursor,
    total_len,
    ERC7730_MAX_TRAILER_LEN,
    "bad erc7730 trailer",
) {
    Ok(t) => t,
    Err(s) => return s,
};
cursor = erc7730_trailer.next_cursor;

// Verify + bind only when present.
let erc7730_verified: Option<VerifiedDescriptor<'_>> = if erc7730_trailer.len > 0 {
    let bytes = &snap[erc7730_trailer.start..erc7730_trailer.start + erc7730_trailer.len];
    match pqsigner_erc7730::bundle::verify_erc7730_bundle(
        bytes,
        &crate::db_roots::ERC7730_DESCRIPTORS_ROOT,
    ) {
        Ok(v) => {
            if let Err(_e) = pqsigner_erc7730::binding::cross_check_contract(
                &v.ir,
                chain_id,
                &to_address,
            ) {
                ui::show_status("Sign", "7730 binding fail");
                return NscStatus::InvalidPointer as u32;
            }
            Some(v)
        }
        Err(_e) => {
            ui::show_status("Sign", "7730 bundle fail");
            return NscStatus::InvalidPointer as u32;
        }
    }
} else {
    None
};
```

3. **Thread `erc7730_verified` through to `pick_sign_pages`** (Phase 4 will consume it; for now just stash it on the stack and log on the way to `confirm()`):

```rust
#[cfg(feature = "debug-log")]
if let Some(v) = erc7730_verified.as_ref() {
    secure_log!(
        "[ERC-7730] matched: chain={} contract=0x{} ir_len={} owner={:?} contract_name={:?}",
        v.ir.chain_id,
        hex::encode(v.ir.contract),
        v.ir.raw.len(),
        core::str::from_utf8(v.ir.owner).unwrap_or("?"),
        core::str::from_utf8(v.ir.contract_name).unwrap_or("?"),
    );
}
```

This is enough for the Phase 3 smoke test; Phase 4 swaps the log for the renderer call.

### 3.3 — `cmd_sign_userop_batch.rs` per-inner-tx trailer (≈half day)

The batch path (`secure/src/nsc/cmd_sign_userop_batch.rs`) already supports per-inner-tx trailers (ERC-20, selector, self-attest, names). Add the ERC-7730 trailer to the per-tx loop using the same shape as 3.2. Verify each one independently — a batch with one valid descriptor and one absent slot must succeed; a batch with one mismatched binding must reject the whole batch (mirror the existing `selector_trailer` mutual-exclusion / error-propagation pattern).

### 3.4 — `cmd_sign_offchain.rs` EIP-712 typed kind (≈1 day)

Edit `secure/src/nsc/cmd_sign_offchain.rs`:

1. Import `OFFCHAIN_KIND_EIP712_TYPED` from proto (line 46 grouping).
2. Extend the parse dispatch (line 157+):

```rust
OFFCHAIN_KIND_EIP712_TYPED => {
    // Payload layout (after the 17-byte header at offset 16):
    //   [domainSep_present(2)][domainSeparator(32) if present]
    //   [primaryTypeHash(32)][encoded_data_len(2)][encoded_data][trailer]
    let mut p = body_start;
    let domain_sep_present = u16::from_be_bytes([snap[p], snap[p + 1]]) != 0;
    p += 2;
    let mut domain_separator = [0u8; 32];
    if domain_sep_present {
        domain_separator.copy_from_slice(&snap[p..p + 32]);
        p += 32;
    } else {
        ui::show_status("Sign", "7730 missing ds");
        return NscStatus::InvalidPointer as u32;
    }
    let mut primary_type_hash = [0u8; 32];
    primary_type_hash.copy_from_slice(&snap[p..p + 32]);
    p += 32;
    let encoded_data_len = u16::from_be_bytes([snap[p], snap[p + 1]]) as usize;
    p += 2;
    let encoded_data = &snap[p..p + encoded_data_len];
    p += encoded_data_len;

    // The trailer is the rest of the payload (length-prefixed, same
    // `read_optional_u16_prefixed` shape).
    // ... verify + bind via cross_check_eip712 ...
}
```

3. Cross-check via `pqsigner_erc7730::binding::cross_check_eip712(&ir, dom.chain_id, &dom.verifying_contract, &domain_separator)`.
4. For Phase 3, log the match (no renderer yet). Phase 4 wires this into a real Pages object.

### 3.5 — `nonsecure/src/usb/commands.rs` buffer bump (≈15 min)

Bump `CHAIN_BUF_LEN_SIGN` (`nonsecure/src/usb/commands.rs:42`) to include the new trailer slot. The constant is a sum of all sign-input slots — add `2 + ERC7730_MAX_TRAILER_LEN`. The aggregate `CHAIN_BUF_LEN` (line 70) is the max across SIGN/BATCH/FW so it bumps automatically.

### 3.6 — `xtask gen-solidity-constants` drift check (≈10 min)

If you've added Solidity-facing constants (probably not, since ERC-7730 is firmware-internal), regenerate the Solidity library. Otherwise the existing `xtask gen-solidity-constants --check` should still pass — verify it does.

### 3.7 — Walker (`pqsigner-erc7730/src/walker.rs`) (≈2 days, the heart of Phase 3)

The Phase 1 stub returns `IrError::BadField` unconditionally. Replace it with a real interpreter. Reference inputs:

- **Path program bytes** in `ir.pool[path_off]`: `[u8 program_len][PathOp_byte][args]...`. Phase 2's emitter is the canonical writer; see `dbgen/src/erc7730.rs::compile_path` for the byte layout. Operands:
  - `0x10 RootStructured` — no args (calldata head root)
  - `0x11 RootContainer` — no args (tx envelope root: `@.value`, `@.to`, …)
  - `0x12 RootMetadata` — no args (descriptor metadata pool root: `$.metadata.…`)
  - `0x20 FieldIdx` — 2-byte BE field index into the current parent's field list
  - `0x21 ArrayIdx` — 4-byte BE array index
  - `0x22 ArraySlice` — 4-byte BE start + 4-byte BE end
  - `0x23 ArrayLast` — no args
  - `0x24 ArrayAll` — no args

- **`AbiView`** in `pqsigner-erc7730/src/abi.rs` (currently a stub holding `body: &[u8]`). Replace with a richer struct that pairs the calldata body with a caller-supplied ABI shape. Keep the surface generic — the walker should NOT depend on `secure/src/tx/typed_call/`. Instead, the secure-side caller assembles an `AbiView` with the shape it derived (probably via `secure::tx::typed_call::abi::walk_shape`) and hands it to the walker.

- **Container envelope** (`@`): expose `Eip1559Tx` fields (`value`, `to`, `from`, `chainId`) and the AA UserOp envelope. The Phase 1 stub doesn't model this; add a `ContainerView` companion to `AbiView` (or fold both into a `WalkerCtx`).

- **Metadata pool** (`$`): the IR's `pool` slice IS the metadata pool. `$.metadata.constants.X` references resolve at compile time (Phase 2 inlines them as TLV payloads) — the walker likely doesn't need `$` at runtime in Phase 3.

Implementation sketch:

```rust
pub fn resolve<'a>(
    ir: &Erc7730Ir<'a>,
    ctx: &WalkerCtx<'a>,           // container + ABI body + shape
    path_off: u16,
) -> Result<AbiValue<'a>, IrError> {
    let pool = ir.pool;
    let off = path_off as usize;
    let prog_len = *pool.get(off).ok_or(IrError::BadField)? as usize;
    let prog = pool.get(off + 1..off + 1 + prog_len).ok_or(IrError::BadField)?;
    let mut cur = Cursor::root(ctx);     // typestate: nothing-selected yet
    let mut p = 0;
    while p < prog.len() {
        let op = PathOp::try_from(prog[p])?;
        p += 1;
        match op {
            PathOp::RootStructured => cur.enter_structured()?,
            PathOp::RootContainer  => cur.enter_container()?,
            PathOp::RootMetadata   => cur.enter_metadata(ir)?,
            PathOp::FieldIdx => {
                let idx = u16::from_be_bytes([prog[p], prog[p+1]]);
                p += 2;
                cur.descend_field(idx)?;
            }
            PathOp::ArrayIdx => {
                let idx = u32::from_be_bytes(prog[p..p+4].try_into().map_err(|_| IrError::BadField)?);
                p += 4;
                cur.descend_array_idx(idx)?;
            }
            PathOp::ArraySlice => { /* … */ }
            PathOp::ArrayLast  => cur.descend_array_last()?,
            PathOp::ArrayAll   => cur.descend_array_all()?,
        }
    }
    cur.into_value()
}
```

Write unit tests in `pqsigner-erc7730/tests/walker.rs` covering:
- Top-level field selection (`#._value` for USDT transfer)
- Nested struct field (`#.params.amountIn` for Uniswap exactInputSingle)
- Container access (`@.value` for WETH `deposit()`)
- Array indexing + slicing (synthetic test data — none of the seed corpus uses these today but the walker has to support them)

Drive every path program in every seed-corpus IR through the walker once (the round-trip integration test can be extended for this).

### 3.8 — Companion-side trailer builder (≈half day)

Add `tools/companion-stub/erc7730_trailer.py` — minimal Python helper that:
1. Loads `tools/companion-stub/erc7730_db.bin`.
2. Looks up `(chain_id, contract_addr)` via binary search on the 72-byte entry array (see `dbgen/src/erc7730.rs` module doc for the byte layout).
3. Emits the byte-for-byte trailer the secure world expects.

This is the dev-only "stand-in" companion. The real companion app (Phase 5) will provide a richer surface. For Phase 3 it's enough to drive `make e2e`.

### 3.9 — Fuzz target (≈half day)

Add `fuzz/fuzz_targets/erc7730_ir_parse.rs` mirroring `fuzz/fuzz_targets/tx_erc20_verify_bundle.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use pqsigner_erc7730::bundle::verify_erc7730_bundle;

fuzz_target!(|data: &[u8]| {
    let _ = verify_erc7730_bundle(data, &[0u8; 32]);
});
```

Followup target for the walker: feed in arbitrary bytes as a path program and check that `resolve` neither panics nor over-reads `ir.pool`. The shape of that target depends on the final walker API.

CI target: `cargo +nightly fuzz run erc7730_ir_parse -- -max_total_time=86400` (24-hour soak); expect zero crashes / OOMs / hangs.

### 3.10 — `make e2e` ERC-7730 smoke step (≈half day)

Add an `erc7730-smoke` step to `make e2e`:
1. Use the Phase 3.8 companion stub to produce a trailer for Tether USDT `transfer(address,uint256)` on chain 1.
2. Drive `cmd_sign_userop` through QEMU with that trailer attached.
3. Assert the secure-world log contains `"[ERC-7730] matched: chain=1 contract=0xdac1…ec7"` plus a walker-evaluated value for one path.

## Where to look in existing code

- **`pqsigner-erc7730/src/{ir,bundle,binding}.rs`** — the Phase 1 surface Phase 3 calls. Do NOT modify.
- **`pqsigner-erc7730/src/{walker,abi}.rs`** — the Phase 1 stubs Phase 3 fleshes out.
- **`secure/src/nsc/cmd_sign_userop.rs:85-476`** — the dispatcher you're editing. Trailer parsing block lives at lines 249-476; new ERC-7730 trailer slots in between lines 427 and 429.
- **`secure/src/nsc/trailer.rs`** — the `read_optional_u16_prefixed` helper. Use as-is.
- **`secure/src/nsc/cmd_sign_userop_batch.rs`** — same shape, per inner tx. Section comments mirror `cmd_sign_userop.rs`.
- **`secure/src/nsc/cmd_sign_offchain.rs`** — three kinds today (RAW32, PERSONAL_SIGN); add a fourth.
- **`secure/src/tx/typed_call/abi.rs`** — the ABI shape walker the secure-side caller uses to build `AbiView`. Phase 3 walker code does NOT depend on it directly (keep `pqsigner-erc7730` typed_call-free), but the caller in `secure/` does.
- **`secure/src/db_roots.rs`** — `ERC7730_DESCRIPTORS_ROOT` lives here, cfg-gated for prod/e2e. Just consume it.
- **`proto/src/lib.rs:912-913`** — existing `OFFCHAIN_KIND_*` constants. Add `OFFCHAIN_KIND_EIP712_TYPED = 2` here.
- **`nonsecure/src/usb/commands.rs:42-71`** — `CHAIN_BUF_LEN_SIGN` cascade. Just bump the leaf constant.
- **`dbgen/src/erc7730.rs`** — Phase 2's emitter. Reference it whenever you need to confirm a wire-format detail (it's the authoritative byte-layout source for everything Phase 3 parses).
- **`fuzz/fuzz_targets/tx_erc20_verify_bundle.rs`** — the fuzz-target shape to mirror.

## Common gotchas

1. **Endianness flip — again.** ERC-7730 IR header uses BE. The catalog blob header (which Phase 3 does *not* read on-device, only the host does) uses LE. The other on-device trust DBs (ERC-20 / Names / Selectors) use LE everywhere. Don't paste `u16::from_le_bytes` calls verbatim into the ERC-7730 parser; the bundle's `ir_len` / `leaf_index` / `proof_depth` are all BE per `pqsigner-erc7730/src/bundle.rs`. (Phase 1 already has the parser correct; just don't change it.)

2. **The companion-supplied `domainSeparator` is the source of truth for the EIP-712 typed kind.** The descriptor's `domain_separator` slot was computed host-side at build time from the same domain fields, and `cross_check_eip712` enforces equality. Recomputing in the secure world from the deserialized `domain` would add cost without changing soundness because the IR is firmware-pinned. If a future phase wants belt-and-braces, that's fine but not Phase 3.

3. **`primaryTypeHash` is the *first 4 bytes* of the format-table selector slot, not a full 32-byte typehash** (per Phase 1's 4-byte selector reservation for the EIP-712 case). The walker dispatches on the full primary-type hash the companion supplies, then locates the matching format inside the IR by comparing those 4 bytes. Collision risk: 2^-32 within the ≤16 formats per descriptor, which is fine for selecting a renderer (the actual cryptographic binding is via the domain separator, not the format-table key).

4. **`SNAP_LEN` is the cap on the entire sign input.** Bump it carefully — it's a `[u8; SNAP_LEN]` `static mut` (line 143 of cmd_sign_userop.rs), so you're growing the secure-world's payload-snapshot buffer. The current value is well under 32 KiB; adding ~5 KiB for the ERC-7730 trailer is fine.

5. **`erc7730_trailer.len == 0` is legal.** Legacy callers that never grow their NS code still produce a zero-trailer sign request. The secure world just sees `erc7730_verified == None` and falls through to the existing display path.

6. **Mutual-exclusion semantics.** Selector / self-attest / ERC-7730 are NOT mutually exclusive on the wire — they can all be present (the renderer in Phase 4 picks the best one per the priority ladder). The existing selector / self-attest mutual-exclusion check at line 600 is between *those two*, not against ERC-7730.

7. **`cross_check_contract` takes `tx.chain_id` and `tx.to`, NOT the values from the IR.** The whole point is to bind the IR to the actual transaction. If you accidentally pass `ir.chain_id` and `ir.contract` you've degraded the check to a tautology.

8. **EIP-712 typed-data offchain mode: `domain.chainId` is the *signing* chain id, not the user-op chain id.** For Phase 3, that's fine because `CMD_SIGN_OFFCHAIN` doesn't carry a user-op chain id at all (it's a pure typed-data sign). For Phase 4+ that wants to render `@.chainId` on EIP-712 paths, this is the value to use.

9. **The walker MUST be `no_std` + no-heap + no-alloc.** Same constraints as the rest of `pqsigner-erc7730`. The on-device path resolves into a single `AbiValue<'a>` borrowing from caller buffers. Don't introduce a `Vec` even temporarily.

10. **Phase 4 reads the walker output.** Whatever surface you commit to (`WalkerCtx`, `AbiView`, `ContainerView`), Phase 4 will wire it into per-formatter renderers. Keep it small + stable; future-proof one optional callback for `$.metadata.…` resolution and call it done.

## Verification recipe for Phase 3

When you think Phase 3 is done:

```bash
# 1. Walker + parser unit tests
cargo test -p pqsigner-erc7730 --tests

# 2. Round-trip integration test (still green from Phase 2)
cargo test -p dbgen --test erc7730_roundtrip

# 3. Full secure-crate test suite — no regression
cargo test -p sphincs-tz-secure --tests --no-default-features \
    --features mock-se,debug-log,ui-semihosting

# 4. Cross-compile clean for the firmware target
cargo build -p pqsigner-erc7730 --target thumbv8m.main-none-eabi
cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi \
    --no-default-features --features dual-se,ui-oled,stm32u585,debug-log

# 5. End-to-end smoke: drive a USDT.transfer with an ERC-7730 trailer
#    through QEMU. Secure-world log should show the match + a walker
#    value for `#._value`.
make e2e

# 6. Codegen drift check (incl. ERC-7730 host pipeline)
make check-erc7730-descriptors
cargo run -q -p pqsigner-xtask -- gen-solidity-constants --check

# 7. Fuzz target compiles cleanly + 1-minute smoke
cargo +nightly fuzz run erc7730_ir_parse -- -max_total_time=60
# Then the 24-hour CI soak target separately.
```

Then add a row to `docs/work-todo.md`'s Completion Log: `YYYY-MM-DD — Phase 3: ERC-7730 sign-input trailer + walker + EIP-712 typed-data offchain extension`.

## What Phase 4+ will need from Phase 3

- **A `VerifiedDescriptor<'_>` on the secure-world stack** at the point `pick_sign_pages` is called, threaded through from the trailer-parse block. Phase 4's renderer entry point is `try_render_erc7730_pages(tx, &VerifiedDescriptor, resolver)`.
- **A stable walker API** that takes `(ir, ctx, path_off) -> Result<AbiValue, IrError>`. Phase 4 calls it once per field per format.
- **`Erc7730Ir::format_iter()` (or similar)** — a way to iterate the formats table to pick the one matching `tx.calldata[..4]` (contract context) or the supplied `primary_type_hash` (EIP-712 context). The Phase 1 `format_count()` is a hint but doesn't return the entries; Phase 3 should add a small iterator.
- **`AbiValue` to display-page bridge** — Phase 4 owns that; Phase 3 just needs `AbiValue` to carry enough type info (it already does: `Uint{bits, be32}`, `Int{bits, be32}`, `Address`, `Bool`, `BytesN`, `Bytes`, `String`).
- **For EIP-712**: `cross_check_eip712` already binds the domain separator. The renderer needs `ir.domain_separator`, `ir.context_kind`, and the resolved AbiValues — all available after Phase 3.

## Open questions intentionally left to Phase 3

- **EIP-712 selector slot widening.** Phase 1's format header reserves 4 bytes for a selector; Phase 2 uses the first 4 bytes of the primary-type hash. Phase 3+ may decide to widen the slot to a full 32-byte typehash via a discriminator byte. Decision deferred — for the seed corpus, 4-byte discriminators have no collisions across the ≤16 formats per descriptor.
- **`AbiView` shape for the walker.** Two design options (see Phase 3.7):
  - (a) Pre-decode ABI shape in `pqsigner-erc7730/src/abi.rs` based on the format-key signature stored implicitly via FieldIdx indices.
  - (b) Have the caller (in `secure/`) build an `AbiView` from `secure::tx::typed_call::abi::walk_shape` and hand it to the walker.
  - Recommendation: (b) — keeps `pqsigner-erc7730` free of typed_call dependency, lets future hosts plug different ABI parsers.
- **`$ref` cycles + `includes` resolution.** Phase 2 rejects `includes`; Phase 3 doesn't need to revisit. Phase 5 / future-phase work will land cycle detection at host build time.
- **Stack depth for nested calldata.** Phase 4's renderer is the consumer; Phase 3 walker doesn't recurse on calldata (that's a formatter concern). But the walker DOES need to handle deeply-nested structs / arrays — cap at `MAX_NESTING = 8` (defined in `pqsigner-erc7730/src/ir.rs:59`).
- **Domain separator recomputation.** See gotcha #2. Phase 3 trusts the cross-check. Phase 5's audit-grade polish may add FI-hardened recomputation.

## Plan-file pointer

The full plan (5 phases, ≈6.5-week total roadmap, verification recipes, risks) lives at:

```
~/.claude/plans/carefully-read-understand-this-transient-feigenbaum.md
```

If something here disagrees with the plan, the plan is authoritative for *intent*; this handoff is authoritative for *what Phase 1 + 2 actually shipped*. Update one or the other if you find drift.

## References

- Phase 2 handoff (input invariants): `docs/handoff-erc7730-phase2.md`
- Clear Signing announcement (2026-05-12): <https://clearsigning.org> · <https://blog.ethereum.org/2026/05/12/clear-signing-announcement>
- ERC-7730 spec: <https://eips.ethereum.org/EIPS/eip-7730>
- ERC-7730 registry: <https://github.com/ethereum/clear-signing-erc7730-registry>
- ERC-7730 v2 schema: <https://raw.githubusercontent.com/ethereum/clear-signing-erc7730-registry/master/specs/erc7730-v2.schema.json>
- ERC-8176 (Magicians thread): <https://ethereum-magicians.org/t/erc-8176-integrity-verification-for-erc-7730/27911>
- ERC-8213 (Magicians thread): <https://ethereum-magicians.org/t/erc-8213-wallet-signature-and-calldata-digest-display/24295>
- Cyfrin clearsig (Python reference): <https://github.com/Cyfrin/clearsig>
