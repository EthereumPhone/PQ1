# Handoff — ERC-7730 / ERC-8213 Clear-Signing, Phase 2 (host DB pipeline)

Date written: 2026-05-14. Last firmware status: Phase 1 complete, on `master`.

This is the "start here" doc for the next implementer (human or future Claude session) picking up Phase 2 of the clear-signing initiative. The full implementation plan lives at `~/.claude/plans/carefully-read-understand-this-transient-feigenbaum.md`; this handoff focuses on what Phase 2 needs to do, where the seams already are, and what *not* to redo.

## Why we're doing this

On **2026-05-12** the Ethereum Foundation, through its Trillion Dollar Security Initiative, launched the Clear Signing standard at <https://clearsigning.org>. Three ERCs:

- **ERC-7730** — JSON descriptor format that turns opaque calldata / EIP-712 structs into human-readable intent
- **ERC-8176** — RFC 8785 JCS-canonicalised + keccak256-of-descriptor, signed by EIP-191 (EOA) or ERC-1271 attesters
- **ERC-8213** — short reproducible fingerprints (calldata digest, EIP-712 final hash) for cross-device verification

PQSigner already does its own clear-signing (CowSwap EIP-712 v3 Groth16-attested, Safe v1, Phase-2 typed-call ABI decoder, ERC-20 / selector / name Merkle bundles). ERC-7730 lets us cover the long tail of the registry (Aave, Compound, Lido, Curve, OpenSea, EAS, Permit2, Uniswap V3, etc.) by ingesting community-curated descriptors rather than hand-writing per-protocol Rust + circuits.

## Architectural choices already locked

These are not up for debate — the user confirmed them on 2026-05-14 and Phase 1 was built around them:

1. **No on-device ERC-8176 verification.** Preserves invariant #5 ("no classical signer anywhere"). 8176 is enforced *at the host build pipeline* — only descriptors that pass policy enter the firmware-pinned Merkle root. **Phase 2 owns this policy enforcement.**
2. **Hybrid distribution.** Firmware pins a 32-byte `ERC7730_DESCRIPTORS_ROOT`; companion ships per-tx IR + Merkle proof in a new trailer slot. Updates rotate via signed firmware (already SPHINCS+C10).
3. **Full 7730 + 8213 in one push.** Every formatter, container value, nested calldata, EIP-712 typed-data binding. ERC-8213 fingerprint pages on every sign path. (8176 = host-only as per #1.)

## What Phase 1 already shipped

Phase 1 landed on `master` (uncommitted as of this writing — verify with `git status`). Key artifacts:

### New workspace crate: `pqsigner-erc7730/`

Pure-logic, `no_std`, no heap, cross-compiles for `thumbv8m.main-none-eabi`.

| File | Purpose | Status |
|------|---------|--------|
| `Cargo.toml` | depends on `pqsigner-tx` (for the shared Merkle `verify_proof`) + `sha2` | done |
| `src/lib.rs` | crate doc, module decls | done |
| `src/ir.rs` | `Erc7730Ir<'a>` zero-copy header parser, opcode enums, caps | done — 11 tests |
| `src/bundle.rs` | `verify_erc7730_bundle(&[u8], &[u8;32]) -> Result<VerifiedDescriptor, BundleError>` | done — 7 tests |
| `src/binding.rs` | `cross_check_contract` / `cross_check_eip712` | done — 7 tests |
| `src/walker.rs` | path-bytecode interpreter — **STUB**, returns `Err(BadField)` | Phase 5 |
| `src/abi.rs` | thin surface over `pqsigner-tx::typed_call::abi` — **STUB** | Phase 5 |

Tests: 24 passing locally (`cargo test -p pqsigner-erc7730`). Secure-crate tests still all 118 pass (`cargo test -p sphincs-tz-secure --tests`). Crate cross-compiles to `thumbv8m.main-none-eabi`.

### Secure-side shim: `secure/src/tx/erc7730.rs`

Pure `pub use` re-export over the workspace crate, same pattern as `secure/src/erc20/mod.rs` re-exporting `pqsigner-tx::erc20`. Added to `secure/src/tx/mod.rs` and `secure/Cargo.toml`. Existing call sites can use `crate::tx::erc7730::*` without ever naming the workspace crate.

### Workspace registration

`Cargo.toml` lists `pqsigner-erc7730` under `members` and exposes it under `[workspace.dependencies]` as `pqsigner-erc7730 = { path = "pqsigner-erc7730" }`.

## The on-device IR layout (CANONICAL — Phase 2 host pipeline MUST match)

This is the byte-for-byte layout the host compiler must emit. The on-device parser in `pqsigner-erc7730/src/ir.rs` is the canonical reader; **drift = silent integrity failure**, so any change to the layout MUST be coordinated with the parser and the IR `SCHEMA_VER` byte bumped.

### Header — 134 bytes, fixed

```
off  size  field                  notes
  0    1  schema_ver             0x01 (constant for IR v1)
  1    1  context_kind           0x01 = contract, 0x02 = EIP-712
  2    8  chain_id (u64 BE)      for EIP-712: domain.chainId
 10   20  contract               for EIP-712: domain.verifyingContract
 30   32  descriptor_hash        sha256 of JCS-canonicalised source JSON
                                 (same as the ERC-8176 hash — useful for
                                 cross-device sanity, NOT verified on-device)
 62   32  domain_separator       EIP-712 only; MUST be all-zero for contract ctx
                                 (parser rejects non-zero in contract ctx)
 94   16  owner                  NUL-padded ASCII, must be clean printable
                                 (0x20..0x7f), max 15 chars + NUL
110   16  contract_name          same encoding as owner
126    2  metadata_off (u16 BE)  MUST == HEADER_LEN (134)
128    2  formats_off  (u16 BE)  MUST == metadata_off + pool_len
130    2  pool_len     (u16 BE)
132    2  formats_len  (u16 BE)
```

After the header come `pool_len` bytes of metadata pool, then `formats_len` bytes of formats table. Total IR ≤ `MAX_IR_LEN` (4096 bytes — Phase 2 MUST reject oversize descriptors with a useful error rather than truncating).

**Endianness note:** all multi-byte numeric fields are **big-endian**. This differs from the existing ERC-20 / Names / Selectors bundles, which use little-endian for `chain_id` / `leaf_index` / `proof_depth`. Don't copy-paste from `dbgen/src/erc20.rs` without flipping. The reason for BE here: aligns with the sign-input header style (`proto/src/lib.rs` is BE) and with the EIP-712 / userOpHash hashing path that the IR feeds.

### Metadata pool — TLV entries

Each entry is `[1 B kind][1 B len][len bytes]`. `len` ≤ `MAX_POOL_ENTRY_LEN` (256). Kinds (stable wire constants — DO NOT renumber):

```
0x01 = address-by-chain map row   (Map of chainId → address)
0x02 = enum row                    (uint → string)
0x03 = constant address            (20 bytes)
0x04 = constant string             (ASCII)
0x05 = token defn                  (chain, addr, decimals, 5-char symbol)
0x10..0x24 = path-bytecode steps   (see PathOp enum in ir.rs)
0x30..0x3F = formatter param TLVs  (see plan; FmtParam enum lands in Phase 5)
```

The Phase 1 parser only validates the *fixed header* — pool + formats are stored as raw slices and validated lazily by the Phase 5 walker. Phase 2 doesn't need to validate them either; it just needs to emit them correctly.

### Formats table

Begins with a 1-byte count (≤ `MAX_FORMATS` = 16). Each format entry:

```
4 B   selector (or 32 B typehash for EIP-712 — primary type matters; let's
      use 4 B for now and figure out EIP-712 wiring in Phase 3+)
1 B   field_count (≤ MAX_FIELDS_PER_FORMAT = 24)
1 B   intent_len
N B   intent (ASCII)
field[0..field_count]
```

Each field: `1 B opcode | 1 B label_len | label | 2 B path_off | 2 B param_off`.

Offsets are into the metadata pool.

### Trailer (outer wire format that the companion ships)

```
off                size  field
0                   2   ir_len (u16 BE)
2                   N   IR bytes (the layout above)
2 + ir_len          4   leaf_index (u32 BE)
2 + ir_len + 4      4   proof_depth (u32 BE)
2 + ir_len + 8      M   Merkle proof, proof_depth * 32 bytes
```

`MAX_PROOF_DEPTH = 32`. Total `MAX_ERC7730_BUNDLE_LEN = 2 + 4096 + 4 + 4 + 32*32 = 5130` bytes.

**Note:** The plan-file sketch had a richer trailer header (version byte + flags + descriptor_hash). Phase 1 simplified that out because schema version and descriptor_hash already live inside the IR header. Phase 3 (trailer wire format) will use this thinner shape — see `bundle::verify_erc7730_bundle` for the canonical parser.

### Merkle scheme — identical to every other trust DB

- Leaf hash: `sha256(0x00 || ir_bytes)` (see `pqsigner-erc7730::bundle::leaf_hash` for the byte-for-byte reference)
- Internal node: `sha256(0x01 || left || right)`
- Padding: duplicate last leaf until power-of-2
- Direction: bit `i` of `leaf_index` selects left/right at level `i`
- The verifier is `pqsigner_tx::erc20::merkle::verify_proof` — Phase 2 host code calls `dbgen::merkle::verify_proof` (the same scheme on the host side), the on-device parser calls the secure-world copy. Both must stay in lockstep; the round-trip test catches drift.

## Phase 2 — what to build

### Phase 2.1 — Host IR compiler in `dbgen/src/erc7730.rs`

Pattern to mirror: `dbgen/src/erc20.rs` (519 lines, the most analogous one — has metadata + Merkle tree). Skim that first.

Tasks:
1. **Parse JSON** — vendor an ERC-7730 v2 schema validator. Cleanest path: use the upstream Cyfrin `clearsig` Python lib via a host-side build-time step, OR ship a vendored Rust schema-validator. Recommend the Python shell-out for MVP; we can rewrite native-Rust later. See <https://github.com/Cyfrin/clearsig> — its `descriptor-hash` / `lint` commands are the parity reference.
2. **JCS canonicalisation** — RFC 8785. The host pipeline produces the same 32-byte `descriptor_hash` that the IR carries at offset 30..62. This MUST match Cyfrin's `descriptor-hash` output byte-for-byte (regression test against their Python output).
3. **8176 attestation policy** — read `secure/data/erc7730/policy.toml`:
   ```toml
   min_attesters = 2
   trusted_attesters = [
     "eip155:1:0x...",   # Ledger
     "eip155:1:0x...",   # Fireblocks
     "eip155:1:0x...",   # Sourcify
   ]
   allow_unattested_dev_descriptors = false
   ```
   Reject descriptors that don't meet the policy. `allow_unattested_dev_descriptors = true` is for bring-up only; CI must reject production builds with that flag on (same pattern as `e2e-test` / `otp-hardcoded-master-key` exclusion).
4. **JSON → IR compiler** — emit the byte layout documented above. This is the long task. Plan for ~500 lines mirroring `dbgen/src/erc20.rs` shape. Handle every formatter from ERC-7730 v2 (the full list is in the plan file under Phase 5 — `raw / amount / tokenAmount / nftName / date / duration / addressName / enum / unit / calldata / chainId / tokenTicker / interoperableAddressName / encrypted`).
5. **Path compilation** — ERC-7730 paths are JSONPath-like strings (`#.params.amountIn`, `@.value`, `$.metadata.enums.mode`). Compile each to the path-bytecode opcode sequence (`PathOp` enum in `pqsigner-erc7730::ir`). Reuse the existing JSONPath parser if you can find one no_std; otherwise write a small hand-rolled one (≤ 200 lines).
6. **Merkle tree** — reuse `dbgen/src/merkle.rs::build_tree` (existing). Sort leaves by `(chain_id, contract)` for contract context, `(chain_id, verifying_contract, primary_type_hash)` for EIP-712. Compute root.
7. **Emit artifacts:**
   - `tools/companion-stub/erc7730_db.bin` — binary catalogue the companion looks up against
   - `tools/companion-stub/erc7730_db_e2e.bin` — tiny test variant
   - `secure/src/db_roots.rs` — append `pub static ERC7730_DESCRIPTORS_ROOT: [u8; 32] = [...]`
   - `secure/data/erc7730.review.txt` — human-readable review file (descriptor IDs + content hashes + attester list) for vendor signing

### Phase 2.2 — Seed corpus in `secure/data/erc7730/`

Start small (10–15 descriptors). Pick a representative mix:

- **USDC / USDT / DAI** — `transfer(address,uint256)` and `approve(address,uint256)` (every chain)
- **Uniswap V3 SwapRouter** — `exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))`
- **Aave V3 Pool** — `supply(address,uint256,address,uint16)`
- **Lido stETH** — `submit(address)`
- **EAS** — `attest((bytes32,(address,uint64,bool,bytes32,bytes,uint256)))`
- **Permit2** — `permit(...)`
- **OpenSea Seaport** — `fulfillOrder(...)`

For each: copy from <https://github.com/ethereum/clear-signing-erc7730-registry> if available; otherwise write from scratch following ERC-7730 v2 schema. Validate with Cyfrin `clearsig lint`.

### Phase 2.3 — xtask subcommand

`xtask/src/main.rs` currently has one subcommand (`gen-solidity-constants`). Add:

```rust
"gen-erc7730-descriptors" => cmd_gen_erc7730_descriptors(&args[1..]),
```

Flags:
```
--registry-mirror ./contrib/clear-signing-erc7730-registry  (optional — pulls
                                                              from a local
                                                              git submodule)
--policy ./secure/data/erc7730/policy.toml
--out-binary ./tools/companion-stub/erc7730_db.bin
--out-root ./secure/src/db_roots.rs
--out-review ./secure/data/erc7730.review.txt
--check    (CI mode — diff against checked-in artifacts, exit non-zero if drift)
```

### Phase 2.4 — CI integration

1. Add to `make prod-check`: regenerate `erc7730_db.bin` + root, diff against checked-in. Same pattern as existing `xtask gen-solidity-constants --check`.
2. Add a `cargo test -p dbgen --test erc7730_roundtrip` integration test:
   - Generate a small fixture catalogue
   - Build the Merkle tree
   - For each leaf: build a bundle, run `pqsigner_erc7730::bundle::verify_erc7730_bundle` against the host-computed root
   - Assert success and that the parsed IR matches the original
3. Add a parity test against Cyfrin `clearsig` (Python): `tools/cross_parity_erc7730.py`. Both pipelines see the same JSON corpus, both emit the 32-byte `descriptor_hash`. Assert byte-equality.

## Where to look in existing code

- **`dbgen/src/erc20.rs`** (519 lines) — best template. Has metadata + Merkle tree. Wire layout in the secure-side mirror `tx/src/erc20/bundle.rs`.
- **`dbgen/src/names.rs`** (361 lines) — simpler Merkle DB.
- **`dbgen/src/selectors.rs`** (347 lines) — text-sig handling, similar to ERC-7730's intent strings.
- **`dbgen/src/merkle.rs`** (133 lines) — the host-side `build_tree` + `verify_proof` you reuse.
- **`dbgen/src/main.rs`** (366 lines) — orchestration. Look at how each sub-DB is registered + driven.
- **`xtask/src/main.rs`** — subcommand dispatch pattern; the `gen-solidity-constants` body is the right shape to copy.
- **`secure/data/erc20.json`** / **`secure/data/names.json`** / **`secure/data/selectors.json`** — example JSON inputs (note: these are *NOT* ERC-7730 format — they're our internal DB format. The ERC-7730 inputs are the upstream registry JSONs).
- **`secure/src/db_roots.rs`** — append-only. Add `ERC7730_DESCRIPTORS_ROOT` next to `ERC20_DB_ROOT` / `SELECTOR_DB_ROOT` / `NAMES_DB_ROOT`.
- **`pqsigner-erc7730/src/ir.rs`** and **`bundle.rs`** — the on-device parser. The host pipeline MUST emit bytes that parse cleanly here.

## Common gotchas

1. **Endianness flip.** ERC-7730 IR uses BE. The existing ERC-20 / Names / Selectors bundles use LE. Don't copy `read_u32_le` calls verbatim from `tx/src/erc20/bundle.rs` — the IR parser uses `from_be_bytes` everywhere. The Phase 1 parser will reject mismatched endianness via the `BadLayout` error path.
2. **The `descriptor_hash` field at IR offset 30..62 is NOT verified on-device** (no JCS canonicaliser on Cortex-M33). It's there for cross-device sanity — a user with Cyfrin `clearsig` on a laptop can recompute it and compare. Phase 2 MUST compute it correctly so that cross-check works.
3. **`owner` and `contract_name` must be clean printable ASCII (0x20..0x7f).** The parser rejects anything else as `BadAscii`. If a descriptor's `metadata.owner` carries Unicode, the host compiler MUST transliterate or reject. The parser's policy is anti-spoof — a hostile DB row must not sneak homoglyphs onto the OLED.
4. **Contract context with non-zero `domain_separator` is REJECTED.** The parser enforces context-discriminator soundness. Make sure the host emits all-zero `domain_separator` when emitting contract-context entries.
5. **`metadata_off` must equal `HEADER_LEN` (134) exactly.** Don't pad. `formats_off` must equal `metadata_off + pool_len`. The parser checks these via the `BadLayout` error.
6. **Pool TLV ordering.** The walker (Phase 5) will assume entries appear in the order the compiler emitted them. If you change the ordering rule (e.g., sort enum entries by key), be consistent — the `$ref` path opcodes encode pool offsets, not pool indices, so the offsets must be stable.
7. **The plan file's trailer sketch had a thicker header (version + flags + descriptor_hash bytes).** Phase 1 simplified it. The canonical trailer is `[u16 BE ir_len][ir][u32 BE leaf_index][u32 BE proof_depth][proof]`. Don't re-introduce the redundant header bytes; schema version and descriptor_hash already live in the IR.
8. **ERC-8176 enforcement is the QUALITY GATE, not a runtime check.** A reader who sees "we skip 8176" will be tempted to also skip the policy.toml enforcement, which is the entire integrity story. Make this loud in code comments and the review file.

## Verification recipe for Phase 2

When you think Phase 2 is done:

```bash
# 1. Re-generate the DB
cargo run -p xtask -- gen-erc7730-descriptors

# 2. Confirm the round-trip — every emitted IR parses cleanly + Merkle-verifies
cargo test -p dbgen --test erc7730_roundtrip
cargo test -p pqsigner-erc7730

# 3. Confirm Cyfrin parity (regenerate fixtures via Python)
python tools/cross_parity_erc7730.py --corpus secure/data/erc7730/

# 4. Confirm the secure crate still cross-compiles + tests pass
cargo build -p pqsigner-erc7730 --target thumbv8m.main-none-eabi
cargo test -p sphincs-tz-secure --tests

# 5. Confirm CI gate
make prod-check
```

Then add a row to `docs/work-todo.md`'s Completion Log: `YYYY-MM-DD — Phase 2: host ERC-7730 IR compiler + Merkle DB + xtask + policy enforcement`.

## What Phase 3+ will need from Phase 2

- A real `ERC7730_DESCRIPTORS_ROOT` in `db_roots.rs` so Phase 3 (trailer parser) has a root to verify against
- A real `erc7730_db.bin` in `tools/companion-stub/` so Phase 7 (companion integration) has something to look up against
- Working golden fixtures in `secure/data/erc7730/` so Phase 5 (display renderer) has descriptors to drive its pages-rendering
- A `policy.toml` shape that future operators understand (review files, ATTESTER_PUBKEY rotation policy)

## Open questions intentionally left to Phase 2

- **Path-string parser dialect.** The ERC-7730 spec is loose on some syntax (`array.[0]` vs `array[0]`, `[-1]` vs `[last]`). Pick one, match Cyfrin's parser, and document. The IR is the canonical representation regardless.
- **Definitions / `$ref` cycles.** Spec allows definition references; we MUST reject cycles at compile time (host) so the on-device walker can stop relying on a depth counter. Implement with a small visited-set during compilation.
- **EIP-712 primary-type representation in the formats table.** Phase 1's format header reserves 4 bytes for a selector; EIP-712 uses 32-byte typehashes. Phase 3 will decide whether to widen the field or use a discriminator byte. Recommend a discriminator byte (`0x00 = selector, 0x01 = typehash`) + variable-width to keep the contract-context happy path 4 bytes.
- **Encrypted (FHEVM) handling.** We render `fallbackLabel` only. Confirm with the user before deciding whether to ship a stub or skip the formatter entirely.

## Plan-file pointer

The full plan (5 phases — consolidated 2026-05-14 from the original 9; ~6.5-week total roadmap; verification recipes; risks) lives at:

```
~/.claude/plans/carefully-read-understand-this-transient-feigenbaum.md
```

If something here disagrees with the plan, the plan is authoritative for *intent*; this handoff is authoritative for *what Phase 1 actually built*. Update one or the other if you find drift.

## References

- Clear Signing announcement (2026-05-12): <https://clearsigning.org> · <https://blog.ethereum.org/2026/05/12/clear-signing-announcement>
- ERC-7730 spec: <https://eips.ethereum.org/EIPS/eip-7730>
- ERC-7730 registry: <https://github.com/ethereum/clear-signing-erc7730-registry>
- ERC-8176 (Magicians thread): <https://ethereum-magicians.org/t/erc-8176-integrity-verification-for-erc-7730/27911>
- ERC-8213 (Magicians thread): <https://ethereum-magicians.org/t/erc-8213-wallet-signature-and-calldata-digest-display/24295>
- Cyfrin clearsig (Python reference): <https://github.com/Cyfrin/clearsig>
- ethereum.org dev tutorial: <https://ethereum.org/developers/tutorials/clear-signing/>
- Cyfrin announcement blog: <https://www.cyfrin.io/blog/blind-signing-solved>
