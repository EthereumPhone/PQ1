# Phase 6 — Deletion pass

**Status:** not started.
**Depends on:** phases 2–5 (firmware + contracts + USB must be stable first
so nothing still references deleted code).
**Blocks:** none, but makes phase 7 (docs) cleaner because there's less stale
code to reference.

## Why this phase exists

After the cutover, large parts of the tree are dead code: the SLH-DSA main
signer, the ML-DSA-44 bootstrap signer, the ZK clear-sign Groth16 machinery
(circuits, verification keys, proof verifiers), the vendored `bls12_381_pka`
crate (Groth16-only), all associated tests and docs. Keeping dead code
around is a maintenance tax, a security surface, and a source of confusion
for anyone reading the repo for the first time.

This is a pure `rm` + `cargo check` iteration loop: delete, fix compile
errors that reference the deleted symbols, repeat until the tree compiles
and tests pass.

## Procedure

Work in **small commits** — each batch is one directory / one crate
worth. After each batch: `cargo build`, `cargo test`, `forge test`. Fix
any stragglers. Commit. Move to next batch.

## Batch 1 — Workspace members

Edit root `Cargo.toml`:

```toml
# Remove these workspace members:
members = [
    # ...
    # "zk-test",           # ← delete
    # "dbgen",             # ← delete
    # "bls12_381_pka",     # ← delete (if present as workspace member)
    # ...
]
```

Then:

```bash
rm -rf zk-test dbgen bls12_381_pka
cargo check --workspace
```

If any remaining crate depends on these, fix the dependency first (most
likely: `secure` depends on `bls12_381`, fix that in batch 2).

## Batch 2 — `secure/Cargo.toml` strip

Remove the `bls12_381` dependency and the `pka-accel` feature:

```toml
# Before:
bls12_381 = { workspace = true, features = [...] }

[features]
# ...
pka-accel = [...]

# After:
# (both removed)
```

After: `cargo check -p sphincs-tz-secure` will fail with missing-symbol
errors wherever secure code uses `bls12_381::*`. These are all in the ZK
module, which is deleted next.

## Batch 3 — Firmware ZK and clear-sign

Delete whole directories:

```bash
rm -rf secure/src/zk/
rm -rf secure/src/tx/eip712/
rm -rf secure/src/erc20/
rm -rf secure/data/vks/
rm secure/data/vks.json
rm secure/src/db_roots.rs  # if it's only for VK Merkle root (check first)
```

Remove references from `secure/src/main.rs`:

```rust
// Before:
#[cfg(not(test))]
mod zk;
#[cfg(not(test))]
mod erc20;
#[cfg(not(test))]
mod db_roots;

// After: (all three removed)
```

Remove the matching lines in any `mod.rs` that pulls in `tx/eip712/`.

## Batch 4 — Delete non-JARDÍN NSC command handlers

```bash
rm secure/src/nsc/cmd_clear_sign.rs
rm secure/src/nsc/cmd_clear_sign_msg.rs
rm secure/src/nsc/cmd_get_bootstrap_pubkey.rs
rm secure/src/nsc/cmd_get_main_pubkey.rs
rm secure/src/nsc/cmd_get_pubkey.rs
rm secure/src/nsc/cmd_sign_bootstrap.rs
rm secure/src/nsc/cmd_sign_message.rs
rm secure/src/nsc/cmd_get_wallet_address.rs
rm secure/src/nsc/cmd_register_jardin_slot.rs   # folded into unified cmd_sign_userop
rm secure/src/nsc/cmd_sign_jardin.rs             # same
rm secure/src/nsc/userop_tail.rs                 # SLH-DSA-specific UserOp tail
```

Remove their `mod` declarations in `secure/src/nsc/mod.rs`. Remove their
dispatch arms. Remove their CMSE veneers.

`secure/src/nsc/mod.rs` dispatch should now only contain:
- `CMD_GET_REMAINING`
- `CMD_REQUEST_UNLOCK`
- `CMD_IS_UNLOCKED`
- `CMD_LOCK`
- `CMD_SIGN_USEROP` (the new unified one from phase 3)
- `CMD_GET_JARDIN_SLOT_INFO`

Remove the old CMD constants from `shared/src/lib.rs`:
- `CMD_GET_PUBKEY`
- `CMD_CLEAR_SIGN`
- `CMD_CLEAR_SIGN_MSG`
- `CMD_GET_BOOTSTRAP_PUBKEY`
- `CMD_GET_MAIN_PUBKEY`
- `CMD_SIGN_BOOTSTRAP`
- `CMD_SIGN_MESSAGE`
- `CMD_GET_WALLET_ADDRESS`
- `CMD_REGISTER_JARDIN_SLOT`
- `CMD_SIGN_JARDIN` (the split one)

Also delete matching wire-format constants:
- All `ZK_*` constants
- All `EIP712_*` constants
- All `USEROP_V1_*` constants
- `WRAPPER_HEADER_LEN`, `WRAPPER_TOTAL_LEN` (SLH-DSA wrapper sizes)
- `SIGNER_MAIN`, `SIGNER_BOOTSTRAP` enum values (keep `SIGNER_JARDIN`)

## Batch 5 — Firmware SLH-DSA dependencies

The `sphincs-c7` crate is actually C11 and is used for Type 1 signing
(phase 2). **Keep it.** Don't delete.

But check `secure/src/crypto.rs` for now-unused functions:
- `derive_main_key_from_entropy*` → delete
- `derive_bootstrap_key_from_entropy*` → delete
- `derive_sign_randomizer` (if only used by SLH-DSA) → delete
- `decrypt_entropy_blob` / `encrypt_entropy_blob` → **keep** (the SE stores
  wrapped entropy, and JARDÍN still needs to decrypt it)

## Batch 6 — USB layer cleanup

Already done in phase 4. Double-check:
- No references to deleted INS codes anywhere in `nonsecure/src/`
- No references to deleted `nsc_api::*` wrappers

## Batch 7 — Contracts cleanup

Already done in phase 5. Double-check:
- `SLHDSAVerifier.sol` / `ISLHDSAVerifier.sol` removed
- `SphincsC7Asm.sol` removed (if it existed as distinct from the new
  `SPHINCsC11Asm.sol`)
- `SLHDSAVerifier.t.sol`, `GasComparison.t.sol` removed
- `mocks/MockSLHDSAVerifier.sol` removed

## Batch 8 — Scripts, tools, circuits

```bash
# Circuit sources (Circom). All Groth16-specific.
rm -rf circuits/aave_v3/
rm -rf circuits/cowswap/
rm -rf circuits/lib/
# If circuits/node_modules was only for snarkjs/Circom, delete it:
rm -rf circuits/node_modules/
# If circuits/ becomes empty, delete the directory itself:
rmdir circuits/ 2>/dev/null || true

# Tools that only exist for the ZK pipeline:
rm tools/build_vks.sh
# Keep tools/build_erc20_db.py only if ERC20 logging survives in the
# companion; otherwise delete.
```

## Batch 9 — Makefile

Remove targets that reference:
- `circuits/` (all circuit compilation)
- `dbgen` / `cargo run -p dbgen`
- `zk-test`
- VK database generation
- `pka-accel` feature

Keep: `play`, `run`, `e2e`, `e2e-hw`, `flash-hw*`, `measure`, `build-hw`,
`test` (scoped down).

## Batch 10 — Tests

```bash
# Delete whole-test-suite files that exist only for non-JARDÍN paths:
rm secure/tests/zk_integration.rs    # if it exists
rm secure/tests/clear_sign_*.rs      # if they exist

# Edit nonsecure/src/e2e_test.rs to remove non-JARDÍN scenarios. Only
# keep: JARDÍN first-sign, JARDÍN rotation, PIN unlock/lock, attempt
# counter behavior.
```

## Batch 11 — Misc docs mentioned in the master plan

See phase 7. Brief:
```bash
rm docs/m4-cowswap-eip712.md
rm docs/m4-cowswap-eip712-impl.md
# Leave the others for phase 7's rewrite.
```

## Verification

After the full batch loop:

```bash
# Firmware compiles
CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x" \
  cargo build --release --target thumbv8m.main-none-eabi \
  --target-dir target/secure -p sphincs-tz-secure \
  --no-default-features --features mock-se,debug-log,ui-semihosting

# Contracts compile + test
cd contracts/smart-wallet && forge build && forge test -vv

# QEMU end-to-end
cd /home/markus/Documents/sphincs_rust && make e2e

# Binary size should shrink significantly — before / after firmware sizes:
# Before: expect ~800 KB (with Groth16 + SLH-DSA)
# After:  expect ~350-450 KB (JARDÍN + C11 only)
ls -la target/secure/thumbv8m.main-none-eabi/release/sphincs-tz-secure
```

## What NOT to do

- **Don't delete `sphincs-c7` crate.** It's the C11 Type 1 signer.
- **Don't delete `jardin-fosc` crate.** Obvious but worth stating.
- **Don't delete `keccak-asm` crate.** It's used by jardin-fosc for speed.
- **Don't delete `secure/src/crypto.rs`.** Prune it to JARDÍN + C11 derivation
  only (phase 2 adds the C11 part; this phase removes the old SLH-DSA / ZK
  parts).
- **Don't delete `secure_element/`, `se050/`, `optiga/`, `dual_se.rs`.** The
  seed-split mechanism is load-bearing.
- **Don't delete `measured_boot.rs`, `fwmeasure/`.** Firmware integrity
  measurement is unchanged.
- **Don't blindly `cargo fix`** to clean up warnings — some of the warnings
  will be in now-unused but not-yet-deleted code. Delete first, then
  `cargo fix` on what's left.

## Mechanical checklist

For each file listed above, after deletion, run:
```bash
grep -rn "<deleted symbol>" /home/markus/Documents/sphincs_rust --include="*.rs" --include="*.sol" --include="*.md"
```

to catch straggler references. Fix them or delete them too.

## Binary size tracking

Record before/after sizes in a commit message. Good progress metric:

| Artifact | Before | After (target) |
|---|---|---|
| `secure` firmware (release) | ~800 KB | ~350 KB |
| `nonsecure` firmware (release) | ~200 KB | ~100 KB |
| `PQCoinbaseSmartWallet.sol` deployed bytecode | ~24 KB | ~6 KB |
