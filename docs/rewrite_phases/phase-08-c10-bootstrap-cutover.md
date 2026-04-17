# Phase 8 — C10 Bootstrap Cutover

**Date:** 2026-04-17
**Status:** Shipped

## What changed

The bootstrap (master) identity flipped from **SPHINCS+C11** (`h=16, sig=3976`) to
**SPHINCS+C10** (`h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205, sig=4008`),
and the on-chain `PQJardinWallet` gained a hard-capped `bootstrapUses` counter.

Key numbers:

| Quantity                          | Pre-C10 (C11) | Post-C10   |
|-----------------------------------|--------------:|-----------:|
| Hypertree height `h`              | 16            | 18         |
| Subtree height `SUBTREE_H = h/d`  | 8             | 9          |
| WOTS leaves per top subtree       | 256           | 512        |
| Count-grind target sum            | 203           | 205        |
| Signature length (bytes)          | 3976          | 4008       |
| Type 1 wire frame (bytes)         | 4041          | 4073       |
| Hypertree capacity (2^h)          | 65,536        | 262,144    |
| On-chain per-chain Type 1 cap     | —             | **65,536** |

## Why C10 and why a cap

C10's deeper hypertree more than quadruples usable signing positions versus C11,
which gives us a much healthier birthday-style safety margin. But the product
decision is to **cap usage well below the tree's raw capacity**: each chain's
`PQJardinWallet` will accept at most 65,536 Type 1 (slot-registration)
signatures. After that, the current JARDÍN slot keeps signing Type 2
transactions until its own `Q_MAX`, but no new slot rotations are possible on
that chain — the companion must surface this as an irrecoverable per-chain
freeze.

Bundling the larger tree with a smaller cap is cheap insurance: if future
cryptanalysis tightens the SPHINCS+ bounds, the wallet never touched more than
1/4 of the tree anyway.

## Touched surfaces

### Crate

- `sphincs-c7/` directory renamed to `sphincs-c10/` (crate name
  `sphincs-c10`). Params flipped; `extract_ht_index` fixed to load up to 4
  bytes of the H_msg digest (H=18 needs bits [143..161), which spans
  `digest[11..15)` — the C11 3-byte load only covered `[136..160)` and would
  have silently truncated bit 160+ under C10).
- `sphincs-c10/tests/gen_test_vectors.rs` emits
  `contracts/smart-wallet/test/c10_test_vectors.json` for the Foundry
  smoketest. Run under `--release` (keygen is multi-second in debug).
- Old `sphincs-c7/tests/cross_language.rs` dropped — it compared against
  keccak-era vectors that had already been broken by the SHA-256 cutover.

### Firmware

- Workspace manifest + `secure/Cargo.toml` both now depend on `sphincs-c10`.
- `secure/src/crypto.rs`: every `derive_c11_*` / `c11_sign_*` renamed to the
  `c10_*` equivalent; the `"sphincs-c6-v1"` HMAC-SHA512 domain tag is
  **intentionally** kept verbatim — it is part of the frozen recovery
  contract and predates the C11→C10 change.
- `secure/src/nsc/cmd_sign_userop.rs`: sig bundle + type 1 assembly updated
  to 4008-byte C10 sigs and 4073-byte Type 1 frames.
- `shared/src/lib.rs`: `SIGNATURE_LEN = 4_008`, new `C10_SIG_LEN` constant,
  `JARDIN_TYPE1_LEN = 4073`, `INIT_CODE_LEN = 4_248` (ABI-padded signature
  width 4032 + the invariant 216-byte header), and the unit tests updated
  to match.

### Contracts

- New `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol` replaces
  `SPHINCsC11Asm.sol`. It still uses the SHA-256 precompile (address 0x02)
  so the on-chain verifier matches the STM32U585 HASH peripheral's output
  byte-for-byte. Tree shape changes: `idxLeaf` mask `0x1FF`,
  `idxTree >>= 9`, 9-level Merkle auth path, count-grind target 205,
  `sigOff` step 144 (9*16).
- `PQJardinWallet.sol`: `TYPE_1_SIG_LEN = 1 + 32 + 16 + 16 + 4008 = 4073`,
  `MAX_BOOTSTRAP_USES = 65_536`, pre-check `bootstrapUses >= cap` returns
  `SIG_VALIDATION_FAILED` (no revert — bundlers can simulate), and a
  post-slot-registration `_bumpBootstrapUses(MAX_BOOTSTRAP_USES)` call
  emits `BootstrapKeyUsed(newCount)`. Interface slot renamed
  `c11Verifier → c10Verifier`.
- `PQOwnable.sol`: added `uint256 bootstrapUses` to `PQSignerStorage`
  (ERC-7201 slot + 1), plus `bootstrapUses()` view and
  `_bumpBootstrapUses(cap)` internal helper that reverts with
  `"bootstrap exhausted"` above the cap.
- `PQJardinWalletFactory.sol`: constructor / storage / `createAccount` /
  `getAddress` all renamed `c11Verifier → c10Verifier`. Salt formula
  `sha256(masterPkSeed || masterPkRoot)` is unchanged — but the
  `masterPkRoot` value itself changes because the hypertree shape
  changed, so every seed now maps to a different CREATE2 address.

### Tests

- 5 new `SPHINCsC10AsmTest` Foundry tests exercise the Yul verifier
  against a Rust-generated signature, a mutated signature (6 byte
  positions across FORS + WOTS + count + Merkle regions), a wrong
  message, a wrong root, and truncated/padded inputs.
- 4 new `PQJardinWalletTest` bootstrap-counter tests cover: (1)
  counter bumps on success, (2) counter does NOT bump on any failure
  path (bad sig, bad length, zero `r`), (3) the cap cleanly rejects
  the 65,537th Type 1, and (4) Type 2 against an already-registered
  slot keeps working after the cap is hit.

## Kept deliberately (do not change)

- HMAC-SHA512 domain tag `"sphincs-c6-v1"` — part of the frozen recovery
  contract; the `C6` in the tag is archaeological and predates every
  parameter-set change we have ever shipped.
- JARDÍN slot domain tags (`"jardin_slot"`, `"jardin_r"`, `"jardin_sub_v1"`,
  `"jardin_pk_seed"`, `"jardin_sk_seed"`) — these live below the
  bootstrap layer and are completely unaffected by the C11→C10 switch.
- Keccak-256 usage in `secure/src/tx/hash.rs`, `secure/src/aa/userop.rs`,
  and the EVM CREATE2 opcode itself (`0xff || factory || salt || keccak256(initCode)`).
  External-standard hashes only — do not migrate these.
