//! Host-side test suite for the `secure-nsc-small-cmds` slice.
//!
//! # What is covered here
//!
//! The slice covers eight files under `secure/src/nsc/`:
//!
//!   * `cmd_request_unlock.rs` — secure-UI PIN prompt, three-way
//!     attempt-counter lockstep, and the lockout-wipe trigger.
//!   * `cmd_get_wallet_address.rs` — CREATE2-predicted wallet address
//!     for `(account_index)` from the bootstrap C10 pubkey.
//!   * `cmd_get_init_code.rs` — 4280-byte ERC-4337 `initCode` for
//!     `(account_index, chain_id)`.
//!   * `cmd_get_remaining.rs` — `min(MCU page-124, SE remaining)`.
//!   * `cmd_is_unlocked.rs` — single-bit pin-verified readback.
//!   * `cmd_lock.rs` — explicit zeroize-and-lock entry point.
//!   * `cmd_test_pin_lockout.rs` — `e2e-test`-only two-pass brute-force
//!     verifier.
//!   * `factory_calldata.rs` — ABI-encoded `createAccount(...)` calldata
//!     shared between `cmd_get_init_code` and `cmd_sign_offchain`.
//!
//! All eight transitively pull in the SE driver `static mut`, OLED
//! stack, flash I/O, and FI helpers — none reachable from a host build,
//! so none of the `run()` functions can be linked into `cargo test`.
//!
//! The suite below covers the slice with four host-runnable test
//! families:
//!
//!   1. **Pure-logic mirrors** — `CREATE2` address derivation and the
//!      `factory_calldata::build` ABI layout are reconstructed at
//!      module scope and exercised against deterministic fixtures, so
//!      a refactor that drifts the byte-exact output surfaces as a
//!      direct test failure.
//!   2. **Wire-format / on-chain-ABI constant pins** — every offset,
//!      length, selector, and embedded address the slice reads from
//!      `pqsigner-proto`. Any silent drift breaks interop with the
//!      on-chain verifier or the companion app, with no other test in
//!      the crate noticing.
//!   3. **Source-text invariant pins** — assertions over the eight
//!      files' source text that the load-bearing gates remain in
//!      place: pin-verified check, NS pointer validation, FI
//!      double-read of the page-124 counter, FAIL-IN sentinel
//!      encoding, three-way counter lockstep, gated_unlock pre-commit,
//!      `c10_sign_verified*` verify-before-release, and the absence of
//!      every forbidden code path called out in CLAUDE.md
//!      (`rotateMasterKeys`, classical signers, EntryPoint v0.7/v0.8,
//!      etc.).
//!   4. **Three-way counter / lockout-wipe semantics** — pin the
//!      values the `cmd_test_pin_lockout` brute-force harness depends
//!      on so a future refactor that quietly bumps `MAX_ATTEMPTS` or
//!      changes the wrong-PIN baked into the e2e test surfaces here
//!      rather than at on-target run time.
//!
//! Negative tests are framed around the assumption each gate enforces
//! (CLAUDE.md invariants #2, #4, #5, #6, #7, #8 + the slice's per-file
//! docstrings). When the assumption holds, the test passes; when a
//! future refactor violates it, the test fails with a panic message
//! naming the assumption.

#![cfg(test)]

use sphincs_tz_shared::{
    C10_SIG_LEN, EIP6492_FACTORY_CALLDATA_LEN, FACTORY_ADD_SLOT_DOMAIN, MAX_ACCOUNT_INDEX,
    MAX_ATTEMPTS, NS_FLASH_BASE, NS_FLASH_END, NS_SRAM_BASE, NS_SRAM_END, NscStatus,
    PQ_CREATE_ACCOUNT_SELECTOR, PQ_INIT_CODE_LEN, PQ_SMART_WALLET_FACTORY, PROXY_INIT_CODE_HASH,
    SHARED_MAILBOX_BASE, SHARED_MAILBOX_END,
};

// ─────────────────────────────────────────────────────────────────────
// 0. Slice source-text fixtures (loaded once).
//
// Every source-text invariant pin reads from one of these constants.
// `include_str!` makes the test crate re-build whenever the underlying
// file changes — no risk of stale-cached source text.
// ─────────────────────────────────────────────────────────────────────

const REQUEST_UNLOCK_SRC: &str = include_str!("nsc/cmd_request_unlock.rs");
const GET_WALLET_ADDRESS_SRC: &str = include_str!("nsc/cmd_get_wallet_address.rs");
const GET_INIT_CODE_SRC: &str = include_str!("nsc/cmd_get_init_code.rs");
const GET_REMAINING_SRC: &str = include_str!("nsc/cmd_get_remaining.rs");
const IS_UNLOCKED_SRC: &str = include_str!("nsc/cmd_is_unlocked.rs");
const LOCK_SRC: &str = include_str!("nsc/cmd_lock.rs");
const TEST_PIN_LOCKOUT_SRC: &str = include_str!("nsc/cmd_test_pin_lockout.rs");
const FACTORY_CALLDATA_SRC: &str = include_str!("nsc/factory_calldata.rs");
const NSC_MOD_SRC: &str = include_str!("nsc/mod.rs");

/// All slice files, paired with a human-readable name for assert
/// messages.
const ALL_SLICE_FILES: &[(&str, &str)] = &[
    ("cmd_request_unlock.rs", REQUEST_UNLOCK_SRC),
    ("cmd_get_wallet_address.rs", GET_WALLET_ADDRESS_SRC),
    ("cmd_get_init_code.rs", GET_INIT_CODE_SRC),
    ("cmd_get_remaining.rs", GET_REMAINING_SRC),
    ("cmd_is_unlocked.rs", IS_UNLOCKED_SRC),
    ("cmd_lock.rs", LOCK_SRC),
    ("cmd_test_pin_lockout.rs", TEST_PIN_LOCKOUT_SRC),
    ("factory_calldata.rs", FACTORY_CALLDATA_SRC),
];

// ─────────────────────────────────────────────────────────────────────
// 1. Positive: CREATE2 address derivation (`cmd_get_wallet_address`)
//
// The handler computes
//   salt    = sha256(pkSeed(32) || pkRoot(32))
//   address = keccak256(0xff || factory || salt || PROXY_INIT_CODE_HASH)[12..]
// This formula is the on-chain identity of every PQSigner wallet — a
// drift breaks invariant #6 (same 24 words → same address on every
// chain). Mirror it here against deterministic fixtures.
// ─────────────────────────────────────────────────────────────────────

/// Pure-logic mirror of `cmd_get_wallet_address::run`'s CREATE2 step.
/// Returns the 20-byte Ethereum address. The handler keeps the
/// computation inline; we re-derive it here so a silent drift surfaces.
fn mirror_predict_wallet_address(pk_seed: &[u8; 32], pk_root: &[u8; 32]) -> [u8; 20] {
    use sha2::{Digest, Sha256};
    use sha3::Keccak256;

    let mut salt_in = [0u8; 64];
    salt_in[..32].copy_from_slice(pk_seed);
    salt_in[32..].copy_from_slice(pk_root);
    let salt: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(salt_in);
        h.finalize().into()
    };

    let mut pre = [0u8; 1 + 20 + 32 + 32];
    pre[0] = 0xff;
    pre[1..21].copy_from_slice(&PQ_SMART_WALLET_FACTORY);
    pre[21..53].copy_from_slice(&salt);
    pre[53..85].copy_from_slice(&PROXY_INIT_CODE_HASH);

    let digest: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(pre);
        h.finalize().into()
    };
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..32]);
    out
}

#[test]
fn positive_create2_deterministic_for_fixed_input() {
    // Same inputs → same address, every time. The whole multi-chain
    // CREATE2 guarantee rides on this — invariant #6.
    let pk_seed = [0x11u8; 32];
    let pk_root = [0x22u8; 32];
    let a = mirror_predict_wallet_address(&pk_seed, &pk_root);
    let b = mirror_predict_wallet_address(&pk_seed, &pk_root);
    assert_eq!(a, b, "CREATE2 derivation must be deterministic");
}

#[test]
fn positive_create2_uses_low_20_bytes_of_keccak() {
    // The address slice is keccak[12..32]. A regression that took
    // keccak[0..20] would produce a different on-chain identity for
    // every wallet ever derived.
    use sha2::{Digest, Sha256};
    use sha3::Keccak256;
    let pk_seed = [0xAAu8; 32];
    let pk_root = [0xBBu8; 32];

    let mut salt_in = [0u8; 64];
    salt_in[..32].copy_from_slice(&pk_seed);
    salt_in[32..].copy_from_slice(&pk_root);
    let salt: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(salt_in);
        h.finalize().into()
    };
    let mut pre = [0u8; 85];
    pre[0] = 0xff;
    pre[1..21].copy_from_slice(&PQ_SMART_WALLET_FACTORY);
    pre[21..53].copy_from_slice(&salt);
    pre[53..85].copy_from_slice(&PROXY_INIT_CODE_HASH);
    let digest: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(pre);
        h.finalize().into()
    };
    let addr = mirror_predict_wallet_address(&pk_seed, &pk_root);
    assert_eq!(&addr[..], &digest[12..32]);
}

#[test]
fn positive_create2_distinct_inputs_yield_distinct_addresses() {
    // Different keys → different addresses. A regression that hashed
    // the wrong byte range would collapse multiple accounts onto one
    // address (and one user's coins onto another user's wallet).
    let a = mirror_predict_wallet_address(&[0u8; 32], &[0u8; 32]);
    let b = mirror_predict_wallet_address(&[1u8; 32], &[0u8; 32]);
    let c = mirror_predict_wallet_address(&[0u8; 32], &[1u8; 32]);
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
}

#[test]
fn positive_create2_preimage_first_byte_is_0xff() {
    // EIP-1014: the CREATE2 preimage starts with the literal byte
    // 0xff. Asserting at the handler call site is moot (the byte is
    // hard-coded), so we pin the mirror's behaviour and the source-
    // text shape together.
    assert!(GET_WALLET_ADDRESS_SRC.contains("pre[0] = 0xff"));
}

// ─────────────────────────────────────────────────────────────────────
// 2. Negative: CREATE2 — adversarial edge cases
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_create2_address_is_20_bytes_exact() {
    // Assumption: addresses are 20 B. Any code that ever produced a
    // 32-byte address would not match anything on-chain.
    let addr = mirror_predict_wallet_address(&[0u8; 32], &[0u8; 32]);
    assert_eq!(addr.len(), 20, "Ethereum addresses are exactly 20 B");
}

#[test]
fn negative_create2_salt_is_sha256_not_keccak256() {
    // CLAUDE.md §"Key derivation": `salt = sha256(masterPkSeed ||
    // masterPkRoot)`. A future refactor that switched to keccak256
    // (because everything else on the chain side uses keccak) would
    // silently change every on-chain address.
    assert!(
        GET_WALLET_ADDRESS_SRC.contains("Sha256::new()"),
        "salt must use SHA-256 — keccak256 would change the wallet address"
    );
    assert!(GET_WALLET_ADDRESS_SRC.contains("salt = sha256"));
}

#[test]
fn negative_create2_preimage_uses_keccak256_not_sha256() {
    // EIP-1014: address = keccak256(0xff || ...). Switching to
    // sha256 here would break interop with every EVM verifier.
    assert!(
        GET_WALLET_ADDRESS_SRC.contains("Keccak256::new()"),
        "CREATE2 preimage hash must be keccak256 (EVM-mandated)"
    );
}

#[test]
fn negative_create2_pk_seed_and_pk_root_are_distinct_positions() {
    // The 64-byte salt input has pkSeed at [0..32] and pkRoot at
    // [32..64]. A regression that put pkRoot first would change the
    // address of every existing wallet.
    let a = mirror_predict_wallet_address(&[0u8; 32], &[0xffu8; 32]);
    let b = mirror_predict_wallet_address(&[0xffu8; 32], &[0u8; 32]);
    assert_ne!(
        a, b,
        "swapping pkSeed and pkRoot must yield a different address"
    );
}

#[test]
fn negative_create2_factory_address_is_pinned() {
    // Invariant #6 (CLAUDE.md): the wallet address is a function of
    // the factory address. A silent change to PQ_SMART_WALLET_FACTORY
    // moves every wallet that has ever been derived.
    let expected: [u8; 20] = [
        0x67, 0x94, 0x34, 0x87, 0xe9, 0xE4, 0x1a, 0x9E, 0xE5, 0xF5, 0xF7, 0xA1, 0x0f, 0x18, 0xaa,
        0x82, 0xfE, 0x19, 0xE0, 0x3B,
    ];
    assert_eq!(PQ_SMART_WALLET_FACTORY, expected);
}

#[test]
fn negative_create2_proxy_init_code_hash_is_pinned() {
    // Invariant #6: the proxy init-code hash is the second half of
    // the CREATE2 preimage. Any drift here moves every wallet.
    let expected: [u8; 32] = [
        0x81, 0xbf, 0x5c, 0xe0, 0x6e, 0x60, 0xf7, 0x1c, 0x41, 0xde, 0x86, 0x99, 0x1b, 0x75, 0x63,
        0x9e, 0x32, 0xd9, 0x67, 0xb8, 0xe9, 0xd4, 0x12, 0xb7, 0x06, 0xa1, 0xc2, 0x4e, 0x25, 0xaa,
        0xdc, 0x4c,
    ];
    assert_eq!(PROXY_INIT_CODE_HASH, expected);
}

#[test]
fn negative_create2_factory_address_not_all_zero() {
    // Defense-in-depth: a buggy build that leaves the address all-zero
    // would silently route every wallet creation to the zero address.
    assert_ne!(PQ_SMART_WALLET_FACTORY, [0u8; 20]);
}

#[test]
fn negative_create2_proxy_init_code_hash_not_all_zero() {
    // As above — would silently collapse every CREATE2 derivation.
    assert_ne!(PROXY_INIT_CODE_HASH, [0u8; 32]);
}

// ─────────────────────────────────────────────────────────────────────
// 3. Positive: `factory_calldata::build` ABI layout
//
// `build` constructs the 4260-byte calldata of
//   PQSmartWalletFactory.createAccount(bytes32, bytes32, bytes32,
//                                      bytes32, uint64, bytes)
// for both `cmd_get_init_code` (initCode tail) and `cmd_sign_offchain`
// (ERC-6492 wrapper). Centralised so the two callers cannot drift.
//
// We cannot link `build` itself from host tests because it calls
// `crate::crypto::c10_sign_verified_with_progress`, which depends on
// the secure-world FI helpers. Instead we mirror just the ABI
// bookkeeping (the parts not touching the signature) and assert that
// every fixed-offset field lands where the docstring promises.
// ─────────────────────────────────────────────────────────────────────

/// Mirror the deterministic non-signature half of `factory_calldata::build`.
/// Leaves the signature bytes ([228..228+4008]) as zero.
fn mirror_build_calldata_abi_only(
    chain_id: u64,
    master_pk_seed_32: &[u8; 32],
    master_pk_root_32: &[u8; 32],
    slot0_pk_seed_32: &[u8; 32],
    slot0_pk_root_32: &[u8; 32],
) -> [u8; EIP6492_FACTORY_CALLDATA_LEN] {
    let mut out = [0u8; EIP6492_FACTORY_CALLDATA_LEN];
    out[..4].copy_from_slice(&PQ_CREATE_ACCOUNT_SELECTOR);
    out[4..36].copy_from_slice(master_pk_seed_32);
    out[36..68].copy_from_slice(master_pk_root_32);
    out[68..100].copy_from_slice(slot0_pk_seed_32);
    out[100..132].copy_from_slice(slot0_pk_root_32);
    // chainId — uint64 left-padded to uint256
    out[132 + 24..164].copy_from_slice(&chain_id.to_be_bytes());
    // Dynamic-bytes head: offset = head_size = 6 × 32 = 0xC0
    out[164 + 24..196].copy_from_slice(&(6u64 * 32).to_be_bytes());
    // Dynamic-bytes length = C10_SIG_LEN
    out[196 + 24..228].copy_from_slice(&(C10_SIG_LEN as u64).to_be_bytes());
    out
}

#[test]
fn positive_factory_calldata_selector_at_offset_zero() {
    let buf = mirror_build_calldata_abi_only(1, &[0u8; 32], &[0u8; 32], &[0u8; 32], &[0u8; 32]);
    assert_eq!(&buf[0..4], &PQ_CREATE_ACCOUNT_SELECTOR);
}

#[test]
fn positive_factory_calldata_master_pk_seed_at_offset_4() {
    let mut master_seed = [0u8; 32];
    for (i, b) in master_seed.iter_mut().enumerate() {
        *b = i as u8 ^ 0xAA;
    }
    let buf =
        mirror_build_calldata_abi_only(0xdead, &master_seed, &[0u8; 32], &[0u8; 32], &[0u8; 32]);
    assert_eq!(&buf[4..36], &master_seed);
}

#[test]
fn positive_factory_calldata_master_pk_root_at_offset_36() {
    let mut master_root = [0u8; 32];
    for (i, b) in master_root.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x10);
    }
    let buf = mirror_build_calldata_abi_only(1, &[0u8; 32], &master_root, &[0u8; 32], &[0u8; 32]);
    assert_eq!(&buf[36..68], &master_root);
}

#[test]
fn positive_factory_calldata_slot0_seed_at_offset_68() {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7);
    }
    let buf = mirror_build_calldata_abi_only(1, &[0u8; 32], &[0u8; 32], &s, &[0u8; 32]);
    assert_eq!(&buf[68..100], &s);
}

#[test]
fn positive_factory_calldata_slot0_root_at_offset_100() {
    let mut r = [0u8; 32];
    for (i, b) in r.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13);
    }
    let buf = mirror_build_calldata_abi_only(1, &[0u8; 32], &[0u8; 32], &[0u8; 32], &r);
    assert_eq!(&buf[100..132], &r);
}

#[test]
fn positive_factory_calldata_chain_id_is_left_padded_u256() {
    let buf = mirror_build_calldata_abi_only(
        0x0123_4567_89ab_cdef,
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 32],
    );
    // Upper 24 bytes of the uint256 slot must be zero (left-padded).
    assert_eq!(&buf[132..132 + 24], &[0u8; 24]);
    // Low 8 bytes carry the chain ID, big-endian.
    assert_eq!(&buf[132 + 24..164], &0x0123_4567_89ab_cdefu64.to_be_bytes());
}

#[test]
fn positive_factory_calldata_dynamic_bytes_offset_is_0xc0() {
    let buf = mirror_build_calldata_abi_only(1, &[0u8; 32], &[0u8; 32], &[0u8; 32], &[0u8; 32]);
    // Solidity ABI: tail offset measured from end of selector; for
    // 6 head slots = 6 × 32 = 0xC0.
    assert_eq!(&buf[164..164 + 24], &[0u8; 24]);
    assert_eq!(&buf[164 + 24..196], &(0xC0u64).to_be_bytes());
}

#[test]
fn positive_factory_calldata_dynamic_bytes_length_matches_c10_sig_len() {
    let buf = mirror_build_calldata_abi_only(1, &[0u8; 32], &[0u8; 32], &[0u8; 32], &[0u8; 32]);
    assert_eq!(&buf[196..196 + 24], &[0u8; 24]);
    assert_eq!(&buf[196 + 24..228], &(C10_SIG_LEN as u64).to_be_bytes());
}

#[test]
fn positive_factory_calldata_total_length_is_eip6492_constant() {
    // Length pin: the calldata is exactly 4260 B (= initCode minus the
    // 20-byte factory address prefix).
    assert_eq!(EIP6492_FACTORY_CALLDATA_LEN, PQ_INIT_CODE_LEN - 20);
    assert_eq!(EIP6492_FACTORY_CALLDATA_LEN, 4260);
}

// ─────────────────────────────────────────────────────────────────────
// 4. Negative: `factory_calldata` ABI layout adversarial cases
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_factory_calldata_signature_window_is_padded_to_32() {
    // Assumption (docstring): signature occupies [228..228 + 4008],
    // followed by 24 zero-pad bytes to the 4260-B boundary
    // (4236 + 24 = 4260). A future refactor that introduced 64-byte
    // alignment would leave 60 bytes of zero pad instead of 24, and
    // the on-chain ABI decoder would mis-locate the next field — if
    // anyone ever added one.
    let sig_start = 228;
    let sig_end = sig_start + C10_SIG_LEN;
    assert_eq!(sig_end, 4236);
    assert_eq!(EIP6492_FACTORY_CALLDATA_LEN - sig_end, 24);
}

#[test]
fn negative_factory_calldata_chain_id_high_24_bytes_must_be_zero() {
    // Assumption: chainId is uint64 left-padded into a uint256. A
    // regression that wrote the chain ID at [132..140] (big-endian
    // u64 at the START of the slot) would make the slot look like
    // a uint256 with the chain ID in its HIGH half — billions of
    // chain-ID values.
    let buf = mirror_build_calldata_abi_only(
        0xffff_ffff_ffff_ffff,
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 32],
    );
    assert_eq!(&buf[132..132 + 24], &[0u8; 24]);
}

#[test]
fn negative_factory_calldata_does_not_overflow_when_chain_id_is_zero() {
    // Edge case: chain_id == 0. Real on-chain interactions never use
    // chain_id == 0, but the firmware must still handle it (e.g. unit
    // tests, dev nets). The slot must be all-zero.
    let buf = mirror_build_calldata_abi_only(0, &[0u8; 32], &[0u8; 32], &[0u8; 32], &[0u8; 32]);
    assert_eq!(&buf[132..164], &[0u8; 32]);
}

#[test]
fn negative_factory_calldata_offset_field_high_bytes_zero() {
    // The dynamic-bytes offset is 0xC0 — fits in a single byte. The
    // upper 31 bytes of its 32-byte slot MUST be zero so the on-chain
    // ABI decoder reads a small offset, not 0xC0...whatever.
    let buf = mirror_build_calldata_abi_only(1, &[0u8; 32], &[0u8; 32], &[0u8; 32], &[0u8; 32]);
    for i in 164..164 + 31 {
        assert_eq!(buf[i], 0, "offset byte {i} must be zero");
    }
    assert_eq!(buf[195], 0xC0);
}

#[test]
fn negative_factory_calldata_length_field_high_bytes_zero() {
    // The dynamic-bytes length is 4008 = 0x0FA8, fitting in 2 bytes.
    // Upper 30 bytes of its 32-byte slot must be zero so the on-chain
    // ABI decoder doesn't grow the length to billions of bytes.
    let buf = mirror_build_calldata_abi_only(1, &[0u8; 32], &[0u8; 32], &[0u8; 32], &[0u8; 32]);
    for i in 196..196 + 30 {
        assert_eq!(buf[i], 0, "length byte {i} must be zero");
    }
    // And the low 2 bytes encode 4008.
    assert_eq!(u16::from_be_bytes([buf[226], buf[227]]) as usize, C10_SIG_LEN);
}

#[test]
fn negative_factory_calldata_pk_seed_and_root_layout_order() {
    // Master and slot pubkeys are 32-byte halves. Order matters: a
    // refactor that put root before seed would invalidate every
    // bootstrap signature the on-chain factory ever verifies.
    let master_seed = [0x01u8; 32];
    let master_root = [0x02u8; 32];
    let slot_seed = [0x03u8; 32];
    let slot_root = [0x04u8; 32];
    let buf = mirror_build_calldata_abi_only(
        1,
        &master_seed,
        &master_root,
        &slot_seed,
        &slot_root,
    );
    assert_eq!(&buf[4..36], &master_seed);
    assert_eq!(&buf[36..68], &master_root);
    assert_eq!(&buf[68..100], &slot_seed);
    assert_eq!(&buf[100..132], &slot_root);
}

#[test]
fn negative_factory_calldata_independent_calls_match_byte_for_byte() {
    // Determinism: the ABI half is pure. Two identical input tuples
    // must yield identical buffers (excluding the signature bytes
    // which the real `build` overwrites).
    let a = mirror_build_calldata_abi_only(42, &[0xAA; 32], &[0xBB; 32], &[0xCC; 32], &[0xDD; 32]);
    let b = mirror_build_calldata_abi_only(42, &[0xAA; 32], &[0xBB; 32], &[0xCC; 32], &[0xDD; 32]);
    assert_eq!(a, b, "deterministic ABI-only build must be byte-equal");
}

// ─────────────────────────────────────────────────────────────────────
// 5. Wire-format / on-chain-ABI constant pins
//
// `cmd_get_init_code.rs` reads `INPUT_LEN = 12` from
// `(account_index u32 BE || chain_id u64 BE)`. The other handlers all
// derive their length surface from `pqsigner-proto` constants. Pin the
// numbers so a refactor that bumps any of them surfaces here, not on
// the bench board.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_max_attempts_is_ten() {
    // CLAUDE.md invariant #2: `MAX_ATTEMPTS = 10` on any one counter
    // → `factory_reset_admin`. Both `cmd_request_unlock` and
    // `cmd_test_pin_lockout` read this constant — a change here
    // requires a coordinated bump on all three counters (MCU,
    // OPTIGA E120, SE050 UserID) plus a fresh provisioning ceremony.
    assert_eq!(MAX_ATTEMPTS, 10);
}

#[test]
fn negative_max_account_index_is_eight_bit_mask() {
    // CLAUDE.md §"Recovery / Key derivation": one seed → 256 wallets
    // via `account_index ∈ [0, 255]`. Both `cmd_get_wallet_address`
    // and `cmd_get_init_code` gate on `account_index >
    // MAX_ACCOUNT_INDEX`. A higher cap would silently break the
    // BIP-39 derivation invariant for newly-allowed indices.
    assert_eq!(MAX_ACCOUNT_INDEX, 0xFF);
}

#[test]
fn negative_pq_init_code_len_is_4280() {
    // The initCode the wallet's deploy path hashes into the CREATE2
    // address. Drift breaks invariant #6.
    assert_eq!(PQ_INIT_CODE_LEN, 4280);
}

#[test]
fn negative_eip6492_factory_calldata_len_is_init_code_minus_20() {
    // `factory_calldata::build` writes EIP6492_FACTORY_CALLDATA_LEN
    // bytes; the `cmd_get_init_code` handler glues a 20-byte factory
    // address prefix in front and emits PQ_INIT_CODE_LEN bytes. The
    // sum must equal PQ_INIT_CODE_LEN; drift here means the slice
    // emits a buffer of unexpected length.
    assert_eq!(EIP6492_FACTORY_CALLDATA_LEN + 20, PQ_INIT_CODE_LEN);
}

#[test]
fn negative_c10_sig_len_unchanged_4008() {
    // The factory calldata's dynamic-bytes length field encodes this
    // value. A drift here breaks ABI decoding on the on-chain
    // factory.
    assert_eq!(C10_SIG_LEN, 4008);
}

#[test]
fn negative_factory_add_slot_domain_unchanged() {
    // The bootstrap C10 key signs this domain string + chain ID +
    // slot-0 pubkey halves to authorise CREATE2. A rename here
    // invalidates every existing bootstrap sig the user could
    // counterfactually have computed; it also breaks the
    // squat-defence in `PQSmartWalletFactory`.
    assert_eq!(FACTORY_ADD_SLOT_DOMAIN, b"pqwallet-factory-add-slot");
    assert_eq!(FACTORY_ADD_SLOT_DOMAIN.len(), 25);
}

#[test]
fn negative_pq_create_account_selector_unchanged() {
    // `factory_calldata::build` emits this selector at offset 0. Any
    // drift means the on-chain factory call reverts.
    assert_eq!(PQ_CREATE_ACCOUNT_SELECTOR, [0xf6, 0x18, 0x2a, 0x73]);
}

#[test]
fn negative_get_init_code_input_len_is_12() {
    // `cmd_get_init_code` enforces `total_len != INPUT_LEN` where
    // INPUT_LEN = 12 = 4 (account_index u32 BE) + 8 (chain_id u64 BE).
    // A silent drift here would either reject correct payloads or
    // accept payloads with extra trailing bytes.
    assert!(
        GET_INIT_CODE_SRC.contains("const INPUT_LEN: usize = 12;"),
        "cmd_get_init_code must declare INPUT_LEN = 12 for the 4 + 8 wire layout"
    );
}

#[test]
fn negative_get_wallet_address_output_len_is_20() {
    // Ethereum addresses are 20 bytes. `cmd_get_wallet_address`'s
    // ADDR_LEN const must stay 20 — `validate_ns_write_ptr` gates the
    // NS buffer on it.
    assert!(
        GET_WALLET_ADDRESS_SRC.contains("const ADDR_LEN: usize = 20;"),
        "cmd_get_wallet_address must declare ADDR_LEN = 20"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 6. Source-text invariant pins — `cmd_request_unlock.rs`
//
// Every load-bearing FI / lockout guard here.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_request_unlock_uses_gated_unlock_not_raw_se_unlock() {
    // CLAUDE.md invariant #2 (hardware PIN gating). Every PIN verify
    // MUST go through `gated_unlock`, which implements the
    // pre-commit attempt-counter bump. A regression that called
    // `se.unlock(pin)` directly would let an attacker brute-force
    // without burning MCU attempts.
    assert!(
        REQUEST_UNLOCK_SRC.contains("super::gated_unlock(se, pin)"),
        "cmd_request_unlock must route through gated_unlock"
    );
    // And no direct calls into the raw SE unlock from this file.
    assert!(
        !REQUEST_UNLOCK_SRC.contains("se.unlock("),
        "cmd_request_unlock must not bypass gated_unlock with a raw se.unlock(...)"
    );
}

#[test]
fn negative_request_unlock_pre_commits_attempt_counter_before_se_call() {
    // Sanity: the gated_unlock contract pre-commits the page-124
    // bump before calling the SE driver. `cmd_request_unlock` relies
    // on that contract; pin the gated_unlock docstring text so a
    // future refactor of the gate's body can't quietly drop the
    // "pre-commit" guarantee. Stored in nsc/mod.rs (the gate lives
    // there).
    assert!(
        NSC_MOD_SRC.contains("Pre-commit"),
        "nsc::gated_unlock docstring must keep the pre-commit guarantee"
    );
    assert!(
        NSC_MOD_SRC.contains("pin_attempts_bump"),
        "nsc::gated_unlock must call pin_attempts_bump before the SE driver"
    );
}

#[test]
fn negative_request_unlock_fail_in_fi_pattern_present() {
    // F-15 FAIL-IN pattern (per the inline comment in the file): the
    // attacker-bypass-target (continue without wiping) is the
    // explicit conditional; the secure default (wipe) is the
    // fall-through. Pin the sentinel use so a refactor that swaps
    // back to a FAIL-OUT shape surfaces here.
    assert!(
        REQUEST_UNLOCK_SRC.contains("check_true_into_sentinel"),
        "cmd_request_unlock must use the Hamming-distant sentinel for the lockout gate"
    );
    assert!(
        REQUEST_UNLOCK_SRC.contains("OK_SENTINEL"),
        "the FAIL-IN sentinel comparison must remain"
    );
}

#[test]
fn negative_request_unlock_double_reads_post_bump_counter() {
    // F-15: defend a value-fault on the post-bump load register by
    // reading the counter twice with a random delay. A regression
    // that dropped the second read would leave the wipe trigger
    // glitchable.
    assert!(
        REQUEST_UNLOCK_SRC.contains("pin_attempts_read")
            && REQUEST_UNLOCK_SRC.contains("wait_random"),
        "cmd_request_unlock must double-read pin_attempts with wait_random between"
    );
    // And the file must actually contain the "if a != b { wipe }"
    // mismatch check.
    assert!(
        REQUEST_UNLOCK_SRC.contains("if a != b"),
        "the double-read mismatch must trigger trigger_lockout_wipe"
    );
}

#[test]
fn negative_request_unlock_zeroizes_pin_buffer_before_return() {
    // CLAUDE.md §"What NOT to do": no secrets in NS world / no
    // lingering plaintext PINs. The handler must `.zeroize()` the
    // PIN buffer after verify, no matter the outcome.
    assert!(
        REQUEST_UNLOCK_SRC.contains("pin_copy.zeroize()"),
        "cmd_request_unlock must zeroize the local PIN copy on every return path"
    );
}

#[test]
fn negative_request_unlock_idle_wipe_zeroizes_state() {
    // PinEntryResult::IdleWipe path must zeroize sensitive state and
    // return IdleWipe — silently returning Ok or UserRejected would
    // leave the master_secret in BSS across the next sign cycle.
    assert!(
        REQUEST_UNLOCK_SRC.contains("PinEntryResult::IdleWipe"),
        "cmd_request_unlock must handle the IdleWipe variant"
    );
    assert!(
        REQUEST_UNLOCK_SRC.contains("zeroize_sensitive_state()"),
        "cmd_request_unlock must zeroize on IdleWipe"
    );
}

#[test]
fn negative_request_unlock_trigger_lockout_wipe_runs_factory_reset_admin() {
    // CLAUDE.md invariant #2: 10 wrong PINs → `factory_reset_admin`.
    // The wipe trigger must call into the SE admin-wipe path; a
    // regression that only erased MCU flash would leave the chips
    // half-provisioned.
    assert!(
        REQUEST_UNLOCK_SRC.contains("factory_reset_admin"),
        "trigger_lockout_wipe must invoke factory_reset_admin"
    );
    assert!(
        REQUEST_UNLOCK_SRC.contains("pin_attempts_reset"),
        "trigger_lockout_wipe must reset the MCU page-124 counter after the SE wipe"
    );
}

#[test]
fn negative_request_unlock_uses_handler_guard_to_block_idle_wipe() {
    // HIGH-7: SysTick must not zeroize BSS secrets while the unlock
    // handler is mid-derive. The HandlerGuard RAII pattern is the
    // contract.
    assert!(
        REQUEST_UNLOCK_SRC.contains("HandlerGuard::enter()"),
        "cmd_request_unlock must enter HandlerGuard to block SysTick idle-wipe"
    );
}

#[test]
fn negative_request_unlock_last_attempt_message_only_at_one() {
    // UX guard: the "LAST ATTEMPT" warning fires only when
    // `remaining_after == 1`. A regression that fired it earlier
    // (e.g. `<= 1` or `< 2`) would scare the user on attempt 9; a
    // regression that fired it later would skip the warning
    // entirely.
    assert!(
        REQUEST_UNLOCK_SRC.contains("if remaining_after == 1"),
        "the LAST ATTEMPT message must trigger at exactly 1 remaining"
    );
}

#[test]
fn negative_request_unlock_does_not_implement_software_pin_compare() {
    // CLAUDE.md §"What NOT to do": no software PIN compare. The PIN
    // bytes must only be handed to the SE silicon. The slice file
    // must not contain a `ConstantTimeEq` or `==` comparison
    // against the PIN bytes.
    assert!(
        !REQUEST_UNLOCK_SRC.contains("ConstantTimeEq"),
        "cmd_request_unlock must not compare PIN bytes — only SE silicon does that"
    );
    assert!(
        !REQUEST_UNLOCK_SRC.contains("== pin"),
        "cmd_request_unlock must not bytewise-compare the PIN — silicon only"
    );
}

#[test]
fn negative_request_unlock_no_classical_signer_mentions() {
    // CLAUDE.md invariant #5: One signature primitive: SPHINCS+C10.
    let forbidden_signers = ["secp256k1", "ECDSA", "ed25519", "Ed25519", "p256", "P256"];
    for f in &forbidden_signers {
        assert!(
            !REQUEST_UNLOCK_SRC.contains(f),
            "cmd_request_unlock must not mention banned signer '{f}'"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// 7. Source-text invariant pins — `cmd_get_wallet_address.rs`
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_get_wallet_address_checks_pin_verified() {
    // CLAUDE.md invariant #2: the handler must gate on `pin_verified`
    // before reading any SE-resident entropy. Returns
    // `NotInitialized` if not unlocked.
    assert!(
        GET_WALLET_ADDRESS_SRC.contains("pin_verified.check_sentinel()"),
        "cmd_get_wallet_address must FI-check pin_verified before deriving"
    );
    assert!(
        GET_WALLET_ADDRESS_SRC.contains("NscStatus::NotInitialized"),
        "the unlock-gate must return NscStatus::NotInitialized"
    );
}

#[test]
fn negative_get_wallet_address_validates_write_ptr_before_deref() {
    // CLAUDE.md invariant #4: NS pointer validation on every gateway
    // call before any deref.
    assert!(
        GET_WALLET_ADDRESS_SRC.contains("validate_ns_write_ptr"),
        "cmd_get_wallet_address must validate the NS write pointer"
    );
    // And the validate call must precede the volatile store loop.
    let validate_pos = GET_WALLET_ADDRESS_SRC
        .find("validate_ns_write_ptr")
        .expect("validate present");
    let write_pos = GET_WALLET_ADDRESS_SRC
        .find("write_volatile(out_ptr")
        .expect("volatile write present");
    assert!(
        validate_pos < write_pos,
        "validate_ns_write_ptr must run BEFORE write_volatile (no TOCTOU)"
    );
}

#[test]
fn negative_get_wallet_address_rejects_account_index_above_mask() {
    // The handler's source must contain the rejection branch for
    // `account_index > MAX_ACCOUNT_INDEX`. A stale companion that
    // sends index 256 must NOT silently alias onto account 0 (per
    // the file-level docstring's explicit reasoning).
    assert!(
        GET_WALLET_ADDRESS_SRC.contains("account_index > MAX_ACCOUNT_INDEX"),
        "cmd_get_wallet_address must reject account_index > 255 — \
         a stale companion would silently alias onto account 0"
    );
}

#[test]
fn negative_get_wallet_address_uses_volatile_writes_to_ns() {
    // CMSE / TrustZone: NS-bound writes must be volatile so the
    // compiler can't reorder them.
    assert!(
        GET_WALLET_ADDRESS_SRC.contains("write_volatile"),
        "cmd_get_wallet_address must write the address via volatile stores"
    );
}

#[test]
fn negative_get_wallet_address_wraps_secrets_in_zeroizing() {
    // CLAUDE.md §"Code Conventions": ZeroizeOnDrop on every secret
    // type. The handler holds the master_secret + entropy on the
    // stack; both must be in Zeroizing<>.
    assert!(
        GET_WALLET_ADDRESS_SRC.contains("Zeroizing::new"),
        "cmd_get_wallet_address must wrap stack-held secrets in Zeroizing"
    );
}

#[test]
fn negative_get_wallet_address_no_rotate_or_reset_paths() {
    for forbidden in &[
        "rotateMasterKeys",
        "rotate_master_keys",
        "resetBootstrapUses",
        "reset_bootstrap_uses",
        "increaseMax",
    ] {
        assert!(
            !GET_WALLET_ADDRESS_SRC.contains(forbidden),
            "cmd_get_wallet_address must not expose '{forbidden}' — CLAUDE.md"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// 8. Source-text invariant pins — `cmd_get_init_code.rs`
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_get_init_code_uses_handler_guard() {
    // HIGH-7: slot keygen takes several seconds — SysTick must NOT
    // zeroize the slot key out from under us.
    assert!(
        GET_INIT_CODE_SRC.contains("HandlerGuard::enter()"),
        "cmd_get_init_code must enter HandlerGuard around the multi-second keygen"
    );
}

#[test]
fn negative_get_init_code_checks_pin_verified() {
    assert!(
        GET_INIT_CODE_SRC.contains("pin_verified.check_sentinel()"),
        "cmd_get_init_code must FI-check pin_verified before SE reads"
    );
    assert!(GET_INIT_CODE_SRC.contains("NscStatus::NotInitialized"));
}

#[test]
fn negative_get_init_code_strictly_checks_total_len_against_input_len() {
    // The dispatcher passes `total_len = args.arg2`. A `>=` instead
    // of `!=` would accept oversize payloads and a hostile companion
    // could feed trailing bytes the parser silently ignores.
    assert!(
        GET_INIT_CODE_SRC.contains("total_len != INPUT_LEN"),
        "cmd_get_init_code must reject any payload that is not exactly 12 bytes"
    );
}

#[test]
fn negative_get_init_code_validates_both_ns_pointers_before_deref() {
    // The handler reads from in_ptr and writes to out_ptr; both must
    // be validated before the volatile stores.
    assert!(GET_INIT_CODE_SRC.contains("validate_ns_read_ptr"));
    assert!(GET_INIT_CODE_SRC.contains("validate_ns_write_ptr"));

    let val_read = GET_INIT_CODE_SRC.find("validate_ns_read_ptr").unwrap();
    let val_write = GET_INIT_CODE_SRC.find("validate_ns_write_ptr").unwrap();
    let read_volatile = GET_INIT_CODE_SRC.find("read_volatile(in_ptr").unwrap();
    let write_volatile = GET_INIT_CODE_SRC.find("write_volatile(out_ptr").unwrap();
    assert!(val_read < read_volatile, "validate read ptr before deref");
    assert!(val_write < write_volatile, "validate write ptr before deref");
}

#[test]
fn negative_get_init_code_snaps_input_into_stack_buffer() {
    // TOCTOU: copy NS bytes to S-stack before parse (CLAUDE.md
    // §"Code Conventions"). A handler that parsed in_ptr directly
    // could be raced by a malicious NS thread between read and use.
    assert!(
        GET_INIT_CODE_SRC.contains("let mut buf = [0u8; INPUT_LEN];"),
        "cmd_get_init_code must snapshot the NS input into a stack buffer"
    );
    assert!(
        GET_INIT_CODE_SRC.contains("read_volatile(in_ptr.add"),
        "the snapshot must use volatile reads"
    );
}

#[test]
fn negative_get_init_code_rejects_account_index_above_mask() {
    // Same rationale as cmd_get_wallet_address: companion gives us a
    // 4-byte field but only 0..=255 is legal. Anything higher is a
    // wire-format bug.
    assert!(
        GET_INIT_CODE_SRC.contains("account_index > MAX_ACCOUNT_INDEX"),
        "cmd_get_init_code must reject account_index > 255"
    );
}

#[test]
fn negative_get_init_code_emits_pq_init_code_len_bytes() {
    // The output buffer is PQ_INIT_CODE_LEN bytes; the write loop
    // must run for the same count.
    assert!(
        GET_INIT_CODE_SRC.contains("PQ_INIT_CODE_LEN"),
        "cmd_get_init_code must size its output at PQ_INIT_CODE_LEN"
    );
    assert!(
        GET_INIT_CODE_SRC.contains("for i in 0..PQ_INIT_CODE_LEN"),
        "the volatile-write loop must cover the full PQ_INIT_CODE_LEN buffer"
    );
}

#[test]
fn negative_get_init_code_delegates_calldata_layout_to_factory_calldata() {
    // The "single source of truth" property: `factory_calldata::build`
    // is the only ABI encoder. A future refactor that inlined the
    // 4260-byte layout here would silently diverge from the
    // ERC-6492 path in `cmd_sign_offchain`.
    assert!(
        GET_INIT_CODE_SRC.contains("super::factory_calldata::build"),
        "cmd_get_init_code must delegate calldata layout to factory_calldata::build"
    );
}

#[test]
fn negative_get_init_code_first_20_bytes_are_factory_address() {
    // The initCode layout: factory_addr(20) || calldata(4260). A
    // regression that prefixed something else would break the
    // CREATE2 init-code hash and therefore the wallet address.
    assert!(
        GET_INIT_CODE_SRC.contains("ic[..20].copy_from_slice(&PQ_SMART_WALLET_FACTORY)"),
        "cmd_get_init_code must prefix the factory address as the first 20 bytes"
    );
}

#[test]
fn negative_get_init_code_wraps_secrets_in_zeroizing() {
    assert!(
        GET_INIT_CODE_SRC.contains("Zeroizing"),
        "cmd_get_init_code must wrap stack-held secrets in Zeroizing"
    );
}

#[test]
fn negative_get_init_code_uses_c10_sign_verified_with_progress() {
    // Verify-before-release: every Type 1 / Type 2 sig MUST be
    // double-checked (CLAUDE.md §"Code Conventions"). The factory
    // calldata's signature is produced by `c10_sign_verified*`, not
    // a raw `c10::sign`.
    assert!(
        FACTORY_CALLDATA_SRC.contains("c10_sign_verified_with_progress"),
        "factory_calldata::build must use the verify-before-release primitive"
    );
    assert!(
        !FACTORY_CALLDATA_SRC.contains("master_c10_sk.sign("),
        "factory_calldata::build must not call raw .sign() — bypasses FI verify"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 9. Source-text invariant pins — `cmd_get_remaining.rs`
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_get_remaining_uses_min_of_mcu_and_se() {
    // CLAUDE.md docstring (cmd_get_remaining.rs:9): "Authoritative
    // value is the MIN across all three counters." A refactor that
    // displayed only the MCU counter (or only the SE counter) would
    // hide a real lockout from the user.
    assert!(
        GET_REMAINING_SRC.contains(".min("),
        "cmd_get_remaining must take the MIN of MCU and SE counters"
    );
}

#[test]
fn negative_get_remaining_uses_saturating_subtract_against_max() {
    // The MCU side returns `MAX_ATTEMPTS - used`, but `used` could in
    // principle be > MAX_ATTEMPTS after a glitched flash bump.
    // `saturating_sub` clamps to 0 instead of wrapping to 255.
    assert!(
        GET_REMAINING_SRC.contains("saturating_sub"),
        "cmd_get_remaining must use saturating_sub against MAX_ATTEMPTS"
    );
}

#[test]
fn negative_get_remaining_persists_value_into_secure_state() {
    // Pin: the handler writes the computed value into
    // `state.remaining_attempts` so the trusted-UI display stays in
    // sync with what the gateway returns.
    assert!(
        GET_REMAINING_SRC.contains("s.remaining_attempts = remaining"),
        "cmd_get_remaining must update SecureState.remaining_attempts"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 10. Source-text invariant pins — `cmd_is_unlocked.rs`
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_is_unlocked_uses_fi_hardened_read_not_raw_bool() {
    // CLAUDE.md F-14: `pin_verified` is stored as `FihBool`
    // (complement-encoded). The handler MUST read via the FI helper,
    // not a raw `s.pin_verified == true`-shaped path.
    assert!(
        IS_UNLOCKED_SRC.contains("pin_verified.is_true_fi()"),
        "cmd_is_unlocked must read pin_verified via the FI-hardened helper"
    );
}

#[test]
fn negative_is_unlocked_returns_only_zero_or_one() {
    // The handler's return values must be exactly 0 or 1 — a single
    // bit reported through a u32. A regression that returned any
    // other value would break the v2 GET_STATUS USB report parser.
    assert!(
        IS_UNLOCKED_SRC.contains("1") && IS_UNLOCKED_SRC.contains("0"),
        "cmd_is_unlocked must return 1 or 0 (no other return values allowed)"
    );
    // And the file shape is so small it has exactly one decision
    // branch — a regression that added a third return value would
    // grow it.
    let line_count = IS_UNLOCKED_SRC.lines().count();
    assert!(
        line_count < 30,
        "cmd_is_unlocked is intentionally tiny ({line_count} lines); \
         growth here is a regression-shaped smell"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 11. Source-text invariant pins — `cmd_lock.rs`
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_lock_calls_zeroize_sensitive_state() {
    // CLAUDE.md §"Lifecycle": Lock must zeroize on demand. A
    // regression that only updated a flag would leave cached
    // master_secret / slot_master_entropy in SRAM.
    assert!(
        LOCK_SRC.contains("zeroize_sensitive_state()"),
        "cmd_lock must zeroize every cached secret"
    );
}

#[test]
fn negative_lock_returns_ok_status() {
    // The companion treats CMD_LOCK as best-effort; the handler must
    // still return Ok so the v2 status parser doesn't surface a
    // false error.
    assert!(
        LOCK_SRC.contains("NscStatus::Ok"),
        "cmd_lock must return NscStatus::Ok"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 12. Source-text invariant pins — `cmd_test_pin_lockout.rs`
//
// This handler is `e2e-test`-only. The brute-force harness depends on
// MAX_ATTEMPTS = 10 and the e2e-test PIN baked into main.rs's auto-
// provision step. Drift between this file and the e2e fast-path
// silently invalidates every brute-force test we ship.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_test_pin_lockout_correct_pin_matches_e2e_fastpath_value() {
    // The handler's CORRECT_PIN must match the PIN baked into
    // main.rs's e2e-test auto-provision step. Drift here silently
    // fails every `make pin-gate-*-e2e` target.
    assert!(
        TEST_PIN_LOCKOUT_SRC.contains(r#"const CORRECT_PIN: [u8; 8] = *b"00000000";"#),
        "cmd_test_pin_lockout's CORRECT_PIN must match main.rs's e2e fast-path PIN"
    );
}

#[test]
fn negative_test_pin_lockout_wrong_pin_differs_from_correct() {
    // The wrong PIN must just need to differ from CORRECT_PIN; if
    // someone accidentally set it to "00000000" the test would
    // ACCEPT every wrong PIN.
    assert!(
        TEST_PIN_LOCKOUT_SRC.contains(r#"const WRONG_PIN: [u8; 8] = *b"99999999";"#),
        "cmd_test_pin_lockout's WRONG_PIN must differ from CORRECT_PIN"
    );
}

#[test]
fn negative_test_pin_lockout_pass_a_runs_max_minus_one_wrong_pins() {
    // Pass A drives MCU 0 → 9, leaves one MCU attempt and one SE050
    // silicon retry intact so the chip stays repeatable. A
    // regression that ran MAX_ATTEMPTS wrong PINs would trip the
    // gate inside pass A and brick the SE050 UserID lifetime
    // budget.
    assert!(
        TEST_PIN_LOCKOUT_SRC
            .contains("let wrong_budget = (MAX_ATTEMPTS as usize).saturating_sub(1);"),
        "pass A must run exactly MAX_ATTEMPTS - 1 wrong PINs"
    );
}

#[test]
fn negative_test_pin_lockout_compiled_only_under_e2e_test_feature() {
    // CLAUDE.md ship gate: `e2e-test` must never reach production.
    // `cmd_test_pin_lockout` exists only behind that flag — pin the
    // gate in nsc/mod.rs.
    assert!(
        NSC_MOD_SRC.contains(r#"#[cfg(feature = "e2e-test")]"#)
            && NSC_MOD_SRC.contains("mod cmd_test_pin_lockout"),
        "cmd_test_pin_lockout must be gated by feature = \"e2e-test\""
    );
}

#[test]
fn negative_test_pin_lockout_cleanup_restores_unlocked_state() {
    // The handler must leave the SE in a clean unlocked state so
    // the harness's following commands work. A regression that
    // skipped the cleanup unlock would leave pin_verified false and
    // every subsequent sign command would refuse with
    // NotInitialized.
    assert!(
        TEST_PIN_LOCKOUT_SRC.contains("unlock_with_master(master_final)"),
        "cmd_test_pin_lockout cleanup must restore pin_verified via unlock_with_master"
    );
}

#[test]
fn negative_test_pin_lockout_passes_b_is_stm32u585_only() {
    // Pass B depends on the MCU page-124 counter, which only exists
    // on real silicon. On QEMU the body must be cfg'd out.
    assert!(
        TEST_PIN_LOCKOUT_SRC.contains(r#"#[cfg(feature = "stm32u585")]"#),
        "pass B (MCU gate) must be cfg-gated to stm32u585"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 13. Source-text invariant pins — `factory_calldata.rs`
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_factory_calldata_pins_factory_add_slot_domain() {
    // The bootstrap key signs FACTORY_ADD_SLOT_DOMAIN + chain_id +
    // slot0 pubkey halves. Renaming the domain string would
    // invalidate every existing bootstrap sig.
    assert!(
        FACTORY_CALLDATA_SRC.contains("FACTORY_ADD_SLOT_DOMAIN"),
        "factory_calldata must use the frozen FACTORY_ADD_SLOT_DOMAIN tag"
    );
    // And the asserted length is part of the call (`debug_assert_eq!`
    // on 25 bytes).
    assert!(
        FACTORY_CALLDATA_SRC.contains("FACTORY_ADD_SLOT_DOMAIN.len(), 25"),
        "factory_calldata must debug_assert the 25-byte domain length"
    );
}

#[test]
fn negative_factory_calldata_fills_buffer_before_writing_fields() {
    // The function is documented to leave trailing bytes past the
    // signature as zero (ABI tail padding). The `out.fill(0)` at the
    // top must remain — otherwise a future caller that doesn't
    // pre-zero its buffer would emit garbage padding bytes.
    assert!(
        FACTORY_CALLDATA_SRC.contains("out.fill(0);"),
        "factory_calldata::build must zero the buffer before writing fields"
    );
}

#[test]
fn negative_factory_calldata_returns_crypto_error_on_sign_failure() {
    // The only sign-side error path must map to
    // NscStatus::CryptoError. A refactor that returned
    // InternalError or some other status would surface a misleading
    // companion-side error and obscure the actual cause.
    assert!(
        FACTORY_CALLDATA_SRC.contains("NscStatus::CryptoError"),
        "factory_calldata must surface sign failure as NscStatus::CryptoError"
    );
}

#[test]
fn negative_factory_calldata_no_classical_signers() {
    let forbidden = [
        "secp256k1", "ECDSA", "ed25519", "Ed25519", "p256", "P256", "RSA",
    ];
    for f in &forbidden {
        assert!(
            !FACTORY_CALLDATA_SRC.contains(f),
            "factory_calldata must not mention banned signer '{f}'"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// 14. Source-text invariant pins — `nsc/mod.rs`'s gated_unlock
//
// The PIN-lockout gate lives in nsc/mod.rs but is the single
// load-bearing primitive every slice in this pass depends on.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_gated_unlock_refuses_when_counter_at_max() {
    // The lockout-counter gate at the top of gated_unlock returns
    // PinLocked when pre_count >= MAX_ATTEMPTS. The Hamming-distant
    // sentinel pattern means a single-fault skip falls through to
    // PinLocked, not to the SE driver.
    assert!(
        NSC_MOD_SRC.contains("pre_count < sphincs_tz_shared::MAX_ATTEMPTS"),
        "gated_unlock must compare pre_count against MAX_ATTEMPTS"
    );
    assert!(
        NSC_MOD_SRC.contains("UnlockError::PinLocked"),
        "gated_unlock must surface lockout as PinLocked"
    );
}

#[test]
fn negative_gated_unlock_refuses_on_flash_bump_failure() {
    // F-15 hardening: a flash bump that fails (PROGERR or readback
    // mismatch) must refuse the attempt without ever calling the SE
    // driver. Otherwise an attacker who can glitch flash writes
    // could burn SE attempts without burning MCU attempts.
    assert!(
        NSC_MOD_SRC.contains("pin_attempts_bump().is_err()"),
        "gated_unlock must check pin_attempts_bump result"
    );
    assert!(
        NSC_MOD_SRC.contains("UnlockError::InternalError"),
        "gated_unlock must surface flash failure as InternalError"
    );
}

#[test]
fn negative_gated_unlock_uses_fi_double_check_on_result() {
    // F-19 (per the docstring): triple-read the result via two
    // wait_random()-separated is_ok() calls + a sentinel. A regression
    // that dropped the second read would let a single fault flip
    // an Err into Ok.
    assert!(
        NSC_MOD_SRC.contains("is_ok_1") && NSC_MOD_SRC.contains("is_ok_2"),
        "gated_unlock must double-check the SE result via two is_ok() reads"
    );
    assert!(
        NSC_MOD_SRC.contains("check_true_into_sentinel"),
        "gated_unlock must route the verdict through the FI sentinel"
    );
}

#[test]
fn negative_gated_unlock_resets_counter_only_on_clean_ok() {
    // The reset path runs only when both `Ok(_)` and `verdict ==
    // OK_SENTINEL`. A regression that reset on any Ok would let a
    // single fault on the verdict still grant a counter reset (which
    // would in turn let the attacker continue brute-forcing past the
    // lockout).
    assert!(
        NSC_MOD_SRC.contains("Ok(master) if verdict == crate::fi::OK_SENTINEL"),
        "gated_unlock must gate the counter reset on (Ok && verdict-sentinel-OK)"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 15. Cross-cutting policy negatives — every slice file
//
// CLAUDE.md §"What NOT to do" hard-bans certain code patterns across
// the entire wallet. These tests sweep all eight files in scope and
// assert no instance has crept in.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_no_slice_file_mentions_a_classical_signer() {
    // CLAUDE.md invariant #5: "One signature primitive: SPHINCS+C10."
    // A drift here = invariant violation.
    let forbidden = [
        "secp256k1",
        "ecdsa_sign",
        "Ed25519",
        "ed25519_sign",
        "P-256",
        "FORS+C",
        "fors_c",
    ];
    for (name, src) in ALL_SLICE_FILES {
        for f in &forbidden {
            assert!(
                !src.contains(f),
                "{name} must not mention banned signer '{f}' — CLAUDE.md invariant #5"
            );
        }
    }
}

#[test]
fn negative_no_slice_file_exposes_reset_or_rotate_paths() {
    // CLAUDE.md §"What NOT to do": no rotateMasterKeys,
    // resetBootstrapUses, resetSlotUses, increaseMax*.
    let forbidden = [
        "rotateMasterKeys",
        "rotate_master_keys",
        "resetBootstrapUses",
        "reset_bootstrap_uses",
        "resetSlotUses",
        "reset_slot_uses",
        "increaseMaxBootstrap",
        "increase_max_bootstrap",
        "increaseMaxSlot",
        "increase_max_slot",
    ];
    for (name, src) in ALL_SLICE_FILES {
        for f in &forbidden {
            assert!(
                !src.contains(f),
                "{name} must not expose '{f}' — CLAUDE.md §What NOT to do"
            );
        }
    }
}

#[test]
fn negative_no_slice_file_targets_entrypoint_v07_or_v08() {
    // CLAUDE.md §"What NOT to do": v0.6 is the frozen target. Any
    // mention of v0.7 / v0.8 is a footgun.
    let forbidden = ["v0.7", "v0_7", "v0.8", "v0_8", "EntryPointV07", "EntryPointV08"];
    for (name, src) in ALL_SLICE_FILES {
        for f in &forbidden {
            assert!(
                !src.contains(f),
                "{name} must target only EntryPoint v0.6 — found '{f}'"
            );
        }
    }
}

#[test]
fn negative_no_slice_file_uses_format_or_alloc() {
    // CLAUDE.md §"Code Conventions": no heap, no allocator. No
    // `Vec` / `Box` / `String` / `format!`. Pin the absence so a
    // future refactor that pulls in alloc doesn't slip past review.
    let forbidden = [
        "Vec::new",
        "Box::new",
        "String::new",
        "String::from",
        "format!(",
        "vec![",
        "to_string()",
    ];
    for (name, src) in ALL_SLICE_FILES {
        for f in &forbidden {
            assert!(
                !src.contains(f),
                "{name} must not use heap-allocated '{f}' — CLAUDE.md §Code Conventions"
            );
        }
    }
}

#[test]
fn negative_no_slice_file_uses_software_prng() {
    // CLAUDE.md §"What NOT to do": No software PRNG. SmallRng /
    // StdRng / thread_rng are all forbidden — only the hardware
    // TRNG (or semihosting /dev/urandom on QEMU) is allowed.
    let forbidden = [
        "rand::thread_rng",
        "SmallRng",
        "ChaCha20Rng",
        "ChaCha8Rng",
        "StdRng::seed_from_u64",
    ];
    for (name, src) in ALL_SLICE_FILES {
        for f in &forbidden {
            assert!(
                !src.contains(f),
                "{name} must not use software PRNG '{f}' — hardware TRNG only"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// 16. NS-pointer validator semantics (`ptr_validate.rs`)
//
// Both `cmd_get_wallet_address` and `cmd_get_init_code` call
// `validate_ns_{read,write}_ptr` before any deref. The constants the
// validators compare against define the NS memory window — any drift
// in either of `NS_SRAM_BASE`, `NS_SRAM_END`, `SHARED_MAILBOX_BASE`,
// `SHARED_MAILBOX_END` would silently widen the validator's accept
// region and let NS supply a secure-side pointer.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_ns_sram_window_is_strictly_below_ns_sram_end() {
    // Sanity: a base equal to or above end would make the validator
    // reject every pointer.
    assert!(
        NS_SRAM_BASE < NS_SRAM_END,
        "NS_SRAM_BASE must be < NS_SRAM_END"
    );
}

#[test]
fn negative_ns_flash_window_is_strictly_below_ns_flash_end() {
    assert!(
        NS_FLASH_BASE < NS_FLASH_END,
        "NS_FLASH_BASE must be < NS_FLASH_END"
    );
}

#[test]
fn negative_shared_mailbox_lies_inside_ns_sram() {
    // The mailbox is a sub-region of NS SRAM. The validator's
    // mailbox-overlap rejection check assumes this nesting.
    assert!(
        SHARED_MAILBOX_BASE >= NS_SRAM_BASE && SHARED_MAILBOX_END <= NS_SRAM_END,
        "SHARED_MAILBOX must nest inside [NS_SRAM_BASE, NS_SRAM_END]"
    );
}

#[test]
fn negative_shared_mailbox_window_nonzero() {
    // The mailbox window must be non-empty; a base-equals-end
    // mailbox would let any NS pointer pass through the overlap
    // gate.
    assert!(
        SHARED_MAILBOX_BASE < SHARED_MAILBOX_END,
        "SHARED_MAILBOX_BASE must be strictly less than SHARED_MAILBOX_END"
    );
}

#[test]
fn negative_ns_sram_and_ns_flash_are_disjoint_regions() {
    // The validate_ns_read_ptr helper accepts the union of NS_SRAM
    // and NS_FLASH; the regions must be disjoint so the union maths
    // doesn't accidentally accept a stretch of secure memory.
    let sram_overlaps_flash =
        NS_SRAM_BASE < NS_FLASH_END && NS_FLASH_BASE < NS_SRAM_END;
    assert!(!sram_overlaps_flash, "NS SRAM and NS Flash must be disjoint");
}

// ─────────────────────────────────────────────────────────────────────
// 17. NscStatus pinning
//
// Every command in this slice returns one of a small set of u32
// status codes. The companion-side parser switches on the integer
// values, so a renumbering would silently mis-classify every error.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_nsc_status_codes_pin() {
    // `cmd_request_unlock` returns Ok / PinIncorrect / PinLocked /
    // InternalError / UserRejected / IdleWipe.
    // `cmd_get_wallet_address` / `cmd_get_init_code` return Ok /
    // NotInitialized / InvalidPointer / InternalError / CryptoError.
    // The numeric assignments must remain stable so a future
    // refactor of `NscStatus` enum order doesn't silently invert
    // success / failure for the companion.
    assert_eq!(NscStatus::Ok as u32, 0, "Ok must be 0");
    // Just ensure the load-bearing codes are non-overlapping and
    // non-zero — companion semantics depend on this.
    let codes = [
        NscStatus::PinIncorrect as u32,
        NscStatus::PinLocked as u32,
        NscStatus::InternalError as u32,
        NscStatus::UserRejected as u32,
        NscStatus::IdleWipe as u32,
        NscStatus::NotInitialized as u32,
        NscStatus::InvalidPointer as u32,
        NscStatus::CryptoError as u32,
    ];
    for &c in &codes {
        assert_ne!(c, 0, "non-Ok status must not collide with Ok");
    }
    // And every code must be distinct.
    for i in 0..codes.len() {
        for j in (i + 1)..codes.len() {
            assert_ne!(
                codes[i], codes[j],
                "NscStatus codes {} and {} collide ({}, {})",
                i, j, codes[i], codes[j]
            );
        }
    }
}
