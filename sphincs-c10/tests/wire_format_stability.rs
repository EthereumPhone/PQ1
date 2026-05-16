//! Frozen wire-format / constant stability tests.
//!
//! The numbers in `sphincs_c10::params` are baked into the on-chain
//! `SPHINCsC10Asm.sol` Yul verifier, the firmware's NSC sign output
//! layout, and the cross-chain CREATE2 init-code hash (which encodes
//! both the bootstrap pk and the on-chain verifier's expectations).
//! Any silent change here is a consensus-level break.
//!
//! These tests duplicate the `const _: assert!(...)` checks in
//! `params.rs` deliberately — the compile-time asserts catch a refactor
//! that changes the structural derivation; these runtime asserts surface
//! a clear, citation-bearing failure if someone "fixes" the constants
//! to a different value.

use sphincs_c10::params::*;

// ---------------------------------------------------------------------------
// Parameter-set constants (C10 frozen)
// ---------------------------------------------------------------------------

#[test]
fn frozen_security_parameter_n() {
    assert_eq!(
        N, 16,
        "N must remain 16 (128-bit security parameter); changing breaks every \
         on-chain verifier and the pk_seed[..N] N_MASK in src/crypto.rs."
    );
}

#[test]
fn frozen_hypertree_geometry() {
    assert_eq!(H, 18, "H must remain 18 (CLAUDE.md C10 parameter set)");
    assert_eq!(D, 2, "D must remain 2 (CLAUDE.md C10 parameter set)");
    assert_eq!(SUBTREE_H, 9, "SUBTREE_H must remain H/D = 9");
    assert_eq!(SUBTREE_LEAVES, 512, "SUBTREE_LEAVES must remain 1 << 9 = 512");
    assert_eq!(SUBTREE_H * D, H, "SUBTREE_H * D must equal H");
}

#[test]
fn frozen_fors_geometry() {
    assert_eq!(K, 13, "K must remain 13 (FORS trees in C10)");
    assert_eq!(A, 11, "A must remain 11 (FORS tree height in C10)");
    assert_eq!(FORS_LEAVES, 2048, "FORS_LEAVES must remain 1 << A = 2048");
}

#[test]
fn frozen_wots_geometry() {
    assert_eq!(W, 8, "Winternitz parameter W must remain 8");
    assert_eq!(LOG_W, 3, "LOG_W must remain 3 = log2(W)");
    assert_eq!(L, 43, "WOTS chain count L must remain 43");
    assert_eq!(W_MASK, 0x07, "W_MASK must remain 7 (W-1)");
    assert_eq!(
        TARGET_SUM, 205,
        "WOTS+C TARGET_SUM must remain 205; on-chain verifier asserts \
         `eq(digitSum, 205)` and reverts otherwise."
    );
}

#[test]
fn frozen_signature_layout_sizes() {
    assert_eq!(
        SIG_FORS_TOTAL, 2336,
        "FORS section size (R+secrets+auth) must remain 2336"
    );
    assert_eq!(
        SIG_HT_LAYER, 836,
        "Hypertree layer size (L*N + 4 + SUBTREE_H*N) must remain 836"
    );
    assert_eq!(
        SIGNATURE_LEN, 4008,
        "Total C10 signature size MUST be 4008 bytes — the secure-world \
         NSC unified sign output, the EIP-1271/6492 wrapper, and the on-chain \
         Yul verifier all hard-code this length."
    );
}

#[test]
fn frozen_key_lengths() {
    assert_eq!(SIGNING_KEY_SEED_LEN, 48, "sk_seed(32) + pk_seed(16) = 48");
    assert_eq!(
        VERIFYING_KEY_LEN, 32,
        "VK = pk_seed(16) || pk_root(16) — frozen since v1; \
         the factory passes 32-byte VKs in initCode."
    );
}

#[test]
fn frozen_signature_layout_offsets_match_companion_mutation_offsets() {
    // The companion tests (tests/gen_test_vectors.rs) mutate bytes at
    // specific signature offsets to exercise the on-chain verifier's
    // rejection paths. Those offsets are baked into Foundry tests, so a
    // layout change here is an immediate on-chain regression.
    let r_offset = 0usize;
    let fors_secrets_offset = N; // R is N bytes
    let fors_auth_paths_offset = fors_secrets_offset + K * N;
    let ht_layer0_offset = SIG_FORS_TOTAL; // FORS section ends here
    let ht_layer0_count_offset = ht_layer0_offset + L * N;
    let ht_layer0_auth_offset = ht_layer0_count_offset + 4;
    let ht_layer1_offset = ht_layer0_offset + SIG_HT_LAYER;

    assert_eq!(r_offset, 0);
    assert_eq!(fors_secrets_offset, 16);
    assert_eq!(fors_auth_paths_offset, 16 + 13 * 16); // 224
    assert_eq!(ht_layer0_offset, 2336);
    assert_eq!(
        ht_layer0_count_offset,
        2336 + 43 * 16, // 3024
        "Count offset matches the value baked into tests/gen_test_vectors.rs"
    );
    assert_eq!(ht_layer0_auth_offset, 3028);
    assert_eq!(ht_layer1_offset, 3172);
    assert_eq!(ht_layer1_offset + SIG_HT_LAYER, SIGNATURE_LEN);
}

// ---------------------------------------------------------------------------
// ADRS type constants (must match Solidity verifier)
// ---------------------------------------------------------------------------

#[test]
fn frozen_adrs_type_constants() {
    assert_eq!(ADRS_WOTS, 0);
    assert_eq!(ADRS_WOTS_PK, 1);
    assert_eq!(ADRS_TREE, 2);
    assert_eq!(ADRS_FORS_TREE, 3);
    assert_eq!(ADRS_FORS_ROOTS, 4);
}
