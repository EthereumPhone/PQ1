//! Known-answer tests for the `keccak256` wrapper.
//!
//! `keccak256` is the EVM-mandated digest used for the EIP-1559 envelope
//! signing hash, EIP-4337 userOpHash, EIP-712 typed-data hashing, and
//! CREATE2 init-code commitments. Substituting a different hash here
//! (e.g. a future refactor that swaps in SHA-3-256 by accident, which
//! is a *different* function despite sharing the sponge construction)
//! would silently break every on-chain commitment the wallet derives.

use pqsigner_tx_core::hash::keccak256;

fn from_hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    assert_eq!(s.len(), 64, "hex string for a 32-byte hash must be 64 chars");
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

// ---------------------------------------------------------------------------
// Positive KATs — pin the actual hash function, not "some 32-byte digest"
// ---------------------------------------------------------------------------

#[test]
fn positive_keccak256_empty_kat() {
    // ASSUMPTION: keccak256 is the EVM Keccak-256, NOT NIST SHA-3-256.
    // Empty-input vector that distinguishes them:
    //   Keccak-256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    //   SHA-3-256("")  = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    let h = keccak256(&[]);
    assert_eq!(
        h,
        from_hex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    );
}

#[test]
fn positive_keccak256_abc_kat() {
    // Standard KAT: Keccak-256("abc")
    let h = keccak256(b"abc");
    assert_eq!(
        h,
        from_hex("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    );
}

#[test]
fn positive_keccak256_eth_canonical_kat() {
    // The string "Hello World!" → known EVM test vector.
    let h = keccak256(b"Hello World!");
    assert_eq!(
        h,
        from_hex("3ea2f1d0abf3fc66cf29eebb70cbd4e7fe762ef8a09bcc06c8edf641230afec0"),
    );
}

#[test]
fn positive_keccak256_long_input_processed_in_full() {
    // 200-byte all-0xff vector, asserts that input > one sponge
    // absorption block is correctly squeezed.
    let h = keccak256(&[0xffu8; 200]);
    // Independent value computed from a reference Keccak-256 implementation.
    assert_eq!(
        h,
        from_hex("3e04329b5f5c0f493dd965957722717ef46ed487733d5f9da932de72d9ac4a51"),
    );
}

#[test]
fn positive_keccak256_output_is_32_bytes() {
    // Trivially true via the signature, but the test pins it as part
    // of the public contract.
    let h = keccak256(b"x");
    assert_eq!(h.len(), 32);
}

#[test]
fn positive_keccak256_deterministic() {
    let inputs: &[&[u8]] = &[b"", b"x", b"the quick brown fox", &[0u8; 1024]];
    for input in inputs {
        let a = keccak256(input);
        let b = keccak256(input);
        assert_eq!(a, b);
    }
}

// ---------------------------------------------------------------------------
// Negative — distinguishing-input checks
// ---------------------------------------------------------------------------

#[test]
fn negative_keccak256_distinct_from_sha3_256_via_known_divergence() {
    // ASSUMPTION: keccak256 MUST equal Ethereum's Keccak-256, NOT
    // FIPS-202 SHA3-256. The two algorithms differ in their domain
    // separator byte (Keccak: 0x01, SHA3: 0x06) and produce different
    // digests for any input. Empty-input vector is the cheapest way
    // to detect a swap.
    let h = keccak256(&[]);
    let sha3_empty =
        from_hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    assert_ne!(
        h, sha3_empty,
        "wrong hash family — looks like SHA3-256 instead of Keccak-256",
    );
}

#[test]
fn negative_keccak256_single_bit_input_change_avalanches() {
    // Two inputs differing by a single bit must produce wildly
    // different digests (informal avalanche check — at least 64 of
    // 256 bits flip in a healthy hash function).
    let h0 = keccak256(b"\x00");
    let h1 = keccak256(b"\x01");
    assert_ne!(h0, h1);
    let mut diff_bits = 0u32;
    for (a, b) in h0.iter().zip(h1.iter()) {
        diff_bits += (a ^ b).count_ones();
    }
    assert!(
        diff_bits >= 64,
        "only {diff_bits}/256 bits flipped — hash is not avalanching",
    );
}

#[test]
fn negative_keccak256_different_inputs_produce_different_digests() {
    // Sanity that we aren't accidentally returning a fixed constant.
    let mut seen = std::collections::HashSet::new();
    for i in 0u8..32 {
        let h = keccak256(&[i]);
        assert!(seen.insert(h), "collision at byte {i}");
    }
}
