//! Checks the manually modelled C10Bytes transcript against the real helpers.
//! This is finite host evidence, not extraction or a proof about SHA-256.
#![cfg(feature = "sim-internals")]

use sha2::{Digest, Sha256};
use sphincs_c10::sim_internals::{make_adrs, pad16, wots_digest};

// C10Bytes.bits_to_bytes: little-endian bits, chunks of eight, reversed bytes.
fn model_bytes(bits: &[bool]) -> Vec<u8> {
    assert_eq!(bits.len() % 8, 0);
    bits.chunks_exact(8)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0, |v, (i, b)| v | (u8::from(*b) << i))
        })
        .rev()
        .collect()
}

#[test]
fn concrete_digest_matches_easycrypt_byte_adapter() {
    let seed = core::array::from_fn(|i| (i * 7 + 3) as u8);
    // Distinct bytes in every address field catch order and width changes.
    let address = make_adrs(
        0x01020304,
        0x05060708090a0b0c,
        0x0d0e0f10,
        0x11121314,
        0x15161718,
        0x191a1b1c,
        0x1d1e1f20,
    );
    assert_eq!(address, core::array::from_fn(|i| (i + 1) as u8));
    let mut counters = vec![0, 1, 9_999_999, 10_000_000, 10_000_001, u32::MAX];
    for bit in 0..32 {
        counters.push(1u32 << bit);
        counters.push((1u32 << bit) - 1);
    }
    for node_value in [0, u128::MAX, 0x0102030405060708090a0b0c0d0e0f10] {
        let node_bits: Vec<_> = (0..128).map(|i| (node_value >> i) & 1 == 1).collect();
        let node = node_value.to_be_bytes();
        assert_eq!(model_bytes(&node_bits), node);
        let padded = pad16(&node);
        assert_eq!(&padded[..16], &node);
        assert_eq!(&padded[16..], &[0u8; 16]);
        for &counter in &counters {
            let counter_bits: Vec<_> = (0..32).map(|i| (counter >> i) & 1 == 1).collect();
            let counter_bytes = model_bytes(&counter_bits);
            assert_eq!(counter_bytes, counter.to_be_bytes());
            let mut transcript = Vec::new();
            transcript.extend(seed);
            transcript.extend(address);
            transcript.extend(model_bytes(&node_bits));
            transcript.extend([0u8; 16 + 28]);
            transcript.extend(counter_bytes);
            assert_eq!(transcript.len(), 128);
            let expected: [u8; 32] = Sha256::digest(&transcript).into();
            // Compare the full output: both halves belong to the same hash.
            assert_eq!(wots_digest(&seed, &address, &padded, counter), expected);
        }
    }
}
