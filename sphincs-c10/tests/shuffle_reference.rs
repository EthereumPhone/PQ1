//! Exact stream/order check: signature equality alone cannot detect a changed
//! shuffle, since every valid permutation produces the same signature.
use sha2::{Digest, Sha256};
use sphincs_c10::shuffle::fisher_yates;

fn reference(seed: &[u8; 32], n: usize) -> [u8; 64] {
    let mut prefix: Vec<u8> = (0..n as u8).collect();
    if seed.iter().any(|&b| b != 0) && n > 1 {
        let stream: Vec<u8> = (0u32..4)
            .flat_map(|counter| {
                let message = [
                    b"sphincs-c10-fisher-yates-v1".as_slice(),
                    seed.as_slice(),
                    &counter.to_be_bytes(),
                ].concat();
                Sha256::digest(message).to_vec()
            })
            .collect();
        for (i, pair) in (1..n).rev().zip(stream.chunks_exact(2)) {
            let sample = u16::from_le_bytes([pair[0], pair[1]]) as u64;
            let j = (sample * (i as u64 + 1) / 65536) as usize;
            prefix.swap(i, j);
        }
    }
    let mut out = [0; 64];
    out[..n].copy_from_slice(&prefix);
    out
}

#[test]
fn exact_order_and_tail_for_every_prefix_length() {
    let mut seeds = vec![[0; 32], [1; 32], [0x55; 32], [0xaa; 32], [0xff; 32]];
    seeds.push(core::array::from_fn(|i| i as u8));
    seeds.push(core::array::from_fn(|i| 255 - i as u8));
    for i in 0..32 {
        let mut seed = [0; 32];
        seed[i] = 1 << (i % 8);
        seeds.push(seed);
    }
    for (case, seed) in seeds.iter().enumerate() {
        for n in 0..=64 {
            assert_eq!(fisher_yates(seed, n), reference(seed, n), "seed {case}, n {n}");
        }
    }
}
