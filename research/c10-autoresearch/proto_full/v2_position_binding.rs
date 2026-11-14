//! RESEARCH (round 20 addendum, 2026-11-14): FORS / WOTS secret POSITION-BINDING for the v2
//! variants, on the Rust signer (copied into a build-time copy of sphincs-c10 by
//! `proto_full/position_binding.sh`; never into the product crate). The Python twin is
//! `c10v2/position_binding.py`; both derive the same key (kat_key(0)) and message sequence,
//! so they must find the same signature pair.
//!
//! F: two HONEST signatures at different hypertree positions that open the same FORS
//!    (tree t, leaf j) reveal DIFFERENT secrets, each equal to `fors_secret` at its position.
//! W: the same chain index at a different (layer, tree, kp) gives a different `wots_secret`
//!    (a grid, each single-field change, and the two honest signatures' own positions).
//! The mutant features `pb-mut-*` (added to the copy only) drop a position field from the PRF
//! input; each must make F or W fail while the signatures still verify.
#![cfg(all(feature = "v2", feature = "sim-internals"))]

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use sphincs_c10::params::{layer_h, D, K, L, N, SIGNATURE_LEN};
use sphincs_c10::sim_internals::{extract_fors_indices, extract_ht_index, fors_secret, grind_r, wots_secret};
use sphincs_c10::SigningKey;

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// c10v2_ref.kat_key(0).
fn key() -> ([u8; 32], [u8; N]) {
    let sk = sha(&[b"c10v2-kat-sk", &0u32.to_be_bytes()]);
    let ps: [u8; N] = sha(&[b"c10v2-kat-pkseed", &0u32.to_be_bytes()])[..N].try_into().unwrap();
    (sk, ps)
}

fn msg(i: u32) -> [u8; 32] {
    sha(&[b"c10v2-posbind-msg", &i.to_be_bytes()])
}

struct Pair {
    i1: u32,
    i2: u32,
    t: usize,
    j: u32,
    ht1: u32,
    ht2: u32,
    s1: Option<[u8; SIGNATURE_LEN]>,
    s2: Option<[u8; SIGNATURE_LEN]>,
}

/// The first message pair (in message order) whose digests open the same (t, j), t < K - 1, at
/// different hypertree positions (the Python twin's search, step for step).
fn find_pair(sk: &[u8; 32], ps: &[u8; N], root: &[u8; N]) -> Pair {
    let mut seen: HashMap<(usize, u32), (u32, u32)> = HashMap::new();
    for i in 0u32.. {
        let (_r, d) = grind_r(sk, ps, root, &msg(i), None);
        let (f, ht) = (extract_fors_indices(&d), extract_ht_index(&d));
        for t in 0..K - 1 {
            if let Some(&(i1, ht1)) = seen.get(&(t, f[t])) {
                if ht1 != ht {
                    return Pair { i1, i2: i, t, j: f[t], ht1, ht2: ht, s1: None, s2: None };
                }
            }
            seen.entry((t, f[t])).or_insert((i, ht));
        }
    }
    unreachable!()
}

fn positions(ht: u32) -> [(u32, u64, u32); D] {
    let mut tree = u64::from(ht);
    core::array::from_fn(|layer| {
        let h = layer_h(layer as u32);
        let kp = (tree & ((1 << h) - 1)) as u32;
        tree >>= h;
        (layer as u32, tree, kp)
    })
}

/// Key, pair and the two honest signatures (both verified).
fn setup() -> ([u8; 32], Pair) {
    let (sk, ps) = key();
    let key = SigningKey::keygen(sk, ps);
    let root = *key.pk_root();
    let p = find_pair(&sk, &ps, &root);
    println!(
        "pair msgs ({}, {}) open FORS (t={}, j={}) at ht {:#07x} / {:#07x}",
        p.i1, p.i2, p.t, p.j, p.ht1, p.ht2
    );
    let (m1, m2) = (msg(p.i1), msg(p.i2));
    let (s1, s2) = (key.sign(&m1, None), key.sign(&m2, None));
    let vk = key.verifying_key();
    let verified = (vk.verify(&m1, &s1), vk.verify(&m2, &s2));
    println!("honest signatures verify: {verified:?}");
    assert!(verified.0 && verified.1, "SETUP: an honest signature does not verify");
    (sk, Pair { s1: Some(s1), s2: Some(s2), ..p })
}

#[test]
fn fors_binding_two_honest_signatures() {
    let (sk, p) = setup();
    let (s1, s2) = (p.s1.unwrap(), p.s2.unwrap());
    let off = N + N * p.t;
    let (a, b): ([u8; N], [u8; N]) = (s1[off..off + N].try_into().unwrap(), s2[off..off + N].try_into().unwrap());
    assert_ne!(p.ht1, p.ht2, "SETUP: the pair is at one position");
    assert_eq!(a, fors_secret(&sk, p.ht1, p.t as u32, p.j), "SETUP: revealed secret is not fors_secret at ht1");
    assert_eq!(b, fors_secret(&sk, p.ht2, p.t as u32, p.j), "SETUP: revealed secret is not fors_secret at ht2");
    assert_ne!(a, b, "F FAILED: FORS (t={}, j={}) secret SHARED across ht {:#x} / {:#x}", p.t, p.j, p.ht1, p.ht2);
    // within one position: distinct (tree, leaf) give distinct secrets, including the prf2 pair partner j ^ 1
    let leaves = [0u32, 1, 2, 3, 2046, 2047, p.j, p.j ^ 1];
    for ht in [p.ht1, p.ht2] {
        let mut seen: HashMap<[u8; N], (u32, u32)> = HashMap::new();
        for t2 in [0u32, p.t as u32, K as u32 - 2, K as u32 - 1] {
            for leaf in leaves {
                let v = fors_secret(&sk, ht, t2, leaf);
                if let Some(prev) = seen.insert(v, (t2, leaf)) {
                    if prev != (t2, leaf) {
                        panic!("F FAILED: FORS secrets of {prev:?} and {:?} COLLIDE within ht {ht:#x}", (t2, leaf));
                    }
                }
            }
        }
    }
    println!("F holds");
}

#[test]
fn wots_binding_grid_and_honest_positions() {
    let (sk, p) = setup();
    // W: a grid of positions per chain index, each single-field change, the honest positions
    let mut grid = Vec::new();
    for layer in 0..D as u32 {
        let kmax = (1u32 << layer_h(layer)) - 1;
        for tree in [0u64, 1, 0x2a5] {
            for kp in [0u32, 1, kmax] {
                grid.push((layer, tree, kp));
            }
        }
    }
    for ci in [0u32, 1, 2, L as u32 - 2, L as u32 - 1] {
        let mut seen: HashMap<[u8; N], (u32, u64, u32)> = HashMap::new();
        for &(layer, tree, kp) in &grid {
            let v = wots_secret(&sk, layer, tree, kp, ci);
            if let Some(prev) = seen.insert(v, (layer, tree, kp)) {
                panic!("W FAILED: wots_secret ci={ci} SHARED by positions {prev:?} and {:?}", (layer, tree, kp));
            }
        }
        let base = wots_secret(&sk, 1, 0x2a5, 1, ci);
        assert_ne!(base, wots_secret(&sk, 0, 0x2a5, 1, ci), "W FAILED: wots_secret ci={ci} ignores layer");
        assert_ne!(base, wots_secret(&sk, 1, 0, 1, ci), "W FAILED: wots_secret ci={ci} ignores tree");
        assert_ne!(base, wots_secret(&sk, 1, 0x2a5, 0, ci), "W FAILED: wots_secret ci={ci} ignores kp");
    }
    // within one position: all L chain secrets distinct (every prf2 pair 2j / 2j + 1, and chain 42)
    let mut own: Vec<(u32, u64, u32)> = vec![(0, 0, 0), (1, 0x2a5, 1)];
    own.extend(positions(p.ht1));
    own.extend(positions(p.ht2));
    for (layer, tree, kp) in own {
        let mut seen: HashMap<[u8; N], u32> = HashMap::new();
        for ci in 0..L as u32 {
            if let Some(prev) = seen.insert(wots_secret(&sk, layer, tree, kp, ci), ci) {
                panic!("W FAILED: wots_secret chains {prev} and {ci} COLLIDE within position {:?}", (layer, tree, kp));
            }
        }
    }
    for (pa, pb) in positions(p.ht1).iter().zip(positions(p.ht2).iter()) {
        if (pa.1, pa.2) == (pb.1, pb.2) {
            continue;
        }
        for ci in 0..L as u32 {
            assert_ne!(
                wots_secret(&sk, pa.0, pa.1, pa.2, ci),
                wots_secret(&sk, pb.0, pb.1, pb.2, ci),
                "W FAILED: honest positions {pa:?} / {pb:?} share chain {ci}'s secret"
            );
        }
    }
    println!("W holds");
}
