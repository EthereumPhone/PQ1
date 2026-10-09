// Test child of the unchanged private-helper module. The oracle assembles
// the hash inputs independently and uses a recursive tree, not the stack.
fn roundtrip_oracle_node(
    seed: &[u8; 32], sk: &[u8; 32], ht: u32, tree: u32, height: u32, index: u32,
) -> [u8; 16] {
    let mut input = seed.to_vec();
    input.extend_from_slice(&reference_adrs(ht, tree, height, index));
    if height == 0 {
        let mut preimage = sk.to_vec();
        preimage.extend_from_slice(b"fors");
        preimage.extend_from_slice(&ht.to_be_bytes());
        preimage.extend_from_slice(&tree.to_be_bytes());
        preimage.extend_from_slice(&index.to_be_bytes());
        input.extend_from_slice(&Sha256::digest(preimage)[..16]);
        input.extend_from_slice(&[0; 16]);
    } else {
        input.extend_from_slice(&roundtrip_oracle_node(seed, sk, ht, tree, height - 1, 2 * index));
        input.extend_from_slice(&[0; 16]);
        input.extend_from_slice(&roundtrip_oracle_node(seed, sk, ht, tree, height - 1, 2 * index + 1));
        input.extend_from_slice(&[0; 16]);
    }
    Sha256::digest(input)[..16].try_into().unwrap()
}

#[test]
fn fors_sign_recover_corpus() {
    let seed = std::array::from_fn(|i| (i * 17 + 13) as u8);
    let sk = std::array::from_fn(|i| (i * 13 + 19) as u8);
    let (ht, tree) = (0x8102_0304, 11);
    let expected = roundtrip_oracle_node(&seed, &sk, ht, tree, 11, 0);
    assert_eq!(fors::compute_fors_root(&seed, &sk, ht, tree), expected);
    for leaf in 0..2048 {
        let (secret, path) = fors::sign_fors_tree(&seed, &sk, ht, tree, leaf);
        assert_eq!(reconstruct_fors_root(&seed, ht, tree, leaf, &secret, &path), expected);
        for h in 0..11 {
            let mut changed = path;
            changed[h][0] ^= 1;
            assert_ne!(reconstruct_fors_root(&seed, ht, tree, leaf, &secret, &changed), expected,
                       "changed sibling accepted: leaf={leaf}, height={h}");
        }
    }
    for (ht, tree, leaf) in [
        (0, 0, 0), (1 << 17, 12, 2047), (1 << 18, 13, 0x555),
        (1 << 31, 1 << 31, 0x2aa), (u32::MAX, u32::MAX, 0),
        (u32::MAX, u32::MAX, 2047),
    ] {
        let expected = roundtrip_oracle_node(&seed, &sk, ht, tree, 11, 0);
        let (secret, path) = fors::sign_fors_tree(&seed, &sk, ht, tree, leaf);
        assert_eq!(reconstruct_fors_root(&seed, ht, tree, leaf, &secret, &path), expected);
        assert_eq!(fors::compute_fors_root(&seed, &sk, ht, tree), expected);
    }
    println!("OK: 2048 actual sign/recover/root cases, 22528 changed siblings, 6 full-width positions");
}
