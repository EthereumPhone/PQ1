// WOTS generation through the actual production module and an independent
// preimage/address/chain/compression oracle. No production source rewriting.
fn ref_wots_secret(sk: &[u8; 32], layer: u32, tree: u64, kp: u32, chain: u32) -> [u8; 16] {
    let mut bytes = sk.to_vec();
    bytes.extend_from_slice(b"wots");
    bytes.extend_from_slice(&layer.to_be_bytes());
    bytes.extend_from_slice(&[0; 24]);
    bytes.extend_from_slice(&tree.to_be_bytes());
    bytes.extend_from_slice(&kp.to_be_bytes());
    bytes.extend_from_slice(&chain.to_be_bytes());
    assert_eq!(bytes.len(), 80);
    Sha256::digest(bytes)[..16].try_into().unwrap()
}

#[test]
fn wots_keygen_corpus() {
    let seed = std::array::from_fn(|i| (7 * i + 13) as u8);
    let sk = std::array::from_fn(|i| (23 * i + 11) as u8);
    let mut cases = vec![
        ([0; 32], [0; 32], 0u32, 0u64, 0u32),
        ([255; 32], [255; 32], u32::MAX, u64::MAX, u32::MAX),
        (seed, sk, 0x8102_0304, 0x8123_4567_89ab_cdef, 0xfeab_cd00),
    ];
    for i in 0..32 {
        let mut one = [0; 32];
        one[i] = 0x81;
        cases.push((one, sk, 0, 0, 0));
        cases.push((seed, one, 0, 0, 0));
        cases.push((seed, sk, 1 << i, 0, 0));
        cases.push((seed, sk, 0, 0, 1 << i));
    }
    for bit in 0..64 {
        cases.push((seed, sk, 0, 1 << bit, 0));
    }
    assert_eq!(cases.len(), 195);
    let mut out = String::from("-- Generated from actual Rust WOTS keygen and independent byte oracle.\nnamespace WotsKeygenDiff\nstructure Vector where\n  seed : Array UInt8\n  sk : Array UInt8\n  layer : Nat\n  tree : Nat\n  kp : Nat\n  result : Array UInt8\n  deriving Inhabited\ndef vectors : List Vector := [\n");
    for (seed, sk, layer, tree, kp) in cases {
        let ends: [[u8; 16]; 43] = std::array::from_fn(|j| {
            ref_chain(
                &seed,
                &ref_adrs(layer, tree, 0, kp, j as u32, 0),
                &ref_wots_secret(&sk, layer, tree, kp, j as u32),
                0,
                7,
            )
        });
        let expected = ref_compress(&seed, &ref_adrs(layer, tree, 1, kp, 0, 0), &ends);
        let actual = crate::wots::keygen_pk(&seed, &sk, layer, tree, kp);
        assert_eq!(actual, expected);
        out.push_str(&format!("{{ seed := {}, sk := {}, layer := {layer}, tree := {tree}, kp := {kp}, result := {} }},\n", array(&seed), array(&sk), array(&actual)));
    }
    out.push_str("]\nend WotsKeygenDiff\n");
    let dest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../extracted/Extracted/WotsKeygenDiffVectors.lean");
    if std::env::var("PQ_WOTS_KEYGEN_GENERATE").as_deref() == Ok("1") {
        std::fs::write(dest, out).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(dest).unwrap(), out);
    }
    println!("OK: 195 actual WOTS keygen calls: full-width address fields, both seeds, all 43 endpoints, seven steps, ordered compression; independent byte oracle");
}
