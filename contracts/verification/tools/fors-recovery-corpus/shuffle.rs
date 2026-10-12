// Independent exact shuffle stream/order oracle, including the unused tail.
fn ref_shuffle(seed: &[u8; 32], n: usize) -> [u8; 64] {
    let mut prefix: Vec<u8> = (0..n as u8).collect();
    if seed.iter().any(|&b| b != 0) && n > 1 {
        let stream: Vec<u8> = (0u32..4).flat_map(|counter| {
            let message = [b"sphincs-c10-fisher-yates-v1".as_slice(), seed.as_slice(), &counter.to_be_bytes()].concat();
            Sha256::digest(message).to_vec()
        }).collect();
        for (i, pair) in (1..n).rev().zip(stream.chunks_exact(2)) {
            let sample = u16::from_le_bytes([pair[0], pair[1]]) as u64;
            prefix.swap(i, (sample * (i as u64 + 1) / 65536) as usize);
        }
    }
    let mut result = [0; 64];
    result[..n].copy_from_slice(&prefix);
    result
}

#[test]
fn shuffle_corpus() {
    let mut cases = Vec::new();
    for seed in [[0; 32], [1; 32], [255; 32], std::array::from_fn(|i| i as u8), std::array::from_fn(|i| (255-i) as u8)] {
        for n in [0, 1, 2, 13, 32, 43, 63, 64] { cases.push((seed, n)); }
    }
    for i in 0..32 {
        let mut seed = [0; 32]; seed[i] = 1 << (i%8);
        cases.push((seed, 43));
    }
    assert_eq!(cases.len(), 72);
    let mut out = String::from("-- Independent SHA stream, multiply/divide reduction and prefix swaps.\nnamespace ShuffleDiff\nstructure Vector where\n  seed : Array UInt8\n  n : Nat\n  order : Array UInt8\n  deriving Inhabited\ndef vectors : List Vector := [\n");
    for (seed, n) in cases {
        let expected = ref_shuffle(&seed, n);
        assert_eq!(crate::shuffle::fisher_yates(&seed, n), expected);
        out.push_str(&format!("{{ seed := {}, n := {n}, order := {} }},\n", array(&seed), array(&expected)));
    }
    out.push_str("]\nend ShuffleDiff\n");
    let dest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../extracted/Extracted/ShuffleDiffVectors.lean");
    if std::env::var("PQ_SHUFFLE_GENERATE").as_deref() == Ok("1") {
        std::fs::write(dest, out).unwrap();
    } else { assert_eq!(std::fs::read_to_string(dest).unwrap(), out); }
    println!("OK: 72 actual shuffle exact-order/tail oracle cases for Lean; all seed bytes, zero seed,0/1/2/13/32/43/63/64 lengths");
}
