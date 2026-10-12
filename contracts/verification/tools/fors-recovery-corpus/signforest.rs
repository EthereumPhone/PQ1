// Whole, unchanged production signer plus an independent recursive byte oracle.
// Full-width forest positions below exercise the component outside the 18-bit header domain.
type SignForestRows = ([[u8; 16]; 13], [[u8; 16]; 13], [[[u8; 16]; 11]; 12]);
fn signforest_oracle(seed: &[u8; 32], sk: &[u8; 32], ht: u32, indices: &[u32; 13]) -> SignForestRows {
    let mut roots = [[0; 16]; 13];
    let mut secrets = [[0; 16]; 13];
    let mut paths = [[[0; 16]; 11]; 12];
    for t in 0..13 {
        let root = roundtrip_oracle_node(seed, sk, ht, t as u32, 11, 0);
        if t == 12 {
            secrets[t] = root;
            let mut input = seed.to_vec();
            input.extend_from_slice(&reference_adrs(ht, 12, 0, 0));
            input.extend_from_slice(&root);
            input.extend_from_slice(&[0; 16]);
            roots[t] = Sha256::digest(input)[..16].try_into().unwrap();
            assert_eq!(fors::compute_fors_root(seed, sk, ht, 12), root);
        } else {
            let mut input = sk.to_vec();
            input.extend_from_slice(b"fors");
            input.extend_from_slice(&ht.to_be_bytes());
            input.extend_from_slice(&(t as u32).to_be_bytes());
            input.extend_from_slice(&indices[t].to_be_bytes());
            secrets[t] = Sha256::digest(input)[..16].try_into().unwrap();
            for h in 0..11 {
                paths[t][h] = roundtrip_oracle_node(seed, sk, ht, t as u32, h as u32, (indices[t] >> h) ^ 1);
            }
            roots[t] = root;
            assert_eq!(fors::sign_fors_tree(seed, sk, ht, t as u32, indices[t]), (secrets[t], paths[t]));
            assert_eq!(reconstruct_fors_root(seed, ht, t as u32, indices[t], &secrets[t], &paths[t]), root);
        }
    }
    (roots, secrets, paths)
}
fn signforest_rows(rows: &[[u8; 16]]) -> String {
    format!("#[{}]", rows.iter().map(|r| array(r)).collect::<Vec<_>>().join(", "))
}
fn signforest_record(out: &mut String, label: &str, seed: &[u8; 32], sk: &[u8; 32], ht: u32,
                     indices: &[u32; 13], shuffle: &[u8; 32], rows: &SignForestRows) {
    let (roots, secrets, paths) = rows;
    let pk = ref_compress(seed, &ref_adrs(0, u64::from(ht), 4, 0, 0, 0), roots);
    assert_eq!(fors::compute_fors_pk(seed, ht, roots), pk);
    let indices = indices.iter().map(u32::to_string).collect::<Vec<_>>().join(", ");
    let paths = format!("#[{}]", paths.iter().map(|p| signforest_rows(p)).collect::<Vec<_>>().join(", "));
    out.push_str(&format!("{{ label := \"{label}\", seed := {}, sk := {}, ht := {ht}, indices := #[{indices}], shuffle := {}, roots := {}, secrets := {}, paths := {paths}, pk := {} }},\n",
        array(seed), array(sk), array(shuffle), signforest_rows(roots), signforest_rows(secrets), array(&pk)));
}
#[test]
fn sign_forest_corpus() {
    let mut out = String::from("-- Independent recursive byte oracle; actual whole-signer and full-width component cases.\nnamespace SignForestDiff\nstructure Vector where\n  label : String\n  seed : Array UInt8\n  sk : Array UInt8\n  ht : Nat\n  indices : Array Nat\n  shuffle : Array UInt8\n  roots : Array (Array UInt8)\n  secrets : Array (Array UInt8)\n  paths : Array (Array (Array UInt8))\n  pk : Array UInt8\n  deriving Inhabited\ndef vectors : List Vector := [\n");
    let shuffles = [[0; 32], [255; 32], std::array::from_fn(|i| (i * 7 + 9) as u8)];
    for case in 0..2 {
        let sk = std::array::from_fn(|i| (i * 13 + 19 + case * 37) as u8);
        let pk_seed = std::array::from_fn(|i| (i * 17 + 11 + case * 23) as u8);
        let msg = std::array::from_fn(|i| (i * 7 + 3 + case * 29) as u8);
        let opt = [case as u8; 16];
        let root = compute_pk_root(&sk, &pk_seed);
        let mut seed = [0; 32]; seed[..16].copy_from_slice(&pk_seed);
        let first = sign_inner(&sk, &pk_seed, &root, &msg, Some(&opt), &progress_none(), &ShuffleSeed(shuffles[0]));
        let digest = prefix_digest(&pk_seed, &root, &msg, &first);
        let ht = prefix_bits(&digest, 143, 18);
        let indices = std::array::from_fn(|t| prefix_bits(&digest, t * 11, 11));
        assert_eq!(indices[12], 0);
        let rows = signforest_oracle(&seed, &sk, ht, &indices);
        for (s, shuffle) in shuffles.iter().enumerate() {
            let sig = if s == 0 { first } else {
                sign_inner(&sk, &pk_seed, &root, &msg, Some(&opt), &progress_none(), &ShuffleSeed(*shuffle))
            };
            assert_eq!(sig, first, "whole signer changed under shuffle");
            assert!(verify(&pk_seed, &root, &msg, &sig));
            for t in 0..13 { assert_eq!(&sig[16+16*t..32+16*t], &rows.1[t]); }
            for t in 0..12 { for h in 0..11 {
                assert_eq!(&sig[224+176*t+16*h..240+176*t+16*h], &rows.2[t][h]);
            } }
        }
        if case == 0 { signforest_record(&mut out, "whole-signer", &seed, &sk, ht, &indices, &shuffles[1], &rows); }
    }
    let seed = std::array::from_fn(|i| (i * 17 + 13) as u8);
    let sk = std::array::from_fn(|i| (i * 13 + 19) as u8);
    let indices = [0,2047,1,2046,0x555,0x2aa,255,256,1023,1024,511,512,u32::MAX];
    let rows = signforest_oracle(&seed, &sk, u32::MAX, &indices);
    signforest_record(&mut out, "full-width-component", &seed, &sk, u32::MAX, &indices, &shuffles[2], &rows);
    out.push_str("]\nstructure DeriveVector where\n  seed : Array UInt8\n  label : Array UInt8\n  derived : Array UInt8\n  deriving Inhabited\ndef derivations : List DeriveVector := [\n");
    let labels: Vec<Vec<u8>> = vec![vec![], b"fors".to_vec(), b"wots\0".to_vec(), b"wots\x01".to_vec(), (0..=255).collect()];
    for seed in shuffles { for label in &labels {
        let expected: [u8; 32] = if seed == [0; 32] { [0; 32] } else {
            let mut input = b"sphincs-c10-shuffle-v1".to_vec(); input.extend_from_slice(&seed); input.extend_from_slice(label);
            Sha256::digest(input).into()
        };
        assert_eq!(ShuffleSeed(seed).derive(label), expected);
        out.push_str(&format!("{{ seed := {}, label := {}, derived := {} }},\n", array(&seed), array(label), array(&expected)));
    } }
    out.push_str("]\nend SignForestDiff\n");
    let dest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../extracted/Extracted/SignForestDiffVectors.lean");
    if std::env::var("PQ_SIGN_FOREST_GENERATE").as_deref() == Ok("1") { std::fs::write(dest, out).unwrap(); }
    else { assert_eq!(std::fs::read_to_string(dest).unwrap(), out); }
    println!("OK: six actual whole signatures over two messages/three shuffles; all 13 secrets/132 siblings against independent recursive oracle; full-width component case; 15 derivations; two Lean forest witnesses");
}
