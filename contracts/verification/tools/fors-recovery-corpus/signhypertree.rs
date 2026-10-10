// Actual unchanged two-layer source fragment versus recursive byte/preimage
// oracles. The oracle chooses fields without calling the production signer,
// path builder, recovery helper, or serializer.
// Selection changes only test inputs. The actual loop retains its full10M
// bound; the universal theorem and failure mutations cover all counts.
fn sign_hypertree_witness(case: usize, index: u32) -> ([u8; 32], [u8; 32], [u8; 16]) {
    let sk = std::array::from_fn(|i| serialization_byte(case, 6, i));
    for salt in 0..10_000u32 {
        let mut seed = std::array::from_fn(|i| serialization_byte(case, 5, i));
        seed[28..].copy_from_slice(&salt.to_be_bytes());
        let lower_root = xmss_oracle_node(&seed, &sk, 0, u64::from(index / 512), 9, 0);
        let leaf1 = (index / 512) % 512;
        let tree1 = u64::from(index / 262144);
        let cheap_top = (0..64u32).any(|c| ref_digits(&seed, 1, tree1, leaf1, &lower_root, c)
            .iter().map(|&d| u32::from(d)).sum::<u32>() == 205);
        if cheap_top {
            let (message, _, _) = sign_case_message(&seed, 0, u64::from(index / 512), index % 512,
                (case + 7) as u8, false);
            return (seed, sk, message);
        }
    }
    panic!("no bounded two-layer executable witness found");
}

#[test]
fn sign_hypertree_corpus() {
    let mut out = String::from("-- Independent recursive byte oracle for both actual signer iterations.\nnamespace SignHypertreeDiff\nstructure Vector where\n  pattern : Nat\n  seed : Array UInt8\n  sk : Array UInt8\n  current : Array UInt8\n  shuffle : Array UInt8\n  index : Nat\n  signature : String\n  root : Array UInt8\n  counts : Array Nat\n  deriving Inhabited\ndef vectors : List Vector := [\n");
    for (case, index) in [262143u32, u32::MAX].into_iter().enumerate() {
        let (seed, sk, current) = sign_hypertree_witness(case, index);
        let shuffle = std::array::from_fn(|i| serialization_byte(case, 8, i));
        let initial = std::array::from_fn(|i| serialization_byte(case, 0, i));
        let mut expected = initial[..2336].to_vec();
        let mut tree = u64::from(index);
        let mut node = current;
        let mut counts = Vec::new();
        for layer in 0..2u32 {
            let leaf = (tree % 512) as u32;
            tree /= 512;
            let (count, digits) = (0..10_000_000u32).find_map(|c| {
                let digits = ref_digits(&seed, layer, tree, leaf, &node, c);
                (digits.iter().map(|&d| u32::from(d)).sum::<u32>() == 205).then_some((c, digits))
            }).expect("fixed oracle case exhausted the production count bound");
            let chains: [[u8; 16]; 43] = std::array::from_fn(|j| ref_chain(
                &seed, &ref_adrs(layer, tree, 0, leaf, j as u32, 0),
                &ref_wots_secret(&sk, layer, tree, leaf, j as u32), 0, digits[j].into()));
            expected.extend(chains.iter().flatten().copied());
            expected.extend([(count / 16777216) as u8, (count / 65536) as u8,
                (count / 256) as u8, count as u8]);
            for h in 0..9 {
                expected.extend(xmss_oracle_node(&seed, &sk, layer, tree, h, (leaf / (1 << h)) ^ 1));
            }
            node = xmss_oracle_node(&seed, &sk, layer, tree, 9, 0);
            counts.push(count);
        }
        assert!(counts.iter().all(|&c| c < 64), "executable witness cost drift");
        assert_eq!(expected.len(), 4008);
        assert_eq!(tree, u64::from(index) / 262144);
        let (actual, offset, root) = sign_hypertree_fragment(&initial, seed, &sk, current, index,
            &progress_none(), &ShuffleSeed(shuffle));
        assert_eq!(offset, 4008);
        assert_eq!(actual.as_slice(), expected, "all bytes case {case}");
        assert_eq!(root, node, "top root case {case}");
        let unshuffled = sign_hypertree_fragment(&initial, seed, &sk, current, index,
            &progress_none(), &ShuffleSeed([0; 32]));
        assert_eq!(unshuffled, (actual, offset, root), "shuffle independence case {case}");
        out.push_str(&format!("{{ pattern := {case}, seed := {}, sk := {}, current := {}, shuffle := {}, index := {index}, signature := \"{}\", root := {}, counts := #[{}, {}] }},\n",
            array(&seed), array(&sk), array(&current), array(&shuffle), serialization_hex(&expected),
            array(&node), counts[0], counts[1]));
        println!("hypertree case {case}: index {index}, first counts {counts:?}");
    }
    out.push_str("]\nend SignHypertreeDiff\n");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../extracted/Extracted/SignHypertreeDiffVectors.lean");
    if std::env::var("PQ_SIGN_HYPERTREE_GENERATE").as_deref() == Ok("1") {
        std::fs::write(path, out).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(path).unwrap(), out, "hypertree corpus drift");
    }
    println!("OK: two full-byte two-layer signer cases versus independent recursive oracle; 18-bit and full-u32 indices, four first counts, top roots and shuffle independence");
}
