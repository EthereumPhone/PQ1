// Actual private WOTS signer against independently assembled preimages, a
// forward chain oracle, and a bounded first-accepted-count search.
fn sign_case_message(seed: &[u8; 32], layer: u32, tree: u64, kp: u32, tag: u8,
                     want_zero: bool) -> ([u8; 16], u32, [u8; 43]) {
    // Keep executable Lean witnesses cheap; the universal proof separately
    // covers the entire 10M bound. Selection does not change the signer.
    for nonce in 0u32..100_000 {
        let mut msg = [tag; 16];
        msg[12..].copy_from_slice(&nonce.to_be_bytes());
        for count in 0..64 {
            let digits = ref_digits(seed, layer, tree, kp, &msg, count);
            if digits.iter().map(|&x| u32::from(x)).sum::<u32>() == 205 {
                if (count == 0) == want_zero && digits.contains(&0) && digits.contains(&7) {
                    return (msg, count, digits);
                }
                break;
            }
        }
    }
    panic!("no cheap deterministic WOTS witness found");
}

#[test]
fn wots_sign_corpus() {
    let seed = std::array::from_fn(|i| (7 * i + 13) as u8);
    let sk = std::array::from_fn(|i| (23 * i + 11) as u8);
    let cases = [
        ([0; 32], [0; 32], 0u32, 0u64, 0u32),
        (seed, sk, 0x8102_0304, 0x8123_4567_89ab_cdef, 0xfeab_cd00),
        ([255; 32], [255; 32], u32::MAX, u64::MAX, u32::MAX),
        (seed, sk, 1, 1, 1),
        (sk, seed, 1 << 31, 1 << 63, 1 << 31),
        (seed, sk, 255, 65535, 511),
    ];
    let shuffle_seeds = [[0; 32], [1; 32], [255; 32], std::array::from_fn(|i| (i * 7 + 9) as u8)];
    let mut out = String::from("-- Three cheap first-count witnesses selected by an independent byte oracle.\nnamespace WotsSignDiff\nstructure Vector where\n  seed : Array UInt8\n  sk : Array UInt8\n  layer : Nat\n  tree : Nat\n  kp : Nat\n  message : Array UInt8\n  shuffle : Array UInt8\n  count : Nat\n  sigma : Array (Array UInt8)\n  pk : Array UInt8\n  deriving Inhabited\ndef vectors : List Vector := [\n");
    for (case, (seed, sk, layer, tree, kp)) in cases.into_iter().enumerate() {
        let (msg, count, digits) = sign_case_message(&seed, layer, tree, kp, case as u8, case == 0);
        assert!(digits.contains(&0) && digits.contains(&7), "both chain endpoints must be exercised");
        let expected: [[u8; 16]; 43] = std::array::from_fn(|j| ref_chain(
            &seed, &ref_adrs(layer, tree, 0, kp, j as u32, 0),
            &ref_wots_secret(&sk, layer, tree, kp, j as u32), 0, digits[j].into()));
        let endpoints: [[u8; 16]; 43] = std::array::from_fn(|j| ref_chain(
            &seed, &ref_adrs(layer, tree, 0, kp, j as u32, 0),
            &ref_wots_secret(&sk, layer, tree, kp, j as u32), 0, 7));
        let pk = ref_compress(&seed, &ref_adrs(layer, tree, 1, kp, 0, 0), &endpoints);
        assert_eq!(crate::wots::keygen_pk(&seed, &sk, layer, tree, kp), pk);
        for shuffle in shuffle_seeds {
            let (sigma, got_count) = crate::wots::sign_with_shuffle(
                &seed, &sk, layer, tree, kp, &msg, &shuffle, &progress_none(), 255);
            assert_eq!(got_count, count, "first count case {case}");
            assert_eq!(sigma, expected, "all positional chains case {case}");
            assert_eq!(crate::wots::pk_from_sig(&seed, layer, tree, kp, &msg, &sigma, count), pk);
        }
        for j in 0..43 {
            let mut changed = expected;
            changed[j][0] ^= 1;
            assert_ne!(crate::wots::pk_from_sig(&seed, layer, tree, kp, &msg, &changed, count), pk);
        }
        if case < 3 {
            let rows = expected.iter().map(|row| array(row)).collect::<Vec<_>>().join(", ");
            out.push_str(&format!("{{ seed := {}, sk := {}, layer := {layer}, tree := {tree}, kp := {kp}, message := {}, shuffle := {}, count := {count}, sigma := #[{rows}], pk := {} }},\n",
                array(&seed), array(&sk), array(&msg), array(&shuffle_seeds[case]), array(&pk)));
        }
    }
    out.push_str("]\nend WotsSignDiff\n");
    let dest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../extracted/Extracted/WotsSignDiffVectors.lean");
    if std::env::var("PQ_WOTS_SIGN_GENERATE").as_deref() == Ok("1") {
        std::fs::write(dest, out).unwrap();
    } else { assert_eq!(std::fs::read_to_string(dest).unwrap(), out); }
    println!("OK: 24 actual shuffled WOTS signatures, six first-count/43-chain/actual recovery/keygen oracle cases, 258 changed chains; three bounded Lean witnesses");
}
