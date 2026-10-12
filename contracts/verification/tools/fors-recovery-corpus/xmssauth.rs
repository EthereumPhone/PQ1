// Actual unmodified XMSS authentication builder against the independent byte
// oracle, including every sibling and actual root recovery.
#[test]
fn xmss_auth_corpus() {
    let seed: [u8; 32] = std::array::from_fn(|i| (7 * i + 13) as u8);
    let sk: [u8; 32] = std::array::from_fn(|i| (23 * i + 11) as u8);
    let mut cases: Vec<_> = [341, 0, 1, 2, 3, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 510, 511]
        .into_iter()
        .map(|leaf| (seed, sk, 0x8102_0304u32, 0x8123_4567_89ab_cdefu64, leaf, 0u8, 255u8))
        .collect();
    cases.extend([
        ([0; 32], [0; 32], 0, 0, 0, 255, 0),
        ([255; 32], [255; 32], u32::MAX, u64::MAX, 511, 255, 255),
        (seed, sk, 1, 0, 256, 31, 33),
    ]);
    let mut out = String::from("-- One full tree selected from twenty independently checked Rust cases.\nnamespace XmssAuthDiff\nstructure Vector where\n  seed : Array UInt8\n  sk : Array UInt8\n  layer : Nat\n  tree : Nat\n  leaf : Nat\n  lo : Nat\n  hi : Nat\n  root : Array UInt8\n  node : Array UInt8\n  path : Array (Array UInt8)\n  deriving Inhabited\ndef vectors : List Vector := [\n");
    for (case, (seed, sk, layer, tree, leaf, lo, hi)) in cases.into_iter().enumerate() {
        let expected_root = xmss_oracle_node(&seed, &sk, layer, tree, 9, 0);
        let expected_node = xmss_oracle_node(&seed, &sk, layer, tree, 0, leaf);
        let expected_path: [[u8; 16]; 9] = std::array::from_fn(|h|
            xmss_oracle_node(&seed, &sk, layer, tree, h as u32, (leaf >> h) ^ 1));
        #[cfg(not(lean_extract))]
        let progress = {
            XMSS_PROGRESS.with(|v| v.borrow_mut().clear());
            ProgressSink(Some(xmss_progress_record))
        };
        #[cfg(lean_extract)]
        let progress = ProgressSink;
        let (path, root) = crate::merkle::build_subtree_with_auth(
            &seed, &sk, layer, tree, leaf, &progress, lo, hi);
        assert_eq!(root, expected_root, "XMSS auth root case {case}");
        assert_eq!(path, expected_path, "XMSS auth siblings case {case}");
        #[cfg(not(lean_extract))]
        XMSS_PROGRESS.with(|v| {
            let expected: Vec<u8> = (1..=32).map(|i|
                (u32::from(lo) + i * 16 * u32::from(hi.saturating_sub(lo)) / 512) as u8).collect();
            assert_eq!(*v.borrow(), expected, "auth progress case {case}");
        });
        let node = crate::wots::keygen_pk(&seed, &sk, layer, tree, leaf);
        assert_eq!(node, expected_node, "WOTS leaf case {case}");
        assert_eq!(crate::merkle::verify_auth_path(&seed, layer, tree, &node, leaf, &path), root);
        assert_eq!(crate::merkle::compute_subtree_root(
            &seed, &sk, layer, tree, &progress_none(), lo, hi), root);
        for h in 0..9 {
            let mut changed = path;
            changed[h][0] ^= 1;
            assert_ne!(crate::merkle::verify_auth_path(&seed, layer, tree, &node, leaf, &changed), root,
                "altered sibling {h} case {case}");
        }
        let mut changed_node = node;
        changed_node[0] ^= 1;
        assert_ne!(crate::merkle::verify_auth_path(&seed, layer, tree, &changed_node, leaf, &path), root);
        assert_ne!(crate::merkle::verify_auth_path(&seed, layer, tree, &node, leaf ^ 1, &path), root);
        if case == 0 {
            let rows = path.iter().map(|row| array(row)).collect::<Vec<_>>().join(", ");
            out.push_str(&format!("{{ seed := {}, sk := {}, layer := {layer}, tree := {tree}, leaf := {leaf}, lo := {lo}, hi := {hi}, root := {}, node := {}, path := #[{rows}] }},\n",
                array(&seed), array(&sk), array(&expected_root), array(&expected_node)));
        }
    }
    out.push_str("]\nend XmssAuthDiff\n");
    let dest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../extracted/Extracted/XmssAuthDiffVectors.lean");
    if std::env::var("PQ_XMSS_AUTH_GENERATE").as_deref() == Ok("1") {
        std::fs::write(dest, out).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(dest).unwrap(), out);
    }
    println!("OK: 20 actual XMSS auth paths/roots versus independent byte oracle; 180 altered siblings, 20 altered leaves, 20 wrong-index recoveries; progress boundaries; 1 Lean vector");
}
