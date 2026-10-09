// Independent recursive XMSS oracle with explicit byte preimages. The actual
// modules are embedded unchanged by this test crate.
fn xmss_oracle_node(seed: &[u8; 32], sk: &[u8; 32], layer: u32, tree: u64,
                    height: u32, index: u32) -> [u8; 16] {
    if height == 0 {
        let ends: [[u8; 16]; 43] = std::array::from_fn(|j| ref_chain(
            seed, &ref_adrs(layer, tree, 0, index, j as u32, 0),
            &ref_wots_secret(sk, layer, tree, index, j as u32), 0, 7));
        return ref_compress(seed, &ref_adrs(layer, tree, 1, index, 0, 0), &ends);
    }
    let mut adrs = ref_adrs(layer, tree, 2, 0, 0, height);
    adrs[28..32].copy_from_slice(&index.to_be_bytes());
    let mut input = seed.to_vec();
    input.extend_from_slice(&adrs);
    input.extend_from_slice(&xmss_oracle_node(seed, sk, layer, tree, height - 1, 2 * index));
    input.extend_from_slice(&[0; 16]);
    input.extend_from_slice(&xmss_oracle_node(seed, sk, layer, tree, height - 1, 2 * index + 1));
    input.extend_from_slice(&[0; 16]);
    assert_eq!(input.len(), 128);
    Sha256::digest(input)[..16].try_into().unwrap()
}

#[cfg(not(lean_extract))]
std::thread_local! {
    static XMSS_PROGRESS: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}
#[cfg(not(lean_extract))]
fn xmss_progress_record(p: u8) { XMSS_PROGRESS.with(|v| v.borrow_mut().push(p)); }

#[test]
fn xmss_root_corpus() {
    let seed: [u8; 32] = std::array::from_fn(|i| (7 * i + 13) as u8);
    let sk: [u8; 32] = std::array::from_fn(|i| (23 * i + 11) as u8);
    let mut padded = [0; 32];
    padded[..16].copy_from_slice(&seed[..16]);
    let cases = [
        (padded, sk, 1u32, 0u64, 0u8, 0u8, true),
        (seed, sk, 0x8102_0304, 0x8123_4567_89ab_cdef, 0, 255, false),
        ([0; 32], [0; 32], 0, 0, 0, 255, false),
        ([255; 32], [255; 32], u32::MAX, u64::MAX, 255, 0, false),
        (seed, sk, 1 << 31, 1 << 63, 127, 255, false),
        (seed, sk, 1, 1 << 32, 201, 199, false),
        (seed, sk, u32::MAX, 0xffff_ffff, 255, 255, false),
        (seed, sk, 0, 0xffff_ffff_0000_0000, 31, 33, false),
    ];
    let mut out = String::from("-- Two full trees selected from eight independently checked Rust cases.\nnamespace XmssRootDiff\nstructure Vector where\n  seed : Array UInt8\n  sk : Array UInt8\n  layer : Nat\n  tree : Nat\n  lo : Nat\n  hi : Nat\n  publicRoot : Bool\n  result : Array UInt8\n  deriving Inhabited\ndef vectors : List Vector := [\n");
    for (case, (seed, sk, layer, tree, lo, hi, public_root)) in cases.into_iter().enumerate() {
        let expected = xmss_oracle_node(&seed, &sk, layer, tree, 9, 0);
        #[cfg(not(lean_extract))]
        let progress = {
            XMSS_PROGRESS.with(|v| v.borrow_mut().clear());
            ProgressSink(Some(xmss_progress_record))
        };
        #[cfg(lean_extract)]
        let progress = ProgressSink;
        let actual = crate::merkle::compute_subtree_root(&seed, &sk, layer, tree, &progress, lo, hi);
        assert_eq!(actual, expected, "XMSS root case {case}");
        #[cfg(not(lean_extract))]
        XMSS_PROGRESS.with(|v| {
            let expected: Vec<u8> = (1..=32).map(|i|
                (u32::from(lo) + i * 16 * u32::from(hi.saturating_sub(lo)) / 512) as u8).collect();
            assert_eq!(*v.borrow(), expected, "progress case {case}");
        });
        if public_root {
            let pk_seed: [u8; 16] = seed[..16].try_into().unwrap();
            assert_eq!(compute_pk_root(&sk, &pk_seed), expected);
            #[cfg(not(lean_extract))]
            assert_eq!(compute_pk_root_with_progress(&sk, &pk_seed, xmss_progress_record, 0, 100), expected);
        }
        if case < 2 {
            out.push_str(&format!("{{ seed := {}, sk := {}, layer := {layer}, tree := {tree}, lo := {lo}, hi := {hi}, publicRoot := {public_root}, result := {} }},\n", array(&seed), array(&sk), array(&expected)));
        }
    }
    out.push_str("]\nend XmssRootDiff\n");
    let dest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../extracted/Extracted/XmssRootDiffVectors.lean");
    if std::env::var("PQ_XMSS_ROOT_GENERATE").as_deref() == Ok("1") {
        std::fs::write(dest, out).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(dest).unwrap(), out);
    }
    println!("OK: 8 actual XMSS roots versus independent recursive WOTS/tree oracle; full-width addresses, zero/max seeds, progress boundaries; actual public-root wrapper; 2 Lean vectors");
}
