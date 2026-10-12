// Independent byte oracle plus unchanged full production verifier calls.
fn ref_adrs(layer: u32, tree: u64, kind: u32, kp: u32, chain: u32, pos: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..4].copy_from_slice(&layer.to_be_bytes());
    out[4..12].copy_from_slice(&tree.to_be_bytes());
    out[12..16].copy_from_slice(&kind.to_be_bytes());
    out[16..20].copy_from_slice(&kp.to_be_bytes());
    out[20..24].copy_from_slice(&chain.to_be_bytes());
    out[24..28].copy_from_slice(&pos.to_be_bytes());
    out
}

fn ref_digits(
    seed: &[u8; 32],
    layer: u32,
    tree: u64,
    kp: u32,
    msg: &[u8; 16],
    count: u32,
) -> [u8; 43] {
    let mut preimage = seed.to_vec();
    preimage.extend_from_slice(&ref_adrs(layer, tree, 0, kp, 0, 0));
    preimage.extend_from_slice(msg);
    preimage.extend_from_slice(&[0; 44]); // node padding and counter high bytes
    preimage.extend_from_slice(&count.to_be_bytes());
    let digest = Sha256::digest(&preimage);
    std::array::from_fn(|i| {
        (0..3)
            .map(|b| ((digest[31 - (3 * i + b) / 8] >> ((3 * i + b) % 8)) & 1) << b)
            .sum()
    })
}

fn ref_chain(
    seed: &[u8; 32],
    adrs: &[u8; 32],
    node: &[u8; 16],
    start: u32,
    steps: u32,
) -> [u8; 16] {
    let mut current = *node;
    for position in start..start.checked_add(steps).unwrap() {
        let mut a = *adrs;
        a[24..28].copy_from_slice(&position.to_be_bytes());
        let mut preimage = seed.to_vec();
        preimage.extend_from_slice(&a);
        preimage.extend_from_slice(&current);
        preimage.extend_from_slice(&[0; 16]);
        current.copy_from_slice(&Sha256::digest(&preimage)[..16]);
    }
    current
}

fn ref_compress(seed: &[u8; 32], adrs: &[u8; 32], nodes: &[[u8; 16]]) -> [u8; 16] {
    let mut preimage = seed.to_vec();
    preimage.extend_from_slice(adrs);
    for node in nodes {
        preimage.extend_from_slice(node);
        preimage.extend_from_slice(&[0; 16]);
    }
    Sha256::digest(&preimage)[..16].try_into().unwrap()
}

fn continuation_oracle(
    seed: &[u8; 32],
    sig: &[u8; SIGNATURE_LEN],
    mut idx: u32,
    mut node: [u8; 16],
) -> ([u8; 16], [bool; 2], [u32; 2]) {
    let mut accepted = [false; 2];
    let mut counts = [0u32; 2];
    for layer in 0..2usize {
        let leaf = idx % 512;
        idx /= 512;
        let base = 2336 + 836 * layer;
        let chains: [[u8; 16]; 43] =
            std::array::from_fn(|j| sig[base + 16 * j..base + 16 * j + 16].try_into().unwrap());
        let count = u32::from_be_bytes(sig[base + 688..base + 692].try_into().unwrap());
        counts[layer] = count;
        let digits = ref_digits(seed, layer as u32, u64::from(idx), leaf, &node, count);
        accepted[layer] = digits.iter().map(|d| usize::from(*d)).sum::<usize>() == 205;
        let wpk = if accepted[layer] {
            let ends: [[u8; 16]; 43] = std::array::from_fn(|j| {
                ref_chain(
                    seed,
                    &ref_adrs(layer as u32, u64::from(idx), 0, leaf, j as u32, 0),
                    &chains[j],
                    u32::from(digits[j]),
                    7 - u32::from(digits[j]),
                )
            });
            ref_compress(
                seed,
                &ref_adrs(layer as u32, u64::from(idx), 1, leaf, 0, 0),
                &ends,
            )
        } else {
            [0; 16]
        };
        assert_eq!(
            wpk,
            crate::wots::pk_from_sig(
                seed,
                layer as u32,
                u64::from(idx),
                leaf,
                &node,
                &chains,
                count
            )
        );
        let auth: [[u8; 16]; 9] = std::array::from_fn(|h| {
            sig[base + 692 + 16 * h..base + 708 + 16 * h]
                .try_into()
                .unwrap()
        });
        node = wpk;
        for (h, sibling) in auth.iter().enumerate() {
            let mut adrs = ref_adrs(layer as u32, u64::from(idx), 2, 0, 0, h as u32 + 1);
            adrs[28..32].copy_from_slice(&(leaf >> (h + 1)).to_be_bytes());
            let (left, right) = if (leaf >> h) & 1 == 0 {
                (&node, sibling)
            } else {
                (sibling, &node)
            };
            node = ref_compress(seed, &adrs, &[*left, *right]);
        }
        assert_eq!(
            node,
            crate::merkle::verify_auth_path(seed, layer as u32, u64::from(idx), &wpk, leaf, &auth)
        );
    }
    (node, accepted, counts)
}
#[test]
fn hypertree_continuation_corpus() {
    let mut cases = prefix_cases();
    let template = cases.iter().find(|c| c.5).unwrap().clone();
    let counts = [
        0,
        1,
        255,
        256,
        65535,
        65536,
        9_999_999,
        10_000_000,
        0x8000_0000,
        u32::MAX,
    ];
    for layer in 0..2 {
        for count in counts {
            let mut c = template.clone();
            c.0 = format!("counter-{layer}-{count}");
            c.4[3024 + 836 * layer..3028 + 836 * layer].copy_from_slice(&count.to_be_bytes());
            // This field changes neither H_msg nor the forced-zero prefix.
            cases.push(c);
        }
    }
    let mut vectors = Vec::new();
    let mut strict_ok = 0;
    let mut rejected = [0; 2];
    for (label, seed, root, msg, sig, _) in cases {
        let digest = prefix_digest(&seed, &root, &msg, &sig);
        assert_eq!(prefix_bits(&digest, 132, 11), 0);
        let ht = prefix_bits(&digest, 143, 18);
        let pk = prefix_fors_pk(&seed, &digest, &sig);
        let mut padded = [0; 32];
        padded[..16].copy_from_slice(&seed);
        let (tail, ok, counts) = continuation_oracle(&padded, &sig, ht, pk);
        let actual = verify(&seed, &root, &msg, &sig);
        assert_eq!(actual, tail == root, "full production verifier: {label}");
        strict_ok += usize::from(ok[0] && ok[1]);
        for l in 0..2 {
            rejected[l] += usize::from(!ok[l]);
        }
        vectors.push((label, padded, root, sig, ht, pk, tail, ok, counts));
    }
    assert!(strict_ok >= 4 && rejected[0] > 0 && rejected[1] > 0);
    assert_eq!(vectors.len(), 42);
    for idx in [0, 1, 511, 512, 513, 262143, 0x8000_0000, u32::MAX] {
        let seed = std::array::from_fn(|j| (j * 13 + 9) as u8);
        let sig = std::array::from_fn(|j| (j * 19 + 23) as u8);
        let current = std::array::from_fn(|j| (j * 7 + 1) as u8);
        let (tail, ok, counts) = continuation_oracle(&seed, &sig, idx, current);
        vectors.push((
            format!("index-{idx}"),
            seed,
            tail,
            sig,
            idx,
            current,
            tail,
            ok,
            counts,
        ));
    }
    let mut out = String::from("-- Generated by hypertree_continuation_corpus from production calls and a byte oracle.\nnamespace HypertreeDiff\nstructure Vector where\n  label : String\n  seed : String\n  root : String\n  sig : String\n  idx : Nat\n  current : String\n  result : String\n  ok0 : Bool\n  ok1 : Bool\n  count0 : Nat\n  count1 : Nat\n  deriving Inhabited\ndef vectors : List Vector := [\n");
    for (label, seed, root, sig, idx, current, tail, ok, counts) in vectors {
        out.push_str(&format!("{{ label := \"{label}\", seed := \"{}\", root := \"{}\", sig := \"{}\", idx := {idx}, current := \"{}\", result := \"{}\", ok0 := {}, ok1 := {}, count0 := {}, count1 := {} }},\n", prefix_hex(&seed), prefix_hex(&root), prefix_hex(&sig), prefix_hex(&current), prefix_hex(&tail), ok[0], ok[1], counts[0], counts[1]));
    }
    out.push_str("]\nend HypertreeDiff\n");
    let dest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../extracted/Extracted/HypertreeDiffVectors.lean");
    if std::env::var("PQ_HYPERTREE_GENERATE").as_deref() == Ok("1") {
        std::fs::write(dest, out).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(dest).unwrap(), out);
    }
    println!("OK: 50 continuation cases; 42 full production verifier calls, 8 additional full-width index cases; strict-success and each layer rejection exercised");
}
