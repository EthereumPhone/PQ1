//! RESEARCH PROTOTYPE (round 17, gate (d); research/c10-autoresearch/proto_w4l65 section 7): the C10 format
//! identifier in both key-derivation branches. Copied into the domain copy's `tests/` by `apply.py`; run by
//! `mk.sh` once per format feature, with `format-kdf` on.
#![cfg(feature = "format-kdf")]
use hmac::{Hmac, Mac};
use pqsigner_domain::{
    bootstrap_master_with_format, compiled_format_id, derive_c10_master_from_bip39_seed, derive_c10_master_from_entropy,
    derive_c10_master_keypair_from_entropy, derive_c10_slot_keypair, format_descriptor, format_id, slot_entropy,
    slot_master_entropy_from_bip39, slot_master_entropy_from_entropy, slot_master_with_format, slot_seeds_with_format,
    FormatParams, COMPILED_FORMAT, FORMAT_DESCRIPTOR_LEN,
};
use sphincs_c10::SigningKey;
use sphincs_tz_bip39::Mnemonic;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashSet;

const A7_03: [u8; 14] = [4, 52, 1, 51, 18, 33, 9, 24, 6, 18, 4, 12, 11, 1];
const A7_810: [u8; 14] = [4, 52, 1, 51, 18, 33, 10, 23, 6, 17, 4, 12, 11, 1];
const A7_W4L65: [u8; 14] = [4, 52, 1, 51, 18, 33, 9, 24, 7, 17, 4, 12, 11, 1];

fn d03() -> FormatParams {
    FormatParams {
        hash_layer: 2, n: 16, h: 18, d: 2, layer_h: [9, 9], a: 11, k: 13, w: 8, l: 43, target_sum: 205, a7: A7_03,
        wots_prf: 1, fors_prf: 1, last_fors: 1, r_prf: 1,
    }
}

/// Every format this research tree can build, plus stock v1 (whose derivation is NOT format-bound).
fn known() -> Vec<(&'static str, FormatParams)> {
    let d = d03();
    let w4l65 = FormatParams { w: 4, l: 65, target_sum: 125, a7: A7_W4L65, ..d };
    vec![
        ("v1", FormatParams { hash_layer: 1, a7: [0; 14], ..d }),
        ("draft03", d),
        ("ts200", FormatParams { target_sum: 200, ..d }),
        ("prf2", FormatParams { wots_prf: 3, fors_prf: 3, ..d }),
        ("split810", FormatParams { layer_h: [8, 10], a7: A7_810, ..d }),
        ("all3", FormatParams { target_sum: 200, wots_prf: 3, fors_prf: 3, layer_h: [8, 10], a7: A7_810, ..d }),
        ("w4", FormatParams { w: 4, l: 64, target_sum: 124, ..d }),
        ("w4l65", w4l65),
        ("wprf2b", FormatParams { wots_prf: 2, ..d }),
        ("w4l65+wprf2b", FormatParams { wots_prf: 2, ..w4l65 }),
        ("forslastprf", FormatParams { last_fors: 2, ..d }),
    ]
}

fn this_build() -> &'static str {
    match (cfg!(feature = "w4l65"), cfg!(feature = "wprf2b"), cfg!(feature = "ts200"), cfg!(feature = "prf2"),
           cfg!(feature = "split810"), cfg!(feature = "forslastprf")) {
        (false, false, false, false, false, false) => "draft03",
        (true, false, false, false, false, false) => "w4l65",
        (false, true, false, false, false, false) => "wprf2b",
        (true, true, false, false, false, false) => "w4l65+wprf2b",
        (false, false, true, false, false, false) => "ts200",
        (false, false, false, true, false, false) => "prf2",
        (false, false, false, false, true, false) => "split810",
        (false, false, true, true, true, false) => "all3",
        (false, false, false, false, false, true) => "forslastprf",
        _ => panic!("no expected format for this feature combination"),
    }
}

fn seeds() -> Vec<[u8; 64]> {
    (0u8..4).map(|i| core::array::from_fn(|j| (j as u8).wrapping_mul(37).wrapping_add(i.wrapping_mul(101)) ^ 0x5a)).collect()
}

fn stock_boot_master(seed: &[u8; 64], acct: u32) -> [u8; 64] {
    let (key, msg): (&[u8], Vec<u8>) = if acct == 0 {
        (b"sphincs-c6-v1", seed.to_vec())
    } else {
        (b"sphincs-c6-v1-acct", [&seed[..], &acct.to_be_bytes()[..]].concat())
    };
    let mut m = <Hmac<Sha512> as Mac>::new_from_slice(key).unwrap();
    m.update(&msg);
    m.finalize().into_bytes().into()
}

fn stock_slot_master(seed: &[u8; 64], acct: u32) -> [u8; 32] {
    let b = if acct == 0 {
        [&b"pqwallet-slot-master"[..], &seed[..], &[0u8][..]].concat()
    } else {
        [&b"pqwallet-slot-master-acct"[..], &seed[..], &acct.to_be_bytes()[..]].concat()
    };
    Sha256::digest(&b).into()
}

#[test]
fn known_format_ids_are_pairwise_distinct() {
    let ids: HashSet<[u8; 32]> = known().iter().map(|(_, f)| format_id(f)).collect();
    assert_eq!(ids.len(), known().len());
}

#[test]
fn every_field_moves_the_descriptor_and_the_id() {
    let base = d03();
    let bump = |x: u8| x.wrapping_add(1);
    let mut muts: Vec<FormatParams> = vec![
        FormatParams { hash_layer: bump(base.hash_layer), ..base }, FormatParams { n: bump(base.n), ..base },
        FormatParams { h: bump(base.h), ..base }, FormatParams { d: bump(base.d), ..base },
        FormatParams { a: bump(base.a), ..base }, FormatParams { k: bump(base.k), ..base },
        FormatParams { w: bump(base.w), ..base }, FormatParams { l: bump(base.l), ..base },
        FormatParams { target_sum: base.target_sum + 1, ..base }, FormatParams { target_sum: base.target_sum + 256, ..base },
        FormatParams { wots_prf: bump(base.wots_prf), ..base }, FormatParams { fors_prf: bump(base.fors_prf), ..base },
        FormatParams { last_fors: bump(base.last_fors), ..base }, FormatParams { r_prf: bump(base.r_prf), ..base },
    ];
    for i in 0..2 {
        let mut lh = base.layer_h;
        lh[i] += 1;
        muts.push(FormatParams { layer_h: lh, ..base });
    }
    for i in 0..14 {
        let mut a7 = base.a7;
        a7[i] = bump(a7[i]);
        muts.push(FormatParams { a7, ..base });
    }
    assert_eq!(muts.len(), 30, "one mutation per descriptor field byte");
    let d0 = format_descriptor(&base);
    let mut seen = HashSet::new();
    for m in &muts {
        let d = format_descriptor(m);
        assert_ne!(d, d0);
        assert_eq!(d.iter().zip(d0.iter()).filter(|(x, y)| x != y).count(), 1, "exactly one byte moves: {m:?}");
        assert_ne!(format_id(m), format_id(&base));
        assert!(seen.insert(format_id(m)));
    }
}

#[test]
fn descriptor_layout_is_fixed() {
    let d = format_descriptor(&d03());
    assert_eq!(d.len(), FORMAT_DESCRIPTOR_LEN);
    assert_eq!(&d[..12], b"PQ1-C10-FMT1");
    assert_eq!(&d[12..24], &[2, 16, 18, 2, 9, 9, 11, 13, 8, 43, 0, 205]);
    assert_eq!(&d[24..38], &A7_03);
    assert_eq!(&d[38..42], &[1, 1, 1, 1]);
}

#[test]
fn compiled_format_is_this_builds_variant() {
    let name = this_build();
    let want = known().into_iter().find(|(n, _)| *n == name).unwrap().1;
    assert_eq!(COMPILED_FORMAT, want, "{name}");
    assert_eq!(compiled_format_id(), format_id(&want));
}

#[test]
fn derivations_separate_formats_accounts_and_stock() {
    let mut boot = HashSet::new();
    let mut slot = HashSet::new();
    let mut seeds_seen = HashSet::new();
    for seed in seeds() {
        for acct in [0u32, 1, 255] {
            assert!(boot.insert(stock_boot_master(&seed, acct).to_vec()));
            assert!(slot.insert(stock_slot_master(&seed, acct).to_vec()));
            for (_, f) in known() {
                let fid = format_id(&f);
                assert!(boot.insert(bootstrap_master_with_format(&fid, &seed, acct).to_vec()), "bootstrap master shared");
                let sm = slot_master_with_format(&fid, &seed, acct);
                assert!(slot.insert(sm.to_vec()), "slot master shared");
                let e = slot_entropy(&sm, 1, 0);
                let (sk, pk) = slot_seeds_with_format(&fid, &e);
                assert!(seeds_seen.insert(sk.to_vec()) && seeds_seen.insert(pk[..16].to_vec()), "slot seed shared");
            }
        }
    }
}

#[test]
fn public_api_is_the_compiled_format() {
    let fid = compiled_format_id();
    for seed in seeds() {
        for acct in [0u32, 7] {
            let m = bootstrap_master_with_format(&fid, &seed, acct);
            let pk_d: [u8; 32] = Sha256::digest([&b"pk_seed"[..], &m[..32]].concat()).into();
            let sk: [u8; 32] = Sha256::digest([&b"sk_seed"[..], &m[..32]].concat()).into();
            let (pk_seed, sk_seed) = derive_c10_master_from_bip39_seed(&seed, acct);
            assert_eq!(&pk_seed[..16], &pk_d[..16]);
            assert_eq!(&pk_seed[16..], &[0u8; 16]);
            assert_eq!(sk_seed, sk);
            assert_eq!(slot_master_entropy_from_bip39(&seed, acct), slot_master_with_format(&fid, &seed, acct));
            // and never the stock values
            let sm = stock_boot_master(&seed, acct);
            let stock_sk: [u8; 32] = Sha256::digest([&b"sk_seed"[..], &sm[..32]].concat()).into();
            assert_ne!(sk_seed, stock_sk);
            assert_ne!(slot_master_entropy_from_bip39(&seed, acct), stock_slot_master(&seed, acct));
        }
    }
}

/// The slot seeds bind the format themselves (belt and braces): the SAME slot entropy under two formats gives
/// different seeds, so a refactor that reused slot entropy across formats could not share a slot key.
#[test]
fn slot_seeds_bind_the_format_directly() {
    let e = [0x42u8; 32];
    let mut seen = HashSet::new();
    for (_, f) in known() {
        let (sk, pk) = slot_seeds_with_format(&format_id(&f), &e);
        assert!(seen.insert(sk.to_vec()), "slot sk_seed ignores the format");
        assert!(seen.insert(pk[..16].to_vec()), "slot pk_seed ignores the format");
    }
}

// ---- independent formulas and pinned vectors (Astra r17: the new labels and encodings need their own pins) ----

fn ind_boot(fid: &[u8; 32], seed: &[u8; 64], acct: u32) -> [u8; 64] {
    let tag: &[u8] = if acct == 0 { b"pq1-c10-fmt-boot-acc0" } else { b"pq1-c10-fmt-boot-acct" };
    let key = [tag, &fid[..]].concat();
    assert_eq!(key.len(), 53);
    let msg = if acct == 0 { seed.to_vec() } else { [&seed[..], &acct.to_be_bytes()[..]].concat() };
    let mut m = <Hmac<Sha512> as Mac>::new_from_slice(&key).unwrap();
    m.update(&msg);
    m.finalize().into_bytes().into()
}

fn ind_slot(fid: &[u8; 32], seed: &[u8; 64], acct: u32) -> [u8; 32] {
    let tag: &[u8] = if acct == 0 { b"pq1-c10-fmt-slot-acc0" } else { b"pq1-c10-fmt-slot-acct" };
    let tail = if acct == 0 { vec![0u8] } else { acct.to_be_bytes().to_vec() };
    Sha256::digest([tag, &fid[..], &seed[..], &tail[..]].concat()).into()
}

fn ind_seeds(fid: &[u8; 32], e: &[u8; 32]) -> ([u8; 32], [u8; 16]) {
    let sk: [u8; 32] = Sha256::digest([&b"slot_c10_sk_seed"[..], &fid[..], &e[..]].concat()).into();
    let pk: [u8; 32] = Sha256::digest([&b"slot_c10_pk_seed"[..], &fid[..], &e[..]].concat()).into();
    (sk, pk[..16].try_into().unwrap())
}

#[test]
fn kdf_encodings_match_independent_formulas() {
    let e = [0x42u8; 32];
    for (_, f) in known() {
        let fid = format_id(&f);
        for seed in seeds() {
            for acct in [0u32, 1, 255] {
                assert_eq!(bootstrap_master_with_format(&fid, &seed, acct), ind_boot(&fid, &seed, acct));
                assert_eq!(slot_master_with_format(&fid, &seed, acct), ind_slot(&fid, &seed, acct));
            }
        }
        let (sk, pk) = slot_seeds_with_format(&fid, &e);
        let (isk, ipk) = ind_seeds(&fid, &e);
        assert_eq!(sk, isk);
        assert_eq!(&pk[..16], &ipk[..]);
        assert_eq!(&pk[16..], &[0u8; 16]);
    }
}

/// Pinned once from an independent Python implementation of the same layouts (ledger round 17 §5).
#[test]
fn pinned_vectors_draft03() {
    let h = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let fid = format_id(&d03());
    let seed = seeds()[0];
    assert_eq!(h(&fid), "e02c1a8132fb1b9094f69f189d26b0e7fc0dcebbe752edc300d180f81179dca7");
    assert_eq!(h(&bootstrap_master_with_format(&fid, &seed, 0)[..32]), "5e41749c032f1080620d725c35965969e5575c44e0f8f40b4d95992a895e3753");
    assert_eq!(h(&bootstrap_master_with_format(&fid, &seed, 5)[..32]), "fada5c8dba5441e61e2180f4f29f624bacbbe6b54e1973a99200f992cd7fab7f");
    assert_eq!(h(&slot_master_with_format(&fid, &seed, 0)), "a3d6bfd0deb8235d1da024c2204f04bc424528470534209c784c4a0d5dbb5cab");
    assert_eq!(h(&slot_master_with_format(&fid, &seed, 5)), "1726df8caa4fb512984010df32121471b9b0c5acbd7cc13ee445b3c784e2e150");
    let (sk, pk) = slot_seeds_with_format(&fid, &[0x42u8; 32]);
    assert_eq!(h(&sk), "bd16a5d15e97d6b90e153b67bd789ee1692de63b10af2e5e282a3c5d7c0ef60a");
    assert_eq!(h(&pk[..16]), "3cf8980313cbfaed4cf03a879eb1e015");
}

/// The public slot-keypair route (slot master -> slot entropy -> slot seeds -> keygen) is the format-bound one.
#[test]
fn public_slot_keypair_route_is_format_bound() {
    let seed = seeds()[1];
    for acct in [0u32, 3] {
        let sm = slot_master_entropy_from_bip39(&seed, acct);
        let (key, pk_seed, root) = derive_c10_slot_keypair(&sm, 1, 2);
        let e = slot_entropy(&sm, 1, 2);
        let (want_sk, want) = slot_seeds_with_format(&compiled_format_id(), &e);
        assert_eq!(pk_seed, want, "slot keypair does not use the format-bound seeds");
        // what keygen actually consumed (Astra r17 final: the secret seed too)
        assert_eq!(key.sk_seed(), &want_sk, "slot keypair secret seed is not the format-bound one");
        assert_eq!(&key.pk_seed()[..], &want[..16]);
        assert_eq!(key.pk_root(), &root[..16]);
        assert_eq!(SigningKey::keygen(want_sk, want[..16].try_into().unwrap()).pk_root(), key.pk_root());
        let stock: [u8; 32] = Sha256::digest([&b"slot_c10_pk_seed"[..], &e[..]].concat()).into();
        assert_ne!(&pk_seed[..16], &stock[..16]);
    }
}

/// The entropy wrappers (PBKDF2 then the bip39-seed derivations) and the bootstrap keypair route are format-bound,
/// and the bootstrap key's keygen consumed exactly the format-bound seeds.
#[test]
fn public_entropy_routes_are_format_bound() {
    let entropy = [0x11u8; 32];
    let bip39_seed = Mnemonic::from_entropy(&entropy).to_seed("");
    let fid = compiled_format_id();
    for acct in [0u32, 4] {
        let (pk, sk) = derive_c10_master_from_entropy(&entropy, acct);
        assert_eq!((pk, sk), derive_c10_master_from_bip39_seed(&bip39_seed, acct));
        let m = bootstrap_master_with_format(&fid, &bip39_seed, acct);
        let want_sk: [u8; 32] = Sha256::digest([&b"sk_seed"[..], &m[..32]].concat()).into();
        assert_eq!(sk, want_sk);
        let (key, pk32, root32) = derive_c10_master_keypair_from_entropy(&entropy, acct);
        assert_eq!(key.sk_seed(), &want_sk, "bootstrap keypair secret seed is not the format-bound one");
        assert_eq!(&key.pk_seed()[..], &pk[..16]);
        assert_eq!(pk32, pk);
        assert_eq!(key.pk_root(), &root32[..16]);
        assert_eq!(slot_master_entropy_from_entropy(&entropy, acct), slot_master_with_format(&fid, &bip39_seed, acct));
    }
}
