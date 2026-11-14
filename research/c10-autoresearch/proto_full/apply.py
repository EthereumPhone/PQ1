#!/usr/bin/env python3
"""apply.py <proto dir> — round 20: the FULL v2 stack (ts200 + prf2 + split810 + top cache #1148 + the merged
two-block paired WOTS PRF + fmtKDF) on top of proto_w4l65/apply.py (sections 1-10, run first by mk.sh), in its own
tree target/proto-full so no round-17/18/19 copy or ELF moves. Merged PRF (c10v2_ref.py: prf2 + wprf2b):
WOTS: sha256(sk_seed || "C10v2-WOTS-PRF2B" || be32(layer) || 0^12 || A7(ci & ~1)) -> bytes 16*(ci & 1)..+16;
FORS: prf2's one-block pair sha256(sk_seed || A7(ha & ~1)) -> bytes 16*(ha & 1)..+16. Signer-side only."""
import os, shutil, sys

P = sys.argv[1]
here = os.path.dirname(os.path.abspath(__file__))


def edit(path, pairs):
    p = f"{P}/{path}"
    s = open(p).read()
    for old, new in pairs:
        assert s.count(old) == 1, (path, old[:80], s.count(old))
        s = s.replace(old, new)
    open(p, "w").write(s)


# ── sphincs-c10 copy: the merged WOTS PRF on the generic path, its format code, its KAT tag ──────────────────────
edit("sphincs-c10/src/v2hash.rs", [
    ('''pub fn wots_secret(sk_seed: &[u8; 32], layer: u32, tree: u64, kp: u32, chain_idx: u32) -> [u8; N] {
    #[cfg(feature = "v2-wprf2b")]
    return wots_prf2b(''', '''/// RESEARCH (round 20, `v2-wprf2b` + `v2-prf2`): the merged PRF — one two-block digest over the A7 of the even
/// chain index gives two secrets (bytes 0..16 for the even index, 16..32 for the odd one); both copies wiped.
#[cfg(all(feature = "v2-wprf2b", feature = "v2-prf2"))]
fn wots_prf2b_half(sk_seed: &[u8; 32], layer: u32, a_even: u64, half: u32) -> [u8; N] {
    let mut b = [0u8; 71];
    b[0..32].copy_from_slice(sk_seed);
    b[32..48].copy_from_slice(b"C10v2-WOTS-PRF2B");
    b[48..52].copy_from_slice(&layer.to_be_bytes());
    put7(&mut b[64..71], a_even);
    let mut d = sha256_bytes(&b);
    let mut out = [0u8; N];
    out.copy_from_slice(&d[N * half as usize..N * half as usize + N]);
    for x in b.iter_mut().chain(d.iter_mut()) {
        // SAFETY: `x` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    out
}

pub fn wots_secret(sk_seed: &[u8; 32], layer: u32, tree: u64, kp: u32, chain_idx: u32) -> [u8; N] {
    #[cfg(all(feature = "v2-wprf2b", feature = "v2-prf2"))]
    return wots_prf2b_half(sk_seed, layer, pack(T_WOTS_PRF, u64::from(layer), tree, u64::from(kp), u64::from(chain_idx & !1), 0, 0), chain_idx & 1);
    #[cfg(all(feature = "v2-wprf2b", not(feature = "v2-prf2")))]
    return wots_prf2b('''),
    ('''    #[cfg(feature = "v2-prf2")]
    return prf_half(sk_seed, pack(T_WOTS_PRF,''', '''    #[cfg(all(feature = "v2-prf2", not(feature = "v2-wprf2b")))]
    return prf_half(sk_seed, pack(T_WOTS_PRF,'''),
])
edit("sphincs-c10/src/lib.rs", [('''#[cfg(all(feature = "v2-wprf2b", feature = "v2-prf2"))]
compile_error!("`v2-wprf2b` and `v2-prf2` are different WOTS PRFs");
''', '')])
edit("sphincs-c10/src/params.rs", [(
    'pub const FMT_WOTS_PRF: u8 = if cfg!(feature = "v2-wprf2b") { 2 } else if cfg!(feature = "v2-prf2") { 3 } else { 1 };',
    '/// (round 20: 4 = the merged two-block paired PRF, `v2-wprf2b` + `v2-prf2`)\n'
    'pub const FMT_WOTS_PRF: u8 = if cfg!(all(feature = "v2-wprf2b", feature = "v2-prf2")) { 4 } else if cfg!(feature = "v2-wprf2b") { 2 }'
    ' else if cfg!(feature = "v2-prf2") { 3 } else { 1 };')])
edit("sphincs-c10/tests/v2_kat.rs", [('''    if cfg!(feature = "v2-wprf2b") {
        return "wprf2b";
    }''', '''    if cfg!(all(feature = "v2-wprf2b", feature = "v2-ts200", feature = "v2-prf2", feature = "v2-split810")) {
        return "all3-wprf2b";
    }
    if cfg!(feature = "v2-wprf2b") {
        return "wprf2b";
    }''')])

# ── hw copy: the Rust key loop and sign chains already feed the wprf2b block before prf2's tail; lift the fence ──
edit("hw/src/hash.rs", [('''#[cfg(all(feature = "v2-wprf2b", feature = "v2-prf2"))]
compile_error!("`v2-wprf2b` and `v2-prf2` are different WOTS PRFs");
''', '')])

# ── domain copy: the full stack's format descriptor in the format tests ─────────────────────────────────────────
edit("domain/tests/format_kdf.rs", [
    ('''        ("forslastprf", FormatParams { last_fors: 2, ..d }),
    ]''', '''        ("forslastprf", FormatParams { last_fors: 2, ..d }),
        // round 20: the full stack (ts200 + prf2 + split810 + the merged two-block paired WOTS PRF)
        ("all3-wprf2b", FormatParams { target_sum: 200, wots_prf: 4, fors_prf: 3, layer_h: [8, 10], a7: A7_810, ..d }),
    ]'''),
    ('''        (false, false, true, true, true, false) => "all3",''',
     '''        (false, false, true, true, true, false) => "all3",
        (false, true, true, true, true, false) => "all3-wprf2b",'''),
])

# ── bench_chain copy: the top cache (#1148) in the FI chain mirror, the format atoms, the first chain's cycles ──
edit("bench_chain/Cargo.toml", [('fi-control-cmp = []\n', 'fi-control-cmp = []\n# round 20: the format atoms and the top cache\n'
     'ts200 = ["sphincs-c10/v2-ts200"]\nprf2 = ["sphincs-c10/v2-prf2", "pqsigner-hw/v2-prf2"]\n'
     'split810 = ["sphincs-c10/v2-split810", "pqsigner-hw/v2-split810"]\nwprf2b = ["sphincs-c10/v2-wprf2b", "pqsigner-hw/v2-wprf2b"]\n'
     'topcache = ["sphincs-c10/top-cache"]\n')])
edit("bench_chain/src/lib.rs", [
    ('''fn chain(sk: &SigningKey, msg_hash: &[u8; 32], seeds: ([u8; 32], [u8; 32]), ph: &mut [u64; NPH]) -> Result<[u8; SIGNATURE_LEN], ()> {''',
     '''fn chain(sk: &SigningKey, #[cfg(feature = "topcache")] cache: &sphincs_c10::topcache::TopCache, msg_hash: &[u8; 32], seeds: ([u8; 32], [u8; 32]), ph: &mut [u64; NPH]) -> Result<[u8; SIGNATURE_LEN], ()> {'''),
    ('''    let sig_a = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle_a, first_half);''',
     '''    #[cfg(not(feature = "topcache"))]
    let sig_a = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle_a, first_half);
    // round 20: both passes sign through the one cache (its stored nodes are shared, not recomputed per pass)
    #[cfg(feature = "topcache")]
    let sig_a = sk.sign_with_shuffle_cached(cache, msg_hash, opt_rand, &shuffle_a);'''),
    ('''    let sig_b = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle_b, second_half);''',
     '''    #[cfg(not(feature = "topcache"))]
    let sig_b = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle_b, second_half);
    #[cfg(feature = "topcache")]
    let sig_b = sk.sign_with_shuffle_cached(cache, msg_hash, opt_rand, &shuffle_b);'''),
    ('''    let t = cyc();
    let sk = SigningKey::keygen(SK_SEED, PK_SEED);
    out(2, cyc().wrapping_sub(t));''', '''    let t = cyc();
    #[cfg(not(feature = "topcache"))]
    let sk = SigningKey::keygen(SK_SEED, PK_SEED);
    #[cfg(feature = "topcache")]
    let mut cache = sphincs_c10::topcache::TopCache::empty();
    // round 20: keygen fills and confirms the cache (two top-tree builds); its time is in out(2)
    #[cfg(feature = "topcache")]
    let sk = sphincs_c10::topcache::keygen_with_top_cache(SK_SEED, PK_SEED, &mut cache);
    out(2, cyc().wrapping_sub(t));'''),
    ('''        let r = chain(&sk, &m, (sa, sb), &mut ph);''', '''        let r = chain(&sk, #[cfg(feature = "topcache")] &cache, &m, (sa, sb), &mut ph);'''),
    ('''        total += u64::from(cyc().wrapping_sub(t0));''', '''        total += u64::from(cyc().wrapping_sub(t0));
        if i == 0 {
            out(21, cyc().wrapping_sub(t0)); // round 20: the first chain after keygen
        }'''),
    ('''        out(20, DELAY_ITERS / NMSG);''', '''        out(20, DELAY_ITERS / NMSG);
        #[cfg(feature = "topcache")]
        out(22, sphincs_c10::topcache::HITS.load(core::sync::atomic::Ordering::Relaxed));'''),
])

# ── bench_v2fb copy (the cached fused bench, golden byte-compare + cache hits) pointed at the copies ──────────────
edit("bench_v2fb/Cargo.toml", [('path = "../../../sphincs-c10"', 'path = "../sphincs-c10"'), ('path = "../../../hw"', 'path = "../hw"'),
                               ('hra-ldm = ["pqsigner-hw/hra-ldm"]', 'hra-ldm = ["pqsigner-hw/hra-ldm"]\nwprf2b = ["sphincs-c10/v2-wprf2b", "pqsigner-hw/v2-wprf2b"]')])
edit("bench_v2fb/src/lib.rs", [('include!("../../inputs.rs");', 'include!("../../../../inputs.rs");')])

# ── bench_v2drv copy: the residue patterns of the merged PRF ──────────────────────────────────────────────────────
edit("bench_v2drv/Cargo.toml", [('cand-w4w = ["pqsigner-hw/v2-w4-asm", "pqsigner-hw/v2-wprf2b"]',
                                 'cand-w4w = ["pqsigner-hw/v2-w4-asm", "pqsigner-hw/v2-wprf2b"]\n'
                                 'cand-full = ["prf2", "split810", "pqsigner-hw/v2-wprf2b"]')])
edit("bench_v2drv/src/lib.rs", [('''    #[cfg(any(feature = "cand-d03w", feature = "cand-w4w"))]
    if a >> 52 == 5 {''', '''    // round 20: the merged PRF — the WOTS pair from one two-block digest over the even ci (FORS: prf2 below)
    #[cfg(feature = "cand-full")]
    if a >> 52 == 5 {
        let half = (a >> CI_SHIFT & 1) as usize;
        let mut blk = [0u8; 32];
        blk[..16].copy_from_slice(b"C10v2-WOTS-PRF2B");
        blk[16..20].copy_from_slice(&(((a >> 51) & 1) as u32).to_be_bytes());
        return sha(&[sk, &blk, &a7b(a & !(1u64 << CI_SHIFT))])[16 * half..16 * half + 16].try_into().unwrap();
    }
    #[cfg(any(feature = "cand-d03w", feature = "cand-w4w"))]
    if a >> 52 == 5 {''')])

# ── checkct workspace for the full stack (driver_wprf = the merged wots_secret, driver_fors = prf2's fors_secret) ──
src = f"{P}/sca-d03w/checkct"
dst = f"{P}/sca-full/checkct"
shutil.copytree(src, dst, ignore=shutil.ignore_patterns("target"))
for d in ("driver", "driver_fors", "driver_th", "driver_wprf"):
    ct = os.path.join(dst, d, "Cargo.toml")
    s = open(ct).read()
    s = s.replace('"v2", "v2-wprf2b"', '"v2", "v2-ts200", "v2-prf2", "v2-split810", "v2-wprf2b"')
    assert "v2-prf2" in s, ct
    open(ct, "w").write(s)
print("applied (proto_full)")
