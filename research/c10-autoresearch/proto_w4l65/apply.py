#!/usr/bin/env python3
"""apply.py <proto dir> — RESEARCH PROTOTYPE (round 16): the w4l65 frontier set (c10v2_ref.py --variant w4l65:
WOTS+C w = 4, l = 65, T = 125, A7 ci 7 bits at 23..17, 4,712-B signatures) as an off-by-default Cargo feature
`v2-w4l65` on a COPY of sphincs-c10, plus copies of the host golden generator and the kit bench pointed at it.

Why a copy: params.rs, wots.rs, shuffle.rs and hash.rs are pinned whole-file by the extraction-freshness gate
(contracts/verification/scripts/check_extraction_freshness.py); editing them would need re-extraction, re-proof
and re-pinning. The product crate stays byte-identical; this script is the whole delta. Every edit is an exact
string replacement asserted to occur once, so a drifted source fails loudly instead of half-applying.
"""
import sys

P = sys.argv[1]


def edit(path, pairs):
    p = f"{P}/{path}"
    s = open(p).read()
    for old, new in pairs:
        assert s.count(old) == 1, (path, old[:70], s.count(old))
        s = s.replace(old, new)
    open(p, "w").write(s)


# ── 1. the variant (the part that would land in sphincs-c10 behind the flag) ──────────────────────────────────
edit("sphincs-c10/Cargo.toml", [('''v2-split810 = ["v2"]
''', '''v2-split810 = ["v2"]
# RESEARCH PROTOTYPE (round 16, research/c10-autoresearch/proto_w4l65; c10v2_ref.py --variant w4l65): WOTS+C
# w = 4, l = 65, target sum 125; A7 ci 7 bits at 23..17; 4,712-B signatures. Generic v2 path only.
v2-w4l65 = ["v2"]
''')])
edit("sphincs-c10/src/params.rs", [
    ('''/// Winternitz parameter.
pub const W: usize = 8;

/// log2(W).
pub const LOG_W: usize = 3;

/// WOTS chain count.
pub const L: usize = 43;

/// WOTS+C target digit sum for count-grinding.
#[cfg(not(feature = "v2-ts200"))]
pub const TARGET_SUM: usize = 205;''',
     '''/// Winternitz parameter.
#[cfg(not(feature = "v2-w4l65"))]
pub const W: usize = 8;
/// RESEARCH PROTOTYPE `v2-w4l65`: w = 4, l = 65, target sum 125.
#[cfg(feature = "v2-w4l65")]
pub const W: usize = 4;

/// log2(W).
#[cfg(not(feature = "v2-w4l65"))]
pub const LOG_W: usize = 3;
#[cfg(feature = "v2-w4l65")]
pub const LOG_W: usize = 2;

/// WOTS chain count.
#[cfg(not(feature = "v2-w4l65"))]
pub const L: usize = 43;
#[cfg(feature = "v2-w4l65")]
pub const L: usize = 65;

#[cfg(all(feature = "v2-w4l65", feature = "v2-ts200"))]
compile_error!("`v2-w4l65` sets its own target sum");
/// WOTS+C target digit sum for count-grinding.
#[cfg(feature = "v2-w4l65")]
pub const TARGET_SUM: usize = 125;
#[cfg(not(any(feature = "v2-ts200", feature = "v2-w4l65")))]
pub const TARGET_SUM: usize = 205;'''),
    ('''const _: () = assert!(SIG_HT_LAYER == 836);
const _: () = assert!(SIGNATURE_LEN == 4008);''',
     '''#[cfg(not(feature = "v2-w4l65"))]
const _: () = assert!(SIG_HT_LAYER == 836);
#[cfg(not(feature = "v2-w4l65"))]
const _: () = assert!(SIGNATURE_LEN == 4008);
#[cfg(feature = "v2-w4l65")]
const _: () = assert!(SIG_HT_LAYER == 1188 && SIGNATURE_LEN == 4712);'''),
])
edit("sphincs-c10/src/wots.rs", [
    ('''pub(crate) fn digit_sum(digest: &[u8; 32]) -> usize {
    let mut sum: usize = 0;''',
     '''#[cfg(not(feature = "v2-w4l65"))]
pub(crate) fn digit_sum(digest: &[u8; 32]) -> usize {
    let mut sum: usize = 0;'''),
    ('''const _: () = assert!(L == 43 && LOG_W == 3 && W_MASK == 7 && L * LOG_W == 5 * 24 + 9);''',
     '''#[cfg(not(feature = "v2-w4l65"))]
const _: () = assert!(L == 43 && LOG_W == 3 && W_MASK == 7 && L * LOG_W == 5 * 24 + 9);
/// RESEARCH PROTOTYPE `v2-w4l65`: the plain sum of the extracted digits.
#[cfg(feature = "v2-w4l65")]
pub(crate) fn digit_sum(digest: &[u8; 32]) -> usize {
    let d = extract_digits(digest);
    let mut sum = 0;
    for i in 0..L {
        sum += d[i] as usize;
    }
    sum
}'''),
])
edit("sphincs-c10/src/shuffle.rs", [
    ('''pub fn fisher_yates(seed: &[u8; 32], n: usize) -> [u8; 64] {
    debug_assert!(n <= 64);

    let mut buf = [0u8; 64];''',
     '''pub fn fisher_yates(seed: &[u8; 32], n: usize) -> [u8; SHUFFLE_CAP] {
    debug_assert!(n <= SHUFFLE_CAP);

    let mut buf = [0u8; SHUFFLE_CAP];'''),
    ('''#[inline(never)]
#[must_use]
pub fn fisher_yates(''',
     '''/// Permutation capacity: 64, or 65 under the RESEARCH PROTOTYPE `v2-w4l65` (l = 65). n = 65 draws
/// 2 * 64 = 128 stream bytes, exactly the 4 precomputed blocks; the Lemire bound stays < 2^22.
#[cfg(not(feature = "v2-w4l65"))]
pub const SHUFFLE_CAP: usize = 64;
#[cfg(feature = "v2-w4l65")]
pub const SHUFFLE_CAP: usize = 65;

#[inline(never)]
#[must_use]
pub fn fisher_yates('''),
])
edit("sphincs-c10/src/v2hash.rs", [
    ('''    assert!(ci < (1 << 6) && cp < 16 && ha < (1 << 11));''',
     '''    assert!(ci < (1 << CI_BITS) && cp < 16 && ha < (1 << 11));'''),
    ('''const CI_SHIFT: u32 = KP_SHIFT - 6;''',
     '''/// `ci`'s width: 6 bits, 7 under the RESEARCH PROTOTYPE `v2-w4l65` (ci <= 64), at 23..17.
#[cfg(not(feature = "v2-w4l65"))]
const CI_BITS: u32 = 6;
#[cfg(feature = "v2-w4l65")]
const CI_BITS: u32 = 7;
#[cfg(all(feature = "v2-w4l65", feature = "v2-split810"))]
compile_error!("`v2-w4l65` and `v2-split810` both re-lay out ci");
const CI_SHIFT: u32 = KP_SHIFT - CI_BITS;'''),
])
edit("sphincs-c10/src/hash.rs", [('''pub const TH_MULTI_MAX: usize = 43;''',
                                  '''#[cfg(not(feature = "v2-w4l65"))]
pub const TH_MULTI_MAX: usize = 43;
/// RESEARCH PROTOTYPE `v2-w4l65`: the WOTS public key compresses L = 65 values.
#[cfg(feature = "v2-w4l65")]
pub const TH_MULTI_MAX: usize = 65;''')])
edit("sphincs-c10/src/lib.rs", [('''#[cfg(all(feature = "near-miss-gen", feature = "v2-split810"))]''',
                                 '''#[cfg(all(feature = "v2-w4l65", any(feature = "near-miss-gen", feature = "v2-prf2")))]
compile_error!("the `v2-w4l65` prototype supports neither `near-miss-gen` nor `v2-prf2`");
#[cfg(all(feature = "near-miss-gen", feature = "v2-split810"))]''')])
edit("sphincs-c10/src/lib.rs", [(") -> (u32, [u8; 32], [u8; 43]) {", ") -> (u32, [u8; 32], [u8; crate::params::L]) {")])   # sim_internals::find_count
edit("sphincs-c10/tests/v2_kat.rs", [('''fn tag() -> &'static str {
    match''', '''fn tag() -> &'static str {
    if cfg!(feature = "v2-w4l65") {
        return "w4l65";
    }
    match''')])

# ── 2. make the copy build on its own (out of the root workspace, research paths) ──────────────────────────
edit("sphincs-c10/Cargo.toml", [("edition.workspace = true", 'edition = "2021"'),
                                ('zeroize = { workspace = true, features = ["zeroize_derive"] }',
                                 'zeroize = { version = "1.8", default-features = false, features = ["zeroize_derive"] }'),
                                ("[lints]\nworkspace = true\n", ""), ("hex = { workspace = true }", 'hex = "0.4"')])
open(f"{P}/sphincs-c10/Cargo.toml", "a").write("\n[workspace]\n")
edit("sphincs-c10/tests/v2_kat.rs", [('{}/../research/c10-autoresearch/c10v2/', '{}/../../../c10v2/')])

# ── 3. the host golden generator and the kit bench, pointed at the copy ──────────────────────────────────────
edit("host_v2/Cargo.toml", [('path = "../../../sphincs-c10"', 'path = "../sphincs-c10"'),
                            ('split810 = ["sphincs-c10/v2-split810"]', 'split810 = ["sphincs-c10/v2-split810"]\nw4l65 = ["sphincs-c10/v2-w4l65"]')])
edit("host_v2/src/main.rs", [('include!("../../inputs.rs");', 'include!("../../../../inputs.rs");'),
                             ('include!("../../diff_cases.rs");', 'include!("../../../../diff_cases.rs");'),
                             ('m: &[u8; 32], sh: &[u8; 32]) -> [u8; 4008] {', 'm: &[u8; 32], sh: &[u8; 32]) -> [u8; sphincs_c10::params::SIGNATURE_LEN] {')])
edit("bench_v2/Cargo.toml", [('path = "../../../sphincs-c10"', 'path = "../sphincs-c10"'), ('path = "../../../hw"', 'path = "../../../../../hw"'),
                             ('hra-ldm = ["pqsigner-hw/hra-ldm"]', 'hra-ldm = ["pqsigner-hw/hra-ldm"]\nw4l65 = ["sphincs-c10/v2-w4l65"]')])
edit("bench_v2/src/lib.rs", [('include!("../../inputs.rs");', 'include!("../../../../inputs.rs");')])

# ── 4. the frozen runner / evaluator read 4,008-B signatures: parameterized copies ───────────────────────────
edit("run_flash_sig.sh", [("read_memory \\$a 32 1002]", "read_memory \\$a 32 ${SIGW:-1002}]")])
edit("run_profile_sig.sh", [("read_memory \\$a 32 1002]", "read_memory \\$a 32 ${SIGW:-1002}]")])
edit("evaluate_sig.py", [("log, golden = sys.argv[1], open(sys.argv[2], 'rb').read()\n",
                          "log, golden = sys.argv[1], open(sys.argv[2], 'rb').read()\nSL = int(sys.argv[3]) if len(sys.argv) > 3 else 4008\n"),
                         ("[])[:4008]\nb1", "[])[:SL]\nb1"), ("s1 or [])[:4008]", "s1 or [])[:SL]"),
                         ("golden[16:16 + 4008]", "golden[16:16 + SL]"), ("golden[16 + 4008:]", "golden[16 + SL:]")])

# ── 5. round 17: the w = 4 fused driver, on a COPY of pqsigner-hw (hw/) ──────────────────────────────────────
# The v2 DATATYPE-00 key loop already takes the chain count and chain length from its context and the ci shift
# from V2_CI_LSB (1 for ci at A7 bits 23..17, as split810), so the asm is reused unchanged; the Rust wrappers'
# 43 / 688 / 178 / 712 become L-derived, the T_43 feed and the w = 8 asm search are compiled out, and the Rust
# search gets a 2-bit digit sum over the low 130 bits.
edit("hw/Cargo.toml", [("edition.workspace = true", 'edition = "2021"'),
                       ("cortex-m = { workspace = true }", 'cortex-m = "0.7"'),
                       ("[dependencies.cortex-m-semihosting]\nworkspace = true\n", '[dependencies.cortex-m-semihosting]\nversion = "0.5"\n'),
                       ('v2-split810 = ["v2"]', 'v2-split810 = ["v2"]\n# RESEARCH PROTOTYPE (round 17, proto_w4l65): the fused driver for w = 4, l = 65, T = 125.\nv2-w4l65 = ["v2"]')])
hp = f"{P}/hw/src/hash.rs"
t = open(hp).read()
n_t43, n_srch = t.count('feature = "v2-asm-t43"'), t.count('feature = "v2-asm-search"')
assert n_t43 > 0 and n_srch > 0, (n_t43, n_srch)
t = t.replace('feature = "v2-asm-t43"', 'all(feature = "v2-asm-t43", not(feature = "v2-w4l65"))')
t = t.replace('feature = "v2-asm-search"', 'all(feature = "v2-asm-search", not(feature = "v2-w4l65"))')
open(hp, "w").write(t)
edit("hw/src/hash.rs", [
    ("""#[cfg(all(feature = "v2", not(feature = "v2-split810")))]
const V2_CI_LSB: u32 = 2;
#[cfg(all(feature = "v2", feature = "v2-split810"))]
const V2_CI_LSB: u32 = 1;""",
     """#[cfg(all(feature = "v2", not(any(feature = "v2-split810", feature = "v2-w4l65"))))]
const V2_CI_LSB: u32 = 2;
#[cfg(all(feature = "v2", any(feature = "v2-split810", feature = "v2-w4l65")))]
const V2_CI_LSB: u32 = 1;
/// WOTS chain count: 43, or 65 under the RESEARCH PROTOTYPE `v2-w4l65` (ci at A7 bits 23..17, word LSB 1).
#[cfg(all(feature = "v2", not(feature = "v2-w4l65")))]
const V2_L: u32 = 43;
#[cfg(all(feature = "v2", feature = "v2-w4l65"))]
const V2_L: u32 = 65;
/// Words of the T_l preimage (S, A7 of WOTS_PK, a zero byte, then l values): 178 (712 B) or 266 (1,064 B).
#[cfg(feature = "v2")]
const V2_PK_WORDS: usize = 6 + 4 * V2_L as usize;
#[cfg(all(feature = "v2-w4l65", any(feature = "v2-prf2", feature = "v2-split810", feature = "v2-fold-sum")))]
compile_error!("`v2-w4l65` (research prototype) builds with neither prf2, split810 nor fold-sum");"""),
    ("""        let mut ctx = [sk_seed as u32, p0, p1, s[0], s[1], s[2], s[3], a0, low24, steps, 43, out as u32];""",
     """        let mut ctx = [sk_seed as u32, p0, p1, s[0], s[1], s[2], s[3], a0, low24, steps, V2_L, out as u32];"""),
    ("""    if steps != 0 && ((out as usize).saturating_add(688) <= sk_seed as usize""",
     """    if steps != 0 && ((out as usize).saturating_add(16 * V2_L as usize) <= sk_seed as usize"""),
    ("""    let mut ci = 0u32;
    while ci < 43 {
        let c = ci << V2_CI_LSB;""", """    let mut ci = 0u32;
    while ci < V2_L {
        let c = ci << V2_CI_LSB;"""),
    ("""    let mut buf = core::mem::MaybeUninit::<[u32; 178]>::uninit();""",
     """    let mut buf = core::mem::MaybeUninit::<[u32; V2_PK_WORDS]>::uninit();"""),
    ("""        pqsigner_sha256_oneshot16(b.cast::<u8>(), 712, out);""",
     """        pqsigner_sha256_oneshot16(b.cast::<u8>(), 4 * V2_PK_WORDS, out);"""),
    ("""        let next = c.wrapping_add(1);
        let more = next != end;
        if more {
            issue(next);
        }
        // Digits 0..31 first""", """        let next = c.wrapping_add(1);
        let more = next != end;
        if more {
            issue(next);
        }
        // RESEARCH PROTOTYPE `v2-w4l65`: 65 two-bit digits, the low 130 bits (c10v2_ref.py --variant w4l65);
        // the caller re-checks the accepted digest with sphincs-c10's own digit sum.
        #[cfg(feature = "v2-w4l65")]
        {
            #[inline(always)]
            fn s2(v: u32) -> u32 {
                let s = (v & 0x3333_3333).wrapping_add((v >> 2) & 0x3333_3333);
                let s = (s & 0x0F0F_0F0F).wrapping_add((s >> 4) & 0x0F0F_0F0F);
                s.wrapping_mul(0x0101_0101) >> 24
            }
            let _ = g24;
            let sum = s2(w7).wrapping_add(s2(w6)).wrapping_add(s2(w5)).wrapping_add(s2(w4)).wrapping_add(w3 & 3);
            if sum == target {
                let mut d = [0u32; 8];
                if more {
                    v2_collect(&mut d);
                }
                issue(c);
                v2_collect(&mut d);
                // SAFETY: `out` names 32 writable bytes.
                unsafe { core::ptr::copy_nonoverlapping(d.as_ptr().cast::<u8>(), out, 32) };
                return c;
            }
            if !more {
                return end;
            }
            c = next;
            continue;
        }
        #[allow(unreachable_code)]
        // Digits 0..31 first"""),
])
edit("bench_v2f/Cargo.toml", [('path = "../../../sphincs-c10"', 'path = "../sphincs-c10"'), ('path = "../../../hw"', 'path = "../hw"'),
                              ('hra-ldm = ["pqsigner-hw/hra-ldm"]', 'hra-ldm = ["pqsigner-hw/hra-ldm"]\nw4l65 = ["sphincs-c10/v2-w4l65", "pqsigner-hw/v2-w4l65"]')])
edit("bench_v2f/src/lib.rs", [('include!("../../inputs.rs");', 'include!("../../../../inputs.rs");')])
edit("bench_avg_v2f/Cargo.toml", [('path = "../../../sphincs-c10"', 'path = "../sphincs-c10"'), ('path = "../../../hw"', 'path = "../hw"'),
                                  ('forslastprf = ["sphincs-c10/v2-fors-last-prf"]',
                                   'forslastprf = ["sphincs-c10/v2-fors-last-prf"]\nw4l65 = ["sphincs-c10/v2-w4l65", "pqsigner-hw/v2-w4l65"]')])
edit("bench_avg_v2f/src/lib.rs", [('include!("../../inputs.rs");', 'include!("../../../../inputs.rs");')])
print(f"fused driver: replaced {n_t43} v2-asm-t43 and {n_srch} v2-asm-search predicates")

# ── 6. round 17, gate (c): the two-block WOTS secret PRF `v2-wprf2b` (c10v2_ref.py --variant wprf2b) ─────────
# sha256(sk_seed || "C10v2-WOTS-PRF2B" || be32(layer) || 0^12 || A7)[:16], 71 B: the first block is constant
# per layer, so sk_seed never meets a varying word in one compression (v1's WOTS-PRF shape). Generic v2 path in
# the sphincs-c10 copy; the fused driver's two Rust WOTS-PRF feeds in the hw copy. The asm key loop issues the
# one-block PRF itself, so `v2-rust-key` compiles it out (the A/B baseline) and `v2-wprf2b` implies it.
edit("sphincs-c10/Cargo.toml", [('v2-w4l65 = ["v2"]', 'v2-w4l65 = ["v2"]\n# RESEARCH PROTOTYPE (round 17, gate (c)): the two-block WOTS secret PRF (c10v2_ref.py --variant wprf2b).\nv2-wprf2b = ["v2"]')])
edit("sphincs-c10/src/v2hash.rs", [
    ("""pub fn wots_secret(sk_seed: &[u8; 32], layer: u32, tree: u64, kp: u32, chain_idx: u32) -> [u8; N] {
    #[cfg(feature = "v2-prf2")]""",
     """/// RESEARCH PROTOTYPE `v2-wprf2b`: `sk_seed ‖ "C10v2-WOTS-PRF2B" ‖ be32(layer) ‖ 0^12 ‖ A7`, 71 bytes, first 16
/// digest bytes; the input copy is wiped.
#[cfg(feature = "v2-wprf2b")]
fn wots_prf2b(sk_seed: &[u8; 32], layer: u32, a: u64) -> [u8; N] {
    let mut b = [0u8; 71];
    b[0..32].copy_from_slice(sk_seed);
    b[32..48].copy_from_slice(b"C10v2-WOTS-PRF2B");
    b[48..52].copy_from_slice(&layer.to_be_bytes());
    put7(&mut b[64..71], a);
    let out = sha256_bytes16(&b);
    for x in b.iter_mut() {
        // SAFETY: `x` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    out
}

pub fn wots_secret(sk_seed: &[u8; 32], layer: u32, tree: u64, kp: u32, chain_idx: u32) -> [u8; N] {
    #[cfg(feature = "v2-wprf2b")]
    return wots_prf2b(sk_seed, layer, pack(T_WOTS_PRF, u64::from(layer), tree, u64::from(kp), u64::from(chain_idx), 0, 0));
    #[cfg(feature = "v2-prf2")]"""),
])
edit("sphincs-c10/src/lib.rs", [('''#[cfg(all(feature = "v2-w4l65", any(feature = "near-miss-gen", feature = "v2-prf2")))]''',
                                 '''#[cfg(all(feature = "v2-wprf2b", feature = "v2-prf2"))]
compile_error!("`v2-wprf2b` and `v2-prf2` are different WOTS PRFs");
#[cfg(all(feature = "v2-w4l65", any(feature = "near-miss-gen", feature = "v2-prf2")))]''')])
edit("sphincs-c10/tests/v2_kat.rs", [('''    if cfg!(feature = "v2-w4l65") {
        return "w4l65";
    }''', '''    if cfg!(feature = "v2-w4l65") {
        assert!(!cfg!(feature = "v2-wprf2b"), "no KAT set for w4l65 + wprf2b");
        return "w4l65";
    }
    if cfg!(feature = "v2-wprf2b") {
        return "wprf2b";
    }''')])
edit("hw/Cargo.toml", [('v2-w4l65 = ["v2"]', 'v2-w4l65 = ["v2"]\n# RESEARCH PROTOTYPE (round 17): the Rust WOTS key loop (asm key loop compiled out), and the two-block WOTS PRF.\nv2-rust-key = ["v2"]\nv2-wprf2b = ["v2-rust-key"]')])
hp = f"{P}/hw/src/hash.rs"
t = open(hp).read()
n_ka = t.count('feature = "v2-asm-key-ga"')
assert n_ka > 0
t = t.replace('feature = "v2-asm-key-ga"', 'all(feature = "v2-asm-key-ga", not(feature = "v2-rust-key"))')
open(hp, "w").write(t)
edit("hw/src/hash.rs", [
    ("""compile_error!("`v2-w4l65` (research prototype) builds with neither prf2, split810 nor fold-sum");""",
     """compile_error!("`v2-w4l65` (research prototype) builds with neither prf2, split810 nor fold-sum");
#[cfg(all(feature = "v2-wprf2b", feature = "v2-prf2"))]
compile_error!("`v2-wprf2b` and `v2-prf2` are different WOTS PRFs");
/// RESEARCH PROTOTYPE `v2-wprf2b` (round 17, gate (c)): the WOTS PRF's second 32 bytes, constant per layer,
/// `"C10v2-WOTS-PRF2B" ‖ be32(layer) ‖ 0^12`; `layer` is A7 bit 51, bit 3 of `p0`'s first byte.
#[cfg(feature = "v2-wprf2b")]
#[inline(always)]
fn v2_wprf2b_block(p0: u32) {
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(b"C10v2-WOTS-PRF2B");
    b[19] = ((p0 >> 3) & 1) as u8;
    // SAFETY: `b` names 32 readable bytes (public data).
    unsafe { feed_words(b.as_ptr(), 8) };
}"""),
    ("""    v2_entry();
    v2_begin();
    // SAFETY: caller contract.
    unsafe { feed_words(sk_seed, 8) };
    write_word(p0);
    #[cfg(not(feature = "v2-prf2"))]
    let v = {
        write_word(p1);""", """    v2_entry();
    v2_begin();
    // SAFETY: caller contract.
    unsafe { feed_words(sk_seed, 8) };
    #[cfg(feature = "v2-wprf2b")]
    v2_wprf2b_block(p0);
    write_word(p0);
    #[cfg(not(feature = "v2-prf2"))]
    let v = {
        write_word(p1);"""),
    ("""    while ci < V2_L {
        let c = ci << V2_CI_LSB;
        v2_begin();
        // SAFETY: caller contract.
        unsafe { feed_words(sk_seed, 8) };
        write_word(p0);""", """    while ci < V2_L {
        let c = ci << V2_CI_LSB;
        v2_begin();
        // SAFETY: caller contract.
        unsafe { feed_words(sk_seed, 8) };
        #[cfg(feature = "v2-wprf2b")]
        v2_wprf2b_block(p0);
        write_word(p0);"""),
])
for b in ("bench_v2f", "bench_avg_v2f"):
    edit(f"{b}/Cargo.toml", [('w4l65 = ["sphincs-c10/v2-w4l65", "pqsigner-hw/v2-w4l65"]',
                              'w4l65 = ["sphincs-c10/v2-w4l65", "pqsigner-hw/v2-w4l65"]\nrustkey = ["pqsigner-hw/v2-rust-key"]\n'
                              'wprf2b = ["sphincs-c10/v2-wprf2b", "pqsigner-hw/v2-wprf2b"]')])
edit("bench_v2/Cargo.toml", [('w4l65 = ["sphincs-c10/v2-w4l65"]', 'w4l65 = ["sphincs-c10/v2-w4l65"]\nwprf2b = ["sphincs-c10/v2-wprf2b"]')])
edit("host_v2/Cargo.toml", [('w4l65 = ["sphincs-c10/v2-w4l65"]', 'w4l65 = ["sphincs-c10/v2-w4l65"]\nwprf2b = ["sphincs-c10/v2-wprf2b"]')])
print(f"gate (c): replaced {n_ka} v2-asm-key-ga predicates")

# ── 7. round 17, gate (d): the C10 format identifier bound into BOTH key-derivation branches ──────────────────
# A copy of pqsigner-domain (domain/) against the sphincs-c10 copy. `format-kdf` (off by default) is required
# by every v2 build and refused by v1 builds, so the stock account-0 / account>0 derivations stay byte-identical.
open(f"{P}/sphincs-c10/src/params.rs", "a").write('''
// RESEARCH PROTOTYPE (round 17, gate (d), proto_w4l65 section 7): the format facts key derivation binds. A new
// format choice (tweak layout, PRF, last FORS slot, digit rule, H_MSG layout) must change one of these values.
/// 1 = the v1 32-byte-ADRS hash layer; 2 = the v2 one-block A7 layer (spec 0.3, incl. its H_MSG and digit rule).
pub const FMT_HASH_LAYER: u8 = if cfg!(feature = "v2") { 2 } else { 1 };
const FMT_KP_BITS: u8 = if cfg!(feature = "v2-split810") { 10 } else { 9 };
const FMT_CI_BITS: u8 = if cfg!(feature = "v2-w4l65") { 7 } else { 6 };
/// A7 (width, shift) per field: type, layer, tree, kp, ci, cp, ha; all zero for v1.
pub const FMT_A7: [u8; 14] = if cfg!(feature = "v2") {
    [4, 52, 1, 51, 18, 33, FMT_KP_BITS, 33 - FMT_KP_BITS, FMT_CI_BITS, 33 - FMT_KP_BITS - FMT_CI_BITS, 4, 12, 11, 1]
} else {
    [0; 14]
};
/// WOTS secret PRF: 1 one block, 2 two blocks (`v2-wprf2b`), 3 paired (`v2-prf2`).
pub const FMT_WOTS_PRF: u8 = if cfg!(feature = "v2-wprf2b") { 2 } else if cfg!(feature = "v2-prf2") { 3 } else { 1 };
/// FORS secret PRF: 1 one secret per digest, 3 paired (`v2-prf2`).
pub const FMT_FORS_PRF: u8 = if cfg!(feature = "v2-prf2") { 3 } else { 1 };
/// Last FORS slot: 1 tree 12's root, 2 a PRF value (`v2-fors-last-prf`).
pub const FMT_LAST_FORS: u8 = if cfg!(feature = "v2-fors-last-prf") { 2 } else { 1 };
/// R-candidate PRF: 1 = v1's (`sk_seed ‖ "R_grind" ‖ …`), shared by every format today.
pub const FMT_R_PRF: u8 = 1;
''')
edit("sphincs-c10/src/v2hash.rs", [("""const CI_SHIFT: u32 = KP_SHIFT - CI_BITS;""",
                                    """const CI_SHIFT: u32 = KP_SHIFT - CI_BITS;
// the key-derivation format facts (params::FMT_A7) describe this layout exactly
const _: () = assert!(crate::params::FMT_A7[6] as u32 == KP_BITS && crate::params::FMT_A7[7] as u32 == KP_SHIFT
    && crate::params::FMT_A7[8] as u32 == CI_BITS && crate::params::FMT_A7[9] as u32 == CI_SHIFT
    && crate::params::FMT_A7[11] as u32 == CP_SHIFT);""")])
edit("domain/Cargo.toml", [
    ("edition.workspace = true", 'edition = "2021"'),
    ("pqsigner-proto      = { workspace = true }", 'pqsigner-proto      = { path = "../../../../../proto" }'),
    ('sphincs-tz-bip39    = { workspace = true, features = ["full-wordlist"] }',
     'sphincs-tz-bip39    = { path = "../../../../../bip39", default-features = false, features = ["full-wordlist"] }'),
    ("sphincs-c10         = { workspace = true }", 'sphincs-c10         = { path = "../sphincs-c10" }'),
    ("zeroize = { workspace = true }", 'zeroize = { version = "1.8", default-features = false }'),
    ("hmac    = { workspace = true }", 'hmac    = { version = "0.12", default-features = false }'),
    ("hex = { workspace = true }", 'hex = "0.4"'),
    ("hmac = { workspace = true }", 'hmac = { version = "0.12", default-features = false }'),
    ('sphincs-tz-bip39 = { workspace = true, features = ["full-wordlist"] }',
     'sphincs-tz-bip39 = { path = "../../../../../bip39", default-features = false, features = ["full-wordlist"] }'),
    ("sphincs-c10 = { workspace = true }", 'sphincs-c10 = { path = "../sphincs-c10" }'),
    ("pqsigner-proto = { workspace = true }", 'pqsigner-proto = { path = "../../../../../proto" }'),
    ("[lints]\nworkspace = true\n", """[features]
# RESEARCH PROTOTYPE (round 17, gate (d)): bind the C10 format identifier into both key-derivation branches.
format-kdf = []
# pass-throughs, so one crate can be tested against each format
v2 = ["sphincs-c10/v2"]
ts200 = ["v2", "sphincs-c10/v2-ts200"]
prf2 = ["v2", "sphincs-c10/v2-prf2"]
split810 = ["v2", "sphincs-c10/v2-split810"]
w4l65 = ["v2", "sphincs-c10/v2-w4l65"]
wprf2b = ["v2", "sphincs-c10/v2-wprf2b"]
forslastprf = ["v2", "sphincs-c10/v2-fors-last-prf"]

[workspace]
"""),
])
edit("domain/src/lib.rs", [
    ("""    let domain: &[u8] = if account_index == 0 {
        b"sphincs-c6-v1"
    } else {
        b"sphincs-c6-v1-acct"
    };
    let mut master: [u8; 64] = if account_index == 0 {""",
     """    #[cfg(feature = "format-kdf")]
    let mut master: [u8; 64] = bootstrap_master_with_format(&compiled_format_id(), bip39_seed, account_index);
    #[cfg(not(feature = "format-kdf"))]
    let domain: &[u8] = if account_index == 0 {
        b"sphincs-c6-v1"
    } else {
        b"sphincs-c6-v1-acct"
    };
    #[cfg(not(feature = "format-kdf"))]
    let mut master: [u8; 64] = if account_index == 0 {"""),
    ("""#[must_use]
pub fn slot_master_entropy_from_bip39(
    bip39_seed: &[u8; 64],
    account_index: u32,
) -> [u8; 32] {
    if account_index == 0 {""",
     """#[must_use]
#[cfg_attr(feature = "format-kdf", allow(unreachable_code))]
pub fn slot_master_entropy_from_bip39(
    bip39_seed: &[u8; 64],
    account_index: u32,
) -> [u8; 32] {
    #[cfg(feature = "format-kdf")]
    return slot_master_with_format(&compiled_format_id(), bip39_seed, account_index);
    if account_index == 0 {"""),
    ("""fn derive_c10_slot_seeds(slot_entropy: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // sk_seed = sha256("slot_c10_sk_seed"[16] ‖ slot_entropy[32]) — 48 bytes.""",
     """#[cfg_attr(feature = "format-kdf", allow(unreachable_code))]
fn derive_c10_slot_seeds(slot_entropy: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    #[cfg(feature = "format-kdf")]
    return slot_seeds_with_format(&compiled_format_id(), slot_entropy);
    // sk_seed = sha256("slot_c10_sk_seed"[16] ‖ slot_entropy[32]) — 48 bytes."""),
])
# the legacy "c7" routes (retired in production, RETIRED_LEGACY_VK) mint C10 keys from format-unbound tags:
# under format-kdf they do not exist (mk.sh's probe proves every caller then fails to compile)
for name in ("slhdsa_seed_from_bip39", "derive_signing_key_from_entropy", "derive_keypair_from_entropy",
             "bootstrap_seed_from_bip39", "derive_bootstrap_key_from_entropy", "derive_bootstrap_keypair_from_entropy",
             "derive_bootstrap_vk_from_entropy"):
    edit("domain/src/lib.rs", [(f"#[must_use]\npub fn {name}(",
                                f"#[cfg(not(feature = \"format-kdf\"))]\n#[must_use]\npub fn {name}(")])
open(f"{P}/domain/src/lib.rs", "a").write('''
// ---------------------------------------------------------------------------
// RESEARCH PROTOTYPE (round 17, gate (d); research/c10-autoresearch/proto_w4l65 section 7): the C10 format
// identifier, bound into BOTH key-derivation branches (bootstrap master, slot master and slot seeds; account 0
// and account > 0). Off by default (`format-kdf`); required by every v2 build and refused by v1 builds, so the
// stock derivations stay byte-identical. Ledger round 17 states the domain-separation argument.
// ---------------------------------------------------------------------------

/// Every parameter and encoding choice that makes two C10 builds produce different keys or signatures.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FormatParams {
    /// 1 = v1 32-byte-ADRS hash layer; 2 = v2 one-block A7 layer (spec 0.3, incl. its H_MSG and digit rule).
    pub hash_layer: u8,
    pub n: u8,
    pub h: u8,
    pub d: u8,
    /// per-layer subtree heights, layer 0 first
    pub layer_h: [u8; 2],
    pub a: u8,
    pub k: u8,
    pub w: u8,
    pub l: u8,
    pub target_sum: u16,
    /// A7 (width, shift) per field: type, layer, tree, kp, ci, cp, ha; zero for v1
    pub a7: [u8; 14],
    /// 1 one block, 2 two blocks (wprf2b), 3 paired (prf2)
    pub wots_prf: u8,
    /// 1 one secret per digest, 3 paired (prf2)
    pub fors_prf: u8,
    /// 1 tree 12's root, 2 a PRF value
    pub last_fors: u8,
    /// 1 = v1's R-grind PRF
    pub r_prf: u8,
}

/// `"PQ1-C10-FMT1"` and 30 fixed-width field bytes: injective on `FormatParams` (fixed positions, no separators).
pub const FORMAT_DESCRIPTOR_LEN: usize = 42;

/// The format this build signs with, from `sphincs_c10::params`.
pub const COMPILED_FORMAT: FormatParams = {
    use sphincs_c10::params as p;
    FormatParams {
        hash_layer: p::FMT_HASH_LAYER,
        n: p::N as u8,
        h: p::H as u8,
        d: p::D as u8,
        layer_h: [p::layer_h(0) as u8, p::layer_h(1) as u8],
        a: p::A as u8,
        k: p::K as u8,
        w: p::W as u8,
        l: p::L as u8,
        target_sum: p::TARGET_SUM as u16,
        a7: p::FMT_A7,
        wots_prf: p::FMT_WOTS_PRF,
        fors_prf: p::FMT_FORS_PRF,
        last_fors: p::FMT_LAST_FORS,
        r_prf: p::FMT_R_PRF,
    }
};

#[cfg(feature = "format-kdf")]
const _: () = assert!(COMPILED_FORMAT.hash_layer == 2, "`format-kdf` binds v2 formats only; v1 keeps its stock derivation");
#[cfg(not(feature = "format-kdf"))]
const _: () = assert!(COMPILED_FORMAT.hash_layer == 1, "a v2 build must bind its format into key derivation (`format-kdf`)");

#[must_use]
pub fn format_descriptor(f: &FormatParams) -> [u8; FORMAT_DESCRIPTOR_LEN] {
    let mut b = [0u8; FORMAT_DESCRIPTOR_LEN];
    b[0..12].copy_from_slice(b"PQ1-C10-FMT1");
    let t = f.target_sum.to_be_bytes();
    let head = [f.hash_layer, f.n, f.h, f.d, f.layer_h[0], f.layer_h[1], f.a, f.k, f.w, f.l, t[0], t[1]];
    b[12..24].copy_from_slice(&head);
    b[24..38].copy_from_slice(&f.a7);
    b[38..42].copy_from_slice(&[f.wots_prf, f.fors_prf, f.last_fors, f.r_prf]);
    b
}

/// `sha256(format_descriptor(f))`.
#[must_use]
pub fn format_id(f: &FormatParams) -> [u8; 32] {
    sha256_bytes(&format_descriptor(f))
}

#[must_use]
pub fn compiled_format_id() -> [u8; 32] {
    format_id(&COMPILED_FORMAT)
}

/// Bootstrap master: HMAC-SHA512(key = "pq1-c10-fmt-boot-acc0" ‖ fid, msg = bip39_seed) for account 0, and
/// HMAC-SHA512(key = "pq1-c10-fmt-boot-acct" ‖ fid, msg = bip39_seed ‖ be32(account)) otherwise. Both keys are
/// 53 B (< the 128-B HMAC-SHA512 block, never prehashed) and of EQUAL length, so their zero-padded forms differ
/// for every pair of fids; they also differ from the stock "sphincs-c6-v1" / "sphincs-c6-v1-acct".
#[cfg(feature = "format-kdf")]
#[must_use]
pub fn bootstrap_master_with_format(fid: &[u8; 32], bip39_seed: &[u8; 64], account_index: u32) -> [u8; 64] {
    if account_index == 0 {
        let mut key = [0u8; 53];
        key[0..21].copy_from_slice(b"pq1-c10-fmt-boot-acc0");
        key[21..53].copy_from_slice(fid);
        hmac_sha512_bytes(&key, bip39_seed)
    } else {
        let mut key = [0u8; 53];
        key[0..21].copy_from_slice(b"pq1-c10-fmt-boot-acct");
        key[21..53].copy_from_slice(fid);
        let mut msg = [0u8; 68];
        msg[0..64].copy_from_slice(bip39_seed);
        msg[64..68].copy_from_slice(&account_index.to_be_bytes());
        let m = hmac_sha512_bytes(&key, &msg);
        msg.zeroize();
        m
    }
}

/// Slot master: sha256("pq1-c10-fmt-slot-acc0" ‖ fid ‖ bip39_seed ‖ 0x00) for account 0 (118 B), and
/// sha256("pq1-c10-fmt-slot-acct" ‖ fid ‖ bip39_seed ‖ be32(account)) otherwise (121 B).
#[cfg(feature = "format-kdf")]
#[must_use]
pub fn slot_master_with_format(fid: &[u8; 32], bip39_seed: &[u8; 64], account_index: u32) -> [u8; 32] {
    if account_index == 0 {
        let mut buf = [0u8; 118];
        buf[0..21].copy_from_slice(b"pq1-c10-fmt-slot-acc0");
        buf[21..53].copy_from_slice(fid);
        buf[53..117].copy_from_slice(bip39_seed);
        let out = sha256_bytes(&buf);
        buf.zeroize();
        out
    } else {
        let mut buf = [0u8; 121];
        buf[0..21].copy_from_slice(b"pq1-c10-fmt-slot-acct");
        buf[21..53].copy_from_slice(fid);
        buf[53..117].copy_from_slice(bip39_seed);
        buf[117..121].copy_from_slice(&account_index.to_be_bytes());
        let out = sha256_bytes(&buf);
        buf.zeroize();
        out
    }
}

/// Slot seeds, belt and braces (the slot master is already format-bound): sk_seed = sha256("slot_c10_sk_seed" ‖
/// fid ‖ slot_entropy), pk_seed = mask_n(sha256("slot_c10_pk_seed" ‖ fid ‖ slot_entropy)), 80 B each.
#[cfg(feature = "format-kdf")]
#[must_use]
pub fn slot_seeds_with_format(fid: &[u8; 32], slot_entropy: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut sk_buf = [0u8; 80];
    sk_buf[0..16].copy_from_slice(b"slot_c10_sk_seed");
    sk_buf[16..48].copy_from_slice(fid);
    sk_buf[48..80].copy_from_slice(slot_entropy);
    let sk_seed: [u8; 32] = sha256_bytes(&sk_buf);
    let mut pk_buf = [0u8; 80];
    pk_buf[0..16].copy_from_slice(b"slot_c10_pk_seed");
    pk_buf[16..48].copy_from_slice(fid);
    pk_buf[48..80].copy_from_slice(slot_entropy);
    let pk_digest: [u8; 32] = sha256_bytes(&pk_buf);
    let mut pk_seed = [0u8; 32];
    pk_seed[..16].copy_from_slice(&pk_digest[..16]);
    sk_buf.zeroize();
    pk_buf.zeroize();
    (sk_seed, pk_seed)
}
''')
import os
open(f"{P}/domain/tests/format_kdf.rs", "w").write(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "format_kdf.rs")).read())
print("gate (d): domain copy patched")

# ── 8. round 18: wprf2b inside the DATATYPE-00 asm key loop (hw copy) ─────────────────────────────────────────
# The dt32 block is duplicated: the original keeps not(v2-wprf2b); the copy feeds the 8 words of
# "C10v2-WOTS-PRF2B" ‖ be32(layer) ‖ 0^12 (big-endian DIN words in DATATYPE 00) after sk_seed at both PRF sites.
# layer = bit 27 of the byte-reversed p0 at [sp, #8] (A7 bit 51). First site: r0..r3 are free; per-chain site:
# r5, r6, r7, r10, r11 are free until label 32 reloads them (r0..r3 hold the finished chain's output).
edit("hw/Cargo.toml", [('v2-wprf2b = ["v2-rust-key"]', 'v2-wprf2b = ["v2"]')])
for b in ("bench_v2f", "bench_avg_v2f"):
    edit(f"{b}/Cargo.toml", [('wprf2b = ["sphincs-c10/v2-wprf2b", "pqsigner-hw/v2-wprf2b"]',
                              'wprf2b = ["sphincs-c10/v2-wprf2b", "pqsigner-hw/v2-wprf2b", "pqsigner-hw/v2-rust-key"]\n'
                              'wprf2b-asm = ["sphincs-c10/v2-wprf2b", "pqsigner-hw/v2-wprf2b"]')])
hp = f"{P}/hw/src/hash.rs"
t = open(hp).read()
cfg_dt = ('#[cfg(all(all(feature = "v2-asm-key-ga", not(feature = "v2-rust-key")), feature = "v2-dt32", '
          'not(feature = "v2-prf2"), not(all(feature = "tick-hook", not(feature = "tick-batch")))))]\ncore::arch::global_asm!(')
assert t.count(cfg_dt) == 1, t.count(cfg_dt)
i = t.index(cfg_dt)
j = t.index("\n);\n", i) + len("\n);\n")
blk = t[i:j]
assert blk.count('.section .text.pq1_v2_key_loop') == 1 and blk.count('"ldrd r0, r1, [sp, #8]",') == 1 \
    and blk.count('"ldrd r8, r9, [sp, #8]",') == 1
q = lambda *xs: "".join(f'    "{x}",\n' for x in xs)
B = ("movw {r0}, #0x3076", "movt {r0}, #0x4331", "movw {r1}, #0x574f", "movt {r1}, #0x322d",
     "movw {r2}, #0x2d50", "movt {r2}, #0x5453", "movw {r3}, #0x3242", "movt {r3}, #0x5246")
first = q(*(x.format(r0="r0", r1="r1", r2="r2", r3="r3") for x in B),
          "str r0, [r4, #-8]", "str r1, [r4, #-8]", "str r2, [r4, #-8]", "str r3, [r4, #-8]",
          "ldr r0, [sp, #8]", "ubfx r0, r0, #27, #1", "mov.w r1, #0",
          "str r0, [r4, #-8]", "str r1, [r4, #-8]", "str r1, [r4, #-8]", "str r1, [r4, #-8]")
new = blk.replace(cfg_dt, cfg_dt.replace('not(feature = "v2-prf2"),', 'not(feature = "v2-prf2"), feature = "v2-wprf2b",'))
new = new.replace('    "ldrd r0, r1, [sp, #8]",\n', '    // RESEARCH (round 18): wprf2b block 2 of 2 of the first PRF\'s 64-B first block (sk_seed, then these 8)\n'
                  + first + '    "ldrd r0, r1, [sp, #8]",\n')
old_chain = '''    "str r5, [r4, #-8]",
    "ldrd r8, r9, [sp, #8]",
    "str r12, [r4, #-8]",
    "str r8, [r4, #-8]",
    "str r9, [r4, #-8]",
'''
assert new.count(old_chain) == 1
chain = ('    "str r5, [r4, #-8]",\n    "str r12, [r4, #-8]",\n'
         '    // RESEARCH (round 18): wprf2b, the per-chain PRF\'s 8 constant words (r5, r6, r7, r10, r11 are free here)\n'
         + q(*(x.format(r0="r5", r1="r6", r2="r7", r3="r10") for x in B),
             "str r5, [r4, #-8]", "str r6, [r4, #-8]", "str r7, [r4, #-8]", "str r10, [r4, #-8]",
             "ldr r11, [sp, #8]", "ubfx r11, r11, #27, #1", "mov.w r5, #0",
             "str r11, [r4, #-8]", "str r5, [r4, #-8]", "str r5, [r4, #-8]", "str r5, [r4, #-8]")
         + '    "ldrd r8, r9, [sp, #8]",\n    "str r8, [r4, #-8]",\n    "str r9, [r4, #-8]",\n')
new = new.replace(old_chain, chain)
orig = blk.replace(cfg_dt, cfg_dt.replace('not(feature = "v2-prf2"),', 'not(feature = "v2-prf2"), not(feature = "v2-wprf2b"),'))
# appended at the END of hash.rs: no line above moves, so no panic Location (file:line) in other builds changes
assert orig.count("\n") == blk.count("\n")
t = (t[:i] + orig + t[j:] + "\n// RESEARCH (round 18): the dt32 key loop with the two-block WOTS PRF (`v2-wprf2b`).\n" + new
     + '''#[cfg(all(feature = "v2-wprf2b", feature = "v2-asm-key-ga", not(feature = "v2-dt32"), not(feature = "v2-rust-key")))]
compile_error!("`v2-wprf2b` has an asm key loop only for `v2-dt32` (or use `v2-rust-key`)");
''')
open(hp, "w").write(t)
print("round 18: wprf2b dt32 key loop added")

# ── 9. round 18: w4l65 at full speed — the 32-bit T_65 feed and the asm w = 4 search (hw copy) ───────────────
# Both new wrappers are appended at the END of hash.rs (no other line moves); the originals step aside through a
# same-line cfg change. Generated by proto_w4l65/gen_v2tl.py (T_43 generalized; 178 reproduces gen_v2t43.py) and
# gen_v2search_w4.py (gen_v2search_dt.py with a 2-bit digit sum).
import subprocess
here = os.path.dirname(os.path.abspath(__file__))
gen = lambda *a: subprocess.run(["python3", *a], capture_output=True, text=True, check=True).stdout
assert gen(os.path.join(here, "gen_v2tl.py"), "178", "pq1_v2_t43") == gen(os.path.join(here, "..", "gen_v2t43.py"))
t65 = gen(os.path.join(here, "gen_v2tl.py"), "266", "pq1_v2_t65")
sw4 = gen(os.path.join(here, "gen_v2search_w4.py"))
W4T = 'all(feature = "v2-w4-asm", feature = "v2-asm-t43", not(feature = "tick-hook"))'
W4S = ('all(feature = "v2-w4-asm", feature = "v2-asm-search", feature = "v2-dt32", '
       'not(all(feature = "tick-hook", not(feature = "tick-batch"))))')
edit("hw/src/hash.rs", [
    ('''#[cfg(feature = "v2")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_wots_pk16(''', f'''#[cfg(all(feature = "v2", not({W4T})))]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_wots_pk16('''),
    ('''#[cfg(feature = "v2")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_search43_target(''', f'''#[cfg(all(feature = "v2", not({W4S})))]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_search43_target('''),
])
open(f"{P}/hw/src/hash.rs", "a").write(f'''
// ---- RESEARCH PROTOTYPE (round 18, proto_w4l65 section 9): w4l65's T_65 feed and w = 4 asm search ----

/// w4l65 (`v2-asm-t43`): `pqsigner_v2_wots_pk16` with the 32-bit T_65 feed (266 words, 17 blocks).
#[cfg({W4T})]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_wots_pk16(
    sk_seed: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, low24: u32, k0: u32, k1: u32, steps: u32,
    out: *mut u8,
) {{
    let mut buf = core::mem::MaybeUninit::<[u32; V2_PK_WORDS]>::uninit();
    let b = buf.as_mut_ptr().cast::<u32>();
    // SAFETY: `b` names V2_PK_WORDS writable words: 0..6 written here, 6.. by the chains (65 x 4), so the
    // whole preimage is initialized before the feed reads it; caller contract for the rest.
    unsafe {{
        let s = v2_load4(seed);
        for (i, w) in s.iter().enumerate() {{
            b.add(i).write(*w);
        }}
        b.add(4).write(k0);
        b.add(5).write(k1);
        pqsigner_v2_wots_chains16(sk_seed, p0, p1, seed, a0, low24, steps, b.add(6).cast::<u8>());
        pq1_v2_t65(b.cast_const(), out);
    }}
}}

#[cfg({W4T})]
core::arch::global_asm!(
{t65}
    hb_lo = const HASH_BASE & 0xFFFF,
    hb_hi = const HASH_BASE >> 16,
    fault = sym hash_engine_fault,
);

#[cfg({W4T})]
extern "C" {{
    /// The T_65 feed above: `src` names 266 readable, 4-aligned words, `out` 16 writable bytes.
    fn pq1_v2_t65(src: *const u32, out: *mut u8);
}}

/// w4l65 (`v2-asm-search` + `v2-dt32`): the count search on `pq1_v2_search_w4` (the dt32 search, w = 4 sum).
#[cfg({W4S})]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_search43_target(sm: *const u8, a0: u32, a1: u32, start: u32, n: u32, target: u32, out: *mut u8) -> u32 {{
    v2_entry();
    let end = start.wrapping_add(n);
    if n == 0 {{
        return end;
    }}
    // SAFETY (issue): caller contract, `sm` names 32 readable bytes.
    let issue = |count: u32| unsafe {{
        v2_begin();
        feed_words(sm, 8);
        write_word(count.swap_bytes());
        write_word(a0);
        write_word(a1);
        REG.str_.write(V2_NBLW | STR_DCAL);
    }};
    // SAFETY: caller contract, `sm` names 32 readable bytes.
    let smw: [u32; 8] = core::array::from_fn(|i| unsafe {{ sm.cast::<u32>().add(i).read_unaligned() }});
    let mut ctx = [0u32; 15];
    for (k, w) in smw.iter().enumerate() {{
        ctx[k] = w.swap_bytes();
    }}
    ctx[8] = a0.swap_bytes();
    ctx[9] = a1.swap_bytes();
    ctx[10] = start;
    ctx[11] = end;
    ctx[12] = target;
    // SAFETY: the function's contract (the context above; it issues try `start`); the engine is idle and STR
    // holds NBLW 24 (`v2_entry`).
    unsafe {{ pq1_v2_search_w4(ctx.as_mut_ptr()) }};
    let (c, flag) = (ctx[13], ctx[14]);
    if flag == 0 {{
        return end;
    }}
    let mut d = [0u32; 8];
    if flag == 1 {{
        v2_collect(&mut d);
    }}
    issue(c);
    v2_collect(&mut d);
    // SAFETY: `out` names 32 writable bytes.
    unsafe {{ core::ptr::copy_nonoverlapping(d.as_ptr().cast::<u8>(), out, 32) }};
    c
}}

#[cfg({W4S})]
core::arch::global_asm!(
{sw4}
    hb_lo = const HASH_BASE & 0xFFFF,
    hb_hi = const HASH_BASE >> 16,
    fault = sym hash_engine_fault,
);

#[cfg({W4S})]
extern "C" {{
    /// The w = 4 dt32 search above (the `pq1_v2_search_dt` context layout).
    fn pq1_v2_search_w4(ctx: *mut u32);
}}
''')
edit("hw/Cargo.toml", [('v2-wprf2b = ["v2"]', 'v2-wprf2b = ["v2"]\n# round 18: w4l65 at full speed (T_65 feed, w = 4 asm search)\nv2-w4-asm = ["v2-w4l65"]')])
for bb in ("bench_v2f", "bench_avg_v2f"):
    edit(f"{bb}/Cargo.toml", [('wprf2b-asm = ["sphincs-c10/v2-wprf2b", "pqsigner-hw/v2-wprf2b"]',
                               'wprf2b-asm = ["sphincs-c10/v2-wprf2b", "pqsigner-hw/v2-wprf2b"]\n'
                               'w4l65-asm = ["w4l65", "pqsigner-hw/v2-w4-asm"]\n'
                               'w4l65-wprf2b = ["w4l65-asm", "wprf2b-asm"]')])
edit("host_v2/Cargo.toml", [('wprf2b = ["sphincs-c10/v2-wprf2b"]', 'wprf2b = ["sphincs-c10/v2-wprf2b"]\nw4l65-wprf2b = ["w4l65", "wprf2b"]')])
edit("sphincs-c10/tests/v2_kat.rs", [('''        assert!(!cfg!(feature = "v2-wprf2b"), "no KAT set for w4l65 + wprf2b");''',
                                     '''        if cfg!(feature = "v2-wprf2b") {
            return "w4l65-wprf2b";
        }''')])
print("round 18: T_65 feed and w = 4 asm search added")

# ── 10. round 18: assurance copies for the two candidates (v2 0.3 + wprf2b = cand-d03w; w4l65 + wprf2b = cand-w4w)
# (a) the residue suite (bench_v2drv) on the hw copy, its patterns built from the candidate's own PRF, chain count,
#     ci layout and chain length; (b) the FI chain mirror (bench_chain) on the fused copies, with two positive
#     controls; (c) the checkct timing proof on the sphincs copy (fisher_yates control, fors_secret, th, and a new
#     wots_secret driver), one checkct workspace per candidate.
edit("bench_v2drv/Cargo.toml", [('path = "../../../hw"', 'path = "../hw"'),
                                ('oneshot-speed = ["pqsigner-hw/oneshot-speed"]',
                                 'oneshot-speed = ["pqsigner-hw/oneshot-speed"]\n# round 18 candidates\n'
                                 'cand-d03w = ["pqsigner-hw/v2-wprf2b"]\ncand-w4w = ["pqsigner-hw/v2-w4-asm", "pqsigner-hw/v2-wprf2b"]')])
edit("bench_v2drv/src/lib.rs", [
    ('const CI_SHIFT: u32 = KP_SHIFT - 6;', '''#[cfg(not(feature = "cand-w4w"))]
const CI_BITS: u32 = 6;
#[cfg(feature = "cand-w4w")]
const CI_BITS: u32 = 7;
const CI_SHIFT: u32 = KP_SHIFT - CI_BITS;
/// round 18: the candidate's WOTS chain count and chain length (W - 1).
#[cfg(not(feature = "cand-w4w"))]
const RL: u64 = 43;
#[cfg(feature = "cand-w4w")]
const RL: u64 = 65;
#[cfg(not(feature = "cand-w4w"))]
const RSTEPS: u32 = 7;
#[cfg(feature = "cand-w4w")]
const RSTEPS: u32 = 3;'''),
    ('kp < 1 << KP_BITS && ci < 1 << 6 && cp < 16', 'kp < 1 << KP_BITS && ci < 1 << CI_BITS && cp < 16'),
    ('''fn prf(sk: &[u8; 32], a: u64) -> [u8; 16] {
''', '''fn prf(sk: &[u8; 32], a: u64) -> [u8; 16] {
    // round 18 candidates: the WOTS PRF (type 5) is two blocks, sk_seed || "C10v2-WOTS-PRF2B" || be32(layer) || 0^12 || A7
    #[cfg(any(feature = "cand-d03w", feature = "cand-w4w"))]
    if a >> 52 == 5 {
        let mut blk = [0u8; 32];
        blk[..16].copy_from_slice(b"C10v2-WOTS-PRF2B");
        blk[16..20].copy_from_slice(&(((a >> 51) & 1) as u32).to_be_bytes());
        return sha(&[sk, &blk, &a7b(a)])[..16].try_into().unwrap();
    }
'''),
    ('''            for ci in 0..43u64 {
                let mut v = prf(&sk, a7(5, layer, tree, kp, ci, 0, 0));
                res_add(&v);
                if ci < 8 {
                    for p in 0..6u64 {''', '''            for ci in 0..RL {
                let mut v = prf(&sk, a7(5, layer, tree, kp, ci, 0, 0));
                res_add(&v);
                if ci < 8 {
                    for p in 0..u64::from(RSTEPS - 1) {'''),
    ('0 => pqsigner_v2_wots_chains16(sk, w[0], w[1], s, w[2], w[3], 7, o),',
     '0 => pqsigner_v2_wots_chains16(sk, w[0], w[1], s, w[2], w[3], RSTEPS, o),'),
    ('1 => pqsigner_v2_wots_pk16(sk, w[0], w[1], s, w[2], w[3], w[4], w[5], 7, o),',
     '1 => pqsigner_v2_wots_pk16(sk, w[0], w[1], s, w[2], w[3], w[4], w[5], RSTEPS, o),'),
    ('static mut RO: [u8; 688] = [0; 688];', 'static mut RO: [u8; 1040] = [0; 1040];'),
])
t = open(f"{P}/bench_v2drv/src/lib.rs").read()
t = t.replace('include!("../../residue.rs");', 'include!("../../../../residue.rs");').replace('include!("../../inputs.rs");', 'include!("../../../../inputs.rs");')
open(f"{P}/bench_v2drv/src/lib.rs", "w").write(t)

V2HW = ('"pqsigner-hw/v2", "pqsigner-hw/v2-asm-chain", "pqsigner-hw/v2-asm-key-ga", "pqsigner-hw/v2-dt32", '
        '"pqsigner-hw/v2-asm-search", "pqsigner-hw/v2-asm-fors", "pqsigner-hw/v2-asm-fors-ga", "pqsigner-hw/v2-asm-t43", '
        '"pqsigner-hw/hra-ldm"')
edit("bench_chain/Cargo.toml", [
    ('path = "../../../sphincs-c10"', 'path = "../sphincs-c10"'), ('path = "../../../hw"', 'path = "../hw"'),
    ('path = "../../../pqsigner-fi"', 'path = "../../../../../pqsigner-fi"'),
    ('residue-control = ["residue"]', 'residue-control = ["residue"]\n# round 18 candidates on the fused one-block driver, and the FI positive controls\n'
     f'v2 = ["sphincs-c10/v2-fused", {V2HW}]\n'
     'cand-d03w = ["v2", "sphincs-c10/v2-wprf2b", "pqsigner-hw/v2-wprf2b"]\n'
     'cand-w4w = ["v2", "sphincs-c10/v2-w4l65", "sphincs-c10/v2-wprf2b", "pqsigner-hw/v2-w4-asm", "pqsigner-hw/v2-wprf2b"]\n'
     'fi-control-cmp = []\nfi-control-verify = []'),
])
t = open(f"{P}/bench_chain/src/lib.rs").read()
t = t.replace('include!("../../residue.rs");', 'include!("../../../../residue.rs");').replace('include!("../../inputs.rs");', 'include!("../../../../inputs.rs");')
old = '''    if !bool::from(sig_a[..].ct_eq(&sig_b[..])) {'''
assert t.count(old) == 1
t = t.replace(old, '''    // round 18 FI positive controls: the two computations differ (the compare must refuse), or both carry the same
    // corruption (the compare passes; the verify-before-release must refuse). Either way: no signature released.
    #[cfg(feature = "fi-control-cmp")]
    let sig_b = {
        let mut s = sig_b;
        s[SIGNATURE_LEN - 1] ^= 1;
        s
    };
    #[cfg(feature = "fi-control-verify")]
    let (sig_a, sig_b) = {
        let (mut a, mut b) = (sig_a, sig_b);
        a[2336 + 5] ^= 1;
        b[2336 + 5] ^= 1;
        (a, b)
    };
''' + old)
open(f"{P}/bench_chain/src/lib.rs", "w").write(t)

# (c) the checkct workspaces: driver (fisher_yates, INSECURE by design), driver_fors, driver_th, driver_wprf (new)
import shutil
def relfix(path, orig_dir, new_dir):
    s = open(path).read()
    for key in ("checkct_macros = { path = \"", "sphincs-c10 = { path = \""):
        while key in s:
            i = s.index(key) + len(key); j = s.index('"', i)
            rel = s[i:j]
            tgt = os.path.normpath(os.path.join(orig_dir, rel))
            if key.startswith("sphincs"):
                tgt = os.path.join(P, "sphincs-c10")
            s = s[:i - len(key)] + key.replace(" = { path = \"", "=@@{path=\"") + os.path.relpath(tgt, new_dir) + s[j:]
        s = s.replace(key.replace(" = { path = \"", "=@@{path=\""), key)
    open(path, "w").write(s)
SCA = os.path.normpath(os.path.join(here, "..", "..", "..", "tools", "sca", "checkct"))
for cand, feats in (("d03w", '"sim-internals", "v2", "v2-wprf2b"'), ("w4w", '"sim-internals", "v2", "v2-w4l65", "v2-wprf2b"')):
    dst = f"{P}/sca-{cand}/checkct"
    os.makedirs(dst, exist_ok=True)
    for d in ("driver", "driver_fors", "driver_th"):
        shutil.copytree(os.path.join(SCA, d), os.path.join(dst, d), ignore=shutil.ignore_patterns("target"))
    shutil.copytree(os.path.join(SCA, "driver_fors"), os.path.join(dst, "driver_wprf"), ignore=shutil.ignore_patterns("target"))
    for f in ("Cargo.lock", "rust-toolchain.toml"):
        shutil.copy(os.path.join(SCA, f), os.path.join(dst, f))
    shutil.copytree(os.path.join(SCA, ".cargo"), os.path.join(dst, ".cargo"))   # thumbv8m target + build-std
    ws = open(os.path.join(SCA, "Cargo.toml")).read()
    ws = ws.replace('members = ["driver", "driver_kdf", "driver_fors", "driver_th", "driver_saes", "driver_ct_eq"]',
                    'members = ["driver", "driver_fors", "driver_th", "driver_wprf"]')
    assert 'driver_wprf' in ws
    open(os.path.join(dst, "Cargo.toml"), "w").write(ws)
    for d in ("driver", "driver_fors", "driver_th", "driver_wprf"):
        ct = os.path.join(dst, d, "Cargo.toml")
        relfix(ct, os.path.join(SCA, d if d != "driver_wprf" else "driver_fors"), os.path.join(dst, d))
        s = open(ct).read()
        s = s.replace('features = ["sim-internals"]', f'features = [{feats}]')
        if d == "driver":
            s = s.replace('sphincs-c10 = { path = "' , 'sphincs-c10 = { features = [' + feats.replace('"sim-internals", ', '') + '], path = "')
        if d == "driver_wprf":
            s = s.replace('name = "driver_fors"', 'name = "driver_wprf"')
        open(ct, "w").write(s)
    drv = os.path.join(dst, "driver_wprf", "src", "driver.rs")
    open(drv, "w").write("""
use crate::rng::{CryptoRng, PrivateRng, PublicRng, RngCore};
use checkct_macros::checkct;
// round 18: CT proof of the candidate's WOTS secret PRF (wprf2b: sha256(sk_seed || tag || layer || 0^12 || A7)):
// the secret sk_seed must not reach a branch or an address; the address fields are public.
#[checkct]
pub fn checkct() {
    use sphincs_c10::sim_internals::wots_secret;
    let mut sk_seed = [0u8; 32];
    PrivateRng.fill_bytes(&mut sk_seed);  // SECRET
    let mut pb = [0u8; 4];
    PublicRng.fill_bytes(&mut pb);        // PUBLIC address fields
    let (layer, kp, ci) = (u32::from(pb[0] & 1), u32::from(pb[1]), u32::from(pb[2] & 31));
    let s = wots_secret(&sk_seed, layer, 7, kp, ci);
    core::hint::black_box(s);
}
""")
print("round 18: assurance copies (residue, FI chain, checkct) prepared")
print("applied")
