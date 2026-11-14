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

/// Bootstrap master: HMAC-SHA512(key = "pq1-c10-fmt-boot" ‖ fid, msg = bip39_seed) for account 0, and
/// HMAC-SHA512(key = "pq1-c10-fmt-boot-acct" ‖ fid, msg = bip39_seed ‖ be32(account)) otherwise. The keys differ
/// from the stock "sphincs-c6-v1" / "sphincs-c6-v1-acct" and from each other for every fid.
#[cfg(feature = "format-kdf")]
#[must_use]
pub fn bootstrap_master_with_format(fid: &[u8; 32], bip39_seed: &[u8; 64], account_index: u32) -> [u8; 64] {
    if account_index == 0 {
        let mut key = [0u8; 48];
        key[0..16].copy_from_slice(b"pq1-c10-fmt-boot");
        key[16..48].copy_from_slice(fid);
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

/// Slot master: sha256("pq1-c10-fmt-slot" ‖ fid ‖ bip39_seed ‖ 0x00) for account 0 (113 B), and
/// sha256("pq1-c10-fmt-slot-acct" ‖ fid ‖ bip39_seed ‖ be32(account)) otherwise (121 B).
#[cfg(feature = "format-kdf")]
#[must_use]
pub fn slot_master_with_format(fid: &[u8; 32], bip39_seed: &[u8; 64], account_index: u32) -> [u8; 32] {
    if account_index == 0 {
        let mut buf = [0u8; 113];
        buf[0..16].copy_from_slice(b"pq1-c10-fmt-slot");
        buf[16..48].copy_from_slice(fid);
        buf[48..112].copy_from_slice(bip39_seed);
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
print("applied")
