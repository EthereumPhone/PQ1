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
print("applied")
