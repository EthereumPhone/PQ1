#!/usr/bin/env python3
"""apply.py <proto dir> — RESEARCH PROTOTYPE (round 19): the d >= 3 insight point h18 d3 a11 k13 w8 l46 T209
(c10v2_ref.py --variant d3l46) as `v2-d3l46` on a FRESH copy of sphincs-c10 (generic v2 path only), with copies of
the host golden generator and the generic kit bench. A separate tree from proto_w4l65 so no round-17/18 copy or
ELF moves. Every edit is an exact replacement asserted to occur once."""
import sys

P = sys.argv[1]


def edit(path, pairs):
    p = f"{P}/{path}"
    s = open(p).read()
    for old, new in pairs:
        assert s.count(old) == 1, (path, old[:70], s.count(old))
        s = s.replace(old, new)
    open(p, "w").write(s)


edit("sphincs-c10/Cargo.toml", [
    ('v2-split810 = ["v2"]\n', 'v2-split810 = ["v2"]\n# RESEARCH PROTOTYPE (round 19, proto_d3): h18 d3 (6, 6, 6) a11 k13 w8 l46 T209; A7 with a 2-bit layer.\nv2-d3l46 = ["v2"]\n'),
    ("edition.workspace = true", 'edition = "2021"'),
    ('zeroize = { workspace = true, features = ["zeroize_derive"] }', 'zeroize = { version = "1.8", default-features = false, features = ["zeroize_derive"] }'),
    ("[lints]\nworkspace = true\n", ""), ("hex = { workspace = true }", 'hex = "0.4"')])
open(f"{P}/sphincs-c10/Cargo.toml", "a").write("\n[workspace]\n")
edit("sphincs-c10/src/params.rs", [
    ("pub const D: usize = 2;", '#[cfg(not(feature = "v2-d3l46"))]\npub const D: usize = 2;\n#[cfg(feature = "v2-d3l46")]\npub const D: usize = 3;'),
    ("const _: () = assert!(layer_h(0) + layer_h(1) == H && layer_h(0) <= MAX_LAYER_H && layer_h(1) <= MAX_LAYER_H);",
     '#[cfg(not(feature = "v2-d3l46"))]\nconst _: () = assert!(layer_h(0) + layer_h(1) == H && layer_h(0) <= MAX_LAYER_H && layer_h(1) <= MAX_LAYER_H);\n'
     '#[cfg(feature = "v2-d3l46")]\nconst _: () = assert!(3 * layer_h(0) == H && layer_h(0) <= MAX_LAYER_H);'),
    ("pub const L: usize = 43;", '#[cfg(not(feature = "v2-d3l46"))]\npub const L: usize = 43;\n#[cfg(feature = "v2-d3l46")]\npub const L: usize = 46;'),
    ('#[cfg(not(feature = "v2-ts200"))]\npub const TARGET_SUM: usize = 205;',
     '#[cfg(not(any(feature = "v2-ts200", feature = "v2-d3l46")))]\npub const TARGET_SUM: usize = 205;\n#[cfg(feature = "v2-d3l46")]\npub const TARGET_SUM: usize = 209;'),
    ("const _: () = assert!(SIG_HT_LAYER == 836);\nconst _: () = assert!(SIGNATURE_LEN == 4008);",
     'const _: () = assert!(SIG_HT_LAYER == 836);\n#[cfg(not(feature = "v2-d3l46"))]\nconst _: () = assert!(SIGNATURE_LEN == 4008);\n'
     '#[cfg(feature = "v2-d3l46")]\nconst _: () = assert!(SIGNATURE_LEN == 4844);'),
])
edit("sphincs-c10/src/wots.rs", [
    ('''pub(crate) fn digit_sum(digest: &[u8; 32]) -> usize {
    let mut sum: usize = 0;''', '''#[cfg(not(feature = "v2-d3l46"))]
pub(crate) fn digit_sum(digest: &[u8; 32]) -> usize {
    let mut sum: usize = 0;'''),
    ('''const _: () = assert!(L == 43 && LOG_W == 3 && W_MASK == 7 && L * LOG_W == 5 * 24 + 9);''',
     '''#[cfg(not(feature = "v2-d3l46"))]
const _: () = assert!(L == 43 && LOG_W == 3 && W_MASK == 7 && L * LOG_W == 5 * 24 + 9);
/// RESEARCH PROTOTYPE `v2-d3l46`: the plain sum of the 46 extracted digits.
#[cfg(feature = "v2-d3l46")]
pub(crate) fn digit_sum(digest: &[u8; 32]) -> usize {
    let d = extract_digits(digest);
    let mut sum = 0;
    for i in 0..L {
        sum += d[i] as usize;
    }
    sum
}'''),
])
edit("sphincs-c10/src/hash.rs", [("pub const TH_MULTI_MAX: usize = 43;",
                                  '#[cfg(not(feature = "v2-d3l46"))]\npub const TH_MULTI_MAX: usize = 43;\n#[cfg(feature = "v2-d3l46")]\npub const TH_MULTI_MAX: usize = 46;')])
edit("sphincs-c10/src/v2hash.rs", [
    ("    assert!(ty < 16 && layer < 2 && tree < (1 << 18) && kp < (1 << KP_BITS));",
     "    assert!(ty < 16 && layer < (1 << LAYER_BITS) && tree < (1 << 18) && kp < (1 << KP_BITS));"),
    ("    ty << 52 | layer << 51 | tree << 33 | kp << KP_SHIFT | ci << CI_SHIFT | cp << CP_SHIFT | ha << 1",
     "    ty << 52 | layer << LAYER_SHIFT | tree << TREE_SHIFT | kp << KP_SHIFT | ci << CI_SHIFT | cp << CP_SHIFT | ha << 1"),
    ('#[cfg(not(feature = "v2-split810"))]\nconst KP_BITS: u32 = 9;',
     '#[cfg(not(any(feature = "v2-split810", feature = "v2-d3l46")))]\nconst KP_BITS: u32 = 9;\n'
     '/// RESEARCH PROTOTYPE `v2-d3l46`: layer 2 bits @50, tree 18 @32, kp 8 bits @24 (kp < 64 or < 13), ci @18.\n'
     '#[cfg(feature = "v2-d3l46")]\nconst KP_BITS: u32 = 8;\n'
     '#[cfg(not(feature = "v2-d3l46"))]\nconst LAYER_BITS: u32 = 1;\n#[cfg(feature = "v2-d3l46")]\nconst LAYER_BITS: u32 = 2;\n'
     'const LAYER_SHIFT: u32 = 52 - LAYER_BITS;\nconst TREE_SHIFT: u32 = LAYER_SHIFT - 18;'),
    ("const KP_SHIFT: u32 = 33 - KP_BITS;", "const KP_SHIFT: u32 = TREE_SHIFT - KP_BITS;"),
])
edit("sphincs-c10/src/lib.rs", [
    ('''#[cfg(all(feature = "near-miss-gen", feature = "v2-split810"))]''',
     '''#[cfg(all(feature = "v2-d3l46", any(feature = "v2-fused", feature = "near-miss-gen", feature = "v2-split810", feature = "v2-ts200", feature = "top-cache")))]
compile_error!("the `v2-d3l46` prototype is generic-path only (no fused driver, near-miss-gen, split810, ts200, top-cache)");
#[cfg(all(feature = "near-miss-gen", feature = "v2-split810"))]'''),
    (") -> (u32, [u8; 32], [u8; 43]) {", ") -> (u32, [u8; 32], [u8; crate::params::L]) {"),
])
edit("sphincs-c10/tests/v2_kat.rs", [('''fn tag() -> &'static str {
    match''', '''fn tag() -> &'static str {
    if cfg!(feature = "v2-d3l46") {
        return "d3l46";
    }
    match'''), ('{}/../research/c10-autoresearch/c10v2/', '{}/../../../c10v2/')])
# host golden generator and generic kit bench, pointed at the copy
edit("host_v2/Cargo.toml", [('path = "../../../sphincs-c10"', 'path = "../sphincs-c10"'),
                            ('split810 = ["sphincs-c10/v2-split810"]', 'split810 = ["sphincs-c10/v2-split810"]\nd3l46 = ["sphincs-c10/v2-d3l46"]')])
edit("host_v2/src/main.rs", [('include!("../../inputs.rs");', 'include!("../../../../inputs.rs");'),
                             ('include!("../../diff_cases.rs");', 'include!("../../../../diff_cases.rs");'),
                             ('m: &[u8; 32], sh: &[u8; 32]) -> [u8; 4008] {', 'm: &[u8; 32], sh: &[u8; 32]) -> [u8; sphincs_c10::params::SIGNATURE_LEN] {')])
edit("bench_v2/Cargo.toml", [('path = "../../../sphincs-c10"', 'path = "../sphincs-c10"'), ('path = "../../../hw"', 'path = "../../../../../hw"'),
                             ('hra-ldm = ["pqsigner-hw/hra-ldm"]', 'hra-ldm = ["pqsigner-hw/hra-ldm"]\nd3l46 = ["sphincs-c10/v2-d3l46"]')])
edit("bench_v2/src/lib.rs", [('include!("../../inputs.rs");', 'include!("../../../../inputs.rs");')])
edit("run_flash_sig.sh", [("read_memory \\$a 32 1002]", "read_memory \\$a 32 ${SIGW:-1002}]")])
edit("evaluate_sig.py", [("log, golden = sys.argv[1], open(sys.argv[2], 'rb').read()\n",
                          "log, golden = sys.argv[1], open(sys.argv[2], 'rb').read()\nSL = int(sys.argv[3]) if len(sys.argv) > 3 else 4008\n"),
                         ("[])[:4008]\nb1", "[])[:SL]\nb1"), ("s1 or [])[:4008]", "s1 or [])[:SL]"),
                         ("golden[16:16 + 4008]", "golden[16:16 + SL]"), ("golden[16 + 4008:]", "golden[16 + SL:]")])
print("applied (proto_d3)")
