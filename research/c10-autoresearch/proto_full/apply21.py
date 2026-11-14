#!/usr/bin/env python3
"""apply21.py <proto dir> — round 21, on top of proto_full/apply.py (target/proto-full): the no-prf2 candidate
v2 0.3 + ts200 + split810 + top cache + wprf2b + fmtKDF as a first-class build. Test-, feature- and copy-only
edits: no line of code that an existing round-20 ELF is built from moves (checked by mk21.sh, which rebuilds a
sample of the round-20 ELFs and compares their hashes)."""
import os, shutil, sys

P = sys.argv[1]
MARK = f"{P}/.apply21-done"
assert not os.path.exists(MARK), "apply21 already applied: rerun proto_full/mk.sh first"


def edit(path, pairs):
    p = f"{P}/{path}"
    s = open(p).read()
    for old, new in pairs:
        assert s.count(old) == 1, (path, old[:80], s.count(old))
        s = s.replace(old, new)
    open(p, "w").write(s)


TAG = "ts200-split810-wprf2b"
# the Rust KAT test picks the candidate's KAT set (before the wprf2b-only arm, which would otherwise match)
edit("sphincs-c10/tests/v2_kat.rs", [('''    if cfg!(feature = "v2-wprf2b") {
        return "wprf2b";
    }''', f'''    if cfg!(all(feature = "v2-wprf2b", feature = "v2-ts200", feature = "v2-split810", not(feature = "v2-prf2"))) {{
        return "{TAG}"; // round 21: the no-prf2 candidate
    }}
    if cfg!(feature = "v2-wprf2b") {{
        return "wprf2b";
    }}''')])
# the format tests: its descriptor, and the build arm
edit("domain/tests/format_kdf.rs", [
    ('''        ("all3-wprf2b", FormatParams { target_sum: 200, wots_prf: 4, fors_prf: 3, layer_h: [8, 10], a7: A7_810, ..d }),
    ]''', f'''        ("all3-wprf2b", FormatParams {{ target_sum: 200, wots_prf: 4, fors_prf: 3, layer_h: [8, 10], a7: A7_810, ..d }}),
        // round 21: the no-prf2 candidate (ts200 + split810 + the unpaired two-block WOTS PRF; FORS one-block)
        ("{TAG}", FormatParams {{ target_sum: 200, wots_prf: 2, layer_h: [8, 10], a7: A7_810, ..d }}),
    ]'''),
    ('''        (false, true, true, true, true, false) => "all3-wprf2b",''',
     f'''        (false, true, true, true, true, false) => "all3-wprf2b",
        (false, true, true, false, true, false) => "{TAG}",'''),
])
# the residue suite: the candidate's patterns = wprf2b's two-block PRF (cand-d03w's model) on split810's layout
edit("bench_v2drv/Cargo.toml", [('cand-full = ["prf2", "split810", "pqsigner-hw/v2-wprf2b"]',
                                 'cand-full = ["prf2", "split810", "pqsigner-hw/v2-wprf2b"]\n'
                                 'cand-np2 = ["split810", "pqsigner-hw/v2-wprf2b"]')])
edit("bench_v2drv/src/lib.rs", [('''    #[cfg(any(feature = "cand-d03w", feature = "cand-w4w"))]
    if a >> 52 == 5 {''', '''    #[cfg(any(feature = "cand-d03w", feature = "cand-w4w", feature = "cand-np2"))]
    if a >> 52 == 5 {''')])
# checkct: driver_wprf = the unpaired two-block wots_secret, driver_fors = the one-block fors_secret
src, dst = f"{P}/sca-d03w/checkct", f"{P}/sca-np2/checkct"
shutil.copytree(src, dst, ignore=shutil.ignore_patterns("target"))
for d in ("driver", "driver_fors", "driver_th", "driver_wprf"):
    ct = os.path.join(dst, d, "Cargo.toml")
    s = open(ct).read()
    assert s.count('"v2", "v2-wprf2b"') == 1, ct
    open(ct, "w").write(s.replace('"v2", "v2-wprf2b"', '"v2", "v2-ts200", "v2-split810", "v2-wprf2b"'))
open(MARK, "w").write("round 21\n")
print("applied (proto_full round 21)")
