#!/usr/bin/env bash
# mk_plants.sh — round 21: the planted top-cache fault controls (#1148), in RAM on the kit. A SEPARATE copy,
# target/proto-cf, of the round-21 tree's sphincs-c10 / hw / bench_chain (no measured copy moves), with:
#  - sphincs-c10/src/topcache.rs: `plant_for_test` APPENDED (corrupt one stored height-4 node after keygen, chosen
#    relative to the top leaf chain 0's signature will use; optionally recompute the cache digest), and a feature
#    `plant-noroot` that compiles out ONLY the in-sign root assert (the "what remains" control);
#  - bench_chain: features plant-*, one chain (NMSG = 1), the plant after keygen, and a panic handler that records
#    the panic location (out 23 = line, out 24 = 1 if in topcache.rs) before the usual halt 0xF1.
# Builds out/r21-plant-<cand>-<plant>.elf for cand in full, np2 and plant in none, digest, own, b0, b2, b5, noroot.
set -euo pipefail
D="$(cd "$(dirname "$0")/.." && pwd)"; P="$D/target/proto-full"; Q="$D/target/proto-cf"
test -f "$P/.apply21-done" || { echo "run proto_full/mk.sh and mk21.sh first"; exit 2; }
rm -rf "$Q"; mkdir -p "$Q"
for c in sphincs-c10 hw bench_chain; do rsync -a --exclude target "$P/$c/" "$Q/$c/"; done
python3 - "$Q" <<'PY'
import sys
Q = sys.argv[1]
def edit(path, pairs, append=None):
    p = f"{Q}/{path}"; s = open(p).read()
    for old, new in pairs:
        assert s.count(old) == 1, (path, old[:60], s.count(old)); s = s.replace(old, new)
    if append: s += append
    open(p, "w").write(s)
edit("sphincs-c10/Cargo.toml", [("[features]\n", "[features]\n# round 21 plant copy only: drop the in-sign root assert\nplant-noroot = []\n")])
edit("sphincs-c10/src/topcache.rs", [('''        assert!(&level[0] == pk_root, "top cache: root is not pk_root");''',
     '''        #[cfg(not(feature = "plant-noroot"))]
        assert!(&level[0] == pk_root, "top cache: root is not pk_root");''')], append='''
// RESEARCH (round 21, the plant copy target/proto-cf only; never in a measured copy): the #1148 must-refuse plants.
/// Corrupt one stored height-`HC` node after keygen, relative to the top leaf the signature of (`message`,
/// `opt_rand`) will use: `b = None` is the target's own node; `Some(b)` the node whose index differs from the
/// target's in bit `b`, so its fault reaches the auth path at height `HC + b` (b = log2(NC) - 1: the node just
/// under pk_root). `consistent` recomputes the cache digest after the corruption. Returns `(i0 << 8) | j`.
#[doc(hidden)]
pub fn plant_for_test(
    cache: &mut TopCache, sk: &crate::SigningKey, message: &[u8; 32], opt_rand: Option<&[u8; N]>, b: Option<u32>,
    corrupt: bool, consistent: bool,
) -> u32 {
    let (_r, d) = crate::fors::grind_r(&sk.sk_seed, &sk.pk_seed, &sk.pk_root, message, opt_rand);
    let top_leaf = crate::fors::extract_ht_index(&d) >> layer_h(0);
    let i0 = (top_leaf as usize) >> HC;
    let j = match b {
        None => i0,
        Some(b) => i0 ^ (1usize << b),
    };
    if corrupt {
        cache.nodes[j][0] ^= 1;
        if consistent {
            cache.digest = TopCache::digest_of(&cache.nodes);
        }
    }
    ((i0 as u32) << 8) | j as u32
}
''')
edit("bench_chain/Cargo.toml", [("topcache = [\"sphincs-c10/top-cache\"]\n", '''topcache = ["sphincs-c10/top-cache"]
# round 21 plant copy only: the #1148 planted top-cache faults (one chain; see mk_plants.sh)
plant = ["topcache"]
plant-none = ["plant"]
plant-digest = ["plant"]
plant-own = ["plant"]
plant-b0 = ["plant"]
plant-b2 = ["plant"]
plant-b5 = ["plant"]
plant-noroot = ["plant", "sphincs-c10/plant-noroot"]
''')])
edit("bench_chain/src/lib.rs", [
    ("const NMSG: u32 = 16;", '#[cfg(not(feature = "plant"))]\nconst NMSG: u32 = 16;\n#[cfg(feature = "plant")]\nconst NMSG: u32 = 1;'),
    ('''fn panic(_: &core::panic::PanicInfo) -> ! {''', '''fn panic(_info: &core::panic::PanicInfo) -> ! {
    // round 21 plants: which assert refused (line; 1 if in topcache.rs)
    #[cfg(feature = "plant")]
    if let Some(l) = _info.location() {
        out(23, l.line());
        out(24, u32::from(l.file().ends_with("topcache.rs")));
    }'''),
    ('''    let sk = sphincs_c10::topcache::keygen_with_top_cache(SK_SEED, PK_SEED, &mut cache);
    out(2, cyc().wrapping_sub(t));''', '''    let sk = sphincs_c10::topcache::keygen_with_top_cache(SK_SEED, PK_SEED, &mut cache);
    out(2, cyc().wrapping_sub(t));
    // round 21: the plant, after keygen, relative to chain 0's top leaf (chain 0 signs MSG0 with [0..4] = 0, [4] ^ 0xA5)
    #[cfg(feature = "plant")]
    {
        let mut m = MSG0;
        m[0..4].copy_from_slice(&0u32.to_le_bytes());
        m[4] ^= 0xA5;
        // (bit, corrupt, recompute the digest)
        #[cfg(feature = "plant-none")]
        let (b, c, k) = (Some(5), false, false);
        #[cfg(feature = "plant-digest")]
        let (b, c, k) = (Some(5), true, false);
        #[cfg(feature = "plant-own")]
        let (b, c, k) = (None, true, true);
        #[cfg(feature = "plant-b0")]
        let (b, c, k) = (Some(0), true, true);
        #[cfg(feature = "plant-b2")]
        let (b, c, k) = (Some(2), true, true);
        #[cfg(feature = "plant-b5")]
        let (b, c, k) = (Some(5), true, true);
        #[cfg(feature = "plant-noroot")]
        let (b, c, k) = (Some(5), true, true);
        out(25, sphincs_c10::topcache::plant_for_test(&mut cache, &sk, &m, Some(&OPT_RAND), b, c, k));
    }'''),
])
print("plant copy patched")
PY
# the assert lines in the plant copy's topcache.rs, for the runner's location -> check mapping
grep -n -E 'assert!\((self\.valid|Self::digest_of|stack\[0\] ==|&level\[0\] ==)' "$Q/sphincs-c10/src/topcache.rs" > "$Q/assert-lines.txt"
cat "$Q/assert-lines.txt"
cd "$D"
B() { CRATE=target/proto-cf/bench_chain LIBNAME=c10_bench_chain LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN" BENCH_RUSTFLAGS="" BENCH_FEATURES=$1 ./build_any.sh out/$2.elf; }
for p in none digest own b0 b2 b5 noroot; do
  B v2,ts200,prf2,split810,wprf2b,plant-$p r21-plant-full-$p
  B v2,ts200,split810,wprf2b,plant-$p r21-plant-np2-$p
done
echo "mk_plants OK"
