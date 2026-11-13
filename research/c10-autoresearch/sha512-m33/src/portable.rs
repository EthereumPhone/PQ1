const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];
// The Sigma functions on 32-bit halves: rotations by r < 32 are (hi >> r | lo << (32 - r)) per half, by
// r >= 32 the halves swap first. Each half is a chain of eor with a shifted operand on ARMv8-M.
#[inline(always)]
fn halves(x: u64) -> (u32, u32) { ((x >> 32) as u32, x as u32) }
#[inline(always)]
fn join(h: u32, l: u32) -> u64 { (u64::from(h) << 32) | u64::from(l) }
#[inline(always)]
fn bsig0(x: u64) -> u64 {
    // rotr 28, 34 (= swap + rotr 2), 39 (= swap + rotr 7)
    let (h, l) = halves(x);
    let hi = (h >> 28 | l << 4) ^ (l >> 2 | h << 30) ^ (l >> 7 | h << 25);
    let lo = (l >> 28 | h << 4) ^ (h >> 2 | l << 30) ^ (h >> 7 | l << 25);
    join(hi, lo)
}
#[inline(always)]
fn bsig1(x: u64) -> u64 {
    // rotr 14, 18, 41 (= swap + rotr 9)
    let (h, l) = halves(x);
    let hi = (h >> 14 | l << 18) ^ (h >> 18 | l << 14) ^ (l >> 9 | h << 23);
    let lo = (l >> 14 | h << 18) ^ (l >> 18 | h << 14) ^ (h >> 9 | l << 23);
    join(hi, lo)
}
#[inline(always)]
fn ssig0(x: u64) -> u64 {
    // rotr 1, 8, shr 7
    let (h, l) = halves(x);
    let hi = (h >> 1 | l << 31) ^ (h >> 8 | l << 24) ^ (h >> 7);
    let lo = (l >> 1 | h << 31) ^ (l >> 8 | h << 24) ^ (l >> 7 | h << 25);
    join(hi, lo)
}
#[inline(always)]
fn ssig1(x: u64) -> u64 {
    // rotr 19, 61 (= swap + rotr 29), shr 6
    let (h, l) = halves(x);
    let hi = (h >> 19 | l << 13) ^ (l >> 29 | h << 3) ^ (h >> 6);
    let lo = (l >> 19 | h << 13) ^ (h >> 29 | l << 3) ^ (l >> 6 | h << 26);
    join(hi, lo)
}

/// One SHA-512 compression of `w` (16 big-endian words, already decoded) into `state`.
#[inline(never)]
pub fn compress(state: &mut [u64; 8], w_in: &[u64; 16]) {
    let mut w = *w_in;
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    macro_rules! round {
        ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $i:expr, $r:expr) => {{
            if $r >= 16 {
                let j = $i & 15;
                w[j] = w[j]
                    .wrapping_add(ssig1(w[(j + 14) & 15]))
                    .wrapping_add(w[(j + 9) & 15])
                    .wrapping_add(ssig0(w[(j + 1) & 15]));
            }
            let t1 = $h
                .wrapping_add(bsig1($e))
                .wrapping_add($g ^ ($e & ($f ^ $g)))
                .wrapping_add(K[$r])
                .wrapping_add(w[$i & 15]);
            let t2 = bsig0($a).wrapping_add(($a & $b) | ($c & ($a | $b)));
            $d = $d.wrapping_add(t1);
            $h = t1.wrapping_add(t2);
        }};
    }
    macro_rules! sixteen {
        ($base:expr) => {{
            round!(a, b, c, d, e, f, g, h, 0, $base);
            round!(h, a, b, c, d, e, f, g, 1, $base + 1);
            round!(g, h, a, b, c, d, e, f, 2, $base + 2);
            round!(f, g, h, a, b, c, d, e, 3, $base + 3);
            round!(e, f, g, h, a, b, c, d, 4, $base + 4);
            round!(d, e, f, g, h, a, b, c, 5, $base + 5);
            round!(c, d, e, f, g, h, a, b, 6, $base + 6);
            round!(b, c, d, e, f, g, h, a, 7, $base + 7);
            round!(a, b, c, d, e, f, g, h, 8, $base + 8);
            round!(h, a, b, c, d, e, f, g, 9, $base + 9);
            round!(g, h, a, b, c, d, e, f, 10, $base + 10);
            round!(f, g, h, a, b, c, d, e, 11, $base + 11);
            round!(e, f, g, h, a, b, c, d, 12, $base + 12);
            round!(d, e, f, g, h, a, b, c, 13, $base + 13);
            round!(c, d, e, f, g, h, a, b, 14, $base + 14);
            round!(b, c, d, e, f, g, h, a, 15, $base + 15);
        }};
    }
    sixteen!(0);
    sixteen!(16);
    sixteen!(32);
    sixteen!(48);
    sixteen!(64);
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}
