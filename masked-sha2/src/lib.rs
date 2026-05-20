//! First-order (2-share) boolean-masked SHA-256 building blocks.
//!
//! Purpose: MEASURE the masking overhead vs the STM32U585 HASH
//! peripheral, to settle the SHAKE-vs-SHA2 question in work-todo §18
//! WITHOUT building (and getting subtly wrong) a full masked SHA-256.
//!
//! The decision hinges on "how much slower is masked SHA-256 than the
//! HASH peripheral?" The slowdown is dominated by two masked gates:
//!
//!   * [`sec_and`] — the ISW first-order masked AND (Ishai-Sahai-Wagner,
//!     CRYPTO 2003). The one non-linear gate; everything else (XOR,
//!     rotate, shift) is linear and free per-share.
//!   * [`sec_add`] — a first-order Kogge-Stone secure boolean adder
//!     (Coron-Großschädl-Vadnala family, CHES 2014). Modular addition
//!     on boolean shares, built from `sec_and`.
//!
//! SHA-256's per-512-bit-block structure is a fixed integer count
//! ([`ADDS_PER_BLOCK`], [`ANDS_PER_BLOCK`]), so the projected masked
//! cost is `ADDS_PER_BLOCK × cost(sec_add) + ANDS_PER_BLOCK ×
//! cost(sec_and)` plus a small linear-op term — algebra, not guesswork.
//! The secure-world bench (`secure/src/bench_masked_sha.rs`) measures
//! `cost(sec_add)` and `cost(sec_and)` on real silicon and computes the
//! projection.
//!
//! **First-order only.** Two shares, defends first-order DPA. Higher
//! orders scale ~quadratically; if first-order is already too slow,
//! higher-order is moot. If first-order is fine, this is the baseline
//! the higher-order cost is measured against.
//!
//! **Not (yet) a production signer.** These primitives graduate into
//! the signing path only if the measurement says SHA-256 masking is
//! viable; otherwise the SHAKE arm of the §18 benchmark wins.

#![no_std]
#![forbid(unsafe_code)]

/// A 32-bit value split into two boolean shares: `value == s[0] ^ s[1]`.
/// Neither share alone reveals a bit of `value` (each is uniform given a
/// uniform mask).
pub type Share = [u32; 2];

/// Modular additions in one SHA-256 512-bit block:
///   * message schedule: 48 words × 3 adds = 144
///   * compression: 64 rounds × 7 adds   = 448
///       (T1 = h+Σ1+Ch+K+W → 4; T2 = Σ0+Maj → 1; e=d+T1 → 1; a=T1+T2 → 1)
///   * final state update: 8
///   * total                              = 600
pub const ADDS_PER_BLOCK: u32 = 600;

/// Non-linear ANDs in one SHA-256 block: only Ch and Maj contain ANDs.
///   * Ch(e,f,g)  = (e&f) ^ (~e&g)        → 2 ANDs
///   * Maj(a,b,c) = (a&b) ^ (a&c) ^ (b&c) → 3 ANDs
///   * 5 per round × 64 rounds            = 320
/// The σ/Σ rotate-mix functions and the message schedule are XOR/rotate
/// only (zero ANDs).
pub const ANDS_PER_BLOCK: u32 = 320;

/// Mask a plaintext value into two boolean shares using one random word.
#[inline]
pub fn mask(value: u32, rand: u32) -> Share {
    [value ^ rand, rand]
}

/// Recombine two boolean shares into the plaintext value.
#[inline]
pub fn unmask(s: Share) -> u32 {
    s[0] ^ s[1]
}

/// Masked XOR — linear, so it's just per-share XOR (no randomness, no
/// leak). `z = a ^ b`.
#[inline]
pub fn sec_xor(a: Share, b: Share) -> Share {
    [a[0] ^ b[0], a[1] ^ b[1]]
}

/// Masked NOT — complement exactly one share. `z = !a`.
/// (Complementing both shares would XOR-cancel; complementing one flips
/// the recombined value.)
#[inline]
pub fn sec_not(a: Share) -> Share {
    [!a[0], a[1]]
}

/// Masked left shift by `n` — linear (fills with zero). `z = a << n`.
#[inline]
pub fn sec_shl(a: Share, n: u32) -> Share {
    [a[0] << n, a[1] << n]
}

/// Masked right rotate — linear. `z = a.rotate_right(n)`.
#[inline]
pub fn sec_rotr(a: Share, n: u32) -> Share {
    [a[0].rotate_right(n), a[1].rotate_right(n)]
}

/// First-order masked AND (Ishai-Sahai-Wagner, CRYPTO 2003), 2 shares.
///
/// `z` such that `unmask(z) == unmask(a) & unmask(b)`. Consumes one
/// fresh random word `r`. The canonical refresh ordering (mix `r` into
/// the `a0&b1` cross term BEFORE combining `a1&b0`) is what makes each
/// output share independent of the unshared inputs — don't reorder.
#[inline]
pub fn sec_and(a: Share, b: Share, r: u32) -> Share {
    let z0 = (a[0] & b[0]) ^ r;
    // Refresh-first ordering for first-order security.
    let mut t = (a[0] & b[1]) ^ r;
    t ^= a[1] & b[0];
    let z1 = (a[1] & b[1]) ^ t;
    [z0, z1]
}

/// Number of fresh random words [`sec_add`] consumes for 32-bit inputs:
/// one initial generate + (W−1) loop iterations × 2 ANDs + 1 final AND,
/// where W = ceil(log2(32)) = 5 → 1 + 4×2 + 1 = 10.
pub const SEC_ADD_RANDS: usize = 10;

/// First-order masked modular addition on boolean shares — a Kogge-Stone
/// secure adder (Coron-Großschädl-Vadnala family, CHES 2014).
///
/// `z` such that `unmask(z) == unmask(a).wrapping_add(unmask(b))`.
/// Consumes [`SEC_ADD_RANDS`] random words via `rands`.
///
/// Carry-lookahead on shares: generate `G = a&b`, propagate `P = a^b`,
/// then log-step combine the carries. Result `= P ^ (carry << 1)`.
pub fn sec_add(a: Share, b: Share, rands: &[u32; SEC_ADD_RANDS]) -> Share {
    // W = ceil(log2(32)) = 5. Carry propagation distance covered:
    // 1+2+4+8 (loop) + 16 (final) = 31, i.e. all 32 bit positions.
    let mut ri = 0usize;
    let mut next_rand = || {
        let r = rands[ri];
        ri += 1;
        r
    };

    let p0 = sec_xor(a, b); // propagate
    let mut p = p0;
    let mut g = sec_and(a, b, next_rand()); // generate

    // Loop i = 1 ..= W-1 = 1..=4 → pow = 1,2,4,8.
    let mut pow = 1u32;
    for _ in 0..4 {
        // G = G ^ SecAnd(G << pow, P)   (uses the CURRENT P)
        let g_sh = sec_shl(g, pow);
        let u = sec_and(g_sh, p, next_rand());
        g = sec_xor(g, u);
        // P = SecAnd(P, P << pow)
        let p_sh = sec_shl(p, pow);
        p = sec_and(p, p_sh, next_rand());
        pow <<= 1;
    }

    // Final step: pow now = 16.
    let g_sh = sec_shl(g, pow);
    let u = sec_and(g_sh, p, next_rand());
    g = sec_xor(g, u);

    // z = a ^ b ^ (carry << 1)
    sec_xor(p0, sec_shl(g, 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny deterministic xorshift32 PRNG — host-test mask source only.
    // Production masks come from the secure-world TRNG (the bench wires
    // that in); for correctness testing we just need reproducible,
    // well-mixed words.
    struct Xs(u32);
    impl Xs {
        fn next(&mut self) -> u32 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.0 = x;
            x
        }
    }

    #[test]
    fn mask_unmask_roundtrip() {
        let mut rng = Xs(0x1234_5678);
        for _ in 0..10_000 {
            let v = rng.next();
            let r = rng.next();
            assert_eq!(unmask(mask(v, r)), v);
        }
    }

    #[test]
    fn sec_xor_correct() {
        let mut rng = Xs(0xC0FF_EE01);
        for _ in 0..10_000 {
            let (x, y) = (rng.next(), rng.next());
            let a = mask(x, rng.next());
            let b = mask(y, rng.next());
            assert_eq!(unmask(sec_xor(a, b)), x ^ y);
        }
    }

    #[test]
    fn sec_not_correct() {
        let mut rng = Xs(0xBEEF_0042);
        for _ in 0..10_000 {
            let x = rng.next();
            let a = mask(x, rng.next());
            assert_eq!(unmask(sec_not(a)), !x);
        }
    }

    #[test]
    fn sec_and_correct() {
        let mut rng = Xs(0xA5A5_1234);
        for _ in 0..50_000 {
            let (x, y) = (rng.next(), rng.next());
            let a = mask(x, rng.next());
            let b = mask(y, rng.next());
            assert_eq!(unmask(sec_and(a, b, rng.next())), x & y);
        }
    }

    #[test]
    fn sec_add_correct() {
        let mut rng = Xs(0x0BAD_F00D);
        for _ in 0..50_000 {
            let (x, y) = (rng.next(), rng.next());
            let a = mask(x, rng.next());
            let b = mask(y, rng.next());
            let mut rands = [0u32; SEC_ADD_RANDS];
            for r in rands.iter_mut() {
                *r = rng.next();
            }
            assert_eq!(unmask(sec_add(a, b, &rands)), x.wrapping_add(y));
        }
    }

    #[test]
    fn sec_add_edge_cases() {
        // Carry-propagation worst cases: 0xFFFF_FFFF + 1 (full ripple),
        // max + max, 0 + 0.
        let mut rng = Xs(0xFACE_B00C);
        let cases = [
            (0xFFFF_FFFFu32, 1u32),
            (0xFFFF_FFFF, 0xFFFF_FFFF),
            (0, 0),
            (0x8000_0000, 0x8000_0000),
            (0x7FFF_FFFF, 1),
        ];
        for (x, y) in cases {
            let a = mask(x, rng.next());
            let b = mask(y, rng.next());
            let mut rands = [0u32; SEC_ADD_RANDS];
            for r in rands.iter_mut() {
                *r = rng.next();
            }
            assert_eq!(
                unmask(sec_add(a, b, &rands)),
                x.wrapping_add(y),
                "sec_add wrong for {x:#010x} + {y:#010x}"
            );
        }
    }

    // Cross-check: a masked SHA-256 Ch and Maj built from the gates must
    // match the plain definitions. This validates that the gates compose
    // correctly the way SHA-256 actually uses them (the projection's
    // ANDS_PER_BLOCK assumes exactly this composition).
    #[test]
    fn masked_ch_maj_compose_correctly() {
        let mut rng = Xs(0xC0DE_1357);
        for _ in 0..20_000 {
            let (e, f, g) = (rng.next(), rng.next(), rng.next());
            let (a, b, c) = (rng.next(), rng.next(), rng.next());

            let me = mask(e, rng.next());
            let mf = mask(f, rng.next());
            let mg = mask(g, rng.next());
            // Ch = (e&f) ^ (~e&g)
            let ch = sec_xor(
                sec_and(me, mf, rng.next()),
                sec_and(sec_not(me), mg, rng.next()),
            );
            assert_eq!(unmask(ch), (e & f) ^ (!e & g));

            let ma = mask(a, rng.next());
            let mb = mask(b, rng.next());
            let mc = mask(c, rng.next());
            // Maj = (a&b) ^ (a&c) ^ (b&c)
            let maj = sec_xor(
                sec_xor(
                    sec_and(ma, mb, rng.next()),
                    sec_and(ma, mc, rng.next()),
                ),
                sec_and(mb, mc, rng.next()),
            );
            assert_eq!(unmask(maj), (a & b) ^ (a & c) ^ (b & c));
        }
    }
}
