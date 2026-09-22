//! Integer fixed-point helpers. Everything animated is Q16 (1/65536), every
//! coordinate Q8 (1/256 px), advances Q6 (1/64 px). No floats anywhere, so
//! host golden renders and on-device frames are bit-identical and the
//! trusted image needs no FPU context.

/// Q16 fixed point (16 fractional bits).
pub type Q16 = i32;
/// Q8 fixed point (8 fractional bits).
pub type Q8 = i32;

pub const ONE_Q16: Q16 = 1 << 16;
pub const ONE_Q8: Q8 = 1 << 8;

#[must_use]
pub const fn q16(v: i32) -> Q16 {
    v << 16
}

#[must_use]
pub const fn q8(v: i32) -> Q8 {
    v << 8
}

/// `a * b` in Q16.
#[must_use]
pub fn mul_q16(a: Q16, b: Q16) -> Q16 {
    ((i64::from(a) * i64::from(b)) >> 16) as Q16
}

/// `a * b` in Q8.
#[must_use]
pub fn mul_q8(a: Q8, b: Q8) -> Q8 {
    ((i64::from(a) * i64::from(b)) >> 8) as Q8
}

/// Linear interpolation `a + (b − a)·t`, `t` in Q16 `[0, 1]`.
#[must_use]
pub fn lerp(a: i32, b: i32, t: Q16) -> i32 {
    (i64::from(a) + ((i64::from(b) - i64::from(a)) * i64::from(t) >> 16)) as i32
}

#[must_use]
pub fn clamp01(t: Q16) -> Q16 {
    t.clamp(0, ONE_Q16)
}

/// Integer square root (floor).
///
/// Values that fit in 32 bits take the `u32` Newton path: on Cortex-M the
/// 32-bit divide is a hardware instruction (`udiv`, ≤ 12 cycles) while a
/// 64-bit divide is a compiler-rt call costing hundreds of cycles per step.
/// Both paths return the exact floor, so the result is identical either way.
#[must_use]
pub fn isqrt_u64(v: u64) -> u32 {
    if v <= u64::from(u32::MAX) {
        return isqrt_u32(v as u32);
    }
    // Newton from a power-of-two seed; converges in a handful of steps.
    let mut x = 1u64 << ((64 - v.leading_zeros()).div_ceil(2));
    loop {
        let y = (x + v / x) >> 1;
        if y >= x {
            return x as u32;
        }
        x = y;
    }
}

/// Integer square root (floor) of a 32-bit value; hardware-divide Newton.
#[must_use]
pub fn isqrt_u32(v: u32) -> u32 {
    if v == 0 {
        return 0;
    }
    let mut x = 1u32 << ((32 - v.leading_zeros()).div_ceil(2));
    loop {
        // `x` never exceeds 2^16 (the seed is ≤ 2^16), so `x + v / x` fits.
        let y = (x + v / x) >> 1;
        if y >= x {
            return x;
        }
        x = y;
    }
}

/// Distance in Q8 between two Q8 points.
#[must_use]
pub fn dist_q8(dx: Q8, dy: Q8) -> Q8 {
    let s = i64::from(dx) * i64::from(dx) + i64::from(dy) * i64::from(dy);
    isqrt_u64(s as u64) as Q8
}

/// `e^(−t)` for `t` in Q16 `[0, 8]`, Q16 out; piecewise-linear over a
/// 129-entry table (max error ≈ 2e-4). Used by the springs and τ-chases.
#[must_use]
pub fn exp_neg_q16(t: Q16) -> Q16 {
    const N: usize = 128;
    const TABLE: [u16; N + 1] = exp_table();
    if t <= 0 {
        return ONE_Q16;
    }
    // Table spans t ∈ [0, 8]: index = t / (8/128) = t / (1/16) = t * 16 / 65536.
    let idx_q16 = (i64::from(t) * 16) >> 16; // integer part
    if idx_q16 >= N as i64 {
        return 0;
    }
    let i = idx_q16 as usize;
    let frac = ((i64::from(t) * 16) & 0xFFFF) as i32; // Q16 fraction inside the cell
    let a = i32::from(TABLE[i]);
    let b = i32::from(TABLE[i + 1]);
    lerp(a, b, frac)
}

/// `e^(−i/16)` in Q16 for i = 0..=128, evaluated at compile time via the
/// series (exact enough at 1e-6, then rounded to u16 — 65535 caps e^0).
const fn exp_table() -> [u16; 129] {
    let mut t = [0u16; 129];
    let mut i = 0;
    while i <= 128 {
        // x = i/16 ; e^-x = (e^-(1/16))^i computed by repeated multiplication
        // of a high-precision Q30 constant.
        // e^(-1/16) = 0.939413062813... → Q30 = 1008622574 (rounded)
        const STEP_Q30: u64 = 1_008_622_574;
        let mut acc: u64 = 1 << 30;
        let mut k = 0;
        while k < i {
            acc = (acc * STEP_Q30) >> 30;
            k += 1;
        }
        let q16 = (acc + (1 << 13)) >> 14; // Q30 → Q16 rounded
        t[i] = if q16 > 65535 { 65535 } else { q16 as u16 };
        i += 1;
    }
    t
}

/// `sin(θ)` in Q16 for `θ` in Q16 turns (1.0 = 360°). Quarter-wave table.
#[must_use]
pub fn sin_turns_q16(turns: Q16) -> Q16 {
    const N: i64 = 64; // entries per quarter
    const TABLE: [u16; 65] = sin_table();
    let t = i64::from(turns).rem_euclid(i64::from(ONE_Q16)); // [0, 1)
    let quadrant = (t * 4) >> 16; // 0..3
    let within = ((t * 4) & 0xFFFF) as i64; // Q16 within the quadrant
    let pos = if quadrant % 2 == 0 { within } else { i64::from(ONE_Q16) - within };
    let idx = (pos * N) >> 16;
    let frac = ((pos * N) & 0xFFFF) as i32;
    let i = idx.min(N - 1) as usize;
    let v = lerp(i32::from(TABLE[i]), i32::from(TABLE[i + 1]), frac);
    if quadrant >= 2 {
        -v
    } else {
        v
    }
}

#[must_use]
pub fn cos_turns_q16(turns: Q16) -> Q16 {
    sin_turns_q16(turns.wrapping_add(ONE_Q16 / 4))
}

/// `sin(i/64 · π/2)` in Q16 for i = 0..=64, via a compile-time Taylor sum.
const fn sin_table() -> [u16; 65] {
    let mut t = [0u16; 65];
    let mut i = 0;
    while i <= 64 {
        // x = i/64 * π/2, in Q30: π/2 = 1686629713 (Q30)
        let x: i64 = (1_686_629_713i64 * i as i64) / 64;
        // Taylor: x − x³/6 + x⁵/120 − x⁷/5040 (Q30 arithmetic, i128 for products)
        let x2 = ((x as i128 * x as i128) >> 30) as i64;
        let x3 = ((x2 as i128 * x as i128) >> 30) as i64;
        let x5 = ((x3 as i128 * x2 as i128) >> 30) as i64;
        let x7 = ((x5 as i128 * x2 as i128) >> 30) as i64;
        let s = x - x3 / 6 + x5 / 120 - x7 / 5040;
        let q16 = (s + (1 << 13)) >> 14;
        t[i] = if q16 > 65535 { 65535 } else if q16 < 0 { 0 } else { q16 as u16 };
        i += 1;
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isqrt_exact_on_squares() {
        for v in [0u64, 1, 4, 9, 16, 100, 65536, 1 << 40] {
            assert_eq!(u64::from(isqrt_u64(v)) * u64::from(isqrt_u64(v)), v);
        }
        assert_eq!(isqrt_u64(15), 3);
        assert_eq!(isqrt_u64(u64::MAX), u32::MAX);
    }

    #[test]
    fn exp_table_matches_reference() {
        let cases = [(0.0f64, 1.0f64), (0.5, 0.60653), (1.0, 0.36788), (2.0, 0.13534), (4.0, 0.01832), (8.0, 0.000335)];
        for (t, e) in cases {
            let q = exp_neg_q16((t * 65536.0) as i32);
            let got = f64::from(q) / 65536.0;
            assert!((got - e).abs() < 4e-4, "exp(-{t}) = {got}, want {e}");
        }
        assert_eq!(exp_neg_q16(-5), ONE_Q16);
        assert_eq!(exp_neg_q16(q16(9)), 0);
    }

    #[test]
    fn sin_cos_reference_points() {
        let s = |turns: f64| f64::from(sin_turns_q16((turns * 65536.0) as i32)) / 65536.0;
        assert!((s(0.0)).abs() < 1e-3);
        assert!((s(0.25) - 1.0).abs() < 1e-3);
        assert!((s(0.5)).abs() < 2e-3);
        assert!((s(0.75) + 1.0).abs() < 1e-3);
        assert!((s(0.125) - 0.70711).abs() < 2e-3);
        let c = f64::from(cos_turns_q16(0)) / 65536.0;
        assert!((c - 1.0).abs() < 1e-3);
    }

    #[test]
    fn lerp_and_mul() {
        assert_eq!(lerp(0, 100, ONE_Q16 / 2), 50);
        assert_eq!(mul_q16(q16(3), q16(2)), q16(6));
        assert_eq!(mul_q8(q8(3), q8(2)), q8(6));
        assert_eq!(dist_q8(q8(3), q8(4)), q8(5));
    }
}

#[cfg(test)]
mod isqrt_tests {
    use super::*;

    fn slow(v: u64) -> u32 {
        let mut r = 0u64;
        while (r + 1) * (r + 1) <= v {
            r += 1;
        }
        r as u32
    }

    #[test]
    fn isqrt_u32_matches_floor_sqrt() {
        for v in (0u32..70_000).chain([u32::MAX, u32::MAX - 1, 1 << 31, 0xFFFE_0001, 0xFFFE_0000]) {
            assert_eq!(isqrt_u32(v), slow(u64::from(v)), "v={v}");
        }
        // Every perfect square and its neighbours up to 2^16.
        for r in 0u64..=65_535 {
            let sq = r * r;
            assert_eq!(u64::from(isqrt_u32(sq as u32)), r);
            if sq > 0 {
                assert_eq!(u64::from(isqrt_u32((sq - 1) as u32)), r - 1);
            }
        }
    }

    #[test]
    fn isqrt_u64_paths_agree_at_the_boundary() {
        for v in [u64::from(u32::MAX) - 5, u64::from(u32::MAX), u64::from(u32::MAX) + 1, 1u64 << 40, (1u64 << 34) + 12_345] {
            assert_eq!(isqrt_u64(v), slow(v), "v={v}");
        }
    }
}
