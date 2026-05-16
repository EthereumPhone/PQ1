//! Positive + negative tests for the shared `U256` integer.
//!
//! Trusted-UI display calls `format_decimal` on every fee/value field
//! shown to the user, so a quiet bug there (overflow truncation, wrong
//! sign of `Ord`, partial buffer writes that the caller renders as a
//! short number) is a sign-the-wrong-amount class of vulnerability.

mod common;

use pqsigner_tx_core::eip1559::U256;

fn u256_from_u64(x: u64) -> U256 {
    let mut buf = [0u8; 32];
    buf[24..32].copy_from_slice(&x.to_be_bytes());
    U256(buf)
}

fn pow10_u256(exp: u32) -> U256 {
    let mut v = [0u8; 32];
    v[31] = 1;
    let mut u = U256(v);
    for _ in 0..exp {
        let (p, over) = u.saturating_mul_u64(10);
        assert!(!over, "pow10 overflowed at exp {exp}");
        u = p;
    }
    u
}

fn format_to_string(v: &U256, decimals: u32, frac: u32, trim: bool) -> Option<String> {
    let mut out = [0u8; 96];
    let n = v.format_decimal(decimals, frac, trim, &mut out)?;
    Some(String::from_utf8(out[..n].to_vec()).unwrap())
}

// ---------------------------------------------------------------------------
// is_zero / zero / Default
// ---------------------------------------------------------------------------

#[test]
fn positive_zero_is_zero() {
    assert!(U256::zero().is_zero());
}

#[test]
fn positive_default_equals_zero() {
    assert_eq!(U256::default(), U256::zero());
}

#[test]
fn positive_any_nonzero_byte_makes_nonzero() {
    for i in 0..32 {
        let mut buf = [0u8; 32];
        buf[i] = 1;
        assert!(!U256(buf).is_zero(), "byte {i} set must register as non-zero");
    }
}

// ---------------------------------------------------------------------------
// Ord — big-endian byte compare must equal numeric magnitude
// ---------------------------------------------------------------------------

#[test]
fn positive_ord_is_numeric_magnitude_across_full_range() {
    // ASSUMPTION: derived `[u8; 32]` lex compare equals numeric magnitude
    // because the bytes are stored big-endian. Walk every byte position
    // and assert that bumping a higher position always outranks any
    // lower-position bump.
    for hi in 0..32 {
        let mut hi_buf = [0u8; 32];
        hi_buf[hi] = 1;
        // A value with the MSB-most byte set to 0xff at any later position
        // is still numerically smaller than `hi_buf`.
        for lo in (hi + 1)..32 {
            let mut lo_buf = [0u8; 32];
            lo_buf[lo] = 0xff;
            assert!(
                U256(hi_buf) > U256(lo_buf),
                "byte {hi}=1 must outrank byte {lo}=0xff in big-endian magnitude",
            );
        }
    }
}

#[test]
fn positive_ord_equal_values_compare_equal() {
    let a = u256_from_u64(0xabcd_ef01_2345_6789);
    let b = u256_from_u64(0xabcd_ef01_2345_6789);
    assert!(a == b);
    assert!(a >= b);
    assert!(a <= b);
    assert!(!(a > b));
    assert!(!(a < b));
}

// ---------------------------------------------------------------------------
// saturating_mul_u64
// ---------------------------------------------------------------------------

#[test]
fn positive_saturating_mul_by_zero_is_zero() {
    let v = U256([0xffu8; 32]);
    let (p, over) = v.saturating_mul_u64(0);
    assert!(!over);
    assert!(p.is_zero());
}

#[test]
fn positive_saturating_mul_by_one_is_identity() {
    let v = u256_from_u64(0x1234_5678_9abc_def0);
    let (p, over) = v.saturating_mul_u64(1);
    assert!(!over);
    assert_eq!(p, v);
}

#[test]
fn positive_saturating_mul_basic() {
    let v = u256_from_u64(7);
    let (p, over) = v.saturating_mul_u64(6);
    assert!(!over);
    assert_eq!(p, u256_from_u64(42));
}

#[test]
fn negative_saturating_mul_overflow_clamps_to_max() {
    // ASSUMPTION: on overflow, the result is U256::MAX (0xff repeated)
    // AND the overflow flag is set. Display callers depend on the flag
    // to render a "would overflow" banner rather than a real-looking
    // huge number.
    let v = U256([0xffu8; 32]);
    let (p, over) = v.saturating_mul_u64(2);
    assert!(over);
    assert_eq!(p, U256([0xffu8; 32]));
}

#[test]
fn negative_saturating_mul_just_over_max_saturates() {
    // (2^255) * 3 = 1.5 × 2^256 — overflows by half of 2^256.
    let mut buf = [0u8; 32];
    buf[0] = 0x80;
    let v = U256(buf);
    let (p, over) = v.saturating_mul_u64(3);
    assert!(over);
    assert_eq!(p, U256([0xffu8; 32]));
}

#[test]
fn positive_saturating_mul_just_under_overflow_does_not_set_flag() {
    // (2^256 - 1) / 1 = (2^256 - 1) -> no overflow.
    let v = U256([0xffu8; 32]);
    let (p, over) = v.saturating_mul_u64(1);
    assert!(!over);
    assert_eq!(p, v);
}

// ---------------------------------------------------------------------------
// format_decimal — positive
// ---------------------------------------------------------------------------

#[test]
fn positive_format_decimal_integer_widths() {
    // 1, 12, 123, 1234 → digit count matches.
    let cases = [(1u64, "1"), (12, "12"), (123, "123"), (1234, "1234")];
    for (n, expect) in cases {
        let s = format_to_string(&u256_from_u64(n), 0, 0, false).unwrap();
        assert_eq!(s, expect);
    }
}

#[test]
fn positive_format_decimal_eth_3_5() {
    // 3.5 ETH = 3.5 * 10^18 wei, decimals=18, frac=3, trim=false → "3.500"
    let v = u256_from_u64(3_500_000_000_000_000_000);
    assert_eq!(
        format_to_string(&v, 18, 3, false).as_deref(),
        Some("3.500"),
    );
    assert_eq!(
        format_to_string(&v, 18, 3, true).as_deref(),
        Some("3.5"),
    );
}

#[test]
fn positive_format_decimal_exact_fit_buffer() {
    // "1.000000" is 8 bytes; a buffer of exactly 8 must succeed.
    let v = pow10_u256(18);
    let mut out = [0u8; 8];
    let n = v.format_decimal(18, 6, false, &mut out).unwrap();
    assert_eq!(n, 8);
    assert_eq!(&out[..n], b"1.000000");
}

#[test]
fn positive_format_decimal_u256_max_is_78_digits() {
    let v = U256([0xffu8; 32]);
    let mut out = [0u8; 96];
    let n = v.format_decimal(0, 0, false, &mut out).unwrap();
    // Canonical decimal expansion of 2^256 - 1.
    assert_eq!(
        &out[..n],
        b"115792089237316195423570985008687907853269984665640564039457584007913129639935",
    );
    assert_eq!(n, 78);
}

#[test]
fn positive_format_decimal_frac_greater_than_decimals_pads_with_zeros() {
    // 5 with 0 decimals, frac=4 → "5.0000"
    let v = u256_from_u64(5);
    assert_eq!(
        format_to_string(&v, 0, 4, false).as_deref(),
        Some("5.0000"),
    );
}

#[test]
fn positive_format_decimal_trim_zero_collapses_decimal_point() {
    // 1.0 ETH trimmed → "1" (no decimal point).
    let v = pow10_u256(18);
    let s = format_to_string(&v, 18, 6, true).unwrap();
    assert_eq!(s, "1");
    assert!(!s.contains('.'));
}

#[test]
fn positive_format_decimal_trim_preserves_significant_tail() {
    // 1.500 trimmed → "1.5" (not "1.500" nor "1.").
    let v = U256({
        let raw: u128 = 1_500_000_000_000_000_000;
        let mut bytes = [0u8; 32];
        bytes[16..32].copy_from_slice(&raw.to_be_bytes());
        bytes
    });
    let s = format_to_string(&v, 18, 6, true).unwrap();
    assert_eq!(s, "1.5");
}

// ---------------------------------------------------------------------------
// format_decimal — negative (the high-value tests)
// ---------------------------------------------------------------------------

#[test]
fn negative_format_decimal_overflow_returns_none_without_writing() {
    // ASSUMPTION: when the rendered number wouldn't fit, format_decimal
    // MUST return None and MUST NOT partially write to the buffer.
    // Otherwise the display layer could render a silently-truncated
    // value, e.g. show "1.5000" for 1.5 ETH and "1.5" for 1.5 trillion
    // ETH, with no way for the caller to distinguish.
    let v = pow10_u256(20); // 100 * 10^18 wei = 100 ETH → "100.000000"
    let sentinel = 0xa5u8;
    let mut out = [sentinel; 4]; // way too small
    assert_eq!(v.format_decimal(18, 6, false, &mut out), None);
    assert_eq!(
        out, [sentinel; 4],
        "format_decimal must not touch the output buffer on overflow",
    );
}

#[test]
fn negative_format_decimal_zero_length_buffer_returns_none() {
    // 0 with no fraction needs 1 byte ("0"); a zero-length buffer must
    // refuse rather than silently truncate to nothing.
    let v = U256::zero();
    let mut out: [u8; 0] = [];
    assert_eq!(v.format_decimal(0, 0, false, &mut out), None);
}

#[test]
fn negative_format_decimal_emits_only_ascii_digits() {
    // ASSUMPTION: every emitted byte is either an ASCII digit '0'..='9'
    // or the single decimal point '.'. The trusted-UI renderer treats
    // anything else as garbage; a stray byte from a future bug could
    // be drawn as e.g. control-character glyph noise on the OLED.
    let cases: &[(U256, u32, u32, bool)] = &[
        (U256::zero(), 18, 6, false),
        (u256_from_u64(1), 18, 18, false),
        (pow10_u256(18), 18, 6, true),
        (U256([0xffu8; 32]), 0, 0, false),
        (u256_from_u64(3_500_000_000_000_000_000), 18, 3, true),
    ];
    for (v, dec, frac, trim) in cases.iter().copied() {
        let mut out = [0u8; 96];
        let n = v.format_decimal(dec, frac, trim, &mut out).unwrap();
        for &b in &out[..n] {
            assert!(
                b == b'.' || (b'0'..=b'9').contains(&b),
                "non-ASCII byte 0x{b:02x} in format_decimal output",
            );
        }
        // Exactly zero or one decimal points.
        let dot_count = out[..n].iter().filter(|&&b| b == b'.').count();
        assert!(dot_count <= 1, "more than one '.' in {:?}", &out[..n]);
    }
}

#[test]
fn negative_format_decimal_no_leading_zeros_on_integer_part() {
    // ASSUMPTION: "001234" is forbidden. Only the canonical leading
    // digit (or single "0" for zero values) is allowed before the
    // decimal point.
    let cases = [
        (u256_from_u64(1234), 0u32, 0u32, false, "1234"),
        (u256_from_u64(1), 0, 0, false, "1"),
        (U256::zero(), 0, 0, false, "0"),
    ];
    for (v, dec, frac, trim, expect) in cases {
        let s = format_to_string(&v, dec, frac, trim).unwrap();
        assert_eq!(s, expect);
        // Explicit leading-zero check on the integer part.
        if let Some(dot) = s.find('.') {
            let int_part = &s[..dot];
            assert!(
                int_part == "0" || !int_part.starts_with('0'),
                "leading zero in integer part of {s:?}",
            );
        } else {
            assert!(
                s == "0" || !s.starts_with('0'),
                "leading zero in {s:?}",
            );
        }
    }
}

#[test]
fn negative_format_decimal_trim_keeps_significant_digits_intact() {
    // Regression guard: trimming must only remove TRAILING zeros, never
    // touch significant digits. 1 wei in 18-decimal frame is ALL
    // significant fractional zeros except the last digit; trim must
    // keep them.
    let v = u256_from_u64(1);
    let s = format_to_string(&v, 18, 18, true).unwrap();
    assert_eq!(s, "0.000000000000000001");
}

#[test]
fn negative_format_decimal_trim_collapses_all_zero_fraction() {
    // value with zero fractional component → "5" not "5.0".
    let v = u256_from_u64(5);
    let s = format_to_string(&v, 0, 3, true).unwrap();
    assert_eq!(s, "5");
}

#[test]
fn negative_format_decimal_whale_amount_overflow_buffer_unchanged() {
    // Defends the same property as the in-crate
    // `format_huge_integer_returns_none_on_tight_buffer` test, but
    // additionally asserts that the buffer is bytewise unchanged so a
    // panicky display layer doesn't accidentally render stale bytes.
    let raw: u128 = 1_234_567_890_123_000_000_000_000_000_000;
    let mut bytes = [0u8; 32];
    bytes[16..32].copy_from_slice(&raw.to_be_bytes());
    let v = U256(bytes);
    let sentinel = 0x5au8;
    let mut buf = [sentinel; 12];
    assert_eq!(v.format_decimal(18, 6, true, &mut buf), None);
    assert_eq!(buf, [sentinel; 12]);
}

#[test]
fn negative_format_decimal_does_not_emit_decimal_point_when_no_fraction() {
    // frac_digits = 0 → never emit a '.'.
    let v = u256_from_u64(42);
    let s = format_to_string(&v, 18, 0, false).unwrap();
    assert_eq!(s, "0");
    assert!(!s.contains('.'));
}

// ---------------------------------------------------------------------------
// Round-trip with parser-produced U256 values
// ---------------------------------------------------------------------------

#[test]
fn positive_round_trip_u64_through_u256_format() {
    // For any plain u64 value, formatting with decimals=0 must yield
    // the same digits as `format!("{value}")`. Property-style spot check.
    let cases: &[u64] = &[
        0, 1, 9, 10, 99, 100, 1_000_000, 999_999_999, u64::MAX,
    ];
    for &n in cases {
        let v = u256_from_u64(n);
        let s = format_to_string(&v, 0, 0, false).unwrap();
        assert_eq!(s, format!("{n}"));
    }
}
