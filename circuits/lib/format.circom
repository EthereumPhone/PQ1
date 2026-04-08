pragma circom 2.0.0;

//
// ─────────────────────────────────────────────────────────────────────
// circuits/lib/format.circom — uint256 → fixed-width ASCII formatter
// ─────────────────────────────────────────────────────────────────────
//
// In-circuit conversion of a uint256 (raw on-chain amount, already
// pre-scaled to MAX_DECIMALS via the registry's `scale_factor`) into
// a fixed-width ASCII string of the form
//
//      "  XXXXXX.YYYY"
//
// where:
//
//   * the integer part is MAX_INT_DIGITS chars wide, with leading
//     zeros replaced by ASCII space (0x20) so the user actually sees
//     something like "  1234.5000" instead of "001234.5000";
//   * the fractional part is FRAC_DIGITS chars wide, padded on the
//     RIGHT with trailing '0's (so 0.5 always shows up as "0.5000").
//
// Output length is MAX_INT_DIGITS + 1 + FRAC_DIGITS bytes (the +1 is
// the literal '.').
//
// Constraint principle (lifted from circuits/aave_v3/formatting.circom
// but specialized for the trimmed-leading-zero display):
//
//   raw_amount * scale_factor
//     == int_value * 10^MAX_DECIMALS
//      + frac_value * 10^(MAX_DECIMALS - FRAC_DIGITS)
//      + remainder
//   0 <= remainder < 10^(MAX_DECIMALS - FRAC_DIGITS)
//
// In other words: the prover provides
//
//   int_digits[MAX_INT_DIGITS]      → big-endian decimal digits of
//                                     the integer part
//   frac_digits[FRAC_DIGITS]        → big-endian decimal digits of
//                                     the displayed fraction
//   n_leading_zeros                 → how many of int_digits are
//                                     leading-zero pad
//   remainder                       → the un-displayed sub-frac
//                                     part of the raw amount
//
// and the circuit checks recomposition + digit-range + leading-zero
// consistency. The amount being signed is the FULL raw_amount (every
// byte is part of the canonical Poseidon binding); the formatted
// display is allowed to TRUNCATE precision at FRAC_DIGITS as long as
// the truncation matches the actual on-chain value.
//
// For v1 (clear-signing CowSwap orders) we use:
//
//      MAX_INT_DIGITS = 6
//      FRAC_DIGITS    = 4
//      MAX_DECIMALS   = 18
//
// → 6 + 1 + 4 = 11 chars per amount, leaving room for a space and a
//   4-char symbol on a 16-char display line.
//
// Constraint footprint per FormatTrimmedAmount instance:
//   ~ 6 IsDigit (int)  + 4 IsDigit (frac)
//   + 6 IsZero (count_lz one-hot)
//   + 1 quadratic recomposition equation
//   + ~30 mux + range constraints
//   ≈ 200 R1CS constraints

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// IsDigit(x) — constrain x ∈ [0, 9].
template IsDigit() {
    signal input  x;
    signal output ok;

    component bits = Num2Bits(4);    // forces x ∈ [0, 15]
    bits.in <== x;

    component lt = LessThan(4);
    lt.in[0] <== x;
    lt.in[1] <== 10;
    ok <== lt.out;
}

// AllDigits(N) — every element in `digits[N]` is in [0, 9].
template AllDigits(N) {
    signal input  digits[N];
    signal output ok;

    component checks[N];
    signal acc[N+1];
    acc[0] <== 1;
    for (var i = 0; i < N; i++) {
        checks[i] = IsDigit();
        checks[i].x <== digits[i];
        acc[i+1] <== acc[i] * checks[i].ok;
    }
    ok <== acc[N];
}

// CountLeadingZeros(N) — verify that exactly the first `n_lz` of
// `digits[N]` are zero AND emit a `is_lz[i]` one-hot/cumulative
// selector for downstream "blank-out leading zeros" muxing.
//
// is_lz[i] == 1 iff i < n_lz, so the caller can replace ASCII '0'
// with ASCII space using a single multiplication per byte.
//
// We do NOT enforce that `digits[n_lz]` is non-zero, so the all-zero
// amount (0.0000) just trims to "    " + "0.0000" = "      0.0000",
// which is the most natural rendering.
template CountLeadingZeros(N) {
    signal input  digits[N];
    signal input  n_lz;

    signal output is_lz[N];
    signal output ok;

    // sel[i] = 1 if i == n_lz
    component eqs[N+1];
    signal sel[N+1];
    for (var i = 0; i <= N; i++) {
        eqs[i] = IsZero();
        eqs[i].in <== n_lz - i;
        sel[i] <== eqs[i].out;
    }

    // cum[i] = sum_{j<=i} sel[j], so cum[i] flips from 0 to 1
    // exactly at i == n_lz. is_lz[i] == 1 - cum[i] (so == 1 iff
    // i < n_lz).
    signal cum[N+1];
    cum[0] <== sel[0];
    for (var i = 0; i < N; i++) {
        cum[i+1] <== cum[i] + sel[i+1];
        is_lz[i] <== 1 - cum[i];
    }

    // Enforce: digits[i] == 0 for every i < n_lz.
    //   is_lz[i] * digits[i] === 0
    signal lz_check[N];
    component check_isz[N];
    signal ok_acc[N+1];
    ok_acc[0] <== 1;
    for (var i = 0; i < N; i++) {
        lz_check[i] <== is_lz[i] * digits[i];
        check_isz[i] = IsZero();
        check_isz[i].in <== lz_check[i];
        ok_acc[i+1] <== ok_acc[i] * check_isz[i].out;
    }

    // Range: 0 <= n_lz <= N.
    component range = LessThan(8);   // N <= 16 in practice
    range.in[0] <== n_lz;
    range.in[1] <== N + 1;

    ok <== ok_acc[N] * range.out;
}

// FormatTrimmedAmount(MAX_INT_DIGITS, FRAC_DIGITS, MAX_DECIMALS) —
// produces a fixed-width ASCII output of length
// `MAX_INT_DIGITS + 1 + FRAC_DIGITS` from a raw uint256 amount.
//
// Inputs (signals):
//   raw_amount   : the on-chain uint256 value
//   scale_factor : 10^(MAX_DECIMALS - decimals_of_token)
//                  (provided by Erc20Registry)
//   int_digits[MAX_INT_DIGITS]   : big-endian integer digits (witness)
//   frac_digits[FRAC_DIGITS]     : big-endian frac digits     (witness)
//   n_leading_zeros              : count of leading int zeros (witness)
//   remainder                    : the un-displayed sub-frac
//                                  part of raw * scale (witness)
//
// Outputs:
//   ascii[MAX_INT_DIGITS + 1 + FRAC_DIGITS] : ASCII bytes
//   ok                                       : 1 if every constraint
//                                              passes
template FormatTrimmedAmount(MAX_INT_DIGITS, FRAC_DIGITS, MAX_DECIMALS) {
    var ASCII_LEN = MAX_INT_DIGITS + 1 + FRAC_DIGITS;

    signal input  raw_amount;
    signal input  scale_factor;
    signal input  int_digits[MAX_INT_DIGITS];
    signal input  frac_digits[FRAC_DIGITS];
    signal input  n_leading_zeros;
    signal input  remainder;

    signal output ascii[ASCII_LEN];
    signal output ok;

    // ── 1. Range-check digits ───────────────────────────────────────
    component int_check  = AllDigits(MAX_INT_DIGITS);
    component frac_check = AllDigits(FRAC_DIGITS);
    for (var i = 0; i < MAX_INT_DIGITS; i++) int_check.digits[i]  <== int_digits[i];
    for (var i = 0; i < FRAC_DIGITS;    i++) frac_check.digits[i] <== frac_digits[i];

    // ── 2. Recompose int and frac ───────────────────────────────────
    signal int_acc[MAX_INT_DIGITS+1];
    int_acc[0] <== 0;
    for (var i = 0; i < MAX_INT_DIGITS; i++) {
        int_acc[i+1] <== int_acc[i] * 10 + int_digits[i];
    }
    signal int_value;
    int_value <== int_acc[MAX_INT_DIGITS];

    signal frac_acc[FRAC_DIGITS+1];
    frac_acc[0] <== 0;
    for (var i = 0; i < FRAC_DIGITS; i++) {
        frac_acc[i+1] <== frac_acc[i] * 10 + frac_digits[i];
    }
    signal frac_value;
    frac_value <== frac_acc[FRAC_DIGITS];

    // ── 3. Compile-time powers of ten ───────────────────────────────
    var pow_max = 1;
    for (var i = 0; i < MAX_DECIMALS; i++) pow_max = pow_max * 10;
    var pow_skip = 1;
    for (var i = 0; i < MAX_DECIMALS - FRAC_DIGITS; i++) pow_skip = pow_skip * 10;

    // ── 4. Recomposition equation ───────────────────────────────────
    //   raw_amount * scale_factor
    //     == int_value * pow_max + frac_value * pow_skip + remainder
    //
    //   remainder === 0   (STRICT: v3 rejects sub-FRAC_DIGITS precision)
    //
    // v2 allowed `0 ≤ remainder < pow_skip`, which silently truncated
    // sub-10^-4 precision and rendered it as "0.0000". That's a
    // clear-signing footgun — a user confirming "0.0000 WETH" would be
    // signing any amount below 10^-4 WETH. v3 enforces `remainder === 0`
    // so the prover has to round-to-FRAC_DIGITS explicitly (or the proof
    // construction fails).
    //
    // `remainder` is still declared as a signal so existing callers
    // don't break; it's simply constrained to 0 below.
    signal scaled;
    scaled <== raw_amount * scale_factor;

    signal int_part;
    int_part <== int_value * pow_max;

    signal frac_part;
    frac_part <== frac_value * pow_skip;

    component recomp_isz = IsZero();
    recomp_isz.in <== scaled - int_part - frac_part - remainder;
    signal recomp_ok;
    recomp_ok <== recomp_isz.out;

    // Force the hidden sub-frac residue to exactly zero.
    component rem_isz = IsZero();
    rem_isz.in <== remainder;
    signal rem_ok;
    rem_ok <== rem_isz.out;

    // ── 5. Leading-zero count + blank-out selector ──────────────────
    component count_lz = CountLeadingZeros(MAX_INT_DIGITS);
    for (var i = 0; i < MAX_INT_DIGITS; i++) {
        count_lz.digits[i] <== int_digits[i];
    }
    count_lz.n_lz <== n_leading_zeros;

    // n_lz must be at most MAX_INT_DIGITS - 1 (we always want at
    // least one digit visible — even for zero amounts, "0" should
    // show). For raw_amount=0 the prover sets n_lz=MAX_INT_DIGITS-1.
    component nlz_lt = LessThan(8);
    nlz_lt.in[0] <== n_leading_zeros;
    nlz_lt.in[1] <== MAX_INT_DIGITS;
    signal nlz_ok;
    nlz_ok <== nlz_lt.out;

    // ── 6. ASCII assembly ───────────────────────────────────────────
    //
    // For each int digit:
    //   ascii[i] = is_lz[i] ? ' ' : ('0' + digit)
    //            = digit + 48 + is_lz[i] * (32 - 48 - digit)
    //            = digit + 48 + is_lz[i] * (-16 - digit)
    //
    // Concretely:
    //   if is_lz=1: ascii = digit + 48 + (-16 - digit) = 32   ✓
    //   if is_lz=0: ascii = digit + 48                     ✓
    signal int_ascii[MAX_INT_DIGITS];
    signal blank_term[MAX_INT_DIGITS];
    for (var i = 0; i < MAX_INT_DIGITS; i++) {
        // Quadratic: is_lz[i] * (digit + 16). Subtract from (digit+48).
        blank_term[i] <== count_lz.is_lz[i] * (int_digits[i] + 16);
        int_ascii[i] <== int_digits[i] + 48 - blank_term[i];
        ascii[i]     <== int_ascii[i];
    }

    // The decimal point.
    ascii[MAX_INT_DIGITS] <== 46;   // '.'

    // Frac digits — never trimmed.
    for (var i = 0; i < FRAC_DIGITS; i++) {
        ascii[MAX_INT_DIGITS + 1 + i] <== frac_digits[i] + 48;
    }

    // ── 7. ok ───────────────────────────────────────────────────────
    signal ok_a; ok_a <== int_check.ok * frac_check.ok;
    signal ok_b; ok_b <== ok_a * recomp_ok;
    signal ok_c; ok_c <== ok_b * rem_ok;
    signal ok_d; ok_d <== ok_c * count_lz.ok;
    ok <== ok_d * nlz_ok;
}
