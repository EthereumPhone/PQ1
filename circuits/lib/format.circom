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
//   raw_amount        : the on-chain uint256 value
//   scale_factor      : 10^(MAX_DECIMALS - decimals_of_token)
//                       (provided by Erc20Registry)
//   int_digits[]      : big-endian integer digits (witness)
//   frac_digits[]     : big-endian frac digits     (witness)
//   n_leading_zeros   : count of leading int zeros (witness)
//   remainder         : the un-displayed sub-frac
//                       part of raw * scale (witness)
//   is_sub_precision  : 0 = normal strict-precision path,
//                       1 = amount is non-zero but below 10^-FRAC_DIGITS.
//                       In sub-precision mode the circuit enforces
//                       int_value==0 && frac_value==0 && 0<scaled<pow_skip
//                       and outputs the fixed ASCII
//                       "    <0.XXXX    " (15 bytes) — where XXXX
//                       is `FRAC_DIGITS`-wide and consists of
//                       (FRAC_DIGITS-1) zeros followed by a '1'.
//                       This prevents the v2 "0.0000 hides 0.00005"
//                       footgun while still allowing a visible,
//                       trustless confirmation of "amount too small
//                       to display precisely — it's below the 10^-FRAC
//                       threshold".
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
    signal input  is_sub_precision;

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
    // Two modes:
    //
    //   (a) Normal (is_sub_precision == 0): enforce remainder === 0.
    //       Prover must round-to-FRAC_DIGITS explicitly. Rejects the
    //       v2 "0.0000 hides 0.00005" footgun.
    //
    //   (b) Sub-precision (is_sub_precision == 1): permit remainder > 0,
    //       but require int_value == 0 AND frac_value == 0 AND
    //       0 < scaled < pow_skip. The resulting ASCII is the fixed
    //       "    <0.XXXX    " string (see step 7), which is visibly
    //       distinct from "0.0000" so the user can tell at a glance
    //       that the amount is non-zero but below the display
    //       threshold. Without the upper bound on `scaled`, an
    //       attacker could flip the flag on a big amount and hide
    //       everything behind "<0.0001" — the bound is what makes this
    //       mode trustworthy.
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

    // is_sub_precision must be binary.
    signal sp_bin_check;
    sp_bin_check <== is_sub_precision * (is_sub_precision - 1);
    sp_bin_check === 0;

    // v3.1: allow non-zero remainder in BOTH normal and sub-precision
    // modes. The unconditional `remainder < pow_skip` bound (step below)
    // is what keeps this safe — with remainder capped below the display
    // threshold, the (int, frac, remainder) decomposition is unique
    // given `scaled`, so no prover can shift value out of int/frac into
    // remainder to under-report what the display shows.
    //
    // In normal mode, non-zero remainder means the displayed int+frac
    // is truncated (rounded DOWN to FRAC_DIGITS precision). Max hidden
    // value per trade = pow_skip - 1 = 10^(MAX_DECIMALS - FRAC_DIGITS) - 1
    // of the token — 10^-FRAC_DIGITS units. That's $0.30 on ETH-priced
    // tokens and $0.0001 on USDC-priced tokens: economically bounded
    // and the standard precision tradeoff every hardware wallet makes.
    //
    // The sub-precision mode (int=frac=0, "<0.0001" render) still
    // exists for the specific case where the entire scaled amount fits
    // below the display threshold — that's the only path where the
    // user would otherwise see the "0.0000" footgun.

    // Sub-precision invariants. Each is gated by is_sub_precision so it
    // only kicks in when the prover claims sub-precision:
    //   (i) int_value * is_sub_precision === 0
    //  (ii) frac_value * is_sub_precision === 0
    // (iii) is_sub_precision == 1 ⇒ scaled > 0 (i.e. amount is
    //       non-zero — otherwise the whole point of the "<0.0001"
    //       render is defeated: zero is zero).
    //  (iv) is_sub_precision == 1 ⇒ scaled < pow_skip (≡ bound the
    //       amount to the display threshold).
    signal int_gated;
    int_gated <== int_value * is_sub_precision;
    component int_gated_isz = IsZero();
    int_gated_isz.in <== int_gated;
    signal int_gated_ok;
    int_gated_ok <== int_gated_isz.out;

    signal frac_gated;
    frac_gated <== frac_value * is_sub_precision;
    component frac_gated_isz = IsZero();
    frac_gated_isz.in <== frac_gated;
    signal frac_gated_ok;
    frac_gated_ok <== frac_gated_isz.out;

    // Range-check `remainder` to 48 bits. In normal mode `remainder ===
    // 0` so this is trivially satisfied; in sub-precision mode it
    // bounds `remainder` (and hence `scaled`, since int=frac=0 forces
    // scaled=remainder via the recomposition) below 2^48, which covers
    // pow_skip=10^14 with plenty of headroom. Using Num2Bits on
    // `remainder` rather than `scaled` avoids the overflow that would
    // otherwise occur in normal mode for large legit amounts where
    // `scaled = raw * scale_factor` easily exceeds 2^60.
    component rem_bits = Num2Bits(48);
    rem_bits.in <== remainder;

    // "scaled > 0" in sub-precision mode ≡ "remainder > 0", because
    // the recomposition forces scaled = 0 + 0 + remainder when
    // int=frac=0. We check this via IsZero on `remainder` gated by
    // the sub-precision flag.
    component rem_is_zero = IsZero();
    rem_is_zero.in <== remainder;
    signal sp_zero_violation;
    sp_zero_violation <== is_sub_precision * rem_is_zero.out;
    component sp_zero_isz = IsZero();
    sp_zero_isz.in <== sp_zero_violation;
    signal sp_nonzero_ok;
    sp_nonzero_ok <== sp_zero_isz.out;

    // UNCONDITIONAL: remainder < pow_skip. This is the load-bearing
    // invariant that makes the relaxed-remainder design safe. With
    // `remainder ∈ [0, pow_skip)` forced in every mode, the
    // `(int, frac, remainder)` decomposition of a given `scaled` is
    // unique — a prover cannot shift value out of `int`/`frac` into
    // the hidden `remainder` to under-report the displayed amount.
    // Drop this check and you open the "display 1.4500 while actually
    // signing 1.5000" attack ($150 loss per ETH).
    component rem_lt_skip = LessThan(48);
    rem_lt_skip.in[0] <== remainder;
    rem_lt_skip.in[1] <== pow_skip;
    rem_lt_skip.out === 1;

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
    // The output byte at position `i` is muxed between two sources:
    //
    //   normal_ascii[i]  — the standard " 1000.0000"-style rendering,
    //                      with leading integer zeros blanked to space.
    //   sub_ascii[i]     — the fixed "    <0.X...X    " rendering
    //                      where the fractional part is
    //                      (FRAC_DIGITS - 1) zeros followed by a '1'.
    //                      Occupies the full ASCII_LEN width.
    //
    //   ascii[i] = normal_ascii[i] + is_sub_precision *
    //              (sub_ascii[i] - normal_ascii[i])
    //
    // which simplifies to normal when is_sub_precision==0 and sub when ==1.
    //
    // For the normal side:
    //   int_ascii[i] = is_lz[i] ? ' ' : ('0' + digit)
    //                = digit + 48 + is_lz[i] * (-16 - digit)
    //
    // For the sub-precision side, precompute the constant byte string
    // as a compile-time template var.
    //
    //   ASCII_LEN = MAX_INT_DIGITS + 1 + FRAC_DIGITS
    //   For MAX_INT_DIGITS=10, FRAC_DIGITS=4 → 15 bytes:
    //     "    <0.0001    "
    //     index: 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14
    //     bytes: ' '' '' '' ''<''0''.''0''0''0''1'' '' '' '' '
    //            32 32 32 32 60 48 46 48 48 48 49 32 32 32 32
    //
    // Building the frac portion dynamically: FRAC_DIGITS zeros with
    // the last one replaced by '1'. For the integer side we leave
    // `MAX_INT_DIGITS - 2` spaces, then "<0" (2 bytes). So:
    //   sub_ascii[0 .. MAX_INT_DIGITS-2]          = ' '
    //   sub_ascii[MAX_INT_DIGITS - 2]             = '<'
    //   sub_ascii[MAX_INT_DIGITS - 1]             = '0'
    //   sub_ascii[MAX_INT_DIGITS]                 = '.'
    //   sub_ascii[MAX_INT_DIGITS+1 .. +FRAC_DIGITS-1] = '0'
    //   sub_ascii[MAX_INT_DIGITS + FRAC_DIGITS]   = '1'
    //
    // With MAX_INT_DIGITS=10, FRAC_DIGITS=4, ASCII_LEN=15:
    //   bytes 0..8   = ' '  (9 spaces) ← wait this gives "         <0.0001"
    //
    // Actually looking again: we want right-aligned "<0.0001" so the
    // '1' sits where the normal last frac digit would be. That already
    // lines up because the '.' is fixed at MAX_INT_DIGITS and the frac
    // area is FRAC_DIGITS wide. So "         <0.0001" (9 spaces + 6
    // chars) has the '<' where the int's last-but-one digit would be.
    // For MAX_INT_DIGITS=10 that is still visually clear.
    var SUB_TEMPLATE[ASCII_LEN];
    for (var i = 0; i < MAX_INT_DIGITS - 2; i++) {
        SUB_TEMPLATE[i] = 32;         // leading spaces
    }
    SUB_TEMPLATE[MAX_INT_DIGITS - 2] = 60;  // '<'
    SUB_TEMPLATE[MAX_INT_DIGITS - 1] = 48;  // '0'
    SUB_TEMPLATE[MAX_INT_DIGITS]     = 46;  // '.'
    for (var i = 0; i < FRAC_DIGITS - 1; i++) {
        SUB_TEMPLATE[MAX_INT_DIGITS + 1 + i] = 48;  // '0'
    }
    SUB_TEMPLATE[MAX_INT_DIGITS + FRAC_DIGITS] = 49;  // '1'

    signal int_ascii[MAX_INT_DIGITS];
    signal blank_term[MAX_INT_DIGITS];
    signal normal_at[ASCII_LEN];
    for (var i = 0; i < MAX_INT_DIGITS; i++) {
        blank_term[i] <== count_lz.is_lz[i] * (int_digits[i] + 16);
        int_ascii[i] <== int_digits[i] + 48 - blank_term[i];
        normal_at[i] <== int_ascii[i];
    }
    normal_at[MAX_INT_DIGITS] <== 46;   // '.'
    for (var i = 0; i < FRAC_DIGITS; i++) {
        normal_at[MAX_INT_DIGITS + 1 + i] <== frac_digits[i] + 48;
    }

    // Mux between normal and sub-precision templates. Every ascii byte
    // is constrained, so a prover cannot smuggle in arbitrary bytes.
    for (var i = 0; i < ASCII_LEN; i++) {
        ascii[i] <== normal_at[i]
                     + is_sub_precision * (SUB_TEMPLATE[i] - normal_at[i]);
    }

    // ── 7. ok ───────────────────────────────────────────────────────
    signal ok_a; ok_a <== int_check.ok * frac_check.ok;
    signal ok_b; ok_b <== ok_a * recomp_ok;
    signal ok_c; ok_c <== ok_b * count_lz.ok;
    signal ok_d; ok_d <== ok_c * nlz_ok;
    signal ok_e; ok_e <== ok_d * int_gated_ok;
    signal ok_f; ok_f <== ok_e * frac_gated_ok;
    ok <== ok_f * sp_nonzero_ok;
    // `rem_lt_skip.out === 1` and `sp_bin_check === 0` are enforced
    // directly above — they don't flow through the `ok` aggregation,
    // but circom still emits them as hard constraints so any witness
    // that violates them fails to generate a valid proof.
}
