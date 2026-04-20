//! Row-level formatting helpers shared by every renderer in this
//! directory. `pub(super)` so only the sibling submodules under
//! `display::` consume them — external crates get the high-level
//! `render_*_pages` entry points.
//!
//! Design rules for every helper in this file:
//!
//! * **Never silently truncate a number.** The OLED is the trusted
//!   display; a truncated value is as dangerous as a wrong one. When
//!   something won't fit, return `false` / `AmountFit::Overflow` and
//!   let the caller render a visible warning.
//! * **No panics on any input** (including attacker-supplied values).
//!   `#![no_std]`, no alloc, no heap.
//! * **Left-aligned, space-padded rows.** Every helper takes a
//!   `&mut [u8; DISPLAY_COLS]` and writes exactly one row's worth of
//!   ASCII. Rows are pre-cleared to `b' '` before any data is written.

use crate::erc20::bundle::Erc20Metadata;
use crate::erc20::calldata::Erc20Call;
use crate::tx::eip1559::U256;
use crate::ui::DISPLAY_COLS;

// ---------------------------------------------------------------------------
// Low-level row primitives
// ---------------------------------------------------------------------------

/// Overwrite `row` with `text`, left-aligned. Truncates to `DISPLAY_COLS`
/// and pads the tail with spaces. Intended for fixed label strings that
/// are known to fit — NEVER feed it attacker-controlled data.
pub(super) fn write_line(row: &mut [u8; DISPLAY_COLS], text: &str) {
    *row = [b' '; DISPLAY_COLS];
    let bytes = text.as_bytes();
    let n = core::cmp::min(bytes.len(), DISPLAY_COLS);
    row[..n].copy_from_slice(&bytes[..n]);
}

/// Append `text` to `row` starting at `pos`. Returns the new write
/// position. Bytes that overflow the row are dropped — caller must
/// check `pos == start + text.len()` if it needs a "fit" guarantee.
fn append(row: &mut [u8; DISPLAY_COLS], pos: usize, text: &[u8]) -> usize {
    let mut p = pos;
    for &b in text {
        if p >= DISPLAY_COLS {
            break;
        }
        row[p] = b;
        p += 1;
    }
    p
}

pub(super) fn hex_nibble(n: u8) -> u8 {
    match n & 0x0f {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

/// Decimal-format a `u64` into `out`. Returns `Some(n)` on success or
/// `None` if the canonical decimal representation does not fit. Unlike
/// the old helper this one refuses to silently truncate.
pub(super) fn format_u64(mut n: u64, out: &mut [u8]) -> Option<usize> {
    if n == 0 {
        if out.is_empty() {
            return None;
        }
        out[0] = b'0';
        return Some(1);
    }
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    if i > out.len() {
        return None;
    }
    for j in 0..i {
        out[j] = buf[i - 1 - j];
    }
    Some(i)
}

// ---------------------------------------------------------------------------
// Amount rendering
// ---------------------------------------------------------------------------

/// Outcome of a width-aware amount render. `Full` means every digit of
/// the value was painted; `Overflow` means the caller must render a
/// truncation banner because even the 2-row fallback couldn't hold the
/// number.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(super) enum AmountFit {
    Full,
    Overflow,
}

/// Try to emit `<amount> <unit>` on a single row.
///
///   * `trim_trailing_zeros = true` for ETH/gwei (shorter form looks
///     cleaner).
///   * `trim_trailing_zeros = false` for ERC-20 token amounts — fixed
///     widths block visual spoofing.
///
/// Returns `true` on success. On failure, the row is left unchanged;
/// caller should fall back to [`write_amount_two_rows`].
pub(super) fn try_write_amount_single_row(
    row: &mut [u8; DISPLAY_COLS],
    value: &U256,
    decimals: u32,
    frac_digits: u32,
    trim_trailing_zeros: bool,
    unit: &str,
) -> bool {
    let unit_bytes = unit.as_bytes();
    // 1 space separator between amount and unit.
    let budget = match DISPLAY_COLS.checked_sub(unit_bytes.len() + 1) {
        Some(b) => b,
        None => return false, // unit alone would overflow row
    };
    let mut tmp = [0u8; 96];
    let n = match value.format_decimal(decimals, frac_digits, trim_trailing_zeros, &mut tmp) {
        Some(n) if n <= budget => n,
        _ => return false,
    };

    *row = [b' '; DISPLAY_COLS];
    row[..n].copy_from_slice(&tmp[..n]);
    row[n] = b' ';
    row[n + 1..n + 1 + unit_bytes.len()].copy_from_slice(unit_bytes);
    true
}

/// Emit `<amount> <unit>` across two rows. The amount's integer part
/// lands on the first row; the fractional tail and the unit go on the
/// second row. This handles amounts whose full decimal representation
/// is up to
///
///     `DISPLAY_COLS + DISPLAY_COLS - unit.len() - 2  ≈ 30 chars`
///
/// which comfortably covers every practical ETH value. For the
/// unrealistic `2^256 - 1 wei` class of inputs the function returns
/// `AmountFit::Overflow` and the caller must paint a banner.
pub(super) fn write_amount_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
    decimals: u32,
    frac_digits: u32,
    trim_trailing_zeros: bool,
    unit: &str,
) -> AmountFit {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    let unit_bytes = unit.as_bytes();

    let mut tmp = [0u8; 96];
    let n = match value.format_decimal(decimals, frac_digits, trim_trailing_zeros, &mut tmp) {
        Some(n) => n,
        None => return AmountFit::Overflow,
    };
    let digits = &tmp[..n];

    // Prefer to split the formatted string at the decimal point so row 1
    // is "<integer>" and row 2 is ".<fraction> <unit>".
    let dot_pos = digits.iter().position(|&b| b == b'.');

    match dot_pos {
        Some(dp) => {
            // Integer part: digits[..dp]. Must fit on row 1 on its own.
            if dp > DISPLAY_COLS {
                return AmountFit::Overflow;
            }
            row1[..dp].copy_from_slice(&digits[..dp]);
            // Row 2: ".<fraction> <unit>"
            let tail = &digits[dp..]; // includes '.'
            let need2 = tail.len() + 1 + unit_bytes.len();
            if need2 > DISPLAY_COLS {
                return AmountFit::Overflow;
            }
            row2[..tail.len()].copy_from_slice(tail);
            row2[tail.len()] = b' ';
            row2[tail.len() + 1..tail.len() + 1 + unit_bytes.len()]
                .copy_from_slice(unit_bytes);
            AmountFit::Full
        }
        None => {
            // Pure integer. Split halfway if needed.
            let need1 = n;
            let need2 = unit_bytes.len();
            if need1 <= DISPLAY_COLS && need2 + 1 <= DISPLAY_COLS {
                // Integer on row 1, unit alone on row 2.
                row1[..need1].copy_from_slice(digits);
                row2[..need2].copy_from_slice(unit_bytes);
                AmountFit::Full
            } else if n <= 2 * DISPLAY_COLS && unit_bytes.len() < DISPLAY_COLS {
                // Split integer across rows, unit takes its own chars on row 2.
                let first = core::cmp::min(n, DISPLAY_COLS);
                row1[..first].copy_from_slice(&digits[..first]);
                let rest = &digits[first..];
                if rest.len() + 1 + unit_bytes.len() > DISPLAY_COLS {
                    return AmountFit::Overflow;
                }
                row2[..rest.len()].copy_from_slice(rest);
                row2[rest.len()] = b' ';
                row2[rest.len() + 1..rest.len() + 1 + unit_bytes.len()]
                    .copy_from_slice(unit_bytes);
                AmountFit::Full
            } else {
                AmountFit::Overflow
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Address rendering — FULL 40 hex chars across three rows
// ---------------------------------------------------------------------------

/// Paint the full 40-hex representation of a 20-byte address across
/// three rows of 16 columns:
///
/// ```text
///   row1: "0x"  + first  7 bytes (14 hex chars, 16 col total)
///   row2: next  8 bytes (16 hex chars, 16 col total)
///   row3: last  5 bytes (10 hex chars + 6 space pad, 16 col total)
/// ```
///
/// Showing the full address eliminates the old collision window the
/// truncated 7+8 hex layout exposed (an attacker could brute-force a
/// 5-byte middle to make a hostile address look identical on screen).
pub(super) fn write_addr_full(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    row3: &mut [u8; DISPLAY_COLS],
    addr: &[u8; 20],
) {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    *row3 = [b' '; DISPLAY_COLS];

    // Row 1: "0x" + bytes 0..7
    row1[0] = b'0';
    row1[1] = b'x';
    for i in 0..7 {
        row1[2 + i * 2] = hex_nibble(addr[i] >> 4);
        row1[2 + i * 2 + 1] = hex_nibble(addr[i] & 0x0f);
    }
    // Row 2: bytes 7..15
    for i in 0..8 {
        let b = addr[7 + i];
        row2[i * 2] = hex_nibble(b >> 4);
        row2[i * 2 + 1] = hex_nibble(b & 0x0f);
    }
    // Row 3: bytes 15..20 — 5 bytes = 10 hex chars, padded to 16
    for i in 0..5 {
        let b = addr[15 + i];
        row3[i * 2] = hex_nibble(b >> 4);
        row3[i * 2 + 1] = hex_nibble(b & 0x0f);
    }
}

// ---------------------------------------------------------------------------
// Chain identification
// ---------------------------------------------------------------------------

/// Human-readable chain label. The secure world recognises only the
/// ids on this list; anything else renders as `(UNVERIFIED)` so the
/// user is visibly warned that the firmware could not confirm what
/// network this transaction targets.
pub(super) fn chain_name(chain_id: u64) -> &'static str {
    match chain_id {
        1 => "(Mainnet)",
        10 => "(Optimism)",
        56 => "(BSC)",
        100 => "(Gnosis)",
        137 => "(Polygon)",
        8453 => "(Base)",
        42161 => "(Arbitrum)",
        11155111 => "(Sepolia)",
        84532 => "(BaseSepolia)",
        _ => "(UNVERIFIED)",
    }
}

pub(super) fn write_chain(row: &mut [u8; DISPLAY_COLS], chain_id: u64) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Chain: ";
    let mut pos = append(row, 0, prefix);
    let mut tmp = [0u8; 20];
    match format_u64(chain_id, &mut tmp) {
        Some(n) if pos + n <= DISPLAY_COLS => {
            row[pos..pos + n].copy_from_slice(&tmp[..n]);
            pos += n;
        }
        _ => {
            // Chain id doesn't even fit as decimal — put a marker.
            pos = append(row, pos, b"!OVF");
        }
    }
    let _ = pos;
}

// ---------------------------------------------------------------------------
// ETH / gwei / gas formatting
// ---------------------------------------------------------------------------

/// Paint an ETH value across (up to) two rows. Trailing zeros are
/// trimmed because ETH amounts are self-describing.
///
/// Row 1 carries the integer portion; row 2 carries the fractional
/// tail plus "ETH". The helper also short-circuits to a single row
/// when the whole thing fits. Returns `AmountFit::Overflow` for
/// pathological values — a 60+ digit integer can't be rendered, and
/// the caller should refuse to sign.
pub(super) fn write_eth_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
) -> AmountFit {
    // Try single-row first with progressively smaller frac digits to
    // give users the most precision that fits.
    for &frac in &[6u32, 4, 2, 0] {
        if try_write_amount_single_row(row1, value, 18, frac, true, "ETH") {
            *row2 = [b' '; DISPLAY_COLS];
            return AmountFit::Full;
        }
    }
    // 2-row fallback, full 18-decimal precision with trim.
    write_amount_two_rows(row1, row2, value, 18, 18, true, "ETH")
}

/// Paint a gas-price value in gwei on a single row. Uses 3 fractional
/// digits by default; degrades precision if the integer portion needs
/// more room. Returns `false` if even the integer form doesn't fit —
/// in practice only possible for attacker-crafted 2^256-class inputs.
pub(super) fn write_gwei(row: &mut [u8; DISPLAY_COLS], value: &U256) -> bool {
    for &frac in &[3u32, 2, 1, 0] {
        if try_write_amount_single_row(row, value, 9, frac, true, "gwei") {
            return true;
        }
    }
    // Last-ditch: raw wei as integer, labelled "wei". Prevents a silent
    // gap on the screen; the user sees an unexpectedly large number.
    for &frac in &[0u32] {
        if try_write_amount_single_row(row, value, 0, frac, true, "wei") {
            return true;
        }
    }
    write_line(row, "!OVERFLOW");
    false
}

/// "(gas: N)" limited to a single row. For gas limits that don't fit
/// in decimal on 16 cols (> 10^15-ish) we emit "(gas: !OVF)" — the
/// attacker-control path that would trip this is already a fee-bomb.
pub(super) fn write_gas(row: &mut [u8; DISPLAY_COLS], gas: u64) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"(gas: ");
    let mut tmp = [0u8; 20];
    match format_u64(gas, &mut tmp) {
        Some(n) if pos + n + 1 <= DISPLAY_COLS => {
            row[pos..pos + n].copy_from_slice(&tmp[..n]);
            pos += n;
        }
        _ => {
            pos = append(row, pos, b"!OVF");
        }
    }
    if pos < DISPLAY_COLS {
        row[pos] = b')';
    }
}

/// "Tip: N gwei" on a single row. Same graceful degradation as
/// [`write_gwei`].
pub(super) fn write_tip_row(row: &mut [u8; DISPLAY_COLS], tip: &U256) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"Tip: ");
    let mut tmp = [0u8; 96];
    let mut wrote = false;
    for &frac in &[3u32, 2, 1, 0] {
        if let Some(n) = tip.format_decimal(9, frac, true, &mut tmp) {
            if pos + n + 5 <= DISPLAY_COLS {
                row[pos..pos + n].copy_from_slice(&tmp[..n]);
                pos += n;
                pos = append(row, pos, b" gwei");
                let _ = pos;
                wrote = true;
                break;
            }
        }
    }
    if !wrote {
        let _ = append(row, 5, b"!OVF");
    }
}

/// "Max: X ETH" worst-case fee budget on a single row. Computed as
/// `max_fee_per_gas * gas_limit`. Silently clamps to U256::MAX on
/// multiplication overflow; the caller sees a suspiciously huge value
/// rather than a wrong-by-modulus one.
pub(super) fn write_fee_budget_row(
    row: &mut [u8; DISPLAY_COLS],
    max_fee_per_gas: &U256,
    gas_limit: u64,
) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"Max: ");
    let (budget, _overflow) = max_fee_per_gas.saturating_mul_u64(gas_limit);
    let mut tmp = [0u8; 96];
    let mut wrote = false;
    for &frac in &[4u32, 3, 2, 1, 0] {
        if let Some(n) = budget.format_decimal(18, frac, true, &mut tmp) {
            if pos + n + 4 <= DISPLAY_COLS {
                row[pos..pos + n].copy_from_slice(&tmp[..n]);
                pos += n;
                pos = append(row, pos, b" ETH");
                let _ = pos;
                wrote = true;
                break;
            }
        }
    }
    if !wrote {
        let _ = append(row, 5, b"!OVF");
    }
}

pub(super) fn write_nonce_row(row: &mut [u8; DISPLAY_COLS], nonce: u64) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"Nonce: ");
    let mut tmp = [0u8; 20];
    match format_u64(nonce, &mut tmp) {
        Some(n) if pos + n <= DISPLAY_COLS => {
            row[pos..pos + n].copy_from_slice(&tmp[..n]);
            pos += n;
        }
        _ => {
            let _ = append(row, pos, b"!OVF");
            return;
        }
    }
    let _ = pos;
}

pub(super) fn write_selector_row(row: &mut [u8; DISPLAY_COLS], data: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"Sel: ");
    if data.len() >= 4 {
        if pos + 10 <= DISPLAY_COLS {
            row[pos] = b'0';
            row[pos + 1] = b'x';
            pos += 2;
            for i in 0..4 {
                row[pos] = hex_nibble(data[i] >> 4);
                row[pos + 1] = hex_nibble(data[i] & 0x0f);
                pos += 2;
            }
        }
    } else {
        let _ = append(row, pos, b"(none)");
    }
}

pub(super) fn write_data_len_row(row: &mut [u8; DISPLAY_COLS], len: usize) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"Data: ");
    let mut tmp = [0u8; 20];
    match format_u64(len as u64, &mut tmp) {
        Some(n) if pos + n + 2 <= DISPLAY_COLS => {
            row[pos..pos + n].copy_from_slice(&tmp[..n]);
            pos += n;
            let _ = append(row, pos, b" B");
        }
        _ => {
            let _ = append(row, pos, b"!OVF");
        }
    }
}

/// Render the first 7 and last 6 bytes of `hash` as
/// "0x<14 hex>...<12 hex>" across two rows. Used on the blind-sign
/// page so the user can compare a dapp-shown calldata hash against
/// what the wallet is actually going to sign.
pub(super) fn write_calldata_hash_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    hash: &[u8; 32],
) {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    row1[0] = b'0';
    row1[1] = b'x';
    for i in 0..7 {
        row1[2 + i * 2] = hex_nibble(hash[i] >> 4);
        row1[2 + i * 2 + 1] = hex_nibble(hash[i] & 0x0f);
    }
    row2[0] = b'.';
    row2[1] = b'.';
    row2[2] = b'.';
    row2[3] = b' ';
    for i in 0..6 {
        let b = hash[26 + i];
        row2[4 + i * 2] = hex_nibble(b >> 4);
        row2[4 + i * 2 + 1] = hex_nibble(b & 0x0f);
    }
}

// ---------------------------------------------------------------------------
// ERC-20 specific
// ---------------------------------------------------------------------------

pub(super) fn write_erc20_header(
    row: &mut [u8; DISPLAY_COLS],
    call: &Erc20Call,
    meta: &Erc20Metadata<'_>,
) {
    *row = [b' '; DISPLAY_COLS];
    let verb: &[u8] = match call {
        Erc20Call::Transfer { .. } => b"Send ",
        Erc20Call::TransferFrom { .. } => b"From ",
        Erc20Call::Approve { .. } => b"Approve ",
    };
    let mut pos = append(row, 0, verb);
    let symbol = meta.symbol;
    let copy = core::cmp::min(symbol.len(), DISPLAY_COLS.saturating_sub(pos));
    if copy > 0 {
        row[pos..pos + copy].copy_from_slice(&symbol[..copy]);
    }
}

pub(super) fn write_token_name(row: &mut [u8; DISPLAY_COLS], meta: &Erc20Metadata<'_>) {
    *row = [b' '; DISPLAY_COLS];
    let copy = core::cmp::min(meta.name.len(), DISPLAY_COLS);
    row[..copy].copy_from_slice(&meta.name[..copy]);
}

/// Render a token amount across up to 2 rows, fixed-width (no
/// trailing-zero trim) so visual-spoofing attacks can't succeed. If
/// the amount overflows both rows the function returns
/// `AmountFit::Overflow` and the caller renders a banner.
pub(super) fn write_token_amount_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    amount: &U256,
    meta: &Erc20Metadata<'_>,
) -> AmountFit {
    // Mirror format_decimal's "decimals-bounded fractional width":
    // frac_digits = min(decimals, 6). For 0-decimal tokens we collapse
    // to pure integer.
    let decimals = meta.decimals as u32;
    let frac = core::cmp::min(decimals, 6);
    let unit_bytes = meta.symbol;

    // Try single row first.
    if single_row_amount_fixed(row1, amount, decimals, frac, unit_bytes) {
        *row2 = [b' '; DISPLAY_COLS];
        return AmountFit::Full;
    }

    // 2-row fallback. Symbol can be up to MAX_DISPLAY_FIELD = 64 bytes
    // from the bundle, but we trust only the first DISPLAY_COLS-1 of
    // it on screen.
    write_amount_two_rows_bytes(row1, row2, amount, decimals, frac, false, unit_bytes)
}

fn single_row_amount_fixed(
    row: &mut [u8; DISPLAY_COLS],
    value: &U256,
    decimals: u32,
    frac: u32,
    unit_bytes: &[u8],
) -> bool {
    let budget = match DISPLAY_COLS.checked_sub(unit_bytes.len() + 1) {
        Some(b) => b,
        None => return false,
    };
    let mut tmp = [0u8; 96];
    let n = match value.format_decimal(decimals, frac, false, &mut tmp) {
        Some(n) if n <= budget => n,
        _ => return false,
    };
    *row = [b' '; DISPLAY_COLS];
    row[..n].copy_from_slice(&tmp[..n]);
    row[n] = b' ';
    row[n + 1..n + 1 + unit_bytes.len()].copy_from_slice(unit_bytes);
    true
}

fn write_amount_two_rows_bytes(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
    decimals: u32,
    frac_digits: u32,
    trim_trailing_zeros: bool,
    unit_bytes: &[u8],
) -> AmountFit {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];

    let mut tmp = [0u8; 96];
    let n = match value.format_decimal(decimals, frac_digits, trim_trailing_zeros, &mut tmp) {
        Some(n) => n,
        None => return AmountFit::Overflow,
    };
    let digits = &tmp[..n];

    let dot_pos = digits.iter().position(|&b| b == b'.');
    let unit_copy = core::cmp::min(unit_bytes.len(), DISPLAY_COLS.saturating_sub(1));
    let unit = &unit_bytes[..unit_copy];

    match dot_pos {
        Some(dp) => {
            if dp > DISPLAY_COLS {
                return AmountFit::Overflow;
            }
            row1[..dp].copy_from_slice(&digits[..dp]);
            let tail = &digits[dp..];
            let need2 = tail.len() + 1 + unit.len();
            if need2 > DISPLAY_COLS {
                return AmountFit::Overflow;
            }
            row2[..tail.len()].copy_from_slice(tail);
            row2[tail.len()] = b' ';
            row2[tail.len() + 1..tail.len() + 1 + unit.len()].copy_from_slice(unit);
            AmountFit::Full
        }
        None => {
            if n <= DISPLAY_COLS && 1 + unit.len() <= DISPLAY_COLS {
                row1[..n].copy_from_slice(digits);
                row2[..unit.len()].copy_from_slice(unit);
                AmountFit::Full
            } else {
                AmountFit::Overflow
            }
        }
    }
}
