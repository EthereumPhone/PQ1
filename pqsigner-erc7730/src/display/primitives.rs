//! Row-level formatting helpers shared by every renderer in this
//! directory. `pub` so only the sibling submodules under
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

use super::{Page, DISPLAY_COLS, DISPLAY_ROWS};
use pqsigner_tx::erc20::bundle::Erc20Metadata;
use pqsigner_tx::erc20::calldata::Erc20Call;
use pqsigner_tx_core::eip1559::U256;
use pqsigner_tx_core::hash::keccak256;

// ---------------------------------------------------------------------------
// Low-level row primitives
// ---------------------------------------------------------------------------

/// Overwrite `row` with `text`, left-aligned. Truncates to `DISPLAY_COLS`
/// and pads the tail with spaces. Intended for fixed label strings that
/// are known to fit — NEVER feed it attacker-controlled data.
pub fn write_line(row: &mut [u8; DISPLAY_COLS], text: &str) {
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

pub fn hex_nibble(n: u8) -> u8 {
    match n & 0x0f {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

/// Decimal-format a `u64` into `out`. Returns `Some(n)` on success or
/// `None` if the canonical decimal representation does not fit. Unlike
/// the old helper this one refuses to silently truncate.
pub fn format_u64(mut n: u64, out: &mut [u8]) -> Option<usize> {
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

/// Outcome of a width-aware amount render. `Full` means the formatter's
/// complete output fit; callers whose policy uses fewer fractional digits than
/// the signed value must separately require
/// [`amount_is_exact_at_fraction_digits`] before treating that output as an
/// exact clear-signing representation. `Overflow` means the value must not be
/// confirmed through that rendering.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AmountFit {
    Full,
    Overflow,
}

/// Return `true` iff scaling `value` to `fraction_digits` would discard only
/// zero base-10 digits.
///
/// `format_decimal` rounds when `decimals > fraction_digits`; a successful
/// width fit alone therefore does not prove that the displayed number binds
/// every signed base unit. This allocation-free predicate supplies that proof
/// for trusted amount sinks. It is bounded to the 78 decimal positions of a
/// `U256`, so an attacker-controlled descriptor cannot turn an absurd decimal
/// count into an unbounded loop.
#[must_use]
#[inline]
pub fn amount_is_exact_at_fraction_digits(
    value: &U256,
    decimals: u32,
    fraction_digits: u32,
) -> bool {
    let discarded_digits = decimals.saturating_sub(fraction_digits);
    if discarded_digits == 0 || value.is_zero() {
        return true;
    }
    // U256::MAX has 78 decimal digits. No non-zero U256 is divisible by
    // 10^78, while divisibility by 10^77 is still possible.
    if discarded_digits > 77 {
        return false;
    }

    let mut quotient = value.0;
    for _ in 0..discarded_digits {
        let mut remainder = 0u16;
        for byte in &mut quotient {
            let dividend = (remainder << 8) | u16::from(*byte);
            *byte = (dividend / 10) as u8;
            remainder = dividend % 10;
        }
        if remainder != 0 {
            return false;
        }
    }
    true
}

/// Select the smallest friendly fractional width that preserves every signed
/// base unit. The search is deliberately capped: ordinary token metadata uses
/// at most 18 displayed decimals, while larger-decimal assets must have enough
/// trailing zero base units to fit that exact envelope or be refused.
#[must_use]
pub fn exact_fraction_digits(value: &U256, decimals: u32, preferred: u32, maximum: u32) -> Option<u32> {
    let mut fraction_digits = core::cmp::min(decimals, preferred);
    let maximum = core::cmp::min(decimals, maximum);
    while fraction_digits <= maximum {
        if amount_is_exact_at_fraction_digits(value, decimals, fraction_digits) {
            return Some(fraction_digits);
        }
        fraction_digits = fraction_digits.checked_add(1)?;
    }
    None
}

/// F14#3 collapse-to-zero guard: true iff `digits` (a `format_decimal`
/// output) represents zero — every byte is `'0'` or the decimal point.
///
/// Used to refuse rendering a NONZERO transfer amount that scaled by an
/// (untrusted) `decimals` formats to `"0"` / `"0.000000"`. A poisoned
/// ERC-7730 descriptor could otherwise inflate `params.decimals` so a
/// balance-draining amount paints as a harmless-looking near-zero — the user
/// confirms "0" while signing a large transfer. Amount sinks pass
/// `reject_zero_collapse = true` so they paint the loud overflow banner
/// instead; FEE/gas formatters (gwei/wei) pass `false` because a genuinely
/// tiny fee rendering as `"0.000"` is truthful, not a hidden magnitude.
#[inline]
pub fn formatted_collapses_to_zero(value: &U256, digits: &[u8]) -> bool {
    !value.is_zero() && digits.iter().all(|&b| b == b'0' || b == b'.')
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
pub fn try_write_amount_single_row(
    row: &mut [u8; DISPLAY_COLS],
    value: &U256,
    decimals: u32,
    frac_digits: u32,
    trim_trailing_zeros: bool,
    reject_zero_collapse: bool,
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
    // F14#3: refuse a nonzero amount that collapsed to all-zero digits (the
    // caller falls back to the 2-row sink, which also rejects → overflow
    // banner). Fee/gas callers pass `reject_zero_collapse = false`.
    if reject_zero_collapse && formatted_collapses_to_zero(value, &tmp[..n]) {
        return false;
    }

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
/// `DISPLAY_COLS + DISPLAY_COLS - unit.len() - 2  ≈ 30 chars`
///
/// which comfortably covers every practical ETH value. For the
/// unrealistic `2^256 - 1 wei` class of inputs the function returns
/// `AmountFit::Overflow` and the caller must paint a banner.
pub fn write_amount_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
    decimals: u32,
    frac_digits: u32,
    trim_trailing_zeros: bool,
    reject_zero_collapse: bool,
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

    // F14#3: a nonzero transfer amount that scaled to all-zero digits is a
    // hidden-magnitude render — paint the loud overflow banner, never a
    // misleading near-zero. (Fee/gas paths pass `reject_zero_collapse = false`.)
    if reject_zero_collapse && formatted_collapses_to_zero(value, digits) {
        return AmountFit::Overflow;
    }

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
            row2[tail.len() + 1..tail.len() + 1 + unit_bytes.len()].copy_from_slice(unit_bytes);
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
                row2[rest.len() + 1..rest.len() + 1 + unit_bytes.len()].copy_from_slice(unit_bytes);
                AmountFit::Full
            } else {
                AmountFit::Overflow
            }
        }
    }
}

/// Paint `<amount> <unit>` preferring a SINGLE row (`"0.5 ETH"`), spilling to
/// two rows only when it doesn't fit — the same single-row-first policy the
/// native ETH/token paths already use (`write_eth_two_rows`), so an ERC-7730
/// amount no longer always splits into a lone integer row + a `".5 unit"` row.
/// Blanks `row2` on the single-row path. Preserves the F14#3 zero-collapse
/// guard: BOTH sinks reject a nonzero value that formats to all-zero digits, so
/// the single-row shortcut can never hide a magnitude the two-row form would
/// have flagged. (review 4.3)
#[allow(clippy::too_many_arguments)]
pub fn write_amount_single_or_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
    decimals: u32,
    frac_digits: u32,
    trim_trailing_zeros: bool,
    reject_zero_collapse: bool,
    unit: &str,
) -> AmountFit {
    if try_write_amount_single_row(
        row1,
        value,
        decimals,
        frac_digits,
        trim_trailing_zeros,
        reject_zero_collapse,
        unit,
    ) {
        *row2 = [b' '; DISPLAY_COLS];
        return AmountFit::Full;
    }
    write_amount_two_rows(
        row1,
        row2,
        value,
        decimals,
        frac_digits,
        trim_trailing_zeros,
        reject_zero_collapse,
        unit,
    )
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
/// EIP-55 mixed-case hex of a 20-byte address — 40 ASCII chars, no `0x`.
///
/// This is the canonical display form everywhere else (Etherscan, wallets,
/// dapps), so the device address is directly comparable char-for-char, and the
/// casing carries EIP-55's own single-character transposition check. The bytes
/// are unchanged — casing only — so there is NO WYSIWYS change, just a more
/// verifiable rendering. Uppercases hex letter `i` iff nibble `i` of
/// `keccak256(lowercase_ascii_hex)` is ≥ 8 (digits are never cased).
pub fn eip55_hex(addr: &[u8; 20]) -> [u8; 40] {
    let mut hex = [0u8; 40];
    for (i, &b) in addr.iter().enumerate() {
        hex[i * 2] = hex_nibble(b >> 4);
        hex[i * 2 + 1] = hex_nibble(b & 0x0f);
    }
    let hash = keccak256(&hex);
    for i in 0..40 {
        if hex[i].is_ascii_alphabetic() {
            let nibble = if i % 2 == 0 {
                hash[i / 2] >> 4
            } else {
                hash[i / 2] & 0x0f
            };
            if nibble >= 8 {
                hex[i] = hex[i].to_ascii_uppercase();
            }
        }
    }
    hex
}

/// Maximum number of verified-name bytes the three-row named-address layout
/// can show. Row 1 has 14 cells after `"+ "`; row 2 has 15 cells after its
/// alignment space. Longer Merkle-verified names are rendered as the first 28
/// bytes plus `~`, never silently clipped.
pub const VERIFIED_NAME_DISPLAY_LEN: usize = 29;
const VERIFIED_NAME_TRUNCATED_PREFIX_LEN: usize = VERIFIED_NAME_DISPLAY_LEN - 1;

/// Canonical bytes painted by the verified-name branch.
///
/// Public so dbgen can reject two trusted name records that would paint the
/// same name. Keeping this transformation single-sourced prevents the
/// catalogue collision gate from drifting away from the secure display.
pub fn verified_name_display_bytes(
    name: &[u8],
    out: &mut [u8; VERIFIED_NAME_DISPLAY_LEN],
) -> usize {
    *out = [0u8; VERIFIED_NAME_DISPLAY_LEN];
    if name.len() <= VERIFIED_NAME_DISPLAY_LEN {
        out[..name.len()].copy_from_slice(name);
        return name.len();
    }
    out[..VERIFIED_NAME_TRUNCATED_PREFIX_LEN]
        .copy_from_slice(&name[..VERIFIED_NAME_TRUNCATED_PREFIX_LEN]);
    out[VERIFIED_NAME_TRUNCATED_PREFIX_LEN] = b'~';
    VERIFIED_NAME_DISPLAY_LEN
}

/// Exact 12 ASCII hex characters painted around the named-address ellipsis:
/// first three and last three address bytes, with EIP-55 casing derived from
/// the complete address. Dbgen uses this together with
/// [`verified_name_display_bytes`] to make the accepted name catalogue
/// injective over the actual trusted-display tuple.
pub fn verified_name_address_fingerprint(addr: &[u8; 20]) -> [u8; 12] {
    let hex = eip55_hex(addr);
    let mut out = [0u8; 12];
    out[..6].copy_from_slice(&hex[..6]);
    out[6..].copy_from_slice(&hex[34..40]);
    out
}

pub fn write_addr_full(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    row3: &mut [u8; DISPLAY_COLS],
    addr: &[u8; 20],
) {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    *row3 = [b' '; DISPLAY_COLS];

    let hex = eip55_hex(addr);
    // Row 1: "0x" + bytes 0..7  (2 + 14 = 16 cols)
    row1[0] = b'0';
    row1[1] = b'x';
    row1[2..16].copy_from_slice(&hex[0..14]);
    // Row 2: bytes 7..15  (16 cols)
    row2[..16].copy_from_slice(&hex[14..30]);
    // Row 3: bytes 15..20 — 5 bytes = 10 hex chars, padded to 16
    row3[..10].copy_from_slice(&hex[30..40]);
}

/// Like [`write_addr_full`] but first consults the merkle-verified
/// address-name DB via the supplied [`NameResolver`]. On a DB hit the
/// three rows render as:
///
/// ```text
///   row1: "+ <name row 1 ...>"     (up to 14 chars after the sentinel)
///   row2: " <name row 2 ...>"      (up to 15 chars; blank if name fits row1)
///   row3: "0xAABBCC..DDEEFF"       (first 3 + last 3 bytes, disambiguation)
/// ```
///
/// Names longer than the 29 available name cells paint their first 28 bytes
/// plus `~`; dbgen rejects case-insensitive collisions in this exact displayed
/// name/address fingerprint across overlapping chain scopes.
///
/// The leading `+` sentinel is user-visible proof that the secure world
/// matched the address against a signed DB entry — raw-hex fallback
/// never carries it. On a DB miss we delegate to [`write_addr_full`].
pub fn write_addr_full_or_name(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    row3: &mut [u8; DISPLAY_COLS],
    addr: &[u8; 20],
    chain_id: u64,
    resolver: &pqsigner_tx::names::NameResolver<'_>,
) {
    if let Some(name) = resolver.lookup(chain_id, addr) {
        *row1 = [b' '; DISPLAY_COLS];
        *row2 = [b' '; DISPLAY_COLS];
        *row3 = [b' '; DISPLAY_COLS];

        // Rows 0..=1: sentinel + name, split across two rows if needed.
        row1[0] = b'+';
        row1[1] = b' ';
        let mut displayed_name = [0u8; VERIFIED_NAME_DISPLAY_LEN];
        let displayed_len = verified_name_display_bytes(name, &mut displayed_name);
        let displayed_name = &displayed_name[..displayed_len];
        let name_room_r1 = DISPLAY_COLS - 2; // after "+ "
        let n1 = core::cmp::min(displayed_name.len(), name_room_r1);
        row1[2..2 + n1].copy_from_slice(&displayed_name[..n1]);
        if displayed_name.len() > name_room_r1 {
            // Leave col 0 blank, start at col 1 to align visually under
            // the name's first char.
            let rest = &displayed_name[name_room_r1..];
            let room_r2 = DISPLAY_COLS - 1;
            let n2 = core::cmp::min(rest.len(), room_r2);
            row2[1..1 + n2].copy_from_slice(&rest[..n2]);
        }

        // Row 3: truncated hex for disambiguation — first 3 bytes, a TWO-dot
        // ellipsis, last 3 bytes: "0x112233..AABBCC" = 2+6+2+6 = 16 cols (fits
        // exactly). A single dot read like a typo inside the hex (review 4.13).
        // EIP-55 casing is computed over the FULL address (never the truncated
        // string), then the shown slices (chars 0..6 and 34..40) are copied out.
        let fingerprint = verified_name_address_fingerprint(addr);
        row3[0] = b'0';
        row3[1] = b'x';
        row3[2..8].copy_from_slice(&fingerprint[..6]);
        row3[8] = b'.';
        row3[9] = b'.';
        row3[10..16].copy_from_slice(&fingerprint[6..]);
    } else {
        write_addr_full(row1, row2, row3, addr);
    }
}

// ---------------------------------------------------------------------------
// Chain identification
// ---------------------------------------------------------------------------

/// Human-readable chain label, shown on the row BELOW the numeric
/// `Chain: <id>` (`write_chain`) — so the id is always the ground truth and
/// this label is advisory. The list covers the chains the vendored ERC-7730
/// registry actually ships descriptors for (a wrong label would misrepresent
/// the network, so only high-confidence mainnet ids are added; the rest fall
/// through to `(unknown chain)`). We say `(unknown chain)` rather than
/// `(UNVERIFIED)` so the stronger `UNVERIFIED` marker keeps a single meaning
/// (an unverified *token*); the numeric id shown above already lets the user
/// confirm the network.
pub fn chain_name(chain_id: u64) -> &'static str {
    match chain_id {
        1 => "(Mainnet)",
        10 => "(Optimism)",
        14 => "(Flare)",
        30 => "(Rootstock)",
        56 => "(BSC)",
        100 => "(Gnosis)",
        137 => "(Polygon)",
        146 => "(Sonic)",
        250 => "(Fantom)",
        324 => "(zkSync Era)",
        999 => "(HyperEVM)",
        1329 => "(Sei)",
        8217 => "(Kaia)",
        8453 => "(Base)",
        42161 => "(Arbitrum)",
        42220 => "(Celo)",
        43114 => "(Avalanche)",
        59144 => "(Linea)",
        534352 => "(Scroll)",
        11155111 => "(Sepolia)",
        84532 => "(BaseSepolia)",
        _ => "(unknown chain)",
    }
}

/// Audited native-currency ticker for a chain whose EVM base unit is known to
/// use 18 decimals.
///
/// `None` is security-significant: it means the firmware has no pinned decimal
/// metadata for this chain. ERC-7730 amount renderers must not turn that into an
/// assumed 18-decimal value. Keep this lookup distinct from [`native_ticker`],
/// whose neutral `NATIVE` fallback is suitable for labels but proves nothing
/// about magnitude.
pub fn known_native_ticker(chain_id: u64) -> Option<&'static [u8]> {
    match chain_id {
        1 | 10 | 324 | 8453 | 42161 | 59144 | 534352 | 11_155_111 | 84_532 => Some(b"ETH"),
        5_000 => Some(b"MNT"),
        56 => Some(b"BNB"),
        137 => Some(b"POL"),
        146 => Some(b"S"),
        250 => Some(b"FTM"),
        100 => Some(b"xDAI"),
        42220 => Some(b"CELO"),
        43114 => Some(b"AVAX"),
        14 => Some(b"FLR"),
        30 => Some(b"RBTC"),
        999 => Some(b"HYPE"),
        1329 => Some(b"SEI"),
        8217 => Some(b"KAIA"),
        80_094 => Some(b"BERA"),
        _ => None,
    }
}

/// Native-currency label for a chain. Unknown chains deliberately use the
/// neutral `NATIVE` label; callers that need decimal metadata must consult
/// [`known_native_ticker`] instead of treating this fallback as evidence for an
/// 18-decimal scale.
pub fn native_ticker(chain_id: u64) -> &'static [u8] {
    known_native_ticker(chain_id).unwrap_or(b"NATIVE")
}

/// Paint `prefix || native_ticker(chain_id) || suffix` on one row.
///
/// Callers use short, fixed ASCII prefixes/suffixes (for example `"Send "`
/// and `"?"`). Keeping this composition in the shared primitive prevents
/// secure renderers from drifting back to hard-coded `ETH` labels while the
/// amount suffix correctly shows another chain's asset.
pub fn write_native_currency_row(
    row: &mut [u8; DISPLAY_COLS],
    prefix: &[u8],
    chain_id: u64,
    suffix: &[u8],
) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, prefix);
    pos = append(row, pos, native_ticker(chain_id));
    let _ = append(row, pos, suffix);
}

/// Render a numeric chain id losslessly across two rows.
///
/// IDs up to nine decimal digits keep the familiar `Chain: N` first row and
/// use the second row for the advisory chain name. Ten-to-twenty-digit `u64`
/// IDs cannot coexist with the prefix on a 16-column display, so their first
/// eight digits are followed by `>` and the remaining (at most twelve) digits
/// continue on row two. No numeric digit is dropped or replaced by `!OVF`.
pub fn write_chain(row1: &mut [u8; DISPLAY_COLS], row2: &mut [u8; DISPLAY_COLS], chain_id: u64) {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    let prefix = b"Chain: ";
    let mut tmp = [0u8; 20];
    let n = format_u64(chain_id, &mut tmp).expect("20-byte buffer fits every u64");
    if prefix.len() + n <= DISPLAY_COLS {
        let pos = append(row1, 0, prefix);
        row1[pos..pos + n].copy_from_slice(&tmp[..n]);
        write_line(row2, chain_name(chain_id));
        return;
    }

    // 7-byte prefix + 8 digits + '>' exactly fills row 1. A u64 has at most
    // 20 decimal digits, so row 2 receives at most 12 and always fits.
    const FIRST_DIGITS: usize = 8;
    let pos = append(row1, 0, prefix);
    row1[pos..pos + FIRST_DIGITS].copy_from_slice(&tmp[..FIRST_DIGITS]);
    row1[DISPLAY_COLS - 1] = b'>';
    row2[..n - FIRST_DIGITS].copy_from_slice(&tmp[FIRST_DIGITS..n]);
}

// ---------------------------------------------------------------------------
// ETH / gwei / gas formatting
// ---------------------------------------------------------------------------

/// Number of fractional digits shown for compact known-chain native amounts.
/// Unlike legacy known-token rows, which may widen to preserve exactness,
/// signed native values keep this stable width when exact and otherwise switch
/// to an explicit unscaled-wei representation. This constant is therefore the
/// compact painter's preferred width, never permission to discard base units.
pub const NATIVE_DISPLAY_FRACTION_DIGITS: u32 = 6;

/// Paint an ETH value across (up to) two rows.
///
/// Row 1 carries the integer portion; row 2 carries the fractional tail
/// plus "ETH". The helper short-circuits to a single row when the whole
/// thing fits. Returns `AmountFit::Overflow` for pathological values — a
/// 17+ digit integer can't be rendered, and the caller paints a banner.
///
/// **Anti-spoof (audit M-6).** The fractional width is FIXED at
/// [`NATIVE_DISPLAY_FRACTION_DIGITS`] and trailing zeros are NOT trimmed. This
/// removes adaptive-width display drift, but six-decimal formatting can still
/// round lower base units. A trusted sink that needs exact signed-value binding
/// must require
/// [`amount_is_exact_at_fraction_digits`] in addition to `AmountFit::Full`.
pub fn write_eth_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
) -> AmountFit {
    // Single row if the fixed-width form fits. `reject_zero_collapse = true`:
    // an ETH transfer is an amount, so a nonzero value rendering as
    // "0.000000 ETH" must overflow loudly, not hide its magnitude (F14#3).
    if try_write_amount_single_row(
        row1,
        value,
        18,
        NATIVE_DISPLAY_FRACTION_DIGITS,
        false,
        true,
        "ETH",
    ) {
        *row2 = [b' '; DISPLAY_COLS];
        return AmountFit::Full;
    }
    // Otherwise spill the SAME fixed-width form across two rows.
    write_amount_two_rows(
        row1,
        row2,
        value,
        18,
        NATIVE_DISPLAY_FRACTION_DIGITS,
        false,
        true,
        "ETH",
    )
}

/// Paint a chain's native-currency amount exactly across up to two rows.
///
/// A chain in [`known_native_ticker`] has firmware-pinned 18-decimal metadata,
/// so values that are exact at the stable six-decimal width keep the audited
/// ticker form. Values that would lose base units in that form fall back to the
/// exact unscaled integer followed by `wei`. An unknown chain keeps the exact,
/// unscaled integer followed by `raw`; the neutral `NATIVE` label alone is not
/// evidence that an 18-decimal interpretation is valid.
///
/// Output is committed only after one complete representation fits. On
/// [`AmountFit::Overflow`] both caller-provided rows are left unchanged.
pub fn write_native_amount_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
    chain_id: u64,
) -> AmountFit {
    let mut painted_row1 = [b' '; DISPLAY_COLS];
    let mut painted_row2 = [b' '; DISPLAY_COLS];

    let fit = match known_native_ticker(chain_id) {
        None => write_amount_two_rows(
            &mut painted_row1,
            &mut painted_row2,
            value,
            0,
            0,
            false,
            true,
            "raw",
        ),
        Some(unit) => {
            let scaled_fit =
                if amount_is_exact_at_fraction_digits(value, 18, NATIVE_DISPLAY_FRACTION_DIGITS) {
                    if single_row_amount_fixed(
                        &mut painted_row1,
                        value,
                        18,
                        NATIVE_DISPLAY_FRACTION_DIGITS,
                        unit,
                    ) {
                        painted_row2 = [b' '; DISPLAY_COLS];
                        AmountFit::Full
                    } else {
                        write_amount_two_rows_bytes(
                            &mut painted_row1,
                            &mut painted_row2,
                            value,
                            18,
                            NATIVE_DISPLAY_FRACTION_DIGITS,
                            false,
                            unit,
                        )
                    }
                } else {
                    AmountFit::Overflow
                };

            if scaled_fit == AmountFit::Full {
                AmountFit::Full
            } else {
                // Never round a signed native amount. The explicit base-unit
                // suffix distinguishes this exact fallback from the ticker-
                // scaled representation and from unknown-chain `raw`.
                write_amount_two_rows(
                    &mut painted_row1,
                    &mut painted_row2,
                    value,
                    0,
                    0,
                    false,
                    true,
                    "wei",
                )
            }
        }
    };

    if fit == AmountFit::Full {
        *row1 = painted_row1;
        *row2 = painted_row2;
    }
    fit
}

/// Return `true` iff the real native-currency painter represents the signed
/// value exactly.
///
/// This deliberately has no parallel precision predicate: it executes
/// [`write_native_amount_two_rows`] into scratch rows, so pre-publication
/// authorization and the bytes eventually painted cannot drift.
#[must_use]
pub fn native_amount_is_exactly_renderable(value: &U256, chain_id: u64) -> bool {
    let mut row1 = [b' '; DISPLAY_COLS];
    let mut row2 = [b' '; DISPLAY_COLS];
    write_native_amount_two_rows(&mut row1, &mut row2, value, chain_id) == AmountFit::Full
}

/// Paint an exact derived native-currency bound across up to two rows.
///
/// Signed transfer values use [`write_native_amount_two_rows`]'s stable
/// six-decimal form or explicit exact-wei fallback. A derived upper bound, such
/// as a Safe gas refund estimate, is not itself a signed amount and commonly
/// has finer-than-six-decimal dust after multiplication, so this sink may widen
/// the ticker-scaled form before using the same exact raw-wei fallback.
/// Unknown-chain amounts retain the exact unscaled `raw` policy because their
/// decimal scale is not pinned.
///
/// Every successful path is injective over `value`: scaled paths are admitted
/// only when no base unit is discarded, and the fallback is the full integer.
#[must_use]
pub fn write_native_derived_amount_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
    chain_id: u64,
) -> AmountFit {
    let Some(unit) = known_native_ticker(chain_id) else {
        return write_native_amount_two_rows(row1, row2, value, chain_id);
    };

    // At 18 fractional digits every U256 is exact, so this search always
    // succeeds. Keep the Option handling fail-closed if that invariant changes.
    if let Some(frac) = exact_fraction_digits(value, 18, NATIVE_DISPLAY_FRACTION_DIGITS, 18) {
        if single_row_amount_fixed(row1, value, 18, frac, unit) {
            *row2 = [b' '; DISPLAY_COLS];
            return AmountFit::Full;
        }
        if write_amount_two_rows_bytes(row1, row2, value, 18, frac, false, unit) == AmountFit::Full
        {
            return AmountFit::Full;
        }
    }

    // A long fractional tail can exceed row 2 even when the exact integer base
    // units comfortably fit across both rows. The explicit `wei` suffix keeps
    // this representation distinguishable from every ticker-scaled form.
    write_amount_two_rows(row1, row2, value, 0, 0, false, true, "wei")
}

/// Paint a gas-price value exactly on a single row. Three fractional gwei
/// digits remain the preferred stable width, but the renderer may use up to
/// all nine gwei decimals when needed to preserve signed wei. If no exact gwei
/// form fits, it falls back to an exact raw-wei integer. Returns `false` only
/// when neither exact representation fits.
#[must_use]
pub fn write_gwei(row: &mut [u8; DISPLAY_COLS], value: &U256) -> bool {
    // Prefer the historical width and shorter exact forms first so large
    // integer portions retain their previous layout.
    for &frac in &[3u32, 2, 1, 0] {
        if amount_is_exact_at_fraction_digits(value, 9, frac)
            && try_write_amount_single_row(row, value, 9, frac, true, false, "gwei")
        {
            return true;
        }
    }
    // Values below 0.001 gwei or carrying sub-micro-gwei dust need more
    // precision, not rounding.
    for frac in 4u32..=9 {
        if amount_is_exact_at_fraction_digits(value, 9, frac)
            && try_write_amount_single_row(row, value, 9, frac, true, false, "gwei")
        {
            return true;
        }
    }
    // Last-ditch: exact raw wei as an integer.
    if try_write_amount_single_row(row, value, 0, 0, true, false, "wei") {
        return true;
    }
    write_line(row, "!OVERFLOW");
    false
}

/// Paint `"(gas: N)"` on one row. Returns `false` and paints
/// `"(gas: !OVF)"` when the exact decimal value cannot fit.
#[must_use]
pub fn write_gas(row: &mut [u8; DISPLAY_COLS], gas: u64) -> bool {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"(gas: ");
    let mut tmp = [0u8; 20];
    let exact = match format_u64(gas, &mut tmp) {
        Some(n) if pos + n + 1 <= DISPLAY_COLS => {
            row[pos..pos + n].copy_from_slice(&tmp[..n]);
            pos += n;
            true
        }
        _ => {
            pos = append(row, pos, b"!OVF");
            false
        }
    };
    if pos < DISPLAY_COLS {
        row[pos] = b')';
    }
    exact
}

/// Paint the priority-fee value on the full row. Legacy fee pages label row 1
/// and row 2 together as `max / tip`, so neither value sacrifices exact
/// numeric width to a repeated inline label.
#[must_use]
pub fn write_tip_row(row: &mut [u8; DISPLAY_COLS], tip: &U256) -> bool {
    write_gwei(row, tip)
}

/// Paint the exact worst-case fee budget on the full row beneath the caller's
/// `Worst-case:` header. Computed as `max_fee_per_gas * gas_limit`. Returns
/// `false` if multiplication overflows or no exact native/wei representation
/// fits.
#[must_use]
pub fn write_fee_budget_row(
    row: &mut [u8; DISPLAY_COLS],
    max_fee_per_gas: &U256,
    gas_limit: u64,
) -> bool {
    write_fee_budget_row_with_unit(row, max_fee_per_gas, gas_limit, b"ETH")
}

/// Chain-aware variant of [`write_fee_budget_row`]. The fee budget is paid in
/// the chain's native asset, so both the suffix and 18-decimal scale must be
/// selected from audited metadata for the signed chain id. Unknown chains
/// refuse rather than assigning an unauthenticated magnitude.
#[must_use]
pub fn write_native_fee_budget_row(
    row: &mut [u8; DISPLAY_COLS],
    max_fee_per_gas: &U256,
    gas_limit: u64,
    chain_id: u64,
) -> bool {
    let Some(unit) = known_native_ticker(chain_id) else {
        write_line(row, "!NO SCALE");
        return false;
    };
    write_fee_budget_row_with_unit(row, max_fee_per_gas, gas_limit, unit)
}

fn write_fee_budget_row_with_unit(
    row: &mut [u8; DISPLAY_COLS],
    max_fee_per_gas: &U256,
    gas_limit: u64,
    unit: &[u8],
) -> bool {
    *row = [b' '; DISPLAY_COLS];
    let (budget, overflow) = max_fee_per_gas.saturating_mul_u64(gas_limit);
    if overflow {
        write_line(row, "!OVF");
        return false;
    }
    let mut tmp = [0u8; 96];
    for &frac in &[4u32, 3, 2, 1, 0] {
        if amount_is_exact_at_fraction_digits(&budget, 18, frac) {
            if let Some(n) = budget.format_decimal(18, frac, true, &mut tmp) {
                if n + 1 + unit.len() <= DISPLAY_COLS {
                    row[..n].copy_from_slice(&tmp[..n]);
                    let mut pos = n;
                    pos = append(row, pos, b" ");
                    let _ = append(row, pos, unit);
                    return true;
                }
            }
        }
    }
    for frac in 5u32..=18 {
        if amount_is_exact_at_fraction_digits(&budget, 18, frac) {
            if let Some(n) = budget.format_decimal(18, frac, true, &mut tmp) {
                if n + 1 + unit.len() <= DISPLAY_COLS {
                    row[..n].copy_from_slice(&tmp[..n]);
                    let mut pos = n;
                    pos = append(row, pos, b" ");
                    let _ = append(row, pos, unit);
                    return true;
                }
            }
        }
    }
    if let Some(n) = budget.format_decimal(0, 0, true, &mut tmp) {
        if n + 4 <= DISPLAY_COLS {
            row[..n].copy_from_slice(&tmp[..n]);
            let pos = n;
            let _ = append(row, pos, b" wei");
            return true;
        }
    }
    write_line(row, "!OVF");
    false
}

/// Number of pages in the compact legacy EIP-1559 fee envelope.
pub const LEGACY_FEE_PAGE_COUNT: usize = 2;

/// A complete legacy EIP-1559 fee render and its exactness verdict.
///
/// Every legacy route copies these pages verbatim, while dispatch independently
/// consumes `exact` before allowing any page set to escape. Keeping both outputs
/// in one builder prevents preflight and the trusted-display bytes from
/// acquiring separate numeric policies.
pub struct LegacyFeeRender {
    pub pages: [Page; LEGACY_FEE_PAGE_COUNT],
    pub exact: bool,
}

/// Build the two legacy EIP-1559 fee pages.
///
/// Known chains retain the historical gwei/native-asset layout byte-for-byte.
/// An unknown chain has no authenticated decimal scale, so its signed fee
/// operands and derived upper bound are displayed as unscaled base-unit
/// integers under explicit `/base` labels. Every accepted integer is complete:
/// max fee and tip fit one row each, while the worst-case total may span two
/// rows with an explicit continuation marker.
#[must_use]
pub fn build_legacy_fee_pages(
    max_fee_per_gas: &U256,
    max_priority_fee_per_gas: &U256,
    gas_limit: u64,
    chain_id: u64,
) -> LegacyFeeRender {
    let mut pages = [[[b' '; DISPLAY_COLS]; DISPLAY_ROWS]; LEGACY_FEE_PAGE_COUNT];

    if known_native_ticker(chain_id).is_some() {
        write_line(&mut pages[0][0], "Fees: max / tip");
        let max_exact = write_gwei(&mut pages[0][1], max_fee_per_gas);
        let tip_exact = write_tip_row(&mut pages[0][2], max_priority_fee_per_gas);
        write_line(&mut pages[0][3], "> next");

        write_line(&mut pages[1][0], "Worst-case:");
        let budget_exact =
            write_native_fee_budget_row(&mut pages[1][1], max_fee_per_gas, gas_limit, chain_id);
        let gas_exact = write_gas(&mut pages[1][2], gas_limit);
        write_line(&mut pages[1][3], "> next");

        return LegacyFeeRender {
            pages,
            exact: max_exact & tip_exact & budget_exact & gas_exact,
        };
    }

    write_line(&mut pages[0][0], "Base: max / tip");
    let max_exact = write_raw_base_unit_row(&mut pages[0][1], max_fee_per_gas);
    let tip_exact = write_raw_base_unit_row(&mut pages[0][2], max_priority_fee_per_gas);
    write_line(&mut pages[0][3], "> next");

    write_line(&mut pages[1][0], "Worst-case/base:");
    let (budget, overflow) = max_fee_per_gas.saturating_mul_u64(gas_limit);
    let budget_exact = if overflow {
        write_line(&mut pages[1][1], "!OVERFLOW");
        false
    } else {
        let [_, total_hi, total_lo, _] = &mut pages[1];
        write_raw_base_unit_two_rows(total_hi, total_lo, &budget)
    };
    let gas_exact = write_gas(&mut pages[1][3], gas_limit);

    LegacyFeeRender {
        pages,
        exact: max_exact & tip_exact & !overflow & budget_exact & gas_exact,
    }
}

fn write_raw_base_unit_row(row: &mut [u8; DISPLAY_COLS], value: &U256) -> bool {
    *row = [b' '; DISPLAY_COLS];
    let mut digits = [0u8; 80];
    let Some(n) = value
        .format_decimal(0, 0, false, &mut digits)
        .filter(|&n| n <= DISPLAY_COLS)
    else {
        write_line(row, "!OVERFLOW");
        return false;
    };
    row[..n].copy_from_slice(&digits[..n]);
    true
}

fn write_raw_base_unit_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
) -> bool {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    let mut digits = [0u8; 80];
    let Some(n) = value
        .format_decimal(0, 0, false, &mut digits)
        .filter(|&n| n <= 2 * DISPLAY_COLS - 1)
    else {
        write_line(row1, "!OVERFLOW");
        return false;
    };
    if n <= DISPLAY_COLS {
        row1[..n].copy_from_slice(&digits[..n]);
        return true;
    }

    let first = DISPLAY_COLS - 1;
    row1[..first].copy_from_slice(&digits[..first]);
    row1[first] = b'>';
    let rest = n - first;
    row2[..rest].copy_from_slice(&digits[first..n]);
    true
}

/// Build the complete legacy fee envelope in scratch storage and report
/// whether every signed/derived value is represented exactly. Dispatch runs
/// this for routes that use the legacy fee painter before publishing their
/// pages, so a formatting failure cannot become an authorization banner.
#[must_use]
pub fn legacy_fee_rows_are_exactly_renderable(
    max_fee_per_gas: &U256,
    max_priority_fee_per_gas: &U256,
    gas_limit: u64,
    chain_id: u64,
) -> bool {
    build_legacy_fee_pages(
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas_limit,
        chain_id,
    )
    .exact
}

/// "Item X of Y" divider row for a nested array-of-struct (`T[]`) render (v2) —
/// separates each element's page group. `idx` is 0-based; the row shows 1-based.
pub fn write_array_item_row(row: &mut [u8; DISPLAY_COLS], idx: usize, count: usize) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"Item ");
    let mut tmp = [0u8; 20];
    if let Some(n) = format_u64((idx as u64).saturating_add(1), &mut tmp) {
        if pos + n <= DISPLAY_COLS {
            row[pos..pos + n].copy_from_slice(&tmp[..n]);
            pos += n;
        }
    }
    pos = append(row, pos, b" of ");
    if let Some(n) = format_u64(count as u64, &mut tmp) {
        if pos + n <= DISPLAY_COLS {
            row[pos..pos + n].copy_from_slice(&tmp[..n]);
            pos += n;
        }
    }
    let _ = pos;
}

pub fn write_nonce_row(row: &mut [u8; DISPLAY_COLS], nonce: u64) {
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

pub fn write_selector_row(row: &mut [u8; DISPLAY_COLS], data: &[u8]) {
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

pub fn write_data_len_row(row: &mut [u8; DISPLAY_COLS], len: usize) {
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
pub fn write_calldata_hash_rows(
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

pub fn write_erc20_header(
    row: &mut [u8; DISPLAY_COLS],
    call: &Erc20Call,
    meta: &Erc20Metadata<'_>,
) {
    *row = [b' '; DISPLAY_COLS];
    // `meta` is the authenticated ERC-20 capability at every production call
    // site. Exact zero therefore means allowance revocation, not an ERC-721
    // token-id guess (the unknown-token path never calls this helper). The
    // complete phrase consumes 15 columns; do not append a ticker fragment.
    if matches!(call, Erc20Call::Approve { amount, .. } if amount.is_zero()) {
        let _ = append(row, 0, b"Revoke approval");
        return;
    }
    let verb: &[u8] = match call {
        Erc20Call::Transfer { .. } => b"Send ",
        Erc20Call::TransferFrom { .. } => b"From ",
        Erc20Call::Approve { .. } => b"Approve ",
    };
    let pos = append(row, 0, verb);
    let symbol = meta.symbol;
    let copy = core::cmp::min(symbol.len(), DISPLAY_COLS.saturating_sub(pos));
    if copy > 0 {
        row[pos..pos + copy].copy_from_slice(&symbol[..copy]);
    }
}

pub fn write_token_name(row: &mut [u8; DISPLAY_COLS], meta: &Erc20Metadata<'_>) {
    *row = [b' '; DISPLAY_COLS];
    let copy = core::cmp::min(meta.name.len(), DISPLAY_COLS);
    row[..copy].copy_from_slice(&meta.name[..copy]);
}

/// Render a token amount across up to 2 rows, fixed-width (no
/// trailing-zero trim) so visual-spoofing attacks can't succeed. If
/// the amount overflows both rows the function returns
/// `AmountFit::Overflow` and the caller renders a banner.
pub fn write_token_amount_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    amount: &U256,
    meta: &Erc20Metadata<'_>,
) -> AmountFit {
    // Keep six fractional digits as the friendly baseline, then widen only as
    // far as needed (up to 18) to preserve every signed base unit. Metadata
    // with more decimals is accepted only when its omitted low digits are all
    // zero. No successful return may contain a rounded amount.
    let decimals = meta.decimals as u32;
    let unit_bytes = meta.symbol;

    if let Some(frac) = exact_fraction_digits(amount, decimals, 6, 18) {
        // Try single row first.
        if single_row_amount_fixed(row1, amount, decimals, frac, unit_bytes) {
            *row2 = [b' '; DISPLAY_COLS];
            return AmountFit::Full;
        }

        // 2-row fallback. Symbol can be up to MAX_DISPLAY_FIELD = 64 bytes
        // from the bundle, but we trust only the first DISPLAY_COLS-1 of
        // it on screen.
        if write_amount_two_rows_bytes(row1, row2, amount, decimals, frac, false, unit_bytes)
            == AmountFit::Full
        {
            return AmountFit::Full;
        }
    }

    // Tiny high-decimal amounts and other awkward exact decimals may not fit
    // the two-row grid. Preserve availability without rounding by rendering
    // the signed integer in explicitly labelled token base units. Refuse when
    // the complete label or integer still cannot fit.
    const BASE_PREFIX: &[u8] = b"base ";
    if unit_bytes.len() > DISPLAY_COLS.saturating_sub(BASE_PREFIX.len() + 1) {
        *row1 = [b' '; DISPLAY_COLS];
        *row2 = [b' '; DISPLAY_COLS];
        return AmountFit::Overflow;
    }
    let mut base_unit = [0u8; DISPLAY_COLS];
    base_unit[..BASE_PREFIX.len()].copy_from_slice(BASE_PREFIX);
    base_unit[BASE_PREFIX.len()..BASE_PREFIX.len() + unit_bytes.len()].copy_from_slice(unit_bytes);
    write_amount_two_rows_bytes(
        row1,
        row2,
        amount,
        0,
        0,
        false,
        &base_unit[..BASE_PREFIX.len() + unit_bytes.len()],
    )
}

/// Pure pre-publication check for legacy token amount sinks. It intentionally
/// executes the real painter into scratch rows so width, unit, decimal and
/// exactness policy cannot drift from the pages later shown to the user.
#[must_use]
pub fn token_amount_is_exactly_renderable(amount: &U256, meta: &Erc20Metadata<'_>) -> bool {
    let mut row1 = [b' '; DISPLAY_COLS];
    let mut row2 = [b' '; DISPLAY_COLS];
    write_token_amount_two_rows(&mut row1, &mut row2, amount, meta) == AmountFit::Full
}

/// CoW swap-leg amount renderer. Formats a 32-byte big-endian amount
/// with `decimals` applied and `symbol` appended, across up to two rows,
/// reusing the same fixed-width (anti-spoof) machinery as the ERC-20
/// transfer path. Keeps the `U256`/`Erc20Metadata`/`AmountFit` plumbing
/// internal so `cowswap_display` (outside the `display` module) can call
/// it with primitive types only.
///
/// Returns `false` on overflow — the magnitude exceeds two rows — and in
/// that case writes a "(amount too big)" marker into `row2` rather than
/// spilling onto an un-budgeted extra page. A decoded CoW amount is
/// astronomically unlikely to overflow (it would need ~16+ decimal
/// digits), but failing safe keeps the page count the renderer
/// pre-computed exact.
pub fn write_cow_leg_amount(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    amount_be: &[u8; 32],
    decimals: u8,
    symbol: &[u8],
) -> bool {
    let amount = U256(*amount_be);
    let meta = Erc20Metadata {
        chain_id: 0,
        contract: [0u8; 20],
        decimals,
        name: &[],
        symbol,
    };
    match write_token_amount_two_rows(row1, row2, &amount, &meta) {
        AmountFit::Full => true,
        AmountFit::Overflow => {
            *row1 = [b' '; DISPLAY_COLS];
            *row2 = [b' '; DISPLAY_COLS];
            let msg = b"(amount too big)";
            row2[..msg.len()].copy_from_slice(msg);
            false
        }
    }
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
    // F14#3: token amounts always reject the zero-collapse — fall back to the
    // 2-row sink (which also rejects → overflow banner) rather than paint a
    // nonzero amount as "0".
    if formatted_collapses_to_zero(value, &tmp[..n]) {
        return false;
    }
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

    // F14#3: token amounts reject the nonzero-collapse-to-zero render.
    if formatted_collapses_to_zero(value, digits) {
        return AmountFit::Overflow;
    }

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

#[cfg(test)]
mod eip55_tests {
    use super::{
        eip55_hex, verified_name_address_fingerprint, verified_name_display_bytes,
        VERIFIED_NAME_DISPLAY_LEN,
    };

    /// The four canonical EIP-55 reference vectors (from the EIP text).
    #[test]
    fn eip55_matches_reference_vectors() {
        let cases: &[([u8; 20], &[u8; 40])] = &[
            (
                [
                    0x5a, 0xae, 0xb6, 0x05, 0x3f, 0x3e, 0x94, 0xc9, 0xb9, 0xa0, 0x9f, 0x33, 0x66,
                    0x94, 0x35, 0xe7, 0xef, 0x1b, 0xea, 0xed,
                ],
                b"5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                [
                    0xfb, 0x69, 0x16, 0x09, 0x5c, 0xa1, 0xdf, 0x60, 0xbb, 0x79, 0xce, 0x92, 0xce,
                    0x3e, 0xa7, 0x4c, 0x37, 0xc5, 0xd3, 0x59,
                ],
                b"fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                [
                    0xdb, 0xf0, 0x3b, 0x40, 0x7c, 0x01, 0xe7, 0xcd, 0x3c, 0xbe, 0xa9, 0x95, 0x09,
                    0xd9, 0x3f, 0x8d, 0xdd, 0xc8, 0xc6, 0xfb,
                ],
                b"dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            ),
            (
                [
                    0xd1, 0x22, 0x0a, 0x0c, 0xf4, 0x7c, 0x7b, 0x9b, 0xe7, 0xa2, 0xe6, 0xba, 0x89,
                    0xf4, 0x29, 0x76, 0x2e, 0x7b, 0x9a, 0xdb,
                ],
                b"D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            ),
        ];
        for (addr, want) in cases {
            let got = eip55_hex(addr);
            assert_eq!(&got, *want, "EIP-55 mismatch for {want:?}");
        }
    }

    #[test]
    fn verified_name_truncation_is_explicit_and_canonical() {
        let mut out = [0u8; VERIFIED_NAME_DISPLAY_LEN];
        let exact = b"12345678901234567890123456789";
        assert_eq!(exact.len(), VERIFIED_NAME_DISPLAY_LEN);
        assert_eq!(verified_name_display_bytes(exact, &mut out), exact.len());
        assert_eq!(&out, exact);

        let long = b"12345678901234567890123456789XYZ";
        assert_eq!(verified_name_display_bytes(long, &mut out), 29);
        assert_eq!(&out[..28], &long[..28]);
        assert_eq!(out[28], b'~');
    }

    #[test]
    fn verified_name_fingerprint_matches_the_painted_eip55_ends() {
        let addr = [
            0x5a, 0xae, 0xb6, 0x05, 0x3f, 0x3e, 0x94, 0xc9, 0xb9, 0xa0, 0x9f, 0x33, 0x66, 0x94,
            0x35, 0xe7, 0xef, 0x1b, 0xea, 0xed,
        ];
        assert_eq!(&verified_name_address_fingerprint(&addr), b"5aAeb61BeAed");
    }
}

#[cfg(test)]
mod native_amount_tests {
    use super::{
        amount_is_exact_at_fraction_digits, known_native_ticker,
        native_amount_is_exactly_renderable, write_native_amount_two_rows,
        write_native_derived_amount_two_rows, AmountFit, DISPLAY_COLS,
    };
    use pqsigner_tx_core::eip1559::U256;

    fn u256_from_u128(value: u128) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[16..].copy_from_slice(&value.to_be_bytes());
        U256(bytes)
    }

    fn trimmed(row: &[u8; DISPLAY_COLS]) -> &[u8] {
        let end = row
            .iter()
            .rposition(|&b| b != b' ')
            .map_or(0, |idx| idx + 1);
        &row[..end]
    }

    #[test]
    fn unknown_chain_native_value_is_unscaled_raw_integer() {
        let mut row1 = [b' '; DISPLAY_COLS];
        let mut row2 = [b' '; DISPLAY_COLS];
        let value = u256_from_u128(1_000_000_000_000_000_000);
        assert_eq!(
            write_native_amount_two_rows(&mut row1, &mut row2, &value, 4_242_424_242),
            AmountFit::Full
        );
        assert_eq!(trimmed(&row1), b"1000000000000000");
        assert_eq!(trimmed(&row2), b"000 raw");
    }

    #[test]
    fn known_chain_native_value_keeps_pinned_scale_and_ticker() {
        let mut row1 = [b' '; DISPLAY_COLS];
        let mut row2 = [b' '; DISPLAY_COLS];
        let value = u256_from_u128(1_000_000_000_000_000_000);
        assert_eq!(
            write_native_amount_two_rows(&mut row1, &mut row2, &value, 1),
            AmountFit::Full
        );
        assert_eq!(trimmed(&row1), b"1.000000 ETH");
        assert!(trimmed(&row2).is_empty());
    }

    #[test]
    fn exactness_gate_covers_six_decimal_boundaries_without_rounding() {
        let one_native = u256_from_u128(1_000_000_000_000_000_000);
        let one_wei_more = u256_from_u128(1_000_000_000_000_000_001);
        let next_exact_step = u256_from_u128(1_000_001_000_000_000_000);
        let rounding_carry = u256_from_u128(999_999_500_000_000_000);

        assert!(amount_is_exact_at_fraction_digits(&one_native, 18, 6));
        assert!(!amount_is_exact_at_fraction_digits(&one_wei_more, 18, 6));
        assert!(amount_is_exact_at_fraction_digits(&next_exact_step, 18, 6));
        assert!(!amount_is_exact_at_fraction_digits(&rounding_carry, 18, 6));
        assert!(amount_is_exact_at_fraction_digits(
            &U256::zero(),
            u32::MAX,
            0
        ));
        assert!(!amount_is_exact_at_fraction_digits(
            &u256_from_u128(1),
            u32::MAX,
            0
        ));
    }

    #[test]
    fn known_native_uses_exact_wei_when_six_decimals_would_round() {
        let one_wei = u256_from_u128(1);
        let rounding_carry = u256_from_u128(999_999_500_000_000_000);
        let one_native = u256_from_u128(1_000_000_000_000_000_000);
        let one_native_plus_one_wei = u256_from_u128(1_000_000_000_000_000_001);
        for chain_id in [1, 56] {
            assert!(known_native_ticker(chain_id).is_some());

            let mut one_wei_rows = [[b' '; DISPLAY_COLS]; 2];
            let [one_wei_row1, one_wei_row2] = &mut one_wei_rows;
            assert_eq!(
                write_native_amount_two_rows(one_wei_row1, one_wei_row2, &one_wei, chain_id),
                AmountFit::Full
            );
            assert!(native_amount_is_exactly_renderable(&one_wei, chain_id));
            assert_eq!(trimmed(&one_wei_rows[0]), b"1");
            assert_eq!(trimmed(&one_wei_rows[1]), b"wei");

            let mut rounding_carry_rows = [[b' '; DISPLAY_COLS]; 2];
            let [rounding_carry_row1, rounding_carry_row2] = &mut rounding_carry_rows;
            assert_eq!(
                write_native_amount_two_rows(
                    rounding_carry_row1,
                    rounding_carry_row2,
                    &rounding_carry,
                    chain_id,
                ),
                AmountFit::Full
            );
            assert_eq!(trimmed(&rounding_carry_rows[0]), b"9999995000000000");
            assert_eq!(trimmed(&rounding_carry_rows[1]), b"00 wei");

            let mut one_native_rows = [[b' '; DISPLAY_COLS]; 2];
            let [one_native_row1, one_native_row2] = &mut one_native_rows;
            assert_eq!(
                write_native_amount_two_rows(
                    one_native_row1,
                    one_native_row2,
                    &one_native,
                    chain_id,
                ),
                AmountFit::Full
            );

            let mut adjacent_rows = [[b' '; DISPLAY_COLS]; 2];
            let [adjacent_row1, adjacent_row2] = &mut adjacent_rows;
            assert_eq!(
                write_native_amount_two_rows(
                    adjacent_row1,
                    adjacent_row2,
                    &one_native_plus_one_wei,
                    chain_id,
                ),
                AmountFit::Full
            );
            assert!(native_amount_is_exactly_renderable(
                &one_native_plus_one_wei,
                chain_id
            ));
            assert_eq!(trimmed(&adjacent_rows[0]), b"1000000000000000");
            assert_eq!(trimmed(&adjacent_rows[1]), b"001 wei");

            assert_ne!(one_wei_rows, one_native_rows);
            assert_ne!(rounding_carry_rows, one_native_rows);
            assert_ne!(one_native_rows, adjacent_rows);
            assert_ne!(one_wei_rows, adjacent_rows);
        }
    }

    #[test]
    fn accepted_adjacent_six_decimal_values_paint_differently() {
        let exact = u256_from_u128(1_000_000_000_000_000_000);
        let next = u256_from_u128(1_000_001_000_000_000_000);
        let mut exact_rows = [[b' '; DISPLAY_COLS]; 2];
        let mut next_rows = [[b' '; DISPLAY_COLS]; 2];
        let [exact_row1, exact_row2] = &mut exact_rows;
        let [next_row1, next_row2] = &mut next_rows;
        assert_eq!(
            write_native_amount_two_rows(exact_row1, exact_row2, &exact, 1),
            AmountFit::Full
        );
        assert!(native_amount_is_exactly_renderable(&exact, 1));
        assert_eq!(
            write_native_amount_two_rows(next_row1, next_row2, &next, 1),
            AmountFit::Full
        );
        assert!(native_amount_is_exactly_renderable(&next, 1));
        assert_ne!(exact_rows, next_rows);
        assert_eq!(trimmed(&next_rows[0]), b"1.000001 ETH");
    }

    #[test]
    fn unknown_chain_raw_integer_is_exact_or_reports_overflow() {
        let mut row1 = [b' '; DISPLAY_COLS];
        let mut row2 = [b' '; DISPLAY_COLS];
        assert_eq!(
            write_native_amount_two_rows(&mut row1, &mut row2, &u256_from_u128(1), 4_242_424_242,),
            AmountFit::Full
        );
        assert!(native_amount_is_exactly_renderable(
            &u256_from_u128(1),
            4_242_424_242
        ));
        assert_eq!(trimmed(&row1), b"1");
        assert_eq!(trimmed(&row2), b"raw");

        assert_eq!(
            write_native_amount_two_rows(&mut row1, &mut row2, &U256([0xff; 32]), 4_242_424_242,),
            AmountFit::Overflow
        );
        assert!(!native_amount_is_exactly_renderable(
            &U256([0xff; 32]),
            4_242_424_242
        ));
    }

    #[test]
    fn overwide_known_native_value_refuses_without_mutating_rows() {
        let mut row1 = *b"row one sentinel";
        let mut row2 = *b"row two sentinel";
        let before = [row1, row2];
        let value = U256([0xff; 32]);

        assert_eq!(
            write_native_amount_two_rows(&mut row1, &mut row2, &value, 1),
            AmountFit::Overflow
        );
        assert_eq!([row1, row2], before);
        assert!(!native_amount_is_exactly_renderable(&value, 1));
    }

    #[test]
    fn derived_native_bound_widens_then_falls_back_to_exact_wei() {
        // Safe refund upper bound for baseGas=43_776 and gasPrice=1 gwei.
        let ordinary = u256_from_u128(30_043_776_000_000_000);
        let mut ordinary_rows = [[b' '; DISPLAY_COLS]; 2];
        let [ordinary_row1, ordinary_row2] = &mut ordinary_rows;
        assert_eq!(
            write_native_derived_amount_two_rows(ordinary_row1, ordinary_row2, &ordinary, 1),
            AmountFit::Full
        );
        assert_eq!(trimmed(&ordinary_rows[0]), b"0.030043776 ETH");
        assert!(trimmed(&ordinary_rows[1]).is_empty());

        // One extra wei per gas needs all 18 decimals; that scaled tail does
        // not fit, but the exact 17-digit base-unit integer does.
        let dusty = u256_from_u128(30_043_776_030_043_776);
        let mut dusty_rows = [[b' '; DISPLAY_COLS]; 2];
        let [dusty_row1, dusty_row2] = &mut dusty_rows;
        assert_eq!(
            write_native_derived_amount_two_rows(dusty_row1, dusty_row2, &dusty, 1),
            AmountFit::Full
        );
        assert_eq!(trimmed(&dusty_rows[0]), b"3004377603004377");
        assert_eq!(trimmed(&dusty_rows[1]), b"6 wei");
        assert_ne!(ordinary_rows, dusty_rows);

        assert_eq!(
            write_native_derived_amount_two_rows(
                &mut [b' '; DISPLAY_COLS],
                &mut [b' '; DISPLAY_COLS],
                &U256([0xff; 32]),
                1,
            ),
            AmountFit::Overflow
        );
    }
}

#[cfg(test)]
mod legacy_fee_page_tests {
    use super::{
        build_legacy_fee_pages, legacy_fee_rows_are_exactly_renderable,
        write_raw_base_unit_two_rows, DISPLAY_COLS,
    };
    use pqsigner_tx_core::eip1559::U256;

    const UNKNOWN_CHAIN: u64 = 4_242_424_242;

    fn u256_from_u128(value: u128) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[16..].copy_from_slice(&value.to_be_bytes());
        U256(bytes)
    }

    fn trimmed(row: &[u8; DISPLAY_COLS]) -> &[u8] {
        let end = row
            .iter()
            .rposition(|&b| b != b' ')
            .map_or(0, |idx| idx + 1);
        &row[..end]
    }

    #[test]
    fn known_chain_fee_pages_keep_the_historical_bytes() {
        let rendered = build_legacy_fee_pages(
            &u256_from_u128(50_000_000_000),
            &u256_from_u128(2_000_000_000),
            21_000,
            1,
        );
        assert!(rendered.exact);
        assert_eq!(
            rendered.pages,
            [
                [
                    *b"Fees: max / tip ",
                    *b"50 gwei         ",
                    *b"2 gwei          ",
                    *b"> next          ",
                ],
                [
                    *b"Worst-case:     ",
                    *b"0.00105 ETH     ",
                    *b"(gas: 21000)    ",
                    *b"> next          ",
                ],
            ],
            "known-chain fee pages must remain byte-identical, including padding"
        );
    }

    #[test]
    fn unknown_chain_fee_pages_are_exact_raw_base_units() {
        let max_fee = u256_from_u128(30_000_000_001);
        let tip = u256_from_u128(1_234_567_890);
        let rendered = build_legacy_fee_pages(&max_fee, &tip, 30_000_000, UNKNOWN_CHAIN);

        assert!(rendered.exact);
        assert!(legacy_fee_rows_are_exactly_renderable(
            &max_fee,
            &tip,
            30_000_000,
            UNKNOWN_CHAIN,
        ));
        assert_eq!(trimmed(&rendered.pages[0][0]), b"Base: max / tip");
        assert_eq!(trimmed(&rendered.pages[0][1]), b"30000000001");
        assert_eq!(trimmed(&rendered.pages[0][2]), b"1234567890");
        assert_eq!(trimmed(&rendered.pages[0][3]), b"> next");
        assert_eq!(trimmed(&rendered.pages[1][0]), b"Worst-case/base:");
        assert_eq!(rendered.pages[1][1][DISPLAY_COLS - 1], b'>');
        assert_eq!(trimmed(&rendered.pages[1][3]), b"(gas: 30000000)");

        let mut total = [0u8; 32];
        let mut total_len = 0usize;
        for &cell in rendered.pages[1][1]
            .iter()
            .chain(rendered.pages[1][2].iter())
        {
            if cell.is_ascii_digit() {
                total[total_len] = cell;
                total_len += 1;
            }
        }
        assert_eq!(&total[..total_len], b"900000000030000000");
        assert!(rendered.pages.iter().flatten().all(|row| {
            !row.windows(4).any(|w| w == b"gwei") && !row.windows(3).any(|w| w == b"ETH")
        }));
    }

    #[test]
    fn adjacent_unknown_fee_operands_have_distinct_transcripts() {
        let one = build_legacy_fee_pages(
            &u256_from_u128(1),
            &u256_from_u128(1),
            21_000,
            UNKNOWN_CHAIN,
        );
        let two = build_legacy_fee_pages(
            &u256_from_u128(2),
            &u256_from_u128(1),
            21_000,
            UNKNOWN_CHAIN,
        );
        assert!(one.exact && two.exact);
        assert_ne!(one.pages, two.pages);
        assert_eq!(trimmed(&one.pages[0][1]), b"1");
        assert_eq!(trimmed(&two.pages[0][1]), b"2");
        assert_eq!(trimmed(&one.pages[1][1]), b"21000");
        assert_eq!(trimmed(&two.pages[1][1]), b"42000");
    }

    #[test]
    fn unknown_fee_width_gas_and_multiplication_boundaries_refuse() {
        let max_rate = u256_from_u128(9_999_999_999_999_999);
        assert!(build_legacy_fee_pages(&max_rate, &max_rate, 999_999_999, UNKNOWN_CHAIN,).exact);

        let wide_rate = u256_from_u128(10_000_000_000_000_000);
        assert!(
            !build_legacy_fee_pages(&wide_rate, &u256_from_u128(1), 21_000, UNKNOWN_CHAIN,).exact
        );
        assert!(
            !build_legacy_fee_pages(
                &u256_from_u128(1),
                &u256_from_u128(1),
                1_000_000_000,
                UNKNOWN_CHAIN,
            )
            .exact
        );

        let overflow =
            build_legacy_fee_pages(&U256([0xff; 32]), &u256_from_u128(1), 2, UNKNOWN_CHAIN);
        assert!(!overflow.exact);
        assert_eq!(trimmed(&overflow.pages[1][1]), b"!OVERFLOW");
    }

    #[test]
    fn raw_total_helper_accepts_31_digits_and_rejects_32() {
        let mut rows = [[b' '; DISPLAY_COLS]; 2];
        let [hi, lo] = &mut rows;
        assert!(write_raw_base_unit_two_rows(
            hi,
            lo,
            &u256_from_u128(9_999_999_999_999_999_999_999_999_999_999),
        ));
        assert_eq!(rows[0][DISPLAY_COLS - 1], b'>');

        let [hi, lo] = &mut rows;
        assert!(!write_raw_base_unit_two_rows(
            hi,
            lo,
            &u256_from_u128(10_000_000_000_000_000_000_000_000_000_000),
        ));
        assert_eq!(trimmed(&rows[0]), b"!OVERFLOW");
        assert!(trimmed(&rows[1]).is_empty());
    }
}

#[cfg(kani)]
mod kani_harness {
    //! Tier-P0 ∀ proof of the full-address hex skeleton (FV frontier Track 2
    //! M3, 2026-07-04).

    use super::*;

    /// Independent hex oracle: a lookup TABLE, not the code's arithmetic
    /// `hex_nibble`.
    const HEX_LOWER_TAB: &[u8; 16] = b"0123456789abcdef";

    /// ∀ 20-byte addresses: `write_addr_full` (the unresolved-name arm's
    /// painter) shows `0x` + ALL 40 nibbles of the address across rows 1-3
    /// in order, each nibble VALUE bound to the independent table. EIP-55
    /// (landed 2026-07-04, commit 89c9e4c3) picks per-letter CASE from
    /// `keccak256(lowercase_hex)` — the case bits are deliberately left
    /// unbound (binding them would put the hash preimage in the proof
    /// obligation): a letter cell may only be the correct hex letter in
    /// either case, and a digit cell is exactly the digit (digits are never
    /// cased). So no address can render with a wrong / reordered / dropped
    /// nibble regardless of what the case rule computes — the value
    /// skeleton is exact ∀; the casing itself is pinned by the concrete
    /// EIP-55 reference-vector witness below and `eip55_tests`.
    #[kani::proof]
    #[kani::unwind(210)]
    fn addr_full_nibble_values_bind() {
        let addr: [u8; 20] = kani::any();
        let mut r1 = [0u8; DISPLAY_COLS];
        let mut r2 = [0u8; DISPLAY_COLS];
        let mut r3 = [0u8; DISPLAY_COLS];
        write_addr_full(&mut r1, &mut r2, &mut r3, &addr);
        assert!(r1[0] == b'0' && r1[1] == b'x');
        let mut i = 0usize;
        while i < 40 {
            let nib = if i % 2 == 0 {
                addr[i / 2] >> 4
            } else {
                addr[i / 2] & 0x0f
            };
            let lower = HEX_LOWER_TAB[nib as usize];
            let got = if i < 14 {
                r1[2 + i]
            } else if i < 30 {
                r2[i - 14]
            } else {
                r3[i - 30]
            };
            if lower.is_ascii_digit() {
                assert!(got == lower); // digits are never cased
            } else {
                assert!(got == lower || got == lower - 32); // exact letter, either case
            }
            i += 1;
        }
        // Row-3 tail is space padding — no stray content after the address.
        let mut c = 10usize;
        while c < DISPLAY_COLS {
            assert!(r3[c] == b' ');
            c += 1;
        }
    }

    /// Non-vacuity + exact-case witness: EIP-55 reference vector 1
    /// (`0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed`) lands across the three
    /// rows with the reference casing.
    #[kani::proof]
    #[kani::unwind(210)]
    fn addr_full_eip55_reference_vector_concrete() {
        let addr: [u8; 20] = [
            0x5a, 0xae, 0xb6, 0x05, 0x3f, 0x3e, 0x94, 0xc9, 0xb9, 0xa0, 0x9f, 0x33, 0x66, 0x94,
            0x35, 0xe7, 0xef, 0x1b, 0xea, 0xed,
        ];
        let mut r1 = [0u8; DISPLAY_COLS];
        let mut r2 = [0u8; DISPLAY_COLS];
        let mut r3 = [0u8; DISPLAY_COLS];
        write_addr_full(&mut r1, &mut r2, &mut r3, &addr);
        assert!(r1 == *b"0x5aAeb6053F3E94");
        assert!(r2 == *b"C9b9A09f33669435");
        assert!(r3 == *b"E7Ef1BeAed      ");
    }
}
