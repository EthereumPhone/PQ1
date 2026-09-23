//! Positive + negative test suite for the `secure-tx-display` slice.
//!
//! See `reports/tests/secure-tx-display.md` for the full inventory.
//!
//! Layout:
//!
//!   * `mod fixtures` — tiny builders for the renderer inputs
//!     (`Eip1559Tx`, `NameResolver`, `Erc20Metadata`, `SelectorMeta`).
//!   * `mod row_helpers` — assertions over rendered `[u8; 16]` rows.
//!   * `positive_*` tests — happy-path coverage of every renderer.
//!   * `negative_*` tests — adversarial cases. **These are the most
//!     important deliverable of this pass.** Each one names the
//!     assumption it attacks and asserts the precise outcome that
//!     proves the assumption holds.

use core::cmp::min;

use super::primitives::{
    build_legacy_fee_pages, chain_name, format_u64, hex_nibble,
    legacy_fee_rows_are_exactly_renderable, native_ticker, token_amount_is_exactly_renderable,
    try_write_amount_single_row, write_addr_full, write_addr_full_or_name, write_amount_two_rows,
    write_calldata_hash_rows, write_chain, write_data_len_row, write_erc20_header,
    write_eth_two_rows, write_fee_budget_row, write_gas, write_gwei, write_line,
    write_native_amount_two_rows, write_native_currency_row, write_native_fee_budget_row,
    write_nonce_row, write_selector_row, write_tip_row, write_token_amount_two_rows,
    write_token_name, AmountFit,
};
use super::{Pages, MAX_PAGES};

use super::batch::{build_final_summary_pages, wrap_pages_with_batch_banner};
use super::blind_sign::render_blind_sign_pages;
use super::eip1271::{render_eip1271_personal_sign_pages, render_eip1271_raw32_pages};
use super::erc20_known::render_erc20_known_pages;
use super::erc20_unknown::render_erc20_unknown_pages;
use super::slot_rotation::build_slot_rotation_pages;
use super::typed_call::try_render_typed_call;
use super::value_transfer::render_pages;

use crate::erc20::bundle::Erc20Metadata;
use crate::erc20::calldata::Erc20Call;
use crate::names::NameResolver;
use crate::selectors::{SelectorMeta, SelectorProvenance};
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

mod fixtures {
    use super::*;

    /// Plain mainnet ETH transfer with non-zero fields so every page
    /// has visible content to assert on.
    pub fn sample_tx() -> Eip1559Tx {
        let mut tx = Eip1559Tx::default();
        tx.chain_id = 1; // Mainnet
        tx.nonce = 7;
        tx.to = Some([0x12; 20]);
        tx.value = u256_from_u64(1_000_000_000_000_000_000); // 1 ETH
        tx.gas_limit = 21_000;
        tx.max_fee_per_gas = u256_from_u64(30_000_000_000); // 30 gwei
        tx.max_priority_fee_per_gas = u256_from_u64(1_500_000_000); // 1.5 gwei
        tx.data_len = 0;
        tx
    }

    pub fn u256_from_u64(n: u64) -> U256 {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&n.to_be_bytes());
        U256(out)
    }

    pub fn usdc_metadata() -> Erc20Metadata<'static> {
        Erc20Metadata {
            chain_id: 1,
            contract: [0xAA; 20],
            decimals: 6,
            name: b"USD Coin",
            symbol: b"USDC",
        }
    }

    pub fn curated_selector(text_sig: &'static [u8], selector: [u8; 4]) -> SelectorMeta<'static> {
        SelectorMeta {
            selector,
            text_sig,
            provenance: SelectorProvenance::Curated,
        }
    }

    pub fn self_attest_selector(
        text_sig: &'static [u8],
        selector: [u8; 4],
    ) -> SelectorMeta<'static> {
        SelectorMeta {
            selector,
            text_sig,
            provenance: SelectorProvenance::SelfAttest,
        }
    }
}

use fixtures::*;

// ---------------------------------------------------------------------------
// Row-level assertion helpers
// ---------------------------------------------------------------------------

mod row_helpers {
    use super::*;

    /// Row content with trailing ASCII-spaces trimmed, as a `String` for
    /// readable assertion failure output.
    pub fn row_str(row: &[u8; DISPLAY_COLS]) -> String {
        let end = row.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
        String::from_utf8(row[..end].to_vec()).expect("rows are ASCII by construction")
    }

    /// Assert that every byte in every row of every page is printable
    /// ASCII — the trusted display must never paint a non-renderable
    /// glyph regardless of input.
    pub fn assert_all_pages_printable(pages: &Pages) {
        for (p, page) in pages.as_slice().iter().enumerate() {
            for (r, row) in page.iter().enumerate() {
                for (c, &b) in row.iter().enumerate() {
                    assert!(
                        (0x20..=0x7E).contains(&b),
                        "page {} row {} col {} byte {:#x} is not printable ASCII",
                        p,
                        r,
                        c,
                        b
                    );
                }
            }
        }
    }
}

use row_helpers::*;

// ===========================================================================
// POSITIVE TESTS — primitives
// ===========================================================================

#[test]
fn positive_write_line_short_fits_then_pads() {
    let mut row = [0u8; DISPLAY_COLS];
    write_line(&mut row, "hi");
    assert_eq!(&row[..2], b"hi");
    assert!(
        row[2..].iter().all(|&b| b == b' '),
        "tail must be space-padded"
    );
}

#[test]
fn positive_write_line_exact_width_no_overflow() {
    let mut row = [0u8; DISPLAY_COLS];
    let s = "0123456789ABCDEF"; // exactly 16 chars
    write_line(&mut row, s);
    assert_eq!(&row[..], s.as_bytes());
}

#[test]
fn positive_write_line_truncates_oversize() {
    let mut row = [0u8; DISPLAY_COLS];
    write_line(&mut row, "this is too long to fit in 16 columns");
    // First 16 bytes are the truncated input.
    assert_eq!(&row[..], b"this is too long");
}

#[test]
fn positive_write_line_empty_zeros_to_spaces() {
    let mut row = [b'X'; DISPLAY_COLS];
    write_line(&mut row, "");
    assert!(
        row.iter().all(|&b| b == b' '),
        "empty text must blank the row"
    );
}

#[test]
fn positive_format_u64_zero() {
    let mut buf = [0u8; 4];
    let n = format_u64(0, &mut buf).expect("zero must fit in 1 byte");
    assert_eq!(n, 1);
    assert_eq!(buf[0], b'0');
}

#[test]
fn positive_format_u64_u64_max() {
    let mut buf = [0u8; 20];
    let n = format_u64(u64::MAX, &mut buf).expect("u64::MAX is 20 digits");
    assert_eq!(n, 20);
    assert_eq!(&buf[..n], b"18446744073709551615");
}

#[test]
fn positive_hex_nibble_covers_full_range() {
    for n in 0u8..16 {
        let c = hex_nibble(n);
        let expected = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
        assert_eq!(c, expected, "hex_nibble({}) wrong", n);
    }
}

#[test]
fn positive_chain_name_known_chains() {
    assert_eq!(chain_name(1), "(Mainnet)");
    assert_eq!(chain_name(10), "(Optimism)");
    assert_eq!(chain_name(56), "(BSC)");
    assert_eq!(chain_name(100), "(Gnosis)");
    assert_eq!(chain_name(137), "(Polygon)");
    assert_eq!(chain_name(8453), "(Base)");
    assert_eq!(chain_name(42161), "(Arbitrum)");
    assert_eq!(chain_name(11155111), "(Sepolia)");
    assert_eq!(chain_name(84532), "(BaseSepolia)");
}

#[test]
fn positive_native_ticker_per_chain() {
    // review 3.5: the `amount` format's default unit is the chain's native
    // ticker. Non-ETH chains must map to their own symbol.
    assert_eq!(native_ticker(137), b"POL");
    assert_eq!(native_ticker(56), b"BNB");
    assert_eq!(native_ticker(43114), b"AVAX");
    assert_eq!(native_ticker(42220), b"CELO");
    assert_eq!(native_ticker(5_000), b"MNT");
    assert_eq!(native_ticker(80_094), b"BERA");
    // Mainnet + explicitly-listed ETH-gas L2s keep ETH. Unknown chains are
    // deliberately neutral: guessing ETH can confidently mislabel value.
    assert_eq!(native_ticker(1), b"ETH");
    assert_eq!(native_ticker(8453), b"ETH");
    assert_eq!(native_ticker(999_999), b"NATIVE");
}

#[test]
fn positive_write_chain_renders_decimal_and_label() {
    let mut row1 = [b' '; DISPLAY_COLS];
    let mut row2 = [b' '; DISPLAY_COLS];
    write_chain(&mut row1, &mut row2, 137);
    let s = row_str(&row1);
    assert_eq!(s, "Chain: 137");
    assert_eq!(row_str(&row2), "(Polygon)");
}

#[test]
fn positive_write_chain_losslessly_splits_large_u64_ids() {
    for chain_id in [1_380_012_617u64, u64::MAX] {
        let mut row1 = [b' '; DISPLAY_COLS];
        let mut row2 = [b' '; DISPLAY_COLS];
        write_chain(&mut row1, &mut row2, chain_id);
        let first = row_str(&row1);
        assert!(first.starts_with("Chain: ") && first.ends_with('>'));
        let reconstructed = format!(
            "{}{}",
            first.trim_start_matches("Chain: ").trim_end_matches('>'),
            row_str(&row2)
        );
        assert_eq!(reconstructed, chain_id.to_string());
        assert!(!first.contains("OVF"));
        assert!(!row_str(&row2).contains("OVF"));
    }
}

#[test]
fn positive_write_gas_renders_parens() {
    let mut row = [b' '; DISPLAY_COLS];
    assert!(write_gas(&mut row, 21_000));
    let s = row_str(&row);
    assert_eq!(s, "(gas: 21000)");
}

#[test]
fn positive_write_eth_two_rows_one_eth() {
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    let value = u256_from_u64(1_000_000_000_000_000_000); // 1 ETH
    let fit = write_eth_two_rows(&mut r1, &mut r2, &value);
    assert_eq!(fit, AmountFit::Full);
    // Audit M-6: ETH amounts render fixed-width (6 fractional digits, no
    // trailing-zero trim) like ERC-20 token amounts, so two distinct
    // values can't alias by the renderer silently dropping the digits
    // that distinguish them.
    assert_eq!(row_str(&r1), "1.000000 ETH");
}

#[test]
fn positive_native_amount_and_label_follow_signed_chain() {
    let mut label = [b' '; DISPLAY_COLS];
    write_native_currency_row(&mut label, b"Send ", 56, b"?");
    assert_eq!(row_str(&label), "Send BNB?");

    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    let one_native = u256_from_u64(1_000_000_000_000_000_000);
    assert_eq!(
        write_native_amount_two_rows(&mut r1, &mut r2, &one_native, 56),
        AmountFit::Full
    );
    assert_eq!(row_str(&r1), "1.000000 BNB");

    write_native_currency_row(&mut label, b"Send ", 999_999, b"?");
    assert_eq!(row_str(&label), "Send NATIVE?");
}

#[test]
fn positive_write_nonce_row() {
    let mut r = [b' '; DISPLAY_COLS];
    write_nonce_row(&mut r, 42);
    assert_eq!(row_str(&r), "Nonce: 42");
}

#[test]
fn positive_write_selector_row_with_data() {
    let mut r = [b' '; DISPLAY_COLS];
    let data = [0xde, 0xad, 0xbe, 0xef, 0x00];
    write_selector_row(&mut r, &data);
    assert_eq!(row_str(&r), "Sel: 0xdeadbeef");
}

#[test]
fn positive_write_selector_row_short_data() {
    let mut r = [b' '; DISPLAY_COLS];
    let data = [0xde, 0xad];
    write_selector_row(&mut r, &data);
    assert_eq!(row_str(&r), "Sel: (none)");
}

#[test]
fn positive_write_data_len_row() {
    let mut r = [b' '; DISPLAY_COLS];
    write_data_len_row(&mut r, 132);
    assert_eq!(row_str(&r), "Data: 132 B");
}

#[test]
fn positive_write_addr_full_renders_40_hex() {
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    let mut r3 = [b' '; DISPLAY_COLS];
    let mut addr = [0u8; 20];
    for (i, b) in addr.iter_mut().enumerate() {
        *b = i as u8;
    }
    write_addr_full(&mut r1, &mut r2, &mut r3, &addr);
    // Concatenate the rendered hex (excluding "0x" prefix and trailing pad).
    let mut hex_chars = Vec::new();
    // Row1 = "0x" + 14 hex chars
    hex_chars.extend_from_slice(&r1[2..16]);
    // Row2 = 16 hex chars
    hex_chars.extend_from_slice(&r2[..16]);
    // Row3 = 10 hex chars + 6 spaces
    hex_chars.extend_from_slice(&r3[..10]);
    assert_eq!(hex_chars.len(), 40);
    let s = String::from_utf8(hex_chars).unwrap();
    assert_eq!(
        s, "000102030405060708090a0b0c0d0e0f10111213",
        "full 40 hex chars must be painted across three rows"
    );
}

#[test]
fn positive_write_calldata_hash_rows_paints_head_and_tail() {
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    let mut hash = [0u8; 32];
    for (i, b) in hash.iter_mut().enumerate() {
        *b = i as u8;
    }
    write_calldata_hash_rows(&mut r1, &mut r2, &hash);
    // Row 1 = "0x" + bytes 0..7 = "0x00010203040506"
    assert_eq!(&r1[..16], b"0x00010203040506");
    // Row 2 = "... " + bytes 26..32 = "1a1b1c1d1e1f"
    assert_eq!(&r2[..4], b"... ");
    assert_eq!(&r2[4..16], b"1a1b1c1d1e1f");
}

#[test]
fn positive_try_write_amount_single_row_fits() {
    let mut row = [b' '; DISPLAY_COLS];
    let v = u256_from_u64(123);
    let ok = try_write_amount_single_row(&mut row, &v, 0, 0, true, true, "wei");
    assert!(ok);
    assert_eq!(row_str(&row), "123 wei");
}

#[test]
fn positive_write_amount_two_rows_integer_plus_unit() {
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    let v = u256_from_u64(123_456_789);
    let fit = write_amount_two_rows(&mut r1, &mut r2, &v, 0, 0, true, true, "TOKEN");
    assert_eq!(fit, AmountFit::Full);
    assert_eq!(row_str(&r1), "123456789");
    assert_eq!(row_str(&r2), "TOKEN");
}

/// F14#3 regression: a NONZERO amount that scales (via an untrusted
/// `decimals`) to all-zero display digits must overflow loudly, never paint a
/// misleading "0.000000". A poisoned ERC-7730 descriptor could otherwise hide
/// a balance-draining magnitude behind a harmless-looking near-zero.
#[test]
fn f14_3_nonzero_amount_collapsing_to_zero_overflows() {
    // 1 token-unit displayed at 30 decimals with 6 fractional digits → "0.000000".
    let v = u256_from_u64(1);
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    // Amount path (reject_zero_collapse = true) → Overflow.
    let fit = write_amount_two_rows(&mut r1, &mut r2, &v, 30, 6, true, true, "TKN");
    assert_eq!(
        fit,
        AmountFit::Overflow,
        "nonzero amount collapsing to 0 must overflow"
    );
    // Single-row amount path likewise refuses.
    let mut row = [b' '; DISPLAY_COLS];
    let ok = try_write_amount_single_row(&mut row, &v, 30, 6, true, true, "TKN");
    assert!(!ok, "single-row amount must refuse the zero-collapse");
    // Fee path (reject_zero_collapse = false): a genuinely tiny fee renders as
    // "0.000000" truthfully and is NOT flipped to overflow.
    let mut frow = [b' '; DISPLAY_COLS];
    let ok_fee = try_write_amount_single_row(&mut frow, &v, 30, 6, true, false, "gwei");
    assert!(ok_fee, "fee path keeps the truthful near-zero render");
    // A true zero is unaffected on the amount path (it really is zero).
    let zero = u256_from_u64(0);
    let mut z1 = [b' '; DISPLAY_COLS];
    let mut z2 = [b' '; DISPLAY_COLS];
    let zfit = write_amount_two_rows(&mut z1, &mut z2, &zero, 18, 6, true, true, "ETH");
    assert_eq!(zfit, AmountFit::Full, "a true zero amount renders normally");
}

#[test]
fn positive_write_token_name() {
    let mut row = [b' '; DISPLAY_COLS];
    let meta = usdc_metadata();
    write_token_name(&mut row, &meta);
    assert_eq!(row_str(&row), "USD Coin");
}

#[test]
fn positive_write_erc20_header_send_and_approve() {
    let meta = usdc_metadata();

    let mut row = [b' '; DISPLAY_COLS];
    let call = Erc20Call::Transfer {
        to: [0; 20],
        amount: u256_from_u64(1),
    };
    write_erc20_header(&mut row, &call, &meta);
    assert_eq!(row_str(&row), "Send USDC");

    let mut row = [b' '; DISPLAY_COLS];
    let call = Erc20Call::Approve {
        spender: [0; 20],
        amount: u256_from_u64(1),
    };
    write_erc20_header(&mut row, &call, &meta);
    assert_eq!(row_str(&row), "Approve USDC");

    let mut row = [b' '; DISPLAY_COLS];
    let call = Erc20Call::Approve {
        spender: [0; 20],
        amount: U256::zero(),
    };
    write_erc20_header(&mut row, &call, &meta);
    assert_eq!(row_str(&row), "Revoke approval");

    let mut row = [b' '; DISPLAY_COLS];
    let call = Erc20Call::TransferFrom {
        from: [0; 20],
        to: [0; 20],
        amount: u256_from_u64(1),
    };
    write_erc20_header(&mut row, &call, &meta);
    assert_eq!(row_str(&row), "From USDC");
}

#[test]
fn positive_write_token_amount_two_rows_full() {
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    let meta = usdc_metadata();
    let amount = u256_from_u64(1_000_000); // 1 USDC (decimals=6)
    let fit = write_token_amount_two_rows(&mut r1, &mut r2, &amount, &meta);
    assert_eq!(fit, AmountFit::Full);
    // Fixed-width fractional digits → "1.000000 USDC" on row 1.
    let s = row_str(&r1);
    assert_eq!(s, "1.000000 USDC");
}

#[test]
fn legacy_token_adjacent_low_digits_render_exactly_without_collision() {
    let meta = Erc20Metadata {
        chain_id: 1,
        contract: [0xBB; 20],
        decimals: 8,
        name: b"Wrapped Bitcoin",
        symbol: b"WBTC",
    };

    for (raw, expected) in [
        (100_000_001, "1.00000001 WBTC"),
        (100_000_002, "1.00000002 WBTC"),
    ] {
        let amount = u256_from_u64(raw);
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        assert!(token_amount_is_exactly_renderable(&amount, &meta));
        assert_eq!(
            write_token_amount_two_rows(&mut r1, &mut r2, &amount, &meta),
            AmountFit::Full
        );
        assert_eq!(row_str(&r1), expected);
        assert_eq!(row_str(&r2), "");
    }
}

/// A full-precision 18-decimal amount (a CoW quote-derived `buyAmount`)
/// fits neither the two-row decimal form nor labelled base units; it wraps
/// exactly across both rows with continuation marks instead of refusing.
#[test]
fn legacy_token_full_precision_18_decimals_wraps_exactly() {
    fn u256_dec(s: &str) -> U256 {
        let mut v = [0u8; 32];
        for c in s.bytes() {
            let mut carry = u32::from(c - b'0');
            for b in v.iter_mut().rev() {
                let x = u32::from(*b) * 10 + carry;
                *b = (x & 0xff) as u8;
                carry = x >> 8;
            }
        }
        U256(v)
    }
    let meta = Erc20Metadata {
        chain_id: 8453,
        contract: [0x50; 20],
        decimals: 18,
        name: b"Dai Stablecoin",
        symbol: b"DAI",
    };
    for (raw, e1, e2) in [
        ("9987654321098765432", "9.9876543210987>", ">65432 DAI"),
        ("1234987654321098765432", "1234.9876543210>", ">98765432 DAI"),
        ("1000000987654321098765432", "1000000.9876543>", ">21098765432 DAI"),
    ] {
        let amount = u256_dec(raw);
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        assert!(token_amount_is_exactly_renderable(&amount, &meta), "{raw}");
        assert_eq!(
            write_token_amount_two_rows(&mut r1, &mut r2, &amount, &meta),
            AmountFit::Full
        );
        assert_eq!(row_str(&r1), e1);
        assert_eq!(row_str(&r2), e2);
    }
    // Ten million DAI at full precision needs 17 columns on row 2: refused,
    // never rounded.
    let amount = u256_dec("10000000987654321098765432");
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    assert!(!token_amount_is_exactly_renderable(&amount, &meta));
    assert_eq!(
        write_token_amount_two_rows(&mut r1, &mut r2, &amount, &meta),
        AmountFit::Overflow
    );
    // Amounts that already fit keep their established form.
    let amount = u256_dec("9987654321000000000");
    assert_eq!(
        write_token_amount_two_rows(&mut r1, &mut r2, &amount, &meta),
        AmountFit::Full
    );
    assert_eq!(row_str(&r1), "9.987654321 DAI");
}

#[test]
fn legacy_token_base_unit_fallback_never_truncates_symbol() {
    let meta = Erc20Metadata {
        chain_id: 1,
        contract: [0xBC; 20],
        decimals: 18,
        name: b"Long symbol token",
        symbol: b"ABCDEFGHIJK",
    };
    let amount = u256_from_u64(1);
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];

    assert!(!token_amount_is_exactly_renderable(&amount, &meta));
    assert_eq!(
        write_token_amount_two_rows(&mut r1, &mut r2, &amount, &meta),
        AmountFit::Overflow
    );
}

// ===========================================================================
// POSITIVE TESTS — value transfer renderer
// ===========================================================================

#[test]
fn positive_value_transfer_renders_six_pages() {
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let pages = render_pages(&tx, &resolver);
    assert_eq!(pages.len, 6, "plain ETH transfer renders exactly 6 pages");
    assert_all_pages_printable(&pages);
}

#[test]
fn positive_value_transfer_send_eth_banner_for_nonzero_value() {
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let pages = render_pages(&tx, &resolver);
    assert_eq!(row_str(&pages.buf[0][0]), "Send ETH?");
    assert_eq!(row_str(&pages.buf[0][1]), "Chain: 1");
    assert_eq!(row_str(&pages.buf[0][2]), "(Mainnet)");
}

#[test]
fn positive_value_transfer_non_eth_chain_never_uses_eth_labels() {
    let mut tx = sample_tx();
    tx.chain_id = 56;
    let resolver = NameResolver::new();
    let pages = render_pages(&tx, &resolver);
    let rows: Vec<String> = pages
        .as_slice()
        .iter()
        .flat_map(|page| page.iter().map(row_str))
        .collect();
    assert!(rows.iter().any(|r| r == "Send BNB?"));
    assert!(rows.iter().any(|r| r.contains("BNB")));
    assert!(
        rows.iter().all(|r| !r.contains("ETH")),
        "BSC native value/fee pages must not be mislabelled ETH: {rows:?}"
    );
}

#[test]
fn positive_value_transfer_contract_call_banner_when_value_zero() {
    let mut tx = sample_tx();
    tx.value = U256::zero();
    let resolver = NameResolver::new();
    let pages = render_pages(&tx, &resolver);
    assert_eq!(row_str(&pages.buf[0][0]), "Contract call?");
}

#[test]
fn positive_value_transfer_last_page_has_cancel_confirm() {
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let pages = render_pages(&tx, &resolver);
    assert_eq!(row_str(&pages.buf[5][2]), "L=Cancel");
    assert_eq!(row_str(&pages.buf[5][3]), "R=Confirm");
}

#[test]
fn positive_value_transfer_contract_create_when_to_none() {
    let mut tx = sample_tx();
    tx.to = None;
    let resolver = NameResolver::new();
    let pages = render_pages(&tx, &resolver);
    assert_eq!(row_str(&pages.buf[1][0]), "To:");
    // write_line truncates to DISPLAY_COLS = 16; "(contract create)" = 17 → ")" drops.
    assert_eq!(row_str(&pages.buf[1][1]), "(contract create");
}

// ===========================================================================
// POSITIVE TESTS — blind sign renderer
// ===========================================================================

#[test]
fn positive_blind_sign_nine_pages_without_selector() {
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let data = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
    let pages = render_blind_sign_pages(&tx, &data, None, &resolver);
    assert_eq!(pages.len, 9, "no-selector blind sign has 9 pages");
    assert_eq!(row_str(&pages.buf[0][0]), "! BLIND SIGN");
    assert_eq!(row_str(&pages.buf[0][1]), "Unknown call");
    assert_eq!(row_str(&pages.buf[0][2]), "Verify on dapp");
    assert_all_pages_printable(&pages);
}

#[test]
fn positive_blind_sign_ten_pages_with_selector() {
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let data = [0xde, 0xad, 0xbe, 0xef, 0x01];
    let meta = curated_selector(b"foo()", [0xde, 0xad, 0xbe, 0xef]);
    let pages = render_blind_sign_pages(&tx, &data, Some(&meta), &resolver);
    assert_eq!(pages.len, 10, "with-selector blind sign has 10 pages");
    assert_eq!(row_str(&pages.buf[1][0]), "FUNCTION:");
    assert_eq!(row_str(&pages.buf[1][1]), "foo()");
}

#[test]
fn positive_blind_sign_calldata_hash_matches_sha256() {
    use sha2::{Digest, Sha256};
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let data: Vec<u8> = (0..50u8).collect();
    let pages = render_blind_sign_pages(&tx, &data, None, &resolver);

    // The calldata-hash page lives at offset 4 in the 9-page no-selector
    // layout (0 banner, 1 to, 2 value, 3 sel+data-len, 4 data hash).
    // Verify the head/tail bytes rendered match SHA-256(data).
    let expected = Sha256::digest(&data);
    let row1 = &pages.buf[4][1];
    let row2 = &pages.buf[4][2];
    // Row 1 head = "0x" + first 7 bytes of hash
    let head_hex = format!(
        "0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        expected[0], expected[1], expected[2], expected[3], expected[4], expected[5], expected[6]
    );
    assert_eq!(&row1[..16], head_hex.as_bytes());
    let tail_hex = format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        expected[26], expected[27], expected[28], expected[29], expected[30], expected[31]
    );
    assert_eq!(&row2[..4], b"... ");
    assert_eq!(&row2[4..16], tail_hex.as_bytes());
}

// ===========================================================================
// POSITIVE TESTS — ERC-20 known renderer
// ===========================================================================

#[test]
fn positive_erc20_known_transfer_eight_pages() {
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let meta = usdc_metadata();
    let call = Erc20Call::Transfer {
        to: [0x33; 20],
        amount: u256_from_u64(100_000_000), // 100 USDC
    };
    let pages = render_erc20_known_pages(&tx, &call, &meta, &resolver);
    assert_eq!(pages.len, 8, "ERC-20 known renderer always returns 8 pages");
    assert_eq!(row_str(&pages.buf[0][0]), "Send USDC");
    assert_eq!(row_str(&pages.buf[0][1]), "USD Coin");
    assert_eq!(row_str(&pages.buf[1][0]), "Recipient:");
    assert_eq!(row_str(&pages.buf[2][0]), "Amount:");
    assert_eq!(row_str(&pages.buf[3][0]), "Contract:");
    assert_eq!(row_str(&pages.buf[4][0]), "Chain:");
    assert_eq!(row_str(&pages.buf[7][3]), "R=Confirm");
}

/// Concatenate ASCII-hex digits across rows 1..3 of a page (drops "0x",
/// spaces, "..." separators) so a full 40-hex address can be matched.
fn page_hex(pages: &Pages, page: usize) -> String {
    (1..DISPLAY_ROWS)
        .flat_map(|r| row_str(&pages.buf[page][r]).chars().collect::<Vec<_>>())
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_lowercase()
}

#[test]
fn positive_erc20_known_transfer_binds_amount_digits_and_recipient_hex() {
    // Item 2 of the 2026-06-29 coverage audit: the prior tests asserted only
    // the LABELS ("Amount:", "Recipient:") — never the rendered digits/hex.
    // The amount + recipient are the security-critical fields; bind them to
    // the DECODED `Erc20Call`, exercising the real `write_token_amount_two_rows`
    // + `write_addr_full` formatters.
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let meta = usdc_metadata(); // 6 decimals, "USDC"
    let recipient = [0x33u8; 20];
    let call = Erc20Call::Transfer {
        to: recipient,
        amount: u256_from_u64(100_000_000), // 100.000000 USDC
    };
    let pages = render_erc20_known_pages(&tx, &call, &meta, &resolver);

    // Amount page (2): the rendered integer digits + symbol, not just "Amount:".
    let amount = format!(
        "{}|{}",
        row_str(&pages.buf[2][1]),
        row_str(&pages.buf[2][2])
    );
    assert!(
        amount.contains("100"),
        "amount must render the integer 100; got {amount:?}"
    );
    assert!(
        amount.contains("USDC"),
        "amount must carry the symbol; got {amount:?}"
    );

    // Recipient page (1): the FULL 40-hex recipient across rows 1-3.
    let want: String = recipient.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        page_hex(&pages, 1).contains(&want),
        "recipient page must show the full 40-hex recipient {want}"
    );
}

#[test]
fn negative_erc20_amount_digits_nonvacuous() {
    // Non-vacuity: a different decoded amount must change the rendered digits
    // (proves the assertion binds the decoded value, not a constant).
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let meta = usdc_metadata();
    let mk = |raw: u64| {
        let call = Erc20Call::Transfer {
            to: [0x33; 20],
            amount: u256_from_u64(raw),
        };
        let p = render_erc20_known_pages(&tx, &call, &meta, &resolver);
        format!("{}|{}", row_str(&p.buf[2][1]), row_str(&p.buf[2][2]))
    };
    let a100 = mk(100_000_000); // 100 USDC
    let a250 = mk(250_000_000); // 250 USDC
    assert!(a100.contains("100") && !a100.contains("250"));
    assert!(a250.contains("250") && !a250.contains("100"));
    assert_ne!(a100, a250);
}

#[test]
fn positive_erc20_known_approve_unlimited_renders_word() {
    let mut tx = sample_tx();
    tx.value = U256::zero();
    let resolver = NameResolver::new();
    let meta = usdc_metadata();
    let unlimited = U256([0xFFu8; 32]);
    let call = Erc20Call::Approve {
        spender: [0x44; 20],
        amount: unlimited,
    };
    let pages = render_erc20_known_pages(&tx, &call, &meta, &resolver);
    assert_eq!(row_str(&pages.buf[2][0]), "Amount:");
    assert_eq!(row_str(&pages.buf[2][1]), "unlimited");
    assert_eq!(
        row_str(&pages.buf[1][0]),
        "Spender:",
        "Approve must label the recipient row as 'Spender:'"
    );
}

#[test]
fn positive_erc20_known_exact_zero_approve_renders_revoke_without_hiding_facts() {
    let mut tx = sample_tx();
    tx.value = U256::zero();
    let resolver = NameResolver::new();
    let meta = usdc_metadata();
    let spender = [0x44; 20];
    let pages = render_erc20_known_pages(
        &tx,
        &Erc20Call::Approve {
            spender,
            amount: U256::zero(),
        },
        &meta,
        &resolver,
    );

    assert_eq!(row_str(&pages.buf[0][0]), "Revoke approval");
    assert_eq!(row_str(&pages.buf[1][0]), "Spender:");
    let spender_hex: String = spender.iter().map(|b| format!("{b:02x}")).collect();
    assert!(page_hex(&pages, 1).contains(&spender_hex));
    assert_eq!(row_str(&pages.buf[2][0]), "Amount:");
    assert!(row_str(&pages.buf[2][1]).starts_with("0.000000 USDC"));
    assert_eq!(row_str(&pages.buf[3][0]), "Contract:");
    assert_eq!(row_str(&pages.buf[4][0]), "Chain:");
    assert_eq!(row_str(&pages.buf[4][1]), "Chain: 1");
}

// ===========================================================================
// POSITIVE TESTS — ERC-20 unknown renderer
// ===========================================================================

#[test]
fn positive_erc20_unknown_renders_warning_banner() {
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let call = Erc20Call::Transfer {
        to: [0x33; 20],
        amount: u256_from_u64(42),
    };
    let pages = render_erc20_unknown_pages(&tx, &call, &resolver);
    assert_eq!(pages.len, 8);
    assert_eq!(row_str(&pages.buf[0][0]), "! Unknown token");
    assert_eq!(row_str(&pages.buf[0][1]), "transfer");
    assert_eq!(row_str(&pages.buf[0][2]), "(decimals = ?)");
}

#[test]
fn positive_unknown_token_zero_approve_paints_revoke_framing() {
    // #474: approve(spender, 0) on an UNKNOWN token is an allowance
    // revocation — the amount page must say so in words (same framing
    // as the known-token header, erc7730 `write_erc20_header`) instead
    // of a raw `0` that reads like a rendering glitch. The banner stays
    // `approve`/`(decimals = ?)` — only the amount page changes.
    let mut tx = sample_tx();
    tx.value = U256::zero();
    let resolver = NameResolver::new();
    let pages = render_erc20_unknown_pages(
        &tx,
        &Erc20Call::Approve {
            spender: [0x44; 20],
            amount: U256::zero(),
        },
        &resolver,
    );
    assert_eq!(row_str(&pages.buf[0][0]), "! Unknown token");
    assert_eq!(row_str(&pages.buf[0][1]), "approve");
    // Amount page for approve: banner, contract, spender, then amount.
    assert_eq!(row_str(&pages.buf[3][0]), "Amount (raw):");
    assert_eq!(row_str(&pages.buf[3][1]), "Revoke approval");
}

#[test]
fn negative_unknown_token_revoke_framing_only_fires_on_exact_zero() {
    // The revoke affordance must not swallow real amounts: a non-zero
    // approve keeps the raw digits, and the `is_unlimited_amount`
    // branch keeps its precedence (unlimited can never read "Revoke").
    let mut tx = sample_tx();
    tx.value = U256::zero();
    let resolver = NameResolver::new();

    let pages = render_erc20_unknown_pages(
        &tx,
        &Erc20Call::Approve {
            spender: [0x44; 20],
            amount: u256_from_u64(42),
        },
        &resolver,
    );
    assert_eq!(row_str(&pages.buf[3][1]), "42");

    let pages = render_erc20_unknown_pages(
        &tx,
        &Erc20Call::Approve {
            spender: [0x44; 20],
            amount: U256([0xFFu8; 32]),
        },
        &resolver,
    );
    assert_eq!(
        row_str(&pages.buf[3][1]),
        "unlimited",
        "is_unlimited_amount must keep precedence over the revoke framing"
    );

    // transfer(to, 0) is a zero SEND, not a revocation — raw `0` stays.
    let pages = render_erc20_unknown_pages(
        &tx,
        &Erc20Call::Transfer {
            to: [0x44; 20],
            amount: U256::zero(),
        },
        &resolver,
    );
    assert_eq!(row_str(&pages.buf[3][1]), "0");
    assert!(pages
        .as_slice()
        .iter()
        .flat_map(|page| page.iter())
        .all(|row| !row_str(row).contains("Revoke")));
}

// ===========================================================================
// POSITIVE TESTS — EIP-1271 renderers
// ===========================================================================

#[test]
fn positive_eip1271_personal_sign_short_message() {
    let wallet = [0x55u8; 20];
    let msg = b"hello dapp";
    let pages = render_eip1271_personal_sign_pages(1, 0, 1, &wallet, msg, 5, 4, 100, true);
    // Layout: 5 fixed + ceil(len/48) = 5 + 1 = 6 pages.
    assert_eq!(pages.len, 6);
    assert_eq!(row_str(&pages.buf[0][0]), "EIP-1271 Sign?");
    assert_eq!(row_str(&pages.buf[0][1]), "personal_sign");
    assert_eq!(row_str(&pages.buf[0][2]), "Verify on dapp");
    // Message page is index 4. Row 0 should be "hello dapp".
    assert_eq!(row_str(&pages.buf[4][0]), "hello dapp");
    assert_all_pages_printable(&pages);
}

#[test]
fn positive_eip1271_personal_sign_empty_message_still_one_msg_page() {
    let wallet = [0x55u8; 20];
    let pages = render_eip1271_personal_sign_pages(1, 0, 0, &wallet, b"", 5, 4, 100, true);
    // Empty message still produces 1 message page (5 fixed + 1 = 6).
    assert_eq!(pages.len, 6);
}

#[test]
fn positive_eip1271_raw32_six_pages() {
    let mut hash = [0u8; 32];
    for (i, b) in hash.iter_mut().enumerate() {
        *b = i as u8;
    }
    let pages = render_eip1271_raw32_pages(1, 0, 1, &hash, 5, 4, 100, true);
    assert_eq!(pages.len, 6);
    assert_eq!(row_str(&pages.buf[0][0]), "EIP-1271 Sign?");
    assert_eq!(row_str(&pages.buf[0][1]), "! BLIND RAW32");
    assert_eq!(row_str(&pages.buf[3][0]), "Hash 1/2:");
    assert_eq!(row_str(&pages.buf[4][0]), "Hash 2/2:");
    // Hash 1/2 row 1: first 8 bytes hex
    assert_eq!(&pages.buf[3][1][..16], b"0001020304050607");
    // Hash 2/2 row 2: last 8 bytes hex
    assert_eq!(&pages.buf[4][2][..16], b"18191a1b1c1d1e1f");
}

// ===========================================================================
// POSITIVE TESTS — slot rotation + batch
// ===========================================================================

#[test]
fn positive_slot_rotation_single_page() {
    let pages = build_slot_rotation_pages(3);
    assert_eq!(pages.len, 1);
    // row 1 = centered "ROTATE SLOT?"
    let row1 = row_str(&pages.buf[0][1]);
    assert!(
        row1.contains("ROTATE SLOT?"),
        "row 1 must show the prompt, got {:?}",
        row1
    );
    let row2 = row_str(&pages.buf[0][2]);
    assert!(
        row2.contains("Slot: 3"),
        "row 2 must show the slot index, got {:?}",
        row2
    );
    let row3 = row_str(&pages.buf[0][3]);
    assert!(
        row3.contains("+bootstrap use"),
        "row 3 must warn about bootstrap-use consumption, got {:?}",
        row3
    );
}

#[test]
fn positive_batch_wrap_adds_banner_page() {
    let resolver = NameResolver::new();
    let tx = sample_tx();
    let inner = render_pages(&tx, &resolver);
    let inner_len = inner.len;
    let wrapped = wrap_batch_for_test(&inner, 0, 3).expect("banner fits");
    assert_eq!(wrapped.len, inner_len + 1);
    // Banner page is page 0
    let row1 = row_str(&wrapped.buf[0][1]);
    assert!(row1.contains("BATCH SIGN"));
    let row2 = row_str(&wrapped.buf[0][2]);
    assert!(
        row2.contains("Tx 1 of 3"),
        "1-based render of batch index, got {:?}",
        row2
    );
}

fn wrap_batch_for_test(inner: &Pages, tx_index: usize, batch_total: usize) -> Result<Pages, ()> {
    let mut wrapped = Pages::empty_with_len(0);
    let mut cfi = crate::fi::CfiCounter::new();
    wrap_pages_with_batch_banner(inner, tx_index, batch_total, &mut wrapped, &mut cfi)?;
    if cfi.check_into_sentinel(super::batch::BATCH_BANNER_CFI_EXPECTED) != crate::fi::OK_SENTINEL
        || super::batch::batch_banner_copy_proof(inner, &wrapped, tx_index, batch_total)
            != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    Ok(wrapped)
}

#[test]
fn positive_batch_final_summary_text() {
    let pages = build_final_summary_pages(3);
    assert_eq!(pages.len, 1);
    let row1 = row_str(&pages.buf[0][1]);
    assert!(row1.contains("Sign 3 txs?"), "got {:?}", row1);
}

// ===========================================================================
// POSITIVE TESTS — Pages container
// ===========================================================================

#[test]
fn positive_pages_empty_with_len_at_max() {
    // The upper bound is inclusive.
    let pages = Pages::empty_with_len(MAX_PAGES);
    assert_eq!(pages.len, MAX_PAGES);
    assert_eq!(pages.as_slice().len(), MAX_PAGES);
}

#[test]
fn positive_pages_row_mut_within_bounds() {
    let mut pages = Pages::empty_with_len(3);
    pages.row_mut(2, DISPLAY_ROWS - 1)[0] = b'X';
    assert_eq!(pages.buf[2][DISPLAY_ROWS - 1][0], b'X');
}

// ===========================================================================
// NEGATIVE TESTS — the critical deliverable
// ===========================================================================

// --- KDF-tag-stability analog: pin chain-name strings ----------------------

#[test]
fn negative_chain_name_unknown_chain_marked_unknown() {
    // A chain id NOT on the curated list renders "(unknown chain)". The numeric
    // id is ALWAYS shown on the row above (`write_chain`), so this label is
    // advisory — an obscure chain does NOT look like mainnet (its id differs on
    // screen). We reserve the stronger "UNVERIFIED" marker for an unverified
    // *token* so it keeps a single meaning (review 4.8). Pins the exact string.
    for unknown in [0u64, 2, 11, 100000, u64::MAX] {
        assert_eq!(
            chain_name(unknown),
            "(unknown chain)",
            "unlisted chain {} must render '(unknown chain)' — see invariant in primitives.rs",
            unknown,
        );
    }
    // Newly-labelled registry chains must NOT fall through to the unknown label.
    assert_eq!(chain_name(43114), "(Avalanche)");
    assert_eq!(chain_name(59144), "(Linea)");
    assert_eq!(chain_name(146), "(Sonic)");
}

#[test]
fn negative_chain_name_mainnet_distinct_from_sidechains() {
    // Assumption: an attacker who flips a single bit of chain_id (e.g.
    // 1 → 10) must not produce a chain name that visually impersonates
    // mainnet. The known-chain list is small so we can spot-check every
    // pair.
    let labels: &[(u64, &str)] = &[
        (1, "(Mainnet)"),
        (10, "(Optimism)"),
        (56, "(BSC)"),
        (100, "(Gnosis)"),
        (137, "(Polygon)"),
        (8453, "(Base)"),
        (42161, "(Arbitrum)"),
        (11155111, "(Sepolia)"),
        (84532, "(BaseSepolia)"),
    ];
    for (id, name) in labels {
        assert_eq!(chain_name(*id), *name);
        // No two labels collide.
        for (id2, name2) in labels {
            if id != id2 {
                assert_ne!(
                    name, name2,
                    "chain labels {} and {} must not visually collide",
                    id, id2
                );
            }
        }
    }
}

// --- "Never silently truncate a number" — primitives.rs design rule -------

#[test]
fn negative_format_u64_refuses_to_truncate() {
    // Assumption: format_u64 returns None rather than silently writing
    // a wrong-but-fitting prefix when out is too small. A wrong-by-
    // truncation gas/nonce/chain rendering would be more dangerous than
    // a visible "!OVF".
    let mut buf = [0u8; 2];
    assert!(
        format_u64(1_000_000, &mut buf).is_none(),
        "format_u64 must NOT silently truncate when buffer is too small"
    );
}

#[test]
fn negative_write_gas_overflow_paints_marker_not_wrong_digits() {
    // Assumption: a gas value that doesn't fit in decimal on 16 cols
    // must surface "!OVF" rather than a truncated number that looks
    // smaller than reality. Triggered by very large gas limits.
    let mut row = [b' '; DISPLAY_COLS];
    // (gas: ) = 6 + ")" = 7. We have 16-7 = 9 cols for the number,
    // so 10^9-ish triggers the overflow marker.
    assert!(!write_gas(&mut row, u64::MAX)); // 20 digits, can't fit
    let s = row_str(&row);
    assert!(
        s.contains("!OVF"),
        "u64::MAX gas must surface !OVF, got {:?}",
        s
    );
}

#[test]
fn legacy_fee_gate_refuses_a_lossy_gas_marker_even_when_fees_are_zero() {
    let zero = u256_from_u64(0);
    let mut row = [b' '; DISPLAY_COLS];

    assert!(write_gas(&mut row, 999_999_999));
    assert_eq!(row_str(&row), "(gas: 999999999)");
    assert!(legacy_fee_rows_are_exactly_renderable(
        &zero,
        &zero,
        999_999_999,
        1,
    ));

    assert!(!write_gas(&mut row, 1_000_000_000));
    assert_eq!(row_str(&row), "(gas: !OVF)");
    assert!(!legacy_fee_rows_are_exactly_renderable(
        &zero,
        &zero,
        1_000_000_000,
        1,
    ));
}

#[test]
fn negative_write_nonce_row_overflow_paints_marker() {
    let mut row = [b' '; DISPLAY_COLS];
    write_nonce_row(&mut row, u64::MAX); // 20 digits, blows past 16 cols
    let s = row_str(&row);
    assert!(
        s.contains("!OVF"),
        "u64::MAX nonce must surface !OVF, got {:?}",
        s
    );
}

#[test]
fn negative_write_eth_two_rows_pathological_overflow() {
    // Assumption: U256::MAX renders as Overflow, not as a wrong
    // modulus-reduced value. write_eth_two_rows attempts 4 frac widths
    // single-row, then a 2-row fallback. A 78-digit integer can't fit;
    // we MUST surface AmountFit::Overflow.
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    let max = U256([0xFFu8; 32]);
    let fit = write_eth_two_rows(&mut r1, &mut r2, &max);
    assert_eq!(
        fit,
        AmountFit::Overflow,
        "U256::MAX as ETH must report Overflow"
    );
}

#[test]
fn negative_write_gwei_overflow_falls_to_explicit_marker() {
    let mut row = [b' '; DISPLAY_COLS];
    let max = U256([0xFFu8; 32]);
    let ok = write_gwei(&mut row, &max);
    let s = row_str(&row);
    assert!(!ok, "U256::MAX gas price must return false");
    assert_eq!(
        s, "!OVERFLOW",
        "overflow must paint the explicit '!OVERFLOW' marker, got {:?}",
        s
    );
}

#[test]
fn legacy_gwei_adjacent_wei_render_exactly_without_collision() {
    for (raw, expected) in [(1, "0.000000001 gwei"), (2, "0.000000002 gwei")] {
        let mut row = [b' '; DISPLAY_COLS];
        assert!(write_gwei(&mut row, &u256_from_u64(raw)));
        assert_eq!(row_str(&row), expected);
    }
}

// --- Anti-spoof: full 40-hex address rendering -----------------------------

#[test]
fn negative_write_addr_full_middle_byte_difference_visible() {
    // Assumption (per erc20_known.rs docstring + primitives.rs full-
    // address contract): two addresses that differ ONLY in a middle
    // byte must render to different rows. Truncated 7+8-hex layouts
    // exposed a brute-force collision window in middle bytes; the
    // current design closes it.
    let a = [0u8; 20];
    let mut b = [0u8; 20];
    b[10] = 0xFF; // attacker mutates a middle byte
    let mut a_rows = [[b' '; DISPLAY_COLS]; 3];
    let mut b_rows = [[b' '; DISPLAY_COLS]; 3];
    let [a1, a2, a3] = &mut a_rows;
    let [b1, b2, b3] = &mut b_rows;
    write_addr_full(a1, a2, a3, &a);
    write_addr_full(b1, b2, b3, &b);
    assert_ne!(
        a_rows, b_rows,
        "addresses differing in byte 10 must render differently"
    );
}

#[test]
fn negative_addr_full_or_name_unknown_falls_back_to_hex() {
    // Assumption: name resolver miss must fall back to the full 40-hex
    // render; a malicious "name" sneak-substitute can't happen because
    // no name is shown without a Merkle hit.
    let resolver = NameResolver::new();
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    let mut r3 = [b' '; DISPLAY_COLS];
    let addr = [0xAB; 20];
    write_addr_full_or_name(&mut r1, &mut r2, &mut r3, &addr, 1, &resolver);
    // No name → no "+ " sentinel — row 1 must start with "0x".
    assert_eq!(
        &r1[..2],
        b"0x",
        "unknown address must fall back to hex render (no name sentinel)"
    );
}

// --- Unlimited-approve UI affordance (anti-spoof) --------------------------

#[test]
fn negative_approve_unlimited_only_fires_for_approve() {
    // Assumption: Approve(2^200+) renders as the word "unlimited" so a
    // dapp can't disguise a max approval as a finite-looking number.
    // BUT: Transfer with the same large amount MUST render the digits
    // (you don't want a Send to be hidden behind the word "unlimited").
    let mut tx = sample_tx();
    tx.value = U256::zero();
    let resolver = NameResolver::new();
    let meta = usdc_metadata();
    let unlimited = U256([0xFFu8; 32]);

    // 1. Approve(unlimited) → word "unlimited".
    let pages = render_erc20_known_pages(
        &tx,
        &Erc20Call::Approve {
            spender: [0; 20],
            amount: unlimited,
        },
        &meta,
        &resolver,
    );
    assert_eq!(row_str(&pages.buf[2][1]), "unlimited");

    // 2. Transfer(unlimited) → MUST NOT collapse to "unlimited".
    let pages = render_erc20_known_pages(
        &tx,
        &Erc20Call::Transfer {
            to: [0; 20],
            amount: unlimited,
        },
        &meta,
        &resolver,
    );
    assert_ne!(
        row_str(&pages.buf[2][1]),
        "unlimited",
        "Transfer must render the digits — only Approve gets the 'unlimited' affordance"
    );
}

#[test]
fn negative_approve_below_threshold_renders_as_number() {
    // Assumption: 2^200 is the threshold (per is_unlimited_amount). One
    // bit below should render as a number, not as "unlimited".
    let mut tx = sample_tx();
    tx.value = U256::zero();
    let resolver = NameResolver::new();
    let meta = usdc_metadata();
    // Construct 2^200 - 1: byte 7 = 0x01 nope; actually 2^200 has byte 6
    // (BE index, MSB-first) = 0x01 and everything below zero. So 2^200-1
    // has bytes 0..7 all zero and bytes 7..32 = 0xFF.
    let mut amt = [0u8; 32];
    for i in 7..32 {
        amt[i] = 0xFF;
    }
    let call = Erc20Call::Approve {
        spender: [0; 20],
        amount: U256(amt),
    };
    let pages = render_erc20_known_pages(&tx, &call, &meta, &resolver);
    assert_ne!(
        row_str(&pages.buf[2][1]),
        "unlimited",
        "amounts < 2^200 must render as digits, not 'unlimited'"
    );
}

// --- ERC-20 native-ETH cross-injection warning -----------------------------

#[test]
fn negative_erc20_known_warns_on_native_eth_attached() {
    // Assumption: a legitimate ERC-20 call never carries native ETH
    // value. If NS supplies non-zero tx.value on an ERC-20 call, the
    // header MUST visibly warn the user.
    let mut tx = sample_tx();
    tx.value = u256_from_u64(1); // attacker hides 1 wei in the ERC-20 wrapper
    let resolver = NameResolver::new();
    let meta = usdc_metadata();
    let call = Erc20Call::Transfer {
        to: [0; 20],
        amount: u256_from_u64(1),
    };
    let pages = render_erc20_known_pages(&tx, &call, &meta, &resolver);
    assert_eq!(row_str(&pages.buf[0][2]), "! native ETH!");
}

#[test]
fn negative_erc20_known_no_false_warning_when_value_zero() {
    // Assumption complement: the warning must NOT appear on a legit
    // zero-value ERC-20 call (no false positives that would train the
    // user to ignore the warning).
    let mut tx = sample_tx();
    tx.value = U256::zero();
    let resolver = NameResolver::new();
    let meta = usdc_metadata();
    let call = Erc20Call::Transfer {
        to: [0; 20],
        amount: u256_from_u64(1),
    };
    let pages = render_erc20_known_pages(&tx, &call, &meta, &resolver);
    assert_ne!(row_str(&pages.buf[0][2]), "! native ETH!");
}

// --- Blind-sign page count / data-hash linkage -----------------------------

#[test]
fn negative_blind_sign_page_count_exact_invariant() {
    // Assumption: a refactor that silently drops a page (e.g. forgetting
    // the data-hash page after a selector page reshuffle) would break
    // the dapp's cross-check workflow. Pin the page counts.
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let data = [0xde, 0xad, 0xbe, 0xef];
    assert_eq!(
        render_blind_sign_pages(&tx, &data, None, &resolver).len,
        9,
        "no-selector blind sign MUST be 9 pages",
    );
    let meta = curated_selector(b"foo()", [0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(
        render_blind_sign_pages(&tx, &data, Some(&meta), &resolver).len,
        10,
        "with-selector blind sign MUST be exactly +1 page",
    );
}

#[test]
fn negative_blind_sign_data_hash_changes_when_any_byte_flips() {
    // Assumption: the calldata-hash page must reflect SHA-256 of the
    // ACTUAL calldata being signed. A single-bit flip in NS's data
    // buffer must surface as different rendered hex.
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let data1 = [0xAA; 16];
    let mut data2 = data1;
    data2[7] ^= 0x01;
    let p1 = render_blind_sign_pages(&tx, &data1, None, &resolver);
    let p2 = render_blind_sign_pages(&tx, &data2, None, &resolver);
    // Data hash is on page 4 (0-banner, 1-to, 2-value, 3-sel, 4-hash, ...).
    assert_ne!(
        p1.buf[4][1], p2.buf[4][1],
        "1-bit calldata change must change the rendered hash row 1"
    );
    assert_ne!(
        p1.buf[4][2], p2.buf[4][2],
        "1-bit calldata change must change the rendered hash row 2"
    );
}

#[test]
fn negative_blind_sign_banner_stays_on_page_zero() {
    // Assumption: "! BLIND SIGN" is the FIRST thing the user sees — a
    // refactor that pushes it deeper into the bundle would let an
    // attacker race the user past the warning.
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let data = [0xde, 0xad, 0xbe, 0xef];

    let pages_no_sel = render_blind_sign_pages(&tx, &data, None, &resolver);
    assert_eq!(row_str(&pages_no_sel.buf[0][0]), "! BLIND SIGN");

    let meta = curated_selector(b"foo()", [0xde, 0xad, 0xbe, 0xef]);
    let pages_with_sel = render_blind_sign_pages(&tx, &data, Some(&meta), &resolver);
    assert_eq!(
        row_str(&pages_with_sel.buf[0][0]),
        "! BLIND SIGN",
        "FUNCTION:/GUESS: page must NEVER displace the BLIND SIGN banner from page 0"
    );
}

#[test]
fn negative_blind_sign_self_attest_uses_guess_label() {
    // Assumption: SelfAttest provenance is visibly weaker than Curated.
    // A companion-supplied text_sig could be a crafted ~2^32 keccak
    // collision; the label MUST surface that distinction.
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let data = [0xde, 0xad, 0xbe, 0xef];
    let curated = curated_selector(b"foo()", [0xde, 0xad, 0xbe, 0xef]);
    let self_attest = self_attest_selector(b"foo()", [0xde, 0xad, 0xbe, 0xef]);

    let p_c = render_blind_sign_pages(&tx, &data, Some(&curated), &resolver);
    let p_s = render_blind_sign_pages(&tx, &data, Some(&self_attest), &resolver);
    assert_eq!(row_str(&p_c.buf[1][0]), "FUNCTION:");
    assert_eq!(row_str(&p_s.buf[1][0]), "GUESS:");
    assert_ne!(
        p_c.buf[1][0], p_s.buf[1][0],
        "Curated and SelfAttest provenance must render distinguishable labels"
    );
}

#[test]
fn negative_blind_sign_nonzero_value_uses_loud_banner() {
    // Assumption: the user must NOT miss native ETH being attached to
    // an opaque call. Loud "! VALUE:" banner instead of the quiet
    // "Value: 0 ETH" line.
    let tx = sample_tx(); // value = 1 ETH
    let resolver = NameResolver::new();
    let data = [0xde, 0xad, 0xbe, 0xef];
    let pages = render_blind_sign_pages(&tx, &data, None, &resolver);
    // Value page = page 2 (0-banner, 1-to, 2-value).
    assert_eq!(
        row_str(&pages.buf[2][0]),
        "! VALUE:",
        "non-zero value on blind-sign must show the loud '! VALUE:' banner"
    );
}

#[test]
fn negative_blind_sign_zero_value_uses_quiet_line() {
    let mut tx = sample_tx();
    tx.value = U256::zero();
    let resolver = NameResolver::new();
    let data = [0xde, 0xad, 0xbe, 0xef];
    let pages = render_blind_sign_pages(&tx, &data, None, &resolver);
    assert_eq!(row_str(&pages.buf[2][0]), "Value: 0 ETH");
}

// --- EIP-1271 sanitisation + provenance affordances ------------------------

#[test]
fn negative_eip1271_personal_sign_sanitises_non_printable() {
    // Assumption: the OLED is a trusted display; non-printable bytes
    // and high-bit / UTF-8 continuation bytes must render as '?' so a
    // dapp can't get the firmware to paint a glyph that doesn't appear
    // in a plain ASCII rendering of the same message text.
    let wallet = [0x55u8; 20];
    // Use control byte 0x1F (US, just below printable range), DEL 0x7F,
    // high-bit 0xC3 (UTF-8 lead).
    let msg = b"a\x1Fb\x7Fc\xC3d";
    let pages = render_eip1271_personal_sign_pages(1, 0, 1, &wallet, msg, 5, 4, 100, true);
    // First message page is index 4. Bytes 0..7 are the rendered text.
    let row = &pages.buf[4][0];
    assert_eq!(row[0], b'a');
    assert_eq!(row[1], b'?', "0x1F (control) must become '?'");
    assert_eq!(row[2], b'b');
    assert_eq!(row[3], b'?', "0x7F (DEL) must become '?'");
    assert_eq!(row[4], b'c');
    assert_eq!(row[5], b'?', "0xC3 (UTF-8 lead) must become '?'");
    assert_eq!(row[6], b'd');
}

#[test]
fn negative_eip1271_personal_sign_printable_edges_pass_through() {
    // Boundary: 0x20 (space) and 0x7E (~) are inclusive of the
    // printable range and must NOT be redacted.
    let wallet = [0x55u8; 20];
    let msg = b" ~";
    let pages = render_eip1271_personal_sign_pages(1, 0, 1, &wallet, msg, 5, 4, 100, true);
    let row = &pages.buf[4][0];
    assert_eq!(row[0], b' ', "0x20 (space) is printable, must render as-is");
    assert_eq!(row[1], b'~', "0x7E (~) is printable, must render as-is");
}

#[test]
fn negative_eip1271_counterfactual_shows_pre_deploy_warning() {
    // Assumption: account_deployed=false (ERC-6492 path) must show a
    // distinct banner so the user understands the sig will counter-
    // factually deploy their wallet on the dapp's first use.
    let wallet = [0x55u8; 20];

    let p_deployed = render_eip1271_personal_sign_pages(1, 0, 1, &wallet, b"hi", 5, 4, 100, true);
    let p_pre_deploy =
        render_eip1271_personal_sign_pages(1, 0, 1, &wallet, b"hi", 5, 4, 100, false);
    assert_eq!(row_str(&p_deployed.buf[0][2]), "Verify on dapp");
    // MEDIUM-1: legible, fit-to-width counterfactual warning (exactly 16
    // chars, no longer truncated). Surfaces the budget-reset risk to a
    // returning user whose wallet is actually deployed.
    assert_eq!(row_str(&p_pre_deploy.buf[0][2]), "! Undeployed sig");
    assert_ne!(p_deployed.buf[0][2], p_pre_deploy.buf[0][2]);

    // Same affordance on the raw32 path.
    let hash = [0u8; 32];
    let r_deployed = render_eip1271_raw32_pages(1, 0, 1, &hash, 5, 4, 100, true);
    let r_pre = render_eip1271_raw32_pages(1, 0, 1, &hash, 5, 4, 100, false);
    assert_eq!(row_str(&r_deployed.buf[0][2]), "Verify on dapp");
    assert_eq!(row_str(&r_pre.buf[0][2]), "! Undeployed sig");
}

#[test]
fn negative_eip1271_msg_pagination_at_chars_per_page_boundary() {
    // Assumption: a message of exactly CHARS_PER_PAGE (=48) bytes must
    // produce exactly 1 message page, not 2. The page-count math
    // (`ceil(len / CHARS_PER_PAGE)`) is load-bearing: an off-by-one
    // would either drop the last chars or add a phantom blank page
    // the user has to click through.
    let wallet = [0x55u8; 20];
    let msg = [b'A'; 48];
    let pages = render_eip1271_personal_sign_pages(1, 0, 0, &wallet, &msg, 5, 4, 100, true);
    assert_eq!(
        pages.len,
        5 + 1,
        "48-byte (= CHARS_PER_PAGE) msg fits in exactly 1 message page"
    );
}

#[test]
fn negative_eip1271_msg_pagination_one_byte_over_boundary() {
    // Just past the boundary needs a second message page.
    let wallet = [0x55u8; 20];
    let msg = [b'A'; 49];
    let pages = render_eip1271_personal_sign_pages(1, 0, 0, &wallet, &msg, 5, 4, 100, true);
    assert_eq!(
        pages.len,
        5 + 2,
        "49-byte msg crosses CHARS_PER_PAGE boundary → 2 message pages"
    );
}

#[test]
fn negative_eip1271_raw32_hash_bytes_round_trip_unchanged() {
    // Assumption: every hex digit shown is a verbatim render of the
    // input hash — flipping any byte must surface in the page output.
    let mut h1 = [0u8; 32];
    let mut h2 = [0u8; 32];
    for (i, b) in h1.iter_mut().enumerate() {
        *b = i as u8;
    }
    h2.copy_from_slice(&h1);
    h2[20] ^= 0x55;

    let p1 = render_eip1271_raw32_pages(1, 0, 0, &h1, 5, 4, 100, true);
    let p2 = render_eip1271_raw32_pages(1, 0, 0, &h2, 5, 4, 100, true);
    // Byte 20 lives on Hash 2/2 page (index 4), inside row 1 (16..24).
    assert_ne!(
        p1.buf[4][1], p2.buf[4][1],
        "byte-20 flip must surface as a different rendered hex row"
    );
}

#[test]
fn negative_eip1271_budget_row_reflects_supplied_counter() {
    // Assumption: the budget row shows the POST-increment local count
    // over the cap, not a stale value. We assert exact text so future
    // refactors can't accidentally swap "used" for "remaining".
    let wallet = [0x55u8; 20];
    let pages = render_eip1271_personal_sign_pages(1, 0, 0, &wallet, b"x", 17, 12, 100, true);
    let last = pages.len - 1;
    let row0 = row_str(&pages.buf[last][0]);
    let row1 = row_str(&pages.buf[last][1]);
    assert_eq!(row0, "17/100");
    assert_eq!(row1, "Gap: 5");
}

#[test]
fn negative_eip1271_gap_is_local_minus_last_userop_saturating() {
    // If somehow last_userop > local_after (shouldn't happen, but if
    // it did via a corrupted state), gap row must saturate to 0 — not
    // underflow / panic. Defensive surface.
    let wallet = [0x55u8; 20];
    let pages = render_eip1271_personal_sign_pages(1, 0, 0, &wallet, b"x", 1, 99, 100, true);
    let last = pages.len - 1;
    assert_eq!(
        row_str(&pages.buf[last][1]),
        "Gap: 0",
        "Gap row must saturating-sub, never underflow"
    );
}

// --- Slot-rotation affordances ---------------------------------------------

#[test]
fn negative_slot_rotation_warns_about_bootstrap_use() {
    // Assumption (slot_rotation.rs docstring): the rotation page exists
    // specifically to surface that a Type 1 sign silently consumes one
    // of the wallet's MAX_BOOTSTRAP_USES budget items. Removing the
    // "+bootstrap use" line would silently regress this UX guarantee.
    let pages = build_slot_rotation_pages(7);
    let row3 = row_str(&pages.buf[0][3]);
    assert!(
        row3.contains("+bootstrap use"),
        "rotation page MUST surface bootstrap-budget consumption, got {:?}",
        row3
    );
}

#[test]
fn negative_slot_rotation_shows_index() {
    // Different slot indices must produce visibly different pages so a
    // user can verify which slot is being rotated.
    let a = build_slot_rotation_pages(3);
    let b = build_slot_rotation_pages(8);
    assert_ne!(
        a.buf[0][2], b.buf[0][2],
        "slot_index must be visible on row 2"
    );
}

#[test]
fn negative_slot_rotation_is_injective_across_22bit_field() {
    // The `slot_index` FLAG-word field is 22 bits (0..=4_194_303); the
    // sign handlers reject only `register_slot && slot_index == 0`, so a
    // buggy or hostile companion can drive any other value into
    // build_slot_rotation_pages BEFORE the confirm dialog. The old ten-byte
    // prefix left only six digit columns, so 1_000_000 and 1_000_001 both
    // painted "New slot: 100000". Independently parse every accepted row
    // and require it to recover the original signed index exactly.
    for idx in 1u32..=4_194_303 {
        let pages = build_slot_rotation_pages(idx);
        let row = &pages.buf[0][2];
        let prefix_at = row
            .windows(b"Slot: ".len())
            .position(|window| window == b"Slot: ")
            .expect("rotation row must contain the complete slot label");
        let digits = &row[prefix_at + b"Slot: ".len()..];
        let mut parsed = 0u32;
        let mut count = 0usize;
        for &byte in digits {
            if !byte.is_ascii_digit() {
                break;
            }
            parsed = parsed
                .checked_mul(10)
                .and_then(|value| value.checked_add(u32::from(byte - b'0')))
                .expect("rendered slot decimal must fit u32");
            count += 1;
        }
        assert!(count > 0, "slot {idx} must render at least one digit");
        assert_eq!(
            parsed, idx,
            "slot {idx} must round-trip through the display"
        );
    }
}

#[test]
fn negative_slot_rotation_renders_large_indices_without_collision() {
    let pages = build_slot_rotation_pages(4_194_303);
    assert_eq!(
        pages.buf[0][2].len(),
        DISPLAY_COLS,
        "row 2 must stay exactly DISPLAY_COLS wide"
    );
    assert!(row_str(&pages.buf[0][2]).contains("Slot: 4194303"));

    let million = build_slot_rotation_pages(1_000_000);
    let million_one = build_slot_rotation_pages(1_000_001);
    assert!(row_str(&million.buf[0][2]).contains("Slot: 1000000"));
    assert!(row_str(&million_one.buf[0][2]).contains("Slot: 1000001"));
    assert_ne!(million.buf[0][2], million_one.buf[0][2]);

    // The formatter is deliberately total over u32, not just today's 22-bit
    // field, so future field widening cannot silently reintroduce truncation.
    let max = build_slot_rotation_pages(u32::MAX);
    assert_eq!(max.buf[0][2], *b"Slot: 4294967295");
}

fn composed_slot_rotation_transcript(slot_index: u32) -> Pages {
    let sender = [0x42; 20];
    let mut nonce = [0u8; 32];
    nonce[0] = 0x01;
    nonce[24..].copy_from_slice(&7u64.to_be_bytes());
    let gas = |value: u64| {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&value.to_be_bytes());
        out
    };

    let mut pages = build_slot_rotation_pages(slot_index);

    let signer_prior = pages.len;
    let mut signer_cfi = crate::fi::CfiCounter::new();
    super::value_page::enforce_from_page(&mut pages, 3, &sender, &mut signer_cfi).unwrap();
    assert_eq!(
        signer_cfi.check_into_sentinel(super::value_page::SIGNER_PAGE_CFI_EXPECTED),
        crate::fi::OK_SENTINEL
    );
    assert_eq!(
        super::value_page::from_page_proof(&pages, signer_prior, 3, &sender),
        crate::fi::OK_SENTINEL
    );

    let nonce_prior = pages.len;
    let mut nonce_cfi = crate::fi::CfiCounter::new();
    super::nonce_lane::enforce_nonce_lane_page(&mut pages, &nonce, &mut nonce_cfi).unwrap();
    assert_eq!(
        nonce_cfi.check_into_sentinel(super::nonce_lane::NONCE_LANE_CFI_EXPECTED),
        crate::fi::OK_SENTINEL
    );
    assert_eq!(
        super::nonce_lane::nonce_lane_page_proof(&pages, nonce_prior, &nonce),
        crate::fi::OK_SENTINEL
    );

    let call = gas(100_000);
    let verify = gas(200_000);
    let prever = gas(21_000);
    let gas_prior = pages.len;
    let mut gas_cfi = crate::fi::CfiCounter::new();
    super::userop_gas_lane::enforce_userop_gas_page(
        &mut pages,
        &call,
        &verify,
        &prever,
        &mut gas_cfi,
    )
    .unwrap();
    assert_eq!(
        gas_cfi.check_into_sentinel(super::userop_gas_lane::USEROP_GAS_CFI_EXPECTED),
        crate::fi::OK_SENTINEL
    );
    assert_eq!(
        super::userop_gas_lane::userop_gas_page_proof(&pages, gas_prior, &call, &verify, &prever,),
        crate::fi::OK_SENTINEL
    );
    pages
}

#[test]
fn slot_rotation_full_single_and_batch_transcripts_preserve_injective_page() {
    // Both handlers construct the same rotation → signer → nonce → gas page
    // set. Hold every non-slot input constant and prove the old collision pair
    // differs only in the complete, still-leading rotation page.
    let million = composed_slot_rotation_transcript(1_000_000);
    let million_one = composed_slot_rotation_transcript(1_000_001);
    assert_eq!(million.len, 4);
    assert_eq!(million.len, million_one.len);
    assert_ne!(million.buf[0], million_one.buf[0]);
    assert_eq!(
        &million.buf[1..million.len],
        &million_one.buf[1..million_one.len]
    );
    assert!(row_str(&million.buf[0][2]).contains("Slot: 1000000"));
    assert!(row_str(&million_one.buf[0][2]).contains("Slot: 1000001"));

    let maximum = composed_slot_rotation_transcript(4_194_303);
    assert!(row_str(&maximum.buf[0][2]).contains("Slot: 4194303"));
    assert_eq!(&maximum.buf[1..maximum.len], &million.buf[1..million.len]);
}

// --- Batch banner: 1-based UI, refuse to overflow MAX_PAGES ---------------

#[test]
fn negative_batch_banner_renders_one_based_index() {
    // 0-based at the call boundary, 1-based on screen. Off-by-one is
    // historically the most common batch-banner bug.
    let resolver = NameResolver::new();
    let tx = sample_tx();
    for idx in 0..4 {
        let inner = render_pages(&tx, &resolver);
        let wrapped = wrap_batch_for_test(&inner, idx, 4).expect("banner fits");
        let row2 = row_str(&wrapped.buf[0][2]);
        let expected_one_based = format!("Tx {} of 4", idx + 1);
        assert!(
            row2.contains(&expected_one_based),
            "batch index {} (0-based) must render as 'Tx {} of 4', got {:?}",
            idx,
            idx + 1,
            row2
        );
    }
}

#[test]
fn negative_batch_banner_refuses_to_overflow_max_pages() {
    // Fail-closed contract (batch.rs, finding F5): if inner.len + 1 > MAX_PAGES
    // the wrapper must return Err so the caller refuses to sign, rather than
    // dropping the "BATCH SIGN | Tx i of N" banner and signing the bare inner
    // pages. Previously this returned the inner pages unchanged (banner
    // silently dropped) and the batch handler signed anyway.
    let mut huge = Pages::empty_with_len(MAX_PAGES);
    // Tag the inner so we can recognise it.
    huge.buf[0][0][0] = b'I';
    let mut wrapped = Pages::empty_with_len(3);
    wrapped.buf[0][0][0] = b'S';
    let mut cfi = crate::fi::CfiCounter::new();
    let result = wrap_pages_with_batch_banner(&huge, 0, 2, &mut wrapped, &mut cfi);
    assert!(
        result.is_err(),
        "wrap must refuse (Err) rather than drop the banner past MAX_PAGES"
    );
    assert_eq!(
        wrapped.len, 0,
        "an overflow refusal must leave the caller-owned output invisibly fail-initialized"
    );
    assert_ne!(
        cfi.check_into_sentinel(super::batch::BATCH_BANNER_CFI_EXPECTED),
        crate::fi::OK_SENTINEL,
        "an overflow refusal must not mint the copy-completion receipt"
    );
}

#[test]
fn batch_banner_copy_has_caller_cfi_and_exact_transcript_proof() {
    let mut inner = Pages::empty_with_len(6);
    for (index, page) in inner.buf[..inner.len].iter_mut().enumerate() {
        *page = [[b'A' + index as u8; DISPLAY_COLS]; DISPLAY_ROWS];
    }
    let mut wrapped = Pages::empty_with_len(0);
    let mut cfi = crate::fi::CfiCounter::new();
    wrap_pages_with_batch_banner(&inner, 2, 4, &mut wrapped, &mut cfi).unwrap();
    assert_eq!(
        cfi.check_into_sentinel(super::batch::BATCH_BANNER_CFI_EXPECTED),
        crate::fi::OK_SENTINEL
    );
    assert_eq!(
        super::batch::batch_banner_copy_proof(&inner, &wrapped, 2, 4),
        crate::fi::OK_SENTINEL
    );
    assert_eq!(&wrapped.buf[1..7], &inner.buf[..6]);

    let skipped = crate::fi::CfiCounter::new();
    assert_ne!(
        skipped.check_into_sentinel(super::batch::BATCH_BANNER_CFI_EXPECTED),
        crate::fi::OK_SENTINEL
    );

    assert_ne!(
        super::batch::batch_banner_copy_proof(&inner, &wrapped, 1, 4),
        crate::fi::OK_SENTINEL,
        "the exact banner must bind the member index"
    );
    assert_ne!(
        super::batch::batch_banner_copy_proof(&inner, &wrapped, 2, 3),
        crate::fi::OK_SENTINEL,
        "the exact banner must bind the verified batch total"
    );

    wrapped.buf[0][1][3] ^= 1;
    assert_ne!(
        super::batch::batch_banner_copy_proof(&inner, &wrapped, 2, 4),
        crate::fi::OK_SENTINEL,
        "one corrupted banner byte must fail the exact transcript proof"
    );
    wrapped.buf[0][1][3] ^= 1;

    wrapped.len -= 1;
    assert_ne!(
        super::batch::batch_banner_copy_proof(&inner, &wrapped, 2, 4),
        crate::fi::OK_SENTINEL,
        "a stale visible length must fail the exact transcript proof"
    );
    wrapped.len += 1;

    wrapped.buf[4][2][9] ^= 1;
    assert_ne!(
        super::batch::batch_banner_copy_proof(&inner, &wrapped, 2, 4),
        crate::fi::OK_SENTINEL,
        "one corrupted copied byte must fail the exact transcript proof"
    );
    wrapped.buf[4][2][9] ^= 1;

    wrapped.buf[1][0][0] ^= 1;
    assert_ne!(
        super::batch::batch_banner_copy_proof(&inner, &wrapped, 2, 4),
        crate::fi::OK_SENTINEL,
        "the first copied byte must be covered"
    );
    wrapped.buf[1][0][0] ^= 1;
    wrapped.buf[inner.len][DISPLAY_ROWS - 1][DISPLAY_COLS - 1] ^= 1;
    assert_ne!(
        super::batch::batch_banner_copy_proof(&inner, &wrapped, 2, 4),
        crate::fi::OK_SENTINEL,
        "the last copied byte must be covered"
    );

    let mut exact_fit = Pages::empty_with_len(MAX_PAGES - 1);
    exact_fit.buf[0][0][0] = b'F';
    exact_fit.buf[MAX_PAGES - 2][DISPLAY_ROWS - 1][DISPLAY_COLS - 1] = b'L';
    let exact_wrapped = wrap_batch_for_test(&exact_fit, 0, 4).expect("banner exactly fits");
    assert_eq!(exact_wrapped.len, MAX_PAGES);
    assert_eq!(exact_wrapped.buf[1], exact_fit.buf[0]);
    assert_eq!(
        exact_wrapped.buf[MAX_PAGES - 1],
        exact_fit.buf[MAX_PAGES - 2]
    );
}

#[test]
fn batch_member_confirm_receipt_rejects_early_exit_and_wrong_sequence() {
    for expected_count in 1..=4 {
        for confirmed_prefix in 0..=expected_count {
            let mut receipt = super::batch::BatchMemberConfirmReceipt::new();
            receipt.fail_initialize();
            for index in 0..confirmed_prefix {
                receipt.record_confirmed(index).unwrap();
            }
            let completed = receipt.completion_proof(expected_count) == crate::fi::OK_SENTINEL;
            assert_eq!(
                completed,
                confirmed_prefix == expected_count,
                "only the complete ordered prefix may satisfy N={expected_count}; prefix={confirmed_prefix}"
            );
        }
    }

    let mut out_of_order = super::batch::BatchMemberConfirmReceipt::new();
    out_of_order.fail_initialize();
    assert!(out_of_order.record_confirmed(1).is_err());
    assert_ne!(out_of_order.completion_proof(2), crate::fi::OK_SENTINEL);

    let mut duplicate = super::batch::BatchMemberConfirmReceipt::new();
    duplicate.fail_initialize();
    duplicate.record_confirmed(0).unwrap();
    assert!(duplicate.record_confirmed(0).is_err());
    assert_ne!(duplicate.completion_proof(2), crate::fi::OK_SENTINEL);

    let mut omitted_middle = super::batch::BatchMemberConfirmReceipt::new();
    omitted_middle.fail_initialize();
    omitted_middle.record_confirmed(0).unwrap();
    assert!(omitted_middle.record_confirmed(2).is_err());
    assert_ne!(omitted_middle.completion_proof(3), crate::fi::OK_SENTINEL);

    let mut reset = super::batch::BatchMemberConfirmReceipt::new();
    for index in 0..4 {
        reset.record_confirmed(index).unwrap();
    }
    reset.fail_initialize();
    assert_ne!(reset.completion_proof(4), crate::fi::OK_SENTINEL);
}

#[test]
fn batch_member_digest_oracle_detects_prefix_omission_and_mutation() {
    use sha3::Digest;

    fn digest_calls(calls: &[Vec<u8>], omitted: Option<usize>) -> [u8; 32] {
        let mut running = sha3::Keccak256::new();
        for (index, call) in calls.iter().enumerate() {
            if omitted == Some(index) {
                continue;
            }
            running.update(pqsigner_tx_core::erc8213::calldata_digest(call));
        }
        running.finalize().into()
    }

    let calls = vec![
        vec![0x11, 0x22, 0x33],
        vec![0x44; 32],
        vec![0x55, 0x66],
        vec![0x77; 127],
    ];
    let full = digest_calls(&calls, None);
    for omitted in 0..calls.len() {
        assert_ne!(
            digest_calls(&calls, Some(omitted)),
            full,
            "omitting confirmed-member digest {omitted} must disagree with the full oracle"
        );
    }
    for prefix in 0..calls.len() {
        assert_ne!(digest_calls(&calls[..prefix], None), full);
    }

    let mut first_changed = calls.clone();
    first_changed[0][0] ^= 1;
    assert_ne!(digest_calls(&first_changed, None), full);
    let mut last_changed = calls.clone();
    let last_call = last_changed.last_mut().unwrap();
    let last_byte = last_call.last_mut().unwrap();
    *last_byte ^= 1;
    assert_ne!(digest_calls(&last_changed, None), full);

    let identical = vec![vec![0xAA; 68]; 4];
    let identical_full = digest_calls(&identical, None);
    for prefix in 0..identical.len() {
        assert_ne!(digest_calls(&identical[..prefix], None), identical_full);
    }
}

// --- Pages container bounds --------------------------------------------------

#[test]
#[should_panic(expected = "Pages::empty_with_len: len > MAX_PAGES")]
fn negative_pages_with_len_panics_above_max() {
    // The buffer is fixed-size MAX_PAGES — an over-cap request would be
    // a firmware bug that we want to surface loudly during dev, not
    // silently truncate.
    let _ = Pages::empty_with_len(MAX_PAGES + 1);
}

#[test]
#[should_panic]
fn negative_pages_row_mut_panics_on_page_out_of_range() {
    let mut pages = Pages::empty_with_len(2);
    let _ = pages.row_mut(2, 0); // 2 is out of range (len = 2)
}

#[test]
#[should_panic]
fn negative_pages_row_mut_panics_on_row_out_of_range() {
    let mut pages = Pages::empty_with_len(1);
    let _ = pages.row_mut(0, DISPLAY_ROWS);
}

// --- MAX_PAGES sized to the worst-case renderer ---------------------------

#[test]
fn negative_max_pages_covers_personal_sign_worst_case() {
    // EIP-1271 PersonalSign render = 5 fixed + ceil(MAX/48) message
    // pages. CLAUDE.md fixes the message cap so the worst case fits in
    // MAX_PAGES (currently 31). This test asserts the budget envelope —
    // if anyone bumps MAX_OFFCHAIN_PERSONAL_SIGN_LEN past what the
    // page bucket can accommodate, MAX_PAGES must grow to match.
    let max_message_pages = MAX_PAGES - 5;
    let max_message_chars = max_message_pages * 48;
    assert!(
        max_message_chars >= 700,
        "MAX_PAGES = {} only buys {} message-page chars = {} bytes; \
         CLAUDE.md documents MAX_OFFCHAIN_PERSONAL_SIGN_LEN ≤ 700",
        MAX_PAGES,
        max_message_pages,
        max_message_chars
    );
}

#[test]
fn negative_max_pages_matches_production_constant() {
    // Pin the literal so a silent reduction would fail loudly. `Pages`/
    // `MAX_PAGES` moved to the host crate (`pqsigner_erc7730::display`) so the
    // ERC-7730 render dispatch can be host-linked; this scaffold's copy and
    // that source must stay in lockstep. Searches the production source text.
    let src = include_str!("../../../pqsigner-erc7730/src/display/mod.rs");
    let needle = "pub const MAX_PAGES: usize = 31;";
    assert!(
        src.contains(needle),
        "production tx/display/mod.rs no longer defines `{}` — either \
         bump MAX_PAGES here and update this test, OR fix the source.",
        needle
    );
}

// --- Source-text invariant: enforce frozen page-renderer surface ----------

#[test]
fn negative_blind_sign_banner_text_pinned() {
    // The "! BLIND SIGN" string is what the user is trained to look
    // for. A copy-edit (e.g. "BLIND SIGNATURE", "Unknown signature")
    // would silently disrupt that training — the source text is pinned
    // here so a tweak fails CI loudly.
    let src = include_str!("../tx/display/blind_sign.rs");
    assert!(
        src.contains("\"! BLIND SIGN\""),
        "blind_sign.rs must keep the exact '! BLIND SIGN' banner literal"
    );
    assert!(
        src.contains("\"Verify on dapp\""),
        "blind_sign.rs must keep the 'Verify on dapp' guidance literal"
    );
}

#[test]
fn negative_personal_sign_sanitiser_range_pinned() {
    // The printable range (0x20..=0x7E) is load-bearing for the
    // glyph-spoofing guarantee. A future refactor to e.g. allow
    // 0x80-0xFF for "UTF-8 passthrough" would break the trusted
    // display contract. Pin the literal.
    let src = include_str!("../tx/display/eip1271.rs");
    assert!(
        src.contains("(0x20..=0x7E)"),
        "eip1271.rs sanitise_byte must keep the (0x20..=0x7E) printable range"
    );
}

#[test]
fn negative_chain_name_list_pinned() {
    // The full curated chain list — bound here so an addition or
    // removal of an entry forces the test to be re-acked. Mirrors the
    // KDF-tag-stability discipline from CLAUDE.md "no casual KDF tag
    // changes".
    // `primitives.rs` was extracted to the host crate (host-fuzzable byte
    // writers); pin against its new canonical location.
    let src = include_str!("../../../pqsigner-erc7730/src/display/primitives.rs");
    for needle in [
        "1 => \"(Mainnet)\"",
        "10 => \"(Optimism)\"",
        "14 => \"(Flare)\"",
        "30 => \"(Rootstock)\"",
        "56 => \"(BSC)\"",
        "100 => \"(Gnosis)\"",
        "137 => \"(Polygon)\"",
        "146 => \"(Sonic)\"",
        "250 => \"(Fantom)\"",
        "324 => \"(zkSync Era)\"",
        "999 => \"(HyperEVM)\"",
        "1329 => \"(Sei)\"",
        "8217 => \"(Kaia)\"",
        "8453 => \"(Base)\"",
        "42161 => \"(Arbitrum)\"",
        "42220 => \"(Celo)\"",
        "43114 => \"(Avalanche)\"",
        "59144 => \"(Linea)\"",
        "534352 => \"(Scroll)\"",
        "11155111 => \"(Sepolia)\"",
        "84532 => \"(BaseSepolia)\"",
        "_ => \"(unknown chain)\"",
    ] {
        assert!(
            src.contains(needle),
            "primitives.rs chain_name must keep `{}`",
            needle
        );
    }
}

// --- Trusted display: no non-ASCII in any rendered output -----------------

#[test]
fn negative_no_non_ascii_anywhere_in_renderer_outputs() {
    // Assumption: every renderer's output is ASCII-by-construction.
    // No path can paint a high-bit byte that the OLED font wouldn't
    // render correctly. We hit each renderer with adversarial inputs
    // and assert printable-ASCII over every cell.
    let resolver = NameResolver::new();
    let tx = sample_tx();

    assert_all_pages_printable(&render_pages(&tx, &resolver));

    let nasty_data: Vec<u8> = (0..=255u16).map(|x| x as u8).collect();
    assert_all_pages_printable(&render_blind_sign_pages(&tx, &nasty_data, None, &resolver));

    let meta_curated = curated_selector(b"foo(bytes,uint256)", [0u8; 4]);
    assert_all_pages_printable(&render_blind_sign_pages(
        &tx,
        &nasty_data,
        Some(&meta_curated),
        &resolver,
    ));

    let meta = usdc_metadata();
    let call = Erc20Call::Transfer {
        to: [0x33; 20],
        amount: u256_from_u64(7),
    };
    assert_all_pages_printable(&render_erc20_known_pages(&tx, &call, &meta, &resolver));
    assert_all_pages_printable(&render_erc20_unknown_pages(&tx, &call, &resolver));

    let wallet = [0x55u8; 20];
    // Mixed control + high-bit message to force the sanitiser.
    let nasty_msg: Vec<u8> = (0u8..=255).collect();
    let nasty_msg = &nasty_msg[..min(nasty_msg.len(), 200)];
    assert_all_pages_printable(&render_eip1271_personal_sign_pages(
        1, 0, 1, &wallet, nasty_msg, 5, 4, 100, true,
    ));
}

// --- Tip / fee budget surface ---------------------------------------------

#[test]
fn positive_write_tip_and_fee_budget_render() {
    let mut tip_row = [b' '; DISPLAY_COLS];
    let tip = u256_from_u64(1_500_000_000); // 1.5 gwei
    assert!(write_tip_row(&mut tip_row, &tip));
    let s = row_str(&tip_row);
    assert_eq!(s, "1.5 gwei");
    assert!(s.contains("gwei"), "expected 'gwei' unit, got {:?}", s);

    let mut fee_row = [b' '; DISPLAY_COLS];
    assert!(write_fee_budget_row(
        &mut fee_row,
        &u256_from_u64(30_000_000_000),
        21_000
    ));
    let s = row_str(&fee_row);
    assert_eq!(s, "0.00063 ETH");
    assert!(s.contains("ETH"), "expected ETH unit, got {:?}", s);

    assert!(write_native_fee_budget_row(
        &mut fee_row,
        &u256_from_u64(30_000_000_000),
        21_000,
        56
    ));
    let s = row_str(&fee_row);
    assert_eq!(s, "0.00063 BNB");
    assert!(s.contains("BNB"), "expected BNB unit, got {s:?}");
    assert!(
        !s.contains("ETH"),
        "BSC fee must not be labelled ETH: {s:?}"
    );
}

#[test]
fn legacy_tip_uses_full_row_for_common_exact_values() {
    for (raw, expected) in [
        (123_456_000_000, "123.456 gwei"),
        (12_345_678, "0.012345678 gwei"),
    ] {
        let mut row = [b' '; DISPLAY_COLS];
        assert!(write_tip_row(&mut row, &u256_from_u64(raw)));
        assert_eq!(row_str(&row), expected);
    }
}

#[test]
fn legacy_fee_budget_exact_fit_boundary_refuses_rounding() {
    let one_wei = u256_from_u64(1);
    let exact_fee = u256_from_u64(1_000);
    let too_wide_fee = u256_from_u64(1_001);
    let exact_gas = 999_999_999;
    let mut row = [b' '; DISPLAY_COLS];

    assert!(write_fee_budget_row(&mut row, &exact_fee, exact_gas));
    assert_eq!(row_str(&row), "999999999000 wei");
    assert!(legacy_fee_rows_are_exactly_renderable(
        &exact_fee,
        &one_wei,
        exact_gas,
        1,
    ));

    assert!(!write_fee_budget_row(
        &mut row,
        &too_wide_fee,
        exact_gas
    ));
    assert_eq!(row_str(&row), "!OVF");
    assert!(!legacy_fee_rows_are_exactly_renderable(
        &too_wide_fee,
        &one_wei,
        exact_gas,
        1,
    ));
}

#[test]
fn legacy_fee_budget_common_low_fee_values_remain_available() {
    let one_gwei = u256_from_u64(1_000_000_000);
    let mut row = [b' '; DISPLAY_COLS];

    assert!(write_fee_budget_row(&mut row, &one_gwei, 21_000));
    assert_eq!(row_str(&row), "0.000021 ETH");
    assert!(legacy_fee_rows_are_exactly_renderable(
        &one_gwei,
        &u256_from_u64(0),
        21_000,
        1,
    ));

    assert!(write_native_fee_budget_row(&mut row, &one_gwei, 21_000, 56,));
    assert_eq!(row_str(&row), "0.000021 BNB");
}

#[test]
fn legacy_fee_budget_unknown_chain_refuses_scale_but_accepts_raw_envelope() {
    let one_gwei = u256_from_u64(1_000_000_000);
    let mut row = [b' '; DISPLAY_COLS];

    assert!(!write_native_fee_budget_row(
        &mut row, &one_gwei, 21_000, 4_242_424,
    ));
    assert_eq!(row_str(&row), "!NO SCALE");
    assert!(legacy_fee_rows_are_exactly_renderable(
        &one_gwei,
        &u256_from_u64(0),
        21_000,
        4_242_424,
    ));
    let rendered = build_legacy_fee_pages(&one_gwei, &u256_from_u64(0), 21_000, 4_242_424);
    assert!(rendered.exact);
    assert_eq!(row_str(&rendered.pages[0][0]), "Base: max / tip");
    assert_eq!(row_str(&rendered.pages[0][1]), "1000000000");
    assert_eq!(row_str(&rendered.pages[1][0]), "Worst-case/base:");
    assert_eq!(row_str(&rendered.pages[1][1]), "21000000000000");
}

#[test]
fn negative_write_fee_budget_refuses_on_multiplication_overflow() {
    // saturating_mul_u64 reports overflow rather than wrapping. The render
    // must refuse and paint an exact marker — a wrong-by-modulus value would
    // mislead the user about fee exposure.
    let mut row = [b' '; DISPLAY_COLS];
    let pathological = U256([0xFFu8; 32]);
    assert!(!write_fee_budget_row(&mut row, &pathological, u64::MAX));
    assert_eq!(row_str(&row), "!OVF");
}

#[test]
fn positive_assert_total_test_breadth() {
    // Sanity: this file must keep producing both halves of the pass.
    // (Compile-time presence check via path-locality.)
    let positives = include_str!("pure_tests.rs")
        .matches("fn positive_")
        .count();
    let negatives = include_str!("pure_tests.rs")
        .matches("fn negative_")
        .count();
    assert!(positives >= 30, "positive coverage shrank to {}", positives);
    assert!(negatives >= 30, "negative coverage shrank to {}", negatives);
}

// Reusable name-resolver hit helper to ensure address+name path -------------

#[test]
fn negative_addr_full_or_name_hit_renders_name_sentinel() {
    // Assumption: a Merkle-verified name match renders with a leading
    // "+ " sentinel that bare hex never carries — the user's proof
    // that the substitution came from a signed DB entry.
    let mut resolver = NameResolver::new();
    let addr = [0xCC; 20];
    resolver.push(crate::names::NameMeta {
        chain_id: 1,
        address: addr,
        name: b"Coinbase",
    });
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    let mut r3 = [b' '; DISPLAY_COLS];
    write_addr_full_or_name(&mut r1, &mut r2, &mut r3, &addr, 1, &resolver);
    assert_eq!(
        r1[0], b'+',
        "name hit must paint the '+' sentinel in row 1 col 0"
    );
    assert_eq!(r1[1], b' ');
    // Hex fallback uses '0' as the first byte of row 1; name hit uses
    // '+' — they must be visually distinguishable.
    let mut bare_r1 = [b' '; DISPLAY_COLS];
    let mut bare_r2 = [b' '; DISPLAY_COLS];
    let mut bare_r3 = [b' '; DISPLAY_COLS];
    write_addr_full(&mut bare_r1, &mut bare_r2, &mut bare_r3, &addr);
    assert_ne!(
        r1[..2],
        bare_r1[..2],
        "name-hit and hex-fallback first-two bytes must differ"
    );
}

// --- typed_call (Phase 2 decoder) renderer --------------------------------

fn ascii_u256(low: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&low.to_be_bytes());
    w
}

#[test]
fn positive_typed_call_renders_uint256_arg() {
    // Valid path: text_sig parses, selector matches, body decodes.
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let sel = [0xab, 0xcd, 0x12, 0x34];
    let meta = curated_selector(b"foo(uint256)", sel);
    let mut inner = Vec::new();
    inner.extend_from_slice(&sel);
    inner.extend_from_slice(&ascii_u256(42));
    let pages = try_render_typed_call(&tx, &inner, &meta, &resolver)
        .expect("typed_call should succeed for valid input");
    // Page 0 = banner; page 1 = first arg.
    let arg_label = row_str(&pages.buf[1][0]);
    assert!(
        arg_label.starts_with("arg 0"),
        "arg 0 label expected, got {:?}",
        arg_label
    );
    let arg_value = row_str(&pages.buf[1][1]);
    assert_eq!(arg_value, "42", "uint256 arg value");
}

#[test]
fn positive_typed_call_renders_address_arg_with_name() {
    let tx = sample_tx();
    let mut resolver = NameResolver::new();
    let addr = [0xCD; 20];
    resolver.push(crate::names::NameMeta {
        chain_id: 1,
        address: addr,
        name: b"Coinbase",
    });
    let sel = [0x11, 0x22, 0x33, 0x44];
    let meta = curated_selector(b"transfer(address)", sel);
    let mut inner = Vec::new();
    inner.extend_from_slice(&sel);
    let mut word = [0u8; 32];
    word[12..32].copy_from_slice(&addr);
    inner.extend_from_slice(&word);
    let pages =
        try_render_typed_call(&tx, &inner, &meta, &resolver).expect("address arg should render");
    // The address arg should produce the "+ Coinbase" name sentinel
    // on row 1 of page 1.
    assert_eq!(
        pages.buf[1][1][0], b'+',
        "name resolver hit on address arg must paint sentinel"
    );
}

#[test]
fn positive_typed_call_renders_bool_arg() {
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let sel = [0xaa, 0xbb, 0xcc, 0xdd];
    let meta = curated_selector(b"flip(bool)", sel);
    let mut inner = Vec::new();
    inner.extend_from_slice(&sel);
    let mut word = [0u8; 32];
    word[31] = 1;
    inner.extend_from_slice(&word);
    let pages =
        try_render_typed_call(&tx, &inner, &meta, &resolver).expect("bool true should render");
    assert_eq!(row_str(&pages.buf[1][1]), "true");
}

#[test]
fn negative_typed_call_declines_non_empty_dynamic_string_arg() {
    // Audit 2026-06-25 LOW-1: a non-empty dynamic `bytes`/`string` arg
    // must DECLINE the typed-call decode (parity with the `bytesN>15`
    // sibling) rather than render a 40-bit head/tail SHA-256 fingerprint
    // of attacker-chosen, signed payload bytes. Declining bails the whole
    // render to `None` → the loud Phase-1 BLIND SIGN flow (which still
    // anchors the full payload via the handler's ERC-8213 256-bit
    // fingerprint).
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let sel = [0x55, 0x66, 0x77, 0x88];
    let meta = curated_selector(b"say(string)", sel);
    let mut inner = Vec::new();
    inner.extend_from_slice(&sel);
    // ABI head: offset = 0x20 (one word).
    let mut head_off = [0u8; 32];
    head_off[31] = 0x20;
    inner.extend_from_slice(&head_off);
    // Payload: length=5 word, then "hello" padded to 32 bytes.
    let mut len_word = [0u8; 32];
    len_word[31] = 5;
    inner.extend_from_slice(&len_word);
    let mut payload = [0u8; 32];
    payload[..5].copy_from_slice(b"hello");
    inner.extend_from_slice(&payload);
    assert!(
        try_render_typed_call(&tx, &inner, &meta, &resolver).is_none(),
        "non-empty dynamic string arg must decline to blind-sign"
    );
}

#[test]
fn positive_typed_call_renders_empty_dynamic_string_arg() {
    // An empty dynamic `string` (`len == 0`) carries no hidden bytes, so
    // the "len: 0" row is a faithful, complete rendering — it still
    // renders rather than declining.
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let sel = [0x55, 0x66, 0x77, 0x88];
    let meta = curated_selector(b"say(string)", sel);
    let mut inner = Vec::new();
    inner.extend_from_slice(&sel);
    // ABI head: offset = 0x20 (one word).
    let mut head_off = [0u8; 32];
    head_off[31] = 0x20;
    inner.extend_from_slice(&head_off);
    // Payload: length=0 word, no data.
    inner.extend_from_slice(&[0u8; 32]);
    let pages = try_render_typed_call(&tx, &inner, &meta, &resolver)
        .expect("empty string arg should render");
    assert_eq!(row_str(&pages.buf[1][1]), "len: 0");
}

#[test]
fn negative_typed_call_declines_on_short_inner_data() {
    // Assumption: an inner_data < 4 bytes cannot carry a selector, so
    // we MUST refuse rather than read OOB.
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let meta = curated_selector(b"foo(uint256)", [0u8; 4]);
    let short = [0u8; 3];
    assert!(try_render_typed_call(&tx, &short, &meta, &resolver).is_none());
}

#[test]
fn negative_typed_call_declines_on_selector_mismatch() {
    // Assumption (typed_call/mod.rs:58): the renderer re-checks
    // inner_data[..4] == meta.selector even though the gateway already
    // did. That defence-in-depth must actually trigger on mismatch.
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let meta = curated_selector(b"foo(uint256)", [0xaa, 0xaa, 0xaa, 0xaa]);
    let mut inner = vec![0xff, 0xff, 0xff, 0xff];
    inner.extend_from_slice(&ascii_u256(1));
    assert!(
        try_render_typed_call(&tx, &inner, &meta, &resolver).is_none(),
        "selector mismatch must force the typed-call renderer to decline"
    );
}

#[test]
fn negative_typed_call_declines_on_unparseable_text_sig() {
    let tx = sample_tx();
    let resolver = NameResolver::new();
    // Missing closing paren — parse_text_sig rejects.
    let meta = curated_selector(b"broken(uint256", [0x12, 0x34, 0x56, 0x78]);
    let mut inner = vec![0x12, 0x34, 0x56, 0x78];
    inner.extend_from_slice(&ascii_u256(1));
    assert!(try_render_typed_call(&tx, &inner, &meta, &resolver).is_none());
}

#[test]
fn negative_typed_call_declines_on_short_body() {
    // Selector matches, parser succeeds, but body is too short for the
    // declared types.
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let sel = [1, 2, 3, 4];
    let meta = curated_selector(b"foo(uint256,uint256)", sel);
    let mut inner = Vec::new();
    inner.extend_from_slice(&sel);
    // Only ONE 32-byte word — the second arg won't decode.
    inner.extend_from_slice(&ascii_u256(7));
    assert!(try_render_typed_call(&tx, &inner, &meta, &resolver).is_none());
}

#[test]
fn negative_typed_call_declines_when_too_many_args() {
    // MAX_TYPED_ARGS_RENDERED = 6; 7 args must force fallback.
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let sel = [9, 8, 7, 6];
    let meta = curated_selector(
        b"f(uint256,uint256,uint256,uint256,uint256,uint256,uint256)",
        sel,
    );
    let mut inner = Vec::new();
    inner.extend_from_slice(&sel);
    for i in 0..7 {
        inner.extend_from_slice(&ascii_u256(i as u64));
    }
    assert!(
        try_render_typed_call(&tx, &inner, &meta, &resolver).is_none(),
        "argument count > MAX_TYPED_ARGS_RENDERED must force the renderer \
         to decline so the caller falls back to BLIND SIGN"
    );
}

#[test]
fn negative_typed_call_self_attest_uses_unverified_banner() {
    // Assumption: provenance affects the banner string. SelfAttest
    // means the user must verify the function name against the dapp.
    let tx = sample_tx();
    let resolver = NameResolver::new();
    let sel = [0xfa, 0xce, 0xbe, 0xef];
    let curated = curated_selector(b"foo(uint256)", sel);
    let attest = self_attest_selector(b"foo(uint256)", sel);
    let mut inner = Vec::new();
    inner.extend_from_slice(&sel);
    inner.extend_from_slice(&ascii_u256(1));

    let p_c = try_render_typed_call(&tx, &inner, &curated, &resolver).unwrap();
    let p_s = try_render_typed_call(&tx, &inner, &attest, &resolver).unwrap();
    assert_eq!(row_str(&p_c.buf[0][0]), "! BLIND SIGN");
    assert_eq!(row_str(&p_s.buf[0][0]), "! UNVERIFIED");
    assert_ne!(
        p_c.buf[0][0], p_s.buf[0][0],
        "Curated vs SelfAttest banner must visibly differ"
    );
}

// Confirms write_selector_row hex bytes match the input ---------------------

#[test]
fn negative_write_selector_row_bytes_match_input_exactly() {
    // Assumption: the displayed selector is the actual selector being
    // signed (after the gateway already cross-checked it against the
    // selector bundle). Bit-flipping any of the 4 bytes must change
    // the row.
    let mut r_a = [b' '; DISPLAY_COLS];
    let mut r_b = [b' '; DISPLAY_COLS];
    let a = [0xa0, 0x71, 0x2d, 0x68];
    let mut b = a;
    b[2] ^= 0x01;
    write_selector_row(&mut r_a, &a);
    write_selector_row(&mut r_b, &b);
    assert_ne!(
        r_a, r_b,
        "1-bit selector change must change the rendered Sel: row"
    );
}
