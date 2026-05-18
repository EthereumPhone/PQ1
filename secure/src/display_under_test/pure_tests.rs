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

use super::{Pages, MAX_PAGES};
use super::primitives::{
    chain_name, format_u64, hex_nibble, write_addr_full, write_addr_full_or_name,
    write_calldata_hash_rows, write_chain, write_data_len_row, write_eth_two_rows,
    write_fee_budget_row, write_gas, write_gwei, write_line, write_nonce_row,
    write_selector_row, write_tip_row, write_token_amount_two_rows,
    write_erc20_header, write_token_name, try_write_amount_single_row,
    write_amount_two_rows, AmountFit,
};

use super::blind_sign::render_blind_sign_pages;
use super::eip1271::{render_eip1271_personal_sign_pages, render_eip1271_raw32_pages};
use super::erc20_known::render_erc20_known_pages;
use super::erc20_unknown::render_erc20_unknown_pages;
use super::slot_rotation::build_slot_rotation_pages;
use super::value_transfer::render_pages;
use super::batch::{build_final_summary_pages, wrap_pages_with_batch_banner};
use super::typed_call::try_render_typed_call;

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

    pub fn self_attest_selector(text_sig: &'static [u8], selector: [u8; 4]) -> SelectorMeta<'static> {
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
                        p, r, c, b
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
    assert!(row[2..].iter().all(|&b| b == b' '),
        "tail must be space-padded");
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
    assert!(row.iter().all(|&b| b == b' '), "empty text must blank the row");
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
fn positive_write_chain_renders_decimal_and_label() {
    let mut row = [b' '; DISPLAY_COLS];
    write_chain(&mut row, 137);
    let s = row_str(&row);
    assert_eq!(s, "Chain: 137");
}

#[test]
fn positive_write_gas_renders_parens() {
    let mut row = [b' '; DISPLAY_COLS];
    write_gas(&mut row, 21_000);
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
    let s = row_str(&r1);
    assert!(s.starts_with("1 ETH") || s == "1 ETH",
        "expected row 1 to start with '1 ETH', got {:?}", s);
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
        s,
        "000102030405060708090a0b0c0d0e0f10111213",
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
    let ok = try_write_amount_single_row(&mut row, &v, 0, 0, true, "wei");
    assert!(ok);
    assert_eq!(row_str(&row), "123 wei");
}

#[test]
fn positive_write_amount_two_rows_integer_plus_unit() {
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    let v = u256_from_u64(123_456_789);
    let fit = write_amount_two_rows(&mut r1, &mut r2, &v, 0, 0, true, "TOKEN");
    assert_eq!(fit, AmountFit::Full);
    assert_eq!(row_str(&r1), "123456789");
    assert_eq!(row_str(&r2), "TOKEN");
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
    let call = Erc20Call::Transfer { to: [0; 20], amount: u256_from_u64(1) };
    write_erc20_header(&mut row, &call, &meta);
    assert_eq!(row_str(&row), "Send USDC");

    let mut row = [b' '; DISPLAY_COLS];
    let call = Erc20Call::Approve { spender: [0; 20], amount: u256_from_u64(1) };
    write_erc20_header(&mut row, &call, &meta);
    assert_eq!(row_str(&row), "Approve USDC");

    let mut row = [b' '; DISPLAY_COLS];
    let call = Erc20Call::TransferFrom { from: [0;20], to: [0;20], amount: u256_from_u64(1) };
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
    let head_hex = format!("0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        expected[0], expected[1], expected[2], expected[3],
        expected[4], expected[5], expected[6]);
    assert_eq!(&row1[..16], head_hex.as_bytes());
    let tail_hex = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        expected[26], expected[27], expected[28],
        expected[29], expected[30], expected[31]);
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
    assert_eq!(row_str(&pages.buf[1][0]), "Spender:",
        "Approve must label the recipient row as 'Spender:'");
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

// ===========================================================================
// POSITIVE TESTS — EIP-1271 renderers
// ===========================================================================

#[test]
fn positive_eip1271_personal_sign_short_message() {
    let wallet = [0x55u8; 20];
    let msg = b"hello dapp";
    let pages = render_eip1271_personal_sign_pages(
        1, 0, 1, &wallet, msg, 5, 4, 100, true,
    );
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
    let pages = render_eip1271_personal_sign_pages(
        1, 0, 0, &wallet, b"", 5, 4, 100, true,
    );
    // Empty message still produces 1 message page (5 fixed + 1 = 6).
    assert_eq!(pages.len, 6);
}

#[test]
fn positive_eip1271_raw32_six_pages() {
    let mut hash = [0u8; 32];
    for (i, b) in hash.iter_mut().enumerate() {
        *b = i as u8;
    }
    let pages = render_eip1271_raw32_pages(
        1, 0, 1, &hash, 5, 4, 100, true,
    );
    assert_eq!(pages.len, 6);
    assert_eq!(row_str(&pages.buf[0][0]), "EIP-1271 Sign?");
    assert_eq!(row_str(&pages.buf[0][1]), "! Raw 32-byte");
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
    assert!(row1.contains("ROTATE SLOT?"), "row 1 must show the prompt, got {:?}", row1);
    let row2 = row_str(&pages.buf[0][2]);
    assert!(row2.contains("New slot: 3"), "row 2 must show the slot index, got {:?}", row2);
    let row3 = row_str(&pages.buf[0][3]);
    assert!(row3.contains("+bootstrap use"),
        "row 3 must warn about bootstrap-use consumption, got {:?}", row3);
}

#[test]
fn positive_batch_wrap_adds_banner_page() {
    let resolver = NameResolver::new();
    let tx = sample_tx();
    let inner = render_pages(&tx, &resolver);
    let inner_len = inner.len;
    let wrapped = wrap_pages_with_batch_banner(inner, 0, 3);
    assert_eq!(wrapped.len, inner_len + 1);
    // Banner page is page 0
    let row1 = row_str(&wrapped.buf[0][1]);
    assert!(row1.contains("BATCH SIGN"));
    let row2 = row_str(&wrapped.buf[0][2]);
    assert!(row2.contains("Tx 1 of 3"),
        "1-based render of batch index, got {:?}", row2);
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
fn negative_chain_name_unknown_chain_marked_unverified() {
    // Assumption: any chain id NOT on the curated list must visibly
    // warn the user the firmware can't confirm what network they're on
    // — otherwise an attacker on an obscure chain looks identical to
    // mainnet on screen.  This pins the exact string.
    for sneaky in [0u64, 2, 11, 250, 100000, u64::MAX] {
        assert_eq!(
            chain_name(sneaky),
            "(UNVERIFIED)",
            "unknown chain {} must render '(UNVERIFIED)' — see invariant in primitives.rs",
            sneaky,
        );
    }
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
                assert_ne!(name, name2,
                    "chain labels {} and {} must not visually collide", id, id2);
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
    assert!(format_u64(1_000_000, &mut buf).is_none(),
        "format_u64 must NOT silently truncate when buffer is too small");
}

#[test]
fn negative_write_gas_overflow_paints_marker_not_wrong_digits() {
    // Assumption: a gas value that doesn't fit in decimal on 16 cols
    // must surface "!OVF" rather than a truncated number that looks
    // smaller than reality. Triggered by very large gas limits.
    let mut row = [b' '; DISPLAY_COLS];
    // (gas: ) = 6 + ")" = 7. We have 16-7 = 9 cols for the number,
    // so 10^9-ish triggers the overflow marker.
    write_gas(&mut row, u64::MAX); // 20 digits, can't fit
    let s = row_str(&row);
    assert!(s.contains("!OVF"),
        "u64::MAX gas must surface !OVF, got {:?}", s);
}

#[test]
fn negative_write_nonce_row_overflow_paints_marker() {
    let mut row = [b' '; DISPLAY_COLS];
    write_nonce_row(&mut row, u64::MAX); // 20 digits, blows past 16 cols
    let s = row_str(&row);
    assert!(s.contains("!OVF"),
        "u64::MAX nonce must surface !OVF, got {:?}", s);
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
    assert_eq!(fit, AmountFit::Overflow,
        "U256::MAX as ETH must report Overflow");
}

#[test]
fn negative_write_gwei_overflow_falls_to_explicit_marker() {
    let mut row = [b' '; DISPLAY_COLS];
    let max = U256([0xFFu8; 32]);
    let ok = write_gwei(&mut row, &max);
    let s = row_str(&row);
    assert!(!ok, "U256::MAX gas price must return false");
    assert_eq!(s, "!OVERFLOW",
        "overflow must paint the explicit '!OVERFLOW' marker, got {:?}", s);
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
    assert_ne!(a_rows, b_rows,
        "addresses differing in byte 10 must render differently");
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
    assert_eq!(&r1[..2], b"0x",
        "unknown address must fall back to hex render (no name sentinel)");
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
        &Erc20Call::Approve { spender: [0; 20], amount: unlimited },
        &meta,
        &resolver,
    );
    assert_eq!(row_str(&pages.buf[2][1]), "unlimited");

    // 2. Transfer(unlimited) → MUST NOT collapse to "unlimited".
    let pages = render_erc20_known_pages(
        &tx,
        &Erc20Call::Transfer { to: [0; 20], amount: unlimited },
        &meta,
        &resolver,
    );
    assert_ne!(row_str(&pages.buf[2][1]), "unlimited",
        "Transfer must render the digits — only Approve gets the 'unlimited' affordance");
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
    for i in 7..32 { amt[i] = 0xFF; }
    let call = Erc20Call::Approve { spender: [0; 20], amount: U256(amt) };
    let pages = render_erc20_known_pages(&tx, &call, &meta, &resolver);
    assert_ne!(row_str(&pages.buf[2][1]), "unlimited",
        "amounts < 2^200 must render as digits, not 'unlimited'");
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
    let call = Erc20Call::Transfer { to: [0; 20], amount: u256_from_u64(1) };
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
    let call = Erc20Call::Transfer { to: [0; 20], amount: u256_from_u64(1) };
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
    assert_ne!(p1.buf[4][1], p2.buf[4][1],
        "1-bit calldata change must change the rendered hash row 1");
    assert_ne!(p1.buf[4][2], p2.buf[4][2],
        "1-bit calldata change must change the rendered hash row 2");
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
    assert_eq!(row_str(&pages_with_sel.buf[0][0]), "! BLIND SIGN",
        "FUNCTION:/GUESS: page must NEVER displace the BLIND SIGN banner from page 0");
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
    assert_ne!(p_c.buf[1][0], p_s.buf[1][0],
        "Curated and SelfAttest provenance must render distinguishable labels");
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
    assert_eq!(row_str(&pages.buf[2][0]), "! VALUE:",
        "non-zero value on blind-sign must show the loud '! VALUE:' banner");
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
    let pages = render_eip1271_personal_sign_pages(
        1, 0, 1, &wallet, msg, 5, 4, 100, true,
    );
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
    let pages = render_eip1271_personal_sign_pages(
        1, 0, 1, &wallet, msg, 5, 4, 100, true,
    );
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

    let p_deployed = render_eip1271_personal_sign_pages(
        1, 0, 1, &wallet, b"hi", 5, 4, 100, true,
    );
    let p_pre_deploy = render_eip1271_personal_sign_pages(
        1, 0, 1, &wallet, b"hi", 5, 4, 100, false,
    );
    assert_eq!(row_str(&p_deployed.buf[0][2]), "Verify on dapp");
    // "! Pre-deploy 6492" is 17 chars — truncated to 16 by write_line.
    assert_eq!(row_str(&p_pre_deploy.buf[0][2]), "! Pre-deploy 649");
    assert_ne!(p_deployed.buf[0][2], p_pre_deploy.buf[0][2]);

    // Same affordance on the raw32 path.
    let hash = [0u8; 32];
    let r_deployed = render_eip1271_raw32_pages(1, 0, 1, &hash, 5, 4, 100, true);
    let r_pre = render_eip1271_raw32_pages(1, 0, 1, &hash, 5, 4, 100, false);
    assert_eq!(row_str(&r_deployed.buf[0][2]), "Verify on dapp");
    assert_eq!(row_str(&r_pre.buf[0][2]), "! Pre-deploy 649");
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
    let pages = render_eip1271_personal_sign_pages(
        1, 0, 0, &wallet, &msg, 5, 4, 100, true,
    );
    assert_eq!(pages.len, 5 + 1,
        "48-byte (= CHARS_PER_PAGE) msg fits in exactly 1 message page");
}

#[test]
fn negative_eip1271_msg_pagination_one_byte_over_boundary() {
    // Just past the boundary needs a second message page.
    let wallet = [0x55u8; 20];
    let msg = [b'A'; 49];
    let pages = render_eip1271_personal_sign_pages(
        1, 0, 0, &wallet, &msg, 5, 4, 100, true,
    );
    assert_eq!(pages.len, 5 + 2,
        "49-byte msg crosses CHARS_PER_PAGE boundary → 2 message pages");
}

#[test]
fn negative_eip1271_raw32_hash_bytes_round_trip_unchanged() {
    // Assumption: every hex digit shown is a verbatim render of the
    // input hash — flipping any byte must surface in the page output.
    let mut h1 = [0u8; 32];
    let mut h2 = [0u8; 32];
    for (i, b) in h1.iter_mut().enumerate() { *b = i as u8; }
    h2.copy_from_slice(&h1);
    h2[20] ^= 0x55;

    let p1 = render_eip1271_raw32_pages(1, 0, 0, &h1, 5, 4, 100, true);
    let p2 = render_eip1271_raw32_pages(1, 0, 0, &h2, 5, 4, 100, true);
    // Byte 20 lives on Hash 2/2 page (index 4), inside row 1 (16..24).
    assert_ne!(p1.buf[4][1], p2.buf[4][1],
        "byte-20 flip must surface as a different rendered hex row");
}

#[test]
fn negative_eip1271_budget_row_reflects_supplied_counter() {
    // Assumption: the budget row shows the POST-increment local count
    // over the cap, not a stale value. We assert exact text so future
    // refactors can't accidentally swap "used" for "remaining".
    let wallet = [0x55u8; 20];
    let pages = render_eip1271_personal_sign_pages(
        1, 0, 0, &wallet, b"x", 17, 12, 100, true,
    );
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
    let pages = render_eip1271_personal_sign_pages(
        1, 0, 0, &wallet, b"x", 1, 99, 100, true,
    );
    let last = pages.len - 1;
    assert_eq!(row_str(&pages.buf[last][1]), "Gap: 0",
        "Gap row must saturating-sub, never underflow");
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
    assert!(row3.contains("+bootstrap use"),
        "rotation page MUST surface bootstrap-budget consumption, got {:?}", row3);
}

#[test]
fn negative_slot_rotation_shows_index() {
    // Different slot indices must produce visibly different pages so a
    // user can verify which slot is being rotated.
    let a = build_slot_rotation_pages(3);
    let b = build_slot_rotation_pages(8);
    assert_ne!(a.buf[0][2], b.buf[0][2],
        "slot_index must be visible on row 2");
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
        let wrapped = wrap_pages_with_batch_banner(inner, idx, 4);
        let row2 = row_str(&wrapped.buf[0][2]);
        let expected_one_based = format!("Tx {} of 4", idx + 1);
        assert!(row2.contains(&expected_one_based),
            "batch index {} (0-based) must render as 'Tx {} of 4', got {:?}",
            idx, idx + 1, row2);
    }
}

#[test]
fn negative_batch_banner_refuses_to_overflow_max_pages() {
    // Assumption (batch.rs: 33-39): if inner.len + 1 > MAX_PAGES, the
    // wrapper must fall back to the inner pages unchanged rather than
    // truncating or panicking. This guards against future renderers
    // growing past MAX_PAGES - 1 and silently dropping the banner OR
    // the last inner page.
    let mut huge = Pages::empty_with_len(MAX_PAGES);
    // Tag the inner so we can recognise it.
    huge.buf[0][0][0] = b'I';
    let wrapped = wrap_pages_with_batch_banner(huge, 0, 2);
    assert_eq!(wrapped.len, MAX_PAGES,
        "wrap must refuse to grow past MAX_PAGES");
    assert_eq!(wrapped.buf[0][0][0], b'I',
        "on refusal, inner pages must be returned unchanged");
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
    // MAX_PAGES (currently 22). This test asserts the budget envelope —
    // if anyone bumps MAX_OFFCHAIN_PERSONAL_SIGN_LEN past what the
    // page bucket can accommodate, MAX_PAGES must grow to match.
    let max_message_pages = MAX_PAGES - 5;
    let max_message_chars = max_message_pages * 48;
    assert!(max_message_chars >= 700,
        "MAX_PAGES = {} only buys {} message-page chars = {} bytes; \
         CLAUDE.md documents MAX_OFFCHAIN_PERSONAL_SIGN_LEN ≤ 700",
        MAX_PAGES, max_message_pages, max_message_chars);
}

#[test]
fn negative_max_pages_matches_production_constant() {
    // Pin the literal so a silent reduction would fail loudly. The
    // canonical value lives in `tx/display/mod.rs:72`; this scaffold's
    // copy and that source must stay in lockstep. Searches the
    // production source text rather than the gated-out module.
    let src = include_str!("../tx/display/mod.rs");
    let needle = "pub const MAX_PAGES: usize = 22;";
    assert!(src.contains(needle),
        "production tx/display/mod.rs no longer defines `{}` — either \
         bump MAX_PAGES here and update this test, OR fix the source.",
        needle);
}

// --- Source-text invariant: enforce frozen page-renderer surface ----------

#[test]
fn negative_blind_sign_banner_text_pinned() {
    // The "! BLIND SIGN" string is what the user is trained to look
    // for. A copy-edit (e.g. "BLIND SIGNATURE", "Unknown signature")
    // would silently disrupt that training — the source text is pinned
    // here so a tweak fails CI loudly.
    let src = include_str!("../tx/display/blind_sign.rs");
    assert!(src.contains("\"! BLIND SIGN\""),
        "blind_sign.rs must keep the exact '! BLIND SIGN' banner literal");
    assert!(src.contains("\"Verify on dapp\""),
        "blind_sign.rs must keep the 'Verify on dapp' guidance literal");
}

#[test]
fn negative_personal_sign_sanitiser_range_pinned() {
    // The printable range (0x20..=0x7E) is load-bearing for the
    // glyph-spoofing guarantee. A future refactor to e.g. allow
    // 0x80-0xFF for "UTF-8 passthrough" would break the trusted
    // display contract. Pin the literal.
    let src = include_str!("../tx/display/eip1271.rs");
    assert!(src.contains("(0x20..=0x7E)"),
        "eip1271.rs sanitise_byte must keep the (0x20..=0x7E) printable range");
}

#[test]
fn negative_chain_name_list_pinned() {
    // The full curated chain list — bound here so an addition or
    // removal of an entry forces the test to be re-acked. Mirrors the
    // KDF-tag-stability discipline from CLAUDE.md "no casual KDF tag
    // changes".
    let src = include_str!("../tx/display/primitives.rs");
    for needle in [
        "1 => \"(Mainnet)\"",
        "10 => \"(Optimism)\"",
        "56 => \"(BSC)\"",
        "100 => \"(Gnosis)\"",
        "137 => \"(Polygon)\"",
        "8453 => \"(Base)\"",
        "42161 => \"(Arbitrum)\"",
        "11155111 => \"(Sepolia)\"",
        "84532 => \"(BaseSepolia)\"",
        "_ => \"(UNVERIFIED)\"",
    ] {
        assert!(src.contains(needle),
            "primitives.rs chain_name must keep `{}`", needle);
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
    assert_all_pages_printable(&render_blind_sign_pages(&tx, &nasty_data, Some(&meta_curated), &resolver));

    let meta = usdc_metadata();
    let call = Erc20Call::Transfer { to: [0x33; 20], amount: u256_from_u64(7) };
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
    write_tip_row(&mut tip_row, &tip);
    let s = row_str(&tip_row);
    assert!(s.starts_with("Tip:"), "expected Tip: prefix, got {:?}", s);
    assert!(s.contains("gwei"), "expected 'gwei' unit, got {:?}", s);

    let mut fee_row = [b' '; DISPLAY_COLS];
    write_fee_budget_row(&mut fee_row, &u256_from_u64(30_000_000_000), 21_000);
    let s = row_str(&fee_row);
    assert!(s.starts_with("Max:"), "expected Max: prefix, got {:?}", s);
    assert!(s.contains("ETH"), "expected ETH unit, got {:?}", s);
}

#[test]
fn negative_write_fee_budget_saturates_on_multiplication_overflow() {
    // saturating_mul_u64 returns U256::MAX on overflow rather than
    // wrapping. The render must surface "Max: " with a non-empty value
    // (clamped, not zero) — a wrong-by-modulus rendering would mislead
    // the user about fee exposure.
    let mut row = [b' '; DISPLAY_COLS];
    let pathological = U256([0xFFu8; 32]);
    write_fee_budget_row(&mut row, &pathological, u64::MAX);
    let s = row_str(&row);
    assert!(s.starts_with("Max:"),
        "fee budget row must still carry the 'Max:' prefix, got {:?}", s);
    // Either the marker or a clamped-MAX render is acceptable; what's
    // forbidden is a quiet "Max: 0 ETH" (which would be the wrap-around
    // bug we're guarding against).
    assert_ne!(s, "Max: 0 ETH");
}

#[test]
fn positive_assert_total_test_breadth() {
    // Sanity: this file must keep producing both halves of the pass.
    // (Compile-time presence check via path-locality.)
    let positives = include_str!("pure_tests.rs").matches("fn positive_").count();
    let negatives = include_str!("pure_tests.rs").matches("fn negative_").count();
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
    assert_eq!(r1[0], b'+', "name hit must paint the '+' sentinel in row 1 col 0");
    assert_eq!(r1[1], b' ');
    // Hex fallback uses '0' as the first byte of row 1; name hit uses
    // '+' — they must be visually distinguishable.
    let mut bare_r1 = [b' '; DISPLAY_COLS];
    let mut bare_r2 = [b' '; DISPLAY_COLS];
    let mut bare_r3 = [b' '; DISPLAY_COLS];
    write_addr_full(&mut bare_r1, &mut bare_r2, &mut bare_r3, &addr);
    assert_ne!(r1[..2], bare_r1[..2],
        "name-hit and hex-fallback first-two bytes must differ");
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
    assert!(arg_label.starts_with("arg 0"),
        "arg 0 label expected, got {:?}", arg_label);
    let arg_value = row_str(&pages.buf[1][1]);
    assert_eq!(arg_value, "42", "uint256 arg value");
}

#[test]
fn positive_typed_call_renders_address_arg_with_name() {
    let tx = sample_tx();
    let mut resolver = NameResolver::new();
    let addr = [0xCD; 20];
    resolver.push(crate::names::NameMeta {
        chain_id: 1, address: addr, name: b"Coinbase",
    });
    let sel = [0x11, 0x22, 0x33, 0x44];
    let meta = curated_selector(b"transfer(address)", sel);
    let mut inner = Vec::new();
    inner.extend_from_slice(&sel);
    let mut word = [0u8; 32];
    word[12..32].copy_from_slice(&addr);
    inner.extend_from_slice(&word);
    let pages = try_render_typed_call(&tx, &inner, &meta, &resolver)
        .expect("address arg should render");
    // The address arg should produce the "+ Coinbase" name sentinel
    // on row 1 of page 1.
    assert_eq!(pages.buf[1][1][0], b'+',
        "name resolver hit on address arg must paint sentinel");
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
    let pages = try_render_typed_call(&tx, &inner, &meta, &resolver)
        .expect("bool true should render");
    assert_eq!(row_str(&pages.buf[1][1]), "true");
}

#[test]
fn positive_typed_call_renders_dynamic_string_arg() {
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
    let pages = try_render_typed_call(&tx, &inner, &meta, &resolver)
        .expect("string arg should render");
    // Layout for dynamic string args: row 1 = "len: N", row 2 = preview.
    assert_eq!(row_str(&pages.buf[1][1]), "len: 5");
    let row2 = row_str(&pages.buf[1][2]);
    assert!(row2.starts_with("hello"),
        "ASCII string preview must show on row 2, got {:?}", row2);
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
    assert!(try_render_typed_call(&tx, &inner, &meta, &resolver).is_none(),
        "selector mismatch must force the typed-call renderer to decline");
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
        b"f(uint256,uint256,uint256,uint256,uint256,uint256,uint256)", sel);
    let mut inner = Vec::new();
    inner.extend_from_slice(&sel);
    for i in 0..7 {
        inner.extend_from_slice(&ascii_u256(i as u64));
    }
    assert!(try_render_typed_call(&tx, &inner, &meta, &resolver).is_none(),
        "argument count > MAX_TYPED_ARGS_RENDERED must force the renderer \
         to decline so the caller falls back to BLIND SIGN");
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
    assert_ne!(p_c.buf[0][0], p_s.buf[0][0],
        "Curated vs SelfAttest banner must visibly differ");
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
    assert_ne!(r_a, r_b,
        "1-bit selector change must change the rendered Sel: row");
}
