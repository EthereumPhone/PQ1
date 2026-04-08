//! Trusted-UI page renderer for CowSwap EIP-712 v3 orders.
//!
//! This module owns the 8-page confirmation flow that the secure
//! world shows the user after a successful Groth16 verification in
//! `cmd_clear_sign_msg`. It consumes two byte slices:
//!
//!   * `readable` (128 B, bound via `H_str`) — the amounts + symbols
//!      the circuit formatted into ASCII. We splice this verbatim
//!      onto the two "order body" pages without re-parsing.
//!   * `canonical` (204 B, bound via `H_tx`) — the packed GPv2Order
//!      fields. The circuit doesn't format them as ASCII, but they
//!      ARE Poseidon-bound, so the firmware can safely render them
//!      directly into the remaining pages. This is the "two-tier
//!      display" trick the v3 design uses to keep circuit constraint
//!      counts bounded while still surfacing every field the user
//!      needs to confirm.
//!
//! Page layout (8 pages × 4 rows × 16 cols = 512 chars of display):
//!
//!   0: "Sign CowSwap?"  / chain line     / kind line       / "> next"
//!   1: readable[  0.. 64) — kind / SELL: / sell amount     / sell symbol
//!   2: readable[ 64..128) — for-at-least / buy amount      / buy symbol
//!   3: "Receiver:"       / 0x....        / ....XXXXXXXX    / "> next"
//!   4: "Expires:"        / <unix epoch>  / "Partial: Y/N " / "> next"
//!   5: "Fee:"            / <fee hex raw> / "src:X dst:Y   " / "> next"
//!   6: "appData:"        / 0x<first 14h> / <last 14 hex>   / "> next"
//!   7: ""                / "L=Cancel  "  / "R=Confirm    " / (buttons)

use crate::tx::display::{Pages, MAX_PAGES};
use crate::ui::confirm::Page;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

// ---------------------------------------------------------------------------
// Canonical field slice offsets (must match
// `secure/src/tx/eip712/cowswap.rs::decode_canonical`).
// ---------------------------------------------------------------------------

const OFF_CHAIN_ID: usize = 0;
const OFF_RECEIVER: usize = 48;
const OFF_FEE_AMOUNT: usize = 132;
const OFF_VALID_TO: usize = 164;
const OFF_PARTIAL: usize = 169;
const OFF_SELL_TOKEN_BAL: usize = 170;
const OFF_BUY_TOKEN_BAL: usize = 171;
const OFF_APP_DATA: usize = 172;

/// Produce the full 8-page confirmation flow for a verified CowSwap
/// EIP-712 v3 order.
pub fn render_cowswap_pages(canonical: &[u8; 204], readable: &[u8; 128]) -> Pages {
    let mut pages = Pages::empty_with_len(8);

    let chain_id = u64::from_be_bytes([
        canonical[OFF_CHAIN_ID + 0],
        canonical[OFF_CHAIN_ID + 1],
        canonical[OFF_CHAIN_ID + 2],
        canonical[OFF_CHAIN_ID + 3],
        canonical[OFF_CHAIN_ID + 4],
        canonical[OFF_CHAIN_ID + 5],
        canonical[OFF_CHAIN_ID + 6],
        canonical[OFF_CHAIN_ID + 7],
    ]);

    // ── Page 0: Header / chain / "> next" ─────────────────────────
    write_line(&mut pages.row_mut(0, 0), "Sign CowSwap?");
    write_chain_row(&mut pages.row_mut(0, 1), chain_id);
    write_line(&mut pages.row_mut(0, 2), chain_name_str(chain_id));
    write_line(&mut pages.row_mut(0, 3), "> next");

    // ── Page 1: readable[0..64) — 4 lines of ASCII from the proof ──
    splice_readable_rows(&mut pages, 1, &readable[0..64]);

    // ── Page 2: readable[64..128) — remaining 4 lines ──────────────
    splice_readable_rows(&mut pages, 2, &readable[64..128]);

    // ── Page 3: Receiver ───────────────────────────────────────────
    write_line(&mut pages.row_mut(3, 0), "Receiver:");
    let receiver: [u8; 20] = canonical[OFF_RECEIVER..OFF_RECEIVER + 20]
        .try_into()
        .expect("20-byte slice");
    // `write_addr_two_rows` needs mutable access to rows 1 and 2 at
    // the same time. Borrow the page slice once and split it so both
    // rows get independent mutable refs without tripping the
    // double-mutable-borrow check.
    {
        let page = pages.page_mut(3);
        let (head, tail) = page.split_at_mut(2);
        write_addr_two_rows(&mut head[1], &mut tail[0], &receiver);
    }
    write_line(&mut pages.row_mut(3, 3), "> next");

    // ── Page 4: Expires + partiallyFillable ───────────────────────
    write_line(&mut pages.row_mut(4, 0), "Expires:");
    let valid_to = u32::from_be_bytes([
        canonical[OFF_VALID_TO + 0],
        canonical[OFF_VALID_TO + 1],
        canonical[OFF_VALID_TO + 2],
        canonical[OFF_VALID_TO + 3],
    ]);
    write_u32_row(&mut pages.row_mut(4, 1), "unix ", valid_to);
    write_partial_row(&mut pages.row_mut(4, 2), canonical[OFF_PARTIAL]);
    write_line(&mut pages.row_mut(4, 3), "> next");

    // ── Page 5: Fee + balance kinds ────────────────────────────────
    write_line(&mut pages.row_mut(5, 0), "Fee:");
    // Fee amount is a uint256 BE; show the last 8 bytes as hex. Zero
    // shows as "0x0000000000000000" which is unambiguous. Non-zero
    // fees are rare on CowSwap user orders (the solver pays gas), so
    // this raw hex is mostly a safety indicator rather than a value
    // the user has to parse.
    write_fee_row(
        &mut pages.row_mut(5, 1),
        &canonical[OFF_FEE_AMOUNT..OFF_FEE_AMOUNT + 32],
    );
    write_balance_row(
        &mut pages.row_mut(5, 2),
        canonical[OFF_SELL_TOKEN_BAL],
        canonical[OFF_BUY_TOKEN_BAL],
    );
    write_line(&mut pages.row_mut(5, 3), "> next");

    // ── Page 6: appData ────────────────────────────────────────────
    write_line(&mut pages.row_mut(6, 0), "appData:");
    let app = &canonical[OFF_APP_DATA..OFF_APP_DATA + 32];
    write_app_data_prefix(&mut pages.row_mut(6, 1), app);
    write_app_data_suffix(&mut pages.row_mut(6, 2), app);
    write_line(&mut pages.row_mut(6, 3), "> next");

    // ── Page 7: Confirm ────────────────────────────────────────────
    write_line(&mut pages.row_mut(7, 0), "");
    write_line(&mut pages.row_mut(7, 1), "  Long-press:");
    write_line(&mut pages.row_mut(7, 2), "L=Cancel");
    write_line(&mut pages.row_mut(7, 3), "R=Confirm");

    let _ = MAX_PAGES;
    pages
}

// ---------------------------------------------------------------------------
// Row helpers
// ---------------------------------------------------------------------------

fn write_line(row: &mut [u8; DISPLAY_COLS], text: &str) {
    *row = [b' '; DISPLAY_COLS];
    let bytes = text.as_bytes();
    let n = core::cmp::min(bytes.len(), DISPLAY_COLS);
    row[..n].copy_from_slice(&bytes[..n]);
}

/// Splice 64 bytes of circuit-bound readable output (4 rows × 16) into
/// a page, pinning non-printable bytes to ASCII space so a malicious
/// NS can't sneak control chars onto the OLED. The proof constrains
/// every byte of `readable`, so this filter is belt-and-braces — the
/// only bytes that should ever reach us are 0x20..0x7e already.
fn splice_readable_rows(pages: &mut Pages, page_idx: usize, readable: &[u8]) {
    for row_idx in 0..DISPLAY_ROWS {
        let row = pages.row_mut(page_idx, row_idx);
        *row = [b' '; DISPLAY_COLS];
        let start = row_idx * DISPLAY_COLS;
        for col in 0..DISPLAY_COLS {
            let b = readable[start + col];
            row[col] = if (0x20..0x7f).contains(&b) { b } else { b' ' };
        }
    }
}

fn write_chain_row(row: &mut [u8; DISPLAY_COLS], chain_id: u64) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"chain ";
    row[..prefix.len()].copy_from_slice(prefix);
    let mut tmp = [0u8; 16];
    let n = format_u64_decimal(chain_id, &mut tmp);
    let off = prefix.len();
    let copy = core::cmp::min(n, DISPLAY_COLS - off);
    row[off..off + copy].copy_from_slice(&tmp[..copy]);
}

fn chain_name_str(chain_id: u64) -> &'static str {
    match chain_id {
        1 => "(Mainnet)",
        10 => "(Optimism)",
        56 => "(BSC)",
        100 => "(Gnosis)",
        137 => "(Polygon)",
        8453 => "(Base)",
        42161 => "(Arbitrum)",
        11155111 => "(Sepolia)",
        _ => "",
    }
}

/// Render a 20-byte address across two rows:
///
///   row1: "0x" + first 7 bytes hex (14 chars) → 16 chars
///   row2: "..." + last 6 bytes hex (12 chars + 3 dots + 1 pad) → 16 chars
fn write_addr_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    addr: &[u8; 20],
) {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    row1[0] = b'0';
    row1[1] = b'x';
    for i in 0..7 {
        row1[2 + i * 2] = hex_nibble(addr[i] >> 4);
        row1[2 + i * 2 + 1] = hex_nibble(addr[i] & 0x0f);
    }
    row2[0] = b'.';
    row2[1] = b'.';
    row2[2] = b'.';
    row2[3] = b' ';
    // Last 6 bytes of the address = 12 hex chars at cols 4..16.
    for i in 0..6 {
        let b = addr[14 + i];
        row2[4 + i * 2] = hex_nibble(b >> 4);
        row2[4 + i * 2 + 1] = hex_nibble(b & 0x0f);
    }
}

fn write_u32_row(row: &mut [u8; DISPLAY_COLS], prefix: &str, value: u32) {
    *row = [b' '; DISPLAY_COLS];
    let p = prefix.as_bytes();
    let n = core::cmp::min(p.len(), DISPLAY_COLS);
    row[..n].copy_from_slice(&p[..n]);
    let mut tmp = [0u8; 16];
    let k = format_u64_decimal(value as u64, &mut tmp);
    let off = n;
    let copy = core::cmp::min(k, DISPLAY_COLS - off);
    row[off..off + copy].copy_from_slice(&tmp[..copy]);
}

fn write_partial_row(row: &mut [u8; DISPLAY_COLS], partial: u8) {
    write_line(row, if partial == 0 { "Partial: no" } else { "Partial: yes" });
}

/// Render the last 8 bytes of a 32-byte fee amount as
/// "fee 0xXXXXXXXXXXXXXXXX" (6+2+16 = 24 chars)... which overflows
/// 16 cols. Compress to "0x" + 14 hex chars of the last 7 bytes =
/// 16 chars exactly.
fn write_fee_row(row: &mut [u8; DISPLAY_COLS], fee: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    row[0] = b'0';
    row[1] = b'x';
    // Low 7 bytes of the fee (bytes 25..32 of the BE uint256).
    let start = 32 - 7;
    for i in 0..7 {
        let b = fee[start + i];
        row[2 + i * 2] = hex_nibble(b >> 4);
        row[2 + i * 2 + 1] = hex_nibble(b & 0x0f);
    }
}

/// Render the sell/buy balance kinds as:
///   "src:S dst:D"   where S ∈ {e,x,i} (erc20, external, internal)
///                         D ∈ {e,i}   (erc20, internal)
fn write_balance_row(row: &mut [u8; DISPLAY_COLS], sell_bal: u8, buy_bal: u8) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"src:";
    row[..4].copy_from_slice(prefix);
    row[4] = balance_char_sell(sell_bal);
    row[5] = b' ';
    row[6] = b'd';
    row[7] = b's';
    row[8] = b't';
    row[9] = b':';
    row[10] = balance_char_buy(buy_bal);
}

fn balance_char_sell(b: u8) -> u8 {
    match b {
        0 => b'e', // erc20
        1 => b'x', // external
        2 => b'i', // internal
        _ => b'?',
    }
}

fn balance_char_buy(b: u8) -> u8 {
    match b {
        0 => b'e', // erc20
        1 => b'i', // internal
        _ => b'?',
    }
}

/// Render "0x" + first 7 bytes of appData hex = 16 chars.
fn write_app_data_prefix(row: &mut [u8; DISPLAY_COLS], app: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    row[0] = b'0';
    row[1] = b'x';
    for i in 0..7 {
        let b = app[i];
        row[2 + i * 2] = hex_nibble(b >> 4);
        row[2 + i * 2 + 1] = hex_nibble(b & 0x0f);
    }
}

/// Render "..." + last 6 bytes of appData hex = 16 chars.
fn write_app_data_suffix(row: &mut [u8; DISPLAY_COLS], app: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    row[0] = b'.';
    row[1] = b'.';
    row[2] = b'.';
    row[3] = b' ';
    for i in 0..6 {
        let b = app[26 + i];
        row[4 + i * 2] = hex_nibble(b >> 4);
        row[4 + i * 2 + 1] = hex_nibble(b & 0x0f);
    }
}

fn hex_nibble(n: u8) -> u8 {
    match n & 0x0f {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

fn format_u64_decimal(mut n: u64, out: &mut [u8]) -> usize {
    if n == 0 {
        if !out.is_empty() {
            out[0] = b'0';
            return 1;
        }
        return 0;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let len = core::cmp::min(i, out.len());
    for j in 0..len {
        out[j] = buf[i - 1 - j];
    }
    len
}
