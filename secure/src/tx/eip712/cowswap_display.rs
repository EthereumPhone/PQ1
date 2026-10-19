//! Trusted-UI page renderer for CowSwap GPv2Order clear-signing.
//!
//! Consumes a verified order (`VerifiedCowswapV3`): the 204-byte packed
//! `canonical` GPv2Order plus two `CowLeg`s describing how each swap leg
//! should render. `canonical` is bound to the signed setPreSignature
//! calldata by the native keccak cross-check in
//! `crate::tx::eip712::cowswap::verify`, so every field rendered here is
//! provably the order the chain will act on.
//!
//! Each leg renders one of two ways:
//!
//!   * `CowLeg::Decoded` — the leg's ERC-20 bundle Merkle-verified
//!     against `ERC20_DB_ROOT`, so the firmware shows `<amount> <symbol>`
//!     with `decimals` applied (the same fixed-width, anti-spoof
//!     amount formatter the ERC-20 transfer path uses) on page A, and
//!     the human-readable `<name>` + the FULL 20-byte token contract
//!     address (40 hex across 3 rows) on page B — shown in full because
//!     the address is the anti-DB-spoof backstop, exactly like the
//!     ERC-20 transfer path's "Contract:" page and the CoW `receiver`
//!     page. 2 pages.
//!   * `CowLeg::AddrHex` — no usable bundle: the firmware shows the raw
//!     20-byte token address + the full uint256 amount as hex so the
//!     user can still verify magnitudes without trusting the host for
//!     decimals. 2 pages.
//!
//! Token metadata is decoded on-device against a firmware-pinned Merkle
//! root.

use crate::tx::display::Pages;
use crate::tx::eip712::cowswap::CowLeg;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

// ---------------------------------------------------------------------------
// Canonical field slice offsets (must match
// `secure/src/tx/eip712/cowswap.rs::decode_canonical`).
// ---------------------------------------------------------------------------

const OFF_CHAIN_ID: usize = 0;
const OFF_SELL_TOKEN: usize = 8;
const OFF_BUY_TOKEN: usize = 28;
const OFF_RECEIVER: usize = 48;
const OFF_SELL_AMOUNT: usize = 68;
const OFF_BUY_AMOUNT: usize = 100;
const OFF_FEE_AMOUNT: usize = 132;
const OFF_VALID_TO: usize = 164;
const OFF_KIND: usize = 168;
const OFF_PARTIAL: usize = 169;
const OFF_SELL_TOKEN_BAL: usize = 170;
const OFF_BUY_TOKEN_BAL: usize = 171;
const OFF_APP_DATA: usize = 172;

#[derive(Clone, Copy)]
enum Side {
    Sell,
    Buy,
}

/// Number of body pages a leg occupies — 2 in both modes:
///   * Decoded: page A = label + amount + symbol, page B = name + full addr.
///   * AddrHex: page A = token address, page B = uint256 hex amount.
///
/// (`decoded` is kept in the signature so callers stay symmetric and a
/// future divergence is a one-line change.)
const fn leg_page_count(_decoded: bool) -> usize {
    2
}

/// Copy a byte slice into one OLED row, space-padded and truncated to
/// the 16-column width. Bytes are clean ASCII by construction (the
/// ERC-20 bundle verifier rejects non-printable symbol/name fields).
fn write_bytes_row(row: &mut [u8; DISPLAY_COLS], bytes: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let n = core::cmp::min(bytes.len(), DISPLAY_COLS);
    row[..n].copy_from_slice(&bytes[..n]);
}

/// Total order-body page count for the given leg modes. Used by the
/// Safe-wrapped renderer to pre-size its `Pages` before calling
/// [`append_order_body_pages`].
///
/// Body = sell leg + buy leg + receiver + (expires/partial) + (fee/bal) +
/// appData → `leg(sell) + leg(buy) + 4`.
#[must_use]
pub fn order_body_page_count(sell: &CowLeg, buy: &CowLeg) -> usize {
    leg_page_count(sell.is_decoded()) + leg_page_count(buy.is_decoded()) + 4
}

/// Execute the real three CoW amount painters into scratch rows before any
/// order page is published. Sell, buy and fee are all signed canonical words;
/// every one must have an exact representation under its selected token
/// metadata.
#[must_use]
pub fn amounts_are_exactly_renderable(canonical: &[u8; 204], sell: &CowLeg, buy: &CowLeg) -> bool {
    fn leg_fits(amount: &[u8; 32], leg: &CowLeg) -> bool {
        let mut row1 = [b' '; DISPLAY_COLS];
        let mut row2 = [b' '; DISPLAY_COLS];
        match leg {
            CowLeg::Decoded {
                decimals,
                symbol,
                symbol_len,
                ..
            } => crate::tx::display::primitives::write_cow_leg_amount(
                &mut row1,
                &mut row2,
                amount,
                *decimals,
                &symbol[..*symbol_len as usize],
            ),
            // The actual fallback leg renderer publishes the complete uint256
            // as hex on its own page, so every value is exact by construction.
            CowLeg::AddrHex => true,
        }
    }

    fn fee_fits(amount: &[u8; 32], sell: &CowLeg) -> bool {
        let mut row1 = [b' '; DISPLAY_COLS];
        let mut row2 = [b' '; DISPLAY_COLS];
        match sell {
            CowLeg::Decoded {
                decimals,
                symbol,
                symbol_len,
                ..
            } => crate::tx::display::primitives::write_cow_leg_amount(
                &mut row1,
                &mut row2,
                amount,
                *decimals,
                &symbol[..*symbol_len as usize],
            ),
            CowLeg::AddrHex => crate::tx::display::primitives::write_cow_leg_amount(
                &mut row1,
                &mut row2,
                amount,
                0,
                &[],
            ),
        }
    }

    let sell_amount: &[u8; 32] = canonical[OFF_SELL_AMOUNT..OFF_SELL_AMOUNT + 32]
        .try_into()
        .expect("32-byte slice");
    let buy_amount: &[u8; 32] = canonical[OFF_BUY_AMOUNT..OFF_BUY_AMOUNT + 32]
        .try_into()
        .expect("32-byte slice");
    let fee_amount: &[u8; 32] = canonical[OFF_FEE_AMOUNT..OFF_FEE_AMOUNT + 32]
        .try_into()
        .expect("32-byte slice");
    leg_fits(sell_amount, sell) && leg_fits(buy_amount, buy) && fee_fits(fee_amount, sell)
}

/// Produce the full confirmation flow for a verified CowSwap order.
///
/// Page layout: header (chain + kind) → order body → confirm. Each leg
/// is 2 pages in both modes, so the body is a constant 8 pages and the
/// full flow is 10 pages (header + 8 + confirm).
pub fn render_cowswap_pages(canonical: &[u8; 204], sell: &CowLeg, buy: &CowLeg) -> Pages {
    render_framed(canonical, sell, buy, "Sign CowSwap?", None)
}

/// The zero-receiver wording of an off-chain (`eip1271`) order: the
/// signing wallet is the order owner, so GPv2 pays the proceeds to it.
pub const OFFCHAIN_OWNER_LABEL: &str = "(= this wallet)";

/// Produce the confirmation flow for a CoW order this wallet signs
/// OFF-CHAIN (`SIGN_OFFCHAIN` kind 5, the CoW `eip1271` scheme). Same pages
/// as [`render_cowswap_pages`] except the banner and the zero-receiver row,
/// which names this wallet (the order owner) instead of the zero address.
pub fn render_cowswap_offchain_pages(canonical: &[u8; 204], sell: &CowLeg, buy: &CowLeg) -> Pages {
    render_framed(canonical, sell, buy, "Sign CoW order?", Some(OFFCHAIN_OWNER_LABEL))
}

fn render_framed(
    canonical: &[u8; 204],
    sell: &CowLeg,
    buy: &CowLeg,
    banner: &str,
    owner_label: Option<&str>,
) -> Pages {
    let total = 1 + order_body_page_count(sell, buy) + 1;
    let mut pages = Pages::empty_with_len(total);

    let chain_id = read_chain_id(canonical);

    // ── Page 0: Header / chain / chain-name / kind ────────────────────
    write_line(&mut pages.row_mut(0, 0), banner);
    let [_, chain_row, chain_continuation, _] = pages.page_mut(0);
    write_chain_rows(chain_row, chain_continuation, chain_id);
    write_line(&mut pages.row_mut(0, 3), order_kind_label(canonical));

    // ── Order body (shared with the Safe-wrapped flow) ───────────────
    let next = append_order_body_pages(&mut pages, 1, canonical, sell, buy, owner_label);
    debug_assert_eq!(next, total - 1);

    // ── Final page: Confirm ──────────────────────────────────────────
    write_line(&mut pages.row_mut(next, 0), "");
    write_line(&mut pages.row_mut(next, 1), "  Long-press:");
    write_line(&mut pages.row_mut(next, 2), "L=Cancel");
    write_line(&mut pages.row_mut(next, 3), "R=Confirm");

    pages
}

/// Write the order-body pages of a verified CoW order into an
/// already-sized `Pages` buffer starting at index `start`; returns the
/// index of the first page after the body.
///
/// Shared core of [`render_cowswap_pages`] (direct flow) and the
/// Safe-wrapped combined renderer in `crate::tx::display::safe_display`
/// — one body implementation, two framings.
///
/// `owner_label`: GPv2 semantics give `receiver == address(0)` the
/// meaning "proceeds go to the order's owner". The direct flow passes
/// `None` (renders the zero address verbatim); the Safe-wrapped flow
/// passes a label like `"(= the Safe)"` so the user understands where
/// the bought tokens land.
pub fn append_order_body_pages(
    pages: &mut Pages,
    start: usize,
    canonical: &[u8; 204],
    sell: &CowLeg,
    buy: &CowLeg,
    owner_label: Option<&str>,
) -> usize {
    let kind = canonical[OFF_KIND];
    let mut p = start;

    // ── Sell leg ─────────────────────────────────────────────────────
    p = append_leg(pages, p, canonical, sell, Side::Sell, kind);
    // ── Buy leg ──────────────────────────────────────────────────────
    p = append_leg(pages, p, canonical, buy, Side::Buy, kind);

    // ── Receiver ─────────────────────────────────────────────────────
    write_line(&mut pages.row_mut(p, 0), "Receiver:");
    let receiver: [u8; 20] = canonical[OFF_RECEIVER..OFF_RECEIVER + 20]
        .try_into()
        .expect("20-byte slice");
    match owner_label {
        Some(label) if receiver == [0u8; 20] => {
            write_line(&mut pages.row_mut(p, 1), label);
            write_line(&mut pages.row_mut(p, 2), "");
            write_line(&mut pages.row_mut(p, 3), "> next");
        }
        _ => {
            // Full 40-hex across rows 1..3 (audit 2026-06-23 — LOW-5). The
            // receiver is a fund destination; the old 2-row head-7/tail-6
            // form hid 7 middle bytes, inconsistent with the full-address
            // ERC-20 recipient page. The row budget is spent on the address
            // (no "> next" footer), exactly like the Safe-address page.
            let [_lbl, a, b, c] = pages.page_mut(p);
            write_addr_full_three_rows(a, b, c, &receiver);
        }
    }
    p += 1;

    // ── Expires + partiallyFillable ──────────────────────────────────
    write_line(&mut pages.row_mut(p, 0), "Expires:");
    let valid_to = u32::from_be_bytes([
        canonical[OFF_VALID_TO],
        canonical[OFF_VALID_TO + 1],
        canonical[OFF_VALID_TO + 2],
        canonical[OFF_VALID_TO + 3],
    ]);
    write_u32_row(&mut pages.row_mut(p, 1), "unix ", valid_to);
    write_partial_row(&mut pages.row_mut(p, 2), canonical[OFF_PARTIAL]);
    write_line(&mut pages.row_mut(p, 3), "> next");
    p += 1;

    // ── Fee (in sell token) + balance kinds ──────────────────────────
    //
    // The GPv2 `feeAmount` is denominated in the SELL token and is
    // debited from the owner on settlement (the owner pays
    // `sellAmount + feeAmount`; the solver keeps the fee). It is bound by
    // the same orderDigest cross-check as every other field, so it MUST
    // be shown at full magnitude — a benign `sellAmount` with an enormous
    // `feeAmount` is a wallet-draining order otherwise.
    //
    // It is rendered with the SAME fixed-width anti-spoof formatter the
    // sell leg uses (`write_cow_leg_amount`): when the sell leg decoded
    // we apply its `decimals` + `symbol`; otherwise we show the raw
    // integer (decimals = 0, no unit). Either way the formatter fails
    // safe to "(amount too big)" rather than silently dropping the
    // high-order bytes — the bug in the retired `write_fee_row`, which
    // showed only the low 7 of 32 bytes (a 100-WETH fee read as ~0.06,
    // and any multiple of 2^56 read as zero).
    write_line(&mut pages.row_mut(p, 0), "Fee (sell tok):");
    let fee: [u8; 32] = canonical[OFF_FEE_AMOUNT..OFF_FEE_AMOUNT + 32]
        .try_into()
        .expect("32-byte slice");
    {
        let page = pages.page_mut(p);
        let (head, tail) = page.split_at_mut(2);
        match sell {
            CowLeg::Decoded {
                decimals,
                symbol,
                symbol_len,
                ..
            } => {
                crate::tx::display::primitives::write_cow_leg_amount(
                    &mut head[1],
                    &mut tail[0],
                    &fee,
                    *decimals,
                    &symbol[..*symbol_len as usize],
                );
            }
            CowLeg::AddrHex => {
                crate::tx::display::primitives::write_cow_leg_amount(
                    &mut head[1],
                    &mut tail[0],
                    &fee,
                    0,
                    &[],
                );
            }
        }
    }
    // Balance kinds move to the footer row (the fee amount now occupies
    // rows 1-2); the page stays a single page so the constant-8 body
    // budget — and every Safe/multiSend page-budget pre-count — is
    // unchanged.
    write_balance_row(
        &mut pages.row_mut(p, 3),
        canonical[OFF_SELL_TOKEN_BAL],
        canonical[OFF_BUY_TOKEN_BAL],
    );
    p += 1;

    // ── appData ──────────────────────────────────────────────────────
    write_line(&mut pages.row_mut(p, 0), "appData:");
    let app = &canonical[OFF_APP_DATA..OFF_APP_DATA + 32];
    write_app_data_prefix(&mut pages.row_mut(p, 1), app);
    write_app_data_suffix(&mut pages.row_mut(p, 2), app);
    write_line(&mut pages.row_mut(p, 3), "> next");
    p += 1;

    p
}

/// Render a single swap leg starting at page `p`; returns the next free
/// page index.
fn append_leg(
    pages: &mut Pages,
    p: usize,
    canonical: &[u8; 204],
    leg: &CowLeg,
    side: Side,
    kind: u8,
) -> usize {
    let (token_off, amount_off) = match side {
        Side::Sell => (OFF_SELL_TOKEN, OFF_SELL_AMOUNT),
        Side::Buy => (OFF_BUY_TOKEN, OFF_BUY_AMOUNT),
    };

    match leg {
        CowLeg::Decoded {
            decimals,
            symbol,
            symbol_len,
            name,
            name_len,
        } => {
            // Page A: label / amount (2 rows) / "> next".
            write_line(&mut pages.row_mut(p, 0), leg_label(kind, side));
            let amount: [u8; 32] = canonical[amount_off..amount_off + 32]
                .try_into()
                .expect("32-byte slice");
            {
                let page = pages.page_mut(p);
                let (head, tail) = page.split_at_mut(2);
                crate::tx::display::primitives::write_cow_leg_amount(
                    &mut head[1],
                    &mut tail[0],
                    &amount,
                    *decimals,
                    &symbol[..*symbol_len as usize],
                );
            }
            write_line(&mut pages.row_mut(p, 3), "> next");
            // Page B: token name (row 0) + the FULL 20-byte token contract
            // address (rows 1-3). The address is the anti-DB-spoof backstop
            // against a symbol-only collision (two "USDC" rows pointing at
            // different contracts), so it is shown in FULL — 40 hex / 160
            // bits — exactly like the ERC-20 transfer path's "Contract:"
            // page and the CoW `receiver` page (audit 2026-06-23, LOW-5).
            // The earlier compact "0x"+first/last-3-byte form left a 48-bit
            // collision window a vanity-address grind (~2^48) could forge to
            // make a hostile token read as a trusted one while a poisoned DB
            // row supplies its symbol/name (audit 2026-06-26). The symbol
            // still labels the amount on page A; the name identifies the
            // token here.
            let token: [u8; 20] = canonical[token_off..token_off + 20]
                .try_into()
                .expect("20-byte slice");
            write_bytes_row(&mut pages.row_mut(p + 1, 0), &name[..*name_len as usize]);
            {
                let [_name_row, a, b, c] = pages.page_mut(p + 1);
                write_addr_full_three_rows(a, b, c, &token);
            }
            p + 2
        }
        CowLeg::AddrHex => {
            // Page A: the FULL token contract plus an amount-page hint in
            // the label. The fallback is used precisely when no verified
            // metadata is available, so the address is the only injective
            // token identity the trusted display can provide.
            let label: &str = match side {
                Side::Sell => "Sell addr;amtHex",
                Side::Buy => "Buy addr;amtHex",
            };
            write_line(&mut pages.row_mut(p, 0), label);
            let token: [u8; 20] = canonical[token_off..token_off + 20]
                .try_into()
                .expect("20-byte slice");
            {
                let [_label, a, b, c] = pages.page_mut(p);
                write_addr_full_three_rows(a, b, c, &token);
            }
            // Page B: full 32-byte uint256 amount as hex.
            write_uint256_hex_page(pages, p + 1, &canonical[amount_off..amount_off + 32]);
            p + 2
        }
    }
}

/// Per-leg label reflecting the order kind so the user sees which side
/// is the exact amount and which is the limit (WYSIWYS):
///   * SELL order: sell is exact, buy is a minimum.
///   * BUY  order: buy is exact, sell is a maximum.
fn leg_label(kind: u8, side: Side) -> &'static str {
    match (kind, side) {
        (0, Side::Sell) => "Sell exactly:",
        (0, Side::Buy) => "Buy >= (min):",
        (_, Side::Sell) => "Sell <= (max):",
        (_, Side::Buy) => "Buy exactly:",
    }
}

/// "kind=SELL" / "kind=BUY" banner row.
#[must_use]
pub fn order_kind_label(canonical: &[u8; 204]) -> &'static str {
    if canonical[OFF_KIND] == 0 {
        "kind=SELL"
    } else {
        "kind=BUY"
    }
}

fn read_chain_id(canonical: &[u8; 204]) -> u64 {
    u64::from_be_bytes([
        canonical[OFF_CHAIN_ID],
        canonical[OFF_CHAIN_ID + 1],
        canonical[OFF_CHAIN_ID + 2],
        canonical[OFF_CHAIN_ID + 3],
        canonical[OFF_CHAIN_ID + 4],
        canonical[OFF_CHAIN_ID + 5],
        canonical[OFF_CHAIN_ID + 6],
        canonical[OFF_CHAIN_ID + 7],
    ])
}

/// Render a 32-byte BE uint256 as 4 rows × 16 hex chars (no prefix /
/// no label — the preceding page tells the user this is the amount).
fn write_uint256_hex_page(pages: &mut Pages, page_idx: usize, bytes: &[u8]) {
    for row_idx in 0..DISPLAY_ROWS {
        let row = pages.row_mut(page_idx, row_idx);
        *row = [b' '; DISPLAY_COLS];
        let start = row_idx * 8; // 8 bytes per row → 16 hex chars
        for i in 0..8 {
            let b = bytes[start + i];
            row[i * 2] = hex_nibble(b >> 4);
            row[i * 2 + 1] = hex_nibble(b & 0x0f);
        }
    }
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

fn write_chain_rows(
    row: &mut [u8; DISPLAY_COLS],
    continuation: &mut [u8; DISPLAY_COLS],
    chain_id: u64,
) {
    *row = [b' '; DISPLAY_COLS];
    *continuation = [b' '; DISPLAY_COLS];
    let prefix = b"chain ";
    row[..prefix.len()].copy_from_slice(prefix);
    let mut tmp = [0u8; 20];
    let n = format_u64_decimal(chain_id, &mut tmp);
    if prefix.len() + n <= DISPLAY_COLS {
        row[prefix.len()..prefix.len() + n].copy_from_slice(&tmp[..n]);
        write_line(continuation, chain_name_str(chain_id));
        return;
    }

    // Six-byte prefix + nine digits + `>` exactly fills row one. A u64 has
    // at most 20 digits, so the remaining eleven always fit on row two.
    const FIRST_DIGITS: usize = 9;
    row[prefix.len()..prefix.len() + FIRST_DIGITS]
        .copy_from_slice(&tmp[..FIRST_DIGITS]);
    row[DISPLAY_COLS - 1] = b'>';
    continuation[..n - FIRST_DIGITS].copy_from_slice(&tmp[FIRST_DIGITS..n]);
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

/// Full 40-hex address across three rows (7 / 8 / 5 bytes), mirroring
/// `display::primitives::write_addr_full`. Local to this module because
/// the `display::primitives` helpers are `pub(super)`-scoped to the
/// display tree and not reachable from `tx::eip712`. Used for the CoW
/// `receiver` page so every byte of a fund destination is shown (audit
/// 2026-06-23 — LOW-5).
fn write_addr_full_three_rows(
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
    // Row 3: bytes 15..20 (10 hex chars, padded to 16)
    for i in 0..5 {
        let b = addr[15 + i];
        row3[i * 2] = hex_nibble(b >> 4);
        row3[i * 2 + 1] = hex_nibble(b & 0x0f);
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

/// Render the low 7 bytes of a 32-byte fee amount as "0x" + 14 hex
/// chars = 16 chars exactly.

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
