//! Render an `Eip1559Tx` into a fixed set of 4-line × 16-col confirmation
//! pages for the secure UI.
//!
//! Layout (5 pages):
//!
//! ```text
//! Page 1: Confirm Tx?     Page 2: To:           Page 3: Value:
//!         Chain: <n>             0x1234abcd...          1.234567 ETH
//!         <chain name>           ...efgh5678            (gas: <limit>)
//!         > next                 > next                 > next
//!
//! Page 4: Max fee:        Page 5: Data: <n>B
//!         <gwei> gwei            Nonce: <n>
//!         Tip: <gwei>            L=Cancel
//!         > next                 R=Confirm
//! ```

use super::eip1559::{Eip1559Tx, U256};
use crate::erc20::bundle::Erc20Metadata;
use crate::erc20::calldata::{is_unlimited_amount, Erc20Call};
use crate::ui::confirm::Page;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// Maximum number of confirmation pages any renderer can produce.
/// Bumped from 5 to 8 to accommodate ERC20 decoded display (header +
/// recipient + raw contract anti-spoof page + amount + chain/gas + fees
/// + nonce + buttons) and BLIND SIGNING (banner + warning text +
/// to + value + selector/length + gas/fees + nonce + buttons).
/// Bumped again to 10 for the CowSwap EIP-712 v3 render path, which
/// splits across: header + two pages of circuit-bound readable
/// (kind/sell/symbol + at-least/buy/symbol) + receiver + expiry+partial
/// + fee+balance + appData + confirm.
pub const MAX_PAGES: usize = 10;

pub struct Pages {
    buf: [Page; MAX_PAGES],
    len: usize,
}

impl Pages {
    pub fn as_slice(&self) -> &[Page] {
        &self.buf[..self.len]
    }

    fn empty() -> Self {
        Pages {
            buf: [[[b' '; DISPLAY_COLS]; DISPLAY_ROWS]; MAX_PAGES],
            len: 0,
        }
    }

    /// Construct a page bundle with exactly `len` visible pages,
    /// pre-filled with ASCII space. Used both internally by the
    /// EIP-1559 renderers in this file and externally by the
    /// CowSwap EIP-712 renderer in
    /// `crate::tx::eip712::cowswap_display`.
    pub fn empty_with_len(len: usize) -> Self {
        assert!(len <= MAX_PAGES, "Pages::empty_with_len: len > MAX_PAGES");
        Pages {
            buf: [[[b' '; DISPLAY_COLS]; DISPLAY_ROWS]; MAX_PAGES],
            len,
        }
    }

    /// Mutable access to a single row within a single page. Bounds-
    /// checked; panics on out-of-range indices (which would indicate
    /// a firmware bug since both come from compile-time constants).
    pub fn row_mut(&mut self, page: usize, row: usize) -> &mut [u8; DISPLAY_COLS] {
        assert!(page < self.len);
        assert!(row < DISPLAY_ROWS);
        &mut self.buf[page][row]
    }

    /// Mutable access to the full row array of one page. Used by
    /// renderers that need to mutate two rows of the same page
    /// simultaneously (via `split_at_mut`), which the row-at-a-time
    /// `row_mut` helper above can't express without tripping the
    /// borrow checker.
    pub fn page_mut(&mut self, page: usize) -> &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS] {
        assert!(page < self.len);
        &mut self.buf[page]
    }

    fn with_len(len: usize) -> Self {
        Self::empty_with_len(len)
    }
}

pub fn render_pages(tx: &Eip1559Tx) -> Pages {
    let mut pages = Pages::with_len(5);

    // Page 0: Confirm Tx? + chain
    write_line(&mut pages.buf[0][0], "Confirm Tx?");
    write_chain(&mut pages.buf[0][1], tx.chain_id);
    write_line(&mut pages.buf[0][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[0][3], "> next");

    // Page 1: To
    write_line(&mut pages.buf[1][0], "To:");
    if let Some(addr) = &tx.to {
        let (left, right) = pages.buf[1].split_at_mut(2);
        write_addr(&mut left[1], &mut right[0], addr);
    } else {
        write_line(&mut pages.buf[1][1], "(create)");
    }
    write_line(&mut pages.buf[1][3], "> next");

    // Page 2: Value
    write_line(&mut pages.buf[2][0], "Value:");
    write_eth(&mut pages.buf[2][1], &tx.value);
    write_gas(&mut pages.buf[2][2], tx.gas_limit);
    write_line(&mut pages.buf[2][3], "> next");

    // Page 3: Fees
    write_line(&mut pages.buf[3][0], "Max fee:");
    write_gwei(&mut pages.buf[3][1], &tx.max_fee_per_gas);
    {
        let mut row2 = [b' '; DISPLAY_COLS];
        let prefix = b"Tip: ";
        let mut pos = 0;
        for &b in prefix {
            if pos < DISPLAY_COLS {
                row2[pos] = b;
                pos += 1;
            }
        }
        let mut tmp = [0u8; 16];
        let n = tx.max_priority_fee_per_gas.format_decimal(9, 3, &mut tmp);
        for &b in &tmp[..n] {
            if pos < DISPLAY_COLS {
                row2[pos] = b;
                pos += 1;
            }
        }
        let suffix = b" gwei";
        for &b in suffix {
            if pos < DISPLAY_COLS {
                row2[pos] = b;
                pos += 1;
            }
        }
        pages.buf[3][2] = row2;
    }
    write_line(&mut pages.buf[3][3], "> next");

    // Page 4: Data + nonce + confirm/cancel
    {
        let mut row0 = [b' '; DISPLAY_COLS];
        let prefix = b"Data: ";
        let mut pos = 0;
        for &b in prefix {
            if pos < DISPLAY_COLS {
                row0[pos] = b;
                pos += 1;
            }
        }
        let mut tmp = [0u8; 16];
        let n = format_u64(tx.data_len as u64, &mut tmp);
        for &b in &tmp[..n] {
            if pos < DISPLAY_COLS {
                row0[pos] = b;
                pos += 1;
            }
        }
        let suffix = b" B";
        for &b in suffix {
            if pos < DISPLAY_COLS {
                row0[pos] = b;
                pos += 1;
            }
        }
        pages.buf[4][0] = row0;
    }
    {
        let mut row1 = [b' '; DISPLAY_COLS];
        let prefix = b"Nonce: ";
        let mut pos = 0;
        for &b in prefix {
            if pos < DISPLAY_COLS {
                row1[pos] = b;
                pos += 1;
            }
        }
        let mut tmp = [0u8; 16];
        let n = format_u64(tx.nonce, &mut tmp);
        for &b in &tmp[..n] {
            if pos < DISPLAY_COLS {
                row1[pos] = b;
                pos += 1;
            }
        }
        pages.buf[4][1] = row1;
    }
    write_line(&mut pages.buf[4][2], "L=Cancel");
    write_line(&mut pages.buf[4][3], "R=Confirm");

    pages
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_line(row: &mut [u8; DISPLAY_COLS], text: &str) {
    *row = [b' '; DISPLAY_COLS];
    let bytes = text.as_bytes();
    let n = core::cmp::min(bytes.len(), DISPLAY_COLS);
    row[..n].copy_from_slice(&bytes[..n]);
}

fn write_chain(row: &mut [u8; DISPLAY_COLS], chain_id: u64) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Chain: ";
    row[..prefix.len()].copy_from_slice(prefix);
    let mut tmp = [0u8; 16];
    let n = format_u64(chain_id, &mut tmp);
    let off = prefix.len();
    let copy = core::cmp::min(n, DISPLAY_COLS - off);
    row[off..off + copy].copy_from_slice(&tmp[..copy]);
}

fn chain_name(chain_id: u64) -> &'static str {
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

fn write_addr(row1: &mut [u8; DISPLAY_COLS], row2: &mut [u8; DISPLAY_COLS], addr: &[u8; 20]) {
    // Row 1: 0x + first 7 hex bytes (14 chars) = 16 chars total
    // Row 2: last 7 hex bytes + .. + last byte = also 16 chars
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    row1[0] = b'0';
    row1[1] = b'x';
    for i in 0..7 {
        row1[2 + i * 2] = hex_nibble(addr[i] >> 4);
        row1[2 + i * 2 + 1] = hex_nibble(addr[i] & 0x0f);
    }
    // Row 2: last 8 bytes
    for i in 0..8 {
        let b = addr[12 + i];
        row2[i * 2] = hex_nibble(b >> 4);
        row2[i * 2 + 1] = hex_nibble(b & 0x0f);
    }
}

fn hex_nibble(n: u8) -> u8 {
    match n & 0x0f {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

fn write_eth(row: &mut [u8; DISPLAY_COLS], value: &U256) {
    *row = [b' '; DISPLAY_COLS];
    let mut tmp = [0u8; 16];
    let n = value.format_decimal(18, 6, &mut tmp);
    let copy = core::cmp::min(n, DISPLAY_COLS - 4);
    row[..copy].copy_from_slice(&tmp[..copy]);
    if copy + 4 <= DISPLAY_COLS {
        row[copy] = b' ';
        row[copy + 1] = b'E';
        row[copy + 2] = b'T';
        row[copy + 3] = b'H';
    }
}

fn write_gwei(row: &mut [u8; DISPLAY_COLS], value: &U256) {
    *row = [b' '; DISPLAY_COLS];
    let mut tmp = [0u8; 16];
    let n = value.format_decimal(9, 3, &mut tmp);
    let copy = core::cmp::min(n, DISPLAY_COLS - 5);
    row[..copy].copy_from_slice(&tmp[..copy]);
    if copy + 5 <= DISPLAY_COLS {
        row[copy] = b' ';
        row[copy + 1] = b'g';
        row[copy + 2] = b'w';
        row[copy + 3] = b'e';
        row[copy + 4] = b'i';
    }
}

fn write_gas(row: &mut [u8; DISPLAY_COLS], gas: u64) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"(gas: ";
    let mut pos = 0;
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    let mut tmp = [0u8; 16];
    let n = format_u64(gas, &mut tmp);
    for &b in &tmp[..n] {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    if pos < DISPLAY_COLS {
        row[pos] = b')';
    }
}

pub fn format_u64(mut n: u64, out: &mut [u8]) -> usize {
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

// ============================================================================
// ERC20-aware renderers
// ============================================================================
//
// Each renderer below builds a sequence of `Page`s for one specific kind of
// transaction. The first page is always the trust-level header (e.g.
// "Send 100.50 USDC", "! BLIND SIGNING") so the user knows immediately
// what kind of confirmation they're looking at.
//
// Anti-spoof rule: every renderer that displays a token name from the DB
// MUST also include a sub-page with the raw `to` contract address in hex,
// so a malicious DB row pointing an attacker contract at "USDC" can still
// be caught by a careful user reading the address.

/// Decoded ERC20 method targeting a contract pinned in the metadata DB.
/// Trust level 2 — token identity comes from the trusted DB.
pub fn render_erc20_known_pages(
    tx: &Eip1559Tx,
    call: &Erc20Call,
    meta: &Erc20Metadata<'_>,
) -> Pages {
    let mut pages = Pages::with_len(7);

    // Page 0: header — verb + amount + symbol (truncated to 16 cols)
    write_erc20_header(&mut pages.buf[0][0], call, meta);
    // Row 1/2: full token name (DB-trusted)
    write_token_name(&mut pages.buf[0][1], meta);
    // Row 3
    write_line(&mut pages.buf[0][3], "> next");

    // Page 1: recipient (the address the token moves TO, from decoded calldata)
    let recipient_label: &str = match call {
        Erc20Call::Transfer { .. } => "Recipient:",
        Erc20Call::TransferFrom { .. } => "Recipient:",
        Erc20Call::Approve { .. } => "Spender:",
    };
    write_line(&mut pages.buf[1][0], recipient_label);
    let recipient: [u8; 20] = match call {
        Erc20Call::Transfer { to, .. } => *to,
        Erc20Call::TransferFrom { to, .. } => *to,
        Erc20Call::Approve { spender, .. } => *spender,
    };
    {
        let (left, right) = pages.buf[1].split_at_mut(2);
        write_addr(&mut left[1], &mut right[0], &recipient);
    }
    write_line(&mut pages.buf[1][3], "> next");

    // Page 2: amount in full precision (or "unlimited" for huge approve)
    write_line(&mut pages.buf[2][0], "Amount:");
    let amount: U256 = match call {
        Erc20Call::Transfer { amount, .. } => *amount,
        Erc20Call::TransferFrom { amount, .. } => *amount,
        Erc20Call::Approve { amount, .. } => *amount,
    };
    if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
        write_line(&mut pages.buf[2][1], "unlimited");
    } else {
        write_token_amount(&mut pages.buf[2][1], &amount, meta);
    }
    write_line(&mut pages.buf[2][3], "> next");

    // Page 3: raw contract address — the anti-spoof page
    write_line(&mut pages.buf[3][0], "Contract:");
    if let Some(addr) = &tx.to {
        let (left, right) = pages.buf[3].split_at_mut(2);
        write_addr(&mut left[1], &mut right[0], addr);
    }
    write_line(&mut pages.buf[3][3], "> next");

    // Page 4: chain + gas
    write_line(&mut pages.buf[4][0], "Chain:");
    write_chain(&mut pages.buf[4][1], tx.chain_id);
    write_line(&mut pages.buf[4][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[4][3], "> next");

    // Page 5: max fee + tip
    write_line(&mut pages.buf[5][0], "Max fee:");
    write_gwei(&mut pages.buf[5][1], &tx.max_fee_per_gas);
    write_tip_row(&mut pages.buf[5][2], &tx.max_priority_fee_per_gas);
    write_line(&mut pages.buf[5][3], "> next");

    // Page 6: nonce + buttons
    write_nonce_row(&mut pages.buf[6][0], tx.nonce);
    write_gas(&mut pages.buf[6][1], tx.gas_limit);
    write_line(&mut pages.buf[6][2], "L=Cancel");
    write_line(&mut pages.buf[6][3], "R=Confirm");

    pages
}

/// Decoded ERC20 method but the contract is NOT in the metadata DB.
/// Trust level 2.5 — structure trusted, token identity unknown.
pub fn render_erc20_unknown_pages(tx: &Eip1559Tx, call: &Erc20Call) -> Pages {
    let mut pages = Pages::with_len(7);

    // Page 0: warning header
    write_line(&mut pages.buf[0][0], "! Unknown token");
    let method = match call {
        Erc20Call::Transfer { .. } => "transfer",
        Erc20Call::TransferFrom { .. } => "transferFrom",
        Erc20Call::Approve { .. } => "approve",
    };
    write_line(&mut pages.buf[0][1], method);
    write_line(&mut pages.buf[0][2], "(decimals=?)");
    write_line(&mut pages.buf[0][3], "> next");

    // Page 1: contract address
    write_line(&mut pages.buf[1][0], "Contract:");
    if let Some(addr) = &tx.to {
        let (left, right) = pages.buf[1].split_at_mut(2);
        write_addr(&mut left[1], &mut right[0], addr);
    }
    write_line(&mut pages.buf[1][3], "> next");

    // Page 2: recipient
    let recipient_label: &str = match call {
        Erc20Call::Transfer { .. } | Erc20Call::TransferFrom { .. } => "Recipient:",
        Erc20Call::Approve { .. } => "Spender:",
    };
    write_line(&mut pages.buf[2][0], recipient_label);
    let recipient: [u8; 20] = match call {
        Erc20Call::Transfer { to, .. } => *to,
        Erc20Call::TransferFrom { to, .. } => *to,
        Erc20Call::Approve { spender, .. } => *spender,
    };
    {
        let (left, right) = pages.buf[2].split_at_mut(2);
        write_addr(&mut left[1], &mut right[0], &recipient);
    }
    write_line(&mut pages.buf[2][3], "> next");

    // Page 3: amount as raw uint256 (no decimals known)
    write_line(&mut pages.buf[3][0], "Amount (raw):");
    let amount: U256 = match call {
        Erc20Call::Transfer { amount, .. } => *amount,
        Erc20Call::TransferFrom { amount, .. } => *amount,
        Erc20Call::Approve { amount, .. } => *amount,
    };
    if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
        write_line(&mut pages.buf[3][1], "unlimited");
    } else {
        let mut tmp = [0u8; 16];
        let n = amount.format_decimal(0, 0, &mut tmp);
        let copy = core::cmp::min(n, DISPLAY_COLS);
        pages.buf[3][1][..copy].copy_from_slice(&tmp[..copy]);
    }
    write_line(&mut pages.buf[3][3], "> next");

    // Page 4: chain
    write_line(&mut pages.buf[4][0], "Chain:");
    write_chain(&mut pages.buf[4][1], tx.chain_id);
    write_line(&mut pages.buf[4][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[4][3], "> next");

    // Page 5: fees
    write_line(&mut pages.buf[5][0], "Max fee:");
    write_gwei(&mut pages.buf[5][1], &tx.max_fee_per_gas);
    write_tip_row(&mut pages.buf[5][2], &tx.max_priority_fee_per_gas);
    write_line(&mut pages.buf[5][3], "> next");

    // Page 6: nonce + buttons
    write_nonce_row(&mut pages.buf[6][0], tx.nonce);
    write_gas(&mut pages.buf[6][1], tx.gas_limit);
    write_line(&mut pages.buf[6][2], "L=Cancel");
    write_line(&mut pages.buf[6][3], "R=Confirm");

    pages
}

/// Non-empty calldata that doesn't match any known ERC20 selector.
/// Trust level 3 — Ledger-style BLIND SIGNING. The user is told
/// loudly that the wallet does not understand what this transaction
/// will do.
pub fn render_blind_sign_pages(tx: &Eip1559Tx, data: &[u8]) -> Pages {
    let mut pages = Pages::with_len(7);

    // Page 0: BLIND SIGNING banner
    write_line(&mut pages.buf[0][0], "! BLIND SIGN");
    write_line(&mut pages.buf[0][1], "Unknown call");
    write_line(&mut pages.buf[0][2], "Verify on dapp");
    write_line(&mut pages.buf[0][3], "> next");

    // Page 1: contract address
    write_line(&mut pages.buf[1][0], "To:");
    if let Some(addr) = &tx.to {
        let (left, right) = pages.buf[1].split_at_mut(2);
        write_addr(&mut left[1], &mut right[0], addr);
    }
    write_line(&mut pages.buf[1][3], "> next");

    // Page 2: value
    write_line(&mut pages.buf[2][0], "Value:");
    write_eth(&mut pages.buf[2][1], &tx.value);
    write_line(&mut pages.buf[2][3], "> next");

    // Page 3: selector + length
    write_selector_row(&mut pages.buf[3][0], data);
    write_data_len_row(&mut pages.buf[3][1], data.len());
    write_line(&mut pages.buf[3][3], "> next");

    // Page 4: chain
    write_line(&mut pages.buf[4][0], "Chain:");
    write_chain(&mut pages.buf[4][1], tx.chain_id);
    write_line(&mut pages.buf[4][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[4][3], "> next");

    // Page 5: fees
    write_line(&mut pages.buf[5][0], "Max fee:");
    write_gwei(&mut pages.buf[5][1], &tx.max_fee_per_gas);
    write_tip_row(&mut pages.buf[5][2], &tx.max_priority_fee_per_gas);
    write_line(&mut pages.buf[5][3], "> next");

    // Page 6: nonce + buttons
    write_nonce_row(&mut pages.buf[6][0], tx.nonce);
    write_gas(&mut pages.buf[6][1], tx.gas_limit);
    write_line(&mut pages.buf[6][2], "L=Cancel");
    write_line(&mut pages.buf[6][3], "R=Confirm");

    pages
}

/// `tx.to.is_none()` — a CREATE transaction. Treat with the same
/// caution as a blind contract call.
pub fn render_contract_creation_pages(tx: &Eip1559Tx, data: &[u8]) -> Pages {
    let mut pages = Pages::with_len(6);

    write_line(&mut pages.buf[0][0], "! CONTRACT");
    write_line(&mut pages.buf[0][1], "  CREATION");
    write_line(&mut pages.buf[0][2], "to: (none)");
    write_line(&mut pages.buf[0][3], "> next");

    write_line(&mut pages.buf[1][0], "Value:");
    write_eth(&mut pages.buf[1][1], &tx.value);
    write_line(&mut pages.buf[1][3], "> next");

    write_data_len_row(&mut pages.buf[2][0], data.len());
    write_line(&mut pages.buf[2][1], "(init bytecode)");
    write_line(&mut pages.buf[2][3], "> next");

    write_line(&mut pages.buf[3][0], "Chain:");
    write_chain(&mut pages.buf[3][1], tx.chain_id);
    write_line(&mut pages.buf[3][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[3][3], "> next");

    write_line(&mut pages.buf[4][0], "Max fee:");
    write_gwei(&mut pages.buf[4][1], &tx.max_fee_per_gas);
    write_tip_row(&mut pages.buf[4][2], &tx.max_priority_fee_per_gas);
    write_line(&mut pages.buf[4][3], "> next");

    write_nonce_row(&mut pages.buf[5][0], tx.nonce);
    write_gas(&mut pages.buf[5][1], tx.gas_limit);
    write_line(&mut pages.buf[5][2], "L=Cancel");
    write_line(&mut pages.buf[5][3], "R=Confirm");

    pages
}

// ----- shared row helpers used by the new renderers -----

fn write_erc20_header(row: &mut [u8; DISPLAY_COLS], call: &Erc20Call, meta: &Erc20Metadata<'_>) {
    *row = [b' '; DISPLAY_COLS];
    let verb: &[u8] = match call {
        Erc20Call::Transfer { .. } => b"Send ",
        Erc20Call::TransferFrom { .. } => b"TransferFrom ",
        Erc20Call::Approve { .. } => b"Approve ",
    };
    let mut pos = 0usize;
    for &b in verb {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    let symbol = meta.symbol;
    let copy = core::cmp::min(symbol.len(), DISPLAY_COLS - pos);
    row[pos..pos + copy].copy_from_slice(&symbol[..copy]);
}

fn write_token_name(row: &mut [u8; DISPLAY_COLS], meta: &Erc20Metadata<'_>) {
    *row = [b' '; DISPLAY_COLS];
    let copy = core::cmp::min(meta.name.len(), DISPLAY_COLS);
    row[..copy].copy_from_slice(&meta.name[..copy]);
}

fn write_token_amount(row: &mut [u8; DISPLAY_COLS], amount: &U256, meta: &Erc20Metadata<'_>) {
    *row = [b' '; DISPLAY_COLS];
    let mut tmp = [0u8; 32];
    // Show up to 6 fractional digits, fixed-width (no trim).
    let frac = if meta.decimals > 6 { 6 } else { meta.decimals as u32 };
    let n = amount.format_decimal_fixed(meta.decimals as u32, frac, &mut tmp);
    // Reserve space for " " + symbol (max 5 chars typical) at the end
    let symbol = meta.symbol;
    let want = n + 1 + symbol.len();
    let copy_amount = if want <= DISPLAY_COLS {
        n
    } else {
        // truncate amount to make room
        DISPLAY_COLS.saturating_sub(symbol.len() + 1)
    };
    row[..copy_amount].copy_from_slice(&tmp[..copy_amount]);
    let mut pos = copy_amount;
    if pos < DISPLAY_COLS {
        row[pos] = b' ';
        pos += 1;
    }
    let copy_sym = core::cmp::min(symbol.len(), DISPLAY_COLS - pos);
    row[pos..pos + copy_sym].copy_from_slice(&symbol[..copy_sym]);
}

fn write_tip_row(row: &mut [u8; DISPLAY_COLS], tip: &U256) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Tip: ";
    let mut pos = 0;
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    let mut tmp = [0u8; 16];
    let n = tip.format_decimal(9, 3, &mut tmp);
    for &b in &tmp[..n] {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    for &b in b" gwei" {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
}

fn write_nonce_row(row: &mut [u8; DISPLAY_COLS], nonce: u64) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Nonce: ";
    let mut pos = 0;
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    let mut tmp = [0u8; 16];
    let n = format_u64(nonce, &mut tmp);
    for &b in &tmp[..n] {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
}

fn write_selector_row(row: &mut [u8; DISPLAY_COLS], data: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Sel: ";
    let mut pos = 0;
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    if data.len() >= 4 {
        row[pos] = b'0';
        pos += 1;
        row[pos] = b'x';
        pos += 1;
        for i in 0..4 {
            row[pos] = hex_nibble(data[i] >> 4);
            pos += 1;
            row[pos] = hex_nibble(data[i] & 0x0f);
            pos += 1;
        }
    } else {
        for &b in b"(none)" {
            if pos < DISPLAY_COLS {
                row[pos] = b;
                pos += 1;
            }
        }
    }
}

fn write_data_len_row(row: &mut [u8; DISPLAY_COLS], len: usize) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Data: ";
    let mut pos = 0;
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    let mut tmp = [0u8; 16];
    let n = format_u64(len as u64, &mut tmp);
    for &b in &tmp[..n] {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    for &b in b" B" {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
}
