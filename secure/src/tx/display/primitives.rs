//! Row-level formatting helpers shared by every renderer in this
//! directory. Everything here is deliberately `pub(super)` so the
//! sibling submodules can use them but external crates can't.
//!
//! None of these helpers allocate or panic on correct input — they're
//! designed to be called from a `#![no_std]`, no-`alloc` firmware
//! binary where a runaway format string would crash the secure world.

use crate::erc20::bundle::Erc20Metadata;
use crate::erc20::calldata::Erc20Call;
use crate::tx::eip1559::U256;
use crate::ui::DISPLAY_COLS;

// ---------------------------------------------------------------------------
// String / integer primitives
// ---------------------------------------------------------------------------

pub(super) fn write_line(row: &mut [u8; DISPLAY_COLS], text: &str) {
    *row = [b' '; DISPLAY_COLS];
    let bytes = text.as_bytes();
    let n = core::cmp::min(bytes.len(), DISPLAY_COLS);
    row[..n].copy_from_slice(&bytes[..n]);
}

pub(super) fn hex_nibble(n: u8) -> u8 {
    match n & 0x0f {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

/// Decimal-format a `u64` into `out`. Returns the number of bytes
/// written. Never panics: if `out.is_empty()` it returns 0.
pub(super) fn format_u64(mut n: u64, out: &mut [u8]) -> usize {
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

// ---------------------------------------------------------------------------
// Address + chain formatting
// ---------------------------------------------------------------------------

pub(super) fn write_chain(row: &mut [u8; DISPLAY_COLS], chain_id: u64) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Chain: ";
    row[..prefix.len()].copy_from_slice(prefix);
    let mut tmp = [0u8; 16];
    let n = format_u64(chain_id, &mut tmp);
    let off = prefix.len();
    let copy = core::cmp::min(n, DISPLAY_COLS - off);
    row[off..off + copy].copy_from_slice(&tmp[..copy]);
}

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
        _ => "",
    }
}

pub(super) fn write_addr(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    addr: &[u8; 20],
) {
    // Row 1: 0x + first 7 hex bytes (14 chars) = 16 chars total
    // Row 2: last 8 bytes (16 chars)
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

// ---------------------------------------------------------------------------
// ETH / gwei / gas formatting
// ---------------------------------------------------------------------------

pub(super) fn write_eth(row: &mut [u8; DISPLAY_COLS], value: &U256) {
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

pub(super) fn write_gwei(row: &mut [u8; DISPLAY_COLS], value: &U256) {
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

pub(super) fn write_gas(row: &mut [u8; DISPLAY_COLS], gas: u64) {
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

pub(super) fn write_tip_row(row: &mut [u8; DISPLAY_COLS], tip: &U256) {
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

pub(super) fn write_nonce_row(row: &mut [u8; DISPLAY_COLS], nonce: u64) {
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

pub(super) fn write_selector_row(row: &mut [u8; DISPLAY_COLS], data: &[u8]) {
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

pub(super) fn write_data_len_row(row: &mut [u8; DISPLAY_COLS], len: usize) {
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

// ---------------------------------------------------------------------------
// ERC20-specific row helpers
// ---------------------------------------------------------------------------

pub(super) fn write_erc20_header(
    row: &mut [u8; DISPLAY_COLS],
    call: &Erc20Call,
    meta: &Erc20Metadata<'_>,
) {
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

pub(super) fn write_token_name(row: &mut [u8; DISPLAY_COLS], meta: &Erc20Metadata<'_>) {
    *row = [b' '; DISPLAY_COLS];
    let copy = core::cmp::min(meta.name.len(), DISPLAY_COLS);
    row[..copy].copy_from_slice(&meta.name[..copy]);
}

pub(super) fn write_token_amount(
    row: &mut [u8; DISPLAY_COLS],
    amount: &U256,
    meta: &Erc20Metadata<'_>,
) {
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
