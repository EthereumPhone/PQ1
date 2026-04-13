//! `CMD_SIGN_MESSAGE` — EIP-191 personal_sign.
//!
//! Computes `keccak256("\x19Ethereum Signed Message:\n" || len || msg)`,
//! displays the message on the trusted UI, and signs the digest with
//! SLH-DSA. Returns a PQSignatureWrapper (header + raw signature).
//!
//! Wire format (v2):
//!   [0..4)    key_index   u32 BE
//!   [4..8)    ots_index   u32 BE
//!   [8..16)   chain_id    u64 BE  (for display)
//!   [16..18)  msg_len     u16 BE
//!   [18..18+msg_len) message bytes

use sphincs_tz_shared::{NscStatus, WRAPPER_TOTAL_LEN, SIGNER_MAIN};

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::GatewayArgs;
use crate::ui;
use crate::ui::confirm::{confirm, ConfirmResult, Page};

/// Maximum message length (capped by stack/display constraints).
const MAX_MSG_LEN: usize = 1024;

/// Minimum payload: key_index(4) + ots_index(4) + chain_id(8) + msg_len(2) + 1 byte msg.
const MIN_PAYLOAD: usize = 4 + 4 + 8 + 2 + 1;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    ui::show_status("Message", "validating...");

    if !super::state::peek_state(|s| s.pin_verified) {
        ui::show_status("Message", "not unlocked");
        return NscStatus::NotInitialized as u32;
    }

    let payload_ptr = args.arg0 as *const u8;
    let sig_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    if total_len < MIN_PAYLOAD || total_len > 18 + MAX_MSG_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, total_len) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, WRAPPER_TOTAL_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // TOCTOU snapshot
    static mut SNAP: [u8; 18 + MAX_MSG_LEN] = [0u8; 18 + MAX_MSG_LEN];
    let buf = &mut SNAP[..];
    for i in 0..total_len {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // Parse header
    let key_index = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let ots_index = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let _chain_id = u64::from_be_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    let msg_len = u16::from_be_bytes([buf[16], buf[17]]) as usize;

    if msg_len == 0 || 18 + msg_len > total_len || msg_len > MAX_MSG_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    let msg = &buf[18..18 + msg_len];

    // Build display pages — show message excerpt
    let pages = render_message_pages(msg);

    let result = confirm(&pages);
    match result {
        ConfirmResult::Confirmed => {}
        ConfirmResult::Cancelled => {
            ui::show_status("Cancelled", "");
            return NscStatus::UserRejected as u32;
        }
        ConfirmResult::IdleWipe => {
            super::zeroize_sensitive_state();
            ui::show_status("Locked", "(idle wipe)");
            return NscStatus::IdleWipe as u32;
        }
    }

    // Compute EIP-191 hash: keccak256("\x19Ethereum Signed Message:\n" || decimal_len || msg)
    let msg_hash = eip191_hash(msg);

    ui::show_status("Signing msg", "");

    super::state::peek_state(|s| {
        super::sign_and_emit::decrypt_and_sign_wrapped(
            s,
            &msg_hash,
            sig_ptr,
            SIGNER_MAIN,
            key_index,
            ots_index,
            "Signed",
        )
    })
}

/// Compute `keccak256("\x19Ethereum Signed Message:\n" || ascii(msg.len()) || msg)`.
fn eip191_hash(msg: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(b"\x19Ethereum Signed Message:\n");
    // Write length as ASCII decimal
    let mut len_buf = [0u8; 10];
    let len_str = format_decimal(msg.len(), &mut len_buf);
    h.update(len_str);
    h.update(msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Format a usize as ASCII decimal into a fixed buffer. Returns the slice.
fn format_decimal(mut n: usize, buf: &mut [u8; 10]) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut pos = 10;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[pos..]
}

/// Render message content as confirmation pages.
/// First page shows "Sign message?" header; subsequent pages show the
/// message text (up to 48 chars per page on the 16×4 OLED).
fn render_message_pages(msg: &[u8]) -> [Page; 4] {
    use crate::ui::DISPLAY_COLS;

    let mut pages = [[[b' '; DISPLAY_COLS]; 4]; 4];

    // Page 0: header
    let hdr = b"Sign message?";
    pages[0][0][..hdr.len()].copy_from_slice(hdr);

    // Show message bytes across remaining page space (3 lines page 0, 4 lines pages 1-3)
    let mut msg_pos = 0;
    // Page 0 lines 1-3
    for row in 1..4 {
        let chunk = core::cmp::min(DISPLAY_COLS, msg.len().saturating_sub(msg_pos));
        if chunk == 0 {
            break;
        }
        for c in 0..chunk {
            let b = msg[msg_pos + c];
            // Replace non-printable ASCII with '.'
            pages[0][row][c] = if b >= 0x20 && b < 0x7F { b } else { b'.' };
        }
        msg_pos += chunk;
    }

    // Pages 1-3
    for page_idx in 1..4 {
        for row in 0..4 {
            let chunk = core::cmp::min(DISPLAY_COLS, msg.len().saturating_sub(msg_pos));
            if chunk == 0 {
                break;
            }
            for c in 0..chunk {
                let b = msg[msg_pos + c];
                pages[page_idx][row][c] = if b >= 0x20 && b < 0x7F { b } else { b'.' };
            }
            msg_pos += chunk;
        }
    }

    pages
}
