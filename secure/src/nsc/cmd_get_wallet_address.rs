//! `CMD_GET_WALLET_ADDRESS` — compute CREATE2 wallet address from stored
//! bootstrap VK + factory parameters, display on trusted OLED.
//!
//! Wire format:
//!   [0..8)    chain_id         u64 BE
//!   [8..28)   factory_address  20 bytes
//!   [28..60)  init_code_hash   32 bytes
//!
//! On success, writes the 20-byte address to the NS output buffer and
//! displays chain_id + address on the OLED.

use sphincs_tz_shared::NscStatus;

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::GatewayArgs;
use crate::tx::hash::keccak256;
use crate::ui;
use crate::ui::confirm::{confirm, ConfirmResult, Page};

/// Payload: chain_id(8) + factory(20) + init_code_hash(32) = 60 bytes.
const PAYLOAD_LEN: usize = 60;
/// Output: 20-byte Ethereum address.
const ADDRESS_LEN: usize = 20;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    let payload_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    if total_len != PAYLOAD_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, PAYLOAD_LEN) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, ADDRESS_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // TOCTOU snapshot
    let mut buf = [0u8; PAYLOAD_LEN];
    for i in 0..PAYLOAD_LEN {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    let chain_id = u64::from_be_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    let factory = &buf[8..28];
    let init_code_hash = &buf[28..60];

    // Read bootstrap VK (pk_seed[16] || pk_root[16]) from stored r-mem
    let mut vk = [0u8; 32];
    {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        if se.read_bootstrap_vk(&mut vk).is_err() {
            return NscStatus::NotInitialized as u32;
        }
    }

    // Pad pk_seed and pk_root to bytes32 (right-padded with zeros)
    let mut pk_seed_padded = [0u8; 32];
    pk_seed_padded[..16].copy_from_slice(&vk[..16]);
    let mut pk_root_padded = [0u8; 32];
    pk_root_padded[..16].copy_from_slice(&vk[16..32]);

    // salt = keccak256(pk_seed_padded || pk_root_padded)
    let mut salt_input = [0u8; 64];
    salt_input[..32].copy_from_slice(&pk_seed_padded);
    salt_input[32..64].copy_from_slice(&pk_root_padded);
    let salt = keccak256(&salt_input);

    // address = keccak256(0xFF || factory || salt || init_code_hash)[12:]
    let mut create2_input = [0u8; 1 + 20 + 32 + 32]; // 85 bytes
    create2_input[0] = 0xFF;
    create2_input[1..21].copy_from_slice(factory);
    create2_input[21..53].copy_from_slice(&salt);
    create2_input[53..85].copy_from_slice(init_code_hash);
    let hash = keccak256(&create2_input);
    let address = &hash[12..32]; // rightmost 20 bytes

    // Write address to NS output
    for i in 0..ADDRESS_LEN {
        core::ptr::write_volatile(out_ptr.add(i), address[i]);
    }

    // Display address on OLED and wait for user acknowledgement
    let page = render_address_page(chain_id, address);
    let result = confirm(&[page]);
    match result {
        ConfirmResult::Confirmed => {}
        ConfirmResult::Cancelled => {
            return NscStatus::UserRejected as u32;
        }
        ConfirmResult::IdleWipe => {
            super::zeroize_sensitive_state();
            ui::show_status("Locked", "(idle wipe)");
            return NscStatus::IdleWipe as u32;
        }
    }

    ui::show_status("PQSigner OS", "Ready");
    NscStatus::Ok as u32
}

fn render_address_page(chain_id: u64, address: &[u8]) -> Page {
    use crate::ui::DISPLAY_COLS;

    let mut page = [[b' '; DISPLAY_COLS]; 4];

    // Line 0: "Verify address"
    let hdr = b"Verify address";
    page[0][..hdr.len()].copy_from_slice(hdr);

    // Line 1: "Chain: <decimal>"
    let prefix = b"Chain: ";
    page[1][..prefix.len()].copy_from_slice(prefix);
    let mut dec_buf = [0u8; 10];
    let dec = format_decimal_u64(chain_id, &mut dec_buf);
    let copy_len = core::cmp::min(dec.len(), DISPLAY_COLS - prefix.len());
    page[1][prefix.len()..prefix.len() + copy_len].copy_from_slice(&dec[..copy_len]);

    // Lines 2-3: "0x" + hex address (40 chars = 20 bytes × 2)
    page[2][0] = b'0';
    page[2][1] = b'x';
    // First 7 bytes (14 hex chars) on line 2 after "0x"
    for i in 0..7 {
        page[2][2 + i * 2] = HEX_CHARS[(address[i] >> 4) as usize];
        page[2][2 + i * 2 + 1] = HEX_CHARS[(address[i] & 0x0F) as usize];
    }
    // Remaining 13 bytes (26 hex chars) on line 3
    for i in 7..20 {
        let off = (i - 7) * 2;
        if off + 1 < DISPLAY_COLS {
            page[3][off] = HEX_CHARS[(address[i] >> 4) as usize];
            page[3][off + 1] = HEX_CHARS[(address[i] & 0x0F) as usize];
        }
    }

    page
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

fn format_decimal_u64(mut n: u64, buf: &mut [u8; 10]) -> &[u8] {
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
