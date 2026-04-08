//! `CMD_SIGN` — parse an EIP-1559 envelope, pick a trust level,
//! display on the trusted UI, wait for user confirmation, then sign
//! via [`super::sign_and_emit::decrypt_and_sign`].
//!
//! ## Payload wire format (post-Merkle-DB rework)
//!
//! ```text
//!   [0]              has_bundle u8        (0 or 1)
//!   [1..5]           tx_len     u32 LE
//!   [5..5+tx_len]    EIP-1559 envelope
//!   [5+tx_len..]     optional bundle (only if has_bundle == 1):
//!                    [bundle_len u32 LE][bundle bytes]
//! ```
//!
//! The optional bundle is the ERC20 metadata triple
//! `(canonical_bytes, merkle_proof, leaf_index)` produced by the
//! non-secure-side lookup. The secure world re-derives the leaf hash
//! and verifies the proof against `db_roots::ERC20_DB_ROOT`. If the
//! bundle is missing, malformed, or fails Merkle verification, the
//! secure world falls back to the unknown-token / blind-sign path —
//! it never aborts on a bad bundle (a hostile NS shouldn't be able
//! to DoS the wallet by sending garbage).

use sphincs_tz_shared::{NscStatus, MAX_TX_LEN, SIGNATURE_LEN};

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::sign_and_emit::decrypt_and_sign;
use super::{state, GatewayArgs};
use crate::ui;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    use crate::erc20::bundle::{verify_erc20_bundle, Erc20Metadata, MAX_ERC20_BUNDLE_LEN};
    use crate::erc20::{dispatch_tx, TxKind};
    use crate::tx::{
        display::{
            render_blind_sign_pages, render_contract_creation_pages, render_erc20_known_pages,
            render_erc20_unknown_pages, render_pages,
        },
        eip1559,
    };
    use crate::ui::confirm::{confirm, ConfirmResult};

    if !state::peek_state(|s| s.pin_verified) {
        return NscStatus::NotInitialized as u32;
    }

    let payload_ptr = args.arg0 as *const u8;
    let sig_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    // 1. Size + pointer validation.
    let header_min = 1 + 4;
    if total_len < header_min + 1
        || total_len > header_min + MAX_TX_LEN + 4 + MAX_ERC20_BUNDLE_LEN
    {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, total_len) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, SIGNATURE_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // 2. Copy entire payload into a secure-stack buffer (TOCTOU defense).
    //    Buffer is sized for the worst case (header + max tx + max bundle).
    let mut buf = [0u8; 1 + 4 + MAX_TX_LEN + 4 + MAX_ERC20_BUNDLE_LEN];
    if total_len > buf.len() {
        return NscStatus::InvalidPointer as u32;
    }
    for i in 0..total_len {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // 3. Parse the wrapper.
    let has_bundle = buf[0] == 1;
    let tx_len_bytes: [u8; 4] = buf[1..5].try_into().unwrap();
    let tx_len = u32::from_le_bytes(tx_len_bytes) as usize;
    if tx_len == 0 || tx_len > MAX_TX_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    let tx_end = 5 + tx_len;
    if tx_end > total_len {
        return NscStatus::InvalidPointer as u32;
    }
    let tx_bytes = &buf[5..tx_end];

    // 4. Parse the EIP-1559 envelope.
    let parsed = match eip1559::parse(tx_bytes) {
        Ok(t) => t,
        Err(_) => {
            ui::show_status("Bad tx", "(parse fail)");
            return NscStatus::CryptoError as u32;
        }
    };

    // 5. If a metadata bundle was attached, verify it Merkle-up to
    //    ERC20_DB_ROOT and cross-check that its (chain_id, contract)
    //    matches the parsed envelope. Anything wrong → fall through
    //    to "unknown token" instead of aborting.
    let verified_meta: Option<Erc20Metadata<'_>> = if has_bundle {
        if tx_end + 4 > total_len {
            None
        } else {
            let blen_bytes: [u8; 4] = buf[tx_end..tx_end + 4].try_into().unwrap();
            let bundle_len = u32::from_le_bytes(blen_bytes) as usize;
            let bundle_start = tx_end + 4;
            let bundle_end = bundle_start + bundle_len;
            if bundle_len == 0 || bundle_len > MAX_ERC20_BUNDLE_LEN || bundle_end > total_len {
                None
            } else {
                match verify_erc20_bundle(&buf[bundle_start..bundle_end]) {
                    Some(meta) => {
                        // Cross-check: the bundle is verified against
                        // the firmware DB but says nothing about which
                        // tx it belongs to. The (chain_id, contract)
                        // it carries MUST match the envelope being
                        // signed.
                        let to_match = match parsed.tx.to {
                            Some(addr) => addr == meta.contract,
                            None => false,
                        };
                        if meta.chain_id == parsed.tx.chain_id && to_match {
                            Some(meta)
                        } else {
                            None
                        }
                    }
                    None => None,
                }
            }
        }
    } else {
        None
    };

    // 6. Pick a trust level for the trusted UI display.
    let kind = dispatch_tx(&parsed, verified_meta);

    // Test-mode: log the routing decision so the e2e harness can
    // assert which trust level the dispatcher chose for each request.
    #[cfg(feature = "e2e-test")]
    {
        let kind_name: &str = match &kind {
            TxKind::ValueTransfer => "ValueTransfer",
            TxKind::Erc20Known(_, _) => "Erc20Known",
            TxKind::Erc20Unknown(_) => "Erc20Unknown",
            TxKind::ContractCall => "ContractCall",
            TxKind::ContractCreation => "ContractCreation",
        };
        cortex_m_semihosting::hprintln!("[S][e2e] cmd_sign dispatch = {}", kind_name);
    }

    let pages = match kind {
        TxKind::ValueTransfer => render_pages(&parsed.tx),
        TxKind::Erc20Known(call, meta) => render_erc20_known_pages(&parsed.tx, &call, &meta),
        TxKind::Erc20Unknown(call) => render_erc20_unknown_pages(&parsed.tx, &call),
        TxKind::ContractCall => render_blind_sign_pages(&parsed.tx, parsed.data),
        TxKind::ContractCreation => render_contract_creation_pages(&parsed.tx, parsed.data),
    };
    let confirm_result = confirm(pages.as_slice());
    match confirm_result {
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

    ui::show_status("Signing...", "");

    // 7. Hand off to the shared sign-and-emit tail.
    state::peek_state(|s| decrypt_and_sign(s, &parsed.tx.signing_hash, sig_ptr, "Signed"))
}
