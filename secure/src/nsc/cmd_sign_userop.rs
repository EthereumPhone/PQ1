//! `CMD_SIGN_USEROP` — wrap a user-authorised inner EIP-1559
//! transaction as an ERC-4337 v0.6 `UserOperation`, display the inner
//! tx on the trusted UI, recompute the canonical `userOpHash` natively,
//! and sign that hash with SLH-DSA-SHA2-128f.
//!
//! ## Deployment modes
//!
//! The first byte of the payload is the **mode byte**:
//!
//!   * `0` — deployed, no ERC-20 bundle (legacy default)
//!   * `1` — deployed, with ERC-20 bundle (legacy default)
//!   * `2` — **not deployed**: firmware generates initCode automatically
//!   * `3` — not deployed + with ERC-20 bundle
//!
//! When mode ≥ 2, the firmware derives the bootstrap keypair internally,
//! produces the factory authorization signature, builds and hashes the
//! initCode, and includes it in the structured UserOp response alongside
//! the reconstructed callData and the main-signer PQSignatureWrapper.
//!
//! ## Why the secure world (and not NS) computes the userOpHash
//!
//! The single point of authorisation in this device is the trusted UI:
//! whatever bytes the user confirms are exactly the bytes that get
//! authorised on chain. For a normal EIP-1559 sign that's the keccak256
//! of the displayed envelope. For an ERC-4337 UserOp the EntryPoint
//! actually executes `userOp.callData`, which the user never sees as
//! such — they see "send 1 ETH to 0xabc". So the secure world has to
//! reconstruct the callData byte-for-byte from the displayed inner tx
//! and feed only that reconstruction into the userOpHash. A hostile
//! NS that swapped the AA wrapper would have the secure world produce a
//! signature over a hash that doesn't match what NS gave the bundler,
//! so verification on chain would fail loud — never silent fund theft.
//!
//! ## Wire format
//!
//! See `sphincs_tz_shared::CMD_SIGN_USEROP` for the canonical layout.

use sphincs_tz_shared::{
    NscStatus, MAX_TX_LEN, MAX_USEROP_RESPONSE_LEN, USEROP_HEADER_LEN, USEROP_PREFIX_LEN,
};

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::GatewayArgs;
use crate::ui;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    use crate::aa::userop::parse_header;
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

    ui::show_status("Sign", "validating...");

    if !super::state::peek_state(|s| s.pin_verified) {
        ui::show_status("Sign", "not unlocked");
        return NscStatus::NotInitialized as u32;
    }

    let payload_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let has_ots_trailer = args.arg2 & 0x8000_0000 != 0;
    let total_len = (args.arg2 & 0x7FFF_FFFF) as usize;
    //
    // NOTE: These are used only for the PQSignatureWrapper header and
    // the initCode path. The v1 legacy path ignores them.

    // 1. Pointer + size validation.
    // The v2 USB handler may append an 8-byte OTS trailer (key_index + ots_index).
    const OTS_TRAILER_LEN: usize = 8;
    if total_len < USEROP_PREFIX_LEN + 1
        || total_len > USEROP_PREFIX_LEN + MAX_TX_LEN + 4 + MAX_ERC20_BUNDLE_LEN + OTS_TRAILER_LEN
    {
        ui::show_status("Sign", "bad length");
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, total_len) {
        ui::show_status("Sign", "bad ptr");
        return NscStatus::InvalidPointer as u32;
    }

    // 2. TOCTOU snapshot
    const SNAP_LEN: usize = USEROP_PREFIX_LEN + MAX_TX_LEN + 4 + MAX_ERC20_BUNDLE_LEN + OTS_TRAILER_LEN;
    static mut SNAP_BUF: [u8; SNAP_LEN] = [0u8; SNAP_LEN];
    let buf = &mut SNAP_BUF[..];
    if total_len > buf.len() {
        return NscStatus::InvalidPointer as u32;
    }
    for i in 0..total_len {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    ui::show_status("Sign", "parsing...");

    // 3. Parse mode byte.
    let mode = buf[0];
    let has_bundle = mode == 1 || mode == 3;
    let needs_init_code = mode >= 2;

    // Validate output buffer size based on mode.
    let required_out = if needs_init_code {
        MAX_USEROP_RESPONSE_LEN
    } else {
        MAX_USEROP_RESPONSE_LEN // same max — actual write is smaller
    };
    if !validate_ns_write_ptr(args.arg1, required_out) {
        return NscStatus::InvalidPointer as u32;
    }

    // 4. Parse the fixed AA header.
    let mut aa = match parse_header(&buf[..USEROP_HEADER_LEN]) {
        Ok(a) => a,
        Err(_) => return NscStatus::InvalidPointer as u32,
    };

    // 5. Parse the inner-tx length and locate the envelope.
    let tx_len_off = USEROP_HEADER_LEN;
    let tx_len_bytes: [u8; 4] = match buf[tx_len_off..tx_len_off + 4].try_into() {
        Ok(v) => v,
        Err(_) => return NscStatus::InvalidPointer as u32,
    };
    let tx_len = u32::from_le_bytes(tx_len_bytes) as usize;
    if tx_len == 0 || tx_len > MAX_TX_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    let tx_start = USEROP_PREFIX_LEN;
    let tx_end = tx_start + tx_len;
    if tx_end > total_len {
        return NscStatus::InvalidPointer as u32;
    }
    let tx_bytes = &buf[tx_start..tx_end];

    // 6. Parse the inner EIP-1559 envelope.
    let parsed = match eip1559::parse(tx_bytes) {
        Ok(t) => t,
        Err(_) => {
            ui::show_status("Bad tx", "(parse fail)");
            return NscStatus::CryptoError as u32;
        }
    };

    if aa.chain_id != parsed.tx.chain_id {
        ui::show_status("Bad tx", "(chain mismatch)");
        return NscStatus::CryptoError as u32;
    }

    // 7. Optional ERC-20 metadata bundle.
    let verified_meta: Option<Erc20Metadata<'_>> = if has_bundle {
        if tx_end + 4 > total_len {
            None
        } else {
            let blen_bytes: [u8; 4] = match buf[tx_end..tx_end + 4].try_into() {
                Ok(v) => v,
                Err(_) => return NscStatus::InvalidPointer as u32,
            };
            let bundle_len = u32::from_le_bytes(blen_bytes) as usize;
            let bundle_start = tx_end + 4;
            let bundle_end = bundle_start + bundle_len;
            if bundle_len == 0 || bundle_len > MAX_ERC20_BUNDLE_LEN || bundle_end > total_len {
                None
            } else {
                match verify_erc20_bundle(&buf[bundle_start..bundle_end]) {
                    Some(meta) => {
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

    // 8. Trust-ladder dispatch + trusted UI confirmation.
    let kind = dispatch_tx(&parsed, verified_meta);

    #[cfg(all(feature = "e2e-test", feature = "debug-log"))]
    {
        let kind_name: &str = match &kind {
            TxKind::ValueTransfer => "ValueTransfer",
            TxKind::Erc20Known(_, _) => "Erc20Known",
            TxKind::Erc20Unknown(_) => "Erc20Unknown",
            TxKind::ContractCall => "ContractCall",
            TxKind::ContractCreation => "ContractCreation",
        };
        secure_log!("[S][e2e] cmd_sign_userop dispatch = {}", kind_name);
    }

    if matches!(kind, TxKind::ContractCreation) {
        ui::show_status("UserOp", "no CREATE");
        return NscStatus::CryptoError as u32;
    }

    let pages = match kind {
        TxKind::ValueTransfer => render_pages(&parsed.tx),
        TxKind::Erc20Known(call, meta) => render_erc20_known_pages(&parsed.tx, &call, &meta),
        TxKind::Erc20Unknown(call) => render_erc20_unknown_pages(&parsed.tx, &call),
        TxKind::ContractCall => render_blind_sign_pages(&parsed.tx, parsed.data),
        TxKind::ContractCreation => render_contract_creation_pages(&parsed.tx, parsed.data),
    };

    // For undeployed accounts, add a visual hint on the confirmation screen.
    #[cfg(not(feature = "e2e-test"))]
    if needs_init_code {
        ui::show_status("DEPLOY+Sign", "confirm...");
    }

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

    // 9. Extract key_index and ots_index from the TOCTOU-snapped buffer.
    // The v2 USB handler appends key_index(4 BE) + ots_index(4 BE) after
    // the wire payload and sets bit 31 of total_len to signal presence.
    // Legacy v1 callers (QEMU mailbox) don't set the flag → default to 0.
    let (key_index, ots_index, payload_len) = if has_ots_trailer && total_len >= 8 {
        let pl = total_len - 8;
        let ki = u32::from_be_bytes([buf[pl], buf[pl + 1], buf[pl + 2], buf[pl + 3]]);
        let oi = u32::from_be_bytes([buf[pl + 4], buf[pl + 5], buf[pl + 6], buf[pl + 7]]);
        (ki, oi, pl)
    } else {
        (0u32, 0u32, total_len)
    };
    let _ = payload_len; // payload parsing above used total_len before the trailer was stripped

    // 10. OTS monotonicity: only enforced for v2 callers that supply
    //     explicit key_index/ots_index via the trailer. Legacy v1 callers
    //     default to (0, 0) and don't support OTS tracking.
    if has_ots_trailer {
        let ots_ok = super::state::peek_state(|s| {
            if !s.has_signed {
                return true;
            }
            if s.last_chain_id == aa.chain_id && s.last_key_index == key_index {
                ots_index > s.last_ots_index
            } else {
                true // different chain or key epoch: companion is authoritative
            }
        });
        if !ots_ok {
            ui::show_status("OTS reuse", "rejected");
            return NscStatus::CryptoError as u32;
        }
    }

    // 11. Hand off to the signing tail.
    let mut result_len: usize = 0;
    let status = super::userop_tail::sign_userop_full(
        &mut aa,
        &parsed.tx,
        parsed.data,
        out_ptr,
        &mut result_len as *mut usize,
        needs_init_code,
        key_index,
        ots_index,
        "Signed",
    );

    // Record OTS state on success so the next signing request for the
    // same (chain_id, key_index) must present a strictly greater index.
    // Only tracked for v2 callers with explicit OTS indices.
    if status == NscStatus::Ok as u32 && has_ots_trailer {
        super::state::with_state(|s| {
            s.last_chain_id = aa.chain_id;
            s.last_key_index = key_index;
            s.last_ots_index = ots_index;
            s.has_signed = true;
        });
    }

    status
}
