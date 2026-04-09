//! `CMD_SIGN_USEROP` — wrap a user-authorised inner EIP-1559
//! transaction as an ERC-4337 v0.6 `UserOperation`, display the inner
//! tx on the trusted UI, recompute the canonical `userOpHash` natively,
//! and sign that hash with SLH-DSA-SHA2-128f.
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
//! The handler validates pointers, snapshots the entire payload into a
//! secure-stack buffer (TOCTOU defence), parses the AA header, parses
//! the inner EIP-1559 envelope, optionally verifies an attached ERC-20
//! metadata bundle, dispatches the inner tx through the same trust
//! ladder used by `cmd_sign`, displays the inner tx on the trusted UI,
//! reconstructs the canonical `execute(...)` callData, computes the
//! userOpHash natively, then hands that 32-byte digest to the shared
//! `decrypt_and_sign` tail.

use sphincs_tz_shared::{
    NscStatus, MAX_TX_LEN, SIGNATURE_LEN, USEROP_HEADER_LEN, USEROP_PREFIX_LEN,
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

    if !super::state::peek_state(|s| s.pin_verified) {
        return NscStatus::NotInitialized as u32;
    }

    let payload_ptr = args.arg0 as *const u8;
    let sig_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    // 1. Pointer + size validation. The AA prefix (header + tx_len) is
    //    fixed-size; reject anything that can't even fit it.
    if total_len < USEROP_PREFIX_LEN + 1
        || total_len > USEROP_PREFIX_LEN + MAX_TX_LEN + 4 + MAX_ERC20_BUNDLE_LEN
    {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, total_len) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, SIGNATURE_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // 2. TOCTOU snapshot — copy the entire NS payload into a secure
    //    stack buffer before parsing anything.
    let mut buf = [0u8; USEROP_PREFIX_LEN + MAX_TX_LEN + 4 + MAX_ERC20_BUNDLE_LEN];
    if total_len > buf.len() {
        return NscStatus::InvalidPointer as u32;
    }
    for i in 0..total_len {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    let has_bundle = buf[0] == 1;

    // 3. Parse the fixed AA header.
    let aa = match parse_header(&buf[..USEROP_HEADER_LEN]) {
        Ok(a) => a,
        Err(_) => return NscStatus::InvalidPointer as u32,
    };

    // 4. Parse the inner-tx length and locate the envelope.
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

    // 5. Parse the inner EIP-1559 envelope.
    let parsed = match eip1559::parse(tx_bytes) {
        Ok(t) => t,
        Err(_) => {
            ui::show_status("Bad tx", "(parse fail)");
            return NscStatus::CryptoError as u32;
        }
    };

    // Cross-check: the AA chain id and the inner-tx chain id MUST match.
    // Otherwise the user could be fooled into authorising a tx for chain
    // X via the trusted UI while signing a userOpHash for chain Y.
    if aa.chain_id != parsed.tx.chain_id {
        ui::show_status("Bad tx", "(chain mismatch)");
        return NscStatus::CryptoError as u32;
    }

    // 6. Optional ERC-20 metadata bundle (same shape as cmd_sign).
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

    // 7. Dispatch through the same trust ladder as the plain `cmd_sign`
    //    path so the user sees the same trusted-UI flow regardless of
    //    whether their wallet is wrapping the tx as an ERC-4337 UserOp
    //    or sending it directly.
    let kind = dispatch_tx(&parsed, verified_meta);

    #[cfg(feature = "e2e-test")]
    {
        let kind_name: &str = match &kind {
            TxKind::ValueTransfer => "ValueTransfer",
            TxKind::Erc20Known(_, _) => "Erc20Known",
            TxKind::Erc20Unknown(_) => "Erc20Unknown",
            TxKind::ContractCall => "ContractCall",
            TxKind::ContractCreation => "ContractCreation",
        };
        cortex_m_semihosting::hprintln!("[S][e2e] cmd_sign_userop dispatch = {}", kind_name);
    }

    // ContractCreation cannot be wrapped as `execute(...)`. Reject early
    // so we don't try to sign garbage.
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

    // 8. Hand off to the shared UserOp signing tail: reconstruct
    //    execute() callData, compute userOpHash, sign with SLH-DSA.
    super::userop_tail::sign_userop_hash(&aa, &parsed.tx, parsed.data, sig_ptr, "Signed")
}
