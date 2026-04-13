//! `CMD_CLEAR_SIGN` — ZK-verified clear-signing path for
//! calldata-bound protocols (Aave v3, CowSwap `setPreSignature`, …),
//! producing an ERC-4337 UserOp signature.
//!
//! The proof attests that a human-readable string is a faithful ABI
//! interpretation of the calldata the user is about to sign. The
//! secure world re-derives both Poseidon hashes and runs the Groth16
//! pairing check against a Merkle-verified 2-public-signal VK before
//! displaying the readable string on the trusted UI.
//!
//! After user confirmation, the handler reconstructs the canonical
//! `execute(target, value, data)` callData, computes the EntryPoint
//! v0.6 `userOpHash`, and signs that hash with SLH-DSA-SHA2-128f —
//! the same tail as [`super::cmd_sign_userop`], factored into
//! [`super::userop_tail::sign_userop_hash`].
//!
//! ## Payload wire format (v2 — includes AA header)
//!
//! ```text
//!   [0..384)                           proof (π.A || π.B || π.C)
//!   [384..548)                         calldata (164 bytes, right-zero-padded)
//!   [548..612)                         readable string (64 bytes, null-padded)
//!   [612..612+USEROP_HEADER_LEN)       AA header (has_bundle=0, sender, entry_point, …)
//!   [612+USEROP_HEADER_LEN..+4)        tx_len u32 LE
//!   [612+USEROP_HEADER_LEN+4..+tx_len) EIP-1559 envelope
//!   then                               [bundle_len u32 LE][vk bundle bytes]
//! ```

use sphincs_tz_shared::{
    NscStatus, MAX_TX_LEN, SIGNATURE_LEN, USEROP_HEADER_LEN, ZK_HEADER_LEN, ZK_MAX_CALLDATA,
    ZK_PROOF_LEN, ZK_STRING_LEN,
};

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::GatewayArgs;
use crate::ui;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    use crate::aa::userop::parse_header;
    use crate::tx::eip1559;
    use crate::ui::confirm::{confirm, ConfirmResult};
    use crate::zk::vk_bundle::{verify_vk_bundle, MAX_VK_BUNDLE_LEN};
    use crate::zk::{verify_clear_signing_proof, Groth16Proof, VerificationKey};

    if !super::state::peek_state(|s| s.pin_verified) {
        return NscStatus::NotInitialized as u32;
    }

    let payload_ptr = args.arg0 as *const u8;
    let sig_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    // 1. Size + pointer validation.
    if total_len < ZK_HEADER_LEN + 1
        || total_len > ZK_HEADER_LEN + MAX_TX_LEN + 4 + MAX_VK_BUNDLE_LEN
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
    let mut buf = [0u8; ZK_HEADER_LEN + MAX_TX_LEN + 4 + MAX_VK_BUNDLE_LEN];
    if total_len > buf.len() {
        return NscStatus::InvalidPointer as u32;
    }
    for i in 0..total_len {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // 3. Parse the ZK header: proof, calldata, readable.
    let mut off = 0usize;
    let proof_bytes: &[u8; 384] = buf[off..off + ZK_PROOF_LEN].try_into().unwrap();
    off += ZK_PROOF_LEN;
    let calldata: &[u8; ZK_MAX_CALLDATA] = buf[off..off + ZK_MAX_CALLDATA].try_into().unwrap();
    off += ZK_MAX_CALLDATA;
    let readable: &[u8; ZK_STRING_LEN] = buf[off..off + ZK_STRING_LEN].try_into().unwrap();
    off += ZK_STRING_LEN;

    // 4. Parse the AA header (same layout as CMD_SIGN_USEROP).
    let aa = match parse_header(&buf[off..off + USEROP_HEADER_LEN]) {
        Ok(a) => a,
        Err(_) => return NscStatus::InvalidPointer as u32,
    };
    off += USEROP_HEADER_LEN;

    // 5. Parse tx_len and locate the inner EIP-1559 envelope.
    let tx_len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    if tx_len == 0 || tx_len > MAX_TX_LEN || off + tx_len > total_len {
        return NscStatus::InvalidPointer as u32;
    }
    let tx_end = off + tx_len;
    let tx_bytes = &buf[off..tx_end];

    // 6. Parse the EIP-1559 envelope so we can cross-check everything.
    let parsed = match eip1559::parse(tx_bytes) {
        Ok(t) => t,
        Err(_) => {
            ui::show_status("Bad tx", "(parse fail)");
            return NscStatus::CryptoError as u32;
        }
    };

    // 6a. Cross-check: contract creation makes no sense for clear sign.
    let target = match parsed.tx.to {
        Some(a) => a,
        None => {
            ui::show_status("Bad clear-sign", "(no `to`)");
            return NscStatus::CryptoError as u32;
        }
    };

    // 6b. Cross-check: v1 protocols don't bind value; reject any tx
    //     that moves ETH.
    if !parsed.tx.value.is_zero() {
        ui::show_status("Bad clear-sign", "(value > 0)");
        return NscStatus::CryptoError as u32;
    }

    // 6c. Cross-check: the 164-byte calldata field in the payload must
    //     equal `parsed.data` right-zero-padded to 164 bytes.
    if parsed.data.len() > ZK_MAX_CALLDATA {
        ui::show_status("Bad clear-sign", "(calldata>164)");
        return NscStatus::CryptoError as u32;
    }
    if calldata[..parsed.data.len()] != *parsed.data {
        ui::show_status("Bad clear-sign", "(calldata!=tx)");
        return NscStatus::CryptoError as u32;
    }
    if calldata[parsed.data.len()..].iter().any(|&b| b != 0) {
        ui::show_status("Bad clear-sign", "(bad padding)");
        return NscStatus::CryptoError as u32;
    }

    // 6d. Cross-check: the AA chain id must match the inner tx chain id.
    if aa.chain_id != parsed.tx.chain_id {
        ui::show_status("Bad tx", "(chain mismatch)");
        return NscStatus::CryptoError as u32;
    }

    // 7. Parse the trailing VK bundle.
    if tx_end + 4 > total_len {
        ui::show_status("Unsupported", "protocol");
        return NscStatus::CryptoError as u32;
    }
    let blen_bytes: [u8; 4] = buf[tx_end..tx_end + 4].try_into().unwrap();
    let bundle_len = u32::from_le_bytes(blen_bytes) as usize;
    let bundle_start = tx_end + 4;
    let bundle_end = bundle_start + bundle_len;
    if bundle_len == 0 || bundle_len > MAX_VK_BUNDLE_LEN || bundle_end != total_len {
        ui::show_status("Unsupported", "protocol");
        return NscStatus::CryptoError as u32;
    }

    // 8. Merkle-verify the VK bundle against the embedded VK_DB_ROOT.
    let verified = match verify_vk_bundle(&buf[bundle_start..bundle_end]) {
        Some(v) => v,
        None => {
            ui::show_status("Unsupported", "protocol");
            return NscStatus::CryptoError as u32;
        }
    };

    // 8a. Cross-check: the bundle must describe THIS chain and THIS
    //     contract.
    if verified.chain_id != parsed.tx.chain_id || verified.contract != target {
        ui::show_status("Bad clear-sign", "(vk!=target)");
        return NscStatus::CryptoError as u32;
    }

    // 9. Deserialize the verified VK + proof for Groth16.
    let vk = match VerificationKey::from_bytes(verified.vk_as_2pub()) {
        Some(v) => v,
        None => {
            ui::show_status("Bad VK", "(deserialize)");
            return NscStatus::CryptoError as u32;
        }
    };

    let proof = match Groth16Proof::from_bytes(proof_bytes) {
        Some(p) => p,
        None => {
            ui::show_status("Bad proof", "(deserialize)");
            return NscStatus::CryptoError as u32;
        }
    };

    ui::show_status("Verifying", "ZK proof...");

    #[cfg(feature = "e2e-test")]
    secure_log!("[S][e2e] cmd_clear_sign dispatch = ZkClearSign");

    // 10. Verify the ZK clear signing proof against the local VK.
    if !verify_clear_signing_proof(calldata, readable, &proof, &vk) {
        ui::show_status("ZK INVALID", "proof failed");
        return NscStatus::CryptoError as u32;
    }

    // 11. Proof valid! Display ZK-verified readable string on trusted UI.
    let readable_len = readable.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);

    let mut confirm_pages: [[[u8; 16]; 4]; 3] = [[[b' '; 16]; 4]; 3];

    // Page 0: Header
    confirm_pages[0][0][..16].copy_from_slice(b"ZK Clear Sign   ");
    confirm_pages[0][1][..16].copy_from_slice(b"Proof verified! ");
    confirm_pages[0][2][..16].copy_from_slice(b"                ");
    confirm_pages[0][3][..16].copy_from_slice(b"  [scroll ->]   ");

    // Page 1: The ZK-verified action string (up to 4 lines x 16 chars)
    for (i, chunk) in readable[..readable_len].chunks(16).enumerate() {
        if i >= 4 {
            break;
        }
        for (j, &byte) in chunk.iter().enumerate() {
            if byte >= 0x20 && byte < 0x7F {
                confirm_pages[1][i][j] = byte;
            }
        }
    }

    // Page 2: Confirm prompt
    confirm_pages[2][0][..16].copy_from_slice(b"                ");
    confirm_pages[2][1][..16].copy_from_slice(b"  Long-press:   ");
    confirm_pages[2][2][..16].copy_from_slice(b"  L=Cancel      ");
    confirm_pages[2][3][..16].copy_from_slice(b"  R=Confirm     ");

    let confirm_result = confirm(&confirm_pages);
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

    // 12. Hand off to the shared UserOp signing tail: reconstruct
    //     execute() callData, compute userOpHash, sign with SLH-DSA.
    super::userop_tail::sign_userop_hash(&aa, &parsed.tx, parsed.data, sig_ptr, "Signed")
}
