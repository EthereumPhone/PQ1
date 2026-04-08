//! `CMD_CLEAR_SIGN_MSG` — EIP-712 typed-data clear signing.
//!
//! Unlike [`super::cmd_clear_sign`], this path does not receive an
//! EIP-1559 envelope at all — the "transaction" the user signs is an
//! EIP-712 typed-data digest computed natively in the secure world
//! from a 204-byte canonical buffer AFTER a Groth16 proof has bound
//! those bytes to the readable string the user actually confirms.
//!
//! The VK bundle's `contract` field acts as a protocol sentinel
//! (distinct from the real EIP-712 `verifyingContract`). The sentinel
//! selects a dispatch entry in [`crate::tx::eip712::PROTOCOLS`] —
//! adding a new EIP-712 protocol is a two-file change (new submodule
//! under `secure/src/tx/eip712/`, new VK row in `secure/data/vks.json`)
//! with **no edits to this command handler**.
//!
//! ## Payload wire format
//!
//! ```text
//!   [0..384)             proof (π.A || π.B || π.C)
//!   [384..548)           canonical bytes (164 B, packed GPv2Order etc.)
//!   [548..612)           readable string (64 B, null-padded)
//!   [612..616)           bundle_len u32 LE
//!   [616..616+blen)      VK bundle bytes
//! ```

use sphincs_tz_shared::{
    EIP712_CANONICAL_LEN, EIP712_HEADER_LEN, EIP712_PROOF_LEN, EIP712_STRING_LEN, NscStatus,
    SIGNATURE_LEN,
};

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::sign_and_emit::decrypt_and_sign;
use super::{state, GatewayArgs};
use crate::ui;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    use crate::tx::eip712;
    use crate::ui::confirm::{confirm, ConfirmResult};
    use crate::zk::groth16::{Groth16Proof, VerificationKeyV3};
    use crate::zk::poseidon::poseidon_bytes;
    use crate::zk::vk_bundle::{verify_vk_bundle, MAX_VK_BUNDLE_LEN};

    if !state::peek_state(|s| s.pin_verified) {
        return NscStatus::NotInitialized as u32;
    }

    let payload_ptr = args.arg0 as *const u8;
    let sig_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    // 1. Size + pointer validation.
    if total_len < EIP712_HEADER_LEN + 4 + 1
        || total_len > EIP712_HEADER_LEN + 4 + MAX_VK_BUNDLE_LEN
    {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, total_len) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, SIGNATURE_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // 2. Copy entire payload into a secure-stack TOCTOU buffer.
    let mut buf = [0u8; EIP712_HEADER_LEN + 4 + MAX_VK_BUNDLE_LEN];
    if total_len > buf.len() {
        return NscStatus::InvalidPointer as u32;
    }
    for i in 0..total_len {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // 3. Parse the fixed header.
    let mut off = 0usize;
    let proof_bytes: &[u8; EIP712_PROOF_LEN] =
        buf[off..off + EIP712_PROOF_LEN].try_into().unwrap();
    off += EIP712_PROOF_LEN;
    let canonical: &[u8; EIP712_CANONICAL_LEN] =
        buf[off..off + EIP712_CANONICAL_LEN].try_into().unwrap();
    off += EIP712_CANONICAL_LEN;
    let readable: &[u8; EIP712_STRING_LEN] =
        buf[off..off + EIP712_STRING_LEN].try_into().unwrap();
    off += EIP712_STRING_LEN;

    // 4. Parse the trailing VK bundle.
    if off + 4 > total_len {
        ui::show_status("Unsupported", "protocol");
        return NscStatus::CryptoError as u32;
    }
    let blen_bytes: [u8; 4] = buf[off..off + 4].try_into().unwrap();
    let bundle_len = u32::from_le_bytes(blen_bytes) as usize;
    off += 4;
    let bundle_start = off;
    let bundle_end = bundle_start + bundle_len;
    if bundle_len == 0 || bundle_len > MAX_VK_BUNDLE_LEN || bundle_end != total_len {
        ui::show_status("Unsupported", "protocol");
        return NscStatus::CryptoError as u32;
    }

    // 5. Merkle-verify the VK bundle against the embedded VK_DB_ROOT.
    let verified = match verify_vk_bundle(&buf[bundle_start..bundle_end]) {
        Some(v) => v,
        None => {
            ui::show_status("Unsupported", "protocol");
            return NscStatus::CryptoError as u32;
        }
    };

    // 5a. Cross-check: the bundle's contract field MUST match a
    //     known EIP-712 protocol sentinel — NOT a regular
    //     calldata-bound entry from the same DB (e.g. the M3
    //     setPreSignature VK). Without this check NS could
    //     substitute any in-DB VK and trick the firmware into
    //     running an EIP-712 keccak digest over a buffer the proof
    //     was built for a completely different protocol.
    if !eip712::is_known_sentinel(&verified.contract) {
        ui::show_status("Bad clear-sign", "(unknown proto)");
        return NscStatus::CryptoError as u32;
    }

    // 6. Deserialize the verified VK + proof for Groth16.
    //
    // CowSwap EIP-712 v3 uses a 3-public-signal circuit (H_tx, H_str,
    // H_root) with a 4-IC VK = 1056 bytes, so we unpack the full
    // 1056-byte pool slot via `vk_as_3pub`.
    let vk = match VerificationKeyV3::from_bytes(verified.vk_as_3pub()) {
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
    cortex_m_semihosting::hprintln!("[S][e2e] cmd_clear_sign_msg dispatch = ZkClearSignMsg");

    // 7. Verify the Groth16 proof against (Poseidon(canonical),
    //    Poseidon(readable), ERC20_POSEIDON_ROOT). The proof attests
    //    that `readable` is a cryptographically faithful interpretation
    //    of `canonical` AND that the sell + buy tokens referenced in
    //    `canonical` live in the device's Poseidon-rooted ERC20
    //    registry.
    let h_order = poseidon_bytes(canonical, EIP712_CANONICAL_LEN);
    let h_str = poseidon_bytes(readable, EIP712_STRING_LEN);
    let h_root = {
        use bls12_381::Scalar;
        Option::from(Scalar::from_bytes(&crate::db_roots::ERC20_POSEIDON_ROOT))
            .expect("ERC20_POSEIDON_ROOT is a valid BLS12-381 scalar (dbgen invariant)")
    };
    if !crate::zk::groth16::verify_with_public_signals_3pub(
        &proof, &vk, h_order, h_str, h_root,
    ) {
        ui::show_status("ZK INVALID", "proof failed");
        return NscStatus::CryptoError as u32;
    }

    // 8. Native EIP-712 digest computation. The proof has bound
    //    `canonical` ↔ `readable`; here we re-derive the actual
    //    EIP-712 message digest from the SAME bytes the proof
    //    verified, so what we sign matches what the user is about to
    //    confirm on the trusted UI. Dispatch to the protocol
    //    submodule keyed by the sentinel address from the verified
    //    VK bundle.
    let digest = match eip712::dispatch_for_sentinel(
        &verified.contract,
        canonical,
        verified.chain_id,
    ) {
        Ok(d) => d,
        Err(_) => {
            ui::show_status("Bad msg", "(decode)");
            return NscStatus::CryptoError as u32;
        }
    };

    // 9. Render the confirmation flow and ask the user. For now the
    //    only protocol here is CowSwap EIP-712 GPv2Order; when a
    //    second EIP-712 protocol lands this can branch on the
    //    sentinel the same way the digest dispatch above does.
    let pages = eip712::cowswap_display::render_cowswap_pages(canonical, readable);
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

    // 10. Hand off to the shared sign-and-emit tail.
    state::peek_state(|s| decrypt_and_sign(s, &digest, sig_ptr, "ZK Msg Signed"))
}
