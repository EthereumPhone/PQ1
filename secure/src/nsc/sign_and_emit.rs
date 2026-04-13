//! Shared "decrypt entropy → derive signing key → hedged SLH-DSA sign
//! → write signature to NS" tail used by every signing command.
//!
//! Before this module existed every `cmd_*` signing path had its own
//! near-duplicate copy of the tail, and every new gateway command
//! meant pasting another one. Hoisting it into a single helper means:
//!
//!   * Adding a new signing flavour (new EIP-712 protocol, new
//!     clear-sign variant, …) is a five-line change in the new
//!     `cmd_*.rs`: compute a 32-byte message hash, validate the out
//!     pointer, hand both to [`decrypt_and_sign`], done.
//!   * Security-critical changes to the hedge / randomizer / zeroize
//!     pattern happen in one place, not three.
//!
//! The helper is only called once per command dispatch, so it owns
//! the SigningKey for the smallest possible window — the stack slot
//! is wiped by SLH-DSA's own `Drop` impl when the function returns.

use sphincs_tz_shared::{NscStatus, SIGNATURE_LEN, WRAPPER_HEADER_LEN};
use zeroize::Zeroize;

use super::state::SecureState;

/// End-to-end "produce a signature over `msg_hash` and drop it on
/// `sig_ptr`" helper.
///
/// The caller must have:
///
///   * verified that the device is unlocked (`state.pin_verified`);
///   * validated `sig_ptr` via
///     [`super::ptr_validate::validate_ns_write_ptr`] with a length of
///     [`SIGNATURE_LEN`];
///   * gotten through trusted-UI confirmation.
///
/// On success the secure-to-NS signature copy is complete and the
/// trusted UI shows `success_banner`.
///
/// SAFETY: `sig_ptr` must point at a pre-validated `SIGNATURE_LEN`-byte
/// NS-writable region.
pub(super) unsafe fn decrypt_and_sign(
    state: &SecureState,
    msg_hash: &[u8; 32],
    sig_ptr: *mut u8,
    success_banner: &str,
) -> u32 {
    // 1. Read the encrypted entropy blob from the SE.
    let mut entropy_blob = [0u8; 64];
    let entropy_blob_len = {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.read_entropy_blob(&mut entropy_blob) {
            Ok(len) => len,
            Err(_) => return NscStatus::InternalError as u32,
        }
    };

    // 2. Decrypt the entropy using the master secret unwrapped from
    //    PIN entry.
    let mut entropy = match crate::crypto::decrypt_entropy_blob(
        &entropy_blob[..entropy_blob_len],
        &state.master_secret,
    ) {
        Ok(e) => e,
        Err(_) => {
            entropy_blob.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };
    entropy_blob.zeroize();

    // 3. Re-derive the SLH-DSA signing key from the entropy by running
    //    the full BIP-39 chain. The SigningKey only exists on the
    //    stack for the duration of this function, and slh-dsa zeroizes
    //    it on drop.
    let signing_key = crate::crypto::derive_signing_key_from_entropy(&entropy);
    entropy.zeroize();

    // 4. Hedged sign: mix the chip-bound master secret into the per-sig
    //    randomizer so the same message produces different signatures
    //    across different unlocks.
    let mut rand_buf = [0u8; 16];
    derive_sign_randomizer(&state.master_secret, msg_hash, &mut rand_buf);

    use slh_dsa::Sha2_128f;
    use slh_dsa::SigningKey as Sk;
    let sig = match <Sk<Sha2_128f>>::try_sign_with_context(
        &signing_key,
        msg_hash,
        &[],
        Some(&rand_buf),
    ) {
        Ok(s) => s,
        Err(_) => {
            rand_buf.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };

    // 5. Write the 17,088-byte signature to NS memory, byte-at-a-time
    //    via volatile writes (so the compiler can't fold the copy into
    //    a memcpy that skips unmapped pages or similar shenanigans).
    let sig_bytes = sig.to_bytes();
    for i in 0..SIGNATURE_LEN {
        core::ptr::write_volatile(sig_ptr.add(i), sig_bytes[i]);
    }

    // 6. Wipe the per-sig randomizer. The SigningKey goes out of scope
    //    at the end of this function and slh-dsa zeroizes on drop.
    rand_buf.zeroize();

    crate::timeout::reset_activity();
    crate::ui::show_status(success_banner, "");

    // Brief pause so the user sees "Signed", then restore idle screen.
    for _ in 0..3_000_000u32 { cortex_m::asm::nop(); }
    crate::ui::show_status("PQSigner OS", "Ready");

    NscStatus::Ok as u32
}

/// v2 wrapper variant: writes a 73-byte PQSignatureWrapper header
/// (signer_type + key_index + ots_index + pk_seed_padded + pk_root_padded)
/// followed by the 17,088-byte raw SLH-DSA signature. Total output:
/// `WRAPPER_TOTAL_LEN` (17,161) bytes.
///
/// The caller must have validated `sig_ptr` for `WRAPPER_TOTAL_LEN` bytes.
///
/// SAFETY: `sig_ptr` must point at a pre-validated `WRAPPER_TOTAL_LEN`-byte
/// NS-writable region.
pub(super) unsafe fn decrypt_and_sign_wrapped(
    state: &SecureState,
    msg_hash: &[u8; 32],
    sig_ptr: *mut u8,
    signer_type: u8,
    key_index: u32,
    ots_index: u32,
    success_banner: &str,
) -> u32 {
    // 1. Read the encrypted entropy blob from the SE.
    let mut entropy_blob = [0u8; 64];
    let entropy_blob_len = {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.read_entropy_blob(&mut entropy_blob) {
            Ok(len) => len,
            Err(_) => return NscStatus::InternalError as u32,
        }
    };

    // 2. Decrypt the entropy.
    let mut entropy = match crate::crypto::decrypt_entropy_blob(
        &entropy_blob[..entropy_blob_len],
        &state.master_secret,
    ) {
        Ok(e) => e,
        Err(_) => {
            entropy_blob.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };
    entropy_blob.zeroize();

    // 3. Derive the correct signing key based on signer_type.
    //    For MAIN: uses the default derivation (legacy single-key path).
    //    For BOOTSTRAP: uses the bootstrap derivation path.
    //    Per-chain derivation for MAIN with key_index is handled by callers
    //    that pass the appropriate msg_hash (the userOpHash already encodes
    //    chain-specific data).
    let signing_key = if signer_type == sphincs_tz_shared::SIGNER_BOOTSTRAP {
        crate::crypto::derive_bootstrap_key_from_entropy(&entropy)
    } else {
        crate::crypto::derive_signing_key_from_entropy(&entropy)
    };
    entropy.zeroize();

    // 4. Write the 73-byte wrapper header via volatile writes.
    let mut hdr_pos: usize = 0;

    // signer_type (1 byte)
    core::ptr::write_volatile(sig_ptr.add(hdr_pos), signer_type);
    hdr_pos += 1;

    // key_index (4 bytes BE)
    let ki = key_index.to_be_bytes();
    for b in &ki {
        core::ptr::write_volatile(sig_ptr.add(hdr_pos), *b);
        hdr_pos += 1;
    }

    // ots_index (4 bytes BE)
    let oi = ots_index.to_be_bytes();
    for b in &oi {
        core::ptr::write_volatile(sig_ptr.add(hdr_pos), *b);
        hdr_pos += 1;
    }

    // pk_seed (32 bytes: raw 16 bytes right-padded to bytes32)
    {
        use signature::Keypair;
        let vk_bytes = signing_key.verifying_key().to_bytes();
        // VK = pk_seed[16] || pk_root[16]
        // Pad pk_seed to 32 bytes
        for i in 0..16 {
            core::ptr::write_volatile(sig_ptr.add(hdr_pos + i), vk_bytes[i]);
        }
        for i in 16..32 {
            core::ptr::write_volatile(sig_ptr.add(hdr_pos + i), 0u8);
        }
        hdr_pos += 32;

        // pk_root (32 bytes: raw 16 bytes right-padded to bytes32)
        for i in 0..16 {
            core::ptr::write_volatile(sig_ptr.add(hdr_pos + i), vk_bytes[16 + i]);
        }
        for i in 16..32 {
            core::ptr::write_volatile(sig_ptr.add(hdr_pos + i), 0u8);
        }
        hdr_pos += 32;
    }

    debug_assert_eq!(hdr_pos, WRAPPER_HEADER_LEN);

    // 5. Hedged sign
    let mut rand_buf = [0u8; 16];
    derive_sign_randomizer(&state.master_secret, msg_hash, &mut rand_buf);

    use slh_dsa::Sha2_128f;
    use slh_dsa::SigningKey as Sk;
    let sig = match <Sk<Sha2_128f>>::try_sign_with_context(
        &signing_key,
        msg_hash,
        &[],
        Some(&rand_buf),
    ) {
        Ok(s) => s,
        Err(_) => {
            rand_buf.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };

    // 6. Write the raw signature after the header.
    let sig_bytes = sig.to_bytes();
    let sig_offset = WRAPPER_HEADER_LEN;
    for i in 0..SIGNATURE_LEN {
        core::ptr::write_volatile(sig_ptr.add(sig_offset + i), sig_bytes[i]);
    }

    // 7. Cleanup
    rand_buf.zeroize();

    crate::timeout::reset_activity();
    crate::ui::show_status(success_banner, "");

    for _ in 0..3_000_000u32 { cortex_m::asm::nop(); }
    crate::ui::show_status("PQSigner OS", "Ready");

    NscStatus::Ok as u32
}

/// Derive a 16-byte randomizer for hedged SLH-DSA signing from the
/// master secret and the message hash. Keeping this private to the
/// `sign_and_emit` module means callers can't accidentally use it
/// with an unbounded pre-image.
fn derive_sign_randomizer(master: &[u8; 32], msg_hash: &[u8; 32], out: &mut [u8; 16]) {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"sphincs-sign-rand");
    h.update(master);
    h.update(msg_hash);
    let r = h.finalize();
    out.copy_from_slice(&r[..16]);
}
