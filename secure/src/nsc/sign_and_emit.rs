//! Shared "decrypt entropy → derive signing key → hedged SPHINCS+C7 sign
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
//! is wiped by sphincs_c7's `ZeroizeOnDrop` when the function returns.

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

    // 3. Read the cached default VK from r-mem to extract pk_root.
    //    This avoids the expensive hypertree rebuild (~10-15s) by
    //    using SigningKey::from_parts with the cached pk_root.
    let mut vk_buf = [0u8; 32];
    {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        if se.read_vk(&mut vk_buf).is_err() {
            entropy.zeroize();
            return NscStatus::InternalError as u32;
        }
    }
    let mut cached_pk_root = [0u8; 16];
    cached_pk_root.copy_from_slice(&vk_buf[16..32]);

    // 4. Re-derive the SPHINCS+C7 signing key from the entropy +
    //    cached pk_root. BIP-39 chain (PBKDF2 + 2x Keccak) is fast;
    //    from_parts skips the hypertree rebuild.
    let signing_key = crate::crypto::derive_signing_key_from_entropy_fast(
        &entropy,
        &cached_pk_root,
    );
    entropy.zeroize();

    // 5. Hedged sign: mix the chip-bound master secret into the per-sig
    //    randomizer so the same message produces different signatures
    //    across different unlocks.
    let mut rand_buf = [0u8; 16];
    derive_sign_randomizer(&state.master_secret, msg_hash, &mut rand_buf);

    let sig = signing_key.sign_with_progress(msg_hash, Some(&rand_buf), signing_progress);

    // 6. Write signature to NS memory, byte-at-a-time
    //    via volatile writes (so the compiler can't fold the copy into
    //    a memcpy that skips unmapped pages or similar shenanigans).
    for i in 0..SIGNATURE_LEN {
        core::ptr::write_volatile(sig_ptr.add(i), sig[i]);
    }

    // 7. Wipe the per-sig randomizer. The SigningKey goes out of scope
    //    at the end of this function and sphincs_c7 zeroizes on drop.
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
/// followed by the 3,704-byte raw SPHINCS+C7 signature. Total output:
/// `WRAPPER_TOTAL_LEN` (3,777) bytes.
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
    chain_id: u64,
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
    //    BOOTSTRAP: use cached VK from r-mem for fast path (from_parts).
    //    MAIN: per-chain, per-epoch key — no cached VK, full keygen required.
    let signing_key = if signer_type == sphincs_tz_shared::SIGNER_BOOTSTRAP {
        // Bootstrap VK is cached in r-mem — use fast path.
        let mut bvk_buf = [0u8; 32];
        {
            use crate::secure_element::WalletStore;
            let se = &mut *core::ptr::addr_of_mut!(crate::SE);
            if se.read_bootstrap_vk(&mut bvk_buf).is_err() {
                entropy.zeroize();
                return NscStatus::InternalError as u32;
            }
        }
        let mut cached_pk_root = [0u8; 16];
        cached_pk_root.copy_from_slice(&bvk_buf[16..32]);
        crate::crypto::derive_bootstrap_key_from_entropy_fast(&entropy, &cached_pk_root)
    } else {
        crate::crypto::derive_main_key_from_entropy(&entropy, chain_id, key_index)
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

    let sig = signing_key.sign_with_progress(msg_hash, Some(&rand_buf), signing_progress);

    // 6. Write the raw signature after the header.
    let sig_offset = WRAPPER_HEADER_LEN;
    for i in 0..SIGNATURE_LEN {
        core::ptr::write_volatile(sig_ptr.add(sig_offset + i), sig[i]);
    }

    // 7. Cleanup
    rand_buf.zeroize();

    crate::timeout::reset_activity();
    crate::ui::show_status(success_banner, "");

    for _ in 0..3_000_000u32 { cortex_m::asm::nop(); }
    crate::ui::show_status("PQSigner OS", "Ready");

    NscStatus::Ok as u32
}

/// Derive a 16-byte randomizer for hedged SPHINCS+C11 signing from the
/// master secret and the message hash. Keeping this private to the
/// `sign_and_emit` module means callers can't accidentally use it
/// with an unbounded pre-image.
fn derive_sign_randomizer(master: &[u8; 32], msg_hash: &[u8; 32], out: &mut [u8; 16]) {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(b"sphincsc7-sign-rand");
    h.update(master);
    h.update(msg_hash);
    let r = h.finalize();
    out.copy_from_slice(&r[..16]);
}

/// Progress callback for the SPHINCS+C11 signing operation.
/// Updates the OLED/console with a progress bar.
fn signing_progress(percent: u8) {
    crate::ui::show_progress("Signing", percent);
}

/// JARDIN FORS+C compact signing variant.
///
/// Ensures the JARDIN slot is initialized for the given (chain_id, slot_index),
/// signs the message, and writes the JARDIN wrapper header + variable-length
/// signature to NS memory.
///
/// SAFETY: `sig_ptr` must point at a pre-validated region of at least
/// `JARDIN_WRAPPER_MAX_LEN` bytes.
pub(super) unsafe fn decrypt_and_sign_jardin(
    state: &mut super::state::SecureState,
    msg_hash: &[u8; 32],
    sig_ptr: *mut u8,
    chain_id: u64,
    slot_index: u32,
    success_banner: &str,
) -> (u32, usize) {
    use sphincs_tz_shared::{
        NscStatus, JARDIN_WRAPPER_HEADER_LEN, SIGNER_JARDIN,
    };

    // 1. Ensure JARDIN master entropy is derived for this session
    if !state.jardin_master_derived {
        // Read encrypted entropy, decrypt, derive JARDIN master
        let mut entropy_blob = [0u8; 64];
        let entropy_blob_len = {
            use crate::secure_element::WalletStore;
            let se = &mut *core::ptr::addr_of_mut!(crate::SE);
            match se.read_entropy_blob(&mut entropy_blob) {
                Ok(len) => len,
                Err(_) => return (NscStatus::InternalError as u32, 0),
            }
        };
        let mut entropy = match crate::crypto::decrypt_entropy_blob(
            &entropy_blob[..entropy_blob_len],
            &state.master_secret,
        ) {
            Ok(e) => e,
            Err(_) => {
                entropy_blob.zeroize();
                return (NscStatus::CryptoError as u32, 0);
            }
        };
        entropy_blob.zeroize();

        state.jardin_master_entropy =
            crate::crypto::jardin_master_entropy_from_entropy(&entropy);
        entropy.zeroize();
        state.jardin_master_derived = true;
    }

    // 2. Initialize or switch JARDIN slot if needed
    let need_init = !state.jardin_slot_active
        || state.jardin_chain_id != chain_id
        || state.jardin_slot_index != slot_index;

    if need_init {
        crate::ui::show_status("JARDIN keygen", "Please wait...");
        let slot_entropy = jardin_fosc::hash::jardin_slot_entropy(
            &state.jardin_master_entropy,
            slot_index,
        );
        let slot = jardin_fosc::JardinSlot::keygen(slot_entropy);
        // SAFETY: single-threaded access
        unsafe {
            *core::ptr::addr_of_mut!(super::state::JARDIN_SLOT) = Some(slot);
        }
        state.jardin_chain_id = chain_id;
        state.jardin_slot_index = slot_index;
        state.jardin_slot_active = true;
    }

    // 3. Get mutable reference to the slot
    let slot = unsafe {
        match &mut *core::ptr::addr_of_mut!(super::state::JARDIN_SLOT) {
            Some(s) => s,
            None => return (NscStatus::InternalError as u32, 0),
        }
    };

    // 4. Check exhaustion
    if slot.is_exhausted() {
        return (NscStatus::SlotExhausted as u32, 0);
    }

    // 5. Sign
    crate::ui::show_status("Signing", "JARDIN FORS+C");
    let sig = match slot.sign(msg_hash) {
        Ok(s) => s,
        Err(_) => return (NscStatus::CryptoError as u32, 0),
    };

    // 6. Compute slot key: H(r)
    let r = jardin_fosc::hash::jardin_slot_r(
        &state.jardin_master_entropy,
        slot_index,
    );
    let slot_key = jardin_fosc::hash::keccak256(&r);

    // 7. Write JARDIN wrapper header (97 bytes) via volatile writes
    let mut hdr_pos: usize = 0;

    // signer_type (1 byte)
    core::ptr::write_volatile(sig_ptr.add(hdr_pos), SIGNER_JARDIN);
    hdr_pos += 1;

    // slot_key (32 bytes)
    for i in 0..32 {
        core::ptr::write_volatile(sig_ptr.add(hdr_pos + i), slot_key[i]);
    }
    hdr_pos += 32;

    // subPkSeed (32 bytes: N real + 16 zero-padding)
    for i in 0..32 {
        core::ptr::write_volatile(sig_ptr.add(hdr_pos + i), slot.pk_seed[i]);
    }
    hdr_pos += 32;

    // subPkRoot (32 bytes: N real + 16 zero-padding)
    for i in 0..32 {
        core::ptr::write_volatile(sig_ptr.add(hdr_pos + i), slot.pk_root[i]);
    }
    hdr_pos += 32;

    debug_assert_eq!(hdr_pos, JARDIN_WRAPPER_HEADER_LEN);

    // 8. Write the variable-length FORS+C signature
    for i in 0..sig.len {
        core::ptr::write_volatile(sig_ptr.add(hdr_pos + i), sig.data[i]);
    }

    let total_len = JARDIN_WRAPPER_HEADER_LEN + sig.len;

    // 9. Cleanup
    crate::timeout::reset_activity();
    crate::ui::show_status(success_banner, "");

    for _ in 0..3_000_000u32 {
        cortex_m::asm::nop();
    }
    crate::ui::show_status("PQSigner OS", "Ready");

    (NscStatus::Ok as u32, total_len)
}
