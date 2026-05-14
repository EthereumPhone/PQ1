//! PIN verification via MAC-and-Destroy chain.
//!
//! Used by [`crate::secure_element::SecureElement::unlock`] (Mock backend)
//! and by the Tropic01 batch-verify path. SE050 / OPTIGA backends do the
//! PIN compare inside the chip instead of through this MACD pipeline.

use crate::crypto::*;
use crate::secure_element::SecureElement;
use sphincs_tz_shared::{MAX_ATTEMPTS, NscStatus};
use zeroize::Zeroize;

/// Verify PIN against the MAC-and-Destroy chain.
/// On success, returns the decrypted master secret.
/// On failure, increments the attempt counter (may brick the key).
pub fn verify_pin(
    se: &mut impl SecureElement,
    pin: &[u8; 8],
) -> Result<[u8; 32], NscStatus> {
    // Read PIN state
    let mut state_buf = [0u8; PIN_STATE_MAX_LEN];
    let state_len = se
        .r_mem_read(RMEM_PIN_STATE, &mut state_buf)
        .map_err(|_| NscStatus::InternalError)?;
    let ps = deserialize_pin_state(&state_buf, state_len)
        .map_err(|_| NscStatus::InternalError)?;

    if ps.next_index >= MAX_ATTEMPTS {
        // All attempts exhausted — brick the key
        se.r_mem_erase(RMEM_ENCRYPTED_ENTROPY).ok();
        se.r_mem_erase(RMEM_PIN_STATE).ok();
        return Err(NscStatus::PinLocked);
    }

    // Authenticate via MAC-and-Destroy
    let j = ps.next_index;
    let pin_in = macd_pin_input(pin, j);
    let mut w_j = se
        .mac_and_destroy(j as u16, &pin_in)
        .map_err(|_| NscStatus::InternalError)?;

    // Try decrypting the master secret
    let mut ct_buf = [0u8; PER_SLOT_CT_LEN];
    ct_buf.copy_from_slice(&ps.encrypted_secrets[j as usize]);

    match aes_decrypt_inplace(&w_j, &mut ct_buf, PER_SLOT_CT_LEN, j) {
        Ok(32) => {
            // PIN correct — recover master secret
            let mut master_secret = [0u8; 32];
            master_secret.copy_from_slice(&ct_buf[..32]);
            ct_buf.zeroize();
            w_j.zeroize();

            // Re-initialize all MACD slots
            for slot_j in 0..MAX_ATTEMPTS {
                let init_in = macd_init_input(&master_secret, slot_j);
                se.mac_and_destroy(slot_j as u16, &init_in)
                    .map_err(|_| NscStatus::InternalError)?;
            }

            // Reset attempt counter
            let mut new_state_buf = [0u8; PIN_STATE_MAX_LEN];
            let len = serialize_pin_state(0, &ps.encrypted_secrets, &mut new_state_buf);
            se.r_mem_erase(RMEM_PIN_STATE).ok();
            se.r_mem_write(RMEM_PIN_STATE, &new_state_buf[..len])
                .map_err(|_| NscStatus::InternalError)?;

            Ok(master_secret)
        }
        _ => {
            // PIN incorrect — advance attempt counter
            ct_buf.zeroize();
            w_j.zeroize();

            let new_index = j + 1;
            if new_index >= MAX_ATTEMPTS {
                // Last attempt failed — erase everything
                se.r_mem_erase(RMEM_ENCRYPTED_ENTROPY).ok();
                se.r_mem_erase(RMEM_PIN_STATE).ok();
                se.r_mem_erase(RMEM_VERIFYING_KEY).ok();
                return Err(NscStatus::PinLocked);
            }

            let mut new_state_buf = [0u8; PIN_STATE_MAX_LEN];
            let len = serialize_pin_state(new_index, &ps.encrypted_secrets, &mut new_state_buf);
            se.r_mem_erase(RMEM_PIN_STATE).ok();
            se.r_mem_write(RMEM_PIN_STATE, &new_state_buf[..len]).ok();

            Err(NscStatus::PinIncorrect)
        }
    }
}
