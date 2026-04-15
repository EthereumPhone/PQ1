//! Shared UserOp signing tail used by [`super::cmd_sign_userop`] and
//! [`super::cmd_clear_sign`].
//!
//! After the caller has validated the inner transaction and obtained
//! user confirmation via the trusted UI, the remaining steps are
//! identical for every UserOp signing path:
//!
//!   1. Reconstruct `execute(target, value, data)` callData from the
//!      user-confirmed inner EIP-1559 envelope.
//!   2. Hash the callData with keccak256.
//!   3. Compute the EntryPoint v0.6 `userOpHash` from the AA wrapper
//!      parameters plus the callData hash.
//!   4. Hand the 32-byte `userOpHash` to [`super::sign_and_emit::decrypt_and_sign`].
//!
//! For **undeployed** accounts (mode ≥ 2), step 3 is preceded by an
//! automatic initCode generation: the bootstrap keypair signs a factory
//! authorization message, and the resulting initCode is both hashed
//! (to produce `init_code_hash` for the userOpHash) and written to the
//! output buffer.
//!
//! Hoisting this into a single helper means adding a new UserOp-based
//! signing flavour (e.g. a future ZK clear-sign for a new protocol)
//! is a one-line call at the end of the new `cmd_*.rs`.

use crate::aa::userop::{compute_user_op_hash, reconstruct_execute_calldata, AaUserOpParams};
use crate::tx::eip1559::Eip1559Tx;
use crate::tx::hash::keccak256;
use crate::ui;
use sphincs_tz_shared::{NscStatus, SIGNATURE_LEN, WRAPPER_TOTAL_LEN, INIT_CODE_LEN};

use super::sign_and_emit::{decrypt_and_sign, decrypt_and_sign_wrapped};
use super::state;

/// Reconstruct callData, compute `userOpHash`, and sign it.
///
/// The caller must have:
///   * verified that the device is unlocked;
///   * validated `sig_ptr` via `validate_ns_write_ptr`;
///   * gotten through trusted-UI confirmation.
///
/// SAFETY: `sig_ptr` must point at a pre-validated `SIGNATURE_LEN`-byte
/// NS-writable region.
pub(super) unsafe fn sign_userop_hash(
    aa: &AaUserOpParams,
    parsed_tx: &Eip1559Tx,
    inner_data: &[u8],
    sig_ptr: *mut u8,
    success_banner: &str,
) -> u32 {
    let exec_call = match reconstruct_execute_calldata(parsed_tx, inner_data) {
        Ok(c) => c,
        Err(_) => {
            ui::show_status("UserOp", "encode fail");
            return NscStatus::CryptoError as u32;
        }
    };
    let call_data_hash = keccak256(exec_call.as_slice());

    let user_op_hash = compute_user_op_hash(aa, &call_data_hash);

    #[cfg(feature = "e2e-test")]
    secure_log!(
        "[S][e2e] userop_tail userOpHash[..4] = {:02x}{:02x}{:02x}{:02x}",
        user_op_hash[0],
        user_op_hash[1],
        user_op_hash[2],
        user_op_hash[3]
    );

    ui::show_status("Signing UserOp", "");

    state::peek_state(|s| decrypt_and_sign(s, &user_op_hash, sig_ptr, success_banner))
}

/// Full-UserOp response: reconstruct callData, optionally build initCode,
/// compute `userOpHash`, sign, and write the structured response.
///
/// When `needs_init_code` is true, the firmware:
///   1. Derives bootstrap + main keypairs from a single entropy read
///   2. Signs the factory authorization message with the bootstrap key
///   3. Builds and hashes the initCode (overriding `aa.init_code_hash`)
///   4. Writes the initCode to the output buffer
///
/// Then, for both deployed and undeployed:
///   5. Reconstructs `execute(...)` callData
///   6. Computes the `userOpHash`
///   7. Signs userOpHash with the main key
///   8. Writes the structured response:
///      `init_code_len(4) + initCode(N) + call_data_len(4) + callData(M) + wrapper`
///
/// Returns the total number of bytes written via the `result_len` out-param,
/// and an NscStatus code as the function return value.
///
/// # Safety
///
/// `out_ptr` must point at a pre-validated NS-writable region of at least
/// `MAX_USEROP_RESPONSE_LEN` bytes.
pub(super) unsafe fn sign_userop_full(
    aa: &mut AaUserOpParams,
    parsed_tx: &Eip1559Tx,
    inner_data: &[u8],
    out_ptr: *mut u8,
    result_len: *mut usize,
    needs_init_code: bool,
    key_index: u32,
    ots_index: u32,
    success_banner: &str,
) -> u32 {
    use crate::aa::init_code;
    use zeroize::Zeroize;

    // --- Phase 0: Reconstruct callData (needed for both paths) ---
    let exec_call = match reconstruct_execute_calldata(parsed_tx, inner_data) {
        Ok(c) => c,
        Err(_) => {
            ui::show_status("UserOp", "encode fail");
            return NscStatus::CryptoError as u32;
        }
    };

    let mut write_pos: usize = 0;

    // --- Phase 1: initCode (only for undeployed accounts) ---
    if needs_init_code {
        ui::show_status("UserOp", "bootstrap sig...");

        // 1a. Read encrypted entropy from SE
        let mut entropy_blob = [0u8; 64];
        let entropy_blob_len = {
            use crate::secure_element::WalletStore;
            let se = &mut *core::ptr::addr_of_mut!(crate::SE);
            match se.read_entropy_blob(&mut entropy_blob) {
                Ok(len) => len,
                Err(_) => return NscStatus::InternalError as u32,
            }
        };

        let master_secret = state::peek_state(|s| s.master_secret);

        let mut entropy = match crate::crypto::decrypt_entropy_blob(
            &entropy_blob[..entropy_blob_len],
            &master_secret,
        ) {
            Ok(e) => e,
            Err(_) => {
                entropy_blob.zeroize();
                return NscStatus::CryptoError as u32;
            }
        };
        entropy_blob.zeroize();

        // 1b. Read cached bootstrap VK from r-mem (avoids keygen)
        //     + derive main VK for this chain (no cache, full keygen).
        let bootstrap_vk = {
            let mut bvk = [0u8; 32];
            use crate::secure_element::WalletStore;
            let se = &mut *core::ptr::addr_of_mut!(crate::SE);
            if se.read_bootstrap_vk(&mut bvk).is_err() {
                entropy.zeroize();
                return NscStatus::InternalError as u32;
            }
            bvk
        };
        let main_vk = crate::crypto::derive_main_vk_from_entropy(
            &entropy, aa.chain_id, key_index,
        );

        let (b_pk_seed, b_pk_root) = init_code::vk_to_pk_components(&bootstrap_vk);
        let (m_pk_seed, m_pk_root) = init_code::vk_to_pk_components(&main_vk);

        // 1c. Compute the authorization message and sign with bootstrap key
        let auth_msg = init_code::compute_auth_message(&m_pk_seed, &m_pk_root);

        // Use fast path: cached pk_root from the bootstrap VK we just read.
        let mut cached_b_pk_root = [0u8; 16];
        cached_b_pk_root.copy_from_slice(&bootstrap_vk[16..32]);
        let bootstrap_sk = crate::crypto::derive_bootstrap_key_from_entropy_fast(
            &entropy, &cached_b_pk_root,
        );

        // Hedged randomizer for bootstrap signature
        let mut rand_buf = [0u8; 16];
        {
            use sha3::{Digest as _, Keccak256};
            let mut h = Keccak256::new();
            h.update(b"sphincsc7-bootstrap-init-code-rand");
            h.update(&master_secret);
            h.update(&auth_msg);
            let r = h.finalize();
            rand_buf.copy_from_slice(&r[..16]);
        }

        let bootstrap_sig = bootstrap_sk.sign_with_progress(
            &auth_msg, Some(&rand_buf), bootstrap_sign_progress,
        );
        rand_buf.zeroize();
        drop(bootstrap_sk); // zeroize on drop

        // Copy the signature into a static buffer so we can free the
        // stack slot and still reference the data for hashing + writing.
        static mut BS_BUF: [u8; SIGNATURE_LEN] = [0u8; SIGNATURE_LEN];
        {
            let bs_ptr = &raw mut BS_BUF;
            for i in 0..SIGNATURE_LEN {
                (*bs_ptr)[i] = bootstrap_sig[i];
            }
        }

        // 1d. Compute init_code_hash and override AA params
        let bs_slice: &[u8; SIGNATURE_LEN] = &*(&raw const BS_BUF);
        let init_code_hash = init_code::compute_init_code_hash(
            &b_pk_seed, &b_pk_root, &m_pk_seed, &m_pk_root,
            bs_slice,
        );
        aa.init_code_hash = init_code_hash;

        // 1e. Write init_code_len (u32 BE) + initCode to output
        let ic_len_bytes = (INIT_CODE_LEN as u32).to_be_bytes();
        for b in &ic_len_bytes {
            core::ptr::write_volatile(out_ptr.add(write_pos), *b);
            write_pos += 1;
        }
        write_pos += init_code::write_init_code_to_ns(
            out_ptr.add(write_pos),
            &b_pk_seed, &b_pk_root, &m_pk_seed, &m_pk_root,
            bs_slice,
        );

        // Zeroize the bootstrap sig static (not secret, but good hygiene)
        {
            let bs_ptr = &raw mut BS_BUF;
            (*bs_ptr).fill(0);
        }
        entropy.zeroize();
    } else {
        // Deployed: init_code_len = 0
        let zero = 0u32.to_be_bytes();
        for b in &zero {
            core::ptr::write_volatile(out_ptr.add(write_pos), *b);
            write_pos += 1;
        }
    }

    // --- Phase 2: Write callData ---
    let call_data = exec_call.as_slice();
    let cd_len_bytes = (call_data.len() as u32).to_be_bytes();
    for b in &cd_len_bytes {
        core::ptr::write_volatile(out_ptr.add(write_pos), *b);
        write_pos += 1;
    }
    for i in 0..call_data.len() {
        core::ptr::write_volatile(out_ptr.add(write_pos), call_data[i]);
        write_pos += 1;
    }

    // --- Phase 3: Compute userOpHash and sign with main key ---
    let call_data_hash = keccak256(call_data);
    let user_op_hash = compute_user_op_hash(aa, &call_data_hash);

    #[cfg(feature = "e2e-test")]
    secure_log!(
        "[S][e2e] userop_tail full userOpHash[..4] = {:02x}{:02x}{:02x}{:02x}",
        user_op_hash[0],
        user_op_hash[1],
        user_op_hash[2],
        user_op_hash[3]
    );

    ui::show_status("Signing UserOp", "");

    let sig_out = out_ptr.add(write_pos);
    let status = state::peek_state(|s| {
        decrypt_and_sign_wrapped(
            s,
            &user_op_hash,
            sig_out,
            sphincs_tz_shared::SIGNER_MAIN,
            aa.chain_id,
            key_index,
            ots_index,
            success_banner,
        )
    });

    if status == NscStatus::Ok as u32 {
        write_pos += WRAPPER_TOTAL_LEN;
        core::ptr::write_volatile(result_len, write_pos);
    }

    status
}

fn bootstrap_sign_progress(percent: u8) {
    crate::ui::show_progress("Bootstrap sig", percent);
}
