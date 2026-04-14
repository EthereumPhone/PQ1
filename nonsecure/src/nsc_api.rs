//! NS-side gateway API.
//!
//! Two transports, picked at compile time by the `stm32u585` feature.
//!
//!   * **QEMU mps2-an505**: shared-memory mailbox in NS SRAM. NS writes
//!     the command word + args, the SysTick handler in the secure world
//!     polls the mailbox, runs the handler, and flips `DONE`. NS spins
//!     on `DONE`. This is a workaround for QEMU 8.2.2's broken SG
//!     instruction check on mps2-an505.
//!   * **Real STM32U585**: the six gateway commands are exposed as
//!     proper ARMv8-M CMSE `extern "cmse-nonsecure-entry"` veneers on
//!     the secure side. The `--cmse-implib` linker pass emits SG stubs
//!     for them into `veneers.o`, the NS crate links against that
//!     implib, and we resolve the `nsc_*` symbols as plain `extern "C"`
//!     functions here. Each call issues `BLXNS` → SG → secure handler
//!     → `BXNS` synchronously — no polling, no shared memory.

// ---------------------------------------------------------------------------
// QEMU transport: shared-memory mailbox
// ---------------------------------------------------------------------------

#[cfg(not(feature = "stm32u585"))]
mod transport {
    use sphincs_tz_shared::SHARED_MAILBOX_BASE;
    const SHARED_CMD: *mut u32 = SHARED_MAILBOX_BASE as *mut u32;
    const SHARED_ARG0: *mut u32 = (SHARED_MAILBOX_BASE + 4) as *mut u32;
    const SHARED_ARG1: *mut u32 = (SHARED_MAILBOX_BASE + 8) as *mut u32;
    const SHARED_ARG2: *mut u32 = (SHARED_MAILBOX_BASE + 12) as *mut u32;
    const SHARED_RESULT: *const u32 = (SHARED_MAILBOX_BASE + 16) as *const u32;
    const SHARED_DONE: *mut u32 = (SHARED_MAILBOX_BASE + 20) as *mut u32;

    const CMD_GET_REMAINING: u32 = 1;
    const CMD_REQUEST_UNLOCK: u32 = 2;
    const CMD_GET_PUBKEY: u32 = 3;
    const CMD_CLEAR_SIGN: u32 = 5;
    const CMD_CLEAR_SIGN_MSG: u32 = 6;
    const CMD_SIGN_USEROP: u32 = 7;
    const CMD_GET_BOOTSTRAP_PUBKEY: u32 = 8;
    const CMD_GET_MAIN_PUBKEY: u32 = 9;
    const CMD_SIGN_BOOTSTRAP: u32 = 10;
    const CMD_IS_UNLOCKED: u32 = 11;
    const CMD_LOCK: u32 = 12;
    const CMD_SIGN_MESSAGE: u32 = 13;
    const CMD_GET_WALLET_ADDRESS: u32 = 14;

    unsafe fn gateway_call(cmd: u32, arg0: u32, arg1: u32, arg2: u32) -> u32 {
        core::ptr::write_volatile(SHARED_DONE, 0);
        core::ptr::write_volatile(SHARED_ARG0, arg0);
        core::ptr::write_volatile(SHARED_ARG1, arg1);
        core::ptr::write_volatile(SHARED_ARG2, arg2);
        core::ptr::write_volatile(SHARED_CMD, cmd);

        while core::ptr::read_volatile(SHARED_DONE as *const u32) == 0 {
            cortex_m::asm::nop();
        }
        core::ptr::read_volatile(SHARED_RESULT)
    }

    #[inline]
    pub(super) fn get_remaining_attempts() -> u32 {
        unsafe { gateway_call(CMD_GET_REMAINING, 0, 0, 0) }
    }

    #[inline]
    pub(super) fn request_unlock() -> u32 {
        unsafe { gateway_call(CMD_REQUEST_UNLOCK, 0, 0, 0) }
    }

    #[inline]
    pub(super) fn get_pubkey(out_ptr: *mut u8, out_len: u32) -> u32 {
        unsafe { gateway_call(CMD_GET_PUBKEY, 0, out_ptr as u32, out_len) }
    }

    #[inline]
    pub(super) fn clear_sign_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe { gateway_call(CMD_CLEAR_SIGN, payload_ptr as u32, sig_ptr as u32, total_len) }
    }

    #[inline]
    pub(super) fn clear_sign_msg_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe {
            gateway_call(CMD_CLEAR_SIGN_MSG, payload_ptr as u32, sig_ptr as u32, total_len)
        }
    }

    #[inline]
    pub(super) fn sign_userop_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe {
            gateway_call(CMD_SIGN_USEROP, payload_ptr as u32, sig_ptr as u32, total_len)
        }
    }

    #[inline]
    pub(super) fn get_bootstrap_pubkey(out_ptr: *mut u8, out_len: u32) -> u32 {
        unsafe { gateway_call(CMD_GET_BOOTSTRAP_PUBKEY, 0, out_ptr as u32, out_len) }
    }

    #[inline]
    pub(super) fn get_main_pubkey(
        payload_ptr: *const u8,
        out_ptr: *mut u8,
        out_len: u32,
    ) -> u32 {
        unsafe {
            gateway_call(CMD_GET_MAIN_PUBKEY, payload_ptr as u32, out_ptr as u32, out_len)
        }
    }

    #[inline]
    pub(super) fn sign_bootstrap_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe {
            gateway_call(CMD_SIGN_BOOTSTRAP, payload_ptr as u32, sig_ptr as u32, total_len)
        }
    }

    #[inline]
    pub(super) fn is_unlocked() -> u32 {
        unsafe { gateway_call(CMD_IS_UNLOCKED, 0, 0, 0) }
    }

    #[inline]
    pub(super) fn lock() -> u32 {
        unsafe { gateway_call(CMD_LOCK, 0, 0, 0) }
    }

    #[inline]
    pub(super) fn sign_message_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe {
            gateway_call(CMD_SIGN_MESSAGE, payload_ptr as u32, sig_ptr as u32, total_len)
        }
    }

    #[inline]
    pub(super) fn get_wallet_address_call(
        payload_ptr: *const u8,
        out_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe {
            gateway_call(CMD_GET_WALLET_ADDRESS, payload_ptr as u32, out_ptr as u32, total_len)
        }
    }
}

// ---------------------------------------------------------------------------
// STM32U585 transport: direct CMSE veneer calls
// ---------------------------------------------------------------------------
//
// The six `nsc_*` symbols below resolve through `veneers.o`, which is
// passed to the NS link step via `-C link-arg=<path>/veneers.o` (see
// the Makefile). Each call is a `BLXNS` → SG → secure handler →
// `BXNS`. No shared memory, no polling.

#[cfg(feature = "stm32u585")]
mod transport {
    extern "C" {
        fn nsc_get_remaining_attempts() -> u32;
        fn nsc_request_unlock() -> u32;
        fn nsc_get_pubkey(out_ptr: u32, out_len: u32) -> u32;
        fn nsc_clear_sign(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
        fn nsc_clear_sign_msg(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
        fn nsc_sign_userop(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
        fn nsc_get_bootstrap_pubkey(out_ptr: u32, out_len: u32) -> u32;
        fn nsc_get_main_pubkey(payload_ptr: u32, out_ptr: u32, out_len: u32) -> u32;
        fn nsc_sign_bootstrap(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
        fn nsc_is_unlocked() -> u32;
        fn nsc_lock() -> u32;
        fn nsc_sign_message(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
        fn nsc_get_wallet_address(payload_ptr: u32, out_ptr: u32, total_len: u32) -> u32;
    }

    #[inline]
    pub(super) fn get_remaining_attempts() -> u32 {
        unsafe { nsc_get_remaining_attempts() }
    }

    #[inline]
    pub(super) fn request_unlock() -> u32 {
        unsafe { nsc_request_unlock() }
    }

    #[inline]
    pub(super) fn get_pubkey(out_ptr: *mut u8, out_len: u32) -> u32 {
        unsafe { nsc_get_pubkey(out_ptr as u32, out_len) }
    }

    #[inline]
    pub(super) fn clear_sign_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe { nsc_clear_sign(payload_ptr as u32, sig_ptr as u32, total_len) }
    }

    #[inline]
    pub(super) fn clear_sign_msg_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe { nsc_clear_sign_msg(payload_ptr as u32, sig_ptr as u32, total_len) }
    }

    #[inline]
    pub(super) fn sign_userop_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe { nsc_sign_userop(payload_ptr as u32, sig_ptr as u32, total_len) }
    }

    #[inline]
    pub(super) fn get_bootstrap_pubkey(out_ptr: *mut u8, out_len: u32) -> u32 {
        unsafe { nsc_get_bootstrap_pubkey(out_ptr as u32, out_len) }
    }

    #[inline]
    pub(super) fn get_main_pubkey(
        payload_ptr: *const u8,
        out_ptr: *mut u8,
        out_len: u32,
    ) -> u32 {
        unsafe { nsc_get_main_pubkey(payload_ptr as u32, out_ptr as u32, out_len) }
    }

    #[inline]
    pub(super) fn sign_bootstrap_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe { nsc_sign_bootstrap(payload_ptr as u32, sig_ptr as u32, total_len) }
    }

    #[inline]
    pub(super) fn is_unlocked() -> u32 {
        unsafe { nsc_is_unlocked() }
    }

    #[inline]
    pub(super) fn lock() -> u32 {
        unsafe { nsc_lock() }
    }

    #[inline]
    pub(super) fn sign_message_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe { nsc_sign_message(payload_ptr as u32, sig_ptr as u32, total_len) }
    }

    #[inline]
    pub(super) fn get_wallet_address_call(
        payload_ptr: *const u8,
        out_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe { nsc_get_wallet_address(payload_ptr as u32, out_ptr as u32, total_len) }
    }
}

// ---------------------------------------------------------------------------
// Transport-agnostic public surface
// ---------------------------------------------------------------------------

pub fn get_remaining_attempts() -> u32 {
    transport::get_remaining_attempts()
}

/// Ask the secure world to prompt the user for their PIN on the trusted UI.
/// The PIN never crosses the gateway — NS only sees the result.
pub fn request_unlock() -> u32 {
    transport::request_unlock()
}

pub fn get_pubkey(buf: &mut [u8; 32]) -> u32 {
    transport::get_pubkey(buf.as_mut_ptr(), 32)
}

/// ZK clear-sign (UserOp): forward a Groth16 proof + AA header + an
/// inner EIP-1559 envelope + a Merkle-verified VK bundle for an
/// Aave-style protocol. The secure world verifies the ZK proof,
/// displays the circuit-attested readable string, reconstructs the
/// `execute()` callData from the inner tx, computes the EntryPoint
/// v0.6 `userOpHash`, and signs that hash with SLH-DSA.
///
/// Wire format: proof(384) || calldata(164) || readable(64) ||
/// AA_HEADER(305) || tx_len(4) || tx || bundle_len(4) || vk_bundle.
pub fn clear_sign(payload: &[u8], sig_buf: &mut [u8]) -> u32 {
    transport::clear_sign_call(payload.as_ptr(), sig_buf.as_mut_ptr(), payload.len() as u32)
}

/// EIP-712 typed-data clear signing (M4 — CowSwap GPv2Order).
///
/// The payload layout is:
///
/// ```text
///   [0..384)         Groth16 proof (π.A || π.B || π.C)
///   [384..548)       canonical bytes (164 bytes, packed GPv2Order)
///   [548..612)       readable string (64 bytes, null-padded)
///   [612..616)       bundle_len u32 LE
///   [616..)          VK bundle bytes
/// ```
///
/// The secure world Merkle-verifies the VK bundle, runs Groth16 to
/// confirm `Poseidon(canonical) ‖ Poseidon(readable)` are the bound
/// public signals, recomputes the EIP-712 digest natively from the
/// SAME canonical bytes, displays the readable string on the trusted
/// UI, and signs the digest with SLH-DSA.
pub fn clear_sign_msg(payload: &[u8], sig_buf: &mut [u8]) -> u32 {
    transport::clear_sign_msg_call(
        payload.as_ptr(),
        sig_buf.as_mut_ptr(),
        payload.len() as u32,
    )
}

/// ERC-4337 v0.6 UserOperation signing.
///
/// The payload is the wire-format buffer produced by
/// [`crate::aa::build_userop_payload`] (or
/// [`crate::aa::build_userop_payload_with_bundle`]). The secure world
/// validates pointers, parses the AA header + inner EIP-1559 envelope,
/// reconstructs the canonical `execute(...)` callData itself, computes
/// the EntryPoint v0.6 `userOpHash` natively, displays the inner tx on
/// the trusted UI, and signs the resulting hash with SLH-DSA.
pub fn sign_userop(payload: &[u8], sig_buf: &mut [u8]) -> u32 {
    transport::sign_userop_call(
        payload.as_ptr(),
        sig_buf.as_mut_ptr(),
        payload.len() as u32,
    )
}

/// Like [`sign_userop`] but signals the presence of a trailing
/// `key_index(4 BE) + ots_index(4 BE)` trailer by setting bit 31 of
/// the total_len argument. The secure world uses this flag to extract
/// the OTS fields instead of defaulting to 0.
pub fn sign_userop_with_ots(payload: &[u8], sig_buf: &mut [u8]) -> u32 {
    transport::sign_userop_call(
        payload.as_ptr(),
        sig_buf.as_mut_ptr(),
        payload.len() as u32 | 0x8000_0000,
    )
}

/// Read the 32-byte bootstrap signer's verifying key. No unlock required.
pub fn get_bootstrap_pubkey(buf: &mut [u8; 32]) -> u32 {
    transport::get_bootstrap_pubkey(buf.as_mut_ptr(), 32)
}

/// Derive and read the 32-byte main signer's verifying key for a specific
/// chain and key epoch. Requires PIN unlock.
///
/// The `chain_id` and `key_index` are packed into a 12-byte payload and
/// passed to the secure world.
pub fn get_main_pubkey(chain_id: u64, key_index: u32, buf: &mut [u8; 32]) -> u32 {
    let mut payload = [0u8; 12];
    payload[0..8].copy_from_slice(&chain_id.to_be_bytes());
    payload[8..12].copy_from_slice(&key_index.to_be_bytes());
    transport::get_main_pubkey(payload.as_ptr(), buf.as_mut_ptr(), 32)
}

/// Sign a 32-byte message hash with the bootstrap signer. Used for
/// factory deployment authorization and emergency rotation.
pub fn sign_bootstrap(msg_hash: &[u8; 32], sig_buf: &mut [u8]) -> u32 {
    transport::sign_bootstrap_call(
        msg_hash.as_ptr(),
        sig_buf.as_mut_ptr(),
        32,
    )
}

/// Returns 1 if the device is PIN-unlocked this session, 0 otherwise.
pub fn is_unlocked() -> bool {
    transport::is_unlocked() == 1
}

/// Explicitly lock the device: zeroize cached secrets and mark as locked.
pub fn lock() -> u32 {
    transport::lock()
}

/// EIP-191 personal_sign. The payload carries key_index, ots_index,
/// chain_id, and the message. The secure world computes the EIP-191
/// hash, displays the message on the trusted UI, and signs with SLH-DSA.
/// Returns a WRAPPER_TOTAL_LEN-byte PQSignatureWrapper.
pub fn sign_message(payload: &[u8], sig_buf: &mut [u8]) -> u32 {
    transport::sign_message_call(
        payload.as_ptr(),
        sig_buf.as_mut_ptr(),
        payload.len() as u32,
    )
}

/// Compute CREATE2 wallet address from bootstrap VK + factory parameters,
/// display on trusted OLED. Returns 20-byte address in `out`.
pub fn get_wallet_address(payload: &[u8], out: &mut [u8; 20]) -> u32 {
    transport::get_wallet_address_call(
        payload.as_ptr(),
        out.as_mut_ptr(),
        payload.len() as u32,
    )
}
