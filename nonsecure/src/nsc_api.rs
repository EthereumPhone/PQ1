//! NS-side gateway API — thin shim over two transports.
//!
//! * **QEMU mps2-an505**: shared-memory mailbox in NS SRAM. NS writes
//!   the command word + args, the SysTick handler in the secure world
//!   polls the mailbox, runs the handler, and flips `DONE`. NS spins
//!   on `DONE`. This is a workaround for QEMU 8.2.2's broken SG
//!   instruction check on mps2-an505.
//! * **Real STM32U585**: the handful of gateway commands are exposed
//!   as proper ARMv8-M CMSE `extern "cmse-nonsecure-entry"` veneers
//!   on the secure side. Each call is a `BLXNS` → SG → secure handler
//!   → `BXNS` synchronously. No shared memory, no polling.

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
    const CMD_SIGN_USEROP: u32 = 7;
    const CMD_IS_UNLOCKED: u32 = 11;
    const CMD_LOCK: u32 = 12;
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
    pub(super) fn sign_userop_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe { gateway_call(CMD_SIGN_USEROP, payload_ptr as u32, sig_ptr as u32, total_len) }
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
    pub(super) fn get_wallet_address(out_ptr: *mut u8) -> u32 {
        unsafe { gateway_call(CMD_GET_WALLET_ADDRESS, out_ptr as u32, 0, 0) }
    }
}

// ---------------------------------------------------------------------------
// STM32U585 transport: direct CMSE veneer calls
// ---------------------------------------------------------------------------

#[cfg(feature = "stm32u585")]
mod transport {
    extern "C" {
        fn nsc_get_remaining_attempts() -> u32;
        fn nsc_request_unlock() -> u32;
        fn nsc_sign_userop(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
        fn nsc_is_unlocked() -> u32;
        fn nsc_lock() -> u32;
        fn nsc_get_wallet_address(out_ptr: u32) -> u32;
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
    pub(super) fn sign_userop_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe { nsc_sign_userop(payload_ptr as u32, sig_ptr as u32, total_len) }
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
    pub(super) fn get_wallet_address(out_ptr: *mut u8) -> u32 {
        unsafe { nsc_get_wallet_address(out_ptr as u32) }
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

/// Unified JARDÍN sign command (Type 1 + Type 2 state machine).
///
/// `payload` is the `SIGN_USEROP_HEADER_LEN`-byte header plus the
/// inner-tx calldata. `sig_buf` must be large enough to hold the
/// bundled response (`MAX_JARDIN_RESPONSE_LEN` bytes).
pub fn sign_userop(payload: &[u8], sig_buf: &mut [u8]) -> u32 {
    transport::sign_userop_call(payload.as_ptr(), sig_buf.as_mut_ptr(), payload.len() as u32)
}

/// Returns 1 if the device is PIN-unlocked this session, 0 otherwise.
pub fn is_unlocked() -> bool {
    transport::is_unlocked() == 1
}

/// Explicitly lock the device: zeroize cached secrets and mark as locked.
pub fn lock() -> u32 {
    transport::lock()
}

/// Compute the CREATE2-predicted wallet address from the bootstrap C10
/// pubkey + firmware-embedded factory / proxy-init-code-hash constants.
/// Writes 20 bytes into `out`. First call after unlock takes ~6 s
/// (bootstrap keygen); subsequent calls hit the in-SRAM cache and return
/// in <1 ms.
pub fn get_wallet_address(out: &mut [u8; 20]) -> u32 {
    transport::get_wallet_address(out.as_mut_ptr())
}
