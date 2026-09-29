//! `CMD_GET_PIN_ATTEMPT_LOG` — read the PIN-attempt reason log.
//!
//! Read-only. See `crate::pin_attempt_log` for why this exists (#715) and for
//! the disclosure argument: reason codes plus the pre-attempt counter value,
//! no secret material.

use sphincs_tz_shared::NscStatus;

use super::ptr_validate::validate_ns_write_ptr;
use super::GatewayArgs;

const OUT_LEN: usize = crate::pin_attempt_log::SERIALISED_LEN;

const _: () = assert!(
    OUT_LEN == sphincs_tz_shared::PIN_ATTEMPT_LOG_LEN,
    "the wire length and the serialiser must agree, or the host decodes garbage"
);

/// # Safety
/// CMSE non-secure-entry handler — the NS pointer is dereferenced only after
/// `validate_ns_write_ptr`.
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    if !validate_ns_write_ptr(args.arg1, OUT_LEN) {
        return NscStatus::InvalidPointer as u32;
    }
    let mut buf = [0u8; OUT_LEN];
    crate::pin_attempt_log::snapshot(&mut buf);

    let out = args.arg1 as *mut u8;
    for (i, b) in buf.iter().enumerate() {
        // SAFETY: arg1 was validated for OUT_LEN bytes above.
        unsafe { core::ptr::write_volatile(out.add(i), *b) };
    }
    NscStatus::Ok as u32
}
