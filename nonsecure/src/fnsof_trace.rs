//! Test-only trace of the USB frame clock (`OTG_DSTS.FNSOF`).
//!
//! The 2026-10-17 EVT-3D21 run found the 5.8 hang hook's frame accumulator
//! gaining whole 2,048-frame wraps. The same wrap-aware accumulation bounds
//! the 30 s chain lifetime and the 30 s / 120 s GET_RESPONSE drain, so a
//! backward FNSOF step would shorten them. This samples FNSOF once per poll
//! iteration and logs every consecutive pair whose 11-bit delta is >= 1024
//! (a backward step or a jump of more than a second), with the raw `DSTS`
//! words and an immediate re-read, for an SWD read-back.
//!
//! Called only when the NS image is built with `FNSOF_TRACE` set in the
//! environment (`option_env!` in `main.rs`); stock images never reference
//! this module, so its statics are dropped at link time.

/// OTG_DSTS: OTG_FS base `0x4204_0000` (`usb/mod.rs`) + 0x808.
const OTG_DSTS: *const u32 = 0x4204_0808 as *const u32;
const LOG_LEN: usize = 64;

#[no_mangle]
static mut FNSOF_SAMPLES: u32 = 0;
/// Sum of the wrap-aware 11-bit deltas, as `main.rs`'s hook accumulates.
#[no_mangle]
static mut FNSOF_ACC: u32 = 0;
#[no_mangle]
static mut FNSOF_EVENTS: u32 = 0;
/// Per event: `[sample index, previous DSTS, DSTS, DSTS re-read]`.
#[no_mangle]
static mut FNSOF_LOG: [[u32; 4]; LOG_LEN] = [[0; 4]; LOG_LEN];
static mut LAST_DSTS: u32 = u32::MAX;

fn dsts() -> u32 {
    // SAFETY: read-only access to the NS-mapped OTG_DSTS register.
    unsafe { core::ptr::read_volatile(OTG_DSTS) }
}

/// One poll-loop sample. Single-threaded: only the NS main loop calls it.
pub fn sample() {
    let d = dsts();
    // SAFETY: the statics are touched only here, from the NS main loop.
    unsafe {
        let last = core::ptr::read_volatile(core::ptr::addr_of!(LAST_DSTS));
        let n = core::ptr::read_volatile(core::ptr::addr_of!(FNSOF_SAMPLES));
        if last != u32::MAX {
            let f = (d >> 8) & 0x7FF;
            let lf = (last >> 8) & 0x7FF;
            let delta = f.wrapping_sub(lf) & 0x7FF;
            let acc = core::ptr::addr_of_mut!(FNSOF_ACC);
            core::ptr::write_volatile(acc, core::ptr::read_volatile(acc).wrapping_add(delta));
            if delta >= 1024 {
                let again = dsts();
                let ev = core::ptr::addr_of_mut!(FNSOF_EVENTS);
                let e = core::ptr::read_volatile(ev);
                let slot = core::ptr::addr_of_mut!(FNSOF_LOG[(e as usize) % LOG_LEN]);
                core::ptr::write_volatile(slot, [n, last, d, again]);
                core::ptr::write_volatile(ev, e.wrapping_add(1));
            }
        }
        core::ptr::write_volatile(core::ptr::addr_of_mut!(LAST_DSTS), d);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(FNSOF_SAMPLES), n.wrapping_add(1));
    }
}
