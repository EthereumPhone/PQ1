//! NV3007 tearing-effect (TE) input — the panel's scan-out clock (#780).
//!
//! The panel is already told to pulse TE once per frame (`lcd_nv3007::init`
//! sends `0x35` with parameter `0x00` = "V-blanking only", and `0x44` sets the
//! tear scanline). Until this module existed nothing read the pin, so every
//! blit raced the scan-out and the seam drifted.
//!
//! The pin is `board::LCD_TE` — `Some((GPIOB_S, 2))` on pq1, `None` on iota2
//! (that board has no panel at all), so every entry point here is a no-op when
//! the board has no TE line and the caller needs no `cfg`.
//!
//! **Pull-DOWN, deliberately.** A panel that is absent, unpowered or whose TE
//! is misconfigured then reads a steady 0 rather than floating noise, so
//! "TE is dead" is a determinate observation instead of a random one. That
//! matters because the wait below has to distinguish the two.

use super::mmio::{Reg32, RoReg32};
use crate::board;

/// `(port_base, pin)`, or `None` on a board with no panel.
const TE: Option<(u32, u32)> = board::LCD_TE;

/// GPIO register offsets (RM0456 §12.4).
const MODER_OFF: u32 = 0x00;
const PUPDR_OFF: u32 = 0x0C;
const IDR_OFF: u32 = 0x10;

/// Configure the TE pin as a pulled-down input. Idempotent; no-op without a
/// TE line. Must run after `lcd_nv3007::init` has brought the panel up, but
/// the GPIO clock is enabled here anyway so the order is not load-bearing.
pub fn init() {
    let Some((port, pin)) = TE else { return };
    let pin2 = pin * 2;

    // SAFETY: `port` comes from the board map, so RCC_AHB2ENR1 and the port's
    // MODER/PUPDR are real, 4-byte-aligned MMIO registers. All three are
    // shared with other drivers (`rcc`, `buttons`, `lcd_nv3007`) but every
    // access is a read-modify-write on disjoint bits in the single-threaded
    // secure world — the same discipline as `buttons::REG`.
    unsafe {
        Reg32::new(board::RCC_S + board::RCC_AHB2ENR1_OFF).set_bits(board::gpio_rcc_bit(port));
        cortex_m::asm::dsb();

        // MODER field -> 00 (input), PUPDR field -> 10 (pull-down). Only the
        // two bits belonging to this pin are touched, so the LCD's own
        // PB0/PB1/PB15 and anything else on the port keep their modes.
        Reg32::new(port + MODER_OFF).modify(|v| v & !(0b11 << pin2));
        Reg32::new(port + PUPDR_OFF).modify(|v| (v & !(0b11 << pin2)) | (0b10 << pin2));
    }
    cortex_m::asm::dsb();
}

/// Current TE level. `false` when the board has no TE line.
#[must_use]
pub fn level() -> bool {
    let Some((port, pin)) = TE else { return false };
    // SAFETY: `port` comes from the board map; IDR is a real, 4-byte-aligned
    // read-only MMIO register and this is a plain load.
    unsafe { RoReg32::new(port + IDR_OFF) }.read() & (1 << pin) != 0
}

/// Whether this board has a TE line at all.
#[must_use]
pub const fn present() -> bool {
    TE.is_some()
}

// ---------------------------------------------------------------------------
// DWT cycle counter — MEASUREMENT ONLY
// ---------------------------------------------------------------------------
//
// Mirrors `bench_masked_sha.rs:31-55`: the core debug block is always
// accessible to secure code, and CYCCNT is the only clock on this part with
// sub-frame resolution (SysTick is 1 kHz, i.e. coarser than a TE period).
//
// Gated on `ui-px-te-probe` so these four raw `read_volatile`/`write_volatile`
// — CLAUDE.md's "avoidable unsafe" category — never link into a ship image,
// and so nothing on a shipping path can come to depend on CYCCNT being armed.
// That dependency is a real hazard here, not a hypothetical: CYCCNT is enabled
// only just before `boot_ns::boot` and in prodtest, whereas `ui::splash()`
// paints long before either.
#[cfg(feature = "ui-px-te-probe")]
mod probe_clock {
    use super::{level, TE};

    const DEMCR: *mut u32 = 0xE000_EDFC as *mut u32;
    const DWT_CTRL: *mut u32 = 0xE000_1000 as *mut u32;
    const DWT_CYCCNT: *mut u32 = 0xE000_1004 as *mut u32;
    const DWT_LAR: *mut u32 = 0xE000_1FB0 as *mut u32;

    /// Enable TRCENA, unlock the DWT and start CYCCNT. Idempotent.
    pub fn cyccnt_enable() {
        // SAFETY: plain debug-block writes, always accessible to secure code on
        // Cortex-M33 (same sequence as `bench_masked_sha::enable_cycle_counter`).
        // 0xC5AC_CE55 is the ARMv8-M lock-access key; any other value leaves the
        // DWT locked and CYCCNT frozen at 0.
        unsafe {
            core::ptr::write_volatile(DEMCR, core::ptr::read_volatile(DEMCR) | (1 << 24));
            core::ptr::write_volatile(DWT_LAR, 0xC5AC_CE55);
            core::ptr::write_volatile(DWT_CYCCNT, 0);
            core::ptr::write_volatile(DWT_CTRL, core::ptr::read_volatile(DWT_CTRL) | 1);
        }
}

/// Free-running cycle count. Wraps every 2^32 cycles (26.8 s at 160 MHz);
/// every use here is a wrapping difference, so the wrap is harmless.
#[must_use]
pub fn cycles() -> u32 {
    // SAFETY: plain read of the free-running DWT cycle counter.
    unsafe { core::ptr::read_volatile(DWT_CYCCNT) }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// What one TE observation window saw.
#[derive(Clone, Copy, Default)]
pub struct TeMeasure {
    /// Rising edges counted in the window.
    pub edges: u32,
    /// Mean period between rising edges, in cycles. 0 with fewer than 2 edges.
    pub period_cyc: u32,
    /// Shortest observed period, in cycles. 0 with fewer than 2 edges.
    pub period_min_cyc: u32,
    /// Longest observed period, in cycles. 0 with fewer than 2 edges.
    pub period_max_cyc: u32,
    /// Width of the last complete high pulse, in cycles.
    pub high_cyc: u32,
    /// The window expired before `want_edges` were seen.
    pub timed_out: bool,
}

/// Watch TE for up to `budget_cyc`, stopping early once `want_edges` rising
/// edges have been seen.
///
/// Polls `IDR` rather than using EXTI: this runs once, the poll loop is five
/// instructions, and an interrupt path would need a handler, an NVIC entry and
/// a secure-world vector — none of which a measurement should own.
///
/// Always terminates: the loop is bounded by `budget_cyc` whether or not TE
/// ever moves, which is the property `spi_end`'s unbounded `while EOT == 0`
/// lacked before `spi_force_down` (#780 review).
#[must_use]
pub fn measure(want_edges: u32, budget_cyc: u32) -> TeMeasure {
    let mut m = TeMeasure::default();
    if TE.is_none() {
        m.timed_out = true;
        return m;
    }

    let t0 = cycles();
    let mut prev = level();
    let mut last_rise: Option<u32> = None;
    let mut sum: u64 = 0;
    let mut n: u32 = 0;

    loop {
        let now = cycles();
        if now.wrapping_sub(t0) >= budget_cyc {
            m.timed_out = m.edges < want_edges;
            break;
        }
        let cur = level();
        if cur && !prev {
            // Rising edge.
            m.edges += 1;
            if let Some(p) = last_rise {
                let d = now.wrapping_sub(p);
                sum += u64::from(d);
                n += 1;
                if m.period_min_cyc == 0 || d < m.period_min_cyc {
                    m.period_min_cyc = d;
                }
                if d > m.period_max_cyc {
                    m.period_max_cyc = d;
                }
            }
            last_rise = Some(now);
            if m.edges >= want_edges {
                break;
            }
        } else if !cur && prev {
            // Falling edge: the pulse that just ended started at `last_rise`.
            if let Some(p) = last_rise {
                m.high_cyc = now.wrapping_sub(p);
            }
        }
        prev = cur;
    }

    if n > 0 {
        m.period_cyc = (sum / u64::from(n)) as u32;
    }
    m
}

}

#[cfg(feature = "ui-px-te-probe")]
pub use probe_clock::{cycles, cyccnt_enable, measure, TeMeasure};

/// Consecutive missed edges. At `DEAD_AFTER` the line is declared dead.
///
/// Without a latch a dead pin costs the full poll cap on EVERY frame, which
/// halves the frame rate of a board that is otherwise fine. But latching on a
/// SINGLE miss is too eager: one spurious miss would disable synchronisation
/// for the rest of the boot with no way back, and that is exactly the failure
/// that hid `lcd_te::init()` not being called — the first frame missed, the
/// latch stuck, and every later frame skipped the wait silently. Three
/// consecutive misses is still ~190 ms of evidence at worst and cannot be a
/// glitch.
static mut TE_MISSES: u32 = 0;

/// Consecutive misses before the line is declared dead.
const DEAD_AFTER: u32 = 3;

/// Has the TE line been observed dead? (Latched by [`sync_to_scanout`] after
/// [`DEAD_AFTER`] consecutive misses.)
#[must_use]
pub fn dead() -> bool {
    // SAFETY: single-threaded frame loop; a plain u32 written only here and in
    // `sync_to_scanout`, never from an ISR.
    let n = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TE_MISSES)) };
    n >= DEAD_AFTER
}

/// Phase-lock the caller to the panel's scan-out: block until the next TE
/// rising edge. Returns `true` if an edge was seen.
///
/// Measured on the EVT unit 2026-10-06: the panel runs at **62.5 Hz** (16.0 ms)
/// and the TE pulse is **18 us** wide — a half-line strobe at the `0x44` tear
/// scanline, NOT the V-blank level the datasheet's `Tvdh >= 1000 us` describes.
/// Two things follow. A tight poll catches an 18 us pulse easily (it is
/// 150-300 iterations wide), but a single opportunistic read would see it only
/// 0.11% of the time — so there is no cheap non-blocking variant of this, and
/// anything that cannot spin needs a latched EXTI edge instead. And there is no
/// wide blanking window to start inside, which is why the blit TRAILS the beam
/// rather than trying to outrun it.
///
/// Once latched dead this returns immediately, so a panel-less board pays the
/// cap once rather than every frame.
pub fn sync_to_scanout(spin_cap: u32) -> bool {
    if dead() {
        return false;
    }
    if wait_rising(spin_cap) {
        // A good edge clears the run: a transient miss must not accumulate
        // across an otherwise healthy boot.
        // SAFETY: as `dead()`.
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(TE_MISSES), 0) };
        return true;
    }
    // SAFETY: as `dead()`.
    unsafe {
        let n = core::ptr::read_volatile(core::ptr::addr_of!(TE_MISSES));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(TE_MISSES), n.saturating_add(1));
    }
    false
}

/// Block until the next TE rising edge, or until `spin_cap` poll iterations
/// have been spent. Returns `true` only if an edge was actually seen.
///
/// **Bounded on POLL ITERATIONS, not core cycles** — the same contract as
/// `gpdma::wait`, and for a sharper reason here. DWT CYCCNT is armed only
/// immediately before `boot_ns::boot` (and in prodtest), while `ui::splash()`
/// paints much earlier in boot. A cycle-based bound would therefore compare
/// `0 >= budget` on every early frame, which is false forever: on a board
/// whose TE never rises (the pull-down holds it low when no panel is fitted)
/// that is a SILENT PERMANENT HANG at the splash, because IWDG is kicked from
/// the SysTick ISR and so never fires. A poll count cannot be frozen.
///
/// The RISING edge specifically: entering mid-pulse surrenders part of the
/// head start the synchronisation exists to buy.
pub fn wait_rising(spin_cap: u32) -> bool {
    if TE.is_none() {
        return false;
    }
    let mut spins = 0u32;
    // Drain a level that is already high, so a stale high does not read as an
    // edge. If TE is stuck high this falls through to the cap, as intended.
    while level() {
        spins += 1;
        if spins >= spin_cap {
            return false;
        }
        core::hint::spin_loop();
    }
    while !level() {
        spins += 1;
        if spins >= spin_cap {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}
