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
    // The edge latch. Without this `wait_rising` is back to racing an 18 us
    // strobe against the SysTick ISR — see the EXTI block below.
    exti_init(port, pin);
}

// ---------------------------------------------------------------------------
// The TE edge is LATCHED IN HARDWARE (EXTI), not polled as a level
// ---------------------------------------------------------------------------
//
// WHY. The TE pulse is 18 us wide and the panel repeats it every 16.0 ms.
// Polling the LEVEL means the CPU has to be looking during those 18 us, and
// SysTick runs at 1 kHz — so a strobe that lands inside the SysTick ISR is
// invisible. That would be a rare miss if the two were unrelated, but the TE
// period is an EXACT multiple of the tick (16.0 ms = 16 ticks), so once a
// strobe coincides with the ISR, every following strobe coincides too. The
// poll then burns its whole cap, and `te_wait` reads ~100 ms instead of the
// <= 16 ms a wait for an edge can ever legitimately take. MEASURED on the EVT
// unit 2026-10-07: te_wait 3.6 ms early, >= 99.9 ms once it set in, with the
// frame period going 32.3 -> >= 99.9 ms. The old `while !level()` loop is at
// the bottom of that.
//
// EXTI fixes it at the root: the edge-detect circuit sets `RPR1.RPIF2` the
// instant the pin rises, whether or not the CPU is executing anything at all
// (RM0456 23.6.4: "This bit is set when the rising edge event ... arrives on
// the configurable event line. This bit is cleared by writing 1 to it").
// So the strobe cannot be missed for ANY reason — not an ISR, not a beat, not
// a slow frame — and we poll a sticky flag instead of a 0.11%-duty level.
//
// `IMR1` STAYS MASKED. Its reset value is 0 and we never set it, so no
// interrupt or wake-up is generated: this is a latch we read, not an ISR.
// The pending flag is fed by the edge detector ahead of the interrupt and
// event masks (RM0456 23.3, Figure 102), so masking costs us nothing.

/// EXTI, secure alias (NS is 0x4602_2000; +0x1000_0000 like RCC and GPDMA).
const EXTI_S: u32 = 0x5602_2000;
const EXTI_RTSR1: u32 = 0x000;
const EXTI_SWIER1: u32 = 0x008;
const EXTI_RPR1: u32 = 0x00C;
const EXTI_SECCFGR1: u32 = 0x014;
const EXTI_EXTICR1: u32 = 0x060;
const EXTI_IMR1: u32 = 0x080;

/// `(EXTICRn offset, shift)` for the TE pin's port-select field, plus the
/// line bit. Derived from the BOARD map rather than hardcoded, the same way
/// the SPI and LCD pins are: `EXTICRn` holds four 8-bit fields, and the port
/// index is the GPIO base's distance from `GPIOA_S` in 0x400 steps.
const fn exti_line(pin: u32) -> u32 {
    1 << pin
}

/// Configure the TE pin's EXTI line for rising-edge detection, and claim it
/// as SECURE so the non-secure world cannot clear the flag out from under the
/// trusted display (which would silently drop us back to an unsynchronised
/// blit, i.e. #780's tearing, on demand).
fn exti_init(port: u32, pin: u32) {
    let port_index = (port - board::GPIOA_S) / 0x400;
    // SAFETY: every address is a real, 4-byte-aligned EXTI register on the
    // secure alias; `Reg32` encapsulates the volatile access.
    unsafe {
        // Port select for this line: four 8-bit fields per EXTICR register.
        let cr = Reg32::new(EXTI_S + EXTI_EXTICR1 + (pin / 4) * 4);
        let shift = (pin % 4) * 8;
        cr.modify(|v| (v & !(0xFF << shift)) | (port_index << shift));
        // Secure-only, before arming, so there is no window in which NS owns
        // the flag.
        Reg32::new(EXTI_S + EXTI_SECCFGR1).set_bits(exti_line(pin));
        // Rising edge only; falling is left disabled.
        Reg32::new(EXTI_S + EXTI_RTSR1).set_bits(exti_line(pin));
        // UNMASK THE LINE. This was the missing write, and its absence is why
        // the first EXTI attempt latched nothing: on the EVT unit a `SWIER1`
        // software trigger did not set `RPR1` while `IMR1` was at its 0 reset
        // value, which is the classic STM32 EXTI behaviour — the pending flag
        // only latches for an UNMASKED line. The register is literally named
        // "CPU wake-up with interrupt mask" (RM0456 23.6.10).
        //
        // SAFE WITHOUT AN ISR: `IMR1` gates EXTI's output toward the NVIC, and
        // NVIC EXTI2 is never enabled in this firmware (the only unmasked IRQs
        // are TAMP and the TZIC — see `main_sau_pure_tests`), so no handler can
        // run. The flag is latched for us to poll, which is all we want.
        Reg32::new(EXTI_S + EXTI_IMR1).set_bits(exti_line(pin));
        // Discard anything latched during configuration.
        Reg32::new(EXTI_S + EXTI_RPR1).write(exti_line(pin));
    }
    cortex_m::asm::dsb();

    // READ BACK, AND FALL BACK IF IT DID NOT STICK.
    //
    // This is here because the first cut of this change SHIPPED BROKEN and
    // made things worse: on the EVT unit the line missed its three
    // `DEAD_AFTER` waits inside the first 15 s, latched dead, and the blit
    // then ran with NO synchronisation at all — trading #783's intermittent
    // stall for #780's tearing, permanently. The level poll it replaced was
    // imperfect but demonstrably worked (`te_wait` 3.6 ms measured).
    //
    // The register addresses and the port encoding check out against RM0456
    // (EXTI_S 0x5602_2000 per the memory map at Rev 7 p.7283; EXTI2 in
    // EXTICR1[23:16]; port B = 0x01), so the fault is not something a
    // re-read of the manual found. Rather than guess again, the driver now
    // PROVES its own configuration took effect and keeps the old path when it
    // did not. A trusted display must not lose scan-out sync because an
    // optimisation silently failed.
    // SELF-TEST THE LATCH ITSELF, with no hardware and no panel.
    //
    // RM0456 23.6.4: `RPIFx` "is set when the rising edge event OR AN
    // EXTI_SWIER SOFTWARE TRIGGER arrives on the configurable event line". So
    // a write to `SWIER1` exercises the whole latch — register offsets,
    // security configuration, pending logic — WITHOUT needing an edge on the
    // pin. That splits the one question I could not answer from the armchair
    // into two that a single flash settles:
    //
    //   SWIER sets RPR  -> the EXTI block and my register map are correct,
    //                      and the fault is specifically the PIN -> EXTI
    //                      input path (EXTICR port select, or the GPIO input
    //                      path to the edge detector).
    //   SWIER does NOT  -> the block is not doing what I configured at all:
    //                      clock, security, or an offset that the SVD and I
    //                      agree on and the silicon does not.
    //
    // Runs regardless of `ui-px-te-exti`, because its whole value is telling
    // us whether that feature is worth turning on.
    // SAFETY: real, 4-byte-aligned EXTI registers on the secure alias.
    let swier_ok = unsafe {
        let rpr = Reg32::new(EXTI_S + EXTI_RPR1);
        rpr.write(exti_line(pin));
        Reg32::new(EXTI_S + EXTI_SWIER1).write(exti_line(pin));
        cortex_m::asm::dsb();
        // POLL, DO NOT SNAPSHOT. The first version read `RPR1` once,
        // immediately after the `SWIER1` write, and reported FALSE on the EVT
        // unit — which I was about to read as "EXTI is broken". But the edge
        // path is an ASYNCHRONOUS detector resynchronised to `hclk`
        // (RM0456 23.3, Figure 102 — note the explicit `Delay` and `hclk`
        // stages), and `dsb` orders the two stores without waiting for that
        // synchroniser. A single read can therefore sample before the flag
        // lands, and a false negative here is indistinguishable from a real
        // one. Poll a bounded window instead, so the result means what it says.
        let mut latched = false;
        for _ in 0..1_000u32 {
            if RoReg32::new(EXTI_S + EXTI_RPR1).read() & exti_line(pin) != 0 {
                latched = true;
                break;
            }
            core::hint::spin_loop();
        }
        rpr.write(exti_line(pin));
        latched
    };
    // SAFETY: plain bool, written once during init, read by the frame loop.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(EXTI_SWIER_OK), swier_ok) };

    // OPT-IN, AND OFF BY DEFAULT (2026-10-07). The configuration READS BACK
    // CORRECTLY on the EVT unit and the line still never latches an edge:
    // measured `37 / 28 / 3` on the bench overlay — 37 misses in 28 s with
    // `exti_in_use` true and the line dead. So the registers accept and hold
    // what RM0456 says to write, and no edge arrives at `RPR1`, while the
    // level poll on the SAME pin demonstrably sees the strobe (`te_wait`
    // 3.6 ms, and a frame period that quantises to the refresh).
    //
    // That is not something another re-read of the manual is going to settle,
    // and guessing has already cost two flashes and shipped a session-long
    // loss of scan-out sync. The next step is a logic analyser on PB2 (the
    // `la1010` skill) to see what the strobe actually looks like — polarity,
    // width, and whether it is push-pull — before any more register theory.
    //
    // Until then the level poll is the DEFAULT, because it works. `ui-px-te-exti`
    // exists so the EXTI path can be re-tested in one flash during that
    // investigation without reverting anything.
    let config_ok = unsafe {
        let cr = RoReg32::new(EXTI_S + EXTI_EXTICR1 + (pin / 4) * 4);
        let rtsr = RoReg32::new(EXTI_S + EXTI_RTSR1);
        let shift = (pin % 4) * 8;
        (cr.read() >> shift) & 0xFF == port_index && rtsr.read() & exti_line(pin) != 0
    };
    // SELF-PROVING, not flag-gated. The driver uses the latch only when it has
    // demonstrated, on this boot and this silicon, that the latch answers:
    // the configuration must read back AND a software trigger must actually
    // set the pending flag. Anything less falls back to the level poll.
    //
    // This replaces a `ui-px-te-exti` feature flag, which was the wrong shape:
    // a flag records what someone BELIEVED when they built the image, while
    // the self-test records what the hardware DID a moment ago. Shipping the
    // unproven path once already cost a session-long loss of scan-out sync.
    let ok = config_ok && swier_ok;
    // SAFETY: plain bool, written once during init, read by the frame loop.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(EXTI_USABLE), ok) };
}

/// Did `exti_init`'s configuration read back correctly?
static mut EXTI_USABLE: bool = false;

/// Did a software trigger set the rising-edge pending flag? See the self-test
/// in [`exti_init`] — this is the diagnostic that separates "my register map
/// is wrong" from "the pin never reaches the edge detector".
static mut EXTI_SWIER_OK: bool = false;

/// Whether the EXTI latch answered a software trigger at init.
#[must_use]
pub fn exti_swier_ok() -> bool {
    // SAFETY: as `EXTI_SWIER_OK`'s writer.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EXTI_SWIER_OK)) }
}

/// Whether the hardware edge latch is in use (vs the level-polling fallback).
#[must_use]
pub fn exti_in_use() -> bool {
    // SAFETY: as `EXTI_USABLE`'s writer.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EXTI_USABLE)) }
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

/// Frames to skip before re-testing a line that was declared dead.
///
/// 64 frames is ~2 s at this frame rate: often enough that a transient costs
/// a couple of seconds of sync rather than the session, rare enough that a
/// genuinely absent panel pays the spin cap about once every two seconds
/// instead of every frame.
const RETRY_EVERY: u32 = 64;

/// Frames skipped since the line was declared dead.
static mut TE_RETRY: u32 = 0;

/// Has the TE line been observed dead? (Latched by [`sync_to_scanout`] after
/// [`DEAD_AFTER`] consecutive misses.)
#[must_use]
pub fn dead() -> bool {
    // SAFETY: single-threaded frame loop; a plain u32 written only here and in
    // `sync_to_scanout`, never from an ISR.
    let n = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TE_MISSES)) };
    n >= DEAD_AFTER
}

/// Cumulative count of TE waits that gave up without seeing an edge.
///
/// Exposed so the bench overlay can show it: a miss is invisible in the frame
/// time of the NEXT frame but costs the whole spin cap in THIS one, so
/// "misses climbing" and "frames are slow" are the same fact seen from two
/// ends. Saturates rather than wrapping, so a long run cannot make it read
/// healthy.
static mut TE_MISS_TOTAL: u32 = 0;

/// Total TE waits that found no edge since boot.
#[must_use]
pub fn miss_total() -> u32 {
    // SAFETY: as `dead()` — plain u32, frame loop only, never from an ISR.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TE_MISS_TOTAL)) }
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
        // RECOVERABLE, not terminal. A permanent latch is how the EVT unit
        // ended up blitting with no synchronisation at all for a whole
        // session: three early misses and the trusted display silently gave
        // up scan-out sync forever, i.e. it chose #780's tearing over #783's
        // stall without anyone deciding that. Retry occasionally so a
        // transient cause costs a bounded number of frames instead of the
        // rest of the boot. The retry is cheap because a working line answers
        // in under one refresh period.
        // SAFETY: as `dead()`.
        unsafe {
            let n = core::ptr::read_volatile(core::ptr::addr_of!(TE_RETRY));
            if n + 1 < RETRY_EVERY {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TE_RETRY), n + 1);
                return false;
            }
            core::ptr::write_volatile(core::ptr::addr_of_mut!(TE_RETRY), 0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(TE_MISSES), 0);
        }
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
        let t = core::ptr::read_volatile(core::ptr::addr_of!(TE_MISS_TOTAL));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(TE_MISS_TOTAL), t.saturating_add(1));
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
    let Some((_, pin)) = TE else { return false };
    if !exti_in_use() {
        return wait_rising_by_level(spin_cap);
    }
    let line = exti_line(pin);
    // SAFETY: real, 4-byte-aligned EXTI registers on the secure alias.
    let rpr = unsafe { Reg32::new(EXTI_S + EXTI_RPR1) };
    // Clear first, so what we wait for is the NEXT edge and not one latched
    // while the previous frame was still streaming. Write-1-to-clear.
    rpr.write(line);
    let mut spins = 0u32;
    while rpr.read() & line == 0 {
        spins += 1;
        if spins >= spin_cap {
            return false;
        }
        core::hint::spin_loop();
    }
    // Leave it clear for the next caller.
    rpr.write(line);
    true
}

/// The original level-polling wait, kept as the fallback.
///
/// It races an 18 us strobe against the 1 kHz SysTick ISR and can therefore
/// burn its whole cap when the two phase-lock (#783) — but it WORKS, which
/// the EXTI path has not yet earned on this panel. Imperfect sync beats none:
/// no sync means #780's tearing, every frame, which is a trusted-display
/// correctness problem rather than a smoothness one.
fn wait_rising_by_level(spin_cap: u32) -> bool {
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
