//! GPDMA1 channel 0 — the pixel-UI strip blit, secure SRAM -> SPI1_TXDR.
//!
//! WHY. `ui::px::lcd` renders a strip and then streams it, serially: measured
//! on the EVT panel 2026-10-05 at 40 MHz, render 11 ms THEN blit 19 ms, a 31 ms
//! frame against a 16 ms pacing target (`FRAME_PERIOD_MS`). The CPU spends most
//! of the blit spinning on `SR.TXP` — at 40 MHz a byte clocks out in 200 ns
//! (~32 core cycles at 160 MHz) while the poll-and-store is ~10-15. Handing the
//! stream to GPDMA frees that spin, so strip k streams while strip k+1 renders
//! and the frame becomes `max(render, blit)` instead of their sum.
//!
//! WHAT THIS CANNOT DO. A FULL 428x142 repaint has a hard wire floor of
//! 24.31 ms (60,776 px x 16 b / 40 MHz). DMA hides the render half; it cannot
//! make the panel accept bits faster. Since #780 every frame IS a full
//! repaint — the per-band digest skip is gone, because a TE-synchronised
//! frame goes out under one `set_window` and skipping a band would misplace
//! every band after it — so 24.31 ms is the floor for all of them, and the
//! panel's own 62.5 Hz refresh quantises the period to a multiple of 16.0 ms.
//! The job of this driver is therefore to get the WIRE to that floor, which
//! is what the word-beat width below is for (#790).
//!
//! EVERY REGISTER VALUE HERE WAS EXTRACTED FROM RM0456 Rev 7 AND INDEPENDENTLY
//! RE-VERIFIED against the manual, because a wrong bit is a silent fault on the
//! trusted display rather than a compile error. One such error was caught that
//! way: `spi1_tx_dma` is request **7**, not 8 — Table 137 (p687) reads
//! `6 spi1_rx_dma / 7 spi1_tx_dma / 8 spi2_rx_dma`, so 8 would have selected
//! `spi2_rx_dma` and silently streamed nothing.

use crate::board;
use crate::hw::mmio::Reg32;

/// GPDMA1, secure alias (NS alias is 0x4002_0000). RM0456 memory map.
const GPDMA1_S: u32 = 0x5002_0000;

/// The channel we own. Channels 0..=11 have the plain `CxBR1` layout (12..=15
/// add the 2D `BRC`/`SDEC` fields we do not want).
const CH: u32 = 0;
const CH_OFF: u32 = 0x80 * CH;

/// `GPDMA_CxTR1` = DSEC | DDW_LOG2(word) | SSEC | SINC | SDW_LOG2(word).
///
/// WORD source and destination width (SDW_LOG2 = DDW_LOG2 = 0b10) since #790,
/// source incrementing (SINC = 1), destination FIXED (DINC = 0, TXDR does not
/// move), single beats (SBL_1 = DBL_1 = 0), and both the source and
/// destination accesses marked SECURE.
///
/// WHY WORD AND NOT BYTE. At byte width the SPI raised one DMA request per
/// byte and the controller answered each with one AHB read plus one AHB write,
/// against the 200 ns a byte of 40 MHz wire affords — the measured wire ran at
/// ~77% of line rate (#790). A word beat carries FOUR bytes, so the same AHB
/// round trip has 800 ns to hide in, and the beat count per band drops
/// 13,632 → 3,408.
///
/// This is only legal because `SPI_CFG1.DSIZE` is 16 for the pixel stream: a
/// 32-bit access is a MULTIPLE of the 16-bit frame, so the SPI packs it into
/// two frames automatically (RM0456 §68.4.14 "The packing mode is enabled if
/// the DMA channel PSIZE value is a multiple of the data size"), lowest
/// half-word first. An access SMALLER than the frame is forbidden
/// (§68.4.14 "Configuring any DMA data access to less than the configured
/// data size is forbidden"), which is why `TR1_VAL` and `DSIZE` must move
/// together and why `start_px` is the only entry point.
///
/// `PAM` is ignored because the widths are equal (§17.8.14). `DBX`/`DHX` are
/// LIVE at word width and both 0 — no byte exchange within a half-word, no
/// half-word exchange within a word — so the word reaches TXDR verbatim and
/// the wire order is the buffer's own. `SBX` is ignored at word source width.
const TR1_VAL: u32 = 0x8002_800A;

/// `GPDMA_CxTR2` = DREQ | REQSEL(7).
///
/// REQSEL = 7 is `spi1_tx_dma`. DREQ = 1 because the requesting peripheral is
/// the DESTINATION (SRAM -> SPI1). SWREQ = 0 so the SPI's hardware request
/// drives it; BREQ = 0 (burst-level); no trigger (TRIGPOL = 00); TCEM = 00
/// (block level, which is one whole strip here since `CxLLR` = 0).
const TR2_VAL: u32 = 0x0000_0407;

/// Write-1-to-clear every flag in `GPDMA_CxFCR` (TOF/SUSPF/USEF/ULEF/DTEF/
/// HTF/TCF). HTF fires mid-strip even though we ignore it, so it must be in
/// the blanket clear or it leaks into the next transfer's status read.
const FCR_ALL: u32 = 0x0000_7F00;

const SR_TCF: u32 = 1 << 8;
const SR_HTF: u32 = 1 << 9;
const SR_DTEF: u32 = 1 << 10;
const SR_ULEF: u32 = 1 << 11;
const SR_USEF: u32 = 1 << 12;
const SR_SUSPF: u32 = 1 << 13;
/// Any of these means the transfer died; hardware has already cleared `EN`.
const SR_ERR: u32 = SR_USEF | SR_ULEF | SR_DTEF;

const CR_EN: u32 = 1 << 0;
const CR_RESET: u32 = 1 << 1;
const CR_SUSP: u32 = 1 << 2;

/// `SPI_CFG1.TXDMAEN`.
const CFG1_TXDMAEN: u32 = 1 << 15;

struct GpdmaRegs {
    rcc_ahb1enr: Reg32,
    seccfgr: Reg32,
    privcfgr: Reg32,
    cfcr: Reg32,
    csr: Reg32,
    ccr: Reg32,
    ctr1: Reg32,
    ctr2: Reg32,
    cbr1: Reg32,
    csar: Reg32,
    cdar: Reg32,
    cllr: Reg32,
    spi_cfg1: Reg32,
}

// SAFETY: every address below is a real GPDMA1 / RCC / SPI1 register on the
// secure alias, taken from RM0456's memory map and this board's `board::`
// constants. `Reg32` encapsulates the volatile access; see `hw::mmio`.
const REG: GpdmaRegs = unsafe {
    GpdmaRegs {
        rcc_ahb1enr: Reg32::new(board::RCC_S + 0x088),
        seccfgr: Reg32::new(GPDMA1_S + 0x00),
        privcfgr: Reg32::new(GPDMA1_S + 0x04),
        cfcr: Reg32::new(GPDMA1_S + 0x5C + CH_OFF),
        csr: Reg32::new(GPDMA1_S + 0x60 + CH_OFF),
        ccr: Reg32::new(GPDMA1_S + 0x64 + CH_OFF),
        ctr1: Reg32::new(GPDMA1_S + 0x90 + CH_OFF),
        ctr2: Reg32::new(GPDMA1_S + 0x94 + CH_OFF),
        cbr1: Reg32::new(GPDMA1_S + 0x98 + CH_OFF),
        csar: Reg32::new(GPDMA1_S + 0x9C + CH_OFF),
        cdar: Reg32::new(GPDMA1_S + 0xA0 + CH_OFF),
        cllr: Reg32::new(GPDMA1_S + 0xCC + CH_OFF),
        spi_cfg1: Reg32::new(board::SPI1_S + 0x08),
    }
};

/// The destination: SPI1's transmit data register.
///
/// `DDW_LOG2 = 10` makes each GPDMA beat a 32-bit write here, which is TWO
/// SPI frames because `lcd_nv3007::spi_begin_px` programs `CFG1.DSIZE = 15`
/// for the pixel stream. RM0456's SPI_TXDR note forbids an access SMALLER
/// than the configured frame size (§68.8.13) and defines an access that is a
/// multiple of it as packed, lowest half-word first (§68.4.11) — so word
/// beats are legal here and byte beats would NOT be. The register is at a
/// 4-byte-aligned address, which word beats also require (§17.8.14: "A
/// destination address must be aligned with the programmed data width").
const TXDR: u32 = board::SPI1_S + 0x20;

/// Why a blit gave up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaErr {
    /// `USEF` — a user setting error. The channel config is wrong (a null
    /// block size with no linked-list update, a misaligned burst, …).
    Setting,
    /// `ULEF` — link error.
    Link,
    /// `DTEF` — data transfer error: the bus rejected an access.
    Transfer,
    /// The poll ran past its bound without `TCF`. Treated as fatal: the
    /// channel is aborted rather than left streaming into a frame we are
    /// about to overwrite.
    Timeout,
}

/// One-time setup: clock the controller, claim channel `CH` as SECURE and
/// privileged, and write the static half of the channel configuration.
///
/// ORDER MATTERS. `SECCFGR.SECx` must be set BEFORE `PRIVCFGR.PRIVx` and
/// before `CxTR1.DSEC`/`SSEC`: once a channel is secure its privilege bit is
/// writable only from secure privileged code, and a secure write to `DSEC`/
/// `SSEC` is *ignored* while `SECCFGR.SECx` is 0 (RM0456 §17.8.10). Getting
/// this backwards yields a working channel that performs NON-SECURE accesses.
pub fn init() {
    // AHB1ENR has a non-zero reset value, so this must be read-modify-write.
    REG.rcc_ahb1enr.set_bits(1 << 0); // GPDMA1EN
    cortex_m::asm::dsb();

    REG.seccfgr.set_bits(1 << CH);
    REG.privcfgr.set_bits(1 << CH);

    REG.ctr1.write(TR1_VAL);
    REG.ctr2.write(TR2_VAL);
    // No linked list. Written explicitly rather than trusted to reset, because
    // a stale LLR is how a channel silently chains into someone else's memory.
    REG.cllr.write(0);

    // Let the SPI raise TX DMA requests. Read-modify-write: CFG1 also holds
    // MBR (the board's panel clock) and DSIZE, which must survive.
    REG.spi_cfg1.set_bits(CFG1_TXDMAEN);
}

/// Arm the channel for `px`, a run of RGB565 pixels in the panel's native
/// scan order. Returns immediately — the transfer runs in the background.
///
/// The caller owns the SPI framing: `CS` asserted, the window command sent,
/// and `spi_begin_px(px.len())` done so `CR2.TSIZE` is the FRAME count while
/// `BNDT` below is the BYTE count. Those are different numbers at 16-bit
/// frames; see `lcd_nv3007::spi_begin_px` for what an under-supply does.
/// `lcd_nv3007::stream_dma_start` is the one call site and derives both from
/// the same slice.
///
/// `px` must stay alive and unmodified until [`wait`] returns.
///
/// Takes `&[u16]` rather than `&[u8]` so the two USEF preconditions of word
/// beats are checkable at the type and the assert rather than trusted: the
/// source address must be 4-byte aligned and `BNDT` must be a multiple of the
/// 4-byte source width (RM0456 §17.8.14 — "Else, a user setting error is
/// reported and no transfer is issued"). An even pixel count gives the second;
/// the band buffers are `#[repr(align(4))]` for the first.
pub fn start_px(px: &[u16]) {
    debug_assert!(!px.is_empty(), "a null block raises USEF, not a no-op");
    let bytes = px.len() * 2;
    debug_assert!(bytes <= 0xFFFF, "BNDT is 16 bits");
    debug_assert!(
        px.as_ptr() as usize % 4 == 0,
        "word beats need a 4-byte-aligned source or the channel raises USEF"
    );
    debug_assert!(
        px.len() % 2 == 0,
        "BNDT must be a multiple of the 4-byte source data width"
    );

    REG.cfcr.write(FCR_ALL);

    // SAR/DAR/BR1 are modified by hardware as the block progresses, so all
    // three are rewritten for every transfer rather than set once in `init`.
    REG.csar.write(px.as_ptr() as u32);
    REG.cdar.write(TXDR);
    REG.cbr1.write(bytes as u32); // BNDT is BYTES, whatever the beat width

    // BARRIER. The rasteriser fills the band buffer with ORDINARY stores, and
    // volatile MMIO writes are ordered only against other volatile accesses —
    // nothing stops LLVM sinking those plain stores past this arming write,
    // and this tree builds with fat LTO and codegen-units=1, which is exactly
    // where that reordering happens. `dsb` is both a compiler and a memory
    // barrier (its `asm!` carries no `nomem`), and the same idiom already
    // guards every clock enable in this tree.
    cortex_m::asm::dsb();

    // EN last, and nothing else in CxCR: all interrupt enables stay 0 (we
    // poll), PRIO stays at its reset low/low, LAP/LSM stay 0.
    REG.ccr.write(CR_EN);
}

/// Block until the armed transfer completes, or fails, or exceeds `spin_cap`
/// polls. On any non-success the channel is aborted before returning, so it
/// cannot still be streaming into a buffer the caller is about to reuse.
///
/// `spin_cap` counts POLL ITERATIONS, not core cycles.
///
/// The caller must NOT follow an `Err` with `spi_end`: a dead transfer left
/// fewer than `TSIZE` bytes in TXDR, so the SPI's EOT never asserts and that
/// wait would never return. See `lcd_nv3007::spi_force_down`.
pub fn wait(spin_cap: u32) -> Result<(), DmaErr> {
    let mut spins = 0u32;
    loop {
        let sr = REG.csr.read();
        if sr & SR_ERR != 0 {
            // Hardware already forced EN low on these, but reset the channel
            // anyway: that also flushes the FIFO, so a partially-drained
            // transfer cannot leak bytes into the next strip's stream.
            abort();
            REG.cfcr.write(FCR_ALL);
            return Err(if sr & SR_USEF != 0 {
                DmaErr::Setting
            } else if sr & SR_ULEF != 0 {
                DmaErr::Link
            } else {
                DmaErr::Transfer
            });
        }
        if sr & SR_TCF != 0 {
            REG.cfcr.write(FCR_ALL);
            // BARRIER before the caller may reuse the buffer the channel was
            // reading: without it the next band's rasteriser stores can be
            // hoisted above this poll, since the loop is provably bounded and
            // nothing creates a data dependency on the band buffer.
            cortex_m::asm::dsb();
            return Ok(());
        }
        spins += 1;
        if spins >= spin_cap {
            abort();
            return Err(DmaErr::Timeout);
        }
    }
}

/// Bring a channel down that may still be mid-transfer.
///
/// `RESET` ALONE IS NOT ENOUGH. RM0456 §17.8.9: the reset "is effective when
/// the channel is in steady state", i.e. suspended or already disabled — a
/// channel streaming pixels is in neither, and writing `RESET` to it does
/// nothing. §17.4.4 gives the real sequence, which is what this implements:
/// suspend, wait for `SUSPF`, then reset. Anything that arms the channel again
/// must rewrite `BR1`/`SAR`/`DAR`, which [`start`] does unconditionally.
pub fn abort() {
    // WHOLE-REGISTER write, not read-modify-write: an RMW reads EN back and
    // writes it again, which on a channel that completed between the caller's
    // status read and this call would re-arm it. Every other CxCR field is 0
    // by design here, so nothing is lost.
    REG.ccr.write(CR_SUSP);
    // Bounded: a wedged channel must not wedge the display loop too.
    let mut spins = 0u32;
    while REG.csr.read() & SR_SUSPF == 0 && spins < 100_000 {
        spins += 1;
    }
    REG.ccr.write(CR_RESET);
    REG.cfcr.write(FCR_ALL);
}

/// True once `init` has run and the SPI will raise TX DMA requests.
#[must_use]
pub fn armed() -> bool {
    REG.spi_cfg1.read() & CFG1_TXDMAEN != 0
}

/// `HTF` is set halfway through a block. We ignore it, but it is named here so
/// the blanket clear in [`FCR_ALL`] is traceable to a flag rather than a magic
/// constant.
#[allow(dead_code)]
const _HTF_IS_IGNORED_BUT_CLEARED: u32 = SR_HTF;
