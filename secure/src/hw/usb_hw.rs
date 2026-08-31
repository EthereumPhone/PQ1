//! USB OTG FS hardware initialization for STM32U585.
//!
//! Common to both boards: PA11/PA12 as D-/D+ (AF10), the VDDUSB supply
//! monitor (`PWR_SVMCR.USV`), the OTG FS clock and reset, and handing the
//! USB pads to the non-secure world.
//!
//! **Board-dependent:** `iota2` additionally brings up UCPD1 for USB Type-C
//! CC detection (PA15/PB15) and drives the TCPP03-M20 port-protection enable
//! (PB5). `pq1` does neither — no CC line reaches the MCU there (an AW35602
//! owns CC and orientation with its enable strapped on-board), and all three
//! of those pins carry something else: PA15 is the OPTIGA reset, PB5 the
//! SE050 enable, PB15 the display backlight. Those paths are `#[cfg]`-ed out
//! rather than remapped, because there is no counterpart to remap them to.
//!
//! Which pads go non-secure is likewise a board fact — `USB_NS_PINS_A` /
//! `USB_NS_PINS_B` in `board/{iota2,pq1}.rs`, guarded by the `const assert!`s
//! in `board/mod.rs` that reject a mask overlapping the board's reserved
//! lines. Enumeration on pq1 was confirmed on silicon with only PA11/PA12
//! handed over (`GPIOA_SECCFGR` readback `0xe7ff` — PA15 still secure).
//!
//! All configuration is done from the secure world before the non-secure
//! USB stack starts.  The USB OTG peripheral itself is marked non-secure
//! by GTZC TZSC (see sau.rs).

use crate::board;
use crate::hw::mmio::Reg32;

// ---------------------------------------------------------------------------
// RCC registers — SECURE alias required for TZEN=1 (GPIO clock enables
// are secure-only; writes via NS alias 0x4602_xxxx are silently ignored).
// ---------------------------------------------------------------------------
const RCC_S: u32 = 0x5602_0C00;
// Note: USB OTG FS uses ICLK (shared with RNG), already set to HSI48 in rcc.rs.

// ---------------------------------------------------------------------------
// PWR registers (secure alias — NS writes are silently ignored)
// ---------------------------------------------------------------------------
const PWR: u32 = 0x5602_0800;

// PWR_SVMCR bits (from stm32u585xx.h: PWR_SVMCR_USV_Pos = 28)
const USV: u32 = 1 << 28; // VDDUSB supply valid (removes electrical isolation)

// ---------------------------------------------------------------------------
// GPIOA registers (secure alias — GPIOA is secure by default with TZEN=1)
// ---------------------------------------------------------------------------
const GPIOA_S: u32 = 0x5202_0000;

// GPIOB registers (secure alias)
const GPIOB_S: u32 = 0x5202_0400;

// ---------------------------------------------------------------------------
// UCPD1 registers — secure alias (APB1 peripherals are secure with TZEN=1;
// writes via NS alias 0x4000_xxxx are silently ignored).
// ---------------------------------------------------------------------------
const UCPD1: u32 = 0x5000_DC00;

struct UsbHwRegs {
    rcc_ahb2enr1: Reg32,
    rcc_apb1enr2: Reg32,
    rcc_ahb2rstr1: Reg32,
    pwr_svmcr: Reg32,
    pwr_ucpdr: Reg32,
    gpioa_moder: Reg32,
    gpioa_ospeedr: Reg32,
    gpioa_afrh: Reg32,
    gpioa_seccfgr: Reg32,
    gpiob_moder: Reg32,
    gpiob_ospeedr: Reg32,
    gpiob_bsrr: Reg32,
    gpiob_seccfgr: Reg32,
    ucpd1_cfg1: Reg32,
    ucpd1_cr: Reg32,
}

// SAFETY: each address is a real, 4-byte-aligned MMIO register touched
// once during boot by this driver, in the single-threaded secure world.
// Shared RCC and GPIO registers are accessed via disjoint-bit RMW so
// concurrent (sequential, non-overlapping) edits from other drivers are
// safe. USB endpoint RAM / FIFOs are deliberately NOT wrapped here —
// they require richer types than `Reg32` (see hw::mmio module docs).
const REG: UsbHwRegs = unsafe {
    UsbHwRegs {
        rcc_ahb2enr1: Reg32::new(RCC_S + 0x8C),
        rcc_apb1enr2: Reg32::new(RCC_S + 0xA0),
        rcc_ahb2rstr1: Reg32::new(RCC_S + 0x64),
        pwr_svmcr: Reg32::new(PWR + 0x10),
        pwr_ucpdr: Reg32::new(PWR + 0x2C),
        gpioa_moder: Reg32::new(GPIOA_S + 0x00),
        gpioa_ospeedr: Reg32::new(GPIOA_S + 0x08),
        gpioa_afrh: Reg32::new(GPIOA_S + 0x24),
        gpioa_seccfgr: Reg32::new(GPIOA_S + 0x30),
        gpiob_moder: Reg32::new(GPIOB_S + 0x00),
        gpiob_ospeedr: Reg32::new(GPIOB_S + 0x08),
        gpiob_bsrr: Reg32::new(GPIOB_S + 0x18),
        gpiob_seccfgr: Reg32::new(GPIOB_S + 0x30),
        ucpd1_cfg1: Reg32::new(UCPD1 + 0x00),
        ucpd1_cr: Reg32::new(UCPD1 + 0x0C),
    }
};

/// Initialize USB OTG FS hardware from the secure world.
///
/// This must be called after `rcc::init()` (HSI48 is already running)
/// and after `sau::init()` (GTZC TZSC has marked USB OTG as NS).
///
/// Pin mapping — **iota2** (B-U585I-IOT02A / MB1551, UM2839 Tables 8+9),
/// where the USB-C connector goes through a **TCPP03-M20** port-protection
/// chip (U8) that must be enabled before the data lines are connected:
///   PA11 = USB_OTG_FS_DM (D-)    — direct to CN1
///   PA12 = USB_OTG_FS_DP (D+)    — direct to CN1
///   PA15 = UCPD1_CC1              — through TCPP03 to CN1
///   PB15 = UCPD1_CC2              — through TCPP03 to CN1
///   PB5  = TCPP03 EN (drive HIGH to enable)
///
/// Pin mapping — **pq1** (AL_A66_MB_V10):
///   PA11 = USB_OTG_FS_DM (D-)    — through the AW35602 to the USB-C port
///   PA12 = USB_OTG_FS_DP (D+)    — through the AW35602 to the USB-C port
/// and nothing else: steps 8 and 9 below are compiled out, because PA15,
/// PB5 and PB15 belong to the secure elements and the display there.
///
/// # Safety
/// Direct register access.  Must be called exactly once during boot.
pub unsafe fn init() {
    // ---- 1. Enable GPIO clocks: GPIOA, GPIOB, GPIOE (AHB2ENR1 bits 0,1,4) ----
    // GPIOAEN | GPIOBEN. (GPIOEEN was also set here; no USB pin is on port E
    // on either board, and port E is not even bonded on pq1's 48-pin part.)
    REG.rcc_ahb2enr1.set_bits((1 << 0) | (1 << 1));
    cortex_m::asm::dsb();

    // ---- 2. Enable VDDUSB supply monitoring (PWR_SVMCR.USV) ----
    REG.pwr_svmcr.set_bits(USV);
    cortex_m::asm::dsb();

    // ---- 3. Enable USB OTG FS clock (AHB2ENR1 bit 14) ----
    REG.rcc_ahb2enr1.set_bits(1 << 14);
    cortex_m::asm::dsb();

    // USB 48 MHz clock: uses ICLK (shared with RNG), already set to HSI48 by rcc::init().

    // ---- 4. Reset USB OTG FS peripheral (AHB2RSTR1 bit 14) ----
    REG.rcc_ahb2rstr1.set_bits(1 << 14);
    cortex_m::asm::dsb();
    REG.rcc_ahb2rstr1.clear_bits(1 << 14);
    cortex_m::asm::dsb();

    // ---- 6. Mark USB pins as non-secure (per-pin GPIO security) ----
    // With TZEN=1, all GPIO pins default to secure (SECCFGR = 0xFFFF).
    // The USB OTG FS peripheral runs in NS domain, so it can only drive
    // pins that are marked as non-secure. Clear the security bits for
    // PA11 (D-), PA12 (D+), PA15 (CC1) and PB5 (TCPP03 EN), PB15 (CC2).
    // Hand the USB pads — and only those — to the non-secure world.
    //
    // WHICH pads is a board fact: see `USB_NS_PINS_A` / `USB_NS_PINS_B` in
    // `board/{iota2,pq1}.rs`, and the exact `const assert!`s in `board/mod.rs`
    // that reject any mask overlapping this board's reserved lines. iota2
    // hands over five pins (its UCPD CC pair and the TCPP03 enable as well);
    // pq1 hands over two, because there those three pins are the secure
    // elements' reset/enable and the trusted display's backlight.
    //
    // Deliberately ONE unconditional call per port rather than a cfg'd pair:
    // a second call site is how extra pins would leak to NS, so the test suite
    // counts these, and a zero mask is a harmless same-value write.
    REG.gpioa_seccfgr.clear_bits(board::USB_NS_PINS_A);
    REG.gpiob_seccfgr.clear_bits(board::USB_NS_PINS_B);

    #[cfg(feature = "debug-log")]
    {
        // Comprehensive register dump for USB bring-up debugging
        secure_log!(
            "[S][USB] RCC_AHB2ENR1=0x{:08x}",
            REG.rcc_ahb2enr1.read()
        );
        secure_log!(
            "[S][USB] GPIOA_MODER=0x{:08x} (expect PA11/12=AF=0b10)",
            REG.gpioa_moder.read()
        );
        secure_log!(
            "[S][USB] GPIOA_AFRH =0x{:08x} (expect PA11/12=AF10=0xA)",
            REG.gpioa_afrh.read()
        );
        // Read several offsets around 0x30 to find SECCFGR
        for off in [0x28u32, 0x2C, 0x30, 0x34] {
            let addr = GPIOA_S + off;
            // SAFETY: GPIOA register bank, 4-byte-aligned read for debug log.
            let val = unsafe { core::ptr::read_volatile(addr as *const u32) };
            secure_log!(
                "[S][USB] GPIOA+0x{:02x}=0x{:08x}", off, val
            );
        }
    }

    // ---- 7. Configure PA11 (D-) and PA12 (D+) as AF10 (USB), very-high speed ----
    REG.gpioa_moder.modify(|v| {
        (v & !(0b11 << 22) & !(0b11 << 24)) | (0b10 << 22) | (0b10 << 24)
    });

    REG.gpioa_ospeedr.set_bits((0b11 << 22) | (0b11 << 24));

    // AFRH: PA11 = AF10, PA12 = AF10
    REG.gpioa_afrh.modify(|v| {
        (v & !(0xF << 12) & !(0xF << 16)) | (10 << 12) | (10 << 16)
    });

    #[cfg(feature = "debug-log")]
    {
        secure_log!(
            "[S][USB] After GPIO config: MODER=0x{:08x} AFRH=0x{:08x}",
            REG.gpioa_moder.read(), REG.gpioa_afrh.read()
        );
    }

    // ---- 8. Enable TCPP03 (PB5 HIGH) ----
    // The TCPP03-M20 (U8) provides ESD protection and CC routing for the
    // USB-C connector (CN1).  Must be enabled for both USB-A→C and C→C cables.
    // iota2 only — see enable_tcpp03. On pq1 PB5 is the SE050 enable, owned
    // by hw::se_power; there is no TCPP03 on that board.
    #[cfg(not(feature = "board-pq1"))]
    enable_tcpp03();

    // ---- 9. UCPD1 CC detection (PA15/PB15) ----
    // iota2 only — see init_ucpd. pq1 has no CC lines routed to the MCU.
    #[cfg(not(feature = "board-pq1"))]
    init_ucpd();
}

/// Drive PB5 HIGH to enable the TCPP03-M20 port protection chip.
///
/// **iota2 only.** On pq1 this pin (PB5) is `SE1_EN`, the SE050 enable owned
/// by `hw::se_power`, and there is no TCPP03 on that board — an AW35602
/// handles port protection with its enable strapped on-board.
#[cfg(not(feature = "board-pq1"))]
fn enable_tcpp03() {
    // PB5: output, push-pull, very-high speed, no pull
    // MODER bits [11:10] = 01 (output)
    REG.gpiob_moder.modify(|v| (v & !(0b11 << 10)) | (0b01 << 10));

    // OSPEEDR bits [11:10] = 11 (very high speed)
    REG.gpiob_ospeedr.set_bits(0b11 << 10);

    // BSRR: set PB5 HIGH. BSRR is atomic-set (write-1-to-set, no read needed).
    REG.gpiob_bsrr.write(1 << 5);

    // Small delay for TCPP03 to initialize
    for _ in 0..100_000 {
        cortex_m::asm::nop();
    }
}

/// Soft-disconnect the device from USB, then `SCB::sys_reset`. Does
/// not return.
///
/// **What it does (and what it doesn't).** Setting `OTG_DCTL.SDIS=1`
/// drops the D+ pull-up so the host's USB 2.0 layer observes a clean
/// `USB disconnect` event in `dmesg` (TDDIS ≥ 2.5 µs per USB 2.0
/// §7.1.7.3). On B-U585I-IOT02A powered through the USB-C cable, this
/// is **not sufficient by itself** to make the host *re-attach* the
/// device on the post-reset boot — VBUS stays continuously asserted
/// (the host is supplying it), so Linux's typec subsystem treats the
/// brief D+/CC transitions as transient noise rather than a real
/// unplug, and the port stays bound to the pre-reset device session.
/// `lsusb` therefore still requires a physical cable replug to refresh
/// after a firmware-initiated reset; see
/// `reference_usb_c_warm_reset_edge` for the full topology analysis.
///
/// **Why we still do this.** Two real benefits:
///   1. Companion / host apps that watch for `USB disconnect` see a
///      clean event instead of a transport-level error mid-transaction.
///   2. On topologies where VBUS *does* drop across the reset (USB-A
///      host, USB-C-via-a-hub-with-PD-cycle, dev boards powered from
///      ST-LINK with USB-C dongle data-only), the host re-enumerates
///      automatically without a replug.
///
/// **Path classification.** USB OTG FS is GTZC-marked NS — the
/// canonical access path from secure code is the NS alias
/// `0x4204_0000` (same pattern as the FLASH-NSCR-via-NS-alias finding
/// in `reference_stm32u5_nscr_ns_alias`).
///
/// # Safety
/// Caller is committed to resetting the chip. Mutates the NS-mapped
/// USB OTG controller via a volatile RMW on `OTG_DCTL`. If OTG isn't
/// powered (boot-time pre-NS-init), the write hits a register block
/// whose default has SDIS=1 anyway — no-op, no observable host detach,
/// but still safe.
#[inline(never)]
pub unsafe fn soft_disconnect_then_reset() -> ! {
    // USB OTG FS NS alias (matches `nonsecure/src/usb/mod.rs:USB_OTG_BASE`).
    const OTG_NS: u32 = 0x4204_0000;
    // OTG_DCTL @ +0x804 (STM32U5 RM §72 / RM0456). Bit 1 = SDIS.
    const OTG_DCTL: u32 = OTG_NS + 0x804;
    const SDIS: u32 = 1 << 1;

    // SAFETY: NS-mapped peripheral, single-threaded secure-world
    // caller on an about-to-reset path. RMW preserves the rest of
    // DCTL (none of which matters past the imminent reset).
    // RMW via the typed MMIO handle (hw::mmio) — no raw volatile (unsafe
    // taxonomy). Preserves the rest of DCTL (none of which matters past
    // the imminent reset).
    Reg32::new(OTG_DCTL).modify(|v| v | SDIS);

    // ~20 ms hold so the host's USB 2.0 layer registers the detach.
    // Empirically tested on B-U585I-IOT02A + Linux: this is enough
    // for `dmesg` to log a clean `USB disconnect` event. It is NOT
    // enough on its own to convince Linux's typec subsystem to drop
    // the port and re-enumerate when VBUS stays asserted by the host
    // — that's a USB-C topology constraint UM2839 documents no
    // jumper to break (no SB isolates VBUS at CN1). Tried-and-failed
    // mitigations (don't re-add without re-testing): SDIS +
    // `OTG_GCCFG.PWRDWN=0`, SDIS + UCPD `CCENABLE=0`, SDIS + PA12-as-
    // GPIO-LOW, SDIS + PA12-LOW + PB5-LOW (TCPP03 disable), various
    // 10 ms → 500 ms holds. None re-attach without a physical replug
    // while VBUS stays continuously asserted. See memory
    // `reference_usb_c_warm_reset_edge` for the full topology trace.
    // ~3.2 M `nop`s at 160 MHz.
    for _ in 0..3_200_000 {
        cortex_m::asm::nop();
    }

    cortex_m::peripheral::SCB::sys_reset();
}

/// Hold the USB-C CC lines fully OPEN long enough that the host's
/// Type-C port controller registers a real detach (past tCCDebounce
/// ≈ 100–200 ms), then `sys_reset`. On the post-reset boot the
/// dead-battery Rd re-engages (hardware default), which the host sees
/// as a fresh attach → re-enumeration WITHOUT a physical replug.
///
/// This is the task-#26 fix for the USB-C warm-reset edge. A bare
/// `sys_reset` leaves the host port stuck (VBUS stays asserted, so the
/// typec layer keeps the port bound and never re-probes). HW-validated
/// on B-U585I-IOT02A via the `fwup-transport-hw-iwdg` wipe-trigger:
/// the kernel logs a clean detach + `new full-speed USB device`
/// (1209:7051) re-attach with no physical replug, and the device is
/// stable afterward. End-to-end latency ≈ 20–25 s (dominated by device
/// boot; the host typec/VBUS cycle adds a few seconds).
///
/// Earlier failed attempts held CC open only ~200 ms (under
/// tCCDebounce margin) and/or drove the TCPP03 EN (PB5) low — which
/// puts the TCPP03 into *dead-battery mode* and PRESENTS Rd, the exact
/// opposite of opening CC. The working recipe leaves EN high
/// (passthrough) and removes BOTH device-side Rd sources below.
///
/// To open CC we must remove BOTH Rd sources the device can present:
///   * UCPD's own Rd — clear `UCPD1_CR.CCENABLE` (bits 11:10) +
///     `ANAMODE` (bit 9).
///   * The STM32 dead-battery Rd — set `PWR_UCPDR.UCPD_DBDIS` (bit 0).
/// We deliberately do NOT touch the TCPP03 EN (PB5): driving it low
/// puts the TCPP03 into *dead-battery mode*, which PRESENTS Rd — the
/// opposite of what we want. Leaving EN high passes the (now-open)
/// UCPD CC state straight through to the connector.
///
/// Does not return.
///
/// **iota2 only**, and dead code even there: it has NO caller anywhere in the
/// tree (`grep` finds only doc mentions and a forbidden-string assertion
/// against a different file). On pq1 it would touch UCPD1 — which that board
/// never enables — so it would be a silent ~1.5 s stall followed by a reset.
///
/// # Safety
/// Secure-alias UCPD1 + PWR registers (same as `init_ucpd`), single-
/// threaded about-to-reset path.
#[cfg(not(feature = "board-pq1"))]
#[inline(never)]
pub unsafe fn cc_open_then_reset() -> ! {
    // UCPD1 CR (secure alias, matches `init_ucpd`).
    const UCPD1_CR: u32 = 0x5000_DC00 + 0x0C;
    const CC_ENABLE_MASK: u32 = 0b11 << 10; // CCENABLE[1:0]
    const ANAMODE: u32 = 1 << 9; // sink Rd
    // PWR_UCPDR (secure alias). UCPD_DBDIS = bit 0.
    const PWR_UCPDR: u32 = 0x5602_0800 + 0x2C;
    const UCPD_DBDIS: u32 = 1 << 0;
    // OTG_DCTL.SDIS — also drop the D+ pull-up (USB-2 layer detach)
    // alongside the CC open.
    const OTG_DCTL: u32 = 0x4204_0000 + 0x804;
    const SDIS: u32 = 1 << 1;

    // Typed MMIO (hw::mmio) RMW — no raw volatile.
    // 1. Drop the USB-2 D+ pull-up.
    Reg32::new(OTG_DCTL).modify(|v| v | SDIS);
    // 2. Drop UCPD's Rd (clear CCENABLE + ANAMODE).
    Reg32::new(UCPD1_CR).modify(|v| v & !CC_ENABLE_MASK & !ANAMODE);
    // 3. Disable the STM32 dead-battery Rd (idempotent — init set
    //    this too, but a defensive re-assert in case anything reset
    //    it). With UCPD Rd gone AND dead-battery disabled AND
    //    TCPP03 still enabled (passthrough), CC reads open.
    Reg32::new(PWR_UCPDR).modify(|v| v | UCPD_DBDIS);

    // Hold CC open ~1.5 s — comfortably past the host's tCCDebounce
    // (100–200 ms) + any port-controller settle, so the typec layer
    // tears the port down to "unattached". ~240 M nops at 160 MHz.
    for _ in 0..240_000_000 {
        cortex_m::asm::nop();
    }

    cortex_m::peripheral::SCB::sys_reset();
}

/// Drop the USB 2.0 D+ pull-up via `OTG_DCTL.SDIS=1`. Used at the top
/// of the "halt + wait for user to replug" paths in
/// `cmd_fw_commit::run` and `cmd_fw_begin::arm_wipe_and_reset` so
/// companion / host apps see a clean `USB disconnect` event in dmesg
/// before the OLED-displayed "Replug USB" prompt becomes the
/// human-facing signal.
///
/// Does NOT `sys_reset` (use [`soft_disconnect_then_reset`] for that).
/// Does NOT wait — caller is responsible for any settle delay.
///
/// # Safety
/// Mutates the NS-mapped USB OTG controller via a volatile RMW on
/// `OTG_DCTL`. If OTG isn't powered the write is a no-op on reset-
/// state `SDIS=1`.
#[inline(never)]
pub unsafe fn soft_disconnect() {
    const OTG_DCTL: u32 = 0x4204_0000 + 0x804;
    const SDIS: u32 = 1 << 1;
    // Typed MMIO (hw::mmio) RMW — no raw volatile.
    Reg32::new(OTG_DCTL).modify(|v| v | SDIS);
}

/// Initialize UCPD1 for USB Type-C CC detection (sink/device mode).
///
/// On the B-U585I-IOT02A (UM2839 Table 8):
///   PA15 = UCPD1_CC1 (analog)
///   PB15 = UCPD1_CC2 (analog)
///
/// We configure UCPD1 as a sink so the host detects Rd on CC and provides VBUS.
///
/// **iota2 only.** pq1 routes NO CC line to the MCU (an AW35602 owns CC and
/// orientation), so this would be dead silicon there — and PA15/PB15, which
/// it puts into ANALOG mode, are `SE_RST` and `LCM_EN` on that board.
/// Compiled out rather than remapped: there is no counterpart.
#[cfg(not(feature = "board-pq1"))]
fn init_ucpd() {
    // Enable UCPD1 clock (APB1ENR2 bit 23)
    REG.rcc_apb1enr2.set_bits(1 << 23);
    cortex_m::asm::dsb();

    // Configure PA15 as analog (UCPD CC1)
    // MODER bits [31:30] for PA15 = 11 (analog)
    REG.gpioa_moder.set_bits(0b11 << 30);

    // Configure PB15 as analog (UCPD CC2)
    // MODER bits [31:30] for PB15 = 11 (analog)
    REG.gpiob_moder.set_bits(0b11 << 30);

    // UCPD1 CFG1: prescaler and timing for CC detection.
    // Values follow ST's reference configuration for HSI16.
    let cfg1: u32 = (13 << 0)   // HBITCLKDIV
        | (16 << 6)              // IFRGAP
        | (7 << 11)              // TRANSWIN
        | (0b01 << 17)           // PSC_USBPDCLK = /2 (HSI16/2 = 8 MHz)
        | (1 << 31);             // UCPDEN (enable UCPD)
    REG.ucpd1_cfg1.write(cfg1);
    cortex_m::asm::dsb();

    // UCPD1 CR: enable CC PHYs and connect Rd pull-downs (sink mode).
    // Bit 9:     ANAMODE  = 1  (sink → connects 5.1kΩ Rd on CC lines)
    // Bits 11:10 CCENABLE = 11 (both CC1 and CC2 PHYs enabled)
    //
    // IMPORTANT: bits 20/21 are **CC1TCDIS / CC2TCDIS = the Type-C voltage
    // *detector* disables**, NOT a dead-battery control (verified against
    // ST's LL driver: `LL_UCPD_TypeCDetectionCC1Disable() = SET_BIT(
    // CC1TCDIS)`). A prior version set them to 1 — which BLINDED the CC
    // voltage detectors (UCPD_SR.TYPEC_VSTATE stuck at 0, no attach ever
    // detected). We leave them CLEAR so the detectors run.
    let cr: u32 = (0b11 << 10)  // CCENABLE: both CC lines enabled
        | (1 << 9);              // ANAMODE: sink (Rd pull-down)
    REG.ucpd1_cr.write(cr);
    cortex_m::asm::dsb();

    // Disable the DEAD-BATTERY pull-downs the CORRECT way: PWR_UCPDR.
    // UCPD_DBDIS (bit 0). Mirrors `LL_PWR_DisableUCPDDeadBattery()` =
    // `SET_BIT(PWR->UCPDR, PWR_UCPDR_UCPD_DBDIS)` (PWR @ 0x5602_0800,
    // UCPDR @ +0x2C). After reset the dead-battery Rd is engaged (so an
    // unpowered/just-booted sink presents Rd); now that UCPD presents its
    // own Rd (ANAMODE=1) we release the dead-battery so it doesn't sit in
    // PARALLEL with the UCPD Rd and shift the CC voltage the host reads
    // (which is what broke USB-C-to-USB-C detection). Done AFTER the CR
    // config so there is no window with no Rd presented.
    REG.pwr_ucpdr.set_bits(1 << 0); // UCPD_DBDIS
    cortex_m::asm::dsb();

    // Settling delay for CC pull-downs
    for _ in 0..50_000 {
        cortex_m::asm::nop();
    }
}
