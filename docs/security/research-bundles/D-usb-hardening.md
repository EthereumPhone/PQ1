# Research Prompt D — USB Stack Hardening for USB-C-Only Hardware Wallet

## Research question

Audit the known attack surface of USB-stack implementations on STM32
Cortex-M MCUs and recommend hardening for our situation (USB-C only,
custom USB stack handling both HID with Ledger-compatible APDU framing
and a PQSigner-native protocol on a vendor class).

Specifically:

1. Known CVEs and proof-of-concept exploits against STM32 USB
   peripherals 2023-2025 (STM32Cube USB libraries, RTOS drivers, HID
   descriptor parsers). Include Colin O'Flynn's EMFI-on-USB work and
   descendants. Distinguish what applies to our custom stack vs what
   only affects STM32Cube.
2. Highest-risk USB descriptor parsing paths for a custom stack that
   handles HID + custom vendor protocol. Common lurking bugs
   (endpoint count overflow, string descriptor length misparse,
   SETUP-stage DMA corruption, etc.).
3. Minimum set of sanity checks between the USB ISR and our firmware's
   APDU handler to resist malformed/adversarial host behaviour.
4. Architectural evaluation: is there a defensible argument for
   implementing USB in a separate co-processor (tiny MCU beside the
   STM32 with a serial shim) to shrink attack surface on the
   crypto-hosting chip? What do real production wallets do?

Deliverables: CVE catalogue with applicability notes, ranked hardening
checklist, architectural recommendation on co-processor USB.


---

## Project context (condensed; current sources are linked in each bundle)

**What this is.** PQSigner OS: a post-quantum ERC-4337 smart-wallet
firmware for STM32U585 (Cortex-M33 + ARM TrustZone) on the
B-U585I-IOT02A Discovery board. Only external interface is USB-C. No
Bluetooth, no UART, no debug access in production (RDP Level 2
planned).

**Secure elements.** **Dual**-SE architecture, not single:
- **NXP SE050** (I2C1, addr `0x48`, EAL6+): stores `half_E` of XOR-
  split BIP-39 entropy. Hardware PIN gate via UserID (10 attempts).
- **Infineon OPTIGA Trust M V3** (I2C1, addr `0x30`, EAL6+): stores
  `half_O`. Shielded Connection (AES-128-CCM-8) for bus encryption.

Both chips are mandatory. Neither alone reveals any bit of the seed —
only `half_O XOR half_E = entropy`.

**Why signing must run on the Cortex-M33, not the SE.** Bootstrap and
slot signatures both use the project's **SPHINCS+C10** hash-based
post-quantum scheme; there is no classical or ML-DSA signer. No
commercial secure element currently computes it. The SEs are gated
storage, not signing accelerators. The seed
therefore transits STM32 secure-world SRAM during the active signing
window (~120 s idle timeout, then zeroize). TrustZone SAU+GTZC isolates
this from the non-secure world.

**TrustZone partition.** Secure world (flash bank 1, SRAM1) owns all
crypto, PIN, persistent secrets, transaction decoding, and the trusted
NV3007 LCD UI. Non-secure world owns USB transport. Crossings go through
the fixed NSC gateway with pointer validation and TOCTOU-safe copy-in.

**Power supervision state.** BOR, PVD, ECC (except SRAM1 which is
always-on), IWDG all at factory defaults. Stage 1 of a 5-stage brownout
roadmap added reset-cause classification + verified flash writes; the
rest is planned. `make stm32-harden-opts` is a one-time option-byte
setup target (sets BOR3 + SRAM2_RST=0) but has not been run yet. See
`docs/security/brownout-hardening.md` for the full plan.

**VBAT.** Production hardware uses a **0.47 F supercap** (not a
battery) on VBAT via Schottky from Vdd. Bounded retention (~12-24 h
after unplug). The dev board has an unpopulated CR1220 holder whose
pads can be reused for a tack-soldered supercap during validation.
Indefinite-retention tamper monitoring during long cold storage is
explicitly out of scope — the 24-word BIP-39 backup is the long-term
security anchor.

**Accepted trade-offs (research that contradicts these is not useful):**
1. Seed transits STM32 SRAM during signing. Unavoidable until SE can
   do SLH-DSA.
2. SE050's value is hardware PIN gate + XOR storage, not "seed never
   leaves silicon." Don't suggest "do all signing on SE050" — it
   can't.
3. USB-C is the only external interface.
4. Out of scope: EAL6+ invasive decapping attacks.

**Dark Skippy and similar nonce-exfil attacks do NOT apply.** Hash-
based SLH-DSA has no nonce. Don't chase this.

**Current SCP03 lifecycle.** The SE050 SCP03 channel is active (every TX
has CLA=0x84). Factory defaults are not an acceptable production state:
the factory transport credentials are derived from the per-device OTP master
burned for that handoff. After RDP2 self-lock and the BHK first write, the
implemented first-field candidate rotates SE050 SCP03/admin credentials to
the final BHK axis and rotates the OPTIGA E140 PBS to the final DHUK derivation
bound to a fresh TRNG salt persisted in the page-127 journal. Page 126 holds
only the DHUK-wrapped BHK. This candidate is not a production-approved
ceremony: authenticated per-unit handoff and authenticate-before-rotate,
durable old/new/KVN recovery, the exact E140 lifecycle-versus-final-rotation
order, and silicon receipts remain OPEN.

---

## Style guidance

- Cite specific RM0456 / AN5342 / ES0499 / UM11225 / Infineon doc
  sections where possible. Prefer "per AN5342" over inventing
  revision numbers you aren't sure of.
- Say "I don't know" on things not answerable from public sources,
  rather than guessing.
- Give concrete, implementable code / register values — hand-wave
  recommendations without specifics are not useful.
- Respect the architecture above. Suggestions that require signing
  on the SE are category errors for this project.

---


## Relevant code and design


### `secure/src/hw/usb_hw.rs`

```rust
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
// UCPD1 registers — secure alias.
//
// This block used to claim "APB1 peripherals are secure with TZEN=1; writes via
// NS alias 0x4000_xxxx are silently ignored". That was false, and it was the
// kind of false that reads as a guarantee: TZEN=1 secures GPIO by default, but
// APB peripheral attribution belongs to GTZC TZSC, and UCPD1's bit (SECCFGR1
// bit 19) was never in `sau::configure_gtzc`'s image — so the NS alias was
// live. It is set now, on both boards, and pinned by the exact-equality asserts
// in `sau.rs`; see the rationale on `SECCFGR1_UCPD1_BIT` there for why pq1
// cares even though it compiles `init_ucpd` out (PA15/PB15 are SE_RST and
// LCM_EN on that board, and UCPD1 is a second handle on those pads that
// GPIOx_SECCFGR does not cover).
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

```


### `nonsecure/src/usb/mod.rs`

```rust
//! USB HID transport for PQSigner.
//!
//! Implements a Custom HID device (Usage Page 0xFFA0) with Ledger-compatible
//! APDU-over-HID framing.  Runs entirely in the non-secure TrustZone world.

pub mod hid;
pub mod transport;
pub mod commands;

use synopsys_usb_otg::{UsbBus, UsbPeripheral, PhyType};
use usb_device::prelude::*;

// ---------------------------------------------------------------------------
// STM32U585 USB OTG FS peripheral
// ---------------------------------------------------------------------------

/// USB OTG FS peripheral on STM32U585 (DWC2 IP, Full-Speed).
///
/// Zero-sized unit struct — `Send + Sync` are auto-derived.
pub struct Stm32U5UsbOtgFs;

/// USB OTG FS register base (NS alias).
const USB_OTG_BASE: u32 = 0x4204_0000;

/// GCCFG register (Global Core Configuration).
const GCCFG: *mut u32 = (USB_OTG_BASE + 0x38) as *mut u32;
/// GOTGCTL register (OTG Control and Status).
const GOTGCTL: *mut u32 = (USB_OTG_BASE + 0x00) as *mut u32;

unsafe impl UsbPeripheral for Stm32U5UsbOtgFs {
    const REGISTERS: *const () = USB_OTG_BASE as *const ();

    const HIGH_SPEED: bool = false;

    /// FIFO depth: 320 words = 1280 bytes (from Embassy's STM32U5 config).
    const FIFO_DEPTH_WORDS: usize = 320;

    /// 6 bidirectional endpoints (EP0..EP5).
    const ENDPOINT_COUNT: usize = 6;

    fn enable() {
        // Clocks, GPIO, and VDDUSB are already configured by the secure world.
        // VBUS configuration happens in configure_vbus_u5() AFTER the driver's
        // core soft-reset (which clears GOTGCTL).
    }

    fn ahb_frequency_hz(&self) -> u32 {
        160_000_000 // PLL1: HSI16 x 20 / 2 = 160 MHz
    }

    fn phy_type(&self) -> PhyType {
        PhyType::InternalFullSpeed
    }
}

/// Type alias for the USB bus allocator.
pub type UsbBusType = UsbBus<Stm32U5UsbOtgFs>;

/// Static endpoint memory for the DWC2 driver (must be 'static mut).
static mut EP_MEMORY: [u32; 320] = [0u32; 320];

/// Static USB bus allocator (initialized once, lives forever).
static mut USB_BUS_ALLOC: Option<usb_device::bus::UsbBusAllocator<UsbBusType>> = None;

/// Complete USB state: device + HID class + transport + command router.
pub struct UsbStack {
    pub device: UsbDevice<'static, UsbBusType>,
    pub transport: transport::Transport,
    pub commands: commands::CommandRouter,
}

/// Configure VBUS sensing for STM32U5 DWC2.
///
/// Must be called AFTER the synopsys-usb-otg driver's `enable()` runs
/// (triggered by the first `poll()` call), because the driver's core
/// soft-reset clears GOTGCTL to defaults.
///
/// STM32U5 DWC2 core ID is not recognized by synopsys-usb-otg v0.4,
/// so VBUS configuration falls through to a no-op.  We fix it here:
/// disable VBUS detection and force B-session valid.
pub unsafe fn configure_vbus_u5() {
    // Disable VBUS detection (GCCFG bit 21 = VBDEN)
    let gccfg = core::ptr::read_volatile(GCCFG);
    core::ptr::write_volatile(GCCFG, gccfg & !(1 << 21));

    // Force B-peripheral session valid (bypass VBUS sensing)
    // GOTGCTL bit 6 = BVALOEN (override enable)
    // GOTGCTL bit 7 = BVALOVAL (override value = valid)
    let gotgctl = core::ptr::read_volatile(GOTGCTL);
    core::ptr::write_volatile(GOTGCTL, gotgctl | (0b11 << 6));

    cortex_m::asm::dsb();
}

/// §19 P1 production hardening — explicitly force OTG_FS into pure
/// device mode and mask the Start-of-Frame interrupt.
///
/// **Why FDMOD = 1.** The synopsys-usb-otg crate runs in device mode
/// by default but the DWC2 core retains the OTG role-switching state
/// machine. Forcing `OTG_GUSBCFG.FDMOD = 1` removes any attacker-
/// triggered role-switch path — the controller stays as a peripheral
/// until power-cycle.
///
/// **Why mask SOF.** The Start-of-Frame interrupt fires once per
/// 1 ms USB frame. If enabled, it preempts secure-world / NS work
/// on a host-controlled cadence, creating a timing side-channel an
/// attacker can use to gate / correlate other measurements (Colin
/// O'Flynn et al, "Power-Analysis Attacks on USB Controllers"). We
/// don't need SOF events for HID transport — synopsys-usb-otg
/// derives frame timing from URB completions. Mask
/// `OTG_GINTMSK.SOFM = 0` (default after reset, but assert
/// explicitly so a future crate-version change that flips it on
/// can't introduce the side-channel silently).
///
/// Both registers are NS-mapped — same alias as configure_vbus_u5.
///
/// # Safety
/// Volatile RMW on NS-mapped USB OTG registers. Must be called
/// AFTER the synopsys-usb-otg core soft-reset (i.e. after
/// `configure_vbus_u5`).
pub unsafe fn harden_otg() {
    // GUSBCFG @ +0x00C, FDMOD @ bit 30.
    const GUSBCFG: *mut u32 = (USB_OTG_BASE + 0x00C) as *mut u32;
    // GINTMSK @ +0x018, SOFM @ bit 3.
    const GINTMSK: *mut u32 = (USB_OTG_BASE + 0x018) as *mut u32;
    const FDMOD: u32 = 1 << 30;
    const SOFM: u32 = 1 << 3;

    let cfg = core::ptr::read_volatile(GUSBCFG);
    core::ptr::write_volatile(GUSBCFG, cfg | FDMOD);

    let msk = core::ptr::read_volatile(GINTMSK);
    core::ptr::write_volatile(GINTMSK, msk & !SOFM);

    cortex_m::asm::dsb();

    // FDMOD takes effect after 25 ms (per STM32U5 RM §72.16.2
    // GUSBCFG.FDMOD field description). The synopsys-usb-otg crate
    // doesn't poll for this — its own init asserted FHMOD/FDMOD
    // before the soft-reset and then proceeded. Our late assertion
    // here is a belt-and-braces lock-in; the crate is already
    // running in device mode so the 25 ms is a no-op wait. ~4 M
    // `nop`s at 160 MHz.
    for _ in 0..4_000_000 {
        cortex_m::asm::nop();
    }
}

/// Read the USB frame number (`OTG_DSTS.FNSOF`) as a coarse 1 ms-tick
/// monotonic clock for USB-transaction timeouts.
///
/// The host issues a Start-of-Frame token every 1 ms; the DWC2 core
/// latches the frame number into `OTG_DSTS.FNSOF` (bits 21:8, 14-bit,
/// wraps every 16.384 s) — we can read it without enabling the SOF
/// interrupt (which we deliberately mask in `harden_otg` to avoid the
/// timing side-channel). The counter advances ONLY while the host is
/// actively sending SOFs (enumerated + not suspended), which is
/// exactly the window where a reassembly / response timeout is
/// meaningful: a host that stops talking naturally freezes the clock,
/// so we never time out a legitimately-idle session.
///
/// 14-bit range bounds any single timeout to < 16.384 s; the 5 s
/// reassembly timeout (`RX_REASSEMBLY_TIMEOUT_FRAMES`) fits with
/// wrap-aware subtraction at the call site.
#[must_use]
pub fn usb_frame_number() -> u16 {
    // OTG_DSTS @ device-base (0x800) + 0x08 = OTG_FS base + 0x808.
    const OTG_DSTS: *const u32 = (USB_OTG_BASE + 0x808) as *const u32;
    // SAFETY: read-only access to an NS-mapped USB OTG register; no
    // side effects, races, or aliasing concerns for a volatile load.
    let dsts = unsafe { core::ptr::read_volatile(OTG_DSTS) };
    ((dsts >> 8) & 0x3FFF) as u16
}

/// Initialize the USB stack.  Returns a fully-configured `UsbStack` ready
/// to be polled in the main loop.
///
/// # Safety
/// Must be called exactly once.  Uses static mut for EP memory and bus allocator.
pub unsafe fn init() -> UsbStack {
    // SAFETY: `init` is called exactly once before the USB main loop
    // starts polling, and the NS world is single-threaded with no
    // interrupt handlers touching EP_MEMORY / USB_BUS_ALLOC. Both `&mut`
    // / `&` references are released before any second call could
    // reasonably exist.
    let alloc = UsbBus::new(Stm32U5UsbOtgFs, &mut *core::ptr::addr_of_mut!(EP_MEMORY));
    *core::ptr::addr_of_mut!(USB_BUS_ALLOC) = Some(alloc);
    let bus_ref = (*core::ptr::addr_of!(USB_BUS_ALLOC))
        .as_ref()
        .expect("USB_BUS_ALLOC was just set");

    // Create the HID class (allocates endpoints from the bus)
    let hid_class = hid::PqSignerHid::new(bus_ref);

    // Build the USB device
    let usb_dev = UsbDeviceBuilder::new(bus_ref, UsbVidPid(0x1209, 0x7051))
        .strings(&[StringDescriptors::default()
            .manufacturer("PQSigner")
            .product("PQSigner OS")
            .serial_number("0001")])
        .unwrap()
        .device_class(0x00)     // per-interface
        .max_packet_size_0(64)
        .unwrap()
        .build();

    // Force B-session valid now that the driver has completed its core
    // soft-reset (which clears GOTGCTL).  Without this the DWC2 core
    // does not recognise the STM32U5 and VBUS sensing silently fails,
    // preventing enumeration on USB-C to USB-C connections.
    configure_vbus_u5();

    // §19 P1: force FDMOD=1 + mask SOF interrupt. See `harden_otg`
    // docstring + memory `production-security.md` §2.4.
    harden_otg();

    UsbStack {
        device: usb_dev,
        transport: transport::Transport::new(hid_class),
        commands: commands::CommandRouter::new(),
    }
}

```


### `nonsecure/src/usb/transport.rs`

```rust
//! Ledger-compatible APDU-over-HID transport.
//!
//! Fragments/reassembles APDUs into 64-byte HID reports using the
//! standard hardware-wallet framing protocol (Ledger/Keycard Shell).
//!
//! Response flow for large data (e.g. 17 KB signatures):
//! 1. Command handler returns first APDU response (≤255 bytes) with
//!    SW=0x61XX indicating more data available.
//! 2. Host sends GET_RESPONSE (INS 0xC0) APDUs to drain remaining data.
//! 3. Each response APDU is individually HID-framed (fragmented into
//!    64-byte HID reports).

use sphincs_tz_shared::{HID_REPORT_SIZE, HID_TAG_APDU};
use sphincs_tz_shared::apdu_framing::{
    FrameOutcome, HidFrameAssembler, HID_CONT_DATA, HID_FIRST_DATA, MAX_APDU_RX,
};
use super::hid::PqSignerHid;
use super::UsbBusType;

/// APDU-over-HID transport state machine.
///
/// RX framing logic — `HidFrameAssembler` — lives in the `shared` crate
/// so the production path here and the proptest harness in
/// `shared/src/apdu_framing.rs::fuzz_props` exercise byte-identical
/// state-machine code. Adding a new edge case there immediately covers
/// this transport too.
pub struct Transport {
    pub hid: PqSignerHid<'static, UsbBusType>,

    // RX state: bookkeeping (channel/seq/expected) lives in the
    // assembler; the actual reassembly buffer is owned here.
    rx: HidFrameAssembler,
    rx_buf: [u8; MAX_APDU_RX],

    // USB frame number (OTG_DSTS.FNSOF) captured when a multi-frame
    // reassembly began, or `None` when idle. Drives the 5 s reassembly
    // timeout in `check_rx_timeout`. `Some` precisely while the
    // assembler is mid-APDU (between a seq=0 NeedMore and the matching
    // ApduComplete/Dropped).
    rx_start_frame: Option<u16>,

    // TX state: fragment one response APDU into multiple HID frames.
    // `channel_id` is captured from the most recent successfully
    // reassembled RX so outgoing frames carry the matching id.
    channel_id: u16,
    tx_buf: [u8; 256],   // response APDU (max 255 bytes, fits any single APDU)
    tx_len: usize,
    tx_pos: usize,
    tx_seq: u16,
    tx_active: bool,
}

/// 5 s reassembly timeout in USB frames (1 frame = 1 ms SOF). Below
/// the 14-bit `OTG_DSTS.FNSOF` wrap (16.384 s) so wrap-aware
/// subtraction stays unambiguous. §19 P0 "Bounded APDU reassembly".
pub const RX_REASSEMBLY_TIMEOUT_FRAMES: u16 = 5000;

impl Transport {
    pub fn new(hid: PqSignerHid<'static, UsbBusType>) -> Self {
        Self {
            hid,
            rx: HidFrameAssembler::new(),
            rx_buf: [0u8; MAX_APDU_RX],
            rx_start_frame: None,
            channel_id: 0,
            tx_buf: [0u8; 256],
            tx_len: 0,
            tx_pos: 0,
            tx_seq: 0,
            tx_active: false,
        }
    }

    /// Try to receive a complete APDU from the host.
    /// Returns `Some(slice)` when a full APDU has been reassembled
    /// from one or more HID frames.
    ///
    /// `now_frame` is the current `OTG_DSTS.FNSOF` (see
    /// `usb::usb_frame_number`); it stamps the reassembly start so
    /// `check_rx_timeout` can bound how long a partial APDU may sit
    /// half-assembled.
    ///
    /// On `ApduComplete` returns `(channel_id, apdu_bytes)` — the HID channel
    /// the completed APDU arrived on is threaded through to `dispatch` for the
    /// single-session router lease (finding F11). It is returned in the tuple
    /// rather than read via a separate accessor because the returned slice
    /// borrows `self`, so a second `&self` access here would not borrow-check.
    pub fn try_receive(&mut self, now_frame: u16) -> Option<(u16, &[u8])> {
        let mut report = [0u8; HID_REPORT_SIZE];
        let n = self.hid.read_report(&mut report)?;

        match self.rx.process_frame(&report, n, &mut self.rx_buf) {
            FrameOutcome::ApduComplete(len) => {
                let channel = self.rx.channel_id();
                self.channel_id = channel;
                self.rx_start_frame = None;
                Some((channel, &self.rx_buf[..len]))
            }
            FrameOutcome::PingEcho => {
                self.hid.write_report(&report);
                None
            }
            FrameOutcome::NeedMore => {
                // Reassembly in progress — stamp the start frame on the
                // transition from idle so the total-reassembly clock
                // runs from the first chunk, not the latest.
                if self.rx_start_frame.is_none() {
                    self.rx_start_frame = Some(now_frame);
                }
                None
            }
            FrameOutcome::Dropped => {
                // Clear the reassembly deadline only when the drop also
                // killed the stream (desync abort / invalid first frame).
                // A FOREIGN-channel frame is dropped while the owner's
                // stream survives — clearing the deadline here would let
                // one injected frame disarm `check_rx_timeout` for a
                // stalled owner indefinitely (GPT-5.6 wave finding).
                if self.rx.rx_expected() == 0 {
                    self.rx_start_frame = None;
                }
                None
            }
        }
    }

    /// Enforce the reassembly timeout. Call once per main-loop
    /// iteration with the current `OTG_DSTS.FNSOF`. If a partial APDU
    /// has been sitting half-assembled longer than
    /// `RX_REASSEMBLY_TIMEOUT_FRAMES`, scrub the reassembly buffer +
    /// reset the assembler and return `true`.
    ///
    /// Why: a host that sends a seq=0 (declaring a large APDU) and
    /// then stalls would otherwise pin a partial secret-bearing buffer
    /// indefinitely. The frame clock only advances while the host is
    /// sending SOFs, so a genuinely-idle (suspended/unplugged) link
    /// won't false-trip this.
    pub fn check_rx_timeout(&mut self, now_frame: u16) -> bool {
        let Some(start) = self.rx_start_frame else {
            return false;
        };
        // Wrap-aware elapsed over the 14-bit frame counter.
        let elapsed = now_frame.wrapping_sub(start) & 0x3FFF;
        if elapsed >= RX_REASSEMBLY_TIMEOUT_FRAMES {
            self.rx_buf.fill(0);
            self.rx.reset();
            self.rx_start_frame = None;
            return true;
        }
        false
    }

    /// Queue a response APDU for HID-framed transmission.
    ///
    /// The response data at `ptr` of `len` bytes (including 2-byte SW)
    /// is copied into an internal buffer and fragmented into 64-byte
    /// HID reports by `poll_tx()`.
    ///
    /// # Safety
    /// `ptr` must be valid for `len` bytes.
    pub unsafe fn queue_response(&mut self, ptr: *const u8, len: usize) {
        // FI-hardened length clamp — the secure-side `len` flows
        // directly into a `copy_nonoverlapping`, so an EMFI-glitch on
        // the `min` here would let a stale-or-faulted `len` punch past
        // `tx_buf` end. `pqsigner_fi::fi_min` recomputes via the
        // opposite branch if the result fails the post-condition.
        let copy_len = pqsigner_fi::fi_min(len, self.tx_buf.len());
        core::ptr::copy_nonoverlapping(ptr, self.tx_buf.as_mut_ptr(), copy_len);
        self.tx_len = copy_len;
        self.tx_pos = 0;
        self.tx_seq = 0;
        self.tx_active = true;
    }

    /// Send pending HID frames for the current response APDU.
    /// Returns true if a frame was sent.
    pub fn poll_tx(&mut self) -> bool {
        if !self.tx_active {
            return false;
        }

        let mut frame = [0u8; HID_REPORT_SIZE];
        frame[0..2].copy_from_slice(&self.channel_id.to_be_bytes());
        frame[2] = HID_TAG_APDU;
        frame[3..5].copy_from_slice(&self.tx_seq.to_be_bytes());

        if self.tx_seq == 0 {
            // First HID frame: includes data length
            frame[5..7].copy_from_slice(&(self.tx_len as u16).to_be_bytes());
            let remaining = self.tx_len - self.tx_pos;
            let chunk = core::cmp::min(HID_FIRST_DATA, remaining);
            frame[7..7 + chunk].copy_from_slice(&self.tx_buf[self.tx_pos..self.tx_pos + chunk]);
            if !self.hid.write_report(&frame) {
                return false;
            }
            self.tx_pos += chunk;
            self.tx_seq += 1;
        } else {
            // Continuation HID frame
            let remaining = self.tx_len - self.tx_pos;
            let chunk = core::cmp::min(HID_CONT_DATA, remaining);
            frame[5..5 + chunk].copy_from_slice(&self.tx_buf[self.tx_pos..self.tx_pos + chunk]);
            if !self.hid.write_report(&frame) {
                return false;
            }
            self.tx_pos += chunk;
            self.tx_seq += 1;
        }

        if self.tx_pos >= self.tx_len {
            self.tx_active = false;
        }
        true
    }

    pub fn is_tx_active(&self) -> bool {
        self.tx_active
    }
}

```


### `nonsecure/src/usb/hid.rs`

```rust
//! Custom HID class for PQSigner (Usage Page 0xFFA0).
//!
//! Implements a minimal USB HID device with 64-byte IN and OUT interrupt
//! endpoints.  No standard HID report IDs — the entire 64-byte frame is
//! raw APDU-over-HID data (Ledger-compatible framing).

use usb_device::class_prelude::*;
use usb_device::Result;

/// HID Report Descriptor: vendor-defined Usage Page 0xFFA0, 64-byte
/// input and output reports.
///
/// This matches the descriptor used by Ledger, Keycard Shell, and
/// other hardware wallets for Custom HID transport.
const REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xA0, 0xFF, // Usage Page (Vendor Defined 0xFFA0)
    0x09, 0x01,       // Usage (0x01)
    0xA1, 0x01,       // Collection (Application)
    //   Input report (device -> host)
    0x09, 0x20,       //   Usage (0x20)
    0x15, 0x00,       //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08,       //   Report Size (8 bits)
    0x95, 0x40,       //   Report Count (64)
    0x81, 0x02,       //   Input (Data, Variable, Absolute)
    //   Output report (host -> device)
    0x09, 0x21,       //   Usage (0x21)
    0x15, 0x00,       //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08,       //   Report Size (8 bits)
    0x95, 0x40,       //   Report Count (64)
    0x91, 0x02,       //   Output (Data, Variable, Absolute)
    0xC0,             // End Collection
];

/// HID Descriptor body (without bLength and bDescriptorType, which
/// `DescriptorWriter::write(0x21, ...)` adds automatically).
const HID_DESCRIPTOR: &[u8] = &[
    0x11, 0x01, // bcdHID (1.11)
    0x00,       // bCountryCode (not localized)
    0x01,       // bNumDescriptors
    0x22,       // bDescriptorType (Report)
    (REPORT_DESCRIPTOR.len() & 0xFF) as u8,
    ((REPORT_DESCRIPTOR.len() >> 8) & 0xFF) as u8,
];

const REPORT_SIZE: usize = 64;

/// PQSigner Custom HID device class.
pub struct PqSignerHid<'a, B: UsbBus> {
    iface: InterfaceNumber,
    ep_in: EndpointIn<'a, B>,
    ep_out: EndpointOut<'a, B>,
}

impl<'a, B: UsbBus> PqSignerHid<'a, B> {
    pub fn new(alloc: &'a UsbBusAllocator<B>) -> Self {
        Self {
            iface: alloc.interface(),
            ep_in: alloc.interrupt(REPORT_SIZE as u16, 1),  // 1ms poll interval
            ep_out: alloc.interrupt(REPORT_SIZE as u16, 1),
        }
    }

    /// Try to read a 64-byte HID report from the OUT endpoint.
    /// Returns the number of bytes read, or None if no data available.
    pub fn read_report(&mut self, buf: &mut [u8; REPORT_SIZE]) -> Option<usize> {
        self.ep_out.read(buf).ok()
    }

    /// Write a 64-byte HID report to the IN endpoint.
    /// Returns true if the write succeeded, false if the endpoint is busy
    /// or the bus is otherwise unable to accept the report right now.
    pub fn write_report(&mut self, data: &[u8; REPORT_SIZE]) -> bool {
        self.ep_in.write(data).is_ok()
    }
}

impl<B: UsbBus> UsbClass<B> for PqSignerHid<'_, B> {
    fn get_configuration_descriptors(&self, writer: &mut DescriptorWriter) -> Result<()> {
        writer.interface(self.iface, 0x03, 0x00, 0x00)?; // HID class
        writer.write(0x21, HID_DESCRIPTOR)?; // HID descriptor
        writer.endpoint(&self.ep_in)?;
        writer.endpoint(&self.ep_out)?;
        Ok(())
    }

    fn control_in(&mut self, xfer: ControlIn<B>) {
        let req = xfer.request();

        // HID class requests on our interface
        if req.request_type == control::RequestType::Standard
            && req.recipient == control::Recipient::Interface
            && req.index == u8::from(self.iface) as u16
        {
            // GET_DESCRIPTOR for HID Report Descriptor (0x22)
            if req.request == 0x06 {
                // wValue high byte = descriptor type
                let desc_type = (req.value >> 8) as u8;
                if desc_type == 0x22 {
                    // Report descriptor
                    xfer.accept_with_static(REPORT_DESCRIPTOR).ok();
                    return;
                }
                if desc_type == 0x21 {
                    // HID descriptor
                    xfer.accept_with_static(HID_DESCRIPTOR).ok();
                    return;
                }
            }
        }

        // HID-class GET_IDLE / GET_REPORT
        if req.request_type == control::RequestType::Class
            && req.recipient == control::Recipient::Interface
            && req.index == u8::from(self.iface) as u16
        {
            match req.request {
                0x02 => {
                    // GET_IDLE → always return 0 (indefinite)
                    xfer.accept_with(&[0]).ok();
                }
                _ => {}
            }
        }
    }

    fn control_out(&mut self, xfer: ControlOut<B>) {
        let req = xfer.request();

        // HID-class SET_IDLE
        if req.request_type == control::RequestType::Class
            && req.recipient == control::Recipient::Interface
            && req.index == u8::from(self.iface) as u16
            && req.request == 0x0A
        {
            xfer.accept().ok();
        }
    }
}

```


### `nonsecure/src/usb/commands.rs`

```rust
// The router holds its response buffers as module-level `static mut`
// because they outlive any single dispatch call (e.g. the GET_RESPONSE
// chunker pages out of SIG_BUF across multiple HID polls). Every access
// runs inside an `unsafe fn` on the single-threaded NS main loop with
// no interrupts re-entering this module, so the rust-2024
// `static_mut_refs` lint is suppressed per the same pattern as
// `e2e_test.rs` / `bench_key_speed.rs` / `fwup_hw_test.rs`.
#![allow(static_mut_refs)]

//! APDU command router — PQSigner v2 native protocol only (post-cutover).
//!
//! One class byte: `APDU_CLA_V2 = 0xF0`. One signing command. Every
//! legacy signing shim is gone — the single sign-userop Type 1 /
//! Type 2 state machine in the secure world absorbs the lot.
//!
//! Supported v2 instructions:
//!
//! | INS  | Name                     |
//! |------|--------------------------|
//! | 0x01 | GET_DEVICE_INFO          |
//! | 0x02 | GET_STATUS               |
//! | 0x10 | UNLOCK                   |
//! | 0x11 | LOCK                     |
//! | 0x30 | SIGN_USEROP (unified)    |
//! | 0x60 | GET_WALLET_ADDRESS       |
//! | 0x61 | GET_INIT_CODE            |
//! | 0xC0 | GET_RESPONSE             |

use sphincs_tz_shared::*;
use sphincs_tz_shared::apdu_framing::{
    parse_apdu_header, route_v2, router_lease_allows, ChainState, ChainStepOutcome,
};

use crate::nsc_api;

// ---------------------------------------------------------------------------
// Static buffers
// ---------------------------------------------------------------------------

/// Maximum accumulated command data across chained APDUs. Size reflects
/// the worst-case unified sign payload: `SIGN_USEROP_HEADER_LEN`-byte
/// header + max inner-tx calldata (`MAX_TX_LEN`) + optional 2-byte prefix
/// + max ERC-20 bundle + the 2-byte reserved compatibility slot.
///
/// Also accommodates `INS_V2_FW_BEGIN`'s 8 KB manifest — the max
/// function below resolves to whichever of the two use cases is
/// larger. `const fn max` isn't available in no_std stable, so we
/// hand-expand via a pair of `const` branches and compile-asserts.
const CHAIN_BUF_LEN_SIGN: usize = SIGN_USEROP_HEADER_LEN
    + MAX_TX_LEN
    + 2
    + 1120
    + 2 // reserved compatibility slot (length field only, must be 0)
    // CoW order trailer: 2-byte length + canonical + two ERC-20 bundles.
    + 2
    + COW_ORDER_TRAILER_MAX_LEN
    // ERC-7730 clear-signing descriptor trailer: 2-byte length plus
    // either one legacy bundle or a two-bundle proof set (up to
    // ERC7730_MAX_TRAILER_LEN = 10268 B). Sits
    // between self-attest and names per the wire-format ordering in
    // `docs/archive/handoff-erc7730-phase3.md` §"Canonical wire formats".
    + 2
    + sphincs_tz_shared::ERC7730_MAX_TRAILER_LEN
    // Names trailer: 1-byte count + up to 4 × (2-byte length + bundle).
    // The 1200-byte-per-bundle figure is the MAX_NAME_BUNDLE_LEN upper
    // bound plus the 2-byte length prefix, rounded to the 32-bit
    // proof-depth cap.
    + 1
    + 4 * (2 + 1200)
    + 64;
const CHAIN_BUF_LEN_FW: usize = fw_manifest::MANIFEST_SIZE + 64;
/// Worst-case batch sign payload: header + N × (per-tx prefix +
/// MAX_TX_LEN data). Defined in the shared crate as
/// [`sphincs_tz_shared::SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN`].
const CHAIN_BUF_LEN_BATCH: usize = SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN;
const CHAIN_BUF_LEN_SIGN_OR_BATCH: usize = if CHAIN_BUF_LEN_SIGN > CHAIN_BUF_LEN_BATCH {
    CHAIN_BUF_LEN_SIGN
} else {
    CHAIN_BUF_LEN_BATCH
};
const CHAIN_BUF_LEN: usize = if CHAIN_BUF_LEN_SIGN_OR_BATCH > CHAIN_BUF_LEN_FW {
    CHAIN_BUF_LEN_SIGN_OR_BATCH
} else {
    CHAIN_BUF_LEN_FW
};

/// Per-CMD upper bound on accumulated chain payload. The global
/// `CHAIN_BUF_LEN` is the max of all chained CMDs; passing it to
/// `ChainState::step` would let a hostile host accumulate up to that
/// global max for any one CMD before the per-CMD execute-time length
/// check rejected it (e.g. fill ~8 KB for FW_BEGIN even though the
/// real bound is `MANIFEST_SIZE = 8192`). Tighten per-CMD here so the
/// step layer itself rejects oversized accumulations as soon as `lc`
/// pushes past the *real* limit for that CMD. See finding #4 in
/// `docs/security/usb-fw-update-hardening.md`.
///
/// Unknown CMDs fall back to the global max — execute_chain returns
/// `INS_NOT_SUPPORTED` at the next layer, no behaviour change.
const fn per_cmd_chain_bound(ins: u8) -> usize {
    match ins {
        INS_V2_SIGN_USEROP => CHAIN_BUF_LEN_SIGN,
        INS_V2_SIGN_USEROP_BATCH => CHAIN_BUF_LEN_BATCH,
        INS_V2_SIGN_OFFCHAIN => SIGN_OFFCHAIN_INPUT_MAX_LEN,
        // `INS_V2_FW_BEGIN`'s handler is `#[cfg(feature = "stm32u585")]`-
        // gated; the wire constant exists unconditionally, so we match it
        // here without a cfg so this stays a `const fn`. On a non-
        // stm32u585 build, `execute_chain` returns `INS_NOT_SUPPORTED` —
        // tightening the bound costs nothing.
        INS_V2_FW_BEGIN => CHAIN_BUF_LEN_FW,
        _ => CHAIN_BUF_LEN,
    }
}

/// Response buffer — sized for the maximum unified output plus
/// the 2-byte SW.
static mut SIG_BUF: [u8; MAX_SIGN_RESPONSE_LEN + 2] = [0u8; MAX_SIGN_RESPONSE_LEN + 2];

/// Short response buffer (non-signature responses).
static mut RESP_BUF: [u8; 256] = [0u8; 256];

/// Command chaining accumulation buffer.
static mut CHAIN_BUF: [u8; CHAIN_BUF_LEN] = [0u8; CHAIN_BUF_LEN];

/// Pending GET_RESPONSE state.
static mut PENDING_PTR: *const u8 = core::ptr::null();
static mut PENDING_LEN: usize = 0;
static mut PENDING_POS: usize = 0;

/// Single-session router lease owner (finding F11). `Some(channel_id)` while an
/// exchange (a live chained command OR a pending chunked `GET_RESPONSE` drain)
/// is in progress, recording which HID channel started it; `None` when the
/// router is idle. `dispatch` refuses any APDU from a different channel while
/// the lease is held, so a second client on the same physical device can
/// neither drain another channel's queued response nor scrub its chain/pending
/// state. Owned by the single-threaded NS dispatcher, same as `PENDING_*`.
static mut ROUTER_OWNER: Option<u16> = None;

/// 30-second inter-chunk timeout for an in-progress GET_RESPONSE drain
/// (§19 P1 "Response-buffer locking … 30 s timeout"). If the host
/// declares a chunked SLH-DSA-signature response (SW=0x61xx) and then
/// stops issuing GET_RESPONSE entirely — no command at all, so the
/// `dispatch` scrub-on-interleave never fires — the pending buffer
/// would otherwise sit referenced indefinitely. `check_response_timeout`
/// (driven from the NS poll loop by the `OTG_DSTS.FNSOF` frame clock)
/// accumulates elapsed frames between checks and scrubs the pending
/// cursor once `PENDING_TIMEOUT_FRAMES` pass without a GET_RESPONSE.
///
/// Accumulating per-iteration deltas (rather than a single start→now
/// delta) sidesteps the 14-bit FNSOF wrap at 16.384 s: the NS loop
/// polls at kHz, so each `(now - last) & 0x3FFF` delta is tiny and
/// always wrap-correct, and 30 s > one wrap is handled by summation.
static mut PENDING_LAST_FRAME: u16 = 0;
static mut PENDING_ELAPSED_FRAMES: u32 = 0;
/// 30 s at the nominal 1 ms USB SOF cadence.
const PENDING_TIMEOUT_FRAMES: u32 = 30_000;

/// Absolute total-drain deadline (sweep finding F2): the inter-chunk
/// timeout above is activity-reset by every GET_RESPONSE, so a
/// slow-drain keepalive (one GET_RESPONSE every <30 s, final chunk
/// never taken) would pin the F11 router lease forever. This second
/// accumulator is NOT reset by drain activity; once it reaches
/// `PENDING_ABS_TIMEOUT_FRAMES` the drain is scrubbed and the lease
/// released regardless of keepalives. 120 s is ~7× the time a
/// worst-case legitimate drain (17 initCode chunks, even at a
/// pathological 5 s per GET_RESPONSE round-trip) could need.
static mut PENDING_ABS_ELAPSED_FRAMES: u32 = 0;
/// 120 s at the nominal 1 ms USB SOF cadence.
const PENDING_ABS_TIMEOUT_FRAMES: u32 = 120_000;

/// USB SOF frame of the last `check_chain_timeout` call — same
/// wrap-safe delta pattern as `PENDING_LAST_FRAME`.
static mut CHAIN_LAST_FRAME: u16 = 0;

// ---------------------------------------------------------------------------
// Firmware version
// ---------------------------------------------------------------------------

// Hardcoded placeholder, NOT the running image's identity: nothing
// plumbs the real build version into this constant, so GET_DEVICE_INFO
// returns these same bytes for every firmware. Companions must NOT key
// protocol decisions (e.g. wire-format selection) on it.
const FW_VERSION: [u8; 3] = [0x03, 0x00, 0x00];

// ---------------------------------------------------------------------------
// Capability bits (reported by GET_DEVICE_INFO).
// ---------------------------------------------------------------------------

// Bit 1 (CAP_FLASH_NEXT_Q) is retired — post-C10-cutover the firmware
// is stateless for slot selection; the companion drives rotation.
// Bit 2 advertises the versioned ERC-7730 proof-set envelope. Both live bits
// are sourced from pqsigner-proto through sphincs-tz-shared.

// ---------------------------------------------------------------------------
// Response wrapper
// ---------------------------------------------------------------------------

pub struct Response {
    pub ptr: *const u8,
    pub len: usize,
}

// ---------------------------------------------------------------------------
// Command Router
// ---------------------------------------------------------------------------

pub struct CommandRouter {
    /// Chained-APDU state. The ISO 7816-4 framing — INS-mid-chain
    /// detection, monotonic write cursor, overflow-safe length checks
    /// — lives in `sphincs_tz_shared::apdu_framing` so the production
    /// path here and the proptest harness in
    /// `shared/src/apdu_framing.rs` exercise byte-identical logic.
    chain: ChainState,
}

impl CommandRouter {
    pub fn new() -> Self {
        Self {
            chain: ChainState::new(),
        }
    }

    /// Router entry point. Enforces the single-session lease (F11) around the
    /// real dispatch: a foreign channel is refused while another channel owns a
    /// live exchange, and the lease is re-derived from the resulting state so it
    /// releases the instant no chain and no pending drain remain.
    pub unsafe fn dispatch(&mut self, channel: u16, apdu: &[u8]) -> Response {
        if !router_lease_allows(ROUTER_OWNER, channel) {
            // A different channel acted while the owner holds the lease. Reject
            // WITHOUT disturbing the owner's chain/pending state, so a foreign
            // channel can neither siphon its response nor DoS it by scrubbing.
            return self.sw_response(SW_CONDITIONS_NOT_SATISFIED);
        }
        let resp = self.dispatch_inner(apdu);
        // Re-derive the lease: a chain still in progress or a pending chunked
        // drain keeps the lease with `channel`; otherwise it is released.
        ROUTER_OWNER = if PENDING_PTR.is_null() && self.chain.active_ins() == 0 {
            None
        } else {
            Some(channel)
        };
        resp
    }

    unsafe fn dispatch_inner(&mut self, apdu: &[u8]) -> Response {
        // Pure header parser — host-fuzzed in
        // `sphincs_tz_shared::apdu_framing::fuzz_props`.
        let header = match parse_apdu_header(apdu) {
            Ok(h) => h,
            Err(e) => return self.sw_response(e.to_sw()),
        };

        // GET_RESPONSE is CLA-agnostic so the companion can keep using
        // it without tracking which chain the pending bytes belong to.
        if header.ins == INS_V2_GET_RESPONSE {
            return self.get_response();
        }

        // Any command OTHER than GET_RESPONSE arriving while a chunked
        // response is still pending means the host abandoned the drain.
        // Reset the pending cursor so the leftover bytes can't be
        // siphoned by a later GET_RESPONSE that belongs to a different
        // logical exchange. §19 P1 "Response-buffer locking … scrub on
        // anything other than GET_RESPONSE arriving". The 30 s
        // wall-clock half of that item is still owed (NS clock
        // plumbing); this closes the command-interleave half now.
        if !PENDING_PTR.is_null() {
            PENDING_PTR = core::ptr::null();
            PENDING_LEN = 0;
            PENDING_POS = 0;
        }

        if let Err(e) = route_v2(&header) {
            return self.sw_response(e.to_sw());
        }

        let ins = header.ins;
        let p1 = header.p1;
        let lc = header.lc;
        let data = header.data;

        // Non-chained commands (full payload fits in one APDU).
        match ins {
            INS_V2_GET_DEVICE_INFO => return self.cmd_get_device_info(),
            INS_V2_GET_STATUS => return self.cmd_get_status(),
            INS_V2_GET_PIN_ATTEMPT_LOG => return self.cmd_get_pin_attempt_log(),
            INS_V2_UNLOCK => return self.cmd_unlock(),
            INS_V2_LOCK => return self.cmd_lock(),
            INS_V2_GET_WALLET_ADDRESS => return self.cmd_get_wallet_address(data),
            INS_V2_GET_INIT_CODE => return self.cmd_get_init_code(data),
            // INS_V2_SIGN_OFFCHAIN is chained — see `execute_chain`.
            // PersonalSign payloads can run up to ~700 bytes, well past
            // the single-APDU Lc=255 limit.
            INS_V2_OFFCHAIN_STATUS => return self.cmd_offchain_status(data),
            INS_V2_OFFCHAIN_SYNC => return self.cmd_offchain_sync(data),

            // Firmware-update non-chained commands. CHUNK is not in
            // the chained-INS set, so each CMD_FW_CHUNK is exactly one
            // APDU: the u8 `Lc` caps one APDU at 255 payload bytes,
            // i.e. the 8-byte header plus at most 247 bytes of chunk
            // data on the wire (the `FW_MAX_CHUNK = 1024` protocol cap
            // checked in `cmd_fw_chunk` is unreachable in one APDU).
            // COMMIT / STATUS / ABORT have no payload.
            #[cfg(feature = "stm32u585")]
            INS_V2_FW_CHUNK => return self.cmd_fw_chunk(data),
            #[cfg(feature = "stm32u585")]
            INS_V2_FW_COMMIT => return self.cmd_fw_commit(),
            #[cfg(feature = "stm32u585")]
            INS_V2_FW_STATUS => return self.cmd_fw_status(),
            #[cfg(feature = "stm32u585")]
            INS_V2_FW_ABORT => return self.cmd_fw_abort(),

            // Prodtest INSes (companion → device, prodtest builds only).
            // No PIN gating — the prodtest firmware runs before any
            // user state exists. Each command writes its output bytes
            // into `RESP_BUF` followed by the 2-byte SW.
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_GET_ID => return self.cmd_prodtest_get_id(),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_DISPLAY_PATTERN => return self.cmd_prodtest_display_pattern(data),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_SAES_SELFTEST => return self.cmd_prodtest_saes_selftest(),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_BHK_SELFTEST => return self.cmd_prodtest_bhk_selftest(),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_FLASH_RW => return self.cmd_prodtest_flash_rw(data),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_TRNG_SAMPLE => return self.cmd_prodtest_trng_sample(data),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_OPTIGA_HANDSHAKE => return self.cmd_prodtest_optiga_handshake(),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_SE050_HANDSHAKE => return self.cmd_prodtest_se050_handshake(),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_USB_LOOPBACK => return self.cmd_prodtest_usb_loopback(data),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_BUTTON_TEST => return self.cmd_prodtest_button_test(),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_RGB_TEST => return self.cmd_prodtest_rgb_test(data),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_RGB_OSD => return self.cmd_prodtest_rgb_osd(data),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_RNG_CONFIG => return self.cmd_prodtest_rng_config(),

            _ => {}
        }

        // INS allowlist for the chained-command path. Reject unknown
        // INS *before* `chain.step` accepts any payload bytes — a
        // hostile host could otherwise burn up to `CHAIN_BUF_LEN`
        // (~8 KB) of buffer accumulation for a bogus INS before the
        // execute-time `_ => SW_INS_NOT_SUPPORTED` arm finally rejects
        // it. Matches §19 "APDU CLA/INS allowlist at non-secure
        // *before* any NSC gateway call" in `docs/security/production-security.md`.
        // Mirrors the explicit set in `execute_chain` below.
        let is_chained_ins = matches!(
            ins,
            INS_V2_SIGN_USEROP | INS_V2_SIGN_USEROP_BATCH | INS_V2_SIGN_OFFCHAIN
        );
        #[cfg(feature = "stm32u585")]
        let is_chained_ins = is_chained_ins || ins == INS_V2_FW_BEGIN;
        if !is_chained_ins {
            return self.sw_response(SW_INS_NOT_SUPPORTED);
        }

        // Chained commands. The state machine, INS-mismatch detection,
        // and overflow-safe length checks all live in
        // `ChainState::step` — see `shared/src/apdu_framing.rs`. We
        // only need to copy `lc` bytes into `CHAIN_BUF` at the cursor
        // the helper hands us, then either ack or execute.
        match self.chain.step(ins, p1, lc, per_cmd_chain_bound(ins)) {
            ChainStepOutcome::Appended { write_at, lc } => {
                if lc > 0 {
                    CHAIN_BUF[write_at..write_at + lc].copy_from_slice(data);
                }
                self.sw_response(SW_OK)
            }
            ChainStepOutcome::Execute { ins, final_len, write_at, lc } => {
                if lc > 0 {
                    CHAIN_BUF[write_at..write_at + lc].copy_from_slice(data);
                }
                self.execute_chain(ins, final_len)
            }
            ChainStepOutcome::ProtocolError => {
                self.sw_response(ChainStepOutcome::protocol_error_sw())
            }
            ChainStepOutcome::WrongLength => {
                self.sw_response(ChainStepOutcome::wrong_length_sw())
            }
        }
    }

    unsafe fn execute_chain(&mut self, ins: u8, len: usize) -> Response {
        match ins {
            INS_V2_SIGN_USEROP => self.cmd_sign_userop(len),
            INS_V2_SIGN_USEROP_BATCH => self.cmd_sign_userop_batch(len),
            INS_V2_SIGN_OFFCHAIN => self.cmd_sign_offchain(len),
            #[cfg(feature = "stm32u585")]
            INS_V2_FW_BEGIN => self.cmd_fw_begin(len),
            _ => self.sw_response(SW_INS_NOT_SUPPORTED),
        }
    }

    // ===================================================================
    // Command handlers
    // ===================================================================

    /// 0x01 GET_DEVICE_INFO.
    unsafe fn cmd_get_device_info(&self) -> Response {
        let mut p = 0usize;

        RESP_BUF[p..p + 2].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        p += 2;

        RESP_BUF[p..p + 3].copy_from_slice(&FW_VERSION);
        p += 3;

        RESP_BUF[p..p + 16].fill(0); // device_uid placeholder
        p += 16;

        let caps = DEVICE_CAPABILITIES;
        RESP_BUF[p..p + 4].copy_from_slice(&caps.to_be_bytes());
        p += 4;

        RESP_BUF[p] = 2; // sig_param_set: 2 = SPHINCS+C10 (128-bit) everywhere
        p += 1;

        // Type 2 sig size — now fixed at `SIG_TYPE2_LEN` bytes.
        RESP_BUF[p..p + 2].copy_from_slice(&(SIG_TYPE2_LEN as u16).to_be_bytes());
        p += 2;

        // Unused legacy version fields, zeroed.
        RESP_BUF[p..p + 4].fill(0);
        p += 4;
        RESP_BUF[p..p + 4].fill(0);
        p += 4;

        // ep_version: 0x0006 (EntryPoint v0.6).
        RESP_BUF[p..p + 2].copy_from_slice(&0x0006u16.to_be_bytes());
        p += 2;

        // Wrapper-overhead: header bytes prepended to each signed tx.
        RESP_BUF[p..p + 2].copy_from_slice(&(SIG_TYPE2_HEADER_LEN as u16).to_be_bytes());
        p += 2;

        RESP_BUF[p] = (SW_OK >> 8) as u8;
        RESP_BUF[p + 1] = (SW_OK & 0xFF) as u8;
        p += 2;

        Response {
            ptr: RESP_BUF.as_ptr(),
            len: p,
        }
    }

    /// 0x02 GET_STATUS.
    unsafe fn cmd_get_status(&self) -> Response {
        let remaining = nsc_api::get_remaining_attempts();
        let unlocked = nsc_api::is_unlocked();

        // Work-todo X17-UC2: the response carries NO `provisioned`
        // byte. It used to lead the reply, derived as
        // `remaining <= MAX_ATTEMPTS` — always true, so the byte was a
        // constant-1 that lied on blank devices. The honest options
        // were a real provisioning-state veneer (rejected: no such
        // veneer exists and provisioning state is a live SE-chip probe,
        // far too heavy and too much new NS-callable surface for a
        // status poll) or deleting the byte — deleted. Companions must
        // detect the unprovisioned state from the on-device first-boot
        // wizard instead.
        RESP_BUF[0] = if unlocked { 0 } else { 1 };
        RESP_BUF[1] = remaining as u8;
        RESP_BUF[2] = (SW_OK >> 8) as u8;
        RESP_BUF[3] = (SW_OK & 0xFF) as u8;

        Response {
            ptr: RESP_BUF.as_ptr(),
            len: 4,
        }
    }

    /// 0x03 GET_PIN_ATTEMPT_LOG — why each PIN attempt was consumed (#715).
    /// Read-only; no secret material (see `secure/src/pin_attempt_log.rs`).
    unsafe fn cmd_get_pin_attempt_log(&self) -> Response {
        let mut out = [0u8; PIN_ATTEMPT_LOG_LEN];
        let status = nsc_api::get_pin_attempt_log(&mut out);
        if status != 0 {
            return self.sw_response(SW_INTERNAL_ERROR);
        }
        RESP_BUF[..PIN_ATTEMPT_LOG_LEN].copy_from_slice(&out);
        RESP_BUF[PIN_ATTEMPT_LOG_LEN] = (SW_OK >> 8) as u8;
        RESP_BUF[PIN_ATTEMPT_LOG_LEN + 1] = (SW_OK & 0xFF) as u8;
        Response {
            ptr: RESP_BUF.as_ptr(),
            len: PIN_ATTEMPT_LOG_LEN + 2,
        }
    }

    /// 0x10 UNLOCK.
    unsafe fn cmd_unlock(&self) -> Response {
        let status = nsc_api::request_unlock();
        self.nsc_status_to_response(status)
    }

    /// 0x11 LOCK.
    unsafe fn cmd_lock(&self) -> Response {
        nsc_api::lock();
        self.sw_response(SW_OK)
    }

    /// 0x60 GET_WALLET_ADDRESS — return the 20-byte CREATE2-predicted
    /// sender for this device's bootstrap C10 pubkey at `account_index`.
    /// Requires unlock.
    ///
    /// APDU body layout: 4 bytes big-endian `account_index` (0..=255),
    /// optionally followed by a 1-byte `show` flag (PROTOCOL_VERSION
    /// 0x0202+): `0` (or absent) returns the address with no trusted-UI
    /// round-trip; `1` first shows the address on the device OLED behind
    /// a physical confirm (#472) — a user cancel fails closed with
    /// `UserRejected` and no address bytes. Any flag value above 1 is
    /// rejected. An empty body is accepted as `account_index == 0` so
    /// legacy companion builds that pre-date multi-account derivation
    /// still see their original single wallet.
    unsafe fn cmd_get_wallet_address(&self, data: &[u8]) -> Response {
        let (account_index, show) = match data.len() {
            0 => (0u32, 0u32),
            4 => (u32::from_be_bytes([data[0], data[1], data[2], data[3]]), 0u32),
            5 => {
                let flag = u32::from(data[4]);
                if flag > 1 {
                    return self.sw_response(SW_WRONG_DATA);
                }
                (u32::from_be_bytes([data[0], data[1], data[2], data[3]]), flag)
            }
            _ => return self.sw_response(SW_WRONG_LENGTH),
        };
        let mut addr = [0u8; 20];
        let status = nsc_api::get_wallet_address(&mut addr, account_index, show);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        RESP_BUF[..20].copy_from_slice(&addr);
        RESP_BUF[20..22].copy_from_slice(&SW_OK.to_be_bytes());
        Response {
            ptr: RESP_BUF.as_ptr(),
            len: 22,
        }
    }

    /// 0x61 GET_INIT_CODE — return the 4280-byte ERC-4337 initCode for
    /// `(account_index, chain_id)`. Used by the companion's gas
    /// estimator for not-yet-deployed wallets; the bytes are
    /// byte-identical to what the deploy path of SIGN_USEROP emits
    /// and safe to cache. Requires an unlocked device.
    ///
    /// APDU body: 12 bytes `[account_index u32 BE || chain_id u64 BE]`.
    /// Response: 4280 bytes streamed via `GET_RESPONSE` chaining.
    unsafe fn cmd_get_init_code(&self, data: &[u8]) -> Response {
        if data.len() != 12 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let status = nsc_api::get_init_code(
            data,
            &mut SIG_BUF[..PQ_INIT_CODE_LEN],
        );
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        // PQ_INIT_CODE_LEN = 4280 > APDU_MAX_RESP (253), so this always
        // enters the GET_RESPONSE chaining path. The chunker lives in
        // `setup_chunked_response` and reuses the caller's existing
        // PENDING_PTR/LEN/POS cursor.
        self.setup_chunked_response(PQ_INIT_CODE_LEN)
    }

    /// 0x30 SIGN_USEROP — unified Type 1 / Type 2 state machine.
    ///
    /// The payload is the `SIGN_USEROP_HEADER_LEN`-byte header plus
    /// the inner tx calldata (see `sphincs_tz_shared::SIGN_USEROP_HEADER_LEN`
    /// for the canonical layout). The secure world writes a bundled
    /// response into `SIG_BUF`:
    ///
    /// ```text
    ///   [new_offchain_count u64 BE]
    ///   [init_code_len u32 BE] [init_code_bytes...]
    ///   [type1_len     u32 BE] [type1_bytes...]
    ///   [type2_len     u32 BE] [type2_bytes...]
    /// ```
    ///
    /// `init_code_len` is non-zero only when the companion set
    /// `FLAG_INCLUDE_INIT_CODE` on the request (fresh wallet, first deploy
    /// on this chain). Similarly `type1_len == 0` means slot registration
    /// was not needed and the companion should submit only Type 2.
    unsafe fn cmd_sign_userop(&self, data_len: usize) -> Response {
        if data_len < SIGN_USEROP_HEADER_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }

        // All metadata trailers (ERC-20 / native CoW / names / selector /
        // ERC-7730 / …) are built by the companion and arrive inside the
        // request — the DBs live host-side, the device holds only the
        // pinned Merkle roots and verifies every byte in S-world. NS no
        // longer looks anything up. We only normalise the positional
        // trailer skeleton so a companion that sent a short prefix (or no
        // trailers at all) still presents a well-formed, fail-safe layout
        // to the secure parser — missing slots degrade to "unknown token"
        // / raw-hex / blind-sign, never a forged display.
        let effective_len = Self::ensure_trailer_skeleton(data_len);

        let status = nsc_api::sign_userop(
            &CHAIN_BUF[..effective_len],
            &mut SIG_BUF[..MAX_SIGN_RESPONSE_LEN],
        );
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        match Self::total_sign_response_len() {
            Some(total) => self.setup_chunked_response(total),
            None => self.sw_response(SW_INTERNAL_ERROR),
        }
    }

    /// 0x32 SIGN_USEROP_BATCH — atomic multi-call sign command. The
    /// payload is the `CMD_SIGN_USEROP_BATCH` wire format
    /// (`SIGN_USEROP_BATCH_HEADER_LEN` header + N inner-tx blocks);
    /// the response framing is byte-identical to
    /// [`Self::cmd_sign_userop`]'s (the only on-chain difference is
    /// that the resulting UserOp's callData is
    /// `executeBatchWithOffchainCount(...)` instead of the
    /// single-call `executeWithOffchainCount(...)`).
    ///
    /// No NS-side trailer injection: the companion supplies the wire-v2
    /// routed TLV list. ERC-20 metadata, native CoW (frozen wire kind 3),
    /// Safe, selector, ERC-7730, and name trailers all have batch routes;
    /// reserved wire kind 2 is rejected at every payload length.
    unsafe fn cmd_sign_userop_batch(&self, data_len: usize) -> Response {
        if data_len < SIGN_USEROP_BATCH_HEADER_LEN + SIGN_USEROP_BATCH_TX_PREFIX_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }

        let status = nsc_api::sign_userop_batch(
            &CHAIN_BUF[..data_len],
            &mut SIG_BUF[..MAX_SIGN_RESPONSE_LEN],
        );
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        match Self::total_sign_response_len() {
            Some(total) => self.setup_chunked_response(total),
            None => self.sw_response(SW_INTERNAL_ERROR),
        }
    }

    /// Parse the bundled sign-userop response framing — same shape for
    /// the single-call and batch sign paths — out of `SIG_BUF` and return
    /// the total length to ship to the host, or `None` if any declared
    /// length overflows the response buffer (which can only happen on a
    /// firmware bug, hence the `SW_INTERNAL_ERROR` mapping at the call
    /// site).
    ///
    /// Framing (after the firmware's gateway write):
    /// ```text
    ///   [new_offchain_count(8 BE)]
    ///   [init_code_len(4 BE)] [init_code...]
    ///   [type1_len(4 BE)]    [type1...]
    ///   [type2_len(4 BE)]    [type2...]
    /// ```
    unsafe fn total_sign_response_len() -> Option<usize> {
        const COUNT_LEN: usize = 8;

        let ic_len_off = COUNT_LEN;
        let ic_len = read_be_u32(&SIG_BUF, ic_len_off)? as usize;

        let t1_len_off = ic_len_off + 4 + ic_len;
        let t1_len = read_be_u32(&SIG_BUF, t1_len_off)? as usize;

        let t2_len_off = t1_len_off + 4 + t1_len;
        let t2_len = read_be_u32(&SIG_BUF, t2_len_off)? as usize;

        let total = t2_len_off + 4 + t2_len;
        if total > MAX_SIGN_RESPONSE_LEN {
            return None;
        }
        Some(total)
    }

    /// 0x62 SIGN_OFFCHAIN — produce a SPHINCS+C10 sig for an EIP-1271
    /// request. Body is variable-length (`SIGN_OFFCHAIN_HEADER_LEN +
    /// payload_len`); the secure world parses the `kind` byte and
    /// validates `payload_len` against the per-kind constraints. The
    /// hard upper bound (`SIGN_OFFCHAIN_INPUT_MAX_LEN`) is enforced
    /// here so an oversize HID body is rejected before the gateway
    /// call. PersonalSign payloads can run up to ~700 bytes — past the
    /// single-APDU Lc=255 limit — so the request is APDU-chained;
    /// `execute_chain` calls us with the assembled payload pulled out
    /// of `CHAIN_BUF`.
    ///
    /// Response length depends on the `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED`
    /// bit in the input flags byte:
    ///   * set (deployed): 4016 B (8 count + 4008 C10 sig)
    ///   * clear (counterfactual): 8616 B (8 count + 8608 ERC-6492
    ///     wrapped sig)
    unsafe fn cmd_sign_offchain(&self, data_len: usize) -> Response {
        if data_len < sphincs_tz_shared::SIGN_OFFCHAIN_HEADER_LEN
            || data_len > sphincs_tz_shared::SIGN_OFFCHAIN_INPUT_MAX_LEN
        {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let flags = CHAIN_BUF[sphincs_tz_shared::SIGN_OFFCHAIN_INPUT_FLAGS_OFF];
        let account_deployed =
            flags & sphincs_tz_shared::OFFCHAIN_FLAG_ACCOUNT_DEPLOYED != 0;
        let out_len = if account_deployed {
            sphincs_tz_shared::SIGN_OFFCHAIN_OUTPUT_LEN
        } else {
            sphincs_tz_shared::SIGN_OFFCHAIN_OUTPUT_LEN_6492
        };
        let status = nsc_api::sign_offchain(&CHAIN_BUF[..data_len], &mut SIG_BUF[..out_len]);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        self.setup_chunked_response(out_len)
    }

    /// 0x63 OFFCHAIN_STATUS — read per-slot off-chain state. Body: 13
    /// bytes. Response: 24 bytes (fits in a single APDU).
    unsafe fn cmd_offchain_status(&self, data: &[u8]) -> Response {
        if data.len() != sphincs_tz_shared::OFFCHAIN_STATUS_INPUT_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let status = nsc_api::offchain_status(
            data,
            &mut RESP_BUF[..sphincs_tz_shared::OFFCHAIN_STATUS_OUTPUT_LEN],
        );
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        let total = sphincs_tz_shared::OFFCHAIN_STATUS_OUTPUT_LEN;
        RESP_BUF[total..total + 2].copy_from_slice(&SW_OK.to_be_bytes());
        Response {
            ptr: RESP_BUF.as_ptr(),
            len: total + 2,
        }
    }

    /// 0x64 OFFCHAIN_SYNC — bump per-slot `last_userop_count` to a
    /// companion-supplied floor. Input is the 21-byte
    /// `OFFCHAIN_SYNC_INPUT_LEN` payload. No response body, SW only.
    unsafe fn cmd_offchain_sync(&self, data: &[u8]) -> Response {
        if data.len() != sphincs_tz_shared::OFFCHAIN_SYNC_INPUT_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let status = nsc_api::offchain_sync(data);
        self.nsc_status_to_response(status)
    }

    /// Ensure the `[erc20][reserved_v1][cow_order][safe_v1][selector][self_attest][erc7730]`
    /// u16-prefixed trailer skeleton is fully present before `received_len`,
    /// padding any missing prefix with `[0x00, 0x00]`.
    ///
    /// Background: the secure-world sign_userop parser walks trailers
    /// positionally in that exact order and then reads the `names`
    /// trailer at whatever cursor lands after them. If the companion
    /// sent a payload that stops earlier in the chain (e.g. only
    /// `erc20+reserved_v1+cow_order`, or a bare `header+data` with no trailers at
    /// all), the secure parser would consume the `[count][bundle_len][...]`
    /// framing of the names trailer as `safe_v1`'s u16 length and the
    /// next pair as `selector`'s — bytes that are almost always > the
    /// per-trailer caps and trip "bad safe bundle" or "bad selector
    /// bundle" on the OLED. (Earlier symptom: "Sign v3 len>cap" when
    /// only 1 prefix was padded.)
    ///
    /// This helper walks the trailer chain and appends empty `[0, 0]`
    /// u16 prefixes for any section not yet encoded, returning the
    /// updated `received_len`. For a payload that already contains a
    /// full skeleton this is a no-op. It is the ONLY trailer
    /// normalisation NS does now that the metadata DBs live host-side:
    /// the companion builds every real bundle; NS just guarantees a
    /// parseable, fail-safe skeleton so missing trailers degrade
    /// gracefully (unknown token / raw hex / blind-sign).
    unsafe fn ensure_trailer_skeleton(received_len: usize) -> usize {
        if received_len < SIGN_USEROP_HEADER_LEN {
            return received_len;
        }
        let data_len =
            u16::from_be_bytes([CHAIN_BUF[328], CHAIN_BUF[329]]) as usize;
        let after_data = SIGN_USEROP_HEADER_LEN + data_len;
        if after_data > received_len {
            return received_len;
        }
        let mut pos = after_data;
        let mut new_len = received_len;
        // Seven empty u16 prefixes to ensure, in secure-parser order:
        // erc20, reserved_v1, cow_order, safe_v1, selector, self_attest, erc7730.
        // Must match the parse sequence in
        // `secure/src/nsc/cmd_sign_userop.rs::run` exactly — any
        // divergence causes the names trailer to misalign with the
        // secure parser's cursor and surfaces on the OLED as a
        // "bad <section> bundle" / "bad names count" / etc. error.
        //
        // History:
        // - Bumped from 5 → 6 when commit 33cd0ed added the self_attest
        //   slot; without this the NS-injected names count byte got read
        //   as the self_attest u16 length and tripped "bad self-attest"
        //   on every ETH transfer to a named address.
        // - Bumped from 6 → 7 when the ERC-7730 clear-signing trailer
        //   slot landed (after self_attest, before names). Without this
        //   bump, an NS-injected ERC-20 bundle / names section for a
        //   companion that ships no ERC-7730 trailer caused the secure
        //   parser to read the names `[count][bundle_len]` as the
        //   erc7730 trailer's u16 length, skip 256–1024 bytes of names
        //   payload, then sample a random byte from inside the names
        //   bundle as the next names_count → "bad names count" on the
        //   OLED. The fix simply pads a 7th `[0, 0]` u16 so the secure
        //   parser sees an absent erc7730 slot and lands on the real
        //   NS-written names count byte.
        for _ in 0..7 {
            if pos + 2 > new_len {
                if pos + 2 > CHAIN_BUF_LEN {
                    return new_len;
                }
                CHAIN_BUF[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
                new_len = pos + 2;
                pos += 2;
            } else {
                let section_len =
                    u16::from_be_bytes([CHAIN_BUF[pos], CHAIN_BUF[pos + 1]]) as usize;
                pos += 2 + section_len;
                if pos > new_len {
                    // Declared section extends past received_len — leave
                    // it to the secure parser to reject; don't attempt
                    // recovery that could mask a real truncation bug.
                    return new_len;
                }
            }
        }
        new_len
    }


    // ===================================================================
    // GET_RESPONSE (CLA-agnostic)
    // ===================================================================

    unsafe fn get_response(&self) -> Response {
        if PENDING_PTR.is_null() || PENDING_LEN == 0 {
            return self.sw_response(SW_CONDITIONS_NOT_SATISFIED);
        }

        // Progress — the host is actively draining, so reset the
        // inter-chunk idle timeout accumulator. The absolute drain
        // deadline (`PENDING_ABS_ELAPSED_FRAMES`, finding F2) is
        // deliberately NOT reset here: keepalive activity must not
        // extend the total-exchange bound.
        PENDING_ELAPSED_FRAMES = 0;

        let remaining = PENDING_LEN - PENDING_POS;
        // FI-hardened length clamp — a glitched `chunk` value here
        // would either overflow CHUNK_BUF (if it exceeds APDU_MAX_RESP)
        // or read past `PENDING_PTR + PENDING_POS + remaining` (if it
        // exceeds `remaining`), in either case leaking adjacent memory
        // into the response. See `pqsigner_fi::fi_min` docstring.
        let chunk = pqsigner_fi::fi_min(remaining, APDU_MAX_RESP);
        static mut CHUNK_BUF: [u8; APDU_MAX_RESP + 2] = [0u8; APDU_MAX_RESP + 2];
        core::ptr::copy_nonoverlapping(PENDING_PTR.add(PENDING_POS), CHUNK_BUF.as_mut_ptr(), chunk);
        PENDING_POS += chunk;

        if PENDING_POS < PENDING_LEN {
            let left = PENDING_LEN - PENDING_POS;
            CHUNK_BUF[chunk] = SW_MORE_DATA;
            CHUNK_BUF[chunk + 1] = if left > 255 { 0xFF } else { left as u8 };
        } else {
            CHUNK_BUF[chunk] = (SW_OK >> 8) as u8;
            CHUNK_BUF[chunk + 1] = (SW_OK & 0xFF) as u8;
            PENDING_PTR = core::ptr::null();
            PENDING_LEN = 0;
            PENDING_POS = 0;
        }

        Response {
            ptr: CHUNK_BUF.as_ptr(),
            len: chunk + 2,
        }
    }

    /// Enforce the GET_RESPONSE drain timeouts. Call once per NS
    /// poll-loop iteration with the current `OTG_DSTS.FNSOF`
    /// (`usb::usb_frame_number`). Two bounds, either one scrubs the
    /// pending cursor and releases the router lease:
    ///   * idle: no GET_RESPONSE for `PENDING_TIMEOUT_FRAMES` (30 s), so
    ///     a stalled host can't pin the buffer;
    ///   * absolute: `PENDING_ABS_TIMEOUT_FRAMES` (120 s) of total drain
    ///     lifetime regardless of keepalive activity (finding F2), so a
    ///     slow-drain can't pin the F11 lease indefinitely.
    /// No-op when no drain is in progress.
    ///
    /// # Safety
    /// Touches the module `PENDING_*` static-mut state under the
    /// single-threaded NS dispatcher invariant (same as `get_response`
    /// / `dispatch`).
    pub unsafe fn check_response_timeout(&self, now_frame: u16) {
        if PENDING_PTR.is_null() {
            // No drain in progress — keep the clock reference fresh so
            // the first frame of the next drain measures a small delta.
            PENDING_ELAPSED_FRAMES = 0;
            PENDING_ABS_ELAPSED_FRAMES = 0;
            PENDING_LAST_FRAME = now_frame;
            return;
        }
        let delta = now_frame.wrapping_sub(PENDING_LAST_FRAME) & 0x3FFF;
        PENDING_LAST_FRAME = now_frame;
        PENDING_ELAPSED_FRAMES = PENDING_ELAPSED_FRAMES.saturating_add(delta as u32);
        // Activity resets the idle accumulator in `get_response` but
        // never this absolute one.
        PENDING_ABS_ELAPSED_FRAMES = PENDING_ABS_ELAPSED_FRAMES.saturating_add(delta as u32);
        if PENDING_ELAPSED_FRAMES >= PENDING_TIMEOUT_FRAMES
            || PENDING_ABS_ELAPSED_FRAMES >= PENDING_ABS_TIMEOUT_FRAMES
        {
            // Abandoned or over-long drain — scrub, and release the router
            // lease (F11) so a new channel can start a fresh exchange. A
            // pending drain and a live chain are mutually exclusive, so
            // clearing the owner here is safe.
            PENDING_PTR = core::ptr::null();
            PENDING_LEN = 0;
            PENDING_POS = 0;
            PENDING_ELAPSED_FRAMES = 0;
            PENDING_ABS_ELAPSED_FRAMES = 0;
            ROUTER_OWNER = None;
        }
    }

    /// Enforce the 30-second total-lifetime bound on a chained-APDU
    /// exchange (work-todo X17-UC1). Call once per NS poll-loop
    /// iteration, next to `check_response_timeout`. The chain state
    /// machine itself (`ChainState::tick_timeout`) owns the clock and
    /// the reset; on expiry this releases the F11 router lease so a
    /// crashed or keepalive-dripping chain-opener cannot lock out every
    /// other channel until power-cycle. No-op when no chain is live.
    ///
    /// # Safety
    /// Touches the module `ROUTER_OWNER` static-mut state under the
    /// single-threaded NS dispatcher invariant (same as `dispatch`).
    pub unsafe fn check_chain_timeout(&mut self, now_frame: u16) {
        let delta = now_frame.wrapping_sub(CHAIN_LAST_FRAME) & 0x3FFF;
        CHAIN_LAST_FRAME = now_frame;
        if self.chain.tick_timeout(delta as u32) {
            // Chain lifetime expired — `tick_timeout` already reset the
            // chain state. A live chain and a pending drain are mutually
            // exclusive, so clearing the owner here is safe.
            ROUTER_OWNER = None;
        }
    }

    // ===================================================================
    // Firmware-update command handlers (STM32U585 only)
    // ===================================================================

    /// CMD_FW_BEGIN — the 8 KB manifest has been accumulated in
    /// `CHAIN_BUF[..len]`. Hand the whole buffer to the secure world.
    #[cfg(feature = "stm32u585")]
    unsafe fn cmd_fw_begin(&self, len: usize) -> Response {
        if len != fw_manifest::MANIFEST_SIZE {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let status = nsc_api::fw_begin(&CHAIN_BUF[..len]);
        self.sw_response(nsc_status_to_sw(status))
    }

    /// CMD_FW_CHUNK — one APDU, payload is `[header(8) | data(N)]`.
    /// Pass straight through; the secure world does the monotonic /
    /// bounds checks against its in-SRAM streaming state.
    #[cfg(feature = "stm32u585")]
    unsafe fn cmd_fw_chunk(&self, data: &[u8]) -> Response {
        if data.len() < FW_CHUNK_HEADER_LEN
            || data.len() > FW_CHUNK_HEADER_LEN + FW_MAX_CHUNK
        {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let status = nsc_api::fw_chunk(data);
        self.sw_response(nsc_status_to_sw(status))
    }

    /// CMD_FW_COMMIT — may not return if the commit succeeds (the
    /// device resets). Maps to a cancelled status word if the user
    /// rejects the dialog.
    #[cfg(feature = "stm32u585")]
    unsafe fn cmd_fw_commit(&self) -> Response {
        let status = nsc_api::fw_commit();
        self.sw_response(nsc_status_to_sw(status))
    }

    /// CMD_FW_STATUS — returns `[state|recv_s|recv_ns|slot]` + SW.
    #[cfg(feature = "stm32u585")]
    unsafe fn cmd_fw_status(&self) -> Response {
        let mut out = [0u8; FW_STATUS_RESPONSE_LEN];
        let status = nsc_api::fw_status(&mut out);
        if status != 0 {
            return self.sw_response(nsc_status_to_sw(status));
        }
        // Copy response + SW into RESP_BUF.
        RESP_BUF[..FW_STATUS_RESPONSE_LEN].copy_from_slice(&out);
        RESP_BUF[FW_STATUS_RESPONSE_LEN] = (SW_OK >> 8) as u8;
        RESP_BUF[FW_STATUS_RESPONSE_LEN + 1] = (SW_OK & 0xFF) as u8;
        Response {
            ptr: RESP_BUF.as_ptr(),
            len: FW_STATUS_RESPONSE_LEN + 2,
        }
    }

    /// CMD_FW_ABORT — discard partial update. Always returns OK; the
    /// secure-side drop is idempotent.
    #[cfg(feature = "stm32u585")]
    unsafe fn cmd_fw_abort(&self) -> Response {
        let status = nsc_api::fw_abort();
        self.sw_response(nsc_status_to_sw(status))
    }

    // ===================================================================
    // Prodtest command handlers (`prodtest` feature only)
    // ===================================================================
    //
    // Each handler wraps a `CMD_PRODTEST_*` veneer. Response layout:
    //   [output_bytes ... | sw_hi | sw_lo]
    // SW is `SW_OK` on Ok, `SW_INTERNAL_ERROR` otherwise. Output bytes
    // are appended even on failure paths so the host fixture can still
    // log diagnostic data (e.g. the BUTTON_TEST step-status byte).

    #[cfg(feature = "prodtest")]
    unsafe fn prodtest_finalize(&self, n: usize, status: u32) -> Response {
        let sw = if status == 0 { SW_OK } else { SW_INTERNAL_ERROR };
        RESP_BUF[n] = (sw >> 8) as u8;
        RESP_BUF[n + 1] = (sw & 0xFF) as u8;
        Response {
            ptr: RESP_BUF.as_ptr(),
            len: n + 2,
        }
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_get_id(&self) -> Response {
        let mut out = [0u8; 24];
        let status = nsc_api::prodtest_get_id(&mut out);
        RESP_BUF[..24].copy_from_slice(&out);
        self.prodtest_finalize(24, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_display_pattern(&self, data: &[u8]) -> Response {
        if data.len() != 4 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let pattern = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let status = nsc_api::prodtest_display_pattern(pattern);
        self.prodtest_finalize(0, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_saes_selftest(&self) -> Response {
        let mut out = [0u8; 8];
        let status = nsc_api::prodtest_saes_selftest(&mut out);
        RESP_BUF[..8].copy_from_slice(&out);
        self.prodtest_finalize(8, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_bhk_selftest(&self) -> Response {
        let mut out = [0u8; 8];
        let status = nsc_api::prodtest_bhk_selftest(&mut out);
        RESP_BUF[..8].copy_from_slice(&out);
        self.prodtest_finalize(8, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_flash_rw(&self, data: &[u8]) -> Response {
        if data.len() != 4 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let pattern = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let status = nsc_api::prodtest_flash_rw(pattern);
        self.prodtest_finalize(0, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_trng_sample(&self, data: &[u8]) -> Response {
        if data.len() != 4 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let n = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        // Reserve the shared two-byte status-word suffix in RESP_BUF.
        if n == 0 || n as usize > PRODTEST_MAX_RESPONSE_DATA_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let n_usize = n as usize;
        // Buffer carved from RESP_BUF directly to avoid a stack copy.
        let status = nsc_api::prodtest_trng_sample(n, &mut RESP_BUF[..n_usize]);
        self.prodtest_finalize(n_usize, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_optiga_handshake(&self) -> Response {
        let mut out = [0u8; 16];
        let status = nsc_api::prodtest_optiga_handshake(&mut out);
        RESP_BUF[..16].copy_from_slice(&out);
        self.prodtest_finalize(16, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_se050_handshake(&self) -> Response {
        let mut out = [0u8; 16];
        let status = nsc_api::prodtest_se050_handshake(&mut out);
        RESP_BUF[..16].copy_from_slice(&out);
        self.prodtest_finalize(16, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_usb_loopback(&self, data: &[u8]) -> Response {
        if data.is_empty() || data.len() > PRODTEST_MAX_RESPONSE_DATA_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        // Use a stack buffer for the input copy so the input and
        // output don't overlap on the secure side (`crate::SE` may not
        // tolerate aliased ptrs).
        let mut buf = [0u8; PRODTEST_MAX_RESPONSE_DATA_LEN];
        buf[..data.len()].copy_from_slice(data);
        let status = nsc_api::prodtest_usb_loopback(
            &buf[..data.len()],
            &mut RESP_BUF[..data.len()],
        );
        self.prodtest_finalize(data.len(), status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_button_test(&self) -> Response {
        let mut out = [0u8; 4];
        let status = nsc_api::prodtest_button_test(&mut out);
        RESP_BUF[..4].copy_from_slice(&out);
        self.prodtest_finalize(4, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_rgb_test(&self, data: &[u8]) -> Response {
        if data.len() != PRODTEST_RGB_IN_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let mut req = [0u8; PRODTEST_RGB_IN_LEN];
        req.copy_from_slice(data);
        let mut out = [0u8; PRODTEST_RGB_OUT_LEN];
        let status = nsc_api::prodtest_rgb_test(&req, &mut out);
        RESP_BUF[..PRODTEST_RGB_OUT_LEN].copy_from_slice(&out);
        self.prodtest_finalize(PRODTEST_RGB_OUT_LEN, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_rng_config(&self) -> Response {
        let mut out = [0u8; PRODTEST_RNG_CONFIG_LEN];
        let status = nsc_api::prodtest_rng_config(&mut out);
        RESP_BUF[..PRODTEST_RNG_CONFIG_LEN].copy_from_slice(&out);
        self.prodtest_finalize(PRODTEST_RNG_CONFIG_LEN, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_rgb_osd(&self, data: &[u8]) -> Response {
        if data.len() != PRODTEST_RGB_OSD_IN_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let mut req = [0u8; PRODTEST_RGB_OSD_IN_LEN];
        req.copy_from_slice(data);
        let mut out = [0u8; PRODTEST_RGB_OSD_OUT_LEN];
        let status = nsc_api::prodtest_rgb_osd(&req, &mut out);
        RESP_BUF[..PRODTEST_RGB_OSD_OUT_LEN].copy_from_slice(&out);
        self.prodtest_finalize(PRODTEST_RGB_OSD_OUT_LEN, status)
    }

    // ===================================================================
    // Helpers
    // ===================================================================

    /// Set up chunked GET_RESPONSE state for `total_data` bytes in SIG_BUF.
    unsafe fn setup_chunked_response(&self, total_data: usize) -> Response {
        SIG_BUF[total_data] = (SW_OK >> 8) as u8;
        SIG_BUF[total_data + 1] = (SW_OK & 0xFF) as u8;

        if total_data <= APDU_MAX_RESP {
            return Response {
                ptr: SIG_BUF.as_ptr(),
                len: total_data + 2,
            };
        }

        let first_chunk = APDU_MAX_RESP;
        let remaining = total_data - first_chunk;

        PENDING_PTR = SIG_BUF.as_ptr().add(first_chunk);
        PENDING_LEN = remaining;
        PENDING_POS = 0;

        static mut FIRST_RESP: [u8; APDU_MAX_RESP + 2] = [0u8; APDU_MAX_RESP + 2];
        core::ptr::copy_nonoverlapping(SIG_BUF.as_ptr(), FIRST_RESP.as_mut_ptr(), first_chunk);
        FIRST_RESP[first_chunk] = SW_MORE_DATA;
        FIRST_RESP[first_chunk + 1] = if remaining > 255 { 0xFF } else { remaining as u8 };

        Response {
            ptr: FIRST_RESP.as_ptr(),
            len: first_chunk + 2,
        }
    }

    unsafe fn sw_response(&self, sw: u16) -> Response {
        RESP_BUF[0] = (sw >> 8) as u8;
        RESP_BUF[1] = (sw & 0xFF) as u8;
        Response {
            ptr: RESP_BUF.as_ptr(),
            len: 2,
        }
    }

    unsafe fn nsc_status_to_response(&self, status: u32) -> Response {
        self.sw_response(nsc_status_to_sw(status))
    }
}

/// Read a big-endian u32 starting at `off` in `buf`, returning `None`
/// if reading 4 bytes (or the implicit follow-on length field at
/// `off + 4 + len`) would walk past the buffer end. The reads are
/// length-only — callers are responsible for keeping the response
/// pointer inside `SIG_BUF` once the framing has been validated.
#[inline]
fn read_be_u32(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    if end > buf.len() {
        return None;
    }
    Some(u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]))
}

/// Free function so new FW_* command handlers can reuse the mapping
/// without going through a `&self` method. (The existing sign path
/// keeps using `nsc_status_to_response` which wraps this.)
fn nsc_status_to_sw(status: u32) -> u16 {
    match NscStatus::from(status) {
        NscStatus::Ok => SW_OK,
        NscStatus::PinIncorrect => SW_SECURITY_NOT_SATISFIED,
        NscStatus::PinLocked => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::NotInitialized => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::UserRejected => SW_SECURITY_NOT_SATISFIED,
        NscStatus::InvalidPointer => SW_INTERNAL_ERROR,
        NscStatus::CryptoError => SW_INTERNAL_ERROR,
        NscStatus::IdleWipe => SW_REFERENCED_DATA_INVALIDATED,
        // Firmware-update statuses. Map to APDU status words that
        // distinguish "transient retriable" from "permanent — abort".
        //
        // BadState, BadChunk, FlashError → SW_CONDITIONS_NOT_SATISFIED
        //   The companion can issue CMD_FW_ABORT and retry from BEGIN.
        //   (FlashError is also what the post-FA-1.5 fail-closed COMMIT
        //   refusal returns; on this build shape COMMIT can never
        //   succeed, so the "retry" advice is moot but harmless.)
        // BadManifest, BadVersion, BadImage → SW_WRONG_DATA
        //   The release the companion holds is unacceptable to this
        //   device. The companion must fetch a different release.
        // (FwUpdateOtpExhausted → SW_FEATURE_NOT_SUPPORTED was RETIRED in
        //   FA-1.5 with the removed unary OTP floor writer.)
        NscStatus::FwUpdateBadState => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::FwUpdateBadChunk => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::FwUpdateFlashError => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::FwUpdateBadManifest => SW_WRONG_DATA,
        NscStatus::FwUpdateBadVersion => SW_WRONG_DATA,
        NscStatus::FwUpdateBadImage => SW_WRONG_DATA,
        // Off-chain (EIP-1271) sign refusals. All recoverable on the
        // companion side: register a slot / publish a UserOp / rotate.
        NscStatus::OffchainSlotUnregistered => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::OffchainGapExceeded => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::OffchainCapExceeded => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::InternalError => SW_INTERNAL_ERROR,
    }
}

```


### From `docs/companion/usb-protocol-v2.md`

# PQSigner USB Protocol v2 (post-all-C10 cutover)

Companion app integration guide for the PQSigner post-quantum hardware wallet.

## Transport Layer

| Property | Value |
|----------|-------|
| USB class | Custom HID (usage page 0xFFA0) |
| VID / PID | 0x1209 / 0x7051 |
| Report size | 64 bytes (interrupt EP1 IN/OUT) |
| Framing | Ledger-compatible APDU-over-HID |
| CLA byte | **0xF0** (v2 native) |
| Max APDU reassembly | 4096 bytes (`shared::apdu_framing::MAX_APDU_RX`) |

### HID Frame Format

```
First frame (57 bytes payload):
  [0..2)  channel_id   u16 BE
  [2]     tag          0x05 = APDU
  [3..5)  sequence     u16 BE = 0x0000
  [5..7)  total_len    u16 BE (full APDU length)
  [7..64) data         up to 57 bytes

Continuation frames (59 bytes payload):
  [0..2)  channel_id   u16 BE
  [2]     tag          0x05
  [3..5)  sequence     u16 BE (1, 2, 3, ...)
  [5..64) data         up to 59 bytes
```

### APDU Format

```
Request:   CLA(1) INS(1) P1(1) P2(1) [Lc(1) Data(Lc)]
Response:  [Data] SW1(1) SW2(1)
```

### Command Chaining

For payloads exceeding 255 bytes (signing commands), the companion sends
multiple APDUs with the same INS:

- **P1 = 0x00**: last or only block
- **P1 = 0x80**: more blocks follow

The device accumulates data while P1 bit 7 is set and executes only when it
receives a block with **P1 = 0x00**. `Lc` does not terminate a chain: a short
intermediate block is legal with P1=0x80, and an exact-multiple-of-255 payload
still needs its final data block marked P1=0x00.

### Response Chaining (GET_RESPONSE)

Signing responses are up to `MAX_SIGN_RESPONSE_LEN = 12,556` bytes. The device returns the first 253
bytes with `SW = 0x61FF` (more data). The companion drains the rest by
repeatedly sending `INS 0xC0` (GET_RESPONSE) until `SW = 0x9000`.

```
Host → Device:  SIGN_USEROP (chained)
Device → Host:  [253 bytes] SW=0x61FF
Host → Device:  GET_RESPONSE
Device → Host:  [253 bytes] SW=0x61FF
...
Host → Device:  GET_RESPONSE
Device → Host:  [remaining bytes] SW=0x9000
```

### Hard bounds: chain lifetime, drain deadlines, reassembly timeout

The firmware bounds every multi-frame exchange so a stalled or hostile
host cannot pin the single-session router lease (findings X17-UC1, F2,
F11). All clocks tick at the USB SOF cadence (1 frame ≈ 1 ms).

- **Command-chain total lifetime — 30 s**
  (`ChainState::CHAIN_TIMEOUT_FRAMES = 30_000`,
  `shared/src/apdu_framing.rs`). A chained upload (P1=0x80 … P1=0x00)
  must complete within 30 s of its first block. This is a
  total-exchange deadline, NOT an idle timeout: sending more blocks
  does not extend it. On expiry the device silently resets the chain
  and releases the session lease. A late P1=0x80 block is then accepted
  as the FIRST block of a brand-new chain, and a following P1=0x00
  block executes the truncated accumulation — the secure parsers reject
  truncated payloads, so the host sees a late error SW (e.g. 0x6700 /
  0x6A80) from the final block rather than a chain-abort signal at the
  moment of expiry. Retry guidance: finish a chain well inside 30 s;
  after any long pause or late failure, resend the entire chain from
  block 0 — never try to resume a stale chain.

- **GET_RESPONSE drain idle timeout — 30 s**
  (`PENDING_TIMEOUT_FRAMES`, `nonsecure/src/usb/commands.rs`). Each
  successful GET_RESPONSE resets this clock; 30 s of host silence
  scrubs the pending response and releases the lease. Host-visible
  effect: the next GET_RESPONSE returns SW 0x6985. Retry guidance:
  re-issue the original command and drain without long pauses.

- **GET_RESPONSE drain absolute deadline — 120 s**
  (`PENDING_ABS_TIMEOUT_FRAMES`, same file). NOT reset by drain
  activity: a drain must complete within 120 s of its first chunk
  regardless of keepalives. Host-visible effect on expiry is the same
  as the idle timeout (pending data scrubbed; next GET_RESPONSE →
  0x6985). A worst-case legitimate drain (17 initCode chunks; a full
  12,556-byte signing response) needs far less even at seconds per
  round-trip, so 0x6985 mid-drain means the exchange is dead — restart
  the command from scratch.

- **Single-session router lease (F11)**
  (`router_lease_allows`, `shared/src/apdu_framing.rs`). While any
  chain or drain is live, APDUs arriving on a different HID channel are
  refused with SW 0x6985 without disturbing the owning channel's state.
  The lease releases when the exchange completes or one of the
  deadlines above fires. Guidance: one host session at a time — a
  second app or channel must wait out at most the bounds above.

- **Transport RX reassembly timeout — 5 s**
  (`RX_REASSEMBLY_TIMEOUT_FRAMES = 5000`,
  `nonsecure/src/usb/transport.rs`). Once the first HID frame of an
  APDU arrives, its continuation frames must complete within 5 s or the
  partial reassembly is scrubbed. Host-visible effect: no response at
  all — the device silently drops the partial APDU. Retry guidance:
  send an APDU's HID frames back-to-back; after any gap over 5 s,
  resend the whole APDU starting at sequence 0.

## Instruction Set

> **Source of truth.** Authoritative INS values live in `proto/src/lib.rs`
> (search for `INS_V2_*`). This table is a convenience snapshot — when in
> doubt, check the constants.

After the all-C10 cutover, the v2 protocol exposes the following commands:

| INS  | Name                   | Chained? | P1         |
|------|------------------------|----------|------------|
| 0x01 | GET_DEVICE_INFO        | No       | 0          |
| 0x02 | GET_STATUS             | No       | 0          |
| 0x10 | UNLOCK                 | No       | 0          |
| 0x11 | LOCK                   | No       | 0          |
| 0x30 | SIGN_USEROP (unified)  | Yes      | 0x00/0x80  |
| 0x32 | SIGN_USEROP_BATCH      | Yes      | 0x00/0x80  |
| 0x60 | GET_WALLET_ADDRESS     | No       | 0          |
| 0x61 | GET_INIT_CODE          | No       | 0          |
| 0x62 | SIGN_OFFCHAIN          | Yes      | 0x00/0x80  |
| 0x63 | OFFCHAIN_STATUS        | No       | 0          |
| 0x70 | FW_BEGIN               | Yes      | 0x00/0x80  |
| 0x71 | FW_CHUNK               | No       | 0          |
| 0x72 | FW_COMMIT              | No       | 0          |
| 0x73 | FW_STATUS              | No       | 0          |
| 0x74 | FW_ABORT               | No       | 0          |
| 0xC0 | GET_RESPONSE           | No       | 0          |

### 0x30 SIGN_USEROP — unified sign

**This is the only single-UserOp signing command in the post-cutover wallet.**
The companion's flags request initCode or Type 1 output; firmware does not infer
registration state. Current production companions may request the slot-0
factory-deploy path or Type 2 only. They must not request/submit Type 1 until
the reviewed wire bump described below supplies its missing binding material.

**Input payload (`SIGN_USEROP_HEADER_LEN = 330` bytes of header + inner
calldata):**

```
offset  size  field
---------------------------------------------------------
  0     8    chain_id (u64 BE)
  8     4    flags (u32 BE — see shared/src/lib.rs)
 12    20    sender (MUST equal GET_WALLET_ADDRESS(account_index); mismatch is refused)
 32    20    entry_point (EntryPoint v0.6 address)
 52    32    nonce (u256 BE: high 192-bit v0.6 lane key | low 64-bit sequence;
                   base nonce for Type 1 if needed else Type 2)
 84    32    call_gas_limit (u256 BE)
116    32    verification_gas_limit (u256 BE)
148    32    pre_verification_gas (u256 BE)
180    32    max_fee_per_gas (u256 BE)
212    32    max_priority_fee_per_gas (u256 BE)
244    32    paymaster_and_data_hash (sha256, SHA256_EMPTY when empty)
276    20    to_address (inner tx recipient)
296    32    value (u256 BE)
328     2    data_len (u16 BE, 0..=4096)
330     N    data
```

Before any signature is released, every confirmation set includes a mandatory
`Signer acct #N` page followed by the full EIP-55 address independently derived
for `account_index` in secure world. The wire `sender` must match that address,
but is not trusted as the source of the displayed identity. Batch signing shows
the same identity for each member confirmation and again at the final batch
authorization gate.

EntryPoint v0.6 parallel nonce lanes remain supported. The normal renderer's
`Nonce:` row shows the low-64 sequence. If the high-192 lane key is non-zero,
every applicable confirmation set additionally includes one exact
`Nonce lane key:` page containing all 48 lowercase hexadecimal characters.
Lane zero omits the page. The page is reconstructed from the same full nonce
that enters the respective transaction/batch `userOpHash` and is independently
FI-proved before confirmation. With `FLAG_REGISTER_SLOT`, the rotation signature
uses the Type-1 base nonce and its displayed high-192 lane is shared with the
transaction; transaction/batch confirmations show the exact Type-2 `base + 1`
sequence. CRIT-17 rejects low-64 overflow before it can change lanes.

**Response (post-2026-04-29 layout):**

```
[new_offchain_count   u64 BE]               (8 bytes — for Type 2 calldata)
[init_code_len        u32 BE]
[init_code            init_code_len bytes]  (4280 B when FLAG_INCLUDE_INIT_CODE, else 0)
[type1_len            u32 BE]
[type1_wrapper        type1_len bytes]      (4128 B when FLAG_REGISTER_SLOT, else 0)
[type2_len            u32 BE]
[type2_wrapper        type2_len bytes]      (always 4128 B)
```

- `type1_len == 0` means only that no Type 1 was requested/emitted. Except for
  slot 0 installed atomically by the factory path, the companion must verify
  the selected slot is already registered on-chain before requesting Type 2.
- `type1_len == 4128` means firmware signed a rotation to slot N≥1. Wire v2
  does not return the 64-byte new slot public key required to reconstruct the
  signed `addOwnerBytes(bytes)` calldata. Seedless production companions MUST
  reject this response and MUST NOT retry it until a reviewed protocol bump
  supplies the public key or complete Type-1 calldata.

**Type 1 / Type 2 wrapper (each exactly 4128 bytes):**

Both are `abi.encode(uint256 ownerIndex, bytes c10Sig)` where
`c10Sig` is a raw 4008-byte SPHINCS+C10 signature
(`C10_SIG_LEN = 4008`, `OWNER_BYTES_LEN = 64`). The wallet contract
ABI-decodes them as `SignatureWrapper(uint256 ownerIndex, bytes signatureData)`
in `validateUserOp`:

- `ownerIndex == 0` → Type 1 (bootstrap-key sig); installs the slot pubkey
  at the wrapper's destination index.
- `ownerIndex >= 1` → Type 2 (slot-key sig); executes the user's call
  via `executeWithOffchainCount(...)` which atomically updates
  `offchainSigCount[i]` to `new_offchain_count`.

The companion wraps an available wrapper in an EntryPoint v0.6 `UserOperation`
(`UserOperation06`) with the appropriate
`callData`:

- **Type 1 UserOp (rotation, currently companion-blocked):** the signed calldata
  is exactly `addOwnerBytes(newSlotPk)`. A no-op `execute(sender,0,"")` has a
  different hash and fails the contract's Type-1 selector gate. Do not submit
  it. First deployment is not Type 1: set `FLAG_INCLUDE_INIT_CODE`, use slot 0,
  and keep `FLAG_REGISTER_SLOT` clear; the factory installs slot 0.
- **Type 2 UserOp**: `callData = executeWithOffchainCount(ownerIndex,
  new_offchain_count, to, value, data)` — the wallet bumps the EIP-1271
  off-chain counter and dispatches the user's call atomically.

### 0x10 UNLOCK

No arguments. The secure world takes over the trusted UI, prompts the
user for their PIN via buttons, and (on success) unlocks both secure
elements. The PIN never crosses the gateway.

Response is a status word only (no data).

### 0x02 GET_STATUS

Returns:
```
[locked u8] [pin_remaining u8]
```

There is deliberately NO `provisioned` byte: the firmware once emitted
one derived as `pin_remaining <= MAX_ATTEMPTS`, which is always true,
so the byte was a constant-1 that reported "provisioned" even on a
blank device (finding X17-UC2). Rather than lie, the byte was removed.
A blank device runs the on-device first-boot wizard; detect that state
from the wizard UI, not from GET_STATUS.

### 0x01 GET_DEVICE_INFO

Returns a versioning + capability header. Bytes 0–1 are
`protocol_version` (u16 BE) = `PROTOCOL_VERSION` from `proto/src/lib.rs`,
currently **0x0202** (see §Protocol version history below). Reports
`ep_version = 0x0006` (EntryPoint v0.6) and `sig_param_set = 2`
(SPHINCS+C10, `C10_SIG_LEN = 4008`). Capability bit 0 is
`CAP_SIGN_USEROP`; bit 1 is retired and remains clear; bit 2 is
`CAP_ERC7730_PROOF_SET`. A companion may emit the versioned two-bundle
ERC-7730 envelope only when bit 2 is set. Do not infer that support from the
three `fw_version` bytes: they are currently a fixed placeholder rather than
the running image identity.

### 0x60 GET_WALLET_ADDRESS

Input: empty for legacy `account_index = 0`, or `[account_index u32 BE]` for
accounts `0..=255`. No chain id is accepted; wallet addresses are chain-
independent by design. Protocol 0x0202+ additionally accepts a trailing
`[show u8]` flag: `0` behaves as absent; `1` paints the full EIP-55 address
on the device OLED behind a physical confirm before the bytes are returned
(#472 — user cancel yields `0x6982` and no address); any flag above 1 is
rejected with `0x6A80`. Firmware < 0x0202 rejects the 5-byte body with
`0x6700`, so gate the flag on the GET_DEVICE_INFO report.
Output: 20-byte CREATE2-predicted ERC-1967 proxy address.
First call after unlock takes <1 s (master keygen); cached afterwards.

### 0x61 GET_INIT_CODE

Pre-computed 4280-byte `initCode` for `(account_index, chain_id)` so the
companion can run gas estimation against the EntryPoint without
round-tripping through `0x30 SIGN_USEROP`.

### 0x62 SIGN_OFFCHAIN

EIP-1271 signature response with two layouts selected by the input `flags`
byte:

- `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED = 1`:
  `[new_local_offchain_count u64 BE][C10 sig (4008 B)]` (4016 bytes total).
  Wrap the raw signature as `abi.encode(uint256 ownerIndex, bytes c10Sig)` and
  call `wallet.isValidSignature(rawHash, wrappedSig)`.
- `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED = 0`:
  `[new_local_offchain_count u64 BE][ERC-6492 blob (8608 B)]` (8616 bytes
  total). The payload is already the complete ERC-6492 wrapper; pass it through
  unchanged to an ERC-6492-aware verifier and do not ABI-wrap it again. This
  counterfactual path is restricted to slot 0.

The deployed-wallet path refuses an unregistered slot. The undeployed
counterfactual path has one narrow exception: a never-used slot 0 is
auto-registered locally so its ERC-6492 deploy-then-verify blob can be produced.
Both paths refuse when the gap exceeds `MAX_OFFCHAIN_GAP = 100` or the combined
cap is exhausted. Bootstrap key (`ownerIndex == 0`) is **forbidden** for
EIP-1271.

The input header is 17 B (`account(1) | chain(8) | slot(4) | kind(1) |
payload_len(2) | flags(1)`). The `kind` byte selects the payload
format:

| `kind`                          | Value | Payload                                                                                       |
|---------------------------------|-------|-----------------------------------------------------------------------------------------------|
| `OFFCHAIN_KIND_RAW32`           | 0     | 32 companion-supplied opaque bytes; firmware wraps via Solady nested EIP-712 and displays `! BLIND RAW32`. Never translate a typed-data request into this kind. |
| `OFFCHAIN_KIND_PERSONAL_SIGN`   | 1     | UTF-8 message ≤ `MAX_OFFCHAIN_PERSONAL_SIGN_LEN`; firmware applies EIP-191 prefix + wraps.    |
| `OFFCHAIN_KIND_EIP712_TYPED`    | 2     | EIP-712 typed-data (see below) — Phase 4 of the ERC-7730 rollout.                              |
| `OFFCHAIN_KIND_EIP712_TYPED_V3` | 3     | EIP-712 typed-data plus descriptor-selected nested/string display witnesses; see the canonical companion guide §6.5. |

`RAW32` is a deliberately loud blind-sign tier, not evidence that the device
understands a user's intent. A hostile companion can submit the final hash of
otherwise structured typed data through this kind and suppress its semantic
pages. Production companions MUST NOT downgrade structured requests to
`RAW32`; production firmware should disable the kind unless the product owner
explicitly accepts this residual.

#### `kind = OFFCHAIN_KIND_EIP712_TYPED` (2) wire format

Payload layout (immediately after the 17-byte header):

```
[u16 BE = 1]                  // domain_sep_present (must be 1)
[u8; 32] domain_separator     // EIP-712 EIP712Domain final hash
[u8; 32] primary_type_hash    // keccak256(encodeType(primaryType, types))
[u16 BE] encoded_data_len     // ≤ MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN
[u8; encoded_data_len] encoded_data
                              // canonical EIP-712 encodeData body (NOT
                              // including the type hash). Plain ABI encoding
                              // matches only flat static scalar members;
                              // dynamic/composite members use hash words.
[u16 BE] trailer_len          // ERC-7730 descriptor trailer length
[u8; trailer_len] trailer     // ERC-7730 bundle (see docs/companion/erc7730-integration.md)
```

The minimum payload length is `2 + 32 + 32 + 2 + 2 = 70` bytes (empty
`encoded_data` + zero-length trailer reaches the strict framing parser but is
rejected with `empty trailer`). The maximum payload length is
`MAX_OFFCHAIN_EIP712_TYPED_LEN`.

Secure-side processing:

1. Verify the trailer bundle against `ERC7730_DESCRIPTORS_ROOT`.
2. `cross_check_eip712(descriptor.ir, chain_id, domain_separator)` — exact,
   FI-hardened binding. The descriptor compiler forced the deployment
   `verifyingContract` into this domain separator; firmware does not receive a
   second independent contract argument on this path.
3. Constant-time select the authenticated descriptor format using the complete
   32-byte `primary_type_hash`; a four-byte prefix or catalogue hint is never
   sufficient.
4. Compute `struct_hash = keccak256(primary_type_hash || encoded_data)`.
5. Compute the EIP-712 final hash:
   `final = keccak256(0x1901 || domain_separator || struct_hash)`.
6. Render the descriptor's matching format via
   `display::erc7730::render_erc7730_eip712_pages`; render the
   ERC-8213 fingerprint with the `final` hash as the displayed value.
7. Wrap `final` through Solady's nested PersonalSign envelope (no new
   typehash, no on-chain change).
8. Sign with the slot key + bump the per-slot off-chain counter.

Output format is selected by the same deployed/counterfactual flag as kinds 0
and 1: 4016-byte count+C10 for deployed wallets, or 8616-byte
count+ERC-6492 blob for counterfactual slot 0.

### 0x63 OFFCHAIN_STATUS

Per-slot `(local_offchain_count, last_userop_count, registered)` readback.

### 0x70..0x74 FW_BEGIN/CHUNK/COMMIT/STATUS/ABORT

Streaming firmware update. PIN unlock required on every call. See
`docs/firmware/firmware-update.md`.

## Reserved / unused INS values

These INS values exist as constants in `proto/src/lib.rs` but are no
longer dispatched (or are reserved for backwards-compat probing):

- `0x20 GET_BOOTSTRAP_VK`, `0x21 GET_MAIN_VK` — superseded by
  `GET_WALLET_ADDRESS` (slot keys are derived on demand and not exposed)
- `0x31 SIGN_CLEAR_USEROP` — clear-sign is now an in-line side-effect of
  `0x30 SIGN_USEROP` when calldata is recognised (ERC-20, Safe, CowSwap…)
- `0x40 SIGN_MESSAGE`, `0x41 SIGN_EIP712` — EIP-191 / generic EIP-712 are
  served via `0x62 SIGN_OFFCHAIN` (Solady-nested EIP-712 / EIP-1271)
- `0x50 SIGN_BOOTSTRAP` — folded into `0x30 SIGN_USEROP` with
  `FLAG_REGISTER_SLOT`

## Status words

| SW     | Meaning |
|--------|---------|
| 0x9000 | OK |
| 0x6100..0x61FF | More data available; send GET_RESPONSE |
| 0x6501 | Slot exhausted (rotation path failed) |
| 0x6700 | Wrong length |
| 0x6982 | Security condition not satisfied (bad PIN, cancelled sign) |
| 0x6984 | Session expired (idle wipe) |
| 0x6985 | Device locked |
| 0x6A80 | Wrong data |
| 0x6D00 | INS not supported |
| 0x6E00 | CLA not supported |
| 0x6F00 | Internal error |

## Protocol version history

Current `PROTOCOL_VERSION` (GET_DEVICE_INFO bytes 0–1): **0x0202**
(`proto/src/lib.rs`).

- **0x0202 — GET_WALLET_ADDRESS `show` flag (#472):** INS 0x60 accepts
  an optional trailing flag byte; `show = 1` displays the derived
  address on the device OLED behind a physical confirm before it is
  returned (see §0x60 GET_WALLET_ADDRESS).
- **0x0201 — GET_STATUS layout bump (#440):** the 0x02 GET_STATUS
  response shrank from 5 bytes on the wire (3 data bytes + SW) to
  4 bytes (2 data bytes + SW). The leading `provisioned` byte was
  removed (finding X17-UC2) because it was a constant-1 that reported
  even blank devices as provisioned. Firmware reporting 0x0201 or
  later always speaks the 2-byte `[locked][pin_remaining]` layout
  (see §0x02 GET_STATUS).
- **0x0200 ambiguity window:** the layout change originally shipped
  WITHOUT a `PROTOCOL_VERSION` bump, so a 0x0200 report cannot
  distinguish pre- from post-change firmware. Pre-production only,
  with the companion shipped in lockstep. Companions MUST parse the
  current 2-byte layout and SHOULD treat any 0x0200 device as
  ambiguous vintage.



### From `docs/hardware/usb-hid-setup.md`

# USB HID Setup Guide

> **🟠 Pre-cutover protocol details superseded (2026-04-30 audit).**
>
> The hardware setup, cabling, JP4 configuration, flashing, udev rules, and
> Chrome WebHID flow described below are still correct. The **APDU command set
> shown in §"USB Protocol"** is from the v1 era (CLA `0xE0`, SLH-DSA 17,088-byte
> signatures, INS 0x02/0x04/0x06/0x08/0x0C). It does **not** describe the
> shipping protocol.
>
> Current protocol after the all-C10 cutover is **CLA `0xF0`** with INS
> `0x01..0x74` (see proto/src/lib.rs `INS_V2_*`). Authoritative spec:
>
> - `docs/companion/usb-protocol-v2.md` — wire format, INS table, request/response layouts
> - `docs/companion/companion-app-integration.md` — full integration walkthrough
> - `proto/src/lib.rs` — `INS_V2_*` constants are source of truth
>
> The hardware-setup half of this doc (CN1/CN8/JP4/cables/udev) is preserved
> as-is for board bring-up.

USB HID transport for PQSigner on the B-U585I-IOT02A discovery board.

## Hardware Setup

### Board: B-U585I-IOT02A (MB1551)

**Jumper JP4** must be set to **5V_USB_STLK** (routes ST-LINK 5V to VDDUSB).
This powers the USB transceiver from the ST-LINK debugger connection.

**BT_PWR SELECT (SW5/SW6)**: Default positions (3V3 / USB) are fine.

### Cables

You need **two cables** connected simultaneously:

| Port | Cable | Purpose |
|------|-------|---------|
| **CN8** (micro-USB) | USB-A to micro-B | ST-LINK: flashing + debug + VDDUSB power |
| **CN1** (USB-C) | USB-C to USB-A **or** USB-C to USB-C | USB HID: host communication |

Both USB-A to USB-C and USB-C to USB-C cables are supported on CN1.
With JP4 on 5V_USB_STLK the ST-LINK provides VDDUSB power regardless
of cable type.

## Building

### Auto-provisioned test build (recommended for initial testing)

```bash
make build-hw-usb-test
```

This builds:
- **Secure world**: `mock-se` + `ui-noop` + `e2e-test` (auto-provisions, no interactive wizard)
- **Non-secure world**: `usb` feature (USB HID main loop)

No semihosting — runs standalone without debugger.

### Full build (with real UI/SE, for production)

```bash
make build-hw-usb
```

Requires OLED display + buttons for PIN entry / seed wizard.

## Flashing

```bash
# Flash both worlds
make flash-hw-usb-test

# Or manually:
probe-rs download --chip STM32U585AIIx target/nonsecure/thumbv8m.main-none-eabi/release/sphincs-tz-nonsecure
probe-rs download --chip STM32U585AIIx target/secure/thumbv8m.main-none-eabi/release/sphincs-tz-secure

# Configure TrustZone option bytes (one-time)
STM32_Programmer_CLI --connect port=SWD \
    --optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
    SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000

# Reset
probe-rs reset --chip STM32U585AIIx
```

After flashing, **unplug and replug the USB-C cable** from CN1 to trigger
fresh USB enumeration.

## Linux: udev rules

Required for non-root access (WebHID, hidapi, etc.):

```bash
sudo cp tools/99-pqsigner.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
# Unplug and replug the USB-C cable
```

Verify:
```bash
lsusb | grep 1209
# Should show: ID 1209:7051 Generic PQSigner OS

ls -la /dev/hidraw*
# PQSigner's hidraw should show crw-rw-rw-
```

## Testing with WebHID (Chrome)

Open `tools/webhid_test.html` in Chrome:

```bash
google-chrome tools/webhid_test.html
```

1. Click **Connect to PQSigner**
2. Select "PQSigner OS" in the device picker
3. Try **GET_APP_CONF** — returns firmware version + device info
4. Try **GET_PUBLIC_KEY** — returns SLH-DSA verifying key (32 bytes)

## USB Protocol

The v1 APDU command set that previously lived here (CLA `0xE0`, the
0x02..0x0C INS table, and SLH-DSA 17,088-byte chunked responses) has been
**removed as superseded** — it does not describe the shipping firmware.

The current wire protocol is CLA `0xF0` with the `INS_V2_*` command set,
signing with SPHINCS+C10 (4008-byte signatures). See:

- `docs/companion/usb-protocol-v2.md` — wire format, INS table, request/response layouts
- `proto/src/lib.rs` — `APDU_CLA_V2` / `INS_V2_*` constants (source of truth)

## Architecture

```
Host PC (WebHID / node-hid / hidapi)
    |
    | USB Full-Speed (12 Mbps)
    |
[64-byte HID reports]           ← USB HID transport
    |
[APDU-over-HID framing]        ← Ledger-compatible
    |
[APDU Command Router]          ← nonsecure/src/usb/commands.rs
    |
[NSC Gateway]                   ← Shared-memory mailbox
    |
[Secure World]                  ← signing, PIN, native trusted-display decode
```

USB runs entirely in the **non-secure TrustZone world**. The secure
world only handles cryptographic operations via the existing NSC gateway.

## Troubleshooting

**Device not appearing in `lsusb`**:
- Check JP4 is on 5V_USB_STLK
- Unplug and replug USB-C cable after flashing
- Verify ST-LINK micro-USB is also connected (powers VDDUSB)
- USB-C to USB-C: ensure the cable supports data (not charge-only)

**Chrome says "no compatible devices"**:
- Install udev rules and replug the cable
- Verify `ls -la /dev/hidraw*` shows `crw-rw-rw-` for PQSigner

**Device enumerates but doesn't respond**:
- The `e2e-test` build auto-provisions with a test mnemonic
- Without `e2e-test`, the device needs OLED + buttons for first-boot wizard

