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

## Project context (condensed — full version in `docs/ai-research-briefing.md`)

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

**Why signing must run on the Cortex-M33, not the SE.** Transaction
signatures are **post-quantum SLH-DSA (SPHINCS+ SHA2-128f, migrating
to 192f)**. No commercial secure element currently computes SLH-DSA.
Bootstrap signatures are **ML-DSA-44** (also PQ, also not SE-capable).
The SEs are gated storage, not signing accelerators. The seed
therefore transits STM32 secure-world SRAM during the active signing
window (~120 s idle timeout, then zeroize). TrustZone SAU+GTZC isolates
this from the non-secure world.

**TrustZone partition.** Secure world (flash bank 1, SRAM1) owns all
crypto, PIN, persistent secrets. Non-secure world (flash bank 2,
SRAM2) owns UI, USB, tx parsing. Crossings go through 6 NSC gateway
commands with pointer validation and TOCTOU-safe copy-in.

**Power supervision state.** BOR, PVD, ECC (except SRAM1 which is
always-on), IWDG all at factory defaults. Stage 1 of a 5-stage brownout
roadmap added reset-cause classification + verified flash writes; the
rest is planned. `make stm32-harden-opts` is a one-time option-byte
setup target (sets BOR3 + SRAM2_RST=0) but has not been run yet. See
`docs/brownout-hardening.md` for the full plan.

**VBAT.** B-U585I-IOT02A holder is CR1220 (not CR2032), **unpopulated
by default**. Backup-register state machine for dual-SE wipe (Stage 4)
is planned but depends on a populated cell.

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

**Current SCP03 state.** The SE050 SCP03 channel is active (every TX
has CLA=0x84). Using NXP default static keys; rotation to per-device
keys + HUK-SAES wrapping is a production-readiness item (work-todo #7).

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
//! Configures GPIO (PA11/PA12 for D-/D+), enables VDDUSB power supply,
//! and initializes UCPD1 for USB Type-C CC pin detection on the
//! B-U585I-IOT02A discovery board.
//!
//! All configuration is done from the secure world before the non-secure
//! USB stack starts.  The USB OTG peripheral itself is marked non-secure
//! by GTZC TZSC (see sau.rs).

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// RCC registers — SECURE alias required for TZEN=1 (GPIO clock enables
// are secure-only; writes via NS alias 0x4602_xxxx are silently ignored).
// ---------------------------------------------------------------------------
const RCC_S: u32 = 0x5602_0C00;
const RCC_AHB2ENR1: *mut u32 = (RCC_S + 0x8C) as *mut u32;
const RCC_APB1ENR2: *mut u32 = (RCC_S + 0xA0) as *mut u32;
const RCC_AHB2RSTR1: *mut u32 = (RCC_S + 0x64) as *mut u32;
// Note: USB OTG FS uses ICLK (shared with RNG), already set to HSI48 in rcc.rs.

// ---------------------------------------------------------------------------
// PWR registers (secure alias — NS writes are silently ignored)
// ---------------------------------------------------------------------------
const PWR: u32 = 0x5602_0800;
const PWR_SVMCR: *mut u32 = (PWR + 0x10) as *mut u32;

// PWR_SVMCR bits (from stm32u585xx.h: PWR_SVMCR_USV_Pos = 28)
const USV: u32 = 1 << 28; // VDDUSB supply valid (removes electrical isolation)

// ---------------------------------------------------------------------------
// GPIOA registers (secure alias — GPIOA is secure by default with TZEN=1)
// ---------------------------------------------------------------------------
const GPIOA_S: u32 = 0x5202_0000;
const GPIOA_MODER: *mut u32 = (GPIOA_S + 0x00) as *mut u32;
const GPIOA_OSPEEDR: *mut u32 = (GPIOA_S + 0x08) as *mut u32;
const GPIOA_AFRH: *mut u32 = (GPIOA_S + 0x24) as *mut u32;

// GPIOB registers (secure alias)
const GPIOB_S: u32 = 0x5202_0400;
const GPIOB_MODER: *mut u32 = (GPIOB_S + 0x00) as *mut u32;
const GPIOB_OSPEEDR: *mut u32 = (GPIOB_S + 0x08) as *mut u32;
const GPIOB_AFRH: *mut u32 = (GPIOB_S + 0x24) as *mut u32;
const GPIOB_BSRR: *mut u32 = (GPIOB_S + 0x18) as *mut u32;

// GPIOA additional registers
const GPIOA_AFRL: *mut u32 = (GPIOA_S + 0x20) as *mut u32;

// ---------------------------------------------------------------------------
// UCPD1 registers — secure alias (APB1 peripherals are secure with TZEN=1;
// writes via NS alias 0x4000_xxxx are silently ignored).
// ---------------------------------------------------------------------------
const UCPD1: u32 = 0x5000_DC00;
const UCPD1_CFG1: *mut u32 = (UCPD1 + 0x00) as *mut u32;
const UCPD1_CFG2: *mut u32 = (UCPD1 + 0x04) as *mut u32;
const UCPD1_CR: *mut u32 = (UCPD1 + 0x0C) as *mut u32;

/// Initialize USB OTG FS hardware from the secure world.
///
/// This must be called after `rcc::init()` (HSI48 is already running)
/// and after `sau::init()` (GTZC TZSC has marked USB OTG as NS).
///
/// On the B-U585I-IOT02A (MB1551), the USB Type-C connector goes through
/// a **TCPP03-M20** port protection chip (U8) that must be enabled via
/// GPIO PB5 before USB data lines are connected.
///
/// Pin mapping (from UM2839 Table 8 + Table 9):
///   PA11 = USB_OTG_FS_DM (D-)    — direct to CN1
///   PA12 = USB_OTG_FS_DP (D+)    — direct to CN1
///   PA15 = UCPD1_CC1              — through TCPP03 to CN1
///   PB15 = UCPD1_CC2              — through TCPP03 to CN1
///   PB5  = TCPP03 EN (drive HIGH to enable)
///
/// # Safety
/// Direct register access.  Must be called exactly once during boot.
pub unsafe fn init() {
    // ---- 1. Enable GPIO clocks: GPIOA, GPIOB, GPIOE (AHB2ENR1 bits 0,1,4) ----
    let ahb2 = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, ahb2 | (1 << 0) | (1 << 1) | (1 << 4));
    cortex_m::asm::dsb();

    // ---- 2. Enable VDDUSB supply monitoring (PWR_SVMCR.USV) ----
    let svmcr = read_volatile(PWR_SVMCR);
    write_volatile(PWR_SVMCR, svmcr | USV);
    cortex_m::asm::dsb();

    // ---- 3. Enable USB OTG FS clock (AHB2ENR1 bit 14) ----
    let ahb2 = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, ahb2 | (1 << 14));
    cortex_m::asm::dsb();

    // USB 48 MHz clock: uses ICLK (shared with RNG), already set to HSI48 by rcc::init().

    // ---- 4. Reset USB OTG FS peripheral (AHB2RSTR1 bit 14) ----
    let rstr = read_volatile(RCC_AHB2RSTR1);
    write_volatile(RCC_AHB2RSTR1, rstr | (1 << 14));
    cortex_m::asm::dsb();
    write_volatile(RCC_AHB2RSTR1, rstr & !(1 << 14));
    cortex_m::asm::dsb();

    // ---- 6. Mark USB pins as non-secure (per-pin GPIO security) ----
    // With TZEN=1, all GPIO pins default to secure (SECCFGR = 0xFFFF).
    // The USB OTG FS peripheral runs in NS domain, so it can only drive
    // pins that are marked as non-secure. Clear the security bits for
    // PA11 (D-), PA12 (D+) and PB5 (TCPP03 EN), PB6 (CC1), PB7 (CC2).
    const GPIOA_SECCFGR: *mut u32 = (GPIOA_S + 0x30) as *mut u32;
    const GPIOB_SECCFGR: *mut u32 = (GPIOB_S + 0x30) as *mut u32;
    let a_sec = read_volatile(GPIOA_SECCFGR);
    write_volatile(GPIOA_SECCFGR, a_sec & !(1 << 11) & !(1 << 12) & !(1 << 15)); // PA11,12,15 = NS
    let b_sec = read_volatile(GPIOB_SECCFGR);
    write_volatile(GPIOB_SECCFGR, b_sec & !(1 << 5) & !(1 << 15)); // PB5,15 = NS

    #[cfg(feature = "debug-log")]
    {
        // Comprehensive register dump for USB bring-up debugging
        secure_log!(
            "[S][USB] RCC_AHB2ENR1=0x{:08x}",
            read_volatile(RCC_AHB2ENR1)
        );
        secure_log!(
            "[S][USB] GPIOA_MODER=0x{:08x} (expect PA11/12=AF=0b10)",
            read_volatile(GPIOA_MODER)
        );
        secure_log!(
            "[S][USB] GPIOA_AFRH =0x{:08x} (expect PA11/12=AF10=0xA)",
            read_volatile(GPIOA_AFRH)
        );
        // Read several offsets around 0x30 to find SECCFGR
        for off in [0x28u32, 0x2C, 0x30, 0x34] {
            let addr = GPIOA_S + off;
            let val = read_volatile(addr as *const u32);
            secure_log!(
                "[S][USB] GPIOA+0x{:02x}=0x{:08x}", off, val
            );
        }
    }

    // ---- 7. Configure PA11 (D-) and PA12 (D+) as AF10 (USB), very-high speed ----
    let moder = read_volatile(GPIOA_MODER);
    let moder = (moder & !(0b11 << 22) & !(0b11 << 24)) | (0b10 << 22) | (0b10 << 24);
    write_volatile(GPIOA_MODER, moder);

    let ospeedr = read_volatile(GPIOA_OSPEEDR);
    write_volatile(GPIOA_OSPEEDR, ospeedr | (0b11 << 22) | (0b11 << 24));

    // AFRH: PA11 = AF10, PA12 = AF10
    let afrh = read_volatile(GPIOA_AFRH);
    let afrh = (afrh & !(0xF << 12) & !(0xF << 16)) | (10 << 12) | (10 << 16);
    write_volatile(GPIOA_AFRH, afrh);

    #[cfg(feature = "debug-log")]
    {
        secure_log!(
            "[S][USB] After GPIO config: MODER=0x{:08x} AFRH=0x{:08x}",
            read_volatile(GPIOA_MODER), read_volatile(GPIOA_AFRH)
        );
    }

    // ---- 8. Enable TCPP03 (PB5 HIGH) ----
    // The TCPP03-M20 (U8) provides ESD protection and CC routing for the
    // USB-C connector (CN1).  Must be enabled for both USB-A→C and C→C cables.
    enable_tcpp03();

    // ---- 9. UCPD1 CC detection (PA15/PB15) ----
    init_ucpd();
}

/// Drive PB5 HIGH to enable the TCPP03-M20 port protection chip.
unsafe fn enable_tcpp03() {
    // PB5: output, push-pull, very-high speed, no pull
    // MODER bits [11:10] = 01 (output)
    let moder = read_volatile(GPIOB_MODER);
    write_volatile(GPIOB_MODER, (moder & !(0b11 << 10)) | (0b01 << 10));

    // OSPEEDR bits [11:10] = 11 (very high speed)
    let ospeedr = read_volatile(GPIOB_OSPEEDR);
    write_volatile(GPIOB_OSPEEDR, ospeedr | (0b11 << 10));

    // BSRR: set PB5 HIGH
    write_volatile(GPIOB_BSRR, 1 << 5);

    // Small delay for TCPP03 to initialize
    for _ in 0..100_000 {
        cortex_m::asm::nop();
    }
}

/// Initialize UCPD1 for USB Type-C CC detection (sink/device mode).
///
/// On the B-U585I-IOT02A (UM2839 Table 8):
///   PA15 = UCPD1_CC1 (analog)
///   PB15 = UCPD1_CC2 (analog)
///
/// We configure UCPD1 as a sink so the host detects Rd on CC and provides VBUS.
unsafe fn init_ucpd() {
    // Enable UCPD1 clock (APB1ENR2 bit 23)
    let apb1enr2 = read_volatile(RCC_APB1ENR2);
    write_volatile(RCC_APB1ENR2, apb1enr2 | (1 << 23));
    cortex_m::asm::dsb();

    // Configure PA15 as analog (UCPD CC1)
    // MODER bits [31:30] for PA15 = 11 (analog)
    let moder_a = read_volatile(GPIOA_MODER);
    write_volatile(GPIOA_MODER, moder_a | (0b11 << 30));

    // Configure PB15 as analog (UCPD CC2)
    // MODER bits [31:30] for PB15 = 11 (analog)
    let moder_b = read_volatile(GPIOB_MODER);
    write_volatile(GPIOB_MODER, moder_b | (0b11 << 30));

    // UCPD1 CFG1: prescaler and timing for CC detection.
    // Values follow ST's reference configuration for HSI16.
    let cfg1: u32 = (13 << 0)   // HBITCLKDIV
        | (16 << 6)              // IFRGAP
        | (7 << 11)              // TRANSWIN
        | (0b01 << 17)           // PSC_USBPDCLK = /2 (HSI16/2 = 8 MHz)
        | (1 << 31);             // UCPDEN (enable UCPD)
    write_volatile(UCPD1_CFG1, cfg1);
    cortex_m::asm::dsb();

    // UCPD1 CR: enable CC PHYs and connect Rd pull-downs (sink mode).
    // Bit 9:     ANAMODE = 1 (sink → connects 5.1kΩ Rd on CC lines)
    // Bits 11:10 CCENABLE = 11 (both CC1 and CC2 PHYs enabled)
    // Bits 21:20 CC2TCDIS:CC1TCDIS = 11 (disable dead-battery pull-downs)
    //
    // Dead-battery Rd pull-downs are active by default after reset so that
    // a USB-C host can detect the sink even before firmware runs.  Once we
    // configure the UCPD controller with its own Rd (ANAMODE=1) we must
    // disable the dead-battery resistors — they add a parallel path that
    // shifts the CC voltage and can cause mis-detection with USB-C to USB-C
    // cables (where the host Rp is driven by a UCPD controller, not a
    // fixed 56 kΩ pull-up in the cable plug as with USB-A to USB-C).
    let cr: u32 = (0b11 << 10)  // CCENABLE: both CC lines enabled
        | (1 << 9)               // ANAMODE: sink (Rd pull-down)
        | (1 << 20)              // CC1TCDIS: disable CC1 dead-battery
        | (1 << 21);             // CC2TCDIS: disable CC2 dead-battery
    write_volatile(UCPD1_CR, cr);
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
pub struct Stm32U5UsbOtgFs;

unsafe impl Sync for Stm32U5UsbOtgFs {}
unsafe impl Send for Stm32U5UsbOtgFs {}

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

/// Initialize the USB stack.  Returns a fully-configured `UsbStack` ready
/// to be polled in the main loop.
///
/// # Safety
/// Must be called exactly once.  Uses static mut for EP memory and bus allocator.
pub unsafe fn init() -> UsbStack {
    // Create the bus allocator (must live in a static)
    let alloc = UsbBus::new(Stm32U5UsbOtgFs, &mut EP_MEMORY);
    USB_BUS_ALLOC = Some(alloc);
    let bus_ref = USB_BUS_ALLOC.as_ref().unwrap();

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

use sphincs_tz_shared::{HID_REPORT_SIZE, HID_TAG_APDU, HID_TAG_PING};
use super::hid::PqSignerHid;
use super::UsbBusType;

/// Maximum single APDU size we can reassemble from HID frames.
const MAX_APDU_RX: usize = 4096;

/// Data bytes in the first HID fragment (64 - 7 header bytes).
const FIRST_DATA: usize = HID_REPORT_SIZE - 7;

/// Data bytes in continuation fragments (64 - 5 header bytes).
const CONT_DATA: usize = HID_REPORT_SIZE - 5;

/// APDU-over-HID transport state machine.
pub struct Transport {
    pub hid: PqSignerHid<'static, UsbBusType>,

    // RX state: reassemble one APDU from multiple HID frames
    channel_id: u16,
    rx_buf: [u8; MAX_APDU_RX],
    rx_expected: usize,
    rx_pos: usize,
    rx_seq: u16,

    // TX state: fragment one response APDU into multiple HID frames
    tx_buf: [u8; 256],   // response APDU (max 255 bytes, fits any single APDU)
    tx_len: usize,
    tx_pos: usize,
    tx_seq: u16,
    tx_active: bool,
}

impl Transport {
    pub fn new(hid: PqSignerHid<'static, UsbBusType>) -> Self {
        Self {
            hid,
            channel_id: 0,
            rx_buf: [0u8; MAX_APDU_RX],
            rx_expected: 0,
            rx_pos: 0,
            rx_seq: 0,
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
    pub fn try_receive(&mut self) -> Option<&[u8]> {
        let mut report = [0u8; HID_REPORT_SIZE];
        let n = self.hid.read_report(&mut report)?;
        if n < 3 {
            return None;
        }

        let channel = u16::from_be_bytes([report[0], report[1]]);
        let tag = report[2];

        // PING echo
        if tag == HID_TAG_PING {
            self.hid.write_report(&report);
            return None;
        }

        if tag != HID_TAG_APDU {
            return None;
        }

        let seq = u16::from_be_bytes([report[3], report[4]]);

        if seq == 0 {
            // First HID frame — start new APDU
            if n < 7 {
                return None;
            }
            self.channel_id = channel;
            self.rx_expected = u16::from_be_bytes([report[5], report[6]]) as usize;
            if self.rx_expected > MAX_APDU_RX || self.rx_expected == 0 {
                self.reset_rx();
                return None;
            }
            self.rx_pos = 0;
            self.rx_seq = 1;

            let avail = core::cmp::min(FIRST_DATA, self.rx_expected);
            self.rx_buf[..avail].copy_from_slice(&report[7..7 + avail]);
            self.rx_pos = avail;
        } else {
            // Continuation HID frame
            if channel != self.channel_id || seq != self.rx_seq {
                self.reset_rx();
                return None;
            }
            self.rx_seq += 1;

            let remaining = self.rx_expected - self.rx_pos;
            let avail = core::cmp::min(CONT_DATA, remaining);
            self.rx_buf[self.rx_pos..self.rx_pos + avail]
                .copy_from_slice(&report[5..5 + avail]);
            self.rx_pos += avail;
        }

        if self.rx_pos >= self.rx_expected {
            let len = self.rx_expected;
            self.rx_expected = 0;
            self.rx_pos = 0;
            self.rx_seq = 0;
            Some(&self.rx_buf[..len])
        } else {
            None
        }
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
        let copy_len = core::cmp::min(len, self.tx_buf.len());
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
            let chunk = core::cmp::min(FIRST_DATA, remaining);
            frame[7..7 + chunk].copy_from_slice(&self.tx_buf[self.tx_pos..self.tx_pos + chunk]);
            if !self.hid.write_report(&frame) {
                return false;
            }
            self.tx_pos += chunk;
            self.tx_seq += 1;
        } else {
            // Continuation HID frame
            let remaining = self.tx_len - self.tx_pos;
            let chunk = core::cmp::min(CONT_DATA, remaining);
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

    fn reset_rx(&mut self) {
        self.rx_expected = 0;
        self.rx_pos = 0;
        self.rx_seq = 0;
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
        match self.ep_out.read(buf) {
            Ok(n) => Some(n),
            Err(UsbError::WouldBlock) => None,
            Err(_) => None,
        }
    }

    /// Write a 64-byte HID report to the IN endpoint.
    /// Returns true if the write succeeded, false if the endpoint is busy.
    pub fn write_report(&mut self, data: &[u8; REPORT_SIZE]) -> bool {
        match self.ep_in.write(data) {
            Ok(_) => true,
            Err(UsbError::WouldBlock) => false,
            Err(_) => false,
        }
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
//! APDU command router — dual protocol support.
//!
//! CLA 0xE0 → v1 (Keycard Shell compatible, legacy)
//! CLA 0xF0 → v2 (PQSigner native protocol)
//!
//! The v2 protocol drops Keycard Shell compatibility in favor of
//! PQSigner-native commands that expose every device capability:
//! per-chain key derivation, bootstrap signing, ZK clear-signing,
//! EIP-191 message signing, CREATE2 address verification, and
//! structured PQSignatureWrapper responses.

use sphincs_tz_shared::*;
use crate::nsc_api;

// ---------------------------------------------------------------------------
// Static buffers
// ---------------------------------------------------------------------------

/// Maximum accumulated command data (across chained APDUs).
const CHAIN_BUF_LEN: usize = 8192;

/// Signature / UserOp response buffer — sized for the full structured
/// UserOp response (initCode + callData + wrapper) + SW bytes.
static mut SIG_BUF: [u8; MAX_USEROP_RESPONSE_LEN + 2] = [0u8; MAX_USEROP_RESPONSE_LEN + 2];

/// Sign payload assembly buffer (must fit full UserOp wire format).
const SIGN_PAYLOAD_BUF_LEN: usize = USEROP_PREFIX_LEN + 4096 + 4 + 1120 + 64;
static mut SIGN_PAYLOAD_BUF: [u8; SIGN_PAYLOAD_BUF_LEN] = [0u8; SIGN_PAYLOAD_BUF_LEN];

/// Clear-sign payload buffer.
const CLEAR_SIGN_BUF_LEN: usize = ZK_HEADER_LEN + 4096 + 4 + 2048;
static mut CLEAR_SIGN_BUF: [u8; CLEAR_SIGN_BUF_LEN] = [0u8; CLEAR_SIGN_BUF_LEN];

/// EIP-712 clear-sign payload buffer.
const EIP712_BUF_LEN: usize = EIP712_HEADER_LEN + 4 + 2048;
static mut EIP712_BUF: [u8; EIP712_BUF_LEN] = [0u8; EIP712_BUF_LEN];

/// Short response buffer (for non-signature responses).
static mut RESP_BUF: [u8; 256] = [0u8; 256];

/// Command chaining accumulation buffer.
static mut CHAIN_BUF: [u8; CHAIN_BUF_LEN] = [0u8; CHAIN_BUF_LEN];

/// Pending GET_RESPONSE state.
static mut PENDING_PTR: *const u8 = core::ptr::null();
static mut PENDING_LEN: usize = 0;
static mut PENDING_POS: usize = 0;

// ---------------------------------------------------------------------------
// Firmware version
// ---------------------------------------------------------------------------

const FW_VERSION: [u8; 3] = [0x02, 0x00, 0x00];

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
    chain_ins: u8,
    chain_pos: usize,
    /// CLA of current chaining session (0xE0 or 0xF0).
    chain_cla: u8,
    /// P2 byte from the first chaining block (v2 only). Carries
    /// per-command flags like the deployed/not-deployed mode for
    /// SIGN_USEROP.
    chain_p2: u8,
}

impl CommandRouter {
    pub fn new() -> Self {
        Self {
            chain_ins: 0,
            chain_pos: 0,
            chain_cla: 0,
            chain_p2: 0,
        }
    }

    pub unsafe fn dispatch(&mut self, apdu: &[u8]) -> Response {
        if apdu.len() < 4 {
            return self.sw_response(SW_WRONG_LENGTH);
        }

        let cla = apdu[0];
        let ins = apdu[1];
        let p1 = apdu[2];
        let p2 = apdu[3];

        // GET_RESPONSE is CLA-agnostic (shared between v1 and v2)
        if ins == INS_V2_GET_RESPONSE {
            return self.get_response();
        }

        match cla {
            APDU_CLA => self.dispatch_v1(apdu, ins, p1),
            APDU_CLA_V2 => self.dispatch_v2(apdu, ins, p1, p2),
            _ => self.sw_response(SW_CLA_NOT_SUPPORTED),
        }
    }

    // ===================================================================
    // v1 protocol (CLA 0xE0) — Keycard Shell compatible (legacy)
    // ===================================================================

    unsafe fn dispatch_v1(&mut self, apdu: &[u8], ins: u8, p1: u8) -> Response {
        let (lc, data) = if apdu.len() > 4 {
            let lc = apdu[4] as usize;
            if apdu.len() < 5 + lc {
                return self.sw_response(SW_WRONG_LENGTH);
            }
            (lc, &apdu[5..5 + lc])
        } else {
            (0, &[] as &[u8])
        };

        // Non-chained v1 commands
        match ins {
            INS_GET_APP_CONF => return self.cmd_v1_get_app_conf(),
            INS_GET_PUBLIC => return self.cmd_v1_get_public(apdu[3], data, lc),
            INS_GET_PIN_REMAINING => return self.cmd_v1_get_pin_remaining(),
            INS_UNLOCK => return self.cmd_v1_unlock(),
            _ => {}
        }

        // Chained v1 commands
        match p1 {
            P1_FIRST => {
                self.chain_ins = ins;
                self.chain_cla = APDU_CLA;
                self.chain_pos = 0;
                if lc > CHAIN_BUF_LEN {
                    self.chain_ins = 0;
                    return self.sw_response(SW_WRONG_LENGTH);
                }
                if lc > 0 {
                    CHAIN_BUF[..lc].copy_from_slice(data);
                    self.chain_pos = lc;
                }
                if lc < APDU_MAX_DATA {
                    return self.execute_chain_v1(ins);
                }
                self.sw_response(SW_OK)
            }
            P1_MORE => {
                if ins != self.chain_ins || self.chain_cla != APDU_CLA {
                    self.chain_ins = 0;
                    self.chain_pos = 0;
                    return self.sw_response(SW_CONDITIONS_NOT_SATISFIED);
                }
                if self.chain_pos + lc > CHAIN_BUF_LEN {
                    self.chain_ins = 0;
                    self.chain_pos = 0;
                    return self.sw_response(SW_WRONG_LENGTH);
                }
                CHAIN_BUF[self.chain_pos..self.chain_pos + lc].copy_from_slice(data);
                self.chain_pos += lc;
                if lc < APDU_MAX_DATA {
                    return self.execute_chain_v1(ins);
                }
                self.sw_response(SW_OK)
            }
            _ => self.sw_response(SW_WRONG_DATA),
        }
    }

    unsafe fn execute_chain_v1(&mut self, ins: u8) -> Response {
        let len = self.chain_pos;
        self.chain_ins = 0;
        self.chain_pos = 0;

        match ins {
            INS_SIGN_ETH_TX => self.cmd_v1_sign_eth_tx(&CHAIN_BUF[..len], len),
            INS_SIGN_ETH_MSG => self.cmd_v1_sign_eth_msg(&CHAIN_BUF[..len], len),
            INS_SIGN_EIP712 => self.cmd_v1_sign_eip712(&CHAIN_BUF[..len], len),
            _ => self.sw_response(SW_INS_NOT_SUPPORTED),
        }
    }

    // ===================================================================
    // v2 protocol (CLA 0xF0) — PQSigner native
    // ===================================================================

    unsafe fn dispatch_v2(&mut self, apdu: &[u8], ins: u8, p1: u8, p2: u8) -> Response {
        let (lc, data) = if apdu.len() > 4 {
            let lc = apdu[4] as usize;
            if apdu.len() < 5 + lc {
                return self.sw_response(SW_WRONG_LENGTH);
            }
            (lc, &apdu[5..5 + lc])
        } else {
            (0, &[] as &[u8])
        };

        // Non-chained v2 commands (single APDU, no P1 chaining)
        match ins {
            INS_V2_GET_DEVICE_INFO => return self.cmd_v2_get_device_info(),
            INS_V2_GET_STATUS => return self.cmd_v2_get_status(),
            INS_V2_UNLOCK => return self.cmd_v2_unlock(),
            INS_V2_LOCK => return self.cmd_v2_lock(),
            INS_V2_GET_BOOTSTRAP_VK => return self.cmd_v2_get_bootstrap_vk(),
            INS_V2_GET_MAIN_VK => return self.cmd_v2_get_main_vk(data, lc),
            INS_V2_GET_WALLET_ADDRESS => return self.cmd_v2_get_wallet_address(data, lc),
            _ => {}
        }

        // Chained v2 commands (P1=0x00 last/only, P1=0x80 more)
        let is_more = (p1 & 0x80) != 0;
        if !is_more {
            // First or only block — capture P2 for the whole chain
            self.chain_ins = ins;
            self.chain_cla = APDU_CLA_V2;
            self.chain_p2 = p2;
            self.chain_pos = 0;
            if lc > CHAIN_BUF_LEN {
                self.chain_ins = 0;
                return self.sw_response(SW_WRONG_LENGTH);
            }
            if lc > 0 {
                CHAIN_BUF[..lc].copy_from_slice(data);
                self.chain_pos = lc;
            }
            if lc < APDU_MAX_DATA {
                return self.execute_chain_v2(ins);
            }
            self.sw_response(SW_OK)
        } else {
            // Continuation block
            if ins != self.chain_ins || self.chain_cla != APDU_CLA_V2 {
                self.chain_ins = 0;
                self.chain_pos = 0;
                return self.sw_response(SW_CONDITIONS_NOT_SATISFIED);
            }
            if self.chain_pos + lc > CHAIN_BUF_LEN {
                self.chain_ins = 0;
                self.chain_pos = 0;
                return self.sw_response(SW_WRONG_LENGTH);
            }
            CHAIN_BUF[self.chain_pos..self.chain_pos + lc].copy_from_slice(data);
            self.chain_pos += lc;
            if lc < APDU_MAX_DATA {
                return self.execute_chain_v2(ins);
            }
            self.sw_response(SW_OK)
        }
    }

    unsafe fn execute_chain_v2(&mut self, ins: u8) -> Response {
        let len = self.chain_pos;
        self.chain_ins = 0;
        self.chain_pos = 0;

        match ins {
            INS_V2_SIGN_USEROP => self.cmd_v2_sign_userop(&CHAIN_BUF[..len], len),
            INS_V2_SIGN_CLEAR_USEROP => self.cmd_v2_sign_clear_userop(&CHAIN_BUF[..len], len),
            INS_V2_SIGN_MESSAGE => self.cmd_v2_sign_message(&CHAIN_BUF[..len], len),
            INS_V2_SIGN_EIP712 => self.cmd_v2_sign_eip712(&CHAIN_BUF[..len], len),
            INS_V2_SIGN_BOOTSTRAP => self.cmd_v2_sign_bootstrap(&CHAIN_BUF[..len], len),
            _ => self.sw_response(SW_INS_NOT_SUPPORTED),
        }
    }

    // ===================================================================
    // v2 command handlers
    // ===================================================================

    // -- 0x01 GET_DEVICE_INFO --

    unsafe fn cmd_v2_get_device_info(&self) -> Response {
        let mut p = 0usize;

        // protocol_version u16 BE
        RESP_BUF[p..p + 2].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        p += 2;

        // fw_major, fw_minor, fw_patch
        RESP_BUF[p..p + 3].copy_from_slice(&FW_VERSION);
        p += 3;

        // device_uid (16 bytes)
        RESP_BUF[p..p + 16].fill(0);
        p += 16;

        // capabilities u32 BE
        let caps: u32 = (1 << 0)  // UserOp signing
            | (1 << 1)            // ZK clear-sign
            | (1 << 2)            // EIP-712
            | (1 << 3)            // Personal message signing
            | (1 << 4)            // Bootstrap signer
            | (1 << 5)            // Per-chain main key derivation
            | (1 << 7);           // Address verification
        RESP_BUF[p..p + 4].copy_from_slice(&caps.to_be_bytes());
        p += 4;

        // sig_param_set u8 (0 = SHA2-128f)
        RESP_BUF[p] = 0;
        p += 1;

        // sig_size u16 BE
        RESP_BUF[p..p + 2].copy_from_slice(&(SIGNATURE_LEN as u16).to_be_bytes());
        p += 2;

        // erc20_db_version u32 BE
        RESP_BUF[p..p + 4].copy_from_slice(&0x20260408u32.to_be_bytes());
        p += 4;

        // vk_db_version u32 BE
        RESP_BUF[p..p + 4].copy_from_slice(&0x20260408u32.to_be_bytes());
        p += 4;

        // ep_version u16 BE (EntryPoint v0.6)
        RESP_BUF[p..p + 2].copy_from_slice(&0x0006u16.to_be_bytes());
        p += 2;

        // wrapper_overhead u16 BE
        RESP_BUF[p..p + 2].copy_from_slice(&(WRAPPER_HEADER_LEN as u16).to_be_bytes());
        p += 2;

        // SW
        RESP_BUF[p] = (SW_OK >> 8) as u8;
        RESP_BUF[p + 1] = (SW_OK & 0xFF) as u8;
        p += 2;

        Response { ptr: RESP_BUF.as_ptr(), len: p }
    }

    // -- 0x02 GET_STATUS --

    unsafe fn cmd_v2_get_status(&self) -> Response {
        let remaining = nsc_api::get_remaining_attempts();
        let unlocked = nsc_api::is_unlocked();

        let provisioned: u8 = if remaining <= MAX_ATTEMPTS as u32 { 1 } else { 0 };

        RESP_BUF[0] = provisioned;
        RESP_BUF[1] = if unlocked { 0 } else { 1 }; // locked = !unlocked
        RESP_BUF[2] = remaining as u8;
        RESP_BUF[3] = (SW_OK >> 8) as u8;
        RESP_BUF[4] = (SW_OK & 0xFF) as u8;

        Response { ptr: RESP_BUF.as_ptr(), len: 5 }
    }

    // -- 0x10 UNLOCK --

    unsafe fn cmd_v2_unlock(&self) -> Response {
        let status = nsc_api::request_unlock();
        self.nsc_status_to_response(status)
    }

    // -- 0x11 LOCK --

    unsafe fn cmd_v2_lock(&self) -> Response {
        nsc_api::lock();
        self.sw_response(SW_OK)
    }

    // -- 0x20 GET_BOOTSTRAP_VK --

    unsafe fn cmd_v2_get_bootstrap_vk(&self) -> Response {
        let mut vk = [0u8; VERIFYING_KEY_LEN];
        let status = nsc_api::get_bootstrap_pubkey(&mut vk);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        RESP_BUF[..VERIFYING_KEY_LEN].copy_from_slice(&vk);
        RESP_BUF[VERIFYING_KEY_LEN] = (SW_OK >> 8) as u8;
        RESP_BUF[VERIFYING_KEY_LEN + 1] = (SW_OK & 0xFF) as u8;
        Response { ptr: RESP_BUF.as_ptr(), len: VERIFYING_KEY_LEN + 2 }
    }

    // -- 0x21 GET_MAIN_VK --

    unsafe fn cmd_v2_get_main_vk(&self, data: &[u8], lc: usize) -> Response {
        if lc != MAIN_PUBKEY_PAYLOAD_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let chain_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);
        let key_index = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let mut vk = [0u8; VERIFYING_KEY_LEN];
        let status = nsc_api::get_main_pubkey(chain_id, key_index, &mut vk);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        RESP_BUF[..VERIFYING_KEY_LEN].copy_from_slice(&vk);
        RESP_BUF[VERIFYING_KEY_LEN] = (SW_OK >> 8) as u8;
        RESP_BUF[VERIFYING_KEY_LEN + 1] = (SW_OK & 0xFF) as u8;
        Response { ptr: RESP_BUF.as_ptr(), len: VERIFYING_KEY_LEN + 2 }
    }

    // -- 0x60 GET_WALLET_ADDRESS --

    unsafe fn cmd_v2_get_wallet_address(&self, data: &[u8], lc: usize) -> Response {
        if lc != 60 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let mut address = [0u8; 20];
        let status = nsc_api::get_wallet_address(data, &mut address);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        RESP_BUF[..20].copy_from_slice(&address);
        RESP_BUF[20] = (SW_OK >> 8) as u8;
        RESP_BUF[21] = (SW_OK & 0xFF) as u8;
        Response { ptr: RESP_BUF.as_ptr(), len: 22 }
    }

    // -- 0x30 SIGN_USEROP --

    unsafe fn cmd_v2_sign_userop(&self, data: &[u8], len: usize) -> Response {
        // v2 wire: key_index(4) + ots_index(4) + AA header(304) + tx_len(2) + tx + bundle_len(2) + bundle
        // We need to translate this to the v1 NSC wire format that cmd_sign_userop expects.
        if len < USEROP_V2_HEADER_LEN + 2 {
            return self.sw_response(SW_WRONG_DATA);
        }

        let _key_index = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let _ots_index = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        // P2 carries the deployment flag: 0x00 = deployed, 0x01 = not deployed.
        let needs_init_code = self.chain_p2 == P2_NOT_DEPLOYED;

        let aa_start = 8; // skip key_index + ots_index
        let tx_len_off = USEROP_V2_HEADER_LEN;
        if tx_len_off + 2 > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        let tx_len = u16::from_be_bytes([data[tx_len_off], data[tx_len_off + 1]]) as usize;
        let tx_start = tx_len_off + 2;
        let tx_end = tx_start + tx_len;
        if tx_end > len {
            return self.sw_response(SW_WRONG_DATA);
        }

        // Check for optional bundle
        let (has_bundle, bundle_len, bundle_start) = if tx_end + 2 <= len {
            let bl = u16::from_be_bytes([data[tx_end], data[tx_end + 1]]) as usize;
            if bl > 0 && tx_end + 2 + bl <= len {
                (true, bl, tx_end + 2)
            } else {
                (false, 0, 0)
            }
        } else {
            (false, 0, 0)
        };

        // Build v1 NSC payload in SIGN_PAYLOAD_BUF.
        // Mode byte: 0=deployed, 1=deployed+bundle, 2=not-deployed, 3=not-deployed+bundle
        let mut p = 0usize;
        let mode: u8 = match (needs_init_code, has_bundle) {
            (false, false) => 0,
            (false, true) => 1,
            (true, false) => 2,
            (true, true) => 3,
        };
        SIGN_PAYLOAD_BUF[p] = mode;
        p += 1;
        // Copy AA fields (sender through paymaster_hash) — starts at data[8]
        let aa_len = USEROP_V2_HEADER_LEN - 8; // 304 bytes
        SIGN_PAYLOAD_BUF[p..p + aa_len].copy_from_slice(&data[aa_start..aa_start + aa_len]);
        p += aa_len;
        // tx_len as u32 LE
        SIGN_PAYLOAD_BUF[p..p + 4].copy_from_slice(&(tx_len as u32).to_le_bytes());
        p += 4;
        // tx data
        SIGN_PAYLOAD_BUF[p..p + tx_len].copy_from_slice(&data[tx_start..tx_end]);
        p += tx_len;
        // Optional bundle
        if has_bundle {
            SIGN_PAYLOAD_BUF[p..p + 4].copy_from_slice(&(bundle_len as u32).to_le_bytes());
            p += 4;
            SIGN_PAYLOAD_BUF[p..p + bundle_len].copy_from_slice(&data[bundle_start..bundle_start + bundle_len]);
            p += bundle_len;
        }

        // The secure world writes the structured UserOp response into SIG_BUF.
        // Response: init_code_len(4) + initCode(N) + call_data_len(4) + callData(M) + wrapper
        let status = nsc_api::sign_userop(
            &SIGN_PAYLOAD_BUF[..p],
            &mut SIG_BUF[..MAX_USEROP_RESPONSE_LEN],
        );
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        // Parse the structured response to find the total length:
        // init_code_len(4) + initCode + call_data_len(4) + callData + WRAPPER_TOTAL_LEN
        let ic_len = u32::from_be_bytes([SIG_BUF[0], SIG_BUF[1], SIG_BUF[2], SIG_BUF[3]]) as usize;
        let cd_off = 4 + ic_len;
        if cd_off + 4 > MAX_USEROP_RESPONSE_LEN {
            return self.sw_response(SW_INTERNAL_ERROR);
        }
        let cd_len = u32::from_be_bytes([
            SIG_BUF[cd_off], SIG_BUF[cd_off + 1], SIG_BUF[cd_off + 2], SIG_BUF[cd_off + 3],
        ]) as usize;
        let total = cd_off + 4 + cd_len + WRAPPER_TOTAL_LEN;
        if total > MAX_USEROP_RESPONSE_LEN {
            return self.sw_response(SW_INTERNAL_ERROR);
        }

        self.setup_chunked_response(total)
    }

    // -- 0x31 SIGN_CLEAR_USEROP --

    unsafe fn cmd_v2_sign_clear_userop(&self, data: &[u8], len: usize) -> Response {
        // v2 wire: key_index(4) + ots_index(4) + proof(384) + calldata(164) + readable(64) +
        //          AA header(304) + tx_len(2) + tx + vk_bundle_len(2) + vk_bundle
        let zk_header_start = 8; // after key_index + ots_index
        let min_len = 8 + ZK_PROOF_LEN + ZK_MAX_CALLDATA + ZK_STRING_LEN + (USEROP_V2_HEADER_LEN - 8) + 2;
        if len < min_len {
            return self.sw_response(SW_WRONG_DATA);
        }

        // Translate to v1 clear-sign NSC wire format:
        // v1: proof(384) + calldata(164) + readable(64) + [has_bundle(1)][AA header][tx_len u32 LE][tx][bundle_len u32 LE][vk_bundle]
        let mut p = 0usize;

        // Copy ZK header (proof + calldata + readable)
        let zk_len = ZK_PROOF_LEN + ZK_MAX_CALLDATA + ZK_STRING_LEN;
        CLEAR_SIGN_BUF[p..p + zk_len].copy_from_slice(&data[zk_header_start..zk_header_start + zk_len]);
        p += zk_len;

        // AA header: has_bundle = 0 (VK bundle goes at the end in v1 format)
        let aa_v2_start = zk_header_start + zk_len;
        CLEAR_SIGN_BUF[p] = 0; // has_bundle
        p += 1;
        let aa_len = USEROP_V2_HEADER_LEN - 8;
        CLEAR_SIGN_BUF[p..p + aa_len].copy_from_slice(&data[aa_v2_start..aa_v2_start + aa_len]);
        p += aa_len;

        // tx_len (v2: u16 BE → v1: u32 LE)
        let tx_len_off = aa_v2_start + aa_len;
        if tx_len_off + 2 > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        let tx_len = u16::from_be_bytes([data[tx_len_off], data[tx_len_off + 1]]) as usize;
        CLEAR_SIGN_BUF[p..p + 4].copy_from_slice(&(tx_len as u32).to_le_bytes());
        p += 4;

        // tx data
        let tx_start = tx_len_off + 2;
        let tx_end = tx_start + tx_len;
        if tx_end > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        CLEAR_SIGN_BUF[p..p + tx_len].copy_from_slice(&data[tx_start..tx_end]);
        p += tx_len;

        // VK bundle: v2 has vk_bundle_len(2) + vk_bundle; v1 has bundle_len(4) + bundle
        if tx_end + 2 > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        let vk_len = u16::from_be_bytes([data[tx_end], data[tx_end + 1]]) as usize;
        let vk_start = tx_end + 2;
        if vk_start + vk_len > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        CLEAR_SIGN_BUF[p..p + 4].copy_from_slice(&(vk_len as u32).to_le_bytes());
        p += 4;
        CLEAR_SIGN_BUF[p..p + vk_len].copy_from_slice(&data[vk_start..vk_start + vk_len]);
        p += vk_len;

        let status = nsc_api::clear_sign(&CLEAR_SIGN_BUF[..p], &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result_v1(status)
    }

    // -- 0x40 SIGN_MESSAGE --

    unsafe fn cmd_v2_sign_message(&self, data: &[u8], len: usize) -> Response {
        // v2 wire: key_index(4) + ots_index(4) + chain_id(8) + msg_len(2) + msg
        if len < 18 {
            return self.sw_response(SW_WRONG_DATA);
        }

        let status = nsc_api::sign_message(data, &mut SIG_BUF[..WRAPPER_TOTAL_LEN]);
        self.sign_result_wrapped(status)
    }

    // -- 0x41 SIGN_EIP712 --

    unsafe fn cmd_v2_sign_eip712(&self, data: &[u8], len: usize) -> Response {
        // v2 wire: key_index(4) + ots_index(4) + proof(384) + canonical(204) + readable(128) +
        //          vk_bundle_len(2) + vk_bundle
        let min_len = 8 + EIP712_PROOF_LEN + EIP712_CANONICAL_LEN + EIP712_STRING_LEN + 2;
        if len < min_len {
            return self.sw_response(SW_WRONG_DATA);
        }

        // Translate to v1 NSC wire format: proof(384) + canonical(204) + readable(128) + bundle_len(4) + vk_bundle
        // (skip key_index + ots_index which aren't in the v1 format)
        let mut p = 0usize;
        let zk_start = 8;
        let zk_len = EIP712_PROOF_LEN + EIP712_CANONICAL_LEN + EIP712_STRING_LEN;
        EIP712_BUF[p..p + zk_len].copy_from_slice(&data[zk_start..zk_start + zk_len]);
        p += zk_len;

        // VK bundle: v2 u16 BE → v1 u32 LE
        let vk_len_off = zk_start + zk_len;
        if vk_len_off + 2 > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        let vk_len = u16::from_be_bytes([data[vk_len_off], data[vk_len_off + 1]]) as usize;
        let vk_start = vk_len_off + 2;
        if vk_start + vk_len > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        EIP712_BUF[p..p + 4].copy_from_slice(&(vk_len as u32).to_le_bytes());
        p += 4;
        EIP712_BUF[p..p + vk_len].copy_from_slice(&data[vk_start..vk_start + vk_len]);
        p += vk_len;

        let status = nsc_api::clear_sign_msg(&EIP712_BUF[..p], &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result_v1(status)
    }

    // -- 0x50 SIGN_BOOTSTRAP (DEPRECATED) --
    // Bootstrap signing is now handled automatically by SIGN_USEROP when
    // P2=0x01 (not-deployed). Kept for backward compatibility.

    unsafe fn cmd_v2_sign_bootstrap(&self, data: &[u8], len: usize) -> Response {
        // v2 wire: ots_index(4) + context_tag(1) + msg_hash(32) = 37 bytes
        if len != 37 {
            return self.sw_response(SW_WRONG_DATA);
        }

        let _ots_index = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let _context_tag = data[4];
        let mut msg_hash = [0u8; 32];
        msg_hash.copy_from_slice(&data[5..37]);

        let status = nsc_api::sign_bootstrap(&msg_hash, &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result_v1(status)
    }

    // ===================================================================
    // v1 command handlers (unchanged logic from original)
    // ===================================================================

    unsafe fn cmd_v1_get_app_conf(&self) -> Response {
        let mut p = 0usize;
        RESP_BUF[p..p + 3].copy_from_slice(&FW_VERSION);
        p += 3;
        RESP_BUF[p..p + 4].copy_from_slice(&0x20260408u32.to_be_bytes());
        p += 4;
        RESP_BUF[p..p + 16].fill(0);
        p += 16;
        let mut pubkey = [0u8; VERIFYING_KEY_LEN];
        let status = nsc_api::get_pubkey(&mut pubkey);
        if status == NscStatus::Ok as u32 {
            RESP_BUF[p..p + VERIFYING_KEY_LEN].copy_from_slice(&pubkey);
        }
        p += VERIFYING_KEY_LEN;
        RESP_BUF[p] = (SW_OK >> 8) as u8;
        RESP_BUF[p + 1] = (SW_OK & 0xFF) as u8;
        p += 2;
        Response { ptr: RESP_BUF.as_ptr(), len: p }
    }

    unsafe fn cmd_v1_get_public(&self, p2: u8, data: &[u8], lc: usize) -> Response {
        if lc < 1 { return self.sw_response(SW_WRONG_DATA); }
        let mut pubkey = [0u8; VERIFYING_KEY_LEN];
        let status = nsc_api::get_pubkey(&mut pubkey);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        let mut p = 0usize;
        RESP_BUF[p] = 4;
        p += 1;
        RESP_BUF[p..p + 4].copy_from_slice(&pubkey[..4]);
        p += 4;
        RESP_BUF[p] = VERIFYING_KEY_LEN as u8;
        p += 1;
        RESP_BUF[p..p + VERIFYING_KEY_LEN].copy_from_slice(&pubkey);
        p += VERIFYING_KEY_LEN;
        if p2 == 0x01 {
            RESP_BUF[p] = 32;
            p += 1;
            RESP_BUF[p..p + 32].fill(0);
            p += 32;
        } else {
            RESP_BUF[p] = 0;
            p += 1;
        }
        RESP_BUF[p] = (SW_OK >> 8) as u8;
        RESP_BUF[p + 1] = (SW_OK & 0xFF) as u8;
        p += 2;
        Response { ptr: RESP_BUF.as_ptr(), len: p }
    }

    unsafe fn cmd_v1_sign_eth_tx(&self, data: &[u8], len: usize) -> Response {
        if len < 5 { return self.sw_response(SW_WRONG_DATA); }
        let path_elements = data[0] as usize;
        let path_bytes = 1 + path_elements * 4;
        if len < path_bytes { return self.sw_response(SW_WRONG_DATA); }
        let tx_data = &data[path_bytes..];
        let tx_len = len - path_bytes;
        if tx_len == 0 || tx_len > 4096 { return self.sw_response(SW_WRONG_LENGTH); }
        let chain_id = match crate::aa::extract_chain_id(tx_data) {
            Some(id) => id,
            None => return self.sw_response(SW_WRONG_DATA),
        };

        static ENTRYPOINT_V06: [u8; 20] = [
            0x5f, 0xf1, 0x37, 0xd4, 0xb0, 0xfd, 0xcd, 0x49, 0xdc, 0xa3,
            0x0c, 0x7c, 0xf5, 0x7e, 0x57, 0x8a, 0x02, 0x6d, 0x27, 0x89,
        ];
        let zero20 = [0u8; 20];
        let zero32 = [0u8; 32];
        let mut nonce = [0u8; 32]; nonce[31] = 1;
        let mut call_gas = [0u8; 32]; call_gas[29] = 0x01; call_gas[30] = 0x86; call_gas[31] = 0xa0;
        let mut ver_gas = [0u8; 32]; ver_gas[29] = 0x03; ver_gas[30] = 0x0d; ver_gas[31] = 0x40;
        let mut pre_gas = [0u8; 32]; pre_gas[30] = 0x52; pre_gas[31] = 0x08;
        let mut max_fee = [0u8; 32];
        max_fee[24..32].copy_from_slice(&50_000_000_000u64.to_be_bytes());
        let mut max_prio = [0u8; 32];
        max_prio[24..32].copy_from_slice(&2_000_000_000u64.to_be_bytes());

        let wrap = crate::aa::UserOpWrapper {
            sender: &zero20, entry_point: &ENTRYPOINT_V06, chain_id,
            nonce: &nonce, call_gas_limit: &call_gas, verification_gas_limit: &ver_gas,
            pre_verification_gas: &pre_gas, max_fee_per_gas: &max_fee,
            max_priority_fee_per_gas: &max_prio,
            init_code_hash: &crate::aa::KECCAK_EMPTY,
            paymaster_and_data_hash: &crate::aa::KECCAK_EMPTY,
        };
        let payload_len = crate::aa::build_userop_payload(&wrap, tx_data, &mut SIGN_PAYLOAD_BUF);
        let status = nsc_api::sign_userop(&SIGN_PAYLOAD_BUF[..payload_len], &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result_v1(status)
    }

    unsafe fn cmd_v1_sign_eth_msg(&self, data: &[u8], len: usize) -> Response {
        if len < 5 { return self.sw_response(SW_WRONG_DATA); }
        let path_elements = data[0] as usize;
        let path_bytes = 1 + path_elements * 4;
        if len < path_bytes + 4 { return self.sw_response(SW_WRONG_DATA); }
        let msg_data = &data[path_bytes..];
        let msg_len = len - path_bytes;
        if msg_len > SIGN_PAYLOAD_BUF_LEN { return self.sw_response(SW_WRONG_LENGTH); }

        let mut p = 0usize;
        SIGN_PAYLOAD_BUF[p] = 0u8;
        p += 1;
        SIGN_PAYLOAD_BUF[p..p + 4].copy_from_slice(&(msg_len as u32).to_le_bytes());
        p += 4;
        SIGN_PAYLOAD_BUF[p..p + msg_len].copy_from_slice(msg_data);
        p += msg_len;
        let status = nsc_api::sign_userop(&SIGN_PAYLOAD_BUF[..p], &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result_v1(status)
    }

    unsafe fn cmd_v1_sign_eip712(&self, data: &[u8], len: usize) -> Response {
        if len < 5 { return self.sw_response(SW_WRONG_DATA); }
        let path_elements = data[0] as usize;
        let path_bytes = 1 + path_elements * 4;
        if len < path_bytes + 4 { return self.sw_response(SW_WRONG_DATA); }
        let msg_data = &data[path_bytes..];
        let msg_len = len - path_bytes;
        if msg_len > CLEAR_SIGN_BUF_LEN { return self.sw_response(SW_WRONG_LENGTH); }
        CLEAR_SIGN_BUF[..msg_len].copy_from_slice(msg_data);
        let status = nsc_api::clear_sign_msg(&CLEAR_SIGN_BUF[..msg_len], &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result_v1(status)
    }

    unsafe fn cmd_v1_get_pin_remaining(&self) -> Response {
        let remaining = nsc_api::get_remaining_attempts();
        RESP_BUF[0] = remaining as u8;
        RESP_BUF[1] = (SW_OK >> 8) as u8;
        RESP_BUF[2] = (SW_OK & 0xFF) as u8;
        Response { ptr: RESP_BUF.as_ptr(), len: 3 }
    }

    unsafe fn cmd_v1_unlock(&self) -> Response {
        let status = nsc_api::request_unlock();
        self.nsc_status_to_response(status)
    }

    // ===================================================================
    // GET_RESPONSE — drain pending large response (shared v1/v2)
    // ===================================================================

    unsafe fn get_response(&self) -> Response {
        if PENDING_PTR.is_null() || PENDING_POS >= PENDING_LEN {
            PENDING_PTR = core::ptr::null();
            return self.sw_response(SW_CONDITIONS_NOT_SATISFIED);
        }

        let remaining = PENDING_LEN - PENDING_POS;
        let chunk = core::cmp::min(remaining, APDU_MAX_RESP);
        let is_last = (PENDING_POS + chunk) >= PENDING_LEN;

        let src = core::slice::from_raw_parts(PENDING_PTR.add(PENDING_POS), chunk);
        RESP_BUF[..chunk].copy_from_slice(src);
        PENDING_POS += chunk;

        if is_last {
            PENDING_PTR = core::ptr::null();
            RESP_BUF[chunk] = (SW_OK >> 8) as u8;
            RESP_BUF[chunk + 1] = (SW_OK & 0xFF) as u8;
            Response { ptr: RESP_BUF.as_ptr(), len: chunk + 2 }
        } else {
            let still_remaining = PENDING_LEN - PENDING_POS;
            RESP_BUF[chunk] = SW_MORE_DATA;
            RESP_BUF[chunk + 1] = if still_remaining > 255 { 0xFF } else { still_remaining as u8 };
            Response { ptr: RESP_BUF.as_ptr(), len: chunk + 2 }
        }
    }

    // ===================================================================
    // Helpers
    // ===================================================================

    /// Build chunked response for a v1 signing result (raw SIGNATURE_LEN bytes).
    unsafe fn sign_result_v1(&self, status: u32) -> Response {
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        self.setup_chunked_response(SIGNATURE_LEN)
    }

    /// Build chunked response for a v2 signing result (WRAPPER_TOTAL_LEN bytes).
    unsafe fn sign_result_wrapped(&self, status: u32) -> Response {
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        self.setup_chunked_response(WRAPPER_TOTAL_LEN)
    }

    /// Set up chunked GET_RESPONSE state for `total_data` bytes in SIG_BUF.
    unsafe fn setup_chunked_response(&self, total_data: usize) -> Response {
        // Append SW_OK after the data
        SIG_BUF[total_data] = (SW_OK >> 8) as u8;
        SIG_BUF[total_data + 1] = (SW_OK & 0xFF) as u8;

        if total_data <= APDU_MAX_RESP {
            Response {
                ptr: SIG_BUF.as_ptr(),
                len: total_data + 2,
            }
        } else {
            let first_chunk = APDU_MAX_RESP;
            let remaining = total_data - first_chunk;

            PENDING_PTR = SIG_BUF.as_ptr().add(first_chunk);
            PENDING_LEN = remaining;
            PENDING_POS = 0;

            static mut FIRST_RESP: [u8; APDU_MAX_RESP + 2] = [0u8; APDU_MAX_RESP + 2];
            core::ptr::copy_nonoverlapping(
                SIG_BUF.as_ptr(),
                FIRST_RESP.as_mut_ptr(),
                first_chunk,
            );
            FIRST_RESP[first_chunk] = SW_MORE_DATA;
            FIRST_RESP[first_chunk + 1] = if remaining > 255 { 0xFF } else { remaining as u8 };

            Response {
                ptr: FIRST_RESP.as_ptr(),
                len: first_chunk + 2,
            }
        }
    }

    unsafe fn sw_response(&self, sw: u16) -> Response {
        RESP_BUF[0] = (sw >> 8) as u8;
        RESP_BUF[1] = (sw & 0xFF) as u8;
        Response { ptr: RESP_BUF.as_ptr(), len: 2 }
    }

    unsafe fn nsc_status_to_response(&self, status: u32) -> Response {
        let sw = match NscStatus::from(status) {
            NscStatus::Ok => SW_OK,
            NscStatus::PinIncorrect => SW_SECURITY_NOT_SATISFIED,
            NscStatus::PinLocked => SW_CONDITIONS_NOT_SATISFIED,
            NscStatus::NotInitialized => SW_CONDITIONS_NOT_SATISFIED,
            NscStatus::UserRejected => SW_SECURITY_NOT_SATISFIED,
            NscStatus::InvalidPointer => SW_INTERNAL_ERROR,
            NscStatus::CryptoError => SW_INTERNAL_ERROR,
            NscStatus::IdleWipe => SW_REFERENCED_DATA_INVALIDATED,
            NscStatus::InternalError => SW_INTERNAL_ERROR,
        };
        self.sw_response(sw)
    }
}

```


### From `docs/usb-protocol-v2.md`

# PQSigner USB Protocol v2

Companion app integration guide for the PQSigner post-quantum hardware wallet.

## Transport Layer

| Property | Value |
|----------|-------|
| USB class | Custom HID (usage page 0xFFA0) |
| VID / PID | 0x1209 / 0x7051 |
| Report size | 64 bytes (interrupt EP1 IN/OUT) |
| Framing | Ledger-compatible APDU-over-HID |
| CLA byte | **0xF0** (v2 native) |
| Max APDU reassembly | 8192 bytes |

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

The device accumulates data until it receives a block with `Lc < 255`
(the short-last-chunk sentinel), then executes the command.

### Response Chaining (GET_RESPONSE)

Signing responses are 17,161 bytes. The device returns the first 253
bytes with `SW = 0x61FF` (more data). The companion drains the rest by
repeatedly sending `INS 0xC0` (GET_RESPONSE) until `SW = 0x9000`.

```
Host → Device:  SIGN_USEROP (chained)
Device → Host:  [253 bytes] SW=0x61FF
Host → Device:  GET_RESPONSE
Device → Host:  [253 bytes] SW=0x61FF
... (~68 round-trips)
Host → Device:  GET_RESPONSE
Device → Host:  [remaining bytes] SW=0x9000
```

---

## Status Words

| SW | Meaning |
|------|---------|
| 0x9000 | Success |
| 0x61XX | More data available (call GET_RESPONSE) |
| 0x6700 | Wrong length |
| 0x6982 | Security not satisfied (wrong PIN, user rejected on device) |
| 0x6984 | Idle timeout — device locked itself mid-operation |
| 0x6985 | Conditions not satisfied (device locked, not provisioned) |
| 0x6A80 | Wrong data (malformed payload, invalid ZK proof) |
| 0x6D00 | INS not supported |
| 0x6E00 | CLA not supported |
| 0x6F00 | Internal error |

---

## Command Reference

### INS 0x01 — GET_DEVICE_INFO

Capability discovery. **Always call this first.** No unlock required.

**Request:** empty

**Response (41 bytes):**

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 2 | protocol_version | u16 BE, currently `0x0200` |
| 2 | 1 | fw_major | |
| 3 | 1 | fw_minor | |
| 4 | 1 | fw_patch | |
| 5 | 16 | device_uid | STM32 UID96 (zeros on dev builds) |
| 21 | 4 | capabilities | u32 BE bitmap (see below) |
| 25 | 1 | sig_param_set | 0 = SHA2-128f, 1 = SHA2-192f |
| 26 | 2 | sig_size | u16 BE, raw signature bytes (17088) |
| 28 | 4 | erc20_db_version | u32 BE, YYYYMMDD |
| 32 | 4 | vk_db_version | u32 BE, YYYYMMDD |
| 36 | 2 | ep_version | u16 BE, EntryPoint version (0x0006) |
| 38 | 2 | wrapper_overhead | u16 BE, PQSignatureWrapper header (73) |

**Capability bitmap:**

| Bit | Feature |
|-----|---------|
| 0 | UserOp signing (SIGN_USEROP) |
| 1 | ZK clear-sign calldata (SIGN_CLEAR_USEROP) |
| 2 | EIP-712 typed-data signing (SIGN_EIP712) |
| 3 | Personal message signing (SIGN_MESSAGE) |
| 4 | Bootstrap signer (SIGN_BOOTSTRAP) |
| 5 | Per-chain main key derivation (GET_MAIN_VK) |
| 6 | CowSwap EIP-712 v3 |
| 7 | Address verification (GET_WALLET_ADDRESS) |
| 8 | Device attestation (reserved) |
| 9 | EntryPoint v0.7 (reserved) |

**Companion logic:**
```
total_wrapper_size = wrapper_overhead + sig_size  // 73 + 17088 = 17161
```

---

### INS 0x02 — GET_STATUS

Check device state before operations. No unlock required.

**Request:** empty

**Response (3 bytes):**

| Offset | Field | Values |
|--------|-------|--------|
| 0 | provisioned | 0 = not provisioned, 1 = provisioned |
| 1 | locked | 0 = unlocked, 1 = locked |
| 2 | pin_remaining | 0-10 attempts remaining |

---

### INS 0x10 — UNLOCK

Trigger PIN entry on the device's trusted OLED display. The PIN never
crosses USB — the device handles everything internally.

**Request:** empty

**Response:** SW only

- `0x9000` — unlocked successfully
- `0x6982` — wrong PIN entered
- `0x6985` — permanently locked (0 attempts remaining)
- `0x6984` — user took too long, idle timeout

**Note:** This blocks until the user finishes PIN entry on the device
(~5-30 seconds). Set your USB timeout accordingly.

---

### INS 0x11 — LOCK

Explicitly lock the device, zeroizing all cached secrets.

**Request:** empty  
**Response:** `SW 0x9000`

---

### INS 0x20 — GET_BOOTSTRAP_VK

Return the bootstrap signer's 32-byte verifying key. This key is global
(not per-chain), set at provisioning, and never changes.

**No unlock required** — the VK is public data.

**Request:** empty

**Response (32 bytes):**

```
[0..16)   pk_seed    16 bytes
[16..32)  pk_root    16 bytes
```

The bootstrap VK determines the wallet's CREATE2 address on all chains.

---

### INS 0x21 — GET_MAIN_VK

Derive and return the per-chain main signer's verifying key.

**Unlock required.**

**Request (12 bytes):**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | chain_id — u64 BE (e.g., 1 for Ethereum, 8453 for Base) |
| 8 | 4 | key_index — u32 BE (signer epoch, usually 0) |

**Response (32 bytes):**

```
[0..16)   pk_seed    16 bytes
[16..32)  pk_root    16 bytes
```

Each `(chain_id, key_index)` pair produces a cryptographically
independent keypair.

---

### INS 0x30 — SIGN_USEROP

Sign an EIP-1559 transaction as an ERC-4337 UserOperation. The device
displays the inner transaction on its trusted OLED, independently
reconstructs the `execute()` calldata, computes the `userOpHash`, and
signs it with SLH-DSA.

**Unlock required. Command chaining required.**

**Request:**

| Offset | Size | Field | Source |
|--------|------|-------|--------|
| 0 | 4 | key_index | u32 BE — from `wallet.currentKeyIndex()` |
| 4 | 4 | ots_index | u32 BE — from `wallet.currentOTSIndex()` |
| 8 | 20 | sender | wallet contract address |
| 28 | 20 | entry_point | EntryPoint address |
| 48 | 8 | chain_id | u64 BE |
| 56 | 32 | nonce | u256 BE — from EntryPoint |
| 88 | 32 | call_gas_limit | u256 BE — from bundler estimate |
| 120 | 32 | verification_gas_limit | u256 BE |
| 152 | 32 | pre_verification_gas | u256 BE |
| 184 | 32 | max_fee_per_gas | u256 BE |
| 216 | 32 | max_priority_fee_per_gas | u256 BE |
| 248 | 32 | init_code_hash | keccak256(initCode), or keccak256("") |
| 280 | 32 | paymaster_and_data_hash | keccak256(paymasterAndData), or keccak256("") |
| 312 | 2 | tx_len | u16 BE |
| 314 | tx_len | tx_data | unsigned EIP-1559 RLP envelope |
| 314+tx_len | 2 | bundle_len | u16 BE (0 = no ERC20 bundle) |
| +2 | bundle_len | bundle_data | Merkle-verified ERC20 metadata |

**Response: PQSignatureWrapper (17,161 bytes via GET_RESPONSE)**

See [PQSignatureWrapper](#pqsignaturewrapper-response-format) below.

**Constants:**
```
keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
EntryPoint v0.6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
```

---

### INS 0x31 — SIGN_CLEAR_USEROP

ZK clear-signed UserOp. A Groth16 proof attests that a human-readable
string faithfully represents the calldata. The device Merkle-verifies
the VK, runs the Groth16 verifier, displays the readable string on the
OLED, then signs the userOpHash.

**Unlock required. Command chaining required.**

**Request:**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | key_index | u32 BE |
| 4 | 4 | ots_index | u32 BE |
| 8 | 384 | proof | Groth16 proof (pi_A \|\| pi_B \|\| pi_C) |
| 392 | 164 | calldata | zero-padded to 164 bytes |
| 556 | 64 | readable | null-padded to 64 bytes |
| 620 | 20 | sender | |
| 640 | 20 | entry_point | |
| 660 | 8 | chain_id | u64 BE |
| 668 | 32 | nonce | u256 BE |
| ... | ... | *(remaining AA fields same as SIGN_USEROP)* | |
| ... | 2 | tx_len | u16 BE |
| ... | tx_len | tx_data | |
| ... | 2 | vk_bundle_len | u16 BE |
| ... | vk_bundle_len | vk_bundle | Merkle-verified VK |

**Response:** PQSignatureWrapper (17,161 bytes)

---

### INS 0x40 — SIGN_MESSAGE

EIP-191 personal_sign. The device displays the message on its trusted
OLED and signs `keccak256("\x19Ethereum Signed Message:\n" + len + msg)`.

**Unlock required. Command chaining for messages > ~230 bytes.**

**Request:**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | key_index | u32 BE |
| 4 | 4 | ots_index | u32 BE |
| 8 | 8 | chain_id | u64 BE (for display) |
| 16 | 2 | msg_len | u16 BE |
| 18 | msg_len | message | raw bytes (max 1024) |

**Response:** PQSignatureWrapper (17,161 bytes)

---

### INS 0x41 — SIGN_EIP712

EIP-712 typed data signing with ZK clear-sign verification. Used for
CowSwap GPv2 orders and future off-chain signature protocols.

**Unlock required. Command chaining required.**

**Request:**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | key_index | u32 BE |
| 4 | 4 | ots_index | u32 BE |
| 8 | 384 | proof | Groth16 proof |
| 392 | 204 | canonical | protocol-specific packed encoding |
| 596 | 128 | readable | null-padded to 128 bytes |
| 724 | 2 | vk_bundle_len | u16 BE |
| 726 | vk_bundle_len | vk_bundle | Merkle-verified VK |

**Response:** PQSignatureWrapper (17,161 bytes)

---

### INS 0x50 — SIGN_BOOTSTRAP

Sign a 32-byte hash with the bootstrap key. Used for wallet deployment
and emergency signer rotation.

**Unlock required.**

**Request (37 bytes):**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | ots_index | u32 BE — from `wallet.bootstrapOTSIndex()` |
| 4 | 1 | context_tag | 0x00=DEPLOY, 0x01=ROTATE, 0x02=GENERIC |
| 5 | 32 | msg_hash | the bytes32 to sign |

The context_tag controls what the device displays:
- `0x00`: "Deploy wallet?" + hash preview
- `0x01`: "Rotate signer?" + hash preview
- `0x02`: "Bootstrap sign?" + hash preview (warning banner)

**Response:** PQSignatureWrapper (17,161 bytes, signer_type=0x01)

---

### INS 0x60 — GET_WALLET_ADDRESS

Compute the CREATE2 wallet address from the device's stored bootstrap VK
plus factory parameters. The device independently computes the address
and displays it on the OLED for the user to verify visually.

**No unlock required.**

**Request (60 bytes):**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | chain_id | u64 BE (displayed on OLED) |
| 8 | 20 | factory_address | PQCoinbaseSmartWalletFactory |
| 28 | 32 | init_code_hash | from `factory.initCodeHash()` |

The device computes:
```
pk_seed_padded = bootstrap_vk[0..16] ++ zeros[16]
pk_root_padded = bootstrap_vk[16..32] ++ zeros[16]
salt = keccak256(pk_seed_padded ++ pk_root_padded)
address = keccak256(0xFF ++ factory ++ salt ++ init_code_hash)[12..32]
```

**Response (20 bytes):** the Ethereum address.

The user must confirm on the device before the response is sent. If the
user cancels, SW = 0x6982.

---

### INS 0xC0 — GET_RESPONSE

Drain remaining bytes of a large response. See
[Response Chaining](#response-chaining-get_response).

**Request:** empty  
**Response:** next chunk (up to 253 bytes) + SW

---

## PQSignatureWrapper Response Format

All signing commands return this structured response. The companion app
ABI-encodes it for on-chain submission in the UserOp's `signature` field.

```
[0]        signer_type    u8     0x00=MAIN, 0x01=BOOTSTRAP
[1..5)     key_index      u32 BE
[5..9)     ots_index      u32 BE
[9..41)    pk_seed        32 bytes (16 bytes right-padded to bytes32)
[41..73)   pk_root        32 bytes (16 bytes right-padded to bytes32)
[73..17161) signature     17088 bytes (SLH-DSA-SHA2-128f)
```

**Total: 17,161 bytes** (73 header + 17,088 signature)

### ABI Encoding for On-Chain

The on-chain `PQCoinbaseSmartWallet.validateUserOp()` expects:

```solidity
abi.encode(PQSignatureWrapper({
    signerType:  SignerType(wrapper[0]),        // MAIN or BOOTSTRAP
    keyIndex:    uint32(wrapper[1..5]),
    otsIndex:    uint32(wrapper[5..9]),
    pkSeed:      bytes32(wrapper[9..41]),       // already padded
    pkRoot:      bytes32(wrapper[41..73]),       // already padded
    signature:   bytes(wrapper[73..17161])
}))
```

---

## Companion App Workflows

### First Connection

```
GET_DEVICE_INFO                → capabilities, sig_size, versions
GET_STATUS                     → provisioned? locked?
if locked:
    UNLOCK                     → user enters PIN on device
GET_BOOTSTRAP_VK               → 32-byte VK → compute wallet addresses
GET_MAIN_VK(chain_id, 0)       → main signer VK for this chain
```

### Sending ETH

```
1. Build unsigned EIP-1559 envelope
2. Query bundler for gas estimates
3. Query on-chain: wallet.currentKeyIndex(), wallet.currentOTSIndex()
4. Query EntryPoint nonce

SIGN_USEROP(key_index, ots_index, aa_header, tx)
  → user confirms "Send X ETH to 0x..." on device
  → GET_RESPONSE loop → 17161-byte PQSignatureWrapper

5. ABI-encode wrapper → UserOp.signature
6. Submit UserOp to bundler
```

### DeFi Interaction (ZK Clear-Signed)

```
1. Build calldata (e.g., aave.supply(USDC, 1000))
2. Generate Groth16 proof off-device: proof binds calldata → readable
3. Look up VK bundle from local Merkle DB

SIGN_CLEAR_USEROP(key_index, ots_index, proof, calldata,
                  "Aave V3: Supply 1000 USDC", aa_header, tx, vk_bundle)
  → device verifies proof, shows "Aave V3: Supply 1000 USDC"
  → PQSignatureWrapper

4. Submit to bundler
```

### Deploy Wallet on New Chain

```
1. GET_BOOTSTRAP_VK → (pk_seed, pk_root)
2. GET_MAIN_VK(chain_id, 0) → initial main signer (pk_seed, pk_root)
3. Compute auth_msg:
     keccak256("PQWALLET_INIT_V1" ++ mainPkSeed_padded ++ mainPkRoot_padded)

4. SIGN_BOOTSTRAP(bootstrap_ots_index, 0x00, auth_msg)
     → user confirms "Deploy wallet?"
     → PQSignatureWrapper (bootstrap sig)

5. Construct initCode:
     factory_addr ++ abi.encodeCall(createAccount,
       (bootstrapPkSeed_padded, bootstrapPkRoot_padded,
        mainPkSeed_padded, mainPkRoot_padded, bootstrap_sig))

6. Build deployment UserOp with initCode
7. SIGN_USEROP(0, 0, aa_header, inner_tx)
     → PQSignatureWrapper (main sig)
8. Submit to bundler
```

### CowSwap EIP-712 Order

```
1. Pack GPv2Order into 204-byte canonical encoding
2. Generate Groth16 proof: canonical → "Sell 100 USDC for >= 80 DAI"

SIGN_EIP712(key_index, ots_index, proof, canonical, readable, vk_bundle)
  → device verifies proof, shows "Sell 100 USDC for >= 80 DAI"
  → PQSignatureWrapper

3. Submit signed order to CowSwap API
```

### Receive Funds (Address Verification)

```
GET_WALLET_ADDRESS(chain_id, factory_addr, init_code_hash)
  → device computes address, displays on OLED
  → user verifies, presses confirm
  → returns 20-byte address

Compare with locally computed address. Protects against clipboard
attacks and compromised companion displays.
```

---

## Multi-Chain Key Architecture

```
BIP-39 entropy (32 bytes, stored encrypted on dual secure elements)
  │
  ├─► Bootstrap signer (global, never rotates)
  │     domain: "pqwallet-bootstrap-*"
  │     Used for: deployment, emergency rotation
  │     Determines wallet address on all chains (via CREATE2)
  │
  ├─► Main signer (chain_id=1, key_index=0)
  │     domain: "pqwallet-main-*" + chain_id + key_index
  │     Used for: Ethereum mainnet transactions
  │     Rotates every ~1M signatures
  │
  ├─► Main signer (chain_id=8453, key_index=0)
  │     Used for: Base transactions
  │     Cryptographically independent from other chains
  │
  └─► Main signer (chain_id=42161, key_index=0)
        Used for: Arbitrum transactions
```

Same 24-word recovery phrase produces the same keys on any PQSigner
device running this firmware.

---

## Constants

```
Signature size (SHA2-128f):     17,088 bytes
Wrapper header:                 73 bytes
Total wrapper:                  17,161 bytes
Max message length:             1,024 bytes
Max inner tx length:            4,096 bytes
APDU max data per chunk:        255 bytes
APDU max response per chunk:    253 bytes
GET_RESPONSE round-trips:       ~68 for a full signature
VK size (2-public-signal):      960 bytes
VK size (3-public-signal):      1,056 bytes
ZK proof size:                  384 bytes
ZK calldata field:              164 bytes (zero-padded)
ZK readable field:              64 bytes (EIP-1559) / 128 bytes (EIP-712)
EIP-712 canonical field:        204 bytes (CowSwap GPv2Order v3)
```



### From `docs/usb-hid-setup.md`

# USB HID Setup Guide

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

The device speaks a Keycard Shell compatible APDU-over-HID protocol:

- **VID/PID**: 0x1209 / 0x7051
- **USB Class**: Custom HID (Usage Page 0xFFA0)
- **Endpoints**: EP1 IN + EP1 OUT, 64-byte Interrupt, 1ms poll
- **Framing**: Ledger-compatible (channel ID + sequence + fragmentation)
- **APDU CLA**: 0xE0

### Commands

| INS | Name | Description |
|-----|------|-------------|
| 0x02 | GET_PUBLIC | Export SLH-DSA verifying key (32 bytes) |
| 0x04 | SIGN_ETH_TX | Sign EIP-1559 transaction |
| 0x06 | GET_APP_CONF | Firmware version + device info |
| 0x08 | SIGN_ETH_MSG | Sign Ethereum message (personal_sign) |
| 0x0C | SIGN_EIP712 | Sign EIP-712 typed data |
| 0x10 | GET_PIN_REMAINING | PIN attempts remaining |
| 0x12 | UNLOCK | PIN entry on device |
| 0xC0 | GET_RESPONSE | Retrieve remaining response data |

### Command chaining

For payloads > 255 bytes, use P1-based chaining:
- P1=0x00: First chunk
- P1=0x01: Continuation chunks
- Chain ends when Lc < 255 (last chunk)

### Large responses (signatures)

SLH-DSA signatures are 17,088 bytes. Responses > 253 bytes use
APDU-level chunking:
- First response: 253 bytes data + SW=0x61FF
- Host sends GET_RESPONSE (INS 0xC0) to drain remaining data
- Final chunk: remaining data + SW=0x9000

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
[Secure World]                  ← SLH-DSA signing, PIN, ZK verify
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

