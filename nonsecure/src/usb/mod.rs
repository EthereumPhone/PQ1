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
    // Full speed: an 11-bit frame number, wrapping every 2.048 s
    // (`USB_FS_FRAME_MASK`; DVT1 row 11.2). Callers take deltas with
    // `apdu_framing::frame_delta`, never a raw subtraction.
    ((dsts >> 8) as u16) & sphincs_tz_shared::apdu_framing::USB_FS_FRAME_MASK
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
