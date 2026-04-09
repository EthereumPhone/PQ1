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

    UsbStack {
        device: usb_dev,
        transport: transport::Transport::new(hid_class),
        commands: commands::CommandRouter::new(),
    }
}
