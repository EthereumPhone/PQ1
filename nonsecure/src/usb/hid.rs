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
