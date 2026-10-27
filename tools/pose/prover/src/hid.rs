//! Vendor HID class: one 64-byte interrupt IN and OUT endpoint, no report
//! IDs. Trimmed copy of `nonsecure/src/usb/hid.rs`.

use usb_device::class_prelude::*;
use usb_device::Result;

const REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xA0, 0xFF, // Usage Page (Vendor Defined 0xFFA0)
    0x09, 0x01, //       Usage (0x01)
    0xA1, 0x01, //       Collection (Application)
    0x09, 0x20, //         Usage (0x20)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x81, 0x02, //         Input (Data, Variable, Absolute)
    0x09, 0x21, //         Usage (0x21)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x91, 0x02, //         Output (Data, Variable, Absolute)
    0xC0, //             End Collection
];

const HID_DESCRIPTOR: &[u8] = &[
    0x11, 0x01, // bcdHID 1.11
    0x00, //       country
    0x01, //       one descriptor
    0x22, //       report descriptor
    REPORT_DESCRIPTOR.len() as u8,
    0x00,
];

pub struct Hid<'a, B: UsbBus> {
    iface: InterfaceNumber,
    ep_in: EndpointIn<'a, B>,
    ep_out: EndpointOut<'a, B>,
}

impl<'a, B: UsbBus> Hid<'a, B> {
    pub fn new(alloc: &'a UsbBusAllocator<B>) -> Self {
        Self {
            iface: alloc.interface(),
            ep_in: alloc.interrupt(64, 1),
            ep_out: alloc.interrupt(64, 1),
        }
    }

    pub fn read(&mut self, buf: &mut [u8; 64]) -> bool {
        matches!(self.ep_out.read(buf), Ok(64))
    }

    pub fn write(&mut self, buf: &[u8; 64]) -> bool {
        self.ep_in.write(buf).is_ok()
    }
}

impl<B: UsbBus> UsbClass<B> for Hid<'_, B> {
    fn get_configuration_descriptors(&self, w: &mut DescriptorWriter) -> Result<()> {
        w.interface(self.iface, 0x03, 0x00, 0x00)?;
        w.write(0x21, HID_DESCRIPTOR)?;
        w.endpoint(&self.ep_in)?;
        w.endpoint(&self.ep_out)?;
        Ok(())
    }

    fn control_in(&mut self, xfer: ControlIn<B>) {
        let req = xfer.request();
        if req.index != u8::from(self.iface) as u16 || req.recipient != control::Recipient::Interface {
            return;
        }
        if req.request_type == control::RequestType::Standard && req.request == 0x06 {
            match (req.value >> 8) as u8 {
                0x22 => { let _ = xfer.accept_with_static(REPORT_DESCRIPTOR); }
                0x21 => { let _ = xfer.accept_with_static(HID_DESCRIPTOR); }
                _ => {}
            }
        } else if req.request_type == control::RequestType::Class && req.request == 0x02 {
            let _ = xfer.accept_with(&[0]); // GET_IDLE
        }
    }

    fn control_out(&mut self, xfer: ControlOut<B>) {
        let req = xfer.request();
        if req.request_type == control::RequestType::Class
            && req.recipient == control::Recipient::Interface
            && req.index == u8::from(self.iface) as u16
            && req.request == 0x0A
        {
            let _ = xfer.accept(); // SET_IDLE
        }
    }
}
