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
