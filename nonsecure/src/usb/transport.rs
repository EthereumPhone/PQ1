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

impl Transport {
    pub fn new(hid: PqSignerHid<'static, UsbBusType>) -> Self {
        Self {
            hid,
            rx: HidFrameAssembler::new(),
            rx_buf: [0u8; MAX_APDU_RX],
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
    pub fn try_receive(&mut self) -> Option<&[u8]> {
        let mut report = [0u8; HID_REPORT_SIZE];
        let n = self.hid.read_report(&mut report)?;

        match self.rx.process_frame(&report, n, &mut self.rx_buf) {
            FrameOutcome::ApduComplete(len) => {
                self.channel_id = self.rx.channel_id();
                Some(&self.rx_buf[..len])
            }
            FrameOutcome::PingEcho => {
                self.hid.write_report(&report);
                None
            }
            FrameOutcome::NeedMore | FrameOutcome::Dropped => None,
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
