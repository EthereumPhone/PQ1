//! Pure-function APDU framing + HID frame reassembly.
//!
//! These parsers consume bytes that originated on the USB bus and never
//! touch any shared state, hardware, or NSC. They are the one layer
//! between "anything a malicious USB host can send" and the rest of the
//! firmware. Every code path here MUST terminate without panic for
//! arbitrary input — the property is enforced by the proptest harness
//! at the bottom of the file (`cargo test -p sphincs-tz-shared --tests`).
//!
//! Living in the `shared` crate buys two things:
//!
//!   * The non-secure side calls these from `usb::commands` and
//!     `usb::transport`, so the production wire-format parsing IS what
//!     gets fuzzed.
//!   * `shared` is `#![no_std]` with zero deps, so the proptest harness
//!     compiles + runs on host without dragging in a USB stack or any
//!     ARM crate.

use crate::{
    APDU_CLA_V2, HID_REPORT_SIZE, HID_TAG_APDU, HID_TAG_PING,
    INS_V2_GET_RESPONSE, SW_CLA_NOT_SUPPORTED, SW_CONDITIONS_NOT_SATISFIED,
    SW_WRONG_LENGTH,
};

// ---------------------------------------------------------------------------
// APDU header parser
// ---------------------------------------------------------------------------

/// Parsed ISO 7816-4 APDU header + a borrow into the data field.
#[derive(Debug)]
pub struct ApduHeader<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub lc: usize,
    pub data: &'a [u8],
}

/// Why an APDU was rejected before reaching the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// APDU is shorter than the 4-byte header.
    HeaderTooShort,
    /// `apdu.len() < 5 + lc` — the declared `Lc` claims more data than was sent.
    LcOverrun,
}

impl FramingError {
    /// Map back to the on-wire status word the dispatcher would emit.
    pub fn to_sw(self) -> u16 {
        match self {
            FramingError::HeaderTooShort | FramingError::LcOverrun => SW_WRONG_LENGTH,
        }
    }
}

/// Parse a v2 APDU header and validate `Lc`. Pure function, no statics.
///
/// The boundary semantics match `nonsecure::usb::commands::CommandRouter::dispatch`
/// byte-for-byte: a 4-byte APDU is treated as `Lc=0`, anything longer
/// requires the 5th byte to carry an `Lc` that fits in the remainder.
pub fn parse_apdu_header(apdu: &[u8]) -> Result<ApduHeader<'_>, FramingError> {
    if apdu.len() < 4 {
        return Err(FramingError::HeaderTooShort);
    }
    let cla = apdu[0];
    let ins = apdu[1];
    let p1 = apdu[2];
    let p2 = apdu[3];
    let (lc, data) = if apdu.len() > 4 {
        let lc = apdu[4] as usize;
        match 5usize.checked_add(lc) {
            Some(end) if end <= apdu.len() => (lc, &apdu[5..end]),
            _ => return Err(FramingError::LcOverrun),
        }
    } else {
        (0, &[] as &[u8])
    };
    Ok(ApduHeader { cla, ins, p1, p2, lc, data })
}

// ---------------------------------------------------------------------------
// CLA/INS routing
// ---------------------------------------------------------------------------

/// Why CLA/INS routing rejected this APDU before it could reach a handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingError {
    /// CLA != APDU_CLA_V2 (and INS != GET_RESPONSE, which is CLA-agnostic).
    ClassUnsupported,
}

impl RoutingError {
    pub fn to_sw(self) -> u16 {
        match self {
            RoutingError::ClassUnsupported => SW_CLA_NOT_SUPPORTED,
        }
    }
}

/// Decide whether the APDU should reach the v2 dispatcher.
/// `INS_V2_GET_RESPONSE` is treated as CLA-agnostic per ISO 7816-4 so the
/// companion can keep using it without tracking which chain owns the
/// pending bytes.
pub fn route_v2(header: &ApduHeader<'_>) -> Result<(), RoutingError> {
    if header.ins == INS_V2_GET_RESPONSE {
        return Ok(());
    }
    if header.cla != APDU_CLA_V2 {
        return Err(RoutingError::ClassUnsupported);
    }
    Ok(())
}

/// `true` if P1's chaining bit (bit 7) is set, i.e. more chunks follow.
pub const fn p1_more_follows(p1: u8) -> bool {
    (p1 & 0x80) != 0
}

// ---------------------------------------------------------------------------
// Chained-APDU state machine
// ---------------------------------------------------------------------------

/// Wire-format chain-state machine. Tracks the active INS and the
/// current write cursor without owning the buffer; the caller passes the
/// buffer capacity in on every call. Decoupling state from the buffer is
/// what lets the proptest harness exercise the machine over millions of
/// random INS / P1 / Lc sequences without needing 100 KiB of static
/// memory.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainState {
    /// Active chained INS, or `0` when no chain is in progress.
    ins: u8,
    /// Write cursor inside the caller-owned buffer.
    pos: usize,
}

impl ChainState {
    pub const fn new() -> Self {
        Self { ins: 0, pos: 0 }
    }

    pub const fn active_ins(&self) -> u8 {
        self.ins
    }
    pub const fn pos(&self) -> usize {
        self.pos
    }

    /// Reset to the empty state. Idempotent.
    pub fn reset(&mut self) {
        self.ins = 0;
        self.pos = 0;
    }

    /// Step the state machine for one chained APDU. The caller is
    /// responsible for actually copying `lc` bytes into
    /// `buf[outcome.write_at..outcome.write_at + lc]` after this call
    /// returns `Appended` or `Execute`.
    ///
    /// `buf_capacity` is the size of the caller's chain buffer. This
    /// helper performs the overflow-safe length check before mutating
    /// state, so a hostile APDU stream can never advance `pos` past
    /// `buf_capacity`.
    pub fn step(
        &mut self,
        ins: u8,
        p1: u8,
        lc: usize,
        buf_capacity: usize,
    ) -> ChainStepOutcome {
        if self.ins == 0 {
            self.ins = ins;
            self.pos = 0;
        } else if ins != self.ins {
            // Switching INS mid-chain is a protocol error.
            self.reset();
            return ChainStepOutcome::ProtocolError;
        }

        let new_pos = match self.pos.checked_add(lc) {
            Some(np) if np <= buf_capacity => np,
            _ => {
                self.reset();
                return ChainStepOutcome::WrongLength;
            }
        };
        let write_at = self.pos;
        self.pos = new_pos;

        if p1_more_follows(p1) {
            ChainStepOutcome::Appended { write_at, lc }
        } else {
            let final_len = self.pos;
            let active_ins = self.ins;
            self.reset();
            ChainStepOutcome::Execute { ins: active_ins, final_len, write_at, lc }
        }
    }
}

/// What the caller should do with the APDU it just stepped through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainStepOutcome {
    /// Append succeeded; emit `SW_OK` and wait for the next chunk.
    Appended { write_at: usize, lc: usize },
    /// All chunks accumulated; copy the final chunk and execute `ins` over
    /// `buf[..final_len]`.
    Execute {
        ins: u8,
        final_len: usize,
        write_at: usize,
        lc: usize,
    },
    /// Caller should emit `SW_CONDITIONS_NOT_SATISFIED`.
    ProtocolError,
    /// Caller should emit `SW_WRONG_LENGTH`.
    WrongLength,
}

impl ChainStepOutcome {
    pub const fn protocol_error_sw() -> u16 {
        SW_CONDITIONS_NOT_SATISFIED
    }
    pub const fn wrong_length_sw() -> u16 {
        SW_WRONG_LENGTH
    }
}

// ---------------------------------------------------------------------------
// HID frame reassembly
// ---------------------------------------------------------------------------

/// Maximum APDU we'll reassemble from HID frames. Mirrors
/// `nonsecure::usb::transport::MAX_APDU_RX`.
pub const MAX_APDU_RX: usize = 4096;

/// Data bytes in the first HID fragment (`64 - 7` header bytes).
pub const HID_FIRST_DATA: usize = HID_REPORT_SIZE - 7;
/// Data bytes in continuation fragments (`64 - 5` header bytes).
pub const HID_CONT_DATA: usize = HID_REPORT_SIZE - 5;

/// HID frame reassembly state. The actual buffer is owned by the caller
/// — the assembler tracks bookkeeping only. This separation lets us fuzz
/// the state machine without needing a USB stack.
#[derive(Debug, Clone, Copy)]
pub struct HidFrameAssembler {
    channel_id: u16,
    rx_expected: usize,
    rx_pos: usize,
    rx_seq: u16,
}

impl Default for HidFrameAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl HidFrameAssembler {
    pub const fn new() -> Self {
        Self {
            channel_id: 0,
            rx_expected: 0,
            rx_pos: 0,
            rx_seq: 0,
        }
    }

    pub const fn channel_id(&self) -> u16 {
        self.channel_id
    }
    pub const fn rx_expected(&self) -> usize {
        self.rx_expected
    }

    pub fn reset(&mut self) {
        self.rx_expected = 0;
        self.rx_pos = 0;
        self.rx_seq = 0;
    }

    /// Process one HID frame.
    ///
    /// `report` is the (up to 64-byte) raw frame; `n` is the number of
    /// valid bytes the USB stack actually delivered. `buf` is the
    /// caller's reassembly buffer (must be ≥ `MAX_APDU_RX` bytes).
    ///
    /// Returns:
    ///   * `ApduComplete(len)` — caller may read `&buf[..len]`.
    ///   * `NeedMore` — assembler absorbed the frame, waiting on more.
    ///   * `PingEcho` — caller must echo `report[..HID_REPORT_SIZE]`
    ///     back to the host.
    ///   * `Dropped` — frame was malformed, sequence/channel mismatched,
    ///     or out-of-bounds. State has been reset.
    pub fn process_frame(
        &mut self,
        report: &[u8],
        n: usize,
        buf: &mut [u8],
    ) -> FrameOutcome {
        // Two upfront sanity checks: we need at least the 3-byte
        // (channel, tag) prefix, and the caller's `n` must not claim
        // more bytes than actually fit in the report.
        if n < 3 || n > report.len() {
            return FrameOutcome::Dropped;
        }
        let channel = u16::from_be_bytes([report[0], report[1]]);
        let tag = report[2];

        if tag == HID_TAG_PING {
            return FrameOutcome::PingEcho;
        }
        if tag != HID_TAG_APDU {
            return FrameOutcome::Dropped;
        }
        if n < 5 {
            return FrameOutcome::Dropped;
        }
        let seq = u16::from_be_bytes([report[3], report[4]]);

        if seq == 0 {
            // First frame: pull expected length from bytes 5..7.
            if n < 7 {
                return FrameOutcome::Dropped;
            }
            self.channel_id = channel;
            self.rx_expected = u16::from_be_bytes([report[5], report[6]]) as usize;
            // Reject zero-length, oversize, and "won't fit in caller buf"
            // up front. The latter two are belt-and-braces — `MAX_APDU_RX`
            // already caps at 4096 — but a host with a buggy 65535-byte
            // claim must NOT corrupt memory.
            if self.rx_expected == 0
                || self.rx_expected > MAX_APDU_RX
                || self.rx_expected > buf.len()
            {
                self.reset();
                return FrameOutcome::Dropped;
            }
            self.rx_pos = 0;
            self.rx_seq = 1;

            let avail_in_frame = n - 7;
            let take = core::cmp::min(
                core::cmp::min(HID_FIRST_DATA, avail_in_frame),
                self.rx_expected,
            );
            buf[..take].copy_from_slice(&report[7..7 + take]);
            self.rx_pos = take;
        } else {
            if channel != self.channel_id || seq != self.rx_seq {
                self.reset();
                return FrameOutcome::Dropped;
            }
            self.rx_seq = self.rx_seq.saturating_add(1);

            let remaining = self.rx_expected.saturating_sub(self.rx_pos);
            let avail_in_frame = n.saturating_sub(5);
            let take = core::cmp::min(
                core::cmp::min(HID_CONT_DATA, avail_in_frame),
                remaining,
            );
            // Explicit bounds check — defends against `rx_pos + take`
            // exceeding `buf.len()` even if some earlier frame somehow
            // smuggled an out-of-range cursor.
            let end = match self.rx_pos.checked_add(take) {
                Some(e) if e <= buf.len() && e <= MAX_APDU_RX => e,
                _ => {
                    self.reset();
                    return FrameOutcome::Dropped;
                }
            };
            buf[self.rx_pos..end].copy_from_slice(&report[5..5 + take]);
            self.rx_pos = end;
        }

        if self.rx_pos >= self.rx_expected {
            let len = self.rx_expected;
            self.reset();
            FrameOutcome::ApduComplete(len)
        } else {
            FrameOutcome::NeedMore
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOutcome {
    /// An APDU has been reassembled; caller may read `&buf[..len]`.
    ApduComplete(usize),
    /// Frame absorbed; assembler awaits more frames.
    NeedMore,
    /// Frame was a PING — caller should echo the report back to the host.
    PingEcho,
    /// Frame was malformed, mid-chain mismatch, or out-of-bounds. Caller
    /// state has been reset; no copy was made past the buffer end.
    Dropped,
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod fuzz_props {
    //! Property-based fuzz harness for the parsers above.
    //!
    //! Every parser MUST terminate in bounded time without panicking,
    //! buffer-overrunning, or leaving its state machine in a corrupt
    //! shape, for any input bytes. These tests are how we prove that
    //! property holds for the layer between "anything a USB host can
    //! send" and the rest of the firmware. A failure here is a path
    //! from "anyone with a USB cable" to "compute in the secure
    //! world" — i.e., a critical bug.
    //!
    //! See the matching `secure/src/fuzz_props.rs` for sibling
    //! coverage of the secure-world parsers (RLP, EIP-1559,
    //! ERC-20 calldata, UserOp header, etc.).
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // ─────────────────────────────────────────────────────────────
        // APDU header parser. The first thing every USB byte sees;
        // if this panics, every higher layer panics with it.
        // ─────────────────────────────────────────────────────────────
        #[test]
        fn parse_apdu_header_never_panics(
            input in prop::collection::vec(any::<u8>(), 0..=8192)
        ) {
            let _ = parse_apdu_header(&input);
        }

        /// A successful parse must produce a `data` slice of exactly
        /// `lc` bytes that lives entirely inside the input — the
        /// invariant the chain-state machine relies on.
        #[test]
        fn parse_apdu_header_data_len_matches_lc(
            input in prop::collection::vec(any::<u8>(), 0..=8192)
        ) {
            if let Ok(h) = parse_apdu_header(&input) {
                prop_assert_eq!(h.data.len(), h.lc);
                prop_assert!(h.lc <= input.len());
            }
        }

        // ─────────────────────────────────────────────────────────────
        // CLA/INS routing.
        // ─────────────────────────────────────────────────────────────
        #[test]
        fn route_v2_never_panics(
            input in prop::collection::vec(any::<u8>(), 0..=512)
        ) {
            if let Ok(h) = parse_apdu_header(&input) {
                let _ = route_v2(&h);
            }
        }

        // ─────────────────────────────────────────────────────────────
        // Chain-state machine. A single random call.
        // ─────────────────────────────────────────────────────────────
        #[test]
        fn chain_step_terminates(
            ins in any::<u8>(),
            p1 in any::<u8>(),
            lc in 0usize..=512,
            cap in 0usize..=4096,
        ) {
            let mut state = ChainState::new();
            let _ = state.step(ins, p1, lc, cap);
            prop_assert!(state.pos() <= cap);
        }

        // ─────────────────────────────────────────────────────────────
        // Chain-state machine driven by a random APDU sequence.
        //
        // The crucial invariant: after any sequence of step() calls,
        // `pos` MUST stay within `cap`. A regression where `chain_pos`
        // could be advanced past `CHAIN_BUF_LEN` would let a malicious
        // host tee up an out-of-bounds copy in the caller's buffer.
        // ─────────────────────────────────────────────────────────────
        #[test]
        fn chain_step_sequence_pos_within_capacity(
            steps in prop::collection::vec(
                (any::<u8>(), any::<u8>(), 0usize..=300),
                0..=128,
            ),
            cap in 0usize..=2048,
        ) {
            let mut state = ChainState::new();
            for (ins, p1, lc) in steps {
                let _ = state.step(ins, p1, lc, cap);
                prop_assert!(state.pos() <= cap);
            }
        }

        // ─────────────────────────────────────────────────────────────
        // HID frame reassembly. Random bytes, random per-frame `n`.
        //
        // The property: no input sequence can make `process_frame` panic
        // or write past the caller's buffer end.
        // ─────────────────────────────────────────────────────────────
        #[test]
        fn hid_frame_random_input_never_panics(
            frames in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 0..=64),
                0..=64,
            ),
        ) {
            let mut buf = [0u8; MAX_APDU_RX];
            let mut asm = HidFrameAssembler::new();
            for frame in frames {
                let n = frame.len();
                let mut padded = [0u8; HID_REPORT_SIZE];
                let copy = core::cmp::min(n, HID_REPORT_SIZE);
                padded[..copy].copy_from_slice(&frame[..copy]);
                let _ = asm.process_frame(&padded, copy, &mut buf);
            }
        }

        /// Even a single frame with an obviously-bogus `n` (the USB
        /// stack claiming more bytes than actually fit) MUST be
        /// rejected without writing anything.
        #[test]
        fn hid_frame_oversize_n_dropped(
            seed in any::<[u8; 64]>(),
            n in 65usize..=512,
        ) {
            let mut buf = [0u8; MAX_APDU_RX];
            let mut asm = HidFrameAssembler::new();
            let outcome = asm.process_frame(&seed, n, &mut buf);
            prop_assert_eq!(outcome, FrameOutcome::Dropped);
        }

        /// A first-frame claim of zero or > MAX_APDU_RX expected bytes
        /// must drop without leaving stale state.
        #[test]
        fn hid_frame_bogus_expected_len_dropped(
            channel in any::<u16>(),
            expected in any::<u16>(),
            tail in any::<[u8; 57]>(),
        ) {
            let mut buf = [0u8; MAX_APDU_RX];
            let mut asm = HidFrameAssembler::new();
            let mut frame = [0u8; HID_REPORT_SIZE];
            frame[0..2].copy_from_slice(&channel.to_be_bytes());
            frame[2] = HID_TAG_APDU;
            // seq = 0
            frame[3] = 0;
            frame[4] = 0;
            frame[5..7].copy_from_slice(&expected.to_be_bytes());
            frame[7..].copy_from_slice(&tail);
            let _ = asm.process_frame(&frame, HID_REPORT_SIZE, &mut buf);
            // Whatever happened, the assembler's invariant must hold.
            prop_assert!(asm.rx_expected() <= MAX_APDU_RX);
        }
    }

    // ---------------------------------------------------------------
    // Hand-written regression tests — guarded specific edge cases
    // ---------------------------------------------------------------

    #[test]
    fn parse_apdu_header_minimum_4_bytes() {
        let h = parse_apdu_header(&[0xF0, 0x01, 0x02, 0x03]).unwrap();
        assert_eq!(h.cla, 0xF0);
        assert_eq!(h.ins, 0x01);
        assert_eq!(h.p1, 0x02);
        assert_eq!(h.p2, 0x03);
        assert_eq!(h.lc, 0);
        assert!(h.data.is_empty());
    }

    #[test]
    fn parse_apdu_header_3_bytes_fails() {
        assert_eq!(
            parse_apdu_header(&[0xF0, 0x01, 0x02]).unwrap_err(),
            FramingError::HeaderTooShort
        );
    }

    #[test]
    fn parse_apdu_header_lc_overrun() {
        // Lc=10 but only 4 data bytes follow.
        let buf = [0xF0, 0x01, 0x02, 0x03, 10, 1, 2, 3, 4];
        assert_eq!(
            parse_apdu_header(&buf).unwrap_err(),
            FramingError::LcOverrun
        );
    }

    #[test]
    fn parse_apdu_header_lc_zero_no_data() {
        // 5-byte APDU with Lc=0, which is the case-2 (no-data) form.
        let h = parse_apdu_header(&[0xF0, 0x01, 0x02, 0x03, 0]).unwrap();
        assert_eq!(h.lc, 0);
        assert!(h.data.is_empty());
    }

    #[test]
    fn parse_apdu_header_lc_max_short() {
        let mut buf = [0u8; 5 + 255];
        buf[0] = 0xF0;
        buf[4] = 0xFF;
        let h = parse_apdu_header(&buf).unwrap();
        assert_eq!(h.lc, 255);
        assert_eq!(h.data.len(), 255);
    }

    #[test]
    fn route_v2_get_response_is_cla_agnostic() {
        let h = ApduHeader {
            cla: 0x00, // wrong CLA
            ins: INS_V2_GET_RESPONSE,
            p1: 0,
            p2: 0,
            lc: 0,
            data: &[],
        };
        assert!(route_v2(&h).is_ok());
    }

    #[test]
    fn route_v2_rejects_wrong_cla() {
        let h = ApduHeader {
            cla: 0x00,
            ins: 0x42,
            p1: 0,
            p2: 0,
            lc: 0,
            data: &[],
        };
        assert_eq!(
            route_v2(&h).unwrap_err(),
            RoutingError::ClassUnsupported,
        );
    }

    #[test]
    fn chain_state_two_chunk_sequence() {
        let mut s = ChainState::new();
        // First chunk: more follows.
        let outcome = s.step(0x30, 0x80, 100, 4096);
        assert!(matches!(outcome, ChainStepOutcome::Appended { write_at: 0, lc: 100 }));
        assert_eq!(s.pos(), 100);
        // Second chunk: final.
        let outcome = s.step(0x30, 0x00, 50, 4096);
        match outcome {
            ChainStepOutcome::Execute { ins, final_len, write_at, lc } => {
                assert_eq!(ins, 0x30);
                assert_eq!(final_len, 150);
                assert_eq!(write_at, 100);
                assert_eq!(lc, 50);
            }
            _ => panic!("expected Execute"),
        }
        // After Execute, state must be reset.
        assert_eq!(s.active_ins(), 0);
        assert_eq!(s.pos(), 0);
    }

    #[test]
    fn chain_state_ins_swap_resets() {
        let mut s = ChainState::new();
        let _ = s.step(0x30, 0x80, 10, 4096);
        let outcome = s.step(0x40, 0x80, 10, 4096);
        assert_eq!(outcome, ChainStepOutcome::ProtocolError);
        assert_eq!(s.active_ins(), 0);
        assert_eq!(s.pos(), 0);
    }

    #[test]
    fn chain_state_overflow_rejected() {
        let mut s = ChainState::new();
        let outcome = s.step(0x30, 0x80, usize::MAX - 4, 1024);
        assert_eq!(outcome, ChainStepOutcome::WrongLength);
        assert_eq!(s.pos(), 0);
    }
}
