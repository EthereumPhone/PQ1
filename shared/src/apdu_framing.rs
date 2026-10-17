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
    #[must_use]
    pub const fn to_sw(self) -> u16 {
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
    #[must_use]
    pub const fn to_sw(self) -> u16 {
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
    /// USB SOF frames accumulated since this chain opened. Drives the
    /// X17-UC1 total-chain-lifetime timeout — see [`Self::tick_timeout`].
    elapsed_frames: u32,
}

/// Mask of a USB full-speed frame number. A full-speed SOF carries an 11-bit
/// frame number (USB 2.0 §8.4.3), so on the U585's full-speed-only OTG core
/// `OTG_DSTS.FNSOF` counts 0..=2047 and wraps every 2.048 s. The 14-bit field
/// width is the high-speed microframe layout.
///
/// Until 2026-10-15 every timeout here used `& 0x3FFF`. At each wrap a
/// 0x7FF→0 step then read as 14,337 elapsed frames: an APDU whose HID frames
/// straddled a wrap was scrubbed as "timed out" and silently dropped
/// (DVT1 checklist 11.2: 29 lost replies in 300 FW_BEGIN chains, every one
/// with `USB_DIAG_RX_TIMEOUTS` +1 and capture `start=0x7FE now=0x000`), and
/// the 30 s / 120 s lease timers expired after about two wraps.
pub const USB_FS_FRAME_MASK: u16 = 0x7FF;

/// Frames elapsed from `last` to `now` on the 11-bit full-speed frame clock.
///
/// Correct across one wrap. A gap longer than 2.048 s between two samples
/// (the NS loop blocked in a long secure call) loses whole wraps, so callers
/// that accumulate these deltas measure LONGER deadlines than nominal, never
/// shorter: a timeout can fire late but never early.
///
/// A step in the upper half of the ring (`>= 1024`) reads as a backward step
/// and counts as 0. The EVT-3D21 trace (2026-10-17, `nonsecure/src/fnsof_trace.rs`)
/// saw `FNSOF` step back by exactly one frame about once every 4 s, as
/// `DSTS.DEVLNSTS` toggled (e.g. 17 → 16), plus a few torn reads
/// (0x7BF → 0x780). Masked, each read as +2,047 or so: about 2 s gained per
/// event, roughly 1,490 accumulated frames per real second, so the 30 s and
/// 120 s bounds expired after about 20 s and 80 s. Counting the half-ring as
/// backward keeps "late, never early": the NS loop samples at hundreds of
/// kHz, so a real forward gap of >= 1,024 frames only happens inside a long
/// secure call, and dropping it lengthens the deadline.
#[must_use]
pub const fn frame_delta(now: u16, last: u16) -> u32 {
    let d = now.wrapping_sub(last) & USB_FS_FRAME_MASK;
    if d > USB_FS_FRAME_MASK / 2 {
        0
    } else {
        d as u32
    }
}

/// Advance an accumulating frame clock: return [`frame_delta`] from `*last`
/// to `now`, and move `*last` to `now` only when the clock went forward.
///
/// After a backward step `*last` keeps the newest frame already counted, so
/// the frames between the backward reading and that point are not counted a
/// second time when the clock moves on. Callers that accumulate deadlines use
/// this, not `frame_delta` plus `last = now`, which would gain one frame per
/// backward step.
#[must_use]
pub fn frame_step(now: u16, last: &mut u16) -> u32 {
    let d = frame_delta(now, *last);
    if d != 0 {
        *last = now;
    }
    d
}

impl ChainState {
    /// Total lifetime bound for one chained exchange, in USB SOF frames
    /// (nominal 1 ms cadence): 30 s, mirroring the GET_RESPONSE
    /// inter-chunk drain timeout on the nonsecure side.
    pub const CHAIN_TIMEOUT_FRAMES: u32 = 30_000;

    #[must_use]
    pub const fn new() -> Self {
        Self {
            ins: 0,
            pos: 0,
            elapsed_frames: 0,
        }
    }

    #[must_use]
    pub const fn active_ins(&self) -> u8 {
        self.ins
    }

    #[must_use]
    pub const fn pos(&self) -> usize {
        self.pos
    }

    /// Reset to the empty state. Idempotent.
    pub fn reset(&mut self) {
        self.ins = 0;
        self.pos = 0;
        self.elapsed_frames = 0;
    }

    /// Accumulate `delta` elapsed USB SOF frames against the live
    /// chain's lifetime budget (work-todo X17-UC1 / sweep finding F2).
    /// The clock is NOT reset by chain activity — it is a
    /// total-exchange deadline, not an idle timeout — so a host
    /// keepalive-dripping chained APDUs cannot pin the F11
    /// single-session router lease indefinitely, and a crashed client
    /// that simply goes silent trips the same bound. When the budget
    /// is exceeded with a chain live, the chain is reset and `true` is
    /// returned so the caller can release the router lease. No-op when
    /// no chain is in progress (the clock stays zeroed, so the next
    /// chain always starts with a fresh budget).
    pub fn tick_timeout(&mut self, delta: u32) -> bool {
        if self.ins == 0 {
            self.elapsed_frames = 0;
            return false;
        }
        self.elapsed_frames = self.elapsed_frames.saturating_add(delta);
        if self.elapsed_frames >= Self::CHAIN_TIMEOUT_FRAMES {
            self.reset();
            return true;
        }
        false
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
    #[must_use]
    pub const fn protocol_error_sw() -> u16 {
        SW_CONDITIONS_NOT_SATISFIED
    }

    #[must_use]
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
    #[must_use]
    pub const fn new() -> Self {
        Self {
            channel_id: 0,
            rx_expected: 0,
            rx_pos: 0,
            rx_seq: 0,
        }
    }

    #[must_use]
    pub const fn channel_id(&self) -> u16 {
        self.channel_id
    }

    #[must_use]
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
    ///     or out-of-bounds. State has been reset — unless the frame was
    ///     a foreign-channel seq=0, which is dropped with the owner's
    ///     in-progress stream left intact.
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
            if self.rx_expected != 0 {
                // A seq=0 from a DIFFERENT channel mid-stream must NOT
                // scrub the owner's partially reassembled APDU — that
                // is a one-frame cross-channel starvation primitive
                // (finding F1; §31a channel isolation — the continuation
                // path below drops foreign-channel frames the same way).
                // Liveness is `rx_expected` (set when the first frame is
                // accepted), NOT `rx_pos`: a legal 7-byte first frame
                // carries zero payload and must still count as an
                // active stream.
                // Drop the foreign frame, keep the owner's stream; the
                // foreign host retries once the owner finishes.
                if channel != self.channel_id {
                    return FrameOutcome::Dropped;
                }
                // Same channel: abort + scrub when a fresh first-frame
                // interrupts its own in-progress reassembly. A host
                // whose framing state has gone out of sync must restart
                // from a clean slate; we do NOT silently let the new
                // seq=0 reuse the buffer while old partial bytes linger
                // past the new `rx_expected`. `Dropped` produces no
                // response at the transport layer, so the host recovers
                // by retrying its seq=0 after its own timeout.
                // Tracks §19 P0 "Bounded APDU reassembly" in
                // `docs/security/production-security.md` §2.4.
                let stale = core::cmp::min(self.rx_pos, buf.len());
                for b in &mut buf[..stale] {
                    *b = 0;
                }
                self.reset();
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
            self.rx_seq = 1;

            let avail_in_frame = n - 7;
            // FI-hardened length clamp — defeats Colin O'Flynn USENIX
            // WOOT 2019 EMFI-on-min: if the result `take` doesn't
            // satisfy `take ≤ each input`, recompute via the opposite
            // branch direction. See `pqsigner-fi::fi_min` + finding in
            // `docs/security/production-security.md` §2.4.
            let take = pqsigner_fi::fi_min(
                pqsigner_fi::fi_min(HID_FIRST_DATA, avail_in_frame),
                self.rx_expected,
            );
            buf[..take].copy_from_slice(&report[7..7 + take]);
            self.rx_pos = take;
        } else {
            // A continuation frame from a DIFFERENT channel mid-stream
            // must NOT abort the owner's reassembly — that is the same
            // one-frame cross-channel starvation primitive as a foreign
            // seq=0 (finding F1, second half flagged by the 2026-07-19
            // three-reviewer wave). Drop the foreign frame, keep the
            // owner's stream; the foreign host retries once the owner
            // finishes.
            if channel != self.channel_id {
                return FrameOutcome::Dropped;
            }
            // Same channel, wrong sequence: genuine desync — abort the
            // stream so the host restarts from a clean slate. Scrub the
            // partial bytes first, same as the seq=0 abort: the buffer
            // is treated as potentially secret-bearing and the desync
            // reset must not leave a stale fragment behind.
            if seq != self.rx_seq {
                let stale = core::cmp::min(self.rx_pos, buf.len());
                for b in &mut buf[..stale] {
                    *b = 0;
                }
                self.reset();
                return FrameOutcome::Dropped;
            }
            self.rx_seq = self.rx_seq.saturating_add(1);

            let remaining = self.rx_expected.saturating_sub(self.rx_pos);
            let avail_in_frame = n.saturating_sub(5);
            // FI-hardened length clamp (see comment on the first-frame
            // path above).
            let take = pqsigner_fi::fi_min(
                pqsigner_fi::fi_min(HID_CONT_DATA, avail_in_frame),
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

/// Router single-session lease decision (finding F11).
///
/// The device is single-session — one unlock, one signing window — so at most
/// one HID channel may hold a live multi-APDU exchange (a chained command in
/// progress, or a pending chunked `GET_RESPONSE` drain) at any moment. The
/// non-secure router records the owning channel while an exchange is live and
/// consults this predicate on every incoming APDU:
///
/// * `owner == None` — no exchange in progress, so any channel may start one.
/// * `owner == Some(o)` — `o` holds the lease; only `o` may continue or drain
///   it. A foreign channel is rejected *without* touching the owner's state, so
///   it can neither siphon the owner's queued response (the chunked-signature
///   bytes) nor DoS the owner by scrubbing its pending cursor / chain buffer.
///
/// The `channel_id` this operates on is the 2-byte field already present in
/// every HID frame; F11 only adds enforcement, no new wire bytes.
#[must_use]
pub fn router_lease_allows(owner: Option<u16>, caller: u16) -> bool {
    match owner {
        None => true,
        Some(o) => o == caller,
    }
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod router_lease_tests {
    use super::router_lease_allows;

    #[test]
    fn unleased_router_admits_any_channel() {
        assert!(router_lease_allows(None, 0));
        assert!(router_lease_allows(None, 0xABCD));
    }

    #[test]
    fn leased_router_admits_only_the_owner() {
        assert!(router_lease_allows(Some(0x1111), 0x1111));
        // A different channel is refused while the owner holds the lease.
        assert!(!router_lease_allows(Some(0x1111), 0x2222));
        assert!(!router_lease_allows(Some(0x0000), 0x0001));
    }

    #[test]
    fn channel_zero_owner_is_still_enforced() {
        // 0x0000 is a valid channel id; a Some(0) lease must still exclude others.
        assert!(router_lease_allows(Some(0), 0));
        assert!(!router_lease_allows(Some(0), 1));
    }
}

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

    #[test]
    fn chain_tick_timeout_bounds_total_chain_lifetime() {
        // X17-UC1 / F2: a chain that never completes must not pin the
        // router lease forever, whether the host crashed (silence) or
        // keepalive-drips chunks (activity must NOT reset the clock).
        let mut s = ChainState::new();
        // No chain live: ticking is a no-op and never reports.
        assert!(!s.tick_timeout(ChainState::CHAIN_TIMEOUT_FRAMES + 1));
        assert_eq!(s.active_ins(), 0);

        // Open a chain, then keep it busy: steps do not extend the
        // lifetime budget (total-exchange deadline, not idle timeout).
        let _ = s.step(0x30, 0x80, 10, 4096);
        assert_eq!(s.active_ins(), 0x30);
        assert!(!s.tick_timeout(ChainState::CHAIN_TIMEOUT_FRAMES - 1));
        let _ = s.step(0x30, 0x80, 10, 4096); // mid-window activity
        assert!(s.tick_timeout(1));
        // Chain was reset; the caller releases the router lease.
        assert_eq!(s.active_ins(), 0);
        assert_eq!(s.pos(), 0);
        // Edge-triggered: an immediate re-tick does not report again.
        assert!(!s.tick_timeout(ChainState::CHAIN_TIMEOUT_FRAMES + 1));

        // A fresh chain after a timeout starts with a fresh budget.
        let _ = s.step(0x30, 0x80, 10, 4096);
        assert!(!s.tick_timeout(ChainState::CHAIN_TIMEOUT_FRAMES - 1));
        assert_eq!(s.active_ins(), 0x30);
    }

    // ---------------------------------------------------------------
    // HID channel-ID isolation regression test (work-todo §31a)
    // ---------------------------------------------------------------
    //
    // Pins the assembler's mid-stream channel-ID enforcement so a
    // future refactor can't silently weaken it. Trezor's codec_v1
    // and ours both require continuation frames to carry the same
    // channel_id the host claimed in frame 0; mismatch = host
    // confused-deputy / cross-tab race and MUST drop.
    //
    // The proptest harness above exercises `process_frame` against
    // millions of random byte sequences but doesn't construct THIS
    // specific positive/negative pair, so a fix-then-regress on
    // line 364 would slip past CI without a hand-written test.

    fn hid_first_frame(chan: u16, expected: u16, payload: &[u8]) -> [u8; HID_REPORT_SIZE] {
        let mut f = [0u8; HID_REPORT_SIZE];
        f[0..2].copy_from_slice(&chan.to_be_bytes());
        f[2] = HID_TAG_APDU;
        f[3] = 0; // seq = 0
        f[4] = 0;
        f[5..7].copy_from_slice(&expected.to_be_bytes());
        let take = core::cmp::min(payload.len(), HID_FIRST_DATA);
        f[7..7 + take].copy_from_slice(&payload[..take]);
        f
    }

    fn hid_cont_frame(chan: u16, seq: u16, payload: &[u8]) -> [u8; HID_REPORT_SIZE] {
        let mut f = [0u8; HID_REPORT_SIZE];
        f[0..2].copy_from_slice(&chan.to_be_bytes());
        f[2] = HID_TAG_APDU;
        f[3..5].copy_from_slice(&seq.to_be_bytes());
        let take = core::cmp::min(payload.len(), HID_CONT_DATA);
        f[5..5 + take].copy_from_slice(&payload[..take]);
        f
    }

    #[test]
    fn hid_channel_id_mismatch_on_continuation_drops_without_reset() {
        let mut buf = [0u8; MAX_APDU_RX];
        let mut asm = HidFrameAssembler::new();

        // Frame 0: channel 0xAAAA, expected 120 bytes (needs ≥1 cont).
        let f0 = hid_first_frame(0xAAAA, 120, &[0x11; HID_FIRST_DATA]);
        let outcome0 = asm.process_frame(&f0, HID_REPORT_SIZE, &mut buf);
        assert_eq!(outcome0, FrameOutcome::NeedMore);
        assert_eq!(asm.channel_id(), 0xAAAA);
        assert_eq!(asm.rx_expected(), 120);

        // Frame 1 arrives on a DIFFERENT channel (0xBBBB). Host
        // confused-deputy / cross-tab race. Must drop WITHOUT touching
        // the owner's stream — resetting here is the one-frame
        // cross-channel starvation primitive (finding F1, second half).
        // A genuinely stalled owner self-clears via the transport-layer
        // reassembly timeout instead.
        let f1_wrong = hid_cont_frame(0xBBBB, 1, &[0x22; HID_CONT_DATA]);
        let outcome1 = asm.process_frame(&f1_wrong, HID_REPORT_SIZE, &mut buf);
        assert_eq!(outcome1, FrameOutcome::Dropped);
        assert_eq!(asm.channel_id(), 0xAAAA);
        assert_eq!(asm.rx_expected(), 120);
        assert_eq!(&buf[..HID_FIRST_DATA], &[0x11; HID_FIRST_DATA]);
    }

    #[test]
    fn hid_channel_id_match_on_continuation_succeeds() {
        // Sibling positive case so the regression test pair pins
        // BOTH the accept-on-match and reject-on-mismatch paths.
        let mut buf = [0u8; MAX_APDU_RX];
        let mut asm = HidFrameAssembler::new();

        let f0 = hid_first_frame(0xAAAA, 120, &[0x11; HID_FIRST_DATA]);
        assert_eq!(
            asm.process_frame(&f0, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::NeedMore
        );

        let f1 = hid_cont_frame(0xAAAA, 1, &[0x22; HID_CONT_DATA]);
        let outcome1 = asm.process_frame(&f1, HID_REPORT_SIZE, &mut buf);
        // 120 expected = 57 first + 59 cont + extra in a 3rd frame.
        // Two cont frames carry 59 each = 118; with the first 57 we
        // overshoot at 116 + extra. Actually: 57 first + 59 cont = 116;
        // we still need 4 more so this should be NeedMore.
        assert_eq!(outcome1, FrameOutcome::NeedMore);
        assert_eq!(asm.channel_id(), 0xAAAA);
    }

    #[test]
    fn hid_new_channel_can_start_after_owner_completes() {
        // After the owner's stream COMPLETES, a brand-new first-frame
        // from another channel must be accepted (only the in-flight
        // stream is owned — channels are not locked out forever).
        let mut buf = [0u8; MAX_APDU_RX];
        let mut asm = HidFrameAssembler::new();

        // A opens and completes a single-frame stream.
        let small_a = 50u16;
        let f0_a = hid_first_frame(0xAAAA, small_a, &[0x11; HID_FIRST_DATA]);
        assert_eq!(
            asm.process_frame(&f0_a, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::ApduComplete(small_a as usize)
        );

        // B starts fresh immediately.
        let small_b = 42u16;
        let f0_b = hid_first_frame(0xCCCC, small_b, &[0x33; HID_FIRST_DATA]);
        let outcome = asm.process_frame(&f0_b, HID_REPORT_SIZE, &mut buf);
        assert_eq!(outcome, FrameOutcome::ApduComplete(small_b as usize));
        // After completion `channel_id` retains the most recently
        // captured value but `rx_*` are reset.
        assert_eq!(asm.channel_id(), 0xCCCC);
        assert_eq!(asm.rx_expected(), 0);
    }

    #[test]
    fn hid_cross_channel_first_frame_does_not_abort_in_progress_stream() {
        // §31a / finding F1: while channel A's reassembly is in
        // progress, a seq=0 frame from a FOREIGN channel B must be
        // dropped WITHOUT scrubbing/resetting A's stream — otherwise B
        // starves A at a cost of one frame vs A's whole transfer.
        let mut buf = [0u8; MAX_APDU_RX];
        let mut asm = HidFrameAssembler::new();

        // Frame 0: channel 0xAAAA, expected 120 bytes (needs ≥1 cont).
        let f0 = hid_first_frame(0xAAAA, 120, &[0x11; HID_FIRST_DATA]);
        assert_eq!(
            asm.process_frame(&f0, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::NeedMore
        );
        assert_eq!(asm.channel_id(), 0xAAAA);
        assert_eq!(asm.rx_expected(), 120);

        // Channel 0xBBBB injects its own first-frame mid-stream.
        let foreign = hid_first_frame(0xBBBB, 300, &[0xEE; HID_FIRST_DATA]);
        assert_eq!(
            asm.process_frame(&foreign, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::Dropped
        );
        // A's stream is untouched: bookkeeping survives and the
        // reassembly buffer was NOT scrubbed.
        assert_eq!(asm.channel_id(), 0xAAAA);
        assert_eq!(asm.rx_expected(), 120);
        assert_eq!(&buf[..HID_FIRST_DATA], &[0x11; HID_FIRST_DATA]);

        // A's continuation still assembles to completion.
        let f1 = hid_cont_frame(0xAAAA, 1, &[0x22; HID_CONT_DATA]);
        assert_eq!(
            asm.process_frame(&f1, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::NeedMore
        );
        let f2 = hid_cont_frame(0xAAAA, 2, &[0x33; HID_CONT_DATA]);
        assert_eq!(
            asm.process_frame(&f2, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::ApduComplete(120)
        );

        // The same-channel desync-abort is preserved: A restarts with
        // seq=0 mid-stream → scrub + reset + Dropped.
        let f0_a = hid_first_frame(0xAAAA, 120, &[0x44; HID_FIRST_DATA]);
        assert_eq!(
            asm.process_frame(&f0_a, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::NeedMore
        );
        let desync = hid_first_frame(0xAAAA, 300, &[0x55; HID_FIRST_DATA]);
        assert_eq!(
            asm.process_frame(&desync, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::Dropped
        );
        assert_eq!(asm.rx_expected(), 0);
        assert_eq!(&buf[..HID_FIRST_DATA], &[0u8; HID_FIRST_DATA]);
    }

    #[test]
    fn hid_cross_channel_continuation_does_not_abort_in_progress_stream() {
        // §31a / finding F1 second half (three-reviewer wave 2026-07-19):
        // a CONTINUATION-shaped frame from a foreign channel must also be
        // dropped without resetting the owner's in-progress stream —
        // before the fix, `channel != self.channel_id` in the seq!=0
        // branch aborted the owner's reassembly exactly like a foreign
        // seq=0 used to.
        let mut buf = [0u8; MAX_APDU_RX];
        let mut asm = HidFrameAssembler::new();

        // Channel A opens a 120-byte reassembly.
        let f0 = hid_first_frame(0xAAAA, 120, &[0x11; HID_FIRST_DATA]);
        assert_eq!(
            asm.process_frame(&f0, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::NeedMore
        );
        assert_eq!(asm.rx_expected(), 120);

        // Channel B injects a continuation-shaped frame (seq=1).
        let foreign_cont = hid_cont_frame(0xBBBB, 1, &[0xEE; HID_CONT_DATA]);
        assert_eq!(
            asm.process_frame(&foreign_cont, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::Dropped
        );
        // A's stream survives untouched.
        assert_eq!(asm.channel_id(), 0xAAAA);
        assert_eq!(asm.rx_expected(), 120);
        assert_eq!(&buf[..HID_FIRST_DATA], &[0x11; HID_FIRST_DATA]);

        // A still assembles to completion.
        let f1 = hid_cont_frame(0xAAAA, 1, &[0x22; HID_CONT_DATA]);
        assert_eq!(
            asm.process_frame(&f1, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::NeedMore
        );
        let f2 = hid_cont_frame(0xAAAA, 2, &[0x33; HID_CONT_DATA]);
        assert_eq!(
            asm.process_frame(&f2, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::ApduComplete(120)
        );

        // Same-channel desync protection is preserved: an out-of-sequence
        // continuation from the OWNER still aborts the stream.
        let g0 = hid_first_frame(0xAAAA, 120, &[0x44; HID_FIRST_DATA]);
        assert_eq!(
            asm.process_frame(&g0, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::NeedMore
        );
        let wrong_seq = hid_cont_frame(0xAAAA, 7, &[0x55; HID_CONT_DATA]);
        assert_eq!(
            asm.process_frame(&wrong_seq, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::Dropped
        );
        assert_eq!(asm.rx_expected(), 0);
        // The desync abort also scrubs the partial bytes (same rule as
        // the seq=0 abort — no stale fragment left behind).
        assert_eq!(&buf[..HID_FIRST_DATA], &[0u8; HID_FIRST_DATA]);
    }

    #[test]
    fn hid_zero_payload_first_frame_still_counts_as_active_stream() {
        // GPT-5.6 wave finding: stream liveness keys on `rx_expected`,
        // NOT `rx_pos` — a legal 7-byte first frame carries zero payload
        // bytes but opens an active stream that foreign frames must not
        // hijack.
        let mut buf = [0u8; MAX_APDU_RX];
        let mut asm = HidFrameAssembler::new();

        // 7-byte first frame: channel 0xAAAA, seq=0, expected=120, no payload.
        let mut f0 = [0u8; HID_REPORT_SIZE];
        f0[0..2].copy_from_slice(&0xAAAAu16.to_be_bytes());
        f0[2] = HID_TAG_APDU;
        f0[3..5].copy_from_slice(&0u16.to_be_bytes());
        f0[5..7].copy_from_slice(&120u16.to_be_bytes());
        assert_eq!(
            asm.process_frame(&f0, 7, &mut buf),
            FrameOutcome::NeedMore
        );
        assert_eq!(asm.rx_expected(), 120);

        // A foreign first-frame must be dropped, owner's stream intact.
        let foreign = hid_first_frame(0xBBBB, 300, &[0xEE; HID_FIRST_DATA]);
        assert_eq!(
            asm.process_frame(&foreign, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::Dropped
        );
        assert_eq!(asm.channel_id(), 0xAAAA);
        assert_eq!(asm.rx_expected(), 120);

        // The owner's continuations still assemble normally (the first
        // frame carried no payload, so completion needs one more frame
        // than the payload-bearing cases).
        let f1 = hid_cont_frame(0xAAAA, 1, &[0x22; HID_CONT_DATA]);
        assert_eq!(
            asm.process_frame(&f1, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::NeedMore
        );
        let f2 = hid_cont_frame(0xAAAA, 2, &[0x33; HID_CONT_DATA]);
        assert_eq!(
            asm.process_frame(&f2, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::NeedMore
        );
        let f3 = hid_cont_frame(0xAAAA, 3, &[0x44; HID_CONT_DATA]);
        assert_eq!(
            asm.process_frame(&f3, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::ApduComplete(120)
        );
    }
}

// ---------------------------------------------------------------------------
// Kani harnesses — EXHAUSTIVE (∀) panic / out-of-bounds-write freedom for the
// attacker-facing USB reassembly + framing.
//
// The `fuzz_props` proptest harness above SAMPLES random inputs; these PROVE
// the property for ALL inputs. They close the `S-USB-OVERFLOW` row of
// `contracts/verification/docs/THREAT_CLAIM_MAP.md` ("Buffer overflow in APDU
// reassembly", UNCLAIMED → PARTIAL): the reassembly + framing + chain-cursor
// are the one layer between "anything a malicious USB host can send" and the
// rest of the firmware. (The per-command dispatch in
// `nonsecure::usb::commands` stays host-uncompilable — the other half of the
// §35 P7 USB-decoder item — so this is PARTIAL, not COVERED.)
//
// In Rust an out-of-bounds slice write PANICS (`copy_from_slice` length
// mismatch / index OOB), so Kani's built-in bounds/overflow/panic checks ARE
// the no-OOB-write proof; the explicit asserts add the semantic bounds the
// callers rely on. Host 64-bit `usize`; every length here is ≤ MAX_APDU_RX
// (4096) ≪ 2³², so there is no 32-bit-`usize` divergence on the thumbv8m
// target (same faithfulness note as the multiSend host-width caveat, §35 3b-3).
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod kani_harnesses {
    use super::*;

    // `HidFrameAssembler::process_frame` writes host-controlled bytes into the
    // caller's reassembly buffer at `buf[..take]` / `buf[rx_pos..end]`. An
    // out-of-bounds write there IS `S-USB-OVERFLOW`. Both harnesses below run
    // over a **fully arbitrary** assembler state (all four private fields
    // `kani::any()`) and an arbitrary 64-byte frame + arbitrary claimed length
    // `n`. Arbitrary-state (rather than an assumed inductive invariant) is SOUND
    // and strictly stronger because every write is guarded independent of prior
    // state, so even an unreachable state simply drops — no state assumption to
    // be made vacuous (kills the V1 risk). `buf` is sized exactly `MAX_APDU_RX`
    // so BOTH live guards `e <= buf.len()` and `e <= MAX_APDU_RX` are exercised.
    // The two paths are split ONLY to keep CBMC tractable (the seq-0-interrupt
    // scrub is an up-to-`MAX_APDU_RX` loop); together they cover every branch.

    /// Continuation path (seq != 0) — the **overflow-critical** write
    /// `buf[rx_pos..end]` from an ARBITRARY `rx_pos` (incl. at/over the
    /// `MAX_APDU_RX` boundary). Proves the `end = rx_pos.checked_add(take)` with
    /// `e <= buf.len() && e <= MAX_APDU_RX` gate keeps it in-bounds for all
    /// inputs. No scrub on this path (the scrub is seq == 0 only) → small unwind.
    #[kani::proof]
    #[kani::unwind(64)]
    fn process_frame_continuation_no_oob() {
        let mut buf = [0u8; MAX_APDU_RX];
        let mut asm = HidFrameAssembler {
            channel_id: kani::any(),
            rx_expected: kani::any(),
            rx_pos: kani::any(),
            rx_seq: kani::any(),
        };
        let mut report: [u8; HID_REPORT_SIZE] = kani::any();
        // Force a continuation frame. The append path is reachable (non-vacuous)
        // when the arbitrary `channel`/`rx_seq` match the frame's; otherwise it
        // drops — both explored.
        let seq: u16 = kani::any();
        kani::assume(seq != 0);
        report[3..5].copy_from_slice(&seq.to_be_bytes());
        let n: usize = kani::any();
        let outcome = asm.process_frame(&report, n, &mut buf);
        if let FrameOutcome::ApduComplete(len) = outcome {
            assert!(len <= MAX_APDU_RX);
        }
        // NOTE: `asm.rx_pos <= MAX_APDU_RX` is a *reachable-state* invariant, not
        // an all-state one — an early-drop (`n<5` / wrong tag / PingEcho) returns
        // without resetting, so from an arbitrary (unreachable) `rx_pos` it can
        // stay huge. That is harmless (no write occurs on those paths — Kani's
        // built-in bounds checks prove it), so we do NOT assert it here; the
        // no-out-of-bounds-write property is what closes S-USB-OVERFLOW.
    }

    /// First-frame + seq-0-interrupt scrub path (seq == 0). Covers the
    /// first-frame length parse / clamp / copy (`rx_pos == 0`, no scrub) and the
    /// abort-scrub `buf[..min(rx_pos, buf.len())]` + reset (`rx_pos > 0`).
    /// `rx_pos` is bounded so the min-clamped scrub memset stays within a
    /// tractable unwind; the scrub is in-bounds by construction for ANY
    /// `rx_pos` (the `min(_, buf.len())` clamp), and the full range up to
    /// `MAX_APDU_RX` is exercised by the `hid_frame_*` proptest harnesses above.
    #[kani::proof]
    #[kani::unwind(131)]
    fn process_frame_first_and_scrub_no_oob() {
        let mut buf = [0u8; MAX_APDU_RX];
        let mut asm = HidFrameAssembler {
            channel_id: kani::any(),
            rx_expected: kani::any(),
            rx_pos: kani::any(),
            rx_seq: kani::any(),
        };
        kani::assume(asm.rx_pos <= 128);
        let mut report: [u8; HID_REPORT_SIZE] = kani::any();
        report[3] = 0; // seq == 0
        report[4] = 0;
        let n: usize = kani::any();
        let outcome = asm.process_frame(&report, n, &mut buf);
        if let FrameOutcome::ApduComplete(len) = outcome {
            assert!(len <= MAX_APDU_RX);
        }
        // NOTE: `asm.rx_pos <= MAX_APDU_RX` is a *reachable-state* invariant, not
        // an all-state one — an early-drop (`n<5` / wrong tag / PingEcho) returns
        // without resetting, so from an arbitrary (unreachable) `rx_pos` it can
        // stay huge. That is harmless (no write occurs on those paths — Kani's
        // built-in bounds checks prove it), so we do NOT assert it here; the
        // no-out-of-bounds-write property is what closes S-USB-OVERFLOW.
    }

    /// `ChainState::step` advances the chained-APDU write cursor; the caller
    /// then copies `lc` bytes to `buf[write_at..write_at + lc]`. Prove the
    /// cursor can never escape `buf_capacity`, over an arbitrary prior state
    /// and arbitrary `(ins, p1, lc, cap)` incl. `lc` near `usize::MAX` (the
    /// `checked_add` overflow guard): `pos <= cap` after every step, and every
    /// `Appended` / `Execute` outcome has `write_at + lc <= cap` so the
    /// caller's copy is in-bounds. No `assume` — the `np <= buf_capacity` gate
    /// makes both properties hold from any starting `pos`.
    #[kani::proof]
    fn chain_step_cursor_within_capacity() {
        let mut st = ChainState {
            ins: kani::any(),
            pos: kani::any(),
            elapsed_frames: kani::any(),
        };
        let ins: u8 = kani::any();
        let p1: u8 = kani::any();
        let lc: usize = kani::any();
        let cap: usize = kani::any();
        let outcome = st.step(ins, p1, lc, cap);
        assert!(st.pos() <= cap);
        match outcome {
            ChainStepOutcome::Appended { write_at, lc: l }
            | ChainStepOutcome::Execute { write_at, lc: l, .. } => {
                // The caller's `buf[write_at..write_at + l]` copy is in-bounds.
                assert!(write_at.checked_add(l).is_some_and(|e| e <= cap));
            }
            ChainStepOutcome::ProtocolError | ChainStepOutcome::WrongLength => {}
        }
    }

    /// `parse_apdu_header` is the first parse every USB byte hits. Prove it is
    /// panic-free ∀ and that a successful parse yields `data.len() == lc` with
    /// `lc` inside the input — the invariant `route_v2` + the chain machine
    /// rely on. Loop-free; a 16-byte symbolic input exercises the
    /// `HeaderTooShort`, `LcOverrun`, and OK (`5 + lc <= len`) arms. The OK arm
    /// is reached for `lc <= 11` at `N = 16`; the header logic is uniform in
    /// `lc` (`apdu[4] as usize` then `checked_add` + `end <= apdu.len()`, no
    /// per-value special-casing), and the proptest above covers `lc` up to 255
    /// over 0..8192-byte inputs — so this is representative, not `lc`-bounded.
    #[kani::proof]
    fn parse_apdu_header_sound() {
        let arr: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= arr.len());
        if let Ok(h) = parse_apdu_header(&arr[..len]) {
            assert!(h.data.len() == h.lc);
            assert!(h.lc <= len);
        }
    }
}

#[cfg(test)]
mod frame_clock_tests {
    use super::*;

    #[test]
    fn frame_delta_wraps_at_2048_like_full_speed_fnsof() {
        assert_eq!(frame_delta(5, 3), 2);
        // The DVT1 capture: start 0x7FE, now 0x000 is TWO frames, not 14,338.
        assert_eq!(frame_delta(0x000, 0x7FE), 2);
        assert_eq!(frame_delta(0x3FF, 0x000), 0x3FF);
        assert_eq!(frame_delta(0x123, 0x123), 0);
        // Bits above the 11-bit field never leak into a delta.
        assert_eq!(frame_delta(0x3801, 0x0000), 1);
    }

    #[test]
    fn backward_frame_steps_count_as_zero() {
        // EVT-3D21 2026-10-17 FNSOF trace: one-frame backward steps
        // (DSTS 0x00001106 -> 0x00401006, frame 17 -> 16) and torn reads.
        assert_eq!(frame_delta(16, 17), 0);
        assert_eq!(frame_delta(0x7FF, 0x000), 0);
        assert_eq!(frame_delta(0x780, 0x7BF), 0);
        assert_eq!(frame_delta(0x4F0, 0x4F7), 0);
        // The largest forward step still counted, and the first dropped one.
        assert_eq!(frame_delta(0x3FF, 0x000), 1023);
        assert_eq!(frame_delta(0x400, 0x000), 0);
    }

    #[test]
    fn negative_masked_backward_step_gains_two_seconds() {
        // The pre-fix arithmetic on the EVT capture: a one-frame backward
        // step read as 2,047 elapsed frames.
        let old = u32::from(16u16.wrapping_sub(17) & USB_FS_FRAME_MASK);
        assert_eq!(old, 2047, "the defect this guards");
        assert_eq!(frame_delta(16, 17), 0);
    }

    #[test]
    fn backward_steps_every_4_s_never_expire_a_chain_early() {
        // The EVT rate: one one-frame backward step every ~4,000 frames.
        // Pre-fix each step added ~2 s and a 30 s chain expired after about
        // 20 s. Now it expires within a few frames of its budget, never before.
        let mut s = ChainState::new();
        s.ins = 0x40;
        let mut last = 0u16;
        let mut expired_at = None;
        for t in 1..=40_000u32 {
            let mut f = t;
            if t % 4_000 == 0 {
                f -= 2; // the sample one frame behind its predecessor
            }
            let now = (f & u32::from(USB_FS_FRAME_MASK)) as u16;
            if s.tick_timeout(frame_step(now, &mut last)) {
                expired_at = Some(t);
                break;
            }
        }
        assert_eq!(expired_at, Some(ChainState::CHAIN_TIMEOUT_FRAMES));
    }

    #[test]
    fn frame_step_holds_last_across_a_backward_step() {
        let mut last = 17u16;
        assert_eq!(frame_step(16, &mut last), 0);
        assert_eq!(last, 17, "a backward reading must not move the reference");
        assert_eq!(frame_step(18, &mut last), 1);
        assert_eq!(last, 18);
        // Across the wrap.
        let mut last = 0x7FEu16;
        assert_eq!(frame_step(0x001, &mut last), 3);
        assert_eq!(last, 0x001);
    }

    #[test]
    fn negative_last_equals_now_after_backward_step_counts_frames_twice() {
        // The shape frame_step replaces: `delta(now, last); last = now`.
        let mut acc = 0u32;
        let mut last = 0u16;
        for f in [1u16, 2, 3, 2, 3, 4] {
            acc += frame_delta(f, last);
            last = f;
        }
        assert_eq!(acc, 5, "the defect: 4 frames elapsed, 5 counted");
        let mut acc = 0u32;
        let mut last = 0u16;
        for f in [1u16, 2, 3, 2, 3, 4] {
            acc += frame_step(f, &mut last);
        }
        assert_eq!(acc, 4);
    }

    #[test]
    fn negative_old_14_bit_mask_falsely_expires_a_short_reassembly() {
        // The pre-fix arithmetic on the same capture crossed every deadline.
        let old = u32::from(0x000u16.wrapping_sub(0x7FE) & 0x3FFF);
        assert!(old >= 5000, "the defect this guards: {old}");
        assert!(frame_delta(0x000, 0x7FE) < 5000);
    }

    #[test]
    fn accumulating_deltas_measures_a_30_s_chain_across_wraps() {
        // One sample per ms for 30 s across 14 wraps: the chain expires at
        // exactly its budget, not after the first wrap.
        let mut s = ChainState::new();
        s.ins = 0x40;
        let mut last = 0u16;
        let mut expired_at = None;
        for t in 1..=40_000u32 {
            let now = (t & u32::from(USB_FS_FRAME_MASK)) as u16;
            if s.tick_timeout(frame_step(now, &mut last)) {
                expired_at = Some(t);
                break;
            }
        }
        assert_eq!(expired_at, Some(ChainState::CHAIN_TIMEOUT_FRAMES));
    }
}
