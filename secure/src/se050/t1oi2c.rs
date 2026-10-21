//! T=1 over I2C (T1oI2C) transport for SE050 (UM11225).
//!
//! Implements the ISO 7816-3 T=1 protocol adapted for I2C communication
//! with the NXP SE050 secure element.
//!
//! Frame format (SE050 / UM11225):
//!   NAD (1) | PCB (1) | LEN (1) | INF (0..254) | CRC16 (2)
//!
//! For payloads > 254 bytes, I-frame chaining is used.

use super::i2c;

/// SE050 T1oI2C errors.
#[derive(Debug)]
pub enum T1Error {
    I2c(i2c::I2cError),
    /// CRC mismatch in received frame.
    Crc,
    /// Unexpected frame type or protocol error.
    Protocol,
    /// Too many retries / WTX requests.
    Timeout,
    /// Response buffer too small.
    BufferOverflow,
}

impl From<i2c::I2cError> for T1Error {
    fn from(e: i2c::I2cError) -> Self {
        T1Error::I2c(e)
    }
}

// ---------------------------------------------------------------------------
// T1oI2C protocol constants (UM11225 / SE050)
// ---------------------------------------------------------------------------

// NAD_HOST_TO_SE now lives in `sphincs_tz_shared::t1_frame` alongside the
// builder that writes it — one definition, not two copies of a wire constant.

/// Max information field size per I-frame.
const IFSC: usize = 254;

/// Max frame size: NAD(1) + PCB(1) + LEN(2, GP1.0) + INF(254) + CRC(2) = 260.
const MAX_FRAME: usize = IFSC + 6;

/// Max WTX (Waiting Time Extension) retries before giving up.
const MAX_WTX_RETRIES: u32 = 500;

/// Delay (nop loops) between I2C read retries when SE050 is busy.
const READ_RETRY_DELAY: u32 = 50_000;

/// Max I2C read retries when SE050 NACKs (busy processing).
const MAX_READ_RETRIES: u32 = 1000;

/// Max response frames (I-frames + interspersed WTX) the receive loop will
/// accept before giving up. A conformant SE050 answers any APDU in a handful
/// of chained I-frames (<= a few KB / IFSC), plus at most `MAX_WTX_RETRIES`
/// waiting-time extensions — well under this bound. The cap exists so a
/// glitched / brown-out-confused / swapped SE that emits an unbounded stream
/// of frames (e.g. empty chained I-frames, which advance nothing) turns into
/// a clean `Protocol` error the unlock/boot retry path handles, instead of
/// wedging the CPU in an infinite receive loop until a power cycle.
const MAX_RESP_FRAMES: u32 = MAX_WTX_RETRIES + 1024;

// PCB byte masks
const PCB_I_BLOCK: u8 = 0x00; // Bit 7 = 0
const PCB_I_CHAIN: u8 = 0x20; // Bit 5 = chaining (more frames follow)
const PCB_I_SEQ: u8 = 0x40; // Bit 6 = sequence number (N(S))
const PCB_R_BLOCK: u8 = 0x80; // Bits 7:6 = 10
const PCB_S_WTX_REQ: u8 = 0xC3; // S-block WTX request
const PCB_S_WTX_RSP: u8 = 0xE3; // S-block WTX response
const PCB_S_INTF_RESET_REQ: u8 = 0xCF; // S-block interface reset request (UM11225)

// ---------------------------------------------------------------------------
// CRC-16/CCITT (polynomial 0x1021, init 0xFFFF)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Frame build/validate — shim over the Kani-proven extraction
// ---------------------------------------------------------------------------
//
// The pure framing logic lives in `sphincs_tz_shared::t1_frame` so it can be
// host-compiled and bounded-verified (`cargo kani -p sphincs-tz-shared`:
// panic-freedom on any byte string, build/validate round-trip,
// accept => CRC-over-declared-span, and a flipped-CRC-bit negative control).
// Same pattern and same crate as the NS-pointer validator.
//
// These are re-export shims, NOT a second copy: a parallel reimplementation
// beside the driver, with nothing detecting drift, would prove only that the
// two copies agree — see `docs/verification/hardware-assumption-boundary-
// 2026-07-17.md` §2. The driver calls the proven code.

pub use sphincs_tz_shared::t1_frame::build_frame;

/// Validate a received GP 1.0 frame's CRC. Returns (PCB, INF slice).
///
/// Thin `FrameError` -> `T1Error` mapping over the proven
/// `sphincs_tz_shared::t1_frame::validate_frame`; behaviour-identical to the
/// pre-extraction local copy.
fn validate_frame(frame: &[u8]) -> Result<(u8, &[u8]), T1Error> {
    sphincs_tz_shared::t1_frame::validate_frame(frame).map_err(|e| match e {
        sphincs_tz_shared::t1_frame::FrameError::Malformed => T1Error::Protocol,
        sphincs_tz_shared::t1_frame::FrameError::Crc => T1Error::Crc,
    })
}

// ---------------------------------------------------------------------------
// Transport state
// ---------------------------------------------------------------------------

/// T1oI2C transport state — tracks I-frame sequence numbers.
pub struct T1State {
    /// Send sequence number (N(S)), toggles 0/1.
    ns: u8,
    /// Receive sequence number (N(R)), toggles 0/1.
    nr: u8,
}

impl T1State {
    pub const fn new() -> Self {
        Self { ns: 0, nr: 0 }
    }

    /// Send an S-frame Interface Reset to the SE050.
    ///
    /// Must be called once after power-on before any APDU exchange.
    /// The SE050 responds with an ATR (Answer To Reset) in the
    /// interface reset response S-frame.
    pub unsafe fn interface_reset(&mut self) -> Result<(), T1Error> {
        let mut tx_buf = [0u8; MAX_FRAME];
        let mut rx_buf = [0u8; MAX_FRAME];

        // Send S(INTF_RESET_REQ) — empty INF
        let frame_len = build_frame(PCB_S_INTF_RESET_REQ, &[], &mut tx_buf);
        i2c::write(&tx_buf[..frame_len])?;

        // The SE050 needs time to perform internal reset before responding.
        // Datasheet: up to 5 ms for interface reset.
        for _ in 0..1_000_000 {
            cortex_m::asm::nop();
        }

        // Read response — retry since SE050 may NACK while resetting
        self.read_frame(&mut rx_buf)?;

        #[cfg(feature = "debug-log")]
        {
            let inf_len = ((rx_buf[2] as usize) << 8) | (rx_buf[3] as usize);
            secure_log!(
                "[SE050] RX NAD={:02x} PCB={:02x} LEN={} CRC_OK={}",
                rx_buf[0], rx_buf[1], inf_len,
                validate_frame(&rx_buf).is_ok()
            );
        }

        let (rx_pcb, _atr) = validate_frame(&rx_buf)?;

        // GP 1.0: SE050 may respond with R-ACK (0x80/0x82) or
        // S-frame response. Both are acceptable after interface reset.
        // R-block (bits 7:6 = 10) means acknowledged.
        // S-block response (bit 5 set) with RESYNCH/INTF_RESET is also OK.

        // Reset sequence numbers after interface reset
        self.ns = 0;
        self.nr = 0;

        Ok(())
    }

    /// Send an APDU and receive the response.
    ///
    /// Handles I-frame chaining for large APDUs (> 254 bytes) and
    /// WTX (Waiting Time Extension) S-frames from the SE050.
    ///
    /// Returns the number of response bytes written to `resp`.
    pub unsafe fn transceive(&mut self, apdu: &[u8], resp: &mut [u8]) -> Result<usize, T1Error> {
        let mut tx_buf = [0u8; MAX_FRAME];
        let mut rx_buf = [0u8; MAX_FRAME];

        // --- Send phase: chain I-frames if APDU > IFSC ---
        let mut offset = 0;
        while offset < apdu.len() {
            let remaining = apdu.len() - offset;
            let chunk = remaining.min(IFSC);
            let is_last = chunk == remaining;

            let mut pcb = PCB_I_BLOCK;
            if self.ns != 0 {
                pcb |= PCB_I_SEQ;
            }
            if !is_last {
                pcb |= PCB_I_CHAIN;
            }

            let frame_len = build_frame(pcb, &apdu[offset..offset + chunk], &mut tx_buf);
            i2c::write(&tx_buf[..frame_len])?;
            self.ns ^= 1;
            offset += chunk;

            if !is_last {
                // Wait for R(ACK) before sending next chain
                self.read_frame(&mut rx_buf)?;
                let (rx_pcb, _) = validate_frame(&rx_buf)?;
                if rx_pcb & 0xC0 != PCB_R_BLOCK {
                    return Err(T1Error::Protocol);
                }
            }
        }

        // --- Receive phase: collect response I-frames ---
        let mut resp_offset = 0;
        let mut wtx_count = 0u32;
        let mut frame_count = 0u32;

        loop {
            // Total-frame backstop: a conformant SE finishes in a handful of
            // frames; an unbounded stream (glitched/hostile part) becomes a
            // clean error instead of an infinite loop (see MAX_RESP_FRAMES).
            frame_count += 1;
            if frame_count > MAX_RESP_FRAMES {
                return Err(T1Error::Protocol);
            }

            self.read_frame(&mut rx_buf)?;
            let (rx_pcb, inf) = validate_frame(&rx_buf)?;

            // Check frame type
            if rx_pcb & 0xC0 == 0xC0 {
                // S-frame
                if rx_pcb == PCB_S_WTX_REQ {
                    // WTX request — SE050 needs more time
                    wtx_count += 1;
                    if wtx_count > MAX_WTX_RETRIES {
                        return Err(T1Error::Timeout);
                    }
                    // Send WTX response (echo the INF byte)
                    let wtx_frame_len = build_frame(PCB_S_WTX_RSP, inf, &mut tx_buf);
                    i2c::write(&tx_buf[..wtx_frame_len])?;
                    continue;
                }
                return Err(T1Error::Protocol);
            }

            if rx_pcb & 0xC0 == 0x80 {
                // R-frame (unexpected in receive phase)
                return Err(T1Error::Protocol);
            }

            // A chained I-frame (more-data bit set) that carries no payload
            // is never a valid continuation: it advances `resp_offset` by 0,
            // so the BufferOverflow guard below can never trip and the loop
            // would ACK-and-repeat forever on a stuck/hostile SE. Reject it
            // as a protocol error (the frame-count backstop above would also
            // catch it, but this fails fast and is unambiguous).
            if (rx_pcb & PCB_I_CHAIN) != 0 && inf.is_empty() {
                return Err(T1Error::Protocol);
            }

            // I-frame — copy INF to response buffer
            if resp_offset + inf.len() > resp.len() {
                return Err(T1Error::BufferOverflow);
            }
            resp[resp_offset..resp_offset + inf.len()].copy_from_slice(inf);
            resp_offset += inf.len();

            self.nr ^= 1;

            // Check chaining bit
            if rx_pcb & PCB_I_CHAIN == 0 {
                // Last frame — done
                break;
            }

            // More frames coming — send R(ACK)
            let ack_pcb = PCB_R_BLOCK | if self.nr != 0 { 0x10 } else { 0x00 };
            let ack_len = build_frame(ack_pcb, &[], &mut tx_buf);
            i2c::write(&tx_buf[..ack_len])?;
        }

        Ok(resp_offset)
    }

    /// Read a frame from the SE050.
    ///
    /// The SE050 sends an entire T1oI2C frame in response to a single
    /// I2C read transaction. We poll with short reads (1 byte) until
    /// we see the SOF byte (NAD=0xA5), then read the rest of the frame
    /// in one more I2C transaction.
    ///
    /// Two-transaction approach:
    /// 1. Poll: read 1 byte until NAD=0xA5
    /// 2. Bulk: read up to MAX_FRAME-1 bytes (PCB+LEN+INF+CRC)
    unsafe fn read_frame(&self, buf: &mut [u8; MAX_FRAME]) -> Result<(), T1Error> {
        const SOF: u8 = 0xA5; // SE050 → host NAD byte

        // Step 1: Poll for SOF. The SE050 NACKs while busy, or returns
        // 0x00 if it hasn't prepared a response yet.
        let mut found_sof = false;
        for _ in 0..MAX_READ_RETRIES {
            #[cfg(feature = "ui-px-film-gaps")]
            crate::ui::px::film_gaps::count(b'Q');
            match i2c::read(&mut buf[..1]) {
                Ok(()) => {
                    if buf[0] == SOF {
                        found_sof = true;
                        break;
                    }
                    // Not SOF — SE050 not ready
                    for _ in 0..READ_RETRY_DELAY {
                        cortex_m::asm::nop();
                    }
                }
                Err(i2c::I2cError::Nack) => {
                    for _ in 0..READ_RETRY_DELAY {
                        cortex_m::asm::nop();
                    }
                }
                Err(e) => return Err(T1Error::I2c(e)),
            }
            // Not ready yet (both arms above): the provisioning film may draw.
            crate::ui::busy_poll();
        }

        if !found_sof {
            return Err(T1Error::Timeout);
        }

        // Step 2: SOF received. Read the remainder of the frame in one
        // I2C transaction: PCB(1) + LEN(1) + INF(up to 254) + CRC(2).
        // We read a generous fixed size; trailing bytes beyond the frame
        // will be 0x00 or garbage — we parse only up to LEN+CRC.
        // Read remaining frame: PCB(1) + LEN(2) + INF(up to 254) + CRC(2).
        // Max = 259 bytes. Read the full possible frame.
        let read_len = MAX_FRAME - 1; // everything after NAD
        i2c::read(&mut buf[1..1 + read_len])?;

        // buf[0]=NAD(0xA5), buf[1]=PCB, buf[2]=LEN, buf[3..]=INF+CRC
        Ok(())
    }
}
