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

/// Node Address: host → SE050.
const NAD_HOST_TO_SE: u8 = 0x5A;

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

// PCB byte masks
const PCB_I_BLOCK: u8 = 0x00; // Bit 7 = 0
const PCB_I_CHAIN: u8 = 0x20; // Bit 5 = chaining (more frames follow)
const PCB_I_SEQ: u8 = 0x40; // Bit 6 = sequence number (N(S))
const PCB_R_BLOCK: u8 = 0x80; // Bits 7:6 = 10
const PCB_S_BLOCK: u8 = 0xC0; // Bits 7:6 = 11
const PCB_S_WTX_REQ: u8 = 0xC3; // S-block WTX request
const PCB_S_WTX_RSP: u8 = 0xE3; // S-block WTX response
const PCB_S_INTF_RESET_REQ: u8 = 0xCF; // S-block interface reset request (UM11225)
const PCB_S_INTF_RESET_RSP: u8 = 0xEF; // S-block interface reset response

// ---------------------------------------------------------------------------
// CRC-16/CCITT (polynomial 0x1021, init 0xFFFF)
// ---------------------------------------------------------------------------

/// CRC-16 as used by the SE050 T1oI2C protocol (GP 1.0 variant).
///
/// Algorithm: reflected CRC with polynomial 0x8408 (bit-reversed 0x1021),
/// init 0xFFFF, final XOR 0xFFFF. GP 1.0 does NOT byte-swap.
/// This matches `phNxpEseProto7816_ComputeCRC` in the NXP nano-package
/// with `T1oI2C_GP1_0` defined.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^= 0xFFFF;
    crc // GP 1.0: no byte-swap
}

// ---------------------------------------------------------------------------
// Frame encoding / decoding
// ---------------------------------------------------------------------------

// GP 1.0 frame header: NAD(1) + PCB(1) + LEN(2) = 4 bytes
const HEADER_LEN: usize = 4;

/// Build a T1oI2C frame (GP 1.0 format: 2-byte LEN) into `buf`.
/// Returns the total frame length.
fn build_frame(pcb: u8, inf: &[u8], buf: &mut [u8]) -> usize {
    let len = inf.len();
    buf[0] = NAD_HOST_TO_SE;
    buf[1] = pcb;
    buf[2] = (len >> 8) as u8; // LEN MSB
    buf[3] = (len & 0xFF) as u8; // LEN LSB
    buf[HEADER_LEN..HEADER_LEN + len].copy_from_slice(inf);
    let crc = crc16(&buf[..HEADER_LEN + len]);
    buf[HEADER_LEN + len] = (crc >> 8) as u8;
    buf[HEADER_LEN + len + 1] = (crc & 0xFF) as u8;
    HEADER_LEN + len + 2 // NAD + PCB + LEN(2) + INF + CRC16
}

/// Validate a received GP 1.0 frame's CRC. Returns (PCB, INF slice).
fn validate_frame(frame: &[u8]) -> Result<(u8, &[u8]), T1Error> {
    if frame.len() < 6 {
        return Err(T1Error::Protocol);
    }
    let pcb = frame[1];
    let inf_len = ((frame[2] as usize) << 8) | (frame[3] as usize);
    let total = HEADER_LEN + inf_len + 2;
    if frame.len() < total {
        return Err(T1Error::Protocol);
    }
    let computed = crc16(&frame[..HEADER_LEN + inf_len]);
    let received = ((frame[HEADER_LEN + inf_len] as u16) << 8)
        | (frame[HEADER_LEN + inf_len + 1] as u16);
    if computed != received {
        return Err(T1Error::Crc);
    }
    Ok((pcb, &frame[HEADER_LEN..HEADER_LEN + inf_len]))
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

        loop {
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
