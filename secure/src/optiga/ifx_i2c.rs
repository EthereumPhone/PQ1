//! IFX I2C protocol stack for OPTIGA Trust M (layers 1–3).
//!
//! Implements Infineon's proprietary register-based I2C protocol:
//! - **Physical layer**: register read/write via I2C sub-addressing
//! - **Data link layer**: frame construction, Infineon CRC-16, ACK/NACK,
//!   2-bit sequence numbers (mod 4), retransmission
//! - **Transport layer**: PCTR chaining for messages > one frame
//!
//! Reference: Infineon I2C Protocol v2.03

use super::i2c;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum IfxError {
    I2c,
    Crc,
    Nack,
    Timeout,
    FrameTooLarge,
    BadResponse,
    /// ReSynch after too many retries — protocol reset.
    ReSynch,
}

impl From<i2c::I2cError> for IfxError {
    fn from(_: i2c::I2cError) -> Self {
        IfxError::I2c
    }
}

// ---------------------------------------------------------------------------
// IFX I2C register addresses
// ---------------------------------------------------------------------------

/// Data register — read/write frame payloads.
const REG_DATA: u8 = 0x80;
/// Maximum data register length (2 bytes, big-endian).
const REG_DATA_REG_LEN: u8 = 0x81;
/// Device state register (4 bytes). Bit 6 of byte 0 = response ready.
const REG_I2C_STATE: u8 = 0x82;
/// Soft reset register — write `0x0000` to reset.
const REG_SOFT_RESET: u8 = 0x88;

// ---------------------------------------------------------------------------
// Frame control byte (FCTR) encoding
// ---------------------------------------------------------------------------

/// Bit 7: frame type. 0 = data frame, 1 = control frame.
const FCTR_CTRL_BIT: u8 = 0x80;

/// Control frame SEQCTR field (bits 6-5):
/// ACK = 0b00, NACK = 0b01, ReSynch = 0b10
const SEQCTR_ACK: u8 = 0x00;
const SEQCTR_NACK: u8 = 0x20;
const SEQCTR_RESYNCH: u8 = 0x40;

/// Data frame: FRNR in bits 1-0 (our transmit sequence number).
const FRNR_SHIFT: u8 = 0;
/// Data frame: ACKNR in bits 3-2 (expected next rx sequence number).
const ACKNR_SHIFT: u8 = 2;

// ---------------------------------------------------------------------------
// Transport layer PCTR encoding
// ---------------------------------------------------------------------------

/// No chaining — single-frame message.
const PCTR_NO_CHAIN: u8 = 0x00;
/// First fragment of a chained message.
const PCTR_CHAIN_FIRST: u8 = 0x01;
/// Intermediate fragment.
const PCTR_CHAIN_MID: u8 = 0x02;
/// Last fragment.
const PCTR_CHAIN_LAST: u8 = 0x04;
/// Chaining indicator mask (bits 2-0).
const PCTR_CHAIN_MASK: u8 = 0x07;

// ---------------------------------------------------------------------------
// Sizes and limits
// ---------------------------------------------------------------------------

/// Maximum frame size on the wire (IFX I2C default).
const MAX_FRAME_SIZE: usize = 277;
/// Data link header: FCTR(1) + FLEN(2) + CRC(2) = 5 bytes overhead.
const DL_HEADER_SIZE: usize = 5;
/// Transport layer header: PCTR(1).
const TL_HEADER_SIZE: usize = 1;
/// Maximum APDU payload per frame (single, unchained).
const MAX_PAYLOAD_PER_FRAME: usize = MAX_FRAME_SIZE - DL_HEADER_SIZE - TL_HEADER_SIZE;

/// Maximum retries for ACK polling.
const MAX_POLL_RETRIES: u32 = 500;
/// Maximum retransmission attempts on NACK.
const MAX_TX_RETRIES: u32 = 3;

/// I2C_STATE response-ready bit (bit 6 of byte 0).
const STATE_RESP_READY: u8 = 0x40;

/// Maximum reassembled APDU response size (stack buffer).
const MAX_APDU_SIZE: usize = 1557;

// ---------------------------------------------------------------------------
// Infineon CRC-16 (nibble-based, NOT standard CRC-16/CCITT)
// ---------------------------------------------------------------------------

/// Compute the Infineon IFX I2C CRC-16 over `data`.
///
/// This is Infineon's custom nibble-based CRC algorithm. It is NOT the
/// same as the CRC-16/CCITT used by SE050's T1oI2C. Getting this wrong
/// causes every frame to be rejected by the chip.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        let h1 = (crc ^ byte as u16) & 0xFF;
        let h2 = h1 & 0x0F;
        let h3 = (h2 << 4) ^ h1;
        let h4 = h3 >> 4;
        crc = ((((h3 << 1) ^ h4) << 4) ^ h2) << 3 ^ h4 ^ (crc >> 8);
    }
    crc
}

// ---------------------------------------------------------------------------
// IFX I2C state
// ---------------------------------------------------------------------------

/// Protocol state for one IFX I2C connection.
pub struct IfxState {
    /// Our transmit sequence number (2-bit, mod 4).
    tx_seq: u8,
    /// Expected receive sequence number (2-bit, mod 4).
    rx_seq: u8,
}

impl IfxState {
    pub const fn new() -> Self {
        Self { tx_seq: 0, rx_seq: 0 }
    }

    // -----------------------------------------------------------------------
    // Physical layer: register read/write
    // -----------------------------------------------------------------------

    /// Write `data` to an IFX I2C register.
    ///
    /// On the wire this is a single I2C write: `[reg_addr, data...]`.
    unsafe fn write_register(&self, reg: u8, data: &[u8]) -> Result<(), IfxError> {
        // Build [reg, data...] on stack. Max frame is 277 bytes + 1 reg byte.
        let mut buf = [0u8; MAX_FRAME_SIZE + 1];
        let len = 1 + data.len();
        if len > buf.len() {
            return Err(IfxError::FrameTooLarge);
        }
        buf[0] = reg;
        buf[1..len].copy_from_slice(data);
        i2c::write(&buf[..len])?;
        Ok(())
    }

    /// Read `buf.len()` bytes from an IFX I2C register.
    ///
    /// On the wire: I2C write `[reg_addr]`, then I2C read `buf`.
    unsafe fn read_register(&self, reg: u8, buf: &mut [u8]) -> Result<(), IfxError> {
        i2c::write_read(&[reg], buf)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Data link layer: frame construction and validation
    // -----------------------------------------------------------------------

    /// Build a data frame into `buf`. Returns the total frame length.
    ///
    /// Frame: `FCTR(1) | FLEN(2 BE) | payload | CRC-16(2 BE)`
    fn build_data_frame(&self, payload: &[u8], buf: &mut [u8]) -> usize {
        let frame_len = DL_HEADER_SIZE + payload.len();

        // FCTR: data frame (bit 7 = 0), FRNR = tx_seq, ACKNR = rx_seq
        let fctr = (self.tx_seq << FRNR_SHIFT) | (self.rx_seq << ACKNR_SHIFT);
        buf[0] = fctr;

        // FLEN: payload length (big-endian 16-bit)
        let plen = payload.len() as u16;
        buf[1] = (plen >> 8) as u8;
        buf[2] = plen as u8;

        // Payload
        buf[3..3 + payload.len()].copy_from_slice(payload);

        // CRC-16 over everything except the CRC field itself
        let crc = crc16(&buf[..3 + payload.len()]);
        buf[3 + payload.len()] = (crc >> 8) as u8;
        buf[3 + payload.len() + 1] = crc as u8;

        frame_len
    }

    /// Build an ACK control frame into `buf`. Returns 5 (fixed size).
    fn build_ack_frame(&self, buf: &mut [u8]) -> usize {
        // FCTR: control frame (bit 7=1), ACK (bits 6-5=00), ACKNR = rx_seq
        buf[0] = FCTR_CTRL_BIT | SEQCTR_ACK | (self.rx_seq << ACKNR_SHIFT);
        // FLEN = 0 (no payload)
        buf[1] = 0x00;
        buf[2] = 0x00;
        // CRC
        let crc = crc16(&buf[..3]);
        buf[3] = (crc >> 8) as u8;
        buf[4] = crc as u8;
        5
    }

    /// Build a ReSynch control frame into `buf`. Returns 5.
    fn build_resynch_frame(&self, buf: &mut [u8]) -> usize {
        buf[0] = FCTR_CTRL_BIT | SEQCTR_RESYNCH;
        buf[1] = 0x00;
        buf[2] = 0x00;
        let crc = crc16(&buf[..3]);
        buf[3] = (crc >> 8) as u8;
        buf[4] = crc as u8;
        5
    }

    /// Validate a received frame. Returns `(fctr, payload_slice)`.
    fn validate_frame<'a>(&self, frame: &'a [u8]) -> Result<(u8, &'a [u8]), IfxError> {
        if frame.len() < DL_HEADER_SIZE {
            return Err(IfxError::BadResponse);
        }

        let fctr = frame[0];
        let flen = ((frame[1] as usize) << 8) | frame[2] as usize;
        let total = 3 + flen + 2; // header(3) + payload + CRC(2)

        if total > frame.len() {
            return Err(IfxError::BadResponse);
        }

        // Verify CRC
        let expected_crc = crc16(&frame[..3 + flen]);
        let actual_crc = ((frame[3 + flen] as u16) << 8) | frame[3 + flen + 1] as u16;
        if expected_crc != actual_crc {
            return Err(IfxError::Crc);
        }

        let payload = &frame[3..3 + flen];
        Ok((fctr, payload))
    }

    /// Check if a frame is a control frame (ACK/NACK/ReSynch).
    fn is_control_frame(fctr: u8) -> bool {
        fctr & FCTR_CTRL_BIT != 0
    }

    /// Extract SEQCTR from a control frame's FCTR.
    fn ctrl_seqctr(fctr: u8) -> u8 {
        fctr & 0x60
    }

    // -----------------------------------------------------------------------
    // Polling helpers
    // -----------------------------------------------------------------------

    /// NOP delay loop (~1 ms at 160 MHz).
    fn delay_1ms() {
        for _ in 0..40_000 {
            cortex_m::asm::nop();
        }
    }

    /// Poll I2C_STATE register until response-ready bit is set.
    /// Returns the 4-byte state on success.
    unsafe fn poll_response_ready(&self) -> Result<[u8; 4], IfxError> {
        let mut state = [0u8; 4];
        for _ in 0..MAX_POLL_RETRIES {
            self.read_register(REG_I2C_STATE, &mut state)?;
            if state[0] & STATE_RESP_READY != 0 {
                return Ok(state);
            }
            Self::delay_1ms();
        }
        Err(IfxError::Timeout)
    }

    // -----------------------------------------------------------------------
    // Soft reset
    // -----------------------------------------------------------------------

    /// Perform a soft reset of the OPTIGA Trust M.
    ///
    /// Writes `0x0000` to register 0x88, then polls I2C_STATE until the
    /// chip is ready (~15 ms for warm reset).
    pub unsafe fn soft_reset(&mut self) -> Result<(), IfxError> {
        self.write_register(REG_SOFT_RESET, &[0x00, 0x00])?;

        // Wait ~20 ms for soft reset to complete
        for _ in 0..20 {
            Self::delay_1ms();
        }

        // Reset sequence counters
        self.tx_seq = 0;
        self.rx_seq = 0;

        // Send ReSynch to synchronize data link layer
        let mut resynch = [0u8; 5];
        let len = self.build_resynch_frame(&mut resynch);
        self.write_register(REG_DATA, &resynch[..len])?;

        // Wait for ReSynch ACK
        self.poll_response_ready()?;
        let mut resp = [0u8; 5];
        self.read_register(REG_DATA, &mut resp)?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Transceive: send APDU, receive response
    // -----------------------------------------------------------------------

    /// Send an APDU and receive the response.
    ///
    /// Handles transport-layer chaining (fragmentation for large APDUs)
    /// and data-link ACK/NACK/retransmission.
    ///
    /// Returns the number of response bytes written to `resp`.
    pub unsafe fn transceive(
        &mut self,
        apdu: &[u8],
        resp: &mut [u8],
    ) -> Result<usize, IfxError> {
        // --- Transmit phase: fragment APDU if needed ---
        self.send_apdu(apdu)?;

        // --- Receive phase: read and reassemble response ---
        self.receive_response(resp)
    }

    /// Fragment and send an APDU, handling data-link ACK/NACK.
    unsafe fn send_apdu(&mut self, apdu: &[u8]) -> Result<(), IfxError> {
        if apdu.len() <= MAX_PAYLOAD_PER_FRAME {
            // Single frame: PCTR = no chaining
            let mut payload = [0u8; MAX_FRAME_SIZE];
            payload[0] = PCTR_NO_CHAIN;
            payload[1..1 + apdu.len()].copy_from_slice(apdu);
            let payload_len = 1 + apdu.len();
            self.send_frame_with_retry(&payload[..payload_len])?;
        } else {
            // Multi-frame chaining
            let mut offset = 0;
            let total = apdu.len();
            let mut first = true;

            while offset < total {
                let remaining = total - offset;
                let chunk = remaining.min(MAX_PAYLOAD_PER_FRAME);
                let is_last = offset + chunk >= total;

                let pctr = if first {
                    first = false;
                    PCTR_CHAIN_FIRST
                } else if is_last {
                    PCTR_CHAIN_LAST
                } else {
                    PCTR_CHAIN_MID
                };

                let mut payload = [0u8; MAX_FRAME_SIZE];
                payload[0] = pctr;
                payload[1..1 + chunk].copy_from_slice(&apdu[offset..offset + chunk]);
                let payload_len = 1 + chunk;
                self.send_frame_with_retry(&payload[..payload_len])?;

                offset += chunk;
            }
        }
        Ok(())
    }

    /// Send a single data frame and wait for ACK, with retry on NACK.
    unsafe fn send_frame_with_retry(&mut self, payload: &[u8]) -> Result<(), IfxError> {
        let mut frame_buf = [0u8; MAX_FRAME_SIZE];

        for retry in 0..MAX_TX_RETRIES {
            let frame_len = self.build_data_frame(payload, &mut frame_buf);
            self.write_register(REG_DATA, &frame_buf[..frame_len])?;

            // Wait for response (ACK or NACK)
            self.poll_response_ready()?;

            let mut ack_buf = [0u8; MAX_FRAME_SIZE];
            // Read at least 5 bytes for a control frame
            self.read_register(REG_DATA, &mut ack_buf[..5])?;

            let (fctr, _) = self.validate_frame(&ack_buf[..5])?;

            if Self::is_control_frame(fctr) {
                match Self::ctrl_seqctr(fctr) {
                    SEQCTR_ACK => {
                        // Success — advance transmit sequence
                        self.tx_seq = (self.tx_seq + 1) & 0x03;
                        return Ok(());
                    }
                    SEQCTR_NACK => {
                        // Retry
                        if retry == MAX_TX_RETRIES - 1 {
                            return Err(IfxError::Nack);
                        }
                        continue;
                    }
                    SEQCTR_RESYNCH => {
                        self.tx_seq = 0;
                        self.rx_seq = 0;
                        return Err(IfxError::ReSynch);
                    }
                    _ => return Err(IfxError::BadResponse),
                }
            } else {
                // Unexpected data frame instead of control frame
                return Err(IfxError::BadResponse);
            }
        }
        Err(IfxError::Nack)
    }

    /// Receive a response, handling chained fragments.
    /// Returns total response APDU bytes (PCTR stripped).
    unsafe fn receive_response(&mut self, resp: &mut [u8]) -> Result<usize, IfxError> {
        let mut total_len: usize = 0;

        loop {
            // Poll for response data frame
            self.poll_response_ready()?;

            // Read I2C_STATE to get response length
            let mut state = [0u8; 4];
            self.read_register(REG_I2C_STATE, &mut state)?;
            let resp_len = ((state[2] as usize) << 8) | state[3] as usize;
            let read_len = if resp_len > 0 && resp_len <= MAX_FRAME_SIZE {
                resp_len
            } else {
                MAX_FRAME_SIZE
            };

            // Read the response frame
            let mut frame_buf = [0u8; MAX_FRAME_SIZE];
            self.read_register(REG_DATA, &mut frame_buf[..read_len])?;

            let (fctr, payload) = self.validate_frame(&frame_buf[..read_len])?;

            // Send ACK for this data frame
            self.rx_seq = (self.rx_seq + 1) & 0x03;
            let mut ack_buf = [0u8; 5];
            let ack_len = self.build_ack_frame(&mut ack_buf);
            self.write_register(REG_DATA, &ack_buf[..ack_len])?;

            // Control frame as response = error
            if Self::is_control_frame(fctr) {
                return Err(IfxError::BadResponse);
            }

            // Extract transport layer: first byte is PCTR
            if payload.is_empty() {
                return Err(IfxError::BadResponse);
            }
            let pctr = payload[0];
            let apdu_chunk = &payload[1..];

            // Copy into output buffer
            if total_len + apdu_chunk.len() > resp.len() {
                return Err(IfxError::FrameTooLarge);
            }
            resp[total_len..total_len + apdu_chunk.len()].copy_from_slice(apdu_chunk);
            total_len += apdu_chunk.len();

            // Check chaining
            match pctr & PCTR_CHAIN_MASK {
                PCTR_NO_CHAIN | PCTR_CHAIN_LAST => {
                    // Complete message received
                    return Ok(total_len);
                }
                PCTR_CHAIN_FIRST | PCTR_CHAIN_MID => {
                    // More fragments coming — continue loop
                    continue;
                }
                _ => return Err(IfxError::BadResponse),
            }
        }
    }
}
