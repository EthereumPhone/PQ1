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

/// Data frame: FRNR in bits 3-2 (our transmit sequence number).
/// Matches Infineon `DL_FCTR_FRNR_OFFSET = 2`, mask 0x0C.
const FRNR_SHIFT: u8 = 2;
/// Data frame: ACKNR in bits 1-0 (expected next rx sequence number).
/// Matches Infineon `DL_FCTR_ACKNR_OFFSET = 0`, mask 0x03.
const ACKNR_SHIFT: u8 = 0;

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

/// Presence bit — OR'd into the PCTR of every outgoing data frame when the
/// chip's shielded-connection (presentation layer) is available. Matches
/// Infineon `IFX_I2C_PRESENCE_BIT = 0x08`. Without it, the chip does not
/// route the payload through the PRL state machine and treats every frame
/// as a raw APDU (which then produces nonsense responses to handshake
/// messages).
const PCTR_PRESENCE_BIT: u8 = 0x08;

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

/// Maximum retries for ACK polling (one poll per ~1 ms).
/// SetObjectProtected triggers ECDSA-P256 signature verification on the
/// chip, which takes up to ~1 s wall clock on V3 silicon — bump to 3000
/// so we don't time out mid-verify.
const MAX_POLL_RETRIES: u32 = 3000;

/// I2C_STATE response-ready bit (bit 6 of byte 0).
const STATE_RESP_READY: u8 = 0x40;

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

/// Initial DL frame-number value for `rx_seq`. Per Infineon
/// `ifx_i2c_data_link_layer.c` (`DL_MAX_FRAME_NUM = 0x03`) `rx_seq_nr`
/// is initialised to 3 so the first received data frame's FRNR=0
/// passes the `fr_nr == (rx_seq_nr + 1) & 3` check and the ACK we
/// emit carries ACKNR=0 (matching the chip's just-sent FRNR). Our
/// previous init of 0 produced ACKs with ACKNR=1 → chip's DL layer
/// rejected them as ACKNR mismatch against its own tx_seq_nr=0,
/// dropped into DISCARD state, and silently returned 4-byte empty-OK
/// frames to every subsequent APDU.
///
/// `tx_seq` stays at 0 because `build_data_frame` does "use-then-bump"
/// rather than "bump-then-use" — our first send produces FRNR=0
/// directly.
const DL_RX_SEQ_INIT: u8 = 0x03;

impl IfxState {
    pub const fn new() -> Self {
        Self { tx_seq: 0, rx_seq: DL_RX_SEQ_INIT }
    }

    // -----------------------------------------------------------------------
    // Physical layer: register read/write
    // -----------------------------------------------------------------------

    /// Write `data` to an IFX I2C register, retrying on NACK.
    ///
    /// The chip enters sleep mode between transactions and NACKs the first
    /// address byte until it wakes — but the address detection itself is
    /// what wakes it. So NACK on the first transaction is expected; retry
    /// up to 20 times at 500 µs intervals before giving up.
    ///
    /// On the wire each transaction is: `[reg_addr, data...]`.
    unsafe fn write_register(&self, reg: u8, data: &[u8]) -> Result<(), IfxError> {
        let mut buf = [0u8; MAX_FRAME_SIZE + 1];
        let len = 1 + data.len();
        if len > buf.len() {
            return Err(IfxError::FrameTooLarge);
        }
        buf[0] = reg;
        buf[1..len].copy_from_slice(data);

        for _ in 0..20 {
            if i2c::write(&buf[..len]).is_ok() {
                return Ok(());
            }
            // LTO elides `for _ in 0..N { cortex_m::asm::nop() }` on
            // recent toolchains — use `delay` which has a volatile
            // counter and always runs the full cycle count.
            cortex_m::asm::delay(80_000);
        }
        Err(IfxError::I2c)
    }

    /// Read `buf.len()` bytes from an IFX I2C register, retrying on NACK.
    ///
    /// On the wire: I2C write `[reg_addr]`, then I2C read `buf` (repeated START).
    unsafe fn read_register(&self, reg: u8, buf: &mut [u8]) -> Result<(), IfxError> {
        for _ in 0..20 {
            if i2c::write_read(&[reg], buf).is_ok() {
                return Ok(());
            }
            // LTO elides `for _ in 0..N { cortex_m::asm::nop() }` on
            // recent toolchains — use `delay` which has a volatile
            // counter and always runs the full cycle count.
            cortex_m::asm::delay(80_000);
        }
        Err(IfxError::I2c)
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

    /// NOP delay loop (~1 ms at 160 MHz). Uses `cortex_m::asm::delay` —
    /// a `for _ in 0..N { nop() }` version gets elided by LTO.
    fn delay_1ms() {
        cortex_m::asm::delay(40_000);
    }

    /// Poll I2C_STATE register until response-ready bit is set.
    ///
    /// Transient read failures are expected — the chip may NACK while it
    /// is busy processing a previous command. Keep polling until either
    /// the ready bit flips or we exhaust MAX_POLL_RETRIES.
    unsafe fn poll_response_ready(&self) -> Result<[u8; 4], IfxError> {
        let mut state = [0u8; 4];
        let mut ok_reads: u32 = 0;
        let mut last_state0: u8 = 0;
        for i in 0..MAX_POLL_RETRIES {
            if self.read_register(REG_I2C_STATE, &mut state).is_ok() {
                ok_reads += 1;
                last_state0 = state[0];
                if state[0] & STATE_RESP_READY != 0 {
                    secure_log!(
                        "[OPTIGA/ifx] poll: ready after {} iters ({} ok reads), state[0]=0x{:02x}",
                        i, ok_reads, state[0]
                    );
                    return Ok(state);
                }
            }
            Self::delay_1ms();
        }
        secure_log!(
            "[OPTIGA/ifx] poll: TIMEOUT after {} iters, {} ok reads, last state[0]=0x{:02x}",
            MAX_POLL_RETRIES, ok_reads, last_state0
        );
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
        secure_log!("[OPTIGA/ifx] soft_reset: writing REG_SOFT_RESET(0x88)");
        if let Err(e) = self.write_register(REG_SOFT_RESET, &[0x00, 0x00]) {
            secure_log!("[OPTIGA/ifx] soft_reset: REG_SOFT_RESET write FAILED: {:?}", e);
            return Err(e);
        }
        secure_log!("[OPTIGA/ifx] soft_reset: REG_SOFT_RESET write ACKed");

        for _ in 0..20 {
            Self::delay_1ms();
        }

        self.tx_seq = 0;
        self.rx_seq = DL_RX_SEQ_INIT;

        let mut resynch = [0u8; 5];
        let len = self.build_resynch_frame(&mut resynch);
        secure_log!("[OPTIGA/ifx] soft_reset: sending ReSynch frame");
        if let Err(e) = self.write_register(REG_DATA, &resynch[..len]) {
            secure_log!("[OPTIGA/ifx] soft_reset: ReSynch write FAILED: {:?}", e);
            return Err(e);
        }
        secure_log!("[OPTIGA/ifx] soft_reset: ReSynch write ACKed");

        // ReSynch is fire-and-forget: the chip resets its sequence counters
        // but does NOT generate a response frame. Wait for the chip to
        // finish processing, then exit — the next APDU will find a chip in
        // a known state.
        for _ in 0..20 {
            Self::delay_1ms();
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Transceive: send APDU, receive response
    // -----------------------------------------------------------------------

    /// Send an APDU and receive the response.
    ///
    /// Handles transport-layer chaining (fragmentation for large APDUs)
    /// and data-link ACK/NACK/retransmission. PRESENCE_BIT is cleared —
    /// use [`transceive_prl`] for presentation-layer handshake messages.
    ///
    /// Returns the number of response bytes written to `resp`.
    pub unsafe fn transceive(
        &mut self,
        apdu: &[u8],
        resp: &mut [u8],
    ) -> Result<usize, IfxError> {
        self.send_apdu_inner(apdu, false)?;
        self.receive_response(resp)
    }

    /// Same as [`transceive`] but with PRESENCE_BIT set in the outgoing
    /// PCTR. Routes the payload to the chip's presentation layer — use
    /// for handshake messages (MasterHello, MasterFinished) and for
    /// shielded-connection records once a session is active.
    pub unsafe fn transceive_prl(
        &mut self,
        msg: &[u8],
        resp: &mut [u8],
    ) -> Result<usize, IfxError> {
        self.send_apdu_inner(msg, true)?;
        self.receive_response(resp)
    }

    /// Fragment and send an APDU, handling data-link ACK/NACK.
    ///
    /// `presence` selects which chip-side layer processes the payload:
    /// - `false` → bare APDU (OpenApplication, GetDataObject, …)
    /// - `true`  → presentation layer (MasterHello / MasterFinished / Record)
    ///
    /// The chip treats PCTR's PRESENCE_BIT as a layer selector. Setting it
    /// on a bare APDU causes the chip's PRL state machine to interpret
    /// the CMD byte as an SCTR and return an alert.
    unsafe fn send_apdu_inner(&mut self, apdu: &[u8], presence: bool) -> Result<(), IfxError> {
        let presence_bits = if presence { PCTR_PRESENCE_BIT } else { 0 };

        if apdu.len() <= MAX_PAYLOAD_PER_FRAME {
            let mut payload = [0u8; MAX_FRAME_SIZE];
            payload[0] = PCTR_NO_CHAIN | presence_bits;
            payload[1..1 + apdu.len()].copy_from_slice(apdu);
            let payload_len = 1 + apdu.len();
            self.send_frame_with_retry(&payload[..payload_len])?;
        } else {
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
                payload[0] = pctr | presence_bits;
                payload[1..1 + chunk].copy_from_slice(&apdu[offset..offset + chunk]);
                let payload_len = 1 + chunk;
                self.send_frame_with_retry(&payload[..payload_len])?;

                offset += chunk;
            }
        }
        Ok(())
    }

    /// Send a single data frame. Fire-and-forget at this layer — the
    /// OPTIGA Trust M doesn't always send a separate control-frame ACK;
    /// when the chip has a response ready immediately, it piggybacks the
    /// acknowledgment by setting ACKNR in the response data frame itself.
    /// The transmit-sequence increment happens unconditionally, and the
    /// subsequent `receive_response` both drains the response data frame
    /// and (via the chip's internal DL layer) validates the piggybacked ACK.
    unsafe fn send_frame_with_retry(&mut self, payload: &[u8]) -> Result<(), IfxError> {
        let mut frame_buf = [0u8; MAX_FRAME_SIZE];
        let frame_len = self.build_data_frame(payload, &mut frame_buf);
        self.write_register(REG_DATA, &frame_buf[..frame_len])?;
        self.tx_seq = (self.tx_seq + 1) & 0x03;
        Ok(())
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
            secure_log!(
                "[OPTIGA/ifx] rx: state=[{:02x} {:02x} {:02x} {:02x}] resp_len={} read_len={}",
                state[0], state[1], state[2], state[3], resp_len, read_len
            );

            // Read the response frame
            let mut frame_buf = [0u8; MAX_FRAME_SIZE];
            self.read_register(REG_DATA, &mut frame_buf[..read_len])?;
            secure_log!(
                "[OPTIGA/ifx] rx frame[0..8]=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}]",
                frame_buf[0], frame_buf[1], frame_buf[2], frame_buf[3],
                frame_buf[4], frame_buf[5], frame_buf[6], frame_buf[7]
            );

            let (fctr, payload) = match self.validate_frame(&frame_buf[..read_len]) {
                Ok(x) => x,
                Err(e) => {
                    secure_log!("[OPTIGA/ifx] rx validate_frame FAILED: {:?}", e);
                    return Err(e);
                }
            };

            // A control frame ahead of the data response is either the
            // ACK for our last write (fine — the chip will follow up with
            // the data frame) or a NACK (bail, caller should retry the
            // tx). We drain the ACK/NACK here and keep polling for the
            // real data response.
            if Self::is_control_frame(fctr) {
                match Self::ctrl_seqctr(fctr) {
                    SEQCTR_ACK => {
                        secure_log!("[OPTIGA/ifx] rx: ACK received, continuing poll for data");
                        continue;
                    }
                    SEQCTR_NACK => {
                        secure_log!("[OPTIGA/ifx] rx: NACK received");
                        return Err(IfxError::Nack);
                    }
                    SEQCTR_RESYNCH => {
                        secure_log!("[OPTIGA/ifx] rx: ReSynch received");
                        self.tx_seq = 0;
                        self.rx_seq = DL_RX_SEQ_INIT;
                        return Err(IfxError::ReSynch);
                    }
                    _ => return Err(IfxError::BadResponse),
                }
            }

            // Data frame: increment our rx sequence (this was frame N,
            // next expected is N+1) and send a separate ACK frame so the
            // chip knows it can drop its retransmission buffer.
            self.rx_seq = (self.rx_seq + 1) & 0x03;
            let mut ack_buf = [0u8; 5];
            let ack_len = self.build_ack_frame(&mut ack_buf);
            self.write_register(REG_DATA, &ack_buf[..ack_len])?;

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
