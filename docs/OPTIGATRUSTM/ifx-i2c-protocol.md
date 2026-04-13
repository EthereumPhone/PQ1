# IFX I2C Protocol v2.03 -- Complete Reference

The OPTIGA Trust M communicates over a proprietary layered protocol built on top of standard I2C. This document covers all four layers needed to implement a driver.

## Protocol Stack

```
Application Layer (APDU commands -- see commands-and-oids.md)
    |
Presentation Layer (optional Shielded Connection -- see shielded-connection.md)
    |
Transport Layer (fragmentation/reassembly, 1-byte PCTR header)
    |
Data Link Layer (framing, CRC-16, sequence numbers, 5-byte header)
    |
Physical Layer (I2C register read/write at slave address 0x30)
```

---

## 1. Physical Layer

### I2C Slave Address

**Default: `0x30`** (7-bit). In 8-bit format: `0x60` (write), `0x61` (read).

Configurable via register `0x83` (BASE_ADDR). Bit 15 = persist across resets.

### Register Map

| Address | Name | Size | Access | Description |
|---------|------|------|--------|-------------|
| `0x80` | DATA | variable | R/W | Data read/write register |
| `0x81` | DATA_REG_LEN | 2 bytes | R/W | Max data register length (0x0010--0xFFFF) |
| `0x82` | I2C_STATE | 4 bytes | R | Device state + response data length |
| `0x83` | BASE_ADDR | 2 bytes | W | I2C base address (bit 15 = persist) |
| `0x84` | MAX_SCL_FREQU | 4 bytes | R | Maximum clock frequency (KHz) |
| `0x85` | GUARD_TIME | 4 bytes | R | Protocol timing parameter |
| `0x86` | TRANS_TIMEOUT | 4 bytes | R | Transmission timeout |
| `0x87` | PWR_SAVE_TIMEOUT | 4 bytes | R/W | Power save delay (ms) |
| `0x88` | SOFT_RESET | 2 bytes | W | Trigger device reset (write 0x0000) |
| `0x89` | I2C_MODE | 2 bytes | R/W | Current I2C mode |
| `0x90`--`0x9F` | APP_STATE_0..F | 4 bytes | R | Application-specific state |

### I2C_STATE Register (0x82) Bit Fields

```
Byte 0, Bit 6 (0x40): Response Ready -- data available for reading
Byte 0, Bit 3 (0x08): Soft Reset supported
Bytes 2-3: Response frame size (16-bit big-endian)
```

### I2C_MODE Values

| Value | Mode |
|-------|------|
| `0x03` | Standard Mode / Fast Mode (100/400 KHz) |
| `0x04` | Fast Mode Plus (up to 1 MHz) |

### Wire-Level I2C Transactions

**Register write:**
```
I2C_START | slave_addr + W | reg_addr (1 byte) | data_bytes... | I2C_STOP
```

**Register read:**
```
I2C_START | slave_addr + W | reg_addr (1 byte) | I2C_STOP
I2C_START | slave_addr + R | data_bytes... | I2C_STOP
```

Or as a combined (restart) transaction:
```
I2C_START | slave_addr + W | reg_addr | I2C_RESTART | slave_addr + R | data_bytes... | I2C_STOP
```

### Timing Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| RESET_LOW_TIME | 2000 ms | Duration to hold RST pin LOW |
| STARTUP_TIME | 12000 ms | Wait after reset release (worst case) |
| PL_POLLING_INTERVAL | 1000 us | Status polling interval |
| PL_DATA_POLLING_INTERVAL | 5000 us | Data polling interval |
| PL_GUARD_TIME | 50 us | Guard time between I2C transactions |
| PL_POLLING_MAX_CNT | 200 | Max polling retries |
| PL_TRANS_TIMEOUT | 10 ms | Physical layer transaction timeout |

### Busy/Sleep Handling

The chip NACKs I2C addresses when asleep. Implementation must:
1. Retry I2C address probes up to 10 times with 500 us delays
2. Poll I2C_STATE register for Response Ready bit (`0x40`)
3. Respect guard time (50 us) between operations

---

## 2. Data Link Layer

### Frame Format

```
Byte 0:     FCTR  (Frame Control, 1 byte)
Byte 1-2:   FLEN  (Frame Length, 2 bytes big-endian -- length of payload + CRC)
Byte 3..N:  Payload (variable length)
Last 2:     CRC-16 (2 bytes big-endian)
```

**Header size: 5 bytes** (1 FCTR + 2 FLEN + 2 CRC).

**Maximum frame size: 277 bytes** (configurable, minimum 16 bytes). Negotiated via DATA_REG_LEN register.

**Maximum payload per frame:** `frame_size - 5` = 272 bytes (default).

### FCTR (Frame Control) Byte

```
Bit 7     : FTYPE     (0 = Data frame, 1 = Control frame)
Bits 6-5  : SEQCTR    (Sequence Control)
Bit 4     : Reserved
Bits 3-2  : FRNR      (Frame Number -- transmit sequence, 0-3)
Bits 1-0  : ACKNR     (Acknowledge Number -- expected next rx frame)
```

**SEQCTR values (for control frames, FTYPE=1):**

| Value | Meaning |
|-------|---------|
| `0b00` | ACK |
| `0b01` | NACK (request retransmission) |
| `0b10` | ReSynch (reset sequence counters) |
| `0b11` | Reserved |

**Control frame format (fixed 5 bytes):**
```
[FCTR | 0x80] [0x00] [0x00] [CRC-16 high] [CRC-16 low]
```

### Sequence Numbers

- 2-bit counters (0--3), wrap modulo 4
- Sender increments `tx_seq_nr` on each new data frame
- Receiver validates: `frame_number == (rx_seq_nr + 1) & 0x03`
- On mismatch: send NACK control frame
- After 3 failed retries (`DL_TRANS_REPEAT = 3`): send ReSynch (resets both sides to `0x03`)

### CRC-16 Algorithm

Infineon's custom nibble-based CRC (NOT standard CRC-16/CCITT):

```rust
fn ifx_i2c_crc16(data: &[u8]) -> u16 {
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
```

Compute over all frame bytes **except** the 2-byte CRC field itself. Initial seed = 0.

### Data Link Layer State Machine

```
                    +----> TX_DATA_FRAME
                    |           |
                    |     (write to DATA reg)
                    |           |
IDLE --------> SEND_DATA       v
                    |     WAIT_FOR_ACK
                    |           |
                    |     (poll I2C_STATE)
                    |           |
                    |     ACK received? --yes--> DONE
                    |           |
                    |     NACK? --retransmit--> TX_DATA_FRAME (up to 3x)
                    |
                    +----> RECV_DATA
                              |
                        (poll I2C_STATE until Response Ready)
                              |
                        (read from DATA reg)
                              |
                        (validate CRC, send ACK/NACK)
                              |
                            DONE
```

---

## 3. Transport Layer

### PCTR (Protocol Control Transport Record) Byte

1-byte header prepended to each data link payload:

```
Bits 7-3 : Channel (mask 0xF8) -- typically 0x00
Bits 2-0 : Chaining indicator
```

### Chaining Indicators

| Value | Meaning |
|-------|---------|
| `0x00` | No chaining (single packet, fits in one frame) |
| `0x01` | First fragment of multi-part message |
| `0x02` | Intermediate fragment |
| `0x04` | Last fragment |
| `0x07` | Error |

### Fragmentation

Maximum application data per frame: `frame_size - DL_HEADER(5) - TL_HEADER(1)` = `frame_size - 6`.

With default 277-byte frame: **271 bytes** of application data per fragment.

**Sending a large message:**
1. Split into chunks of max `frame_size - 6` bytes
2. First chunk: PCTR = `0x01`, send as data link frame, wait for ACK
3. Middle chunks: PCTR = `0x02`, send, wait for ACK
4. Last chunk: PCTR = `0x04`, send, wait for ACK

**Receiving a large response:**
1. Read frame, check PCTR chaining indicator
2. If `0x01`: start assembling, send ACK, continue reading
3. If `0x02`: append to buffer, send ACK, continue
4. If `0x04`: append final fragment, assembly complete
5. If `0x00`: single-frame response, done

### Transport Layer Timeout

`TL_MAX_EXIT_TIMEOUT = 180 seconds` -- maximum time to wait for a complete multi-frame transfer.

---

## 4. Complete Transaction Flow (Synchronous)

A blocking driver can follow this simplified flow:

```
1. BUILD COMMAND
   - Construct APDU (see commands-and-oids.md)
   - Prepend PCTR byte (0x00 for single frame, or chaining)
   - If Shielded Connection active: encrypt at presentation layer

2. SEND FRAME(S)
   For each fragment:
   a. Build DL frame: FCTR + FLEN + payload + CRC-16
   b. Write frame to DATA register (0x80)
   c. Poll I2C_STATE (0x82) until response ready (bit 6)
   d. Read ACK control frame from DATA register
   e. Verify ACK (SEQCTR=0, ACKNR matches our FRNR)
   f. On NACK: retransmit (up to 3 times)

3. RECEIVE RESPONSE
   a. Poll I2C_STATE (0x82) until response ready (bit 6)
   b. Read response frame from DATA register (0x80)
   c. Validate CRC-16
   d. Send ACK control frame
   e. Check PCTR chaining: if fragmented, repeat until last fragment
   f. If Shielded Connection active: decrypt at presentation layer

4. PARSE RESPONSE
   - Check status byte (0x00 = success)
   - Extract TLV-encoded result data
```

### Pseudocode: Single Command/Response

```rust
fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
    // 1. Wrap in transport layer
    let mut tl_packet = vec![0x00u8]; // PCTR: no chaining
    tl_packet.extend_from_slice(apdu);

    // 2. Build data link frame
    let payload_len = tl_packet.len() + 2; // +2 for CRC
    let mut frame = Vec::new();
    let fctr = (self.tx_seq << 2) | self.rx_seq; // Data frame
    frame.push(fctr);
    frame.push((payload_len >> 8) as u8);
    frame.push(payload_len as u8);
    frame.extend_from_slice(&tl_packet);
    let crc = ifx_i2c_crc16(&frame);
    frame.push((crc >> 8) as u8);
    frame.push(crc as u8);

    // 3. Write to DATA register
    self.i2c_write_register(0x80, &frame)?;

    // 4. Poll for ACK
    self.poll_response_ready()?;
    let ack = self.i2c_read_register(0x80, 5)?;
    // verify ACK...

    // 5. Poll for response data
    self.poll_response_ready()?;
    let state = self.i2c_read_register(0x82, 4)?;
    let resp_len = ((state[2] as usize) << 8) | state[3] as usize;
    let resp_frame = self.i2c_read_register(0x80, resp_len)?;

    // 6. Validate CRC, send ACK, extract payload
    // ...

    Ok(response_apdu)
}
```

---

## 5. Initialization Sequence

```
1. HARDWARE RESET
   - Drive RST pin LOW
   - Wait 2000 ms (RESET_LOW_TIME)
   - Drive RST pin HIGH
   - Wait 12000 ms (STARTUP_TIME)
   [NOTE: Community reports 15ms may suffice for warm resets]

2. NEGOTIATE I2C PARAMETERS
   - Read MAX_SCL_FREQU register (0x84): get max supported frequency
   - If FM+ supported and desired: write I2C_MODE (0x89) = 0x04
   - Read/set DATA_REG_LEN register (0x81): agree on frame size

3. DATA LINK INIT
   - Reset sequence counters to 0
   - Send ReSynch control frame to synchronize with chip

4. OPEN APPLICATION
   - Send OpenApplication APDU (CMD 0x70)
   - AID: D2 76 00 00 04 47 65 6E 41 75 74 68 41 70 70 6C
   - Wait for success response

5. (OPTIONAL) SHIELDED CONNECTION
   - Perform 4-step handshake (see shielded-connection.md)

6. READY FOR COMMANDS
```

### Soft Reset Alternative

Write `0x0000` to register `0x88` (SOFT_RESET). No GPIO manipulation needed.

---

## 6. Error Handling

### I2C-Level Errors

| Condition | Action |
|-----------|--------|
| NACK on address | Chip is sleeping. Retry up to 10x with 500 us delay |
| CRC mismatch | Send NACK, request retransmission |
| Timeout (no Response Ready) | Check PL_POLLING_MAX_CNT (200 attempts) |
| 3 consecutive NACKs | Send ReSynch, reset sequence counters |

### Protocol Status Codes

| Code | Meaning |
|------|---------|
| `0x0000` | Success |
| `0x0001` | Stack busy |
| `0x0102` | Stack error |
| `0x0104` | Memory error |
| `0x0106` | Fatal error |
| `0x0107` | Handshake error (shielded connection) |
| `0x0108` | Session error |

### Application-Level Errors

Read OID `0xF1C2` for the last error code after a command fails (response status != `0x00`).
