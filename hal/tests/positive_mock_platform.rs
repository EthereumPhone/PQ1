//! Mock `Platform` implementation — proves the aggregate trait surface
//! is self-consistent and that a single struct can satisfy all
//! per-peripheral trait bounds. If a future change renames or
//! re-shapes a trait method, this file fails to compile, citing the
//! trait it broke.
//!
//! This is a positive test: the mock implements every documented
//! method, the test calls each, and asserts a sensible value comes
//! back. Negative behaviour (e.g. `KeySelector` is not `Debug`) lives
//! in `tests/negative_invariants.rs`.

use pqsigner_hal::{
    BootStage, BootState, BootStateData, Buttons, Buttonset, ConsumptionMask, Flash, HalError,
    I2cBus, KeySelector, Otp, OtpRange, Platform, Rng, Saes, Sha256, SpiBus, Tamp, TamperCause,
    Uart,
};

// ---------------------------------------------------------------------------
// Mock peripherals
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockRng {
    fill_calls: u32,
    fail: bool,
}
impl Rng for MockRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), HalError> {
        self.fill_calls += 1;
        if self.fail {
            return Err(HalError::Timeout);
        }
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        Ok(())
    }
}

#[derive(Default)]
struct MockSha {
    bytes_in: u64,
    finalised: bool,
}
impl Sha256 for MockSha {
    fn init(&mut self) {
        self.bytes_in = 0;
        self.finalised = false;
    }
    fn update(&mut self, data: &[u8]) {
        self.bytes_in += data.len() as u64;
    }
    fn finalize(&mut self) -> [u8; 32] {
        self.finalised = true;
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&self.bytes_in.to_be_bytes());
        out
    }
}

#[derive(Default)]
struct MockSaes {
    ecb_calls: u32,
    cmac_calls: u32,
}
impl Saes for MockSaes {
    fn aes256_ecb(
        &mut self,
        sel: KeySelector<'_>,
        in_block: &[u8; 16],
        out_block: &mut [u8; 16],
    ) -> Result<(), HalError> {
        self.ecb_calls += 1;
        // Use sel without leaking secret bytes.
        let tag = match sel {
            KeySelector::Software(_) => 1u8,
            KeySelector::Dhuk => 2,
            KeySelector::Bhk => 3,
            KeySelector::DhukXorBhk => 4,
        };
        for (i, o) in out_block.iter_mut().enumerate() {
            *o = in_block[i] ^ tag;
        }
        Ok(())
    }
    fn cmac_dhuk(&mut self, msg: &[u8], out_tag: &mut [u8; 16]) -> Result<(), HalError> {
        self.cmac_calls += 1;
        for (i, o) in out_tag.iter_mut().enumerate() {
            *o = msg.get(i).copied().unwrap_or(0) ^ 0x5A;
        }
        Ok(())
    }
}

#[derive(Default)]
struct MockFlash {
    pages: std::collections::BTreeMap<u16, Vec<u8>>,
    last_err: Option<HalError>,
}
impl Flash for MockFlash {
    fn read(&self, page: u16, offset: u16, buf: &mut [u8]) {
        if let Some(p) = self.pages.get(&page) {
            let o = offset as usize;
            for (i, b) in buf.iter_mut().enumerate() {
                *b = *p.get(o + i).unwrap_or(&0xFF);
            }
        } else {
            buf.fill(0xFF);
        }
    }
    fn program(&mut self, page: u16, offset: u16, data: &[u8]) -> Result<(), HalError> {
        let entry = self.pages.entry(page).or_insert_with(|| vec![0xFF; 8192]);
        let o = offset as usize;
        if o.saturating_add(data.len()) > entry.len() {
            self.last_err = Some(HalError::BadParam);
            return Err(HalError::BadParam);
        }
        for (i, &b) in data.iter().enumerate() {
            entry[o + i] &= b; // STM32U5 program-to-zero semantics.
        }
        Ok(())
    }
    fn erase_page(&mut self, page: u16) -> Result<(), HalError> {
        self.pages.insert(page, vec![0xFF; 8192]);
        Ok(())
    }
}

#[derive(Default)]
struct MockOtp {
    burnt: std::collections::BTreeMap<u8, Vec<u8>>,
}
impl Otp for MockOtp {
    fn read(&self, range: OtpRange, buf: &mut [u8]) {
        let key = otp_key(range);
        if let Some(v) = self.burnt.get(&key) {
            let n = buf.len().min(v.len());
            buf[..n].copy_from_slice(&v[..n]);
            for b in buf.iter_mut().skip(n) {
                *b = 0xFF;
            }
        } else {
            buf.fill(0xFF);
        }
    }
    fn burn_once(&mut self, range: OtpRange, data: &[u8]) -> Result<(), HalError> {
        let key = otp_key(range);
        if let Some(existing) = self.burnt.get(&key) {
            if existing.as_slice() == data {
                return Ok(()); // Idempotent re-burn of identical bits is fine.
            }
            return Err(HalError::Unsupported);
        }
        self.burnt.insert(key, data.to_vec());
        Ok(())
    }
}
fn otp_key(r: OtpRange) -> u8 {
    match r {
        OtpRange::AntiRollback => 0,
        OtpRange::MasterKey => 1,
        OtpRange::BhkProvisioned => 2,
        OtpRange::Reserved(n) => 0x80 | n,
    }
}

#[derive(Default)]
struct MockBootState {
    cur: BootStateData,
}
impl pqsigner_hal::BootState for MockBootState {
    fn read(&self) -> BootStateData {
        self.cur
    }
    fn write(&mut self, data: BootStateData) {
        self.cur = data;
    }
}

#[derive(Default)]
struct MockTamp {
    armed: bool,
    pending: Option<TamperCause>,
}
impl Tamp for MockTamp {
    fn arm(&mut self) {
        self.armed = true;
    }
    fn check(&mut self) -> Option<TamperCause> {
        self.pending.take()
    }
}

#[derive(Default)]
struct MockMask {
    randomized_calls: u32,
}
impl ConsumptionMask for MockMask {
    fn randomize(&mut self) {
        self.randomized_calls += 1;
    }
}

#[derive(Default)]
struct MockI2c {
    last_addr: u8,
}
impl I2cBus for MockI2c {
    fn xfer(&mut self, addr: u8, _w: &[u8], r: &mut [u8]) -> Result<usize, HalError> {
        self.last_addr = addr;
        let n = r.len().min(4);
        for b in r.iter_mut().take(n) {
            *b = addr;
        }
        Ok(n)
    }
}

#[derive(Default)]
struct MockSpi;
impl SpiBus for MockSpi {
    fn xfer(&mut self, w: &[u8], r: &mut [u8]) -> Result<(), HalError> {
        if w.len() != r.len() {
            return Err(HalError::BadParam);
        }
        for (rb, wb) in r.iter_mut().zip(w.iter()) {
            *rb = !*wb;
        }
        Ok(())
    }
}

#[derive(Default)]
struct MockButtons {
    next: Buttonset,
}
impl Buttons for MockButtons {
    fn poll(&mut self) -> Buttonset {
        self.next
    }
}

#[derive(Default)]
struct MockUart {
    sink: Vec<u8>,
}
impl Uart for MockUart {
    fn write(&mut self, buf: &[u8]) {
        self.sink.extend_from_slice(buf);
    }
}

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockPlatform {
    rng: MockRng,
    sha: MockSha,
    saes: MockSaes,
    flash: MockFlash,
    otp: MockOtp,
    boot_state: MockBootState,
    tamp: MockTamp,
    mask: MockMask,
    i2c: MockI2c,
    spi: MockSpi,
    buttons: MockButtons,
    uart: MockUart,
}

impl Platform for MockPlatform {
    type Rng = MockRng;
    type Sha256 = MockSha;
    type Saes = MockSaes;
    type Flash = MockFlash;
    type Otp = MockOtp;
    type BootState = MockBootState;
    type Tamp = MockTamp;
    type ConsumptionMask = MockMask;
    type I2c = MockI2c;
    type Spi = MockSpi;
    type Buttons = MockButtons;
    type Uart = MockUart;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }
    fn sha256(&mut self) -> &mut Self::Sha256 {
        &mut self.sha
    }
    fn saes(&mut self) -> &mut Self::Saes {
        &mut self.saes
    }
    fn flash(&mut self) -> &mut Self::Flash {
        &mut self.flash
    }
    fn otp(&mut self) -> &mut Self::Otp {
        &mut self.otp
    }
    fn boot_state(&mut self) -> &mut Self::BootState {
        &mut self.boot_state
    }
    fn tamp(&mut self) -> &mut Self::Tamp {
        &mut self.tamp
    }
    fn consumption_mask(&mut self) -> &mut Self::ConsumptionMask {
        &mut self.mask
    }
    fn i2c(&mut self) -> &mut Self::I2c {
        &mut self.i2c
    }
    fn spi(&mut self) -> &mut Self::Spi {
        &mut self.spi
    }
    fn buttons(&mut self) -> &mut Self::Buttons {
        &mut self.buttons
    }
    fn uart(&mut self) -> &mut Self::Uart {
        &mut self.uart
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn positive_platform_dispatches_to_all_peripherals() {
    let mut p = MockPlatform::default();

    // Rng: fill 8 bytes.
    let mut buf = [0u8; 8];
    p.rng().fill(&mut buf).expect("rng fill");
    assert_eq!(buf, [0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(p.rng.fill_calls, 1);

    // Sha256: init/update/finalize.
    p.sha256().init();
    p.sha256().update(b"hello");
    let h = p.sha256().finalize();
    assert_eq!(&h[..8], &5u64.to_be_bytes());
    assert!(p.sha.finalised);

    // Saes: ECB + CMAC with each KeySelector variant.
    for sel in [
        KeySelector::Software(&[0u8; 32]),
        KeySelector::Dhuk,
        KeySelector::Bhk,
        KeySelector::DhukXorBhk,
    ] {
        let mut out = [0u8; 16];
        p.saes().aes256_ecb(sel, &[0u8; 16], &mut out).unwrap();
    }
    assert_eq!(p.saes.ecb_calls, 4);
    let mut tag = [0u8; 16];
    p.saes().cmac_dhuk(b"abc", &mut tag).unwrap();
    assert_eq!(p.saes.cmac_calls, 1);

    // Flash: program -> read round-trip on a fresh page.
    p.flash().erase_page(123).unwrap();
    p.flash().program(123, 0, &[0x00, 0x01, 0x02, 0x03]).unwrap();
    let mut rb = [0xFFu8; 4];
    p.flash().read(123, 0, &mut rb);
    // STM32U5 program-to-zero semantics: erased 0xFF & data => data.
    assert_eq!(rb, [0x00, 0x01, 0x02, 0x03]);

    // Otp: burn_once + read.
    p.otp()
        .burn_once(OtpRange::AntiRollback, &[1, 2, 3])
        .unwrap();
    let mut buf = [0u8; 3];
    p.otp().read(OtpRange::AntiRollback, &mut buf);
    assert_eq!(buf, [1, 2, 3]);

    // BootState: write -> read round-trip.
    let s = BootStateData { raw: [0x77; 32] };
    p.boot_state().write(s);
    assert_eq!(p.boot_state().read(), s);

    // Tamp: arm + check (no pending => None).
    p.tamp().arm();
    assert_eq!(p.tamp().check(), None);
    assert!(p.tamp.armed);

    // ConsumptionMask: randomize.
    p.consumption_mask().randomize();
    assert_eq!(p.mask.randomized_calls, 1);

    // I2cBus: xfer with addr.
    let mut rbuf = [0u8; 4];
    let n = p.i2c().xfer(0x6E, &[0xAA], &mut rbuf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(rbuf, [0x6E; 4]);

    // SpiBus: full-duplex xfer (matching lengths).
    let mut r = [0u8; 4];
    p.spi().xfer(&[0x00, 0xFF, 0xAA, 0x55], &mut r).unwrap();
    assert_eq!(r, [0xFF, 0x00, 0x55, 0xAA]);

    // Buttons: poll returns the seeded state.
    p.buttons.next = Buttonset { left: true, right: false };
    assert_eq!(
        p.buttons().poll(),
        Buttonset { left: true, right: false }
    );

    // Uart: write appends.
    p.uart().write(b"PASS");
    assert_eq!(p.uart.sink.as_slice(), b"PASS");
}

#[test]
fn positive_rng_propagates_error() {
    let mut rng = MockRng { fail: true, ..Default::default() };
    let mut buf = [0u8; 4];
    assert_eq!(rng.fill(&mut buf), Err(HalError::Timeout));
}

#[test]
fn positive_otp_burn_once_idempotent_for_identical_data() {
    let mut otp = MockOtp::default();
    otp.burn_once(OtpRange::MasterKey, &[1, 2, 3, 4]).unwrap();
    otp.burn_once(OtpRange::MasterKey, &[1, 2, 3, 4]).unwrap();
}

#[test]
fn positive_spi_zero_length_xfer_ok() {
    let mut spi = MockSpi::default();
    spi.xfer(&[], &mut []).unwrap();
}

#[test]
fn positive_boot_stage_iter_through_all() {
    let mut seen = [false; 6];
    for s in BootStage::ALL {
        let idx = match s {
            BootStage::Clocks => 0,
            BootStage::TrustZone => 1,
            BootStage::Crypto => 2,
            BootStage::Buses => 3,
            BootStage::Ui => 4,
            BootStage::Se => 5,
        };
        seen[idx] = true;
    }
    assert!(seen.iter().all(|&b| b), "every BootStage variant must appear in ALL");
}
