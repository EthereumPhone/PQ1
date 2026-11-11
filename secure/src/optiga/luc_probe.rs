//! DVT 6A.13 / #122 / SE14 silicon probe (`optiga-luc-probe`, bench-only,
//! terminal): does every HMAC authorisation shape advance the usage counter
//! an AuthRef is bound to through `Execute = LUC(counter)`?
//!
//! Touches ONLY spare objects: F1D5 (throwaway AuthRef, `Execute =
//! LUC(E122)`), F1D7 (test data, `Read = Auto(F1D5)`) and the spare counter
//! E122. Never locks; every object stays at LcsO=Creation. Cleanup puts
//! E122's data back, relaxes and zeroes F1D7, and returns F1D5 to
//! `Execute = ALW` with random bytes nobody keeps.
//!
//! Two shapes are compared, each with a right and a wrong MAC, below and at
//! the counter threshold, over the shielded session and (compound shape
//! only) in plaintext with no session at all:
//!
//! - `trezor`: `GetRandom(16, session)` + `DecryptSym` over 18 bytes — the
//!   shape the firmware uses under `optiga-hw-counter`.
//! - `compound`: `GetRandom(32, session, optional data 16)` + `DecryptSym`
//!   over 66 bytes — Infineon's `hmac_verify_with_authorization_reference`
//!   example, the shape the firmware uses without `optiga-hw-counter`.
//!
//! One `[LUC] …` line per leg: counter before/after, the chip's verdict on
//! the verify, and whether F1D7 was served afterwards.

use super::apdu::{self, OptigaError};
use super::OptigaTrustM;

const AUTHREF: u16 = apdu::AC_PROBE_AUTHREF; // F1D5
const DATA: u16 = apdu::AC_PROBE_STRICT; // F1D7
const CTR: u16 = 0xE122;
const SEC_OID: u16 = 0xE0C5;
const LIMIT: u32 = 5;
const PATTERN: [u8; 32] = [0xC3; 32];

/// F1D7: Change = ALW, Read = Auto(F1D5), Execute = NEV.
const DATA_META: [u8; 13] = [
    0x20, 0x0B, 0xD0, 0x01, 0x00, 0xD1, 0x03, 0x23, 0xF1, 0xD5, 0xD3, 0x01, 0xFF,
];

type Step = (&'static str, Option<OptigaError>);

#[derive(Clone, Copy)]
enum Shape {
    Trezor,
    Compound,
    CompoundPlain,
}

impl OptigaTrustM {
    unsafe fn luc_fresh(&mut self) -> Result<(), Step> {
        self.hard_reset_and_reinit().map_err(|e| ("reset", Some(e)))?;
        self.ensure_shield().map_err(|e| ("shield", Some(e)))
    }

    unsafe fn luc_ctr(&mut self) -> Option<(u32, u32)> {
        let mut b = [0u8; 8];
        match apdu::get_data_object(&mut self.ifx, &mut self.shield, CTR, 0, 8, &mut b) {
            Ok(8) => apdu::parse_pin_ctr(&b),
            _ => None,
        }
    }

    unsafe fn luc_sec(&mut self) -> u8 {
        let mut b = [0u8; 1];
        match apdu::get_data_object(&mut self.ifx, &mut self.shield, SEC_OID, 0, 1, &mut b) {
            Ok(1) => b[0],
            _ => 0xFF,
        }
    }

    /// One authorisation attempt. Returns the chip's verdict on the verify.
    unsafe fn luc_auth(
        &mut self,
        shape: Shape,
        secret: &[u8; 32],
        correct: bool,
    ) -> Result<Result<(), OptigaError>, Step> {
        match shape {
            Shape::Trezor => {
                let mut nonce = [0u8; 16];
                apdu::get_random_auto_state(
                    &mut self.ifx, &mut self.shield, apdu::OID_SESSION, &mut nonce,
                )
                .map_err(|e| ("nonce", Some(e)))?;
                let mut mac = Self::hmac_sha256(secret, &nonce);
                if !correct {
                    mac[0] ^= 0x01;
                }
                Ok(apdu::hmac_verify_auto_state(
                    &mut self.ifx, &mut self.shield, AUTHREF, apdu::OID_SESSION, &nonce, &mac,
                ))
            }
            Shape::Compound | Shape::CompoundPlain => {
                let plain = matches!(shape, Shape::CompoundPlain);
                let mut host_nonce = [0u8; 16];
                let mut host_tag = [0u8; 16];
                crate::rng::fill(&mut host_nonce).map_err(|_| ("rng", None))?;
                crate::rng::fill(&mut host_tag).map_err(|_| ("rng", None))?;
                let mut chip_random = [0u8; 32];
                if plain {
                    apdu::plain_ac_probe(
                        &mut self.ifx,
                        apdu::AcProbePlainCmd::AuthCode { host_nonce: &host_nonce },
                        &mut chip_random,
                    )
                    .map_err(|e| ("auth-code", Some(e)))?;
                } else {
                    apdu::generate_auth_code(
                        &mut self.ifx, &mut self.shield, apdu::OID_SESSION, &host_nonce,
                        &mut chip_random,
                    )
                    .map_err(|e| ("auth-code", Some(e)))?;
                }
                let mut input = [0u8; 64];
                input[..16].copy_from_slice(&host_nonce);
                input[16..48].copy_from_slice(&chip_random);
                input[48..].copy_from_slice(&host_tag);
                let mut mac = Self::hmac_sha256(secret, &input);
                if !correct {
                    mac[0] ^= 0x01;
                }
                Ok(if plain {
                    apdu::plain_ac_probe(
                        &mut self.ifx,
                        apdu::AcProbePlainCmd::HmacVerify { input: &input, mac: &mac },
                        &mut [],
                    )
                    .map(|_| ())
                } else {
                    apdu::hmac_verify(
                        &mut self.ifx, &mut self.shield, AUTHREF, apdu::OID_SESSION, &input, &mac,
                    )
                })
            }
        }
    }

    /// One leg: fresh chip state, counter before, attempt, was the data
    /// object served, counter after.
    unsafe fn luc_leg(
        &mut self,
        name: &'static str,
        shape: Shape,
        secret: &[u8; 32],
        correct: bool,
    ) -> Result<(), Step> {
        self.luc_fresh()?;
        let before = self.luc_ctr();
        let sec0 = self.luc_sec();
        let plain = matches!(shape, Shape::CompoundPlain);
        if plain {
            // Desoldered-chip position: reset, no shielded session at all.
            self.hard_reset_and_reinit().map_err(|e| ("reset", Some(e)))?;
            if self.shield.active {
                return Err(("plain-shield-up", None));
            }
        }
        let verdict = self.luc_auth(shape, secret, correct)?;
        let mut buf = [0u8; 32];
        let read = if plain {
            apdu::plain_ac_probe(&mut self.ifx, apdu::AcProbePlainCmd::ReadStrict, &mut buf)
        } else {
            apdu::get_data_object(&mut self.ifx, &mut self.shield, DATA, 0, 32, &mut buf)
        };
        let served = matches!(read, Ok(32)) && buf == PATTERN;
        if plain {
            self.ensure_shield().map_err(|e| ("shield", Some(e)))?;
        }
        let after = self.luc_ctr();
        let sec1 = self.luc_sec();
        secure_log!(
            "[LUC] leg={} mac={} ctr_before={:?} ctr_after={:?} verify={:?} data_served={} read={:?} sec={}->{}",
            name,
            if correct { "right" } else { "wrong" },
            before,
            after,
            verdict,
            served,
            read.map(|_| ()),
            sec0,
            sec1
        );
        // Keep the chip's security event counter well below its throttle.
        if sec1 != 0xFF && sec1 > 40 {
            secure_log!("[LUC] SEC {} > 40 — waiting 60 s", sec1);
            super::settle(u32::MAX); super::settle(u32::MAX);
        }
        Ok(())
    }

    unsafe fn luc_set_ctr(&mut self, cur: u32) -> Result<(), Step> {
        self.luc_fresh()?;
        apdu::set_data_object(&mut self.ifx, &mut self.shield, CTR, &apdu::encode_pin_ctr(cur, LIMIT))
            .map_err(|e| ("ctr-write", Some(e)))
    }

    unsafe fn luc_body(&mut self, secret: &[u8; 32]) -> Result<(), Step> {
        self.init().map_err(|e| ("init", Some(e)))?;
        self.ensure_shield().map_err(|e| ("shield", Some(e)))?;

        for oid in [AUTHREF, DATA, CTR] {
            let mut m = [0u8; 128];
            let n = apdu::get_metadata(&mut self.ifx, &mut self.shield, oid, &mut m)
                .map_err(|e| ("pre-meta", Some(e)))?;
            secure_log!("[LUC] pre 0x{:04x} meta={:02x?}", oid, &m[..n.min(48)]);
            if apdu::is_metadata_operational(&m, n) {
                return Err(("spare-locked", None));
            }
        }

        // Counter first, then the AuthRef that names it, then the data object.
        self.luc_set_ctr(0)?;
        self.luc_fresh()?;
        apdu::set_data_object(&mut self.ifx, &mut self.shield, AUTHREF, secret)
            .map_err(|e| ("authref-data", Some(e)))?;
        let (m, ml) = apdu::build_metadata_auth_ref_luc_oid(CTR, false);
        apdu::set_metadata(&mut self.ifx, &mut self.shield, AUTHREF, &m[..ml])
            .map_err(|e| ("authref-meta", Some(e)))?;
        self.luc_fresh()?;
        apdu::set_data_object(&mut self.ifx, &mut self.shield, DATA, &PATTERN)
            .map_err(|e| ("data-data", Some(e)))?;
        apdu::set_metadata(&mut self.ifx, &mut self.shield, DATA, &DATA_META)
            .map_err(|e| ("data-meta", Some(e)))?;
        self.luc_fresh()?;
        for oid in [AUTHREF, DATA, CTR] {
            let mut m = [0u8; 128];
            let n = apdu::get_metadata(&mut self.ifx, &mut self.shield, oid, &mut m)
                .map_err(|e| ("post-meta", Some(e)))?;
            secure_log!("[LUC] set 0x{:04x} meta={:02x?}", oid, &m[..n.min(48)]);
        }

        match option_env!("LUC_MODE") {
            Some("2") => return self.luc_persistence(secret),
            Some("3") => return self.luc_powercut(secret),
            Some("4") => return self.luc_powercut2(secret),
            Some("5") => return self.luc_powercut3(secret),
            _ => {}
        }

        // Below the threshold.
        self.luc_leg("below/trezor", Shape::Trezor, secret, false)?;
        self.luc_leg("below/trezor", Shape::Trezor, secret, true)?;
        self.luc_set_ctr(0)?;
        self.luc_leg("below/compound", Shape::Compound, secret, false)?;
        self.luc_leg("below/compound", Shape::Compound, secret, true)?;
        self.luc_set_ctr(0)?;
        self.luc_leg("below/compound-plain", Shape::CompoundPlain, secret, false)?;
        self.luc_leg("below/compound-plain", Shape::CompoundPlain, secret, true)?;

        // At the threshold: counter == limit.
        self.luc_set_ctr(LIMIT)?;
        self.luc_leg("at-limit/trezor", Shape::Trezor, secret, true)?;
        self.luc_leg("at-limit/compound", Shape::Compound, secret, true)?;
        self.luc_leg("at-limit/compound-plain", Shape::CompoundPlain, secret, true)?;
        self.luc_leg("at-limit/compound", Shape::Compound, secret, false)?;
        Ok(())
    }

    /// Authorise (right MAC, firmware shape) on a fresh chip and confirm the
    /// data object is served.
    unsafe fn luc_authorise(&mut self, secret: &[u8; 32]) -> Result<(), Step> {
        self.luc_fresh()?;
        self.luc_auth(Shape::Trezor, secret, true)?.map_err(|e| ("auth", Some(e)))?;
        let mut buf = [0u8; 32];
        apdu::get_data_object(&mut self.ifx, &mut self.shield, DATA, 0, 32, &mut buf)
            .map_err(|e| ("auth-read", Some(e)))?;
        Ok(())
    }

    unsafe fn luc_read_served(&mut self) -> (bool, Result<(), OptigaError>) {
        let mut buf = [0u8; 32];
        let r = apdu::get_data_object(&mut self.ifx, &mut self.shield, DATA, 0, 32, &mut buf);
        (matches!(r, Ok(32)) && buf == PATTERN, r.map(|_| ()))
    }

    /// DVT 6A.17: what ends the authorisation state?
    unsafe fn luc_persistence(&mut self, secret: &[u8; 32]) -> Result<(), Step> {
        self.luc_set_ctr(0)?;

        // P1: what the firmware does on LOCK / idle wipe — drop the host
        // session only — then a new handshake, as the next command would.
        self.luc_authorise(secret)?;
        self.shield.zeroize_session();
        self.ensure_shield().map_err(|e| ("p1-shield", Some(e)))?;
        secure_log!("[LUC] persist=P1 host-session-dropped+new-handshake served={:?}", self.luc_read_served());

        // P1b: a second new handshake.
        self.shield.zeroize_session();
        self.ensure_shield().map_err(|e| ("p1b-shield", Some(e)))?;
        secure_log!("[LUC] persist=P1b second-new-handshake served={:?}", self.luc_read_served());

        // P2: OpenApplication again, no reset.
        self.luc_authorise(secret)?;
        let oa = apdu::open_application(&mut self.ifx);
        self.shield.zeroize_session();
        let sh = self.ensure_shield();
        secure_log!("[LUC] persist=P2 open-application={:?} shield={:?} served={:?}", oa, sh, self.luc_read_served());

        // P3: a failed authorisation after a good one.
        self.luc_authorise(secret)?;
        let v = self.luc_auth(Shape::Trezor, secret, false)?;
        secure_log!("[LUC] persist=P3 wrong-auth-after-right verify={:?} served={:?}", v, self.luc_read_served());

        // P4: idle 30 s inside the same session.
        self.luc_authorise(secret)?;
        for _ in 0..8 {
            cortex_m::asm::delay(600_000_000);
        }
        secure_log!("[LUC] persist=P4 idle-30s served={:?}", self.luc_read_served());

        // P5: link-layer soft reset (register 0x88), then a new session.
        self.luc_authorise(secret)?;
        let sr = self.ifx.soft_reset();
        let oa = apdu::open_application(&mut self.ifx);
        self.shield.zeroize_session();
        let sh = self.ensure_shield();
        secure_log!("[LUC] persist=P5 soft-reset={:?} open={:?} shield={:?} served={:?}", sr.is_ok(), oa, sh, self.luc_read_served());

        // P6: RST pin pulse (what a cold boot or `restart_session` does).
        self.luc_authorise(secret)?;
        self.luc_fresh()?;
        secure_log!("[LUC] persist=P6 rst-pulse served={:?}", self.luc_read_served());
        Ok(())
    }

    /// DVT 6A.14: can a power cut refund a wrong attempt? Send the verify
    /// (wrong MAC), wait `d`, cut RST + the SE rail, then read the counter.
    unsafe fn luc_powercut(&mut self, secret: &[u8; 32]) -> Result<(), Step> {
        // A limit far away, so the sweep never reaches it.
        self.luc_fresh()?;
        apdu::set_data_object(&mut self.ifx, &mut self.shield, CTR, &apdu::encode_pin_ctr(0, 0x0010_0000))
            .map_err(|e| ("ctr-write", Some(e)))?;

        // DWT cycle counter for the latency of an uncut wrong verify.
        crate::ARCH.demcr.set_bits(1 << 24);
        crate::ARCH.dwt_lar.write(0xC5AC_CE55);
        crate::ARCH.dwt_cyccnt.write(0);
        crate::ARCH.dwt_ctrl.set_bits(1);
        let mut worst_us = 0u32;
        for _ in 0..3 {
            self.luc_fresh()?;
            let mut nonce = [0u8; 16];
            apdu::get_random_auto_state(&mut self.ifx, &mut self.shield, apdu::OID_SESSION, &mut nonce)
                .map_err(|e| ("nonce", Some(e)))?;
            let mut mac = Self::hmac_sha256(secret, &nonce);
            mac[0] ^= 1;
            let t0 = crate::ARCH.dwt_cyccnt.read();
            let v = apdu::hmac_verify_auto_state(
                &mut self.ifx, &mut self.shield, AUTHREF, apdu::OID_SESSION, &nonce, &mac,
            );
            let us = crate::ARCH.dwt_cyccnt.read().wrapping_sub(t0) / 160;
            secure_log!("[LUC] cut=baseline verify={:?} latency_us={} ctr={:?}", v, us, self.luc_ctr());
            worst_us = worst_us.max(us);
        }
        if worst_us == 0 || worst_us > 400_000 {
            worst_us = 60_000;
        }

        let step_us = 200u32;
        let mut d = 0u32;
        let mut expect = self.luc_ctr().map(|c| c.0).unwrap_or(0);
        let (mut cuts, mut advanced, mut not_advanced, mut odd) = (0u32, 0u32, 0u32, 0u32);
        let (mut first_adv, mut last_not) = (u32::MAX, 0u32);
        while d <= worst_us + 3_000 {
            self.luc_fresh()?;
            let mut nonce = [0u8; 16];
            apdu::get_random_auto_state(&mut self.ifx, &mut self.shield, apdu::OID_SESSION, &mut nonce)
                .map_err(|e| ("nonce", Some(e)))?;
            let mut mac = Self::hmac_sha256(secret, &nonce);
            mac[0] ^= 1;
            apdu::hmac_verify_auto_state_send_only(
                &mut self.ifx, &mut self.shield, AUTHREF, apdu::OID_SESSION, &nonce, &mac,
            )
            .map_err(|e| ("cut-send", Some(e)))?;
            if d > 0 {
                cortex_m::asm::delay(d * 160);
            }
            crate::hw::se_power::power_cycle(40);
            crate::hw::i2c_hw::init();
            self.luc_fresh()?;
            let mut raw = [0u8; 8];
            let r = apdu::get_data_object(&mut self.ifx, &mut self.shield, CTR, 0, 8, &mut raw);
            let cur = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
            cuts += 1;
            if !matches!(r, Ok(8)) || raw[4..] != [0x00, 0x10, 0x00, 0x00] || (cur != expect && cur != expect + 1) {
                odd += 1;
                secure_log!("[LUC] cut=ODD d_us={} read={:?} raw={:02x?} expected={}", d, r, raw, expect);
                if let Ok(8) = r {
                    expect = cur;
                }
            } else if cur == expect + 1 {
                advanced += 1;
                first_adv = first_adv.min(d);
                expect = cur;
            } else {
                not_advanced += 1;
                last_not = last_not.max(d);
            }
            if cuts % 20 == 0 {
                secure_log!("[LUC] cut=progress d_us={} cuts={} advanced={} not={} odd={} sec={}", d, cuts, advanced, not_advanced, odd, self.luc_sec());
            }
            d += step_us;
        }
        secure_log!(
            "[LUC] cut=summary cuts={} advanced={} not_advanced={} odd={} first_advanced_d_us={} last_not_advanced_d_us={} uncut_latency_us={}",
            cuts, advanced, not_advanced, odd, first_adv, last_not, worst_us
        );
        Ok(())
    }

    /// Wait until the chip's security event counter has decayed to `max`.
    unsafe fn luc_wait_sec(&mut self, max: u8) {
        loop {
            let s = self.luc_sec();
            if s == 0xFF || s <= max {
                return;
            }
            secure_log!("[LUC] SEC={} > {} — waiting", s, max);
            for _ in 0..8 {
                cortex_m::asm::delay(600_000_000);
            }
        }
    }

    /// One wrong-MAC verify, then `how`: 0 = RST pulse only, 1 = power cut.
    /// `read_response` selects a full exchange (verdict in hand) or send-only
    /// followed by a wait of `d_us`.
    unsafe fn luc_cut_leg(
        &mut self,
        name: &'static str,
        secret: &[u8; 32],
        read_response: bool,
        d_us: u32,
        power_cut: bool,
    ) -> Result<(), Step> {
        self.luc_fresh()?;
        self.luc_wait_sec(30);
        let before = self.luc_ctr();
        let sec0 = self.luc_sec();
        let mut nonce = [0u8; 16];
        apdu::get_random_auto_state(&mut self.ifx, &mut self.shield, apdu::OID_SESSION, &mut nonce)
            .map_err(|e| ("nonce", Some(e)))?;
        let mut mac = Self::hmac_sha256(secret, &nonce);
        mac[0] ^= 1;
        let verdict = if read_response {
            Some(apdu::hmac_verify_auto_state(
                &mut self.ifx, &mut self.shield, AUTHREF, apdu::OID_SESSION, &nonce, &mac,
            ))
        } else {
            apdu::hmac_verify_auto_state_send_only(
                &mut self.ifx, &mut self.shield, AUTHREF, apdu::OID_SESSION, &nonce, &mac,
            )
            .map_err(|e| ("cut-send", Some(e)))?;
            None
        };
        if d_us > 0 {
            cortex_m::asm::delay(d_us * 160);
        }
        if power_cut {
            crate::hw::se_power::power_cycle(40);
            crate::hw::i2c_hw::init();
        }
        self.luc_fresh()?;
        let mut raw = [0u8; 8];
        let r = apdu::get_data_object(&mut self.ifx, &mut self.shield, CTR, 0, 8, &mut raw);
        secure_log!(
            "[LUC] cut2 leg={} read_response={} d_us={} power_cut={} verdict={:?} ctr_before={:?} ctr_after_raw={:02x?} ({:?}) sec={}->{}",
            name, read_response, d_us, power_cut, verdict, before, raw, r, sec0, self.luc_sec()
        );
        Ok(())
    }

    unsafe fn luc_powercut2(&mut self, secret: &[u8; 32]) -> Result<(), Step> {
        self.luc_fresh()?;
        self.luc_wait_sec(10);
        apdu::set_data_object(&mut self.ifx, &mut self.shield, CTR, &apdu::encode_pin_ctr(0, 0x0010_0000))
            .map_err(|e| ("ctr-write", Some(e)))?;
        self.luc_cut_leg("A full+rst", secret, true, 0, false)?;
        self.luc_cut_leg("B sendonly+100ms+rst", secret, false, 100_000, false)?;
        self.luc_cut_leg("C sendonly+100ms+cut", secret, false, 100_000, true)?;
        self.luc_cut_leg("D full+immediate-cut", secret, true, 0, true)?;
        self.luc_cut_leg("E full+5ms+cut", secret, true, 5_000, true)?;
        self.luc_cut_leg("F full+50ms+cut", secret, true, 50_000, true)?;
        self.luc_cut_leg("G full+500ms+cut", secret, true, 500_000, true)?;
        self.luc_cut_leg("H sendonly+15ms+cut", secret, false, 15_000, true)?;
        self.luc_cut_leg("I sendonly+30ms+cut", secret, false, 30_000, true)?;
        self.luc_cut_leg("J sendonly+0+rst", secret, false, 0, false)?;
        self.luc_cut_leg("K sendonly+6ms+rst", secret, false, 6_000, false)?;
        self.luc_cut_leg("L sendonly+13ms+rst", secret, false, 13_000, false)?;
        Ok(())
    }

    /// Precise leg. `mode`: 0 = send, busy-wait `d_us` (DWT), cut;
    /// 1 = send, poll until the chip flags a response, cut at once;
    /// 2 = as 1, then read the first 12 bytes of the response frame, cut.
    /// Driver logs are muted from the send to the cut.
    unsafe fn luc_precise_leg(&mut self, secret: &[u8; 32], mode: u8, d_us: u32) -> Result<(), Step> {
        self.luc_fresh()?;
        self.luc_wait_sec(40);
        let before = self.luc_ctr();
        let mut nonce = [0u8; 16];
        apdu::get_random_auto_state(&mut self.ifx, &mut self.shield, apdu::OID_SESSION, &mut nonce)
            .map_err(|e| ("nonce", Some(e)))?;
        let mut mac = Self::hmac_sha256(secret, &nonce);
        mac[0] ^= 1;
        crate::LOG_MUTED.store(true, core::sync::atomic::Ordering::Relaxed);
        let t0 = crate::ARCH.dwt_cyccnt.read();
        let sent = apdu::hmac_verify_auto_state_send_only(
            &mut self.ifx, &mut self.shield, AUTHREF, apdu::OID_SESSION, &nonce, &mac,
        );
        let t_sent = crate::ARCH.dwt_cyccnt.read().wrapping_sub(t0) / 160;
        let mut state = [0u8; 4];
        let mut prefix = [0u8; 12];
        let mut polled = Ok(());
        if sent.is_ok() {
            match mode {
                0 => {
                    while crate::ARCH.dwt_cyccnt.read().wrapping_sub(t0) / 160 < d_us {}
                }
                _ => {
                    match self.ifx.probe_poll_ready() {
                        Ok(st) => state = st,
                        Err(_) => polled = Err(()),
                    }
                    if mode == 2 && polled.is_ok() {
                        let _ = self.ifx.probe_read_data_prefix(&mut prefix);
                    }
                    // Modes 3/4: the first pending frame is the 5-byte
                    // link ACK. Drain it, then wait for the data frame.
                    if mode >= 3 && polled.is_ok() {
                        let mut ack = [0u8; 5];
                        let _ = self.ifx.probe_read_data_prefix(&mut ack);
                        prefix[..5].copy_from_slice(&ack);
                        match self.ifx.probe_poll_ready() {
                            Ok(st) => state = st,
                            Err(_) => polled = Err(()),
                        }
                        if mode == 4 && polled.is_ok() {
                            let mut head = [0u8; 7];
                            let _ = self.ifx.probe_read_data_prefix(&mut head);
                            prefix[5..].copy_from_slice(&head);
                        }
                    }
                }
            }
        }
        let t_cut = crate::ARCH.dwt_cyccnt.read().wrapping_sub(t0) / 160;
        crate::hw::se_power::power_cycle(40);
        crate::LOG_MUTED.store(false, core::sync::atomic::Ordering::Relaxed);
        crate::hw::i2c_hw::init();
        sent.map_err(|e| ("cut-send", Some(e)))?;
        self.luc_fresh()?;
        let after = self.luc_ctr();
        secure_log!(
            "[LUC] cut3 mode={} t_sent_us={} t_cut_us={} polled_ok={} state={:02x?} prefix={:02x?} ctr_before={:?} ctr_after={:?} sec={}",
            mode, t_sent, t_cut, polled.is_ok(), state, prefix, before, after, self.luc_sec()
        );
        Ok(())
    }

    unsafe fn luc_powercut3(&mut self, secret: &[u8; 32]) -> Result<(), Step> {
        self.luc_fresh()?;
        self.luc_wait_sec(10);
        apdu::set_data_object(&mut self.ifx, &mut self.shield, CTR, &apdu::encode_pin_ctr(0, 0x0010_0000))
            .map_err(|e| ("ctr-write", Some(e)))?;
        crate::ARCH.demcr.set_bits(1 << 24);
        crate::ARCH.dwt_lar.write(0xC5AC_CE55);
        crate::ARCH.dwt_cyccnt.write(0);
        crate::ARCH.dwt_ctrl.set_bits(1);
        for _ in 0..3 {
            self.luc_precise_leg(secret, 1, 0)?;
        }
        for m in [2u8, 3, 3, 3, 4, 4, 4] {
            self.luc_precise_leg(secret, m, 0)?;
        }
        for d in [2_000u32, 4_000, 6_000, 7_000, 8_000, 9_000, 10_000, 11_000, 12_000, 13_000, 14_000, 16_000, 20_000] {
            self.luc_precise_leg(secret, 0, d)?;
        }
        Ok(())
    }

    unsafe fn luc_cleanup(&mut self, ctr_orig: Option<[u8; 8]>) -> Result<(), Step> {
        self.luc_fresh()?;
        let (m, ml) = apdu::build_metadata_auth_ref();
        apdu::set_metadata(&mut self.ifx, &mut self.shield, AUTHREF, &m[..ml])
            .map_err(|e| ("cleanup-authref-meta", Some(e)))?;
        let mut junk = [0u8; 32];
        crate::rng::fill(&mut junk).map_err(|_| ("rng", None))?;
        apdu::set_data_object(&mut self.ifx, &mut self.shield, AUTHREF, &junk)
            .map_err(|e| ("cleanup-authref", Some(e)))?;
        self.luc_fresh()?;
        let (r, rl) = apdu::build_metadata_relaxed();
        apdu::set_metadata(&mut self.ifx, &mut self.shield, DATA, &r[..rl])
            .map_err(|e| ("cleanup-data-meta", Some(e)))?;
        apdu::set_data_object(&mut self.ifx, &mut self.shield, DATA, &[0u8; 32])
            .map_err(|e| ("cleanup-data", Some(e)))?;
        self.luc_fresh()?;
        if let Some(orig) = ctr_orig {
            apdu::set_data_object(&mut self.ifx, &mut self.shield, CTR, &orig)
                .map_err(|e| ("cleanup-ctr", Some(e)))?;
        }
        for oid in [AUTHREF, DATA, CTR] {
            let mut m = [0u8; 128];
            let n = apdu::get_metadata(&mut self.ifx, &mut self.shield, oid, &mut m)
                .map_err(|e| ("end-meta", Some(e)))?;
            secure_log!("[LUC] end 0x{:04x} meta={:02x?}", oid, &m[..n.min(48)]);
        }
        secure_log!("[LUC] end ctr={:?}", self.luc_ctr());
        Ok(())
    }

    /// The real wallet objects: unlock through the production entry point
    /// with the bench wallet's PIN, do what LOCK does to the OPTIGA (drop the
    /// host session), open a new session and try to read F1D1 / F1D2 and to
    /// rewrite the E120 counter — with no PIN.
    pub(crate) unsafe fn luc_real_after_lock(&mut self) {
        use crate::pin_credential::WalletRole;
        use crate::secure_element::WalletStore;
        secure_log!("[LUC] real: E120 before={:?}", { let _ = self.init(); let _ = self.ensure_shield(); self.read_hw_pin_counter() });
        let creds = match crate::pin_gate::unlock_credentials(WalletRole::Real, b"00000000") {
            Ok(c) => c,
            Err(e) => {
                secure_log!("[LUC] real: no credentials ({:?})", e);
                return;
            }
        };
        let r = self.unlock_with_credential(&creds.optiga);
        secure_log!("[LUC] real: unlock_with_credential ok={}", r.is_ok());
        if let Ok(mut m) = r {
            use zeroize::Zeroize;
            m.zeroize();
        }
        // What `zeroize_caches` (LOCK, idle wipe) does on the OPTIGA side.
        self.zeroize_caches();
        let sh = self.ensure_shield();
        let mut buf = [0u8; 32];
        let r1 = apdu::get_data_object(&mut self.ifx, &mut self.shield, apdu::OID_ENTROPY, 0, 32, &mut buf);
        let r2 = apdu::get_data_object(&mut self.ifx, &mut self.shield, apdu::OID_MASTER_SECRET, 0, 32, &mut buf);
        let ctr = apdu::encode_pin_ctr(0, Self::HW_PIN_CTR_LIMIT);
        let r3 = apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_PIN_CTR, &ctr);
        {
            use zeroize::Zeroize;
            buf.zeroize();
        }
        secure_log!(
            "[LUC] real: after LOCK + new session (no PIN): shield={:?} read_F1D1={:?} read_F1D2={:?} rewrite_E120={:?} E120={:?}",
            sh, r1.map(|_| "SERVED"), r2.map(|_| "SERVED"), r3.map(|_| "ACCEPTED"), self.read_hw_pin_counter()
        );
        secure_log!("=== LUC DONE ===");
    }

    /// Run the probe; logs only.
    ///
    /// # Safety
    /// Drives the OPTIGA APDU stack; caller holds `&mut self`.
    pub(crate) unsafe fn luc_probe(&mut self) {
        secure_log!("[LUC] start (spares F1D5/F1D7/E122 only)");
        let mut ctr_orig = None;
        if self.init().is_ok() && self.ensure_shield().is_ok() {
            let mut b = [0u8; 8];
            if let Ok(8) = apdu::get_data_object(&mut self.ifx, &mut self.shield, CTR, 0, 8, &mut b) {
                secure_log!("[LUC] E122 data at start={:02x?} (factory value is all zero; cleanup restores that)", b);
                ctr_orig = Some([0u8; 8]);
            }
        }
        let mut secret = [0u8; 32];
        if ctr_orig.is_none() || crate::rng::fill(&mut secret).is_err() {
            secure_log!("[LUC] ABORT before any write (counter unreadable or rng)");
            secure_log!("=== LUC DONE ABORT ===");
            return;
        }
        let r = self.luc_body(&secret);
        secure_log!("[LUC] body result: {:?}", r);
        let c = self.luc_cleanup(ctr_orig);
        secure_log!("[LUC] cleanup result: {:?}", c);
        secure_log!("=== LUC DONE ===");
    }
}
