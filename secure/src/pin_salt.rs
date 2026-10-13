//! Persistent store for the PIN-credential salt (issue #855) — pure logic.
//!
//! `pin_credential` derives everything the secure elements see from
//! `PRF(device_key, label || salt || PIN)`. This module owns the salt: 32
//! random bytes written once at provisioning and **destroyed first on every
//! wipe**.
//!
//! ## Why destroying it first matters
//!
//! An attacker who has read one chip holds that chip's stored credential.
//! They cannot search the PIN offline (no device key), but they can emulate
//! the chip and let the genuine device compute `PRF(.., guess)` for each PIN
//! typed in, comparing against the value they hold. The page-124 counter
//! allows ten such guesses and then the device wipes. Without a salt the
//! credential would be the same after the wipe, so every wipe would buy ten
//! more guesses. With the salt destroyed before anything else, the value the
//! attacker holds can never be recomputed by this device again: ten guesses
//! in total. The page-124 counter may therefore be reset only once
//! [`destroy`] has succeeded.
//!
//! ## Layout
//!
//! The salt lives in a log inside secure-flash page 125 (the admin / wipe /
//! duress state page), after the three flag quad-words. A record is three
//! 16-byte quad-words:
//!
//! ```text
//! QW n     salt[ 0..16]
//! QW n+1   salt[16..32]
//! QW n+2   header: "PQPS" | version | 7 zero bytes | CRC-32 of the salt (LE)
//! ```
//!
//! The header is written last, so a record is either complete or invalid.
//! The log is append-only between page erases:
//!
//! - **Create** appends one record after the last non-blank quad-word. It
//!   never erases the page, so the duress-mode flag the wizard programs
//!   before provisioning is untouched.
//! - **Every provisioning gets a new salt.** If a record is already there
//!   when provisioning starts, it is destroyed in place and a fresh one is
//!   appended; it is never reused. Reuse would let an attacker who emulates
//!   both chips provision a throwaway wallet with a PIN they know under the
//!   victim's salt, unlock it to reset the page-124 counter, and keep
//!   guessing the victim's PIN ten at a time.
//! - **Destroy** programs zeros over the log: first the leading data
//!   quad-word of every valid record (which invalidates it), then every
//!   other programmed quad-word, so nothing of the salt is left even when an
//!   earlier destroy was cut short by a power loss. The reference manual
//!   allows programming all zeros over a programmed quad-word (RM0456 Rev 7
//!   section 7.3.7); that has not been exercised on this project's silicon,
//!   so at wipe time a failed overwrite falls back to erasing the whole
//!   page.
//! - The page erase that ends a completed wipe (`erase_admin_page`) returns
//!   the log to blank.
//!
//! At most one valid record exists at a time: create refuses while one is
//! present. Two valid records are reported as [`SaltState::Ambiguous`] and
//! treated as "no usable salt".
//!
//! Everything here is arithmetic over quad-words behind the [`SaltFlash`]
//! trait, so the whole lifecycle — including torn writes and the erase
//! fallback — runs in host tests. `hw::flash` supplies the real page.

// Only the OPTIGA / SE050 backends consume this; QEMU / mock-SE builds have
// neither.
#![allow(dead_code)]

use crate::pin_credential::{PinSalt, SALT_LEN};
use fw_manifest::crc32_ieee;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Bytes per flash quad-word.
pub const QW: usize = 16;
/// Quad-words in one salt record.
pub const RECORD_QWS: usize = 3;

/// Header magic — "PQ PIN Salt".
const MAGIC: [u8; 4] = *b"PQPS";
/// Record format version.
const VERSION: u8 = 1;

const BLANK_QW: [u8; QW] = [0xFF; QW];
const ZERO_QW: [u8; QW] = [0x00; QW];

/// The flash region that holds the salt log.
///
/// Implemented for the real page by `hw::flash`, and by an in-memory model
/// in the tests below.
pub trait SaltFlash {
    /// Number of quad-words in the region.
    fn qw_count(&self) -> usize;
    /// Read quad-word `index`.
    fn read_qw(&self, index: usize) -> [u8; QW];
    /// Program a **blank** quad-word and read it back.
    fn program_qw(&mut self, index: usize, data: &[u8; QW]) -> Result<(), ()>;
    /// Program all zeros over quad-word `index`, whatever it holds, and read
    /// it back.
    fn zero_qw(&mut self, index: usize) -> Result<(), ()>;
    /// Last resort when [`zero_qw`](Self::zero_qw) fails: erase the whole
    /// page, then put the wipe-in-progress marker back so an interrupted
    /// wipe still resumes at the next boot.
    fn erase_region(&mut self) -> Result<(), ()>;
}

/// What the log currently holds.
pub enum SaltState {
    /// No valid record: never provisioned, wiped, or torn.
    Absent,
    /// Exactly one valid record.
    Present(PinSalt),
    /// More than one valid record. Cannot happen through this module; it is
    /// reported so the caller fails closed instead of picking one.
    Ambiguous,
}

impl SaltState {
    /// `true` only for [`SaltState::Absent`].
    #[must_use]
    pub fn is_absent(&self) -> bool {
        matches!(self, SaltState::Absent)
    }
}

/// Result of one pass over the log.
pub struct Scan {
    /// The salt, if exactly one valid record exists.
    pub state: SaltState,
    /// Number of valid records found.
    pub valid_records: usize,
    /// Quad-word index of the first valid record's first data quad-word.
    pub first_valid_at: Option<usize>,
    /// Index one past the last non-blank quad-word: where the next record
    /// would be appended.
    pub frontier: usize,
    /// Quad-words scanned.
    pub capacity: usize,
}

/// Build the three quad-words of a record for `salt`.
#[must_use]
pub fn encode(salt: &PinSalt) -> [[u8; QW]; RECORD_QWS] {
    let s = salt.as_bytes();
    let mut rec = [[0u8; QW]; RECORD_QWS];
    rec[0].copy_from_slice(&s[..QW]);
    rec[1].copy_from_slice(&s[QW..]);
    rec[2][..4].copy_from_slice(&MAGIC);
    rec[2][4] = VERSION;
    // bytes 5..12 stay zero
    rec[2][12..].copy_from_slice(&crc32_ieee(s).to_le_bytes());
    rec
}

/// If `hdr` is a valid header for the two data quad-words before it, return
/// the salt they hold.
fn decode(data_a: &[u8; QW], data_b: &[u8; QW], hdr: &[u8; QW]) -> Option<PinSalt> {
    if hdr[..4] != MAGIC || hdr[4] != VERSION || hdr[5..12] != [0u8; 7] {
        return None;
    }
    let mut bytes = [0u8; SALT_LEN];
    bytes[..QW].copy_from_slice(data_a);
    bytes[QW..].copy_from_slice(data_b);
    let crc_ok = crc32_ieee(&bytes).to_le_bytes() == hdr[12..];
    if !crc_ok {
        bytes.zeroize();
        return None;
    }
    // `PinSalt::new` rejects a half that reads as erased or destroyed flash,
    // and wipes `bytes` when it does.
    PinSalt::new(bytes)
}

/// Scan the whole log.
#[must_use]
pub fn scan<F: SaltFlash + ?Sized>(flash: &F) -> Scan {
    let capacity = flash.qw_count();
    let mut prev2 = BLANK_QW;
    let mut prev1 = BLANK_QW;
    let mut valid_records = 0usize;
    let mut first_valid_at = None;
    let mut found: Option<PinSalt> = None;
    let mut frontier = 0usize;

    for index in 0..capacity {
        let qw = flash.read_qw(index);
        if qw != BLANK_QW {
            frontier = index + 1;
        }
        if index >= 2 {
            if let Some(salt) = decode(&prev2, &prev1, &qw) {
                valid_records += 1;
                if first_valid_at.is_none() {
                    first_valid_at = Some(index - 2);
                }
                found = Some(salt);
            }
        }
        prev2 = prev1;
        prev1 = qw;
    }
    prev2.zeroize();
    prev1.zeroize();

    let state = match (valid_records, found) {
        (0, _) => SaltState::Absent,
        (1, Some(salt)) => SaltState::Present(salt),
        _ => SaltState::Ambiguous,
    };
    Scan { state, valid_records, first_valid_at, frontier, capacity }
}

/// Read the current salt.
#[must_use]
pub fn load<F: SaltFlash + ?Sized>(flash: &F) -> SaltState {
    scan(flash).state
}

/// `true` when no valid salt record exists.
///
/// This is the condition the page-124 reset is gated on after a wipe.
#[must_use]
pub fn is_absent<F: SaltFlash + ?Sized>(flash: &F) -> bool {
    scan(flash).valid_records == 0
}

/// Why [`create`] refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CreateError {
    /// A valid record already exists (or the log is ambiguous). Destroy it
    /// first; a salt is never replaced in place.
    AlreadyPresent,
    /// No room for another record until the page is erased by a completed
    /// wipe.
    Full,
    /// Programming a quad-word failed.
    Flash,
    /// The record was programmed but did not read back as this salt.
    Verify,
}

/// Append a record for `salt`. The log must hold no valid record.
///
/// # Errors
/// See [`CreateError`]. On `Flash` or `Verify` the partial record is left in
/// place; it is invalid (the header is written last) and is skipped by later
/// scans.
pub fn create<F: SaltFlash + ?Sized>(flash: &mut F, salt: &PinSalt) -> Result<(), CreateError> {
    let before = scan(flash);
    if before.valid_records != 0 {
        return Err(CreateError::AlreadyPresent);
    }
    let end = before.frontier.checked_add(RECORD_QWS).ok_or(CreateError::Full)?;
    if end > before.capacity {
        return Err(CreateError::Full);
    }

    let mut record = encode(salt);
    let mut result = Ok(());
    for (k, qw) in record.iter().enumerate() {
        if flash.program_qw(before.frontier + k, qw).is_err() {
            result = Err(CreateError::Flash);
            break;
        }
    }
    for qw in &mut record {
        qw.zeroize();
    }
    result?;

    match scan(flash).state {
        SaltState::Present(stored)
            if bool::from(stored.as_bytes().ct_eq(salt.as_bytes())) =>
        {
            Ok(())
        }
        _ => Err(CreateError::Verify),
    }
}

/// The salt could not be destroyed. The caller must treat the wipe as not
/// done and must not reset the page-124 attempt counter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DestroyFailed;

/// Destroy the salt by overwriting the log in place, with no page erase.
/// Idempotent: an already-clean log is `Ok`.
///
/// Two phases, both safe to repeat after a power loss at any point:
///
/// 1. **Invalidate.** Zero the first data quad-word of every valid record.
///    One completed program removes half the salt and breaks the header's
///    CRC, so from then on no salt is ever loaded again.
/// 2. **Sweep.** Zero every quad-word of the log that is neither blank nor
///    already zero. This removes the rest of the record, and also whatever
///    an interrupted earlier destroy or create left behind — remains that
///    no longer parse as a record and that phase 1 therefore cannot see.
///
/// This is the variant provisioning uses to retire a salt it must not
/// reuse. It never erases the page, so it can neither clear the duress-mode
/// flag nor arm the wipe flag.
///
/// # Errors
/// [`DestroyFailed`] when an overwrite did not take, a valid record
/// survives, or a programmed quad-word is left non-zero.
pub fn destroy_in_place<F: SaltFlash + ?Sized>(flash: &mut F) -> Result<(), DestroyFailed> {
    // Phase 1. Each pass invalidates one record, so the loop is bounded by
    // the number of records the region can hold.
    let max_passes = flash.qw_count() / RECORD_QWS + 1;
    for _ in 0..max_passes {
        let Some(at) = scan(flash).first_valid_at else { break };
        flash.zero_qw(at).map_err(|()| DestroyFailed)?;
    }

    // Phase 2. Everything programmed in the log goes to zero.
    let frontier = scan(flash).frontier;
    for index in 0..frontier {
        let qw = flash.read_qw(index);
        if qw != ZERO_QW && qw != BLANK_QW {
            flash.zero_qw(index).map_err(|()| DestroyFailed)?;
        }
    }

    // Read back: no valid record, and nothing programmed that is not zero.
    let after = scan(flash);
    if after.valid_records != 0 {
        return Err(DestroyFailed);
    }
    for index in 0..after.frontier {
        let qw = flash.read_qw(index);
        if qw != ZERO_QW && qw != BLANK_QW {
            return Err(DestroyFailed);
        }
    }
    Ok(())
}

/// Destroy the salt, falling back to a page erase when the in-place
/// overwrite does not take. Idempotent. This is the variant every wipe uses.
///
/// # Errors
/// [`DestroyFailed`] when a valid record survives both the in-place
/// overwrite and the page-erase fallback.
pub fn destroy<F: SaltFlash + ?Sized>(flash: &mut F) -> Result<(), DestroyFailed> {
    if destroy_in_place(flash).is_ok() {
        return Ok(());
    }

    // The in-place overwrite did not take (or left residue). Erase the page.
    if flash.erase_region().is_err() {
        return Err(DestroyFailed);
    }
    if scan(flash).valid_records == 0 {
        Ok(())
    } else {
        Err(DestroyFailed)
    }
}

// ---------------------------------------------------------------------------
// Which salt a build uses
// ---------------------------------------------------------------------------

/// Where the salt value comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SaltPolicy {
    /// Every shippable build. A fresh random salt per provisioning, read
    /// back from flash at unlock. No record, no credentials.
    PerProvisioning,
    /// Bench builds only (`e2e-test` / `otp-hardcoded-master-key`, both on
    /// the production-forbidden list). The salt value is this public
    /// constant, whatever the flash record says.
    ///
    /// Why bench builds need it: the SE050 user UserID object can only be
    /// deleted by a session that presents its own value. With a random salt
    /// that value is unrecoverable after any wipe or MCU mass-erase, and the
    /// object would be stranded on the bench chip for good. A fixed salt
    /// keeps the credential of a known test PIN reproducible, exactly as
    /// `otp-hardcoded-master-key` keeps the admin credential reproducible.
    ///
    /// The flash record is still written at provisioning and destroyed at
    /// wipe, so the store is exercised on silicon by the e2e flows. What a
    /// bench build does NOT have is the "ten guesses in total" property.
    FixedBench(&'static [u8; SALT_LEN]),
}

/// The salt to unlock with, or `None` when the stored credentials cannot be
/// recomputed.
#[must_use]
pub fn salt_for_unlock(policy: SaltPolicy, state: SaltState) -> Option<PinSalt> {
    match policy {
        SaltPolicy::PerProvisioning => match state {
            SaltState::Present(salt) => Some(salt),
            SaltState::Absent | SaltState::Ambiguous => None,
        },
        SaltPolicy::FixedBench(bytes) => PinSalt::new(*bytes),
    }
}

/// What provisioning must do about the salt before it writes to a chip.
pub enum ProvisionSalt {
    /// Use this salt; the record already on flash stays as it is. Bench
    /// builds only.
    Use(PinSalt),
    /// Draw a fresh random salt, persist it, then use it.
    CreateRandom,
    /// A salt is already present. Destroy it in place first, then proceed as
    /// [`CreateRandom`](Self::CreateRandom). A shippable build never
    /// provisions under a salt that existed before the provisioning began.
    ReplaceRandom,
    /// Persist this fixed salt (to exercise the store), then use it.
    CreateFixed(PinSalt),
    /// The log is in a state provisioning must not build on.
    Refuse,
}

/// Decide the provisioning step from the build's policy and the flash state.
#[must_use]
pub fn salt_for_provisioning(policy: SaltPolicy, state: SaltState) -> ProvisionSalt {
    match policy {
        SaltPolicy::PerProvisioning => match state {
            SaltState::Absent => ProvisionSalt::CreateRandom,
            // Never reuse. The salt on flash belongs to a wallet that was
            // provisioned (or half-provisioned) earlier, and a credential of
            // that wallet may already have been read out of a chip. If a new
            // wallet were provisioned under the same salt, an attacker who
            // emulates both chips could provision one with a PIN they know,
            // unlock it to reset the page-124 counter, and go on testing
            // guesses against the old credential, ten at a time, for ever.
            // Retiring the salt here kills the old credential the moment a
            // new provisioning starts. Two valid records are retired the
            // same way.
            SaltState::Present(_) | SaltState::Ambiguous => ProvisionSalt::ReplaceRandom,
        },
        SaltPolicy::FixedBench(bytes) => match (PinSalt::new(*bytes), state) {
            (None, _) => ProvisionSalt::Refuse,
            (Some(fixed), SaltState::Absent) => ProvisionSalt::CreateFixed(fixed),
            // A record is already there (this value from an earlier bench
            // run, or another from a ship-shaped image). Leave it; the bench
            // value is used regardless.
            (Some(fixed), SaltState::Present(_) | SaltState::Ambiguous) => {
                ProvisionSalt::Use(fixed)
            }
        },
    }
}

/// Whether the decoy wallet may be provisioned now.
///
/// The decoy is only ever provisioned straight after the real wallet, under
/// the salt that provisioning has just minted. Outside that moment a decoy
/// derivation would be an uncharged derivation under a salt an attacker may
/// already hold credentials for. Bench builds have a fixed salt and re-run
/// decoy provisioning freely in their e2e flows.
#[must_use]
pub const fn decoy_provisioning_allowed(policy: SaltPolicy, salt_minted_this_boot: bool) -> bool {
    match policy {
        SaltPolicy::PerProvisioning => salt_minted_this_boot,
        SaltPolicy::FixedBench(_) => true,
    }
}

/// Whether an unlock can possibly succeed. `gated_unlock` asks this before
/// it charges an attempt or sends anything to a chip.
#[must_use]
pub fn credentials_recomputable(policy: SaltPolicy, state: &SaltState) -> bool {
    match policy {
        SaltPolicy::PerProvisioning => matches!(state, SaltState::Present(_)),
        SaltPolicy::FixedBench(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory model of the salt region with NOR-flash rules:
    ///
    /// - a blank quad-word accepts any data;
    /// - a programmed quad-word accepts only all zeros (RM0456 section
    ///   7.3.7), unless `zero_overwrite_works` is cleared to model silicon
    ///   that refuses it;
    /// - an optional countdown makes the n-th program operation fail after
    ///   committing only part of the quad-word (a torn write).
    struct Model {
        qws: std::vec::Vec<[u8; QW]>,
        zero_overwrite_works: bool,
        erase_works: bool,
        tear_after_programs: Option<usize>,
        /// Cleared by a torn write: power is gone, so every later program or
        /// erase does nothing and fails until `power_on()`. Without this a
        /// "torn" operation would carry on running after the cut, which no
        /// real device does.
        powered: bool,
        erases: usize,
        wipe_marker_restored: bool,
    }

    impl Model {
        fn new(qw_count: usize) -> Self {
            Self {
                qws: std::vec![BLANK_QW; qw_count],
                zero_overwrite_works: true,
                erase_works: true,
                tear_after_programs: None,
                powered: true,
                erases: 0,
                wipe_marker_restored: false,
            }
        }

        /// Next boot after a power loss.
        fn power_on(&mut self) {
            self.powered = true;
            self.tear_after_programs = None;
        }

        /// Returns `true` when this program operation must be torn. A torn
        /// operation is the moment power is lost.
        fn tick_tear(&mut self) -> bool {
            match self.tear_after_programs {
                Some(0) => {
                    self.tear_after_programs = None;
                    self.powered = false;
                    true
                }
                Some(n) => {
                    self.tear_after_programs = Some(n - 1);
                    false
                }
                None => false,
            }
        }
    }

    impl SaltFlash for Model {
        fn qw_count(&self) -> usize {
            self.qws.len()
        }
        fn read_qw(&self, index: usize) -> [u8; QW] {
            self.qws[index]
        }
        fn program_qw(&mut self, index: usize, data: &[u8; QW]) -> Result<(), ()> {
            if !self.powered || self.qws[index] != BLANK_QW {
                return Err(());
            }
            if self.tick_tear() {
                // Half the quad-word lands, the rest stays erased.
                self.qws[index][..8].copy_from_slice(&data[..8]);
                return Err(());
            }
            self.qws[index] = *data;
            Ok(())
        }
        fn zero_qw(&mut self, index: usize) -> Result<(), ()> {
            if !self.powered {
                return Err(());
            }
            if !self.zero_overwrite_works && self.qws[index] != BLANK_QW {
                return Err(());
            }
            if self.tick_tear() {
                self.qws[index][..8].fill(0);
                return Err(());
            }
            self.qws[index] = ZERO_QW;
            Ok(())
        }
        fn erase_region(&mut self) -> Result<(), ()> {
            if !self.powered || !self.erase_works {
                return Err(());
            }
            for qw in &mut self.qws {
                *qw = BLANK_QW;
            }
            self.erases += 1;
            self.wipe_marker_restored = true;
            Ok(())
        }
    }

    fn salt(fill: u8) -> PinSalt {
        let mut b = [fill; SALT_LEN];
        b[3] ^= 0x5A;
        b[19] ^= 0xA5;
        PinSalt::new(b).expect("test salt is usable")
    }

    fn present_bytes(flash: &Model) -> Option<[u8; SALT_LEN]> {
        match load(flash) {
            SaltState::Present(s) => Some(*s.as_bytes()),
            _ => None,
        }
    }

    #[test]
    fn positive_blank_region_has_no_salt() {
        let f = Model::new(32);
        let s = scan(&f);
        assert!(s.state.is_absent());
        assert_eq!(s.valid_records, 0);
        assert_eq!(s.frontier, 0);
        assert_eq!(s.capacity, 32);
        assert!(is_absent(&f));
    }

    #[test]
    fn positive_create_then_load_round_trips() {
        let mut f = Model::new(32);
        let s = salt(0x31);
        create(&mut f, &s).expect("create on a blank region");
        assert_eq!(present_bytes(&f), Some(*s.as_bytes()));
        assert!(!is_absent(&f));
        assert_eq!(scan(&f).frontier, RECORD_QWS);
    }

    #[test]
    fn negative_create_refuses_while_a_salt_exists() {
        let mut f = Model::new(32);
        create(&mut f, &salt(0x31)).unwrap();
        assert_eq!(create(&mut f, &salt(0x32)), Err(CreateError::AlreadyPresent));
        // The original salt is untouched.
        assert_eq!(present_bytes(&f), Some(*salt(0x31).as_bytes()));
    }

    #[test]
    fn positive_destroy_removes_the_salt_and_leaves_zeros() {
        let mut f = Model::new(32);
        create(&mut f, &salt(0x31)).unwrap();
        destroy(&mut f).expect("destroy");
        assert!(is_absent(&f));
        // Overwritten in place, not erased: the three quad-words read zero.
        assert_eq!(f.qws[0], ZERO_QW);
        assert_eq!(f.qws[1], ZERO_QW);
        assert_eq!(f.qws[2], ZERO_QW);
        assert_eq!(f.erases, 0);
    }

    #[test]
    fn positive_destroy_is_idempotent() {
        let mut f = Model::new(32);
        destroy(&mut f).expect("destroy on a blank region");
        create(&mut f, &salt(0x31)).unwrap();
        destroy(&mut f).unwrap();
        destroy(&mut f).expect("second destroy");
        assert!(is_absent(&f));
        assert_eq!(f.erases, 0);
    }

    /// The property the whole design rests on: after a wipe and a new
    /// provisioning, the old salt is unrecoverable and the new one is used.
    #[test]
    fn negative_a_destroyed_salt_never_comes_back() {
        let mut f = Model::new(32);
        let old = salt(0x31);
        create(&mut f, &old).unwrap();
        destroy(&mut f).unwrap();

        let new = salt(0x77);
        create(&mut f, &new).expect("create after destroy appends");
        assert_eq!(present_bytes(&f), Some(*new.as_bytes()));
        assert_eq!(scan(&f).valid_records, 1);

        // No quad-word of the region still holds a half of the old salt.
        let old_bytes = old.as_bytes();
        for qw in &f.qws {
            assert_ne!(&qw[..], &old_bytes[..QW]);
            assert_ne!(&qw[..], &old_bytes[QW..]);
        }
    }

    #[test]
    fn positive_create_appends_after_tombstones_without_erasing() {
        let mut f = Model::new(32);
        for round in 0..5u8 {
            create(&mut f, &salt(0x10 + round)).unwrap();
            destroy(&mut f).unwrap();
        }
        assert_eq!(f.erases, 0);
        assert_eq!(scan(&f).frontier, 5 * RECORD_QWS);
        create(&mut f, &salt(0x60)).unwrap();
        assert_eq!(present_bytes(&f), Some(*salt(0x60).as_bytes()));
    }

    #[test]
    fn negative_create_reports_full_when_no_room_is_left() {
        let mut f = Model::new(2 * RECORD_QWS + 1);
        create(&mut f, &salt(0x31)).unwrap();
        destroy(&mut f).unwrap();
        create(&mut f, &salt(0x32)).unwrap();
        destroy(&mut f).unwrap();
        // One blank quad-word left: not enough for a record.
        assert_eq!(create(&mut f, &salt(0x33)), Err(CreateError::Full));
        assert!(is_absent(&f));
    }

    /// Power loss while writing any of the three quad-words must leave "no
    /// salt", never a wrong one.
    #[test]
    fn negative_torn_create_leaves_no_valid_salt() {
        for tear_at in 0..RECORD_QWS {
            let mut f = Model::new(32);
            f.tear_after_programs = Some(tear_at);
            assert_eq!(create(&mut f, &salt(0x31)), Err(CreateError::Flash));
            assert!(is_absent(&f), "torn at quad-word {tear_at} left a valid salt");

            // Next boot: provisioning appends past the debris and works.
            f.power_on();
            create(&mut f, &salt(0x44)).expect("create after a torn write");
            assert_eq!(present_bytes(&f), Some(*salt(0x44).as_bytes()));
        }
    }

    /// Power loss while destroying: once the first quad-word has been hit
    /// the record is invalid, whatever happens to the rest.
    #[test]
    fn negative_torn_destroy_already_invalidates_the_salt() {
        for tear_at in 0..RECORD_QWS {
            let mut f = Model::new(32);
            create(&mut f, &salt(0x31)).unwrap();
            f.tear_after_programs = Some(tear_at);
            // Power is gone from the torn write on, so the call cannot
            // complete — not even through the erase fallback.
            assert_eq!(destroy(&mut f), Err(DestroyFailed));
            assert!(is_absent(&f), "torn at quad-word {tear_at} left a valid salt");
        }
    }

    /// Power is lost in the middle of a destroy, and the wipe resumes at the
    /// next boot. Found in review: after the first quad-word is zeroed the
    /// record no longer parses, so a destroy that only looks for *valid*
    /// records finds nothing on resume and leaves the rest of the salt in
    /// flash. The resumed destroy must clear the remains.
    #[test]
    fn negative_power_loss_mid_destroy_leaves_no_salt_bytes_after_resume() {
        for cut_at in 0..RECORD_QWS {
            let mut f = Model::new(32);
            let s = salt(0x31);
            create(&mut f, &s).unwrap();

            f.tear_after_programs = Some(cut_at);
            assert!(destroy(&mut f).is_err(), "nothing completes once power is gone");

            f.power_on();
            destroy(&mut f).expect("the resumed wipe destroys the salt");
            assert!(is_absent(&f));
            assert_eq!(f.erases, 0, "the resume must not need a page erase");
            for (i, qw) in f.qws.iter().enumerate() {
                assert_ne!(&qw[..], &s.as_bytes()[..QW], "cut at {cut_at}: first half left at {i}");
                assert_ne!(&qw[..], &s.as_bytes()[QW..], "cut at {cut_at}: second half left at {i}");
            }
        }
    }

    /// The first program of a destroy must be the one that kills the salt,
    /// even when debris from an earlier torn create sits in front of the
    /// live record. If the sweep ran first, a power loss during it would
    /// leave the salt valid with the wipe already under way.
    #[test]
    fn negative_destroy_invalidates_the_salt_with_its_first_program() {
        let mut f = Model::new(32);
        // Two quad-words of debris, then the live record.
        f.qws[0] = [0x5A; QW];
        f.qws[1] = [0xA5; QW];
        let rec = encode(&salt(0x31));
        f.qws[2] = rec[0];
        f.qws[3] = rec[1];
        f.qws[4] = rec[2];
        assert!(!is_absent(&f));

        // Exactly one program completes; power is lost during the second.
        f.tear_after_programs = Some(1);
        assert_eq!(destroy(&mut f), Err(DestroyFailed));
        assert!(is_absent(&f), "the one completed program did not invalidate the salt");
        assert_eq!(f.qws[2], ZERO_QW, "the first program must hit the live record");
    }

    /// The same, with the fallback also unavailable: the caller is told, and
    /// a salt whose first quad-word was hit is still gone.
    #[test]
    fn negative_torn_destroy_without_fallback_reports_failure() {
        let mut f = Model::new(32);
        create(&mut f, &salt(0x31)).unwrap();
        f.erase_works = false;
        f.tear_after_programs = Some(1); // first quad-word zeroed, second torn
        assert_eq!(destroy(&mut f), Err(DestroyFailed));
        assert!(is_absent(&f), "the record was already invalid after the first overwrite");
    }

    /// Silicon that refuses the all-zero overwrite: the page-erase fallback
    /// runs and the wipe marker is put back.
    #[test]
    fn positive_destroy_falls_back_to_page_erase() {
        let mut f = Model::new(32);
        create(&mut f, &salt(0x31)).unwrap();
        f.zero_overwrite_works = false;
        destroy(&mut f).expect("fallback destroy");
        assert!(is_absent(&f));
        assert_eq!(f.erases, 1);
        assert!(f.wipe_marker_restored);
    }

    /// Neither path works: the salt survives and the caller must be told, so
    /// it does not reset the attempt counter.
    #[test]
    fn negative_destroy_reports_failure_when_the_salt_survives() {
        let mut f = Model::new(32);
        create(&mut f, &salt(0x31)).unwrap();
        f.zero_overwrite_works = false;
        f.erase_works = false;
        assert_eq!(destroy(&mut f), Err(DestroyFailed));
        assert!(!is_absent(&f));
    }

    #[test]
    fn negative_corrupted_record_is_not_a_salt() {
        let rec = encode(&salt(0x31));
        for qw in 0..RECORD_QWS {
            for byte in 0..QW {
                let mut f = Model::new(8);
                f.qws[0] = rec[0];
                f.qws[1] = rec[1];
                f.qws[2] = rec[2];
                f.qws[qw][byte] ^= 0x01;
                assert!(
                    is_absent(&f),
                    "one flipped bit at quad-word {qw} byte {byte} still parsed"
                );
            }
        }
    }

    #[test]
    fn negative_header_without_data_is_not_a_salt() {
        let rec = encode(&salt(0x31));
        let mut f = Model::new(8);
        // Header alone, data quad-words blank.
        f.qws[2] = rec[2];
        assert!(is_absent(&f));
        // Header over destroyed data.
        f.qws[0] = ZERO_QW;
        f.qws[1] = ZERO_QW;
        assert!(is_absent(&f));
    }

    #[test]
    fn negative_two_valid_records_are_ambiguous_not_chosen() {
        let a = encode(&salt(0x31));
        let b = encode(&salt(0x32));
        let mut f = Model::new(8);
        f.qws[0] = a[0];
        f.qws[1] = a[1];
        f.qws[2] = a[2];
        f.qws[3] = b[0];
        f.qws[4] = b[1];
        f.qws[5] = b[2];
        let s = scan(&f);
        assert_eq!(s.valid_records, 2);
        assert!(matches!(s.state, SaltState::Ambiguous));
        assert!(!is_absent(&f));
        assert_eq!(create(&mut f, &salt(0x33)), Err(CreateError::AlreadyPresent));

        // Destroy clears both.
        destroy(&mut f).unwrap();
        assert!(is_absent(&f));
    }

    #[test]
    fn positive_record_layout_is_data_data_header() {
        let s = salt(0x31);
        let rec = encode(&s);
        assert_eq!(&rec[0][..], &s.as_bytes()[..QW]);
        assert_eq!(&rec[1][..], &s.as_bytes()[QW..]);
        assert_eq!(&rec[2][..4], b"PQPS");
        assert_eq!(rec[2][4], 1);
        assert_eq!(&rec[2][5..12], &[0u8; 7]);
        assert_eq!(rec[2][12..], crc32_ieee(s.as_bytes()).to_le_bytes());
    }

    const BENCH: [u8; SALT_LEN] = *b"PQSIGNER-BENCH-PIN-SALT-NOT-SHIP";

    #[test]
    fn positive_shippable_policy_unlocks_only_with_a_stored_salt() {
        let p = SaltPolicy::PerProvisioning;
        let stored = salt_for_unlock(p, SaltState::Present(salt(0x31))).expect("present");
        assert_eq!(stored.as_bytes(), salt(0x31).as_bytes());
        assert!(salt_for_unlock(p, SaltState::Absent).is_none());
        assert!(salt_for_unlock(p, SaltState::Ambiguous).is_none());

        assert!(credentials_recomputable(p, &SaltState::Present(salt(0x31))));
        assert!(!credentials_recomputable(p, &SaltState::Absent));
        assert!(!credentials_recomputable(p, &SaltState::Ambiguous));
    }

    #[test]
    fn positive_shippable_policy_provisioning_table() {
        let p = SaltPolicy::PerProvisioning;
        assert!(matches!(
            salt_for_provisioning(p, SaltState::Absent),
            ProvisionSalt::CreateRandom
        ));
        // A shippable build never provisions under a salt that was already
        // there: it is retired and replaced.
        assert!(matches!(
            salt_for_provisioning(p, SaltState::Present(salt(0x31))),
            ProvisionSalt::ReplaceRandom
        ));
        assert!(matches!(
            salt_for_provisioning(p, SaltState::Ambiguous),
            ProvisionSalt::ReplaceRandom
        ));
    }

    /// The attack the "never reuse" rule exists for, replayed on the model.
    ///
    /// An attacker has read both chips of a wallet provisioned under salt S0
    /// and emulates them. They cannot wipe (that destroys S0), but they can
    /// make the device believe it is unprovisioned and run the wizard with a
    /// PIN they know. If that provisioning reused S0, unlocking the new
    /// wallet would reset the attempt counter while the device still
    /// computes credentials under S0, so guessing could go on for ever.
    #[test]
    fn replay_reprovisioning_retires_the_old_salt() {
        let mut f = Model::new(32);
        let s0 = salt(0x31);
        create(&mut f, &s0).expect("victim wallet provisioned under S0");

        // Second provisioning starts with S0 still on flash.
        match salt_for_provisioning(SaltPolicy::PerProvisioning, load(&f)) {
            ProvisionSalt::ReplaceRandom => {}
            _ => panic!("provisioning over a live salt must replace it"),
        }
        destroy_in_place(&mut f).expect("retire S0 without a page erase");
        assert_eq!(f.erases, 0, "retiring a salt at provisioning must not erase the page");
        assert!(!f.wipe_marker_restored, "and must not touch the wipe flag");
        let s1 = salt(0x77);
        create(&mut f, &s1).expect("new wallet provisioned under S1");

        // The device now derives under S1; S0 is nowhere in the region.
        assert_eq!(present_bytes(&f), Some(*s1.as_bytes()));
        for qw in &f.qws {
            assert_ne!(&qw[..], &s0.as_bytes()[..QW]);
            assert_ne!(&qw[..], &s0.as_bytes()[QW..]);
        }
    }

    /// Provisioning-time retirement has no erase fallback: on silicon that
    /// refuses the all-zero overwrite it must fail, so the caller falls
    /// into its wipe path rather than erase the page (and the duress-mode
    /// flag with it) behind the wizard's back.
    #[test]
    fn negative_destroy_in_place_never_erases() {
        let mut f = Model::new(32);
        create(&mut f, &salt(0x31)).unwrap();
        f.zero_overwrite_works = false;
        assert_eq!(destroy_in_place(&mut f), Err(DestroyFailed));
        assert_eq!(f.erases, 0);
        assert!(!is_absent(&f));
        // The wipe-time variant does fall back.
        destroy(&mut f).expect("wipe-time destroy erases");
        assert_eq!(f.erases, 1);
    }

    #[test]
    fn negative_decoy_is_provisioned_only_after_a_salt_minted_this_boot() {
        assert!(decoy_provisioning_allowed(SaltPolicy::PerProvisioning, true));
        assert!(!decoy_provisioning_allowed(SaltPolicy::PerProvisioning, false));
        assert!(decoy_provisioning_allowed(SaltPolicy::FixedBench(&BENCH), false));
    }

    /// The shippable policy never hands out the bench constant, and the
    /// bench policy never hands out anything else.
    #[test]
    fn negative_bench_salt_is_confined_to_the_bench_policy() {
        let bench = SaltPolicy::FixedBench(&BENCH);
        for state in [
            SaltState::Absent,
            SaltState::Ambiguous,
            SaltState::Present(salt(0x31)),
        ] {
            let got = salt_for_unlock(bench, state).expect("bench salt is always available");
            assert_eq!(got.as_bytes(), &BENCH);
        }
        assert!(credentials_recomputable(bench, &SaltState::Absent));

        match salt_for_provisioning(bench, SaltState::Absent) {
            ProvisionSalt::CreateFixed(s) => assert_eq!(s.as_bytes(), &BENCH),
            _ => panic!("bench provisioning writes the fixed salt to exercise the store"),
        }
        match salt_for_provisioning(bench, SaltState::Present(salt(0x31))) {
            ProvisionSalt::Use(s) => assert_eq!(s.as_bytes(), &BENCH),
            _ => panic!("bench provisioning uses the fixed salt over any record"),
        }

        // Shippable: whatever is stored is used, and it is not the constant
        // unless that is literally what was stored.
        let shipped = salt_for_unlock(SaltPolicy::PerProvisioning, SaltState::Present(salt(0x31)))
            .expect("present");
        assert_ne!(shipped.as_bytes(), &BENCH);
    }

    #[test]
    fn negative_degenerate_bench_constant_is_refused() {
        static BAD: [u8; SALT_LEN] = [0xFF; SALT_LEN];
        let p = SaltPolicy::FixedBench(&BAD);
        assert!(salt_for_unlock(p, SaltState::Absent).is_none());
        assert!(matches!(
            salt_for_provisioning(p, SaltState::Absent),
            ProvisionSalt::Refuse
        ));
    }

    /// A record is found wherever it sits, not only at multiples of three:
    /// torn writes shift the append position.
    #[test]
    fn positive_record_is_found_at_any_offset() {
        let rec = encode(&salt(0x31));
        for offset in 0..6 {
            let mut f = Model::new(16);
            for qw in f.qws.iter_mut().take(offset) {
                *qw = [0x5A; QW];
            }
            f.qws[offset] = rec[0];
            f.qws[offset + 1] = rec[1];
            f.qws[offset + 2] = rec[2];
            let s = scan(&f);
            assert_eq!(s.valid_records, 1, "offset {offset}");
            assert_eq!(s.first_valid_at, Some(offset));
            assert_eq!(s.frontier, offset + RECORD_QWS);
        }
    }

    // -------------------------------------------------------------------
    // Property tests: the lifecycle over arbitrary histories and arbitrary
    // flash contents. The unit tests above pick the cases a reader would
    // think of; these look for the ones nobody thought of.
    // -------------------------------------------------------------------

    use proptest::prelude::*;

    /// A salt that is different for every `n`, so a later create can never
    /// legitimately re-use the bytes of an earlier one.
    fn unique_salt(n: u32) -> PinSalt {
        let mut b = [0u8; SALT_LEN];
        for (i, chunk) in b.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&(n.wrapping_mul(0x9E37_79B9) ^ (i as u32) ^ 0xA5A5_0000).to_be_bytes());
        }
        // Keep it clear of the two degenerate patterns whatever `n` is.
        b[0] = 0x5A;
        b[16] = 0xA5;
        PinSalt::new(b).expect("unique_salt is usable")
    }

    #[derive(Clone, Debug)]
    enum Op {
        Create,
        Destroy,
        /// Power is lost during the n-th quad-word program of a create.
        TornCreate(usize),
        /// Power is lost during the n-th quad-word overwrite of a destroy.
        TornDestroy(usize),
        /// Destroy on silicon that refuses the all-zero overwrite.
        DestroyByErase,
        /// A provisioning that finds a salt already present: retire it in
        /// place, then create a new one.
        Reprovision,
        /// The page erase that ends a completed wipe.
        Erase,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => Just(Op::Create),
            3 => Just(Op::Destroy),
            2 => (0usize..RECORD_QWS).prop_map(Op::TornCreate),
            2 => (0usize..RECORD_QWS).prop_map(Op::TornDestroy),
            1 => Just(Op::DestroyByErase),
            3 => Just(Op::Reprovision),
            1 => Just(Op::Erase),
        ]
    }

    proptest! {
        /// Whatever happened before, the log holds at most one salt, it is
        /// the one most recently created and not since destroyed, and a
        /// salt that was destroyed never reappears anywhere in the region.
        #[test]
        fn property_lifecycle_never_resurrects_a_destroyed_salt(
            ops in prop::collection::vec(op(), 0..80)
        ) {
            let mut f = Model::new(24);
            let mut current: Option<[u8; SALT_LEN]> = None;
            let mut destroyed: std::vec::Vec<[u8; SALT_LEN]> = std::vec::Vec::new();
            let mut next_salt = 0u32;

            for step in ops {
                f.power_on();
                f.zero_overwrite_works = true;
                match step {
                    Op::Create | Op::TornCreate(_) => {
                        if let Op::TornCreate(at) = step {
                            f.tear_after_programs = Some(at);
                        }
                        next_salt += 1;
                        let s = unique_salt(next_salt);
                        match create(&mut f, &s) {
                            Ok(()) => {
                                prop_assert!(current.is_none(), "create succeeded over a live salt");
                                current = Some(*s.as_bytes());
                            }
                            Err(CreateError::AlreadyPresent) => {
                                prop_assert!(current.is_some(), "AlreadyPresent with no live salt");
                            }
                            Err(CreateError::Full | CreateError::Flash | CreateError::Verify) => {
                                prop_assert!(current.is_none(), "a failed create disturbed a live salt");
                            }
                        }
                        // Next boot.
                        f.power_on();
                    }
                    Op::Destroy | Op::TornDestroy(_) | Op::DestroyByErase => {
                        match step {
                            Op::TornDestroy(at) => f.tear_after_programs = Some(at),
                            Op::DestroyByErase => f.zero_overwrite_works = false,
                            _ => {}
                        }
                        let first = destroy(&mut f);
                        if !f.powered {
                            // Power was lost part-way. Whatever state that
                            // left, the wipe resumes at the next boot (the
                            // wipe flag is armed before the salt is touched)
                            // and must finish the job.
                            prop_assert!(first.is_err(), "a destroy cut short reported success");
                            f.power_on();
                            f.zero_overwrite_works = true;
                            prop_assert!(destroy(&mut f).is_ok(), "the resumed destroy failed");
                        } else {
                            prop_assert!(first.is_ok(), "destroy failed with the erase fallback available");
                        }
                        if let Some(old) = current.take() {
                            destroyed.push(old);
                        }
                    }
                    Op::Reprovision => {
                        let erases_before = f.erases;
                        prop_assert!(destroy_in_place(&mut f).is_ok());
                        prop_assert_eq!(f.erases, erases_before, "provisioning erased the page");
                        if let Some(old) = current.take() {
                            destroyed.push(old);
                        }
                        next_salt += 1;
                        let s = unique_salt(next_salt);
                        match create(&mut f, &s) {
                            Ok(()) => current = Some(*s.as_bytes()),
                            Err(CreateError::Full) => {}
                            Err(e) => prop_assert!(false, "unexpected create error {:?}", e),
                        }
                    }
                    Op::Erase => {
                        f.erase_region().expect("model erase");
                        if let Some(old) = current.take() {
                            destroyed.push(old);
                        }
                    }
                }
                f.power_on();

                // Invariant 1: never more than one valid record.
                let s = scan(&f);
                prop_assert!(s.valid_records <= 1, "{} valid records", s.valid_records);

                // Invariant 2: what load returns is exactly the live salt.
                prop_assert_eq!(present_bytes(&f), current);
                prop_assert_eq!(is_absent(&f), current.is_none());

                // Invariant 3: no half of a destroyed salt is left anywhere.
                for old in &destroyed {
                    for qw in &f.qws {
                        prop_assert!(qw[..] != old[..QW], "first half of a destroyed salt survives");
                        prop_assert!(qw[..] != old[QW..], "second half of a destroyed salt survives");
                    }
                }
            }
        }

        /// Arbitrary flash contents, including valid records dropped at
        /// arbitrary offsets among noise: the scan is consistent with
        /// itself, and destroy always ends with no valid record.
        #[test]
        fn property_scan_and_destroy_hold_on_arbitrary_contents(
            segments in prop::collection::vec(
                prop_oneof![
                    3 => Just(0u8),                      // blank quad-word
                    2 => Just(1u8),                      // zeroed quad-word
                    3 => Just(2u8),                      // noise quad-word
                    2 => Just(3u8),                      // a whole valid record
                    1 => Just(4u8),                      // a record missing its header
                ],
                0..24
            ),
            noise in prop::collection::vec(any::<[u8; QW]>(), 24),
            erase_works in any::<bool>(),
        ) {
            let mut qws: std::vec::Vec<[u8; QW]> = std::vec::Vec::new();
            for (i, kind) in segments.iter().enumerate() {
                match kind {
                    0 => qws.push(BLANK_QW),
                    1 => qws.push(ZERO_QW),
                    2 => qws.push(noise[i]),
                    3 => qws.extend_from_slice(&encode(&unique_salt(i as u32))),
                    _ => qws.extend_from_slice(&encode(&unique_salt(i as u32))[..2]),
                }
            }
            let mut f = Model::new(0);
            f.qws = qws;
            f.erase_works = erase_works;

            let before = scan(&f);
            prop_assert_eq!(before.capacity, f.qws.len());
            prop_assert!(before.frontier <= before.capacity);
            prop_assert_eq!(before.first_valid_at.is_some(), before.valid_records > 0);
            match before.state {
                SaltState::Absent => prop_assert_eq!(before.valid_records, 0),
                SaltState::Present(_) => prop_assert_eq!(before.valid_records, 1),
                SaltState::Ambiguous => prop_assert!(before.valid_records >= 2),
            }
            if let Some(at) = before.first_valid_at {
                prop_assert!(at + RECORD_QWS <= before.capacity);
            }

            // In-place overwrite works in this model, so destroy must
            // succeed whether or not the erase fallback is available, and
            // must not need it.
            prop_assert!(destroy(&mut f).is_ok());
            prop_assert!(is_absent(&f));
            prop_assert_eq!(f.erases, 0);
            // Nothing programmed is left that is not zero: no record, no
            // fragment of one, no noise.
            for qw in &f.qws {
                prop_assert!(*qw == ZERO_QW || *qw == BLANK_QW);
            }
        }
    }
}
