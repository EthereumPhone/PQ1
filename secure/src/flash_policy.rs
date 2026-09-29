//! Pure policy for generic secure-bank flash mutations.
//!
//! Bank-1 page 127 is exclusively owned by the append-only first-boot
//! provisioning journal.  Generic flash callers must not be able to erase it
//! or program a quad-word that overlaps it.  Keeping the policy free of MMIO
//! makes the exact boundary and overflow behaviour executable on the host;
//! the hardware driver consumes the validated address/page capabilities.

/// Secure alias of STM32U585 flash bank 1.
pub(crate) const BANK1_BASE: u32 = pqsigner_geometry::BANK1_BASE;
/// Bank-1 page size.
pub(crate) const PAGE_BYTES: u32 = pqsigner_geometry::PAGE_SIZE;
/// Number of pages in bank 1.
const PAGE_COUNT: u32 = pqsigner_geometry::PAGES_PER_BANK as u32;
/// First byte after secure flash bank 1.
const BANK1_END: u32 = BANK1_BASE + PAGE_COUNT * PAGE_BYTES;
/// Page reserved exclusively for the first-boot provisioning journal.
pub(crate) const FIRST_BOOT_JOURNAL_PAGE: u32 =
    pqsigner_geometry::FIRST_BOOT_JOURNAL_PAGE as u32;
/// First byte of the first-boot provisioning journal.
pub(crate) const FIRST_BOOT_JOURNAL_ADDR: u32 =
    pqsigner_geometry::page_addr(pqsigner_geometry::Bank::One, pqsigner_geometry::FIRST_BOOT_JOURNAL_PAGE);
/// First byte after the first-boot provisioning journal.
const FIRST_BOOT_JOURNAL_END: u32 =
    pqsigner_geometry::page_end(pqsigner_geometry::Bank::One, pqsigner_geometry::FIRST_BOOT_JOURNAL_PAGE);
const QUADWORD_BYTES: u32 = 16;

/// A quad-word address proven to be aligned, in bank 1, and disjoint from
/// the first-boot journal.
pub(crate) struct GenericSecureQwAddr(u32);

impl GenericSecureQwAddr {
    /// Validate an address for the generic secure-bank programming API.
    pub(crate) const fn new(addr: u32) -> Option<Self> {
        if addr % QUADWORD_BYTES != 0 {
            return None;
        }
        let end = match addr.checked_add(QUADWORD_BYTES) {
            Some(end) => end,
            None => return None,
        };
        if addr < BANK1_BASE || end > BANK1_END {
            return None;
        }
        if addr < FIRST_BOOT_JOURNAL_END && end > FIRST_BOOT_JOURNAL_ADDR {
            return None;
        }
        Some(Self(addr))
    }

    /// Recover the validated address for the MMIO driver.
    pub(crate) const fn get(&self) -> u32 {
        self.0
    }
}

/// A page proven erasable through the NON-SECURE erase API, carrying the
/// PHYSICAL BANK it belongs to.
///
/// The twin of [`GenericSecurePage`], and it exists for the mirror-image
/// reason. `erase_ns_page` set `BKER` UNCONDITIONALLY — correct only while
/// "non-secure page" and "bank 2 page" are the same claim, which they are
/// under the current geometry and are NOT under one that puts an NS slot in
/// bank 1. There the failure is worse than the secure-side one: erasing the
/// INACTIVE bank-1 NS slot would target the bank-2 page of the same number,
/// i.e. **the NS slot the device is currently running from**, mid-update.
///
/// No owner exclusion here, deliberately. The secure twin excludes the
/// first-boot journal; the NS side has no such page today, and the pages the
/// frozen registry WOULD protect (the bank-2 FSBL mirror, pages 0..=4) are
/// currently inside the live NS slot A — the #540 conflict pinned by
/// `fsbl-tests/tests/geometry_consistency.rs`. Enforcing
/// `updater_must_preserve` here would break the live NS update; it belongs in
/// the cutover, and that test says so in its own failure message.
pub(crate) struct GenericNsPage {
    page: u32,
    bank: pqsigner_geometry::Bank,
}

impl GenericNsPage {
    /// Validate a BANK-2 non-secure page. Bank 2 is the only bank with
    /// non-secure pages under the current geometry, so this is the ordinary
    /// constructor; [`new_in`] is the general form.
    pub(crate) const fn new(page: u32) -> Option<Self> {
        Self::new_in(pqsigner_geometry::Bank::Two, page)
    }

    /// Validate a non-secure page number in an explicit bank.
    pub(crate) const fn new_in(bank: pqsigner_geometry::Bank, page: u32) -> Option<Self> {
        if page < PAGE_COUNT {
            Some(Self { page, bank })
        } else {
            None
        }
    }

    /// Recover the validated page number for the MMIO driver.
    pub(crate) const fn get(&self) -> u32 {
        self.page
    }

    /// The physical bank. The driver MUST set `BKER` from this.
    pub(crate) const fn bank(&self) -> pqsigner_geometry::Bank {
        self.bank
    }
}

/// A page proven erasable through the generic secure erase API, carrying the
/// PHYSICAL BANK it belongs to.
///
/// The bank used to be implicit — the type was documented as "a bank-1 page"
/// and `new` accepted any `page < 127` with no bank at all, while
/// `erase_secure_page` wrote `SECCR` **without `BKER`**, i.e. always bank 1.
/// That is correct only while every secure page lives in bank 1. Under a
/// geometry that puts a secure slot in bank 2 (v7), a bank-2 page number would
/// be accepted by the proof and silently erase the BANK-1 page of the same
/// number — the manifests, slot A, or the per-device pages. The type that
/// exists to make erases safe would have offered no protection at exactly the
/// moment it was needed.
///
/// Carrying the bank makes that unrepresentable: the driver reads
/// [`GenericSecurePage::bank`] to decide `BKER`, so a mismatch is a
/// type-level impossibility rather than a caller-discipline convention.
pub(crate) struct GenericSecurePage {
    page: u32,
    bank: pqsigner_geometry::Bank,
}

impl GenericSecurePage {
    /// Validate a BANK-1 page number and exclude the journal-owned page 127.
    ///
    /// Bank 1 is the only bank with secure pages under the current geometry,
    /// so this stays the ordinary constructor. [`new_in`] is the general form.
    pub(crate) const fn new(page: u32) -> Option<Self> {
        Self::new_in(pqsigner_geometry::Bank::One, page)
    }

    /// Validate a page number in an explicit bank.
    ///
    /// The journal exclusion is BANK-1-SPECIFIC: `FIRST_BOOT_JOURNAL_PAGE` is
    /// bank-1 page 127 (`pqsigner_geometry::FIRST_BOOT_JOURNAL_PAGE`, "bank-1
    /// only"). A bank-2 page 127 is a different page with a different owner,
    /// so it is bounded by the bank size instead. Getting this backwards would
    /// either wave the journal through or refuse a legitimate bank-2 page.
    pub(crate) const fn new_in(bank: pqsigner_geometry::Bank, page: u32) -> Option<Self> {
        let ok = match bank {
            pqsigner_geometry::Bank::One => page < FIRST_BOOT_JOURNAL_PAGE,
            pqsigner_geometry::Bank::Two => page < PAGE_COUNT,
        };
        if ok {
            Some(Self { page, bank })
        } else {
            None
        }
    }

    /// Recover the validated page number for the MMIO driver.
    pub(crate) const fn get(&self) -> u32 {
        self.page
    }

    /// The physical bank this page lives in. The driver MUST consult this to
    /// set `BKER` (RM0456 §7.9.x: `BKER` selects the bank for a page erase);
    /// ignoring it is the bug this type was widened to prevent.
    pub(crate) const fn bank(&self) -> pqsigner_geometry::Bank {
        self.bank
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_quadword_policy_excludes_every_journal_boundary_case() {
        assert_eq!(
            GenericSecureQwAddr::new(FIRST_BOOT_JOURNAL_ADDR - 16).map(|a| a.get()),
            Some(FIRST_BOOT_JOURNAL_ADDR - 16)
        );

        // Crossing from below, exactly at the start, wholly inside, and the
        // final aligned QW are all journal-owned.
        assert!(GenericSecureQwAddr::new(FIRST_BOOT_JOURNAL_ADDR - 8).is_none());
        assert!(GenericSecureQwAddr::new(FIRST_BOOT_JOURNAL_ADDR).is_none());
        assert!(GenericSecureQwAddr::new(FIRST_BOOT_JOURNAL_ADDR + 16).is_none());
        assert!(GenericSecureQwAddr::new(FIRST_BOOT_JOURNAL_END - 16).is_none());

        // There is no generic bank-1 address above page 127.
        assert!(GenericSecureQwAddr::new(FIRST_BOOT_JOURNAL_END).is_none());
    }

    #[test]
    fn generic_quadword_policy_rejects_misalignment_range_errors_and_overflow() {
        assert!(GenericSecureQwAddr::new(BANK1_BASE).is_some());
        assert!(GenericSecureQwAddr::new(BANK1_BASE + 1).is_none());
        assert!(GenericSecureQwAddr::new(BANK1_BASE - 16).is_none());
        assert!(GenericSecureQwAddr::new(u32::MAX - 15).is_none());
        assert!(GenericSecureQwAddr::new(u32::MAX).is_none());
    }

    #[test]
    fn generic_erase_policy_rejects_journal_and_out_of_range_pages() {
        assert_eq!(GenericSecurePage::new(0).map(|p| p.get()), Some(0));
        assert_eq!(GenericSecurePage::new(126).map(|p| p.get()), Some(126));
        assert!(GenericSecurePage::new(127).is_none());
        assert!(GenericSecurePage::new(128).is_none());
        assert!(GenericSecurePage::new(u32::MAX).is_none());
    }
    /// The bank must be part of the proof, in BOTH directions.
    ///
    /// Before 2026-09-24 this type was documented as "a bank-1 page" and
    /// carried no bank, while the driver wrote `SECCR` without `BKER`. A
    /// bank-2 page number was therefore accepted and erased the BANK-1 page of
    /// the same number. The geometry that makes that reachable (a secure slot
    /// in bank 2) is being drafted now, so the guard has to exist first.
    #[test]
    fn the_page_proof_carries_its_bank() {
        use pqsigner_geometry::Bank;

        // Bank 1: the journal page is still excluded, and the bank is recorded.
        let p = GenericSecurePage::new(126).expect("bank-1 page 126 is erasable");
        assert_eq!(p.get(), 126);
        assert!(matches!(p.bank(), Bank::One), "new() must mean bank 1");
        assert!(
            GenericSecurePage::new(FIRST_BOOT_JOURNAL_PAGE).is_none(),
            "the first-boot journal page must stay un-erasable through the generic API"
        );

        // The journal exclusion is BANK-1-SPECIFIC. Bank-2 page 127 is a
        // different page with a different owner; refusing it would be wrong,
        // and applying the bank-1 rule to it is exactly the confusion the
        // explicit bank prevents.
        let q = GenericSecurePage::new_in(Bank::Two, FIRST_BOOT_JOURNAL_PAGE)
            .expect("bank-2 page 127 is not the bank-1 journal");
        assert!(matches!(q.bank(), Bank::Two));
        assert_eq!(q.get(), FIRST_BOOT_JOURNAL_PAGE);

        // Both banks still reject out-of-range pages.
        assert!(GenericSecurePage::new_in(Bank::Two, PAGE_COUNT).is_none());
        assert!(GenericSecurePage::new_in(Bank::One, PAGE_COUNT).is_none());

        // The discriminating property: same page number, different bank.
        let a = GenericSecurePage::new_in(Bank::One, 5).unwrap();
        let b = GenericSecurePage::new_in(Bank::Two, 5).unwrap();
        assert_eq!(a.get(), b.get(), "same page number");
        assert!(
            !matches!(a.bank(), Bank::Two) && matches!(b.bank(), Bank::Two),
            "...but distinguishable banks — which is the whole point: erasing \
             bank-2 page 5 must not erase bank-1 page 5 (Manifest A)"
        );
    }

    /// The NS page proof carries its bank too — the mirror of
    /// [`the_page_proof_carries_its_bank`], and the more dangerous half.
    ///
    /// `erase_secure_page` without a bank would erase the wrong INACTIVE page.
    /// `erase_ns_page` without a bank, under a geometry with an NS slot in
    /// bank 1, would erase the page the device is RUNNING FROM: the updater
    /// erases the inactive slot, the write lands in the other bank, and that is
    /// the live NS image. Mid-update, with no valid fallback.
    #[test]
    fn the_ns_page_proof_carries_its_bank() {
        use pqsigner_geometry::Bank;

        // `new` still means bank 2 — the only bank with NS pages today.
        let p = GenericNsPage::new(63).expect("bank-2 page 63 is erasable");
        assert_eq!(p.get(), 63);
        assert!(matches!(p.bank(), Bank::Two), "new() must mean bank 2");

        // Bank 1 is representable, for the geometry that needs it.
        let q = GenericNsPage::new_in(Bank::One, 120).expect("bank-1 NS page");
        assert!(matches!(q.bank(), Bank::One));

        // Both banks reject out-of-range pages.
        assert!(GenericNsPage::new_in(Bank::One, PAGE_COUNT).is_none());
        assert!(GenericNsPage::new_in(Bank::Two, PAGE_COUNT).is_none());

        // NO owner exclusion here, deliberately — unlike the secure twin, which
        // excludes the first-boot journal. The pages the frozen registry would
        // protect (bank-2 0..=4, the FSBL mirror) are currently INSIDE the live
        // NS slot A, so enforcing `updater_must_preserve` here would break the
        // live update. That conflict is pinned in
        // `fsbl-tests/tests/geometry_consistency.rs` instead.
        assert!(
            GenericNsPage::new_in(Bank::Two, 0).is_some(),
            "bank-2 page 0 must stay erasable while the legacy NS slot A starts there"
        );

        // The discriminating property, stated as the hazard it prevents.
        let a = GenericNsPage::new_in(Bank::One, 120).unwrap();
        let b = GenericNsPage::new_in(Bank::Two, 120).unwrap();
        assert_eq!(a.get(), b.get());
        assert!(
            !matches!(a.bank(), Bank::Two) && matches!(b.bank(), Bank::Two),
            "same page number, distinguishable banks: erasing the INACTIVE bank-1 \
             NS slot must not erase the bank-2 page of the same number, which \
             under v7 is the RUNNING NS slot"
        );
    }

}
