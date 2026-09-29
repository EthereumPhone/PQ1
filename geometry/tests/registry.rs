//! Host re-derivation of the frozen §5 geometry properties. The
//! compile-time checks in `src/lib.rs` reject gaps/overlaps/second
//! owners at build time; these tests prove the same properties against
//! an independent scan plus the exact address map from Draft 1.1 §5.

use pqsigner_geometry::*;

fn all_pages() -> impl Iterator<Item = (Bank, u8)> {
    Bank::ALL
        .into_iter()
        .flat_map(|bank| (0..PAGES_PER_BANK).map(move |page| (bank, page)))
}

#[test]
fn every_one_of_256_pages_has_exactly_one_owner() {
    assert_eq!(all_pages().count(), 256);
    for (bank, page) in all_pages() {
        let owner = owner_of(bank, page).expect("gap: page has no owner");
        let matches = REGISTRY
            .iter()
            .filter(|row| {
                row.bank == bank && row.first_page <= page && page <= row.last_page
            })
            .count();
        assert_eq!(matches, 1, "second owner for {bank:?} page {page}");
        assert_eq!(
            Some(owner),
            owner_of(bank, page),
            "owner lookup unstable for {bank:?} page {page}"
        );
    }
}

#[test]
fn registry_rows_cover_each_bank_contiguously() {
    for bank in Bank::ALL {
        let mut next = 0u8;
        for row in REGISTRY.iter().filter(|row| row.bank == bank) {
            assert_eq!(row.first_page, next, "gap or overlap before {bank:?} {next}");
            assert!(row.first_page <= row.last_page);
            next = row.last_page + 1;
        }
        assert_eq!(next, PAGES_PER_BANK, "{bank:?} not covered to page 127");
    }
}

#[test]
fn frozen_row_ownership() {
    use Bank::{One, Two};
    use Owner::*;
    let cases: &[((Bank, u8), Owner)] = &[
        ((One, 0), Fsbl),
        ((One, 4), Fsbl),
        ((One, 5), ManifestA),
        ((One, 6), ManifestB), // former boot-state page: sole owner is manifest B
        ((One, 7), SecureSlotA),
        ((One, 63), SecureSlotA),
        ((One, 64), Route1JournalA),
        ((One, 65), SecureSlotB),
        ((One, 121), SecureSlotB),
        ((One, 122), Route1JournalB),
        ((One, 123), OffchainJournal),
        ((One, 124), McuPinState),
        ((One, 125), AdminWipeDuress),
        ((One, 126), WrappedBhk),
        ((One, 127), FirstBootJournal), // Tropic01 reservation retired 2026-07-14
        ((Two, 0), Fsbl),              // byte-identical FSBL mirror
        ((Two, 4), Fsbl),
        ((Two, 5), NsSlotA),
        ((Two, 65), NsSlotA),
        ((Two, 66), NsSlotB),
        ((Two, 126), NsSlotB),
        ((Two, 127), ReservedErased),
    ];
    for &((bank, page), want) in cases {
        assert_eq!(owner_of(bank, page), Some(want), "{bank:?} page {page}");
    }
}

#[test]
fn exact_address_map_matches_section_5() {
    use Bank::{One, Two};
    let addrs: &[((Bank, u8), u32, u32)] = &[
        ((One, 0), 0x0C00_0000, 0x0C00_2000),
        ((One, 4), 0x0C00_8000, 0x0C00_A000),
        ((One, 5), 0x0C00_A000, 0x0C00_C000),
        ((One, 6), 0x0C00_C000, 0x0C00_E000),
        ((One, 7), 0x0C00_E000, 0x0C01_0000),
        ((One, 63), 0x0C07_E000, 0x0C08_0000),
        ((One, 64), 0x0C08_0000, 0x0C08_2000),
        ((One, 65), 0x0C08_2000, 0x0C08_4000),
        ((One, 121), 0x0C0F_2000, 0x0C0F_4000),
        ((One, 122), 0x0C0F_4000, 0x0C0F_6000),
        ((One, 123), 0x0C0F_6000, 0x0C0F_8000),
        ((One, 124), 0x0C0F_8000, 0x0C0F_A000),
        ((One, 125), 0x0C0F_A000, 0x0C0F_C000),
        ((One, 126), 0x0C0F_C000, 0x0C0F_E000),
        ((One, 127), 0x0C0F_E000, 0x0C10_0000),
        ((Two, 0), 0x0810_0000, 0x0810_2000),
        ((Two, 4), 0x0810_8000, 0x0810_A000),
        ((Two, 5), 0x0810_A000, 0x0810_C000),
        ((Two, 65), 0x0818_2000, 0x0818_4000),
        ((Two, 66), 0x0818_4000, 0x0818_6000),
        ((Two, 126), 0x081F_C000, 0x081F_E000),
        ((Two, 127), 0x081F_E000, 0x0820_0000),
    ];
    for &((bank, page), start, end) in addrs {
        assert_eq!(page_addr(bank, page), start, "{bank:?} page {page} start");
        assert_eq!(page_end(bank, page), end, "{bank:?} page {page} end");
    }
}

#[test]
fn slot_and_fsbl_spans() {
    assert_eq!(FSBL_SPAN, 40_960);
    assert_eq!(FSBL_MAX_LOAD_SPAN, 38_912);
    assert!(FSBL_MAX_LOAD_SPAN < FSBL_SPAN);
    assert_eq!(SECURE_SLOT_SPAN, 57 * PAGE_SIZE);
    assert_eq!(NS_SLOT_SPAN, 61 * PAGE_SIZE);
    // Bank totals close: no capacity arithmetic depends on a hidden page.
    let bank1: u32 = REGISTRY
        .iter()
        .filter(|row| row.bank == Bank::One)
        .map(|row| (row.last_page - row.first_page + 1) as u32 * PAGE_SIZE)
        .sum();
    let bank2: u32 = REGISTRY
        .iter()
        .filter(|row| row.bank == Bank::Two)
        .map(|row| (row.last_page - row.first_page + 1) as u32 * PAGE_SIZE)
        .sum();
    assert_eq!(bank1, 128 * PAGE_SIZE);
    assert_eq!(bank2, 128 * PAGE_SIZE);
}

#[test]
fn updater_preserve_rule_matches_section_5() {
    use Bank::{One, Two};
    for page in 0..PAGES_PER_BANK {
        let bank1_want = matches!(page, 0..=4 | 64 | 122 | 123..=127);
        let bank2_want = matches!(page, 0..=4 | 127);
        assert_eq!(
            updater_must_preserve(One, page),
            bank1_want,
            "bank-1 page {page}"
        );
        assert_eq!(
            updater_must_preserve(Two, page),
            bank2_want,
            "bank-2 page {page}"
        );
    }
}

#[test]
fn route1_pages_are_bank1_pairwise_disjoint() {
    assert_eq!(ROUTE1_JOURNAL_PAGES, [64, 122]);
    assert_ne!(ROUTE1_JOURNAL_PAGES[0], ROUTE1_JOURNAL_PAGES[1]);
    assert_eq!(
        owner_of(Bank::One, ROUTE1_JOURNAL_PAGES[0]),
        Some(Owner::Route1JournalA)
    );
    assert_eq!(
        owner_of(Bank::One, ROUTE1_JOURNAL_PAGES[1]),
        Some(Owner::Route1JournalB)
    );
    // Never image capacity, manifest space, or runtime-owned state.
    for &page in &ROUTE1_JOURNAL_PAGES {
        assert!(!matches!(
            owner_of(Bank::One, page),
            Some(Owner::SecureSlotA | Owner::SecureSlotB | Owner::ManifestA | Owner::ManifestB
                 | Owner::OffchainJournal | Owner::McuPinState | Owner::AdminWipeDuress)
        ));
    }
}

#[test]
fn out_of_range_pages_have_no_owner() {
    assert_eq!(owner_of(Bank::One, 128), None);
    assert_eq!(owner_of(Bank::Two, 200), None);
}

/// The two bank-2 aliases are different addresses, and that difference is the
/// whole point.
///
/// `page_addr` returns the NON-SECURE alias for bank 2 — correct under this
/// registry, where every bank-2 page is non-secure. A geometry that puts a
/// secure watermark over part of bank 2 (RM0456 §7.5.2 permits one secure area
/// per bank) makes it quietly wrong: a secure-state read of a secure page
/// through the NS alias returns ZEROS rather than faulting. That is exactly
/// how the FSBL halted on 2026-09-16, hashing 7,488 zero bytes and failing the
/// NS image comparison with no output.
#[test]
fn the_bank_two_secure_alias_is_distinct_from_the_nonsecure_one() {
    use pqsigner_geometry::{
        page_addr, page_addr_secure, Bank, BANK1_BASE, BANK2_BASE, BANK2_SECURE_BASE, PAGE_SIZE,
        PAGES_PER_BANK,
    };

    assert_eq!(BANK2_BASE, 0x0810_0000, "bank 2, non-secure alias");
    assert_eq!(BANK2_SECURE_BASE, 0x0C10_0000, "bank 2, secure alias");
    assert_ne!(
        BANK2_BASE, BANK2_SECURE_BASE,
        "if these were ever equal this whole distinction would be vacuous"
    );

    // Derived, not hard-coded: the secure aliases are contiguous across banks.
    assert_eq!(
        BANK2_SECURE_BASE,
        BANK1_BASE + u32::from(PAGES_PER_BANK) * PAGE_SIZE,
        "bank 2's secure base is bank 1's plus exactly one bank"
    );

    // Bank 1 is already the secure alias, so both accessors agree there.
    for page in [0u8, 7, 63, 127] {
        assert_eq!(
            page_addr(Bank::One, page),
            page_addr_secure(Bank::One, page),
            "bank 1 has one alias"
        );
    }
    // Bank 2 is where they diverge, by exactly one bank.
    for page in [0u8, 5, 65, 127] {
        assert_ne!(page_addr(Bank::Two, page), page_addr_secure(Bank::Two, page));
        assert_eq!(
            page_addr_secure(Bank::Two, page) - page_addr(Bank::Two, page),
            BANK2_SECURE_BASE - BANK2_BASE,
            "the offset between aliases is constant across pages"
        );
    }
}
