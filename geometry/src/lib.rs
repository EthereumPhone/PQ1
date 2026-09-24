//! pqsigner-geometry — the frozen Section-5 flash geometry registry
//! (Draft 1.1, post-errata-4, SHA-256 `abc058b1`).
//!
//! Every one of the 256 flash pages (2 banks × 128 × 8 KiB) has exactly
//! one owner here, including when the owning feature is disabled.
//! Reserved and retired roles remain explicit page owners rather than
//! ownerless gaps. There is no current boot-state role: bank-1 page 6's
//! sole current owner is manifest B.
//!
//! Compile-time checks (below, `const _`) reject every gap, overlap, or
//! second owner at build time; the host tests in `tests/registry.rs`
//! re-derive the same properties plus the exact address map. See
//! `Cargo.toml` for the consumer mandate and dependency policy.

#![no_std]

/// One flash page: 8 KiB (STM32U585AI, 128 pages per 1-MiB bank).
pub const PAGE_SIZE: u32 = 0x2000;
/// Bank-1 base address (secure bank).
pub const BANK1_BASE: u32 = 0x0C00_0000;
/// Bank-2 base address.
pub const BANK2_BASE: u32 = 0x0810_0000;

/// Bank-2 base through the **SECURE** alias.
///
/// [`BANK2_BASE`] is the NON-SECURE alias, which is the right answer only
/// while every bank-2 page is non-secure — true under this registry, where
/// bank 2 holds the FSBL mirror and both NS slots. It stops being true the
/// moment a secure watermark covers part of bank 2 (RM0456 §7.5.2 allows one
/// secure area per bank), and a secure-state read of a secure page through the
/// NS alias returns ZEROS rather than faulting: that is precisely how the FSBL
/// silently halted on 2026-09-16 hashing 7,488 zero bytes.
///
/// So [`page_addr`] is correct today and would be quietly wrong under such a
/// geometry. [`page_addr_secure`] exists so the distinction is explicit
/// instead of implied by a base constant's name.
///
/// Derivation, not a magic number: bank 1 is 1 MiB
/// (`PAGES_PER_BANK * PAGE_SIZE`), and the secure aliases are contiguous, so
/// bank 2's secure base is bank 1's plus one bank.
pub const BANK2_SECURE_BASE: u32 = BANK1_BASE + PAGES_PER_BANK as u32 * PAGE_SIZE;
/// Pages per bank.
pub const PAGES_PER_BANK: u8 = 128;

/// Complete FSBL span: bank pages 0–4, in both banks.
pub const FSBL_SPAN: u32 = 5 * PAGE_SIZE; // 40,960 B
/// FSBL initialized FLASH LOAD-span budget (§5; hard design failure, not
/// a test waiver).
pub const FSBL_MAX_LOAD_SPAN: u32 = 38_912;
/// Secure slot span (bank-1 pages 7–63 and 65–121).
pub const SECURE_SLOT_SPAN: u32 = 0x72000;
/// Nonsecure slot span (bank-2 pages 5–65 and 66–126).
pub const NS_SLOT_SPAN: u32 = 0x7A000;

/// Physical flash bank.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Bank {
    One = 0,
    Two = 1,
}

impl Bank {
    /// Both banks, in index order.
    pub const ALL: [Bank; 2] = [Bank::One, Bank::Two];

    /// Base address of this bank.
    pub const fn base(self) -> u32 {
        match self {
            Bank::One => BANK1_BASE,
            Bank::Two => BANK2_BASE,
        }
    }
}

/// The owner of a flash page. Every page has exactly one; retired roles
/// stay explicit (`ReservedErased`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Owner {
    /// Complete FSBL (bank-1 pages 0–4) or its byte-identical mirror
    /// (bank-2 pages 0–4).
    Fsbl,
    ManifestA,
    ManifestB,
    SecureSlotA,
    SecureSlotB,
    /// Route-1 rollback launch-journal page A (bank-1 page 64).
    Route1JournalA,
    /// Route-1 rollback launch-journal page B (bank-1 page 122).
    Route1JournalB,
    /// Off-chain/UserOp journal (bank-1 page 123).
    OffchainJournal,
    /// MCU PIN-attempt state (bank-1 page 124).
    McuPinState,
    /// Admin-wipe/duress state (bank-1 page 125).
    AdminWipeDuress,
    /// Wrapped SE050 BHK only (bank-1 page 126).
    WrappedBhk,
    /// First-boot provisioning journal + TRNG salt record (bank-1 page
    /// 127; §6.3 `FirstBootJournalWriter`). The Tropic01-key reservation
    /// formerly assigned here was retired with that backend's removal
    /// on 2026-07-14.
    FirstBootJournal,
    NsSlotA,
    NsSlotB,
    /// Bank-2 page 127: reserved/retired-page owner; must remain erased.
    ReservedErased,
}

/// One registry row: an inclusive page range in one bank with one owner.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Row {
    pub bank: Bank,
    pub first_page: u8,
    pub last_page: u8,
    pub owner: Owner,
}

/// The frozen Section-5 registry. Sorted, contiguous, and proven to
/// cover all 256 pages exactly once by the `const _` checks below.
pub const REGISTRY: [Row; 16] = [
    Row { bank: Bank::One, first_page: 0,   last_page: 4,   owner: Owner::Fsbl },
    Row { bank: Bank::One, first_page: 5,   last_page: 5,   owner: Owner::ManifestA },
    Row { bank: Bank::One, first_page: 6,   last_page: 6,   owner: Owner::ManifestB },
    Row { bank: Bank::One, first_page: 7,   last_page: 63,  owner: Owner::SecureSlotA },
    Row { bank: Bank::One, first_page: 64,  last_page: 64,  owner: Owner::Route1JournalA },
    Row { bank: Bank::One, first_page: 65,  last_page: 121, owner: Owner::SecureSlotB },
    Row { bank: Bank::One, first_page: 122, last_page: 122, owner: Owner::Route1JournalB },
    Row { bank: Bank::One, first_page: 123, last_page: 123, owner: Owner::OffchainJournal },
    Row { bank: Bank::One, first_page: 124, last_page: 124, owner: Owner::McuPinState },
    Row { bank: Bank::One, first_page: 125, last_page: 125, owner: Owner::AdminWipeDuress },
    Row { bank: Bank::One, first_page: 126, last_page: 126, owner: Owner::WrappedBhk },
    Row { bank: Bank::One, first_page: 127, last_page: 127, owner: Owner::FirstBootJournal },
    Row { bank: Bank::Two, first_page: 0,   last_page: 4,   owner: Owner::Fsbl },
    Row { bank: Bank::Two, first_page: 5,   last_page: 65,  owner: Owner::NsSlotA },
    Row { bank: Bank::Two, first_page: 66,  last_page: 126, owner: Owner::NsSlotB },
    Row { bank: Bank::Two, first_page: 127, last_page: 127, owner: Owner::ReservedErased },
];

/// Start address of a page. No validity requirement: `page` values at or
/// above [`PAGES_PER_BANK`] simply address past the bank.
pub const fn page_addr(bank: Bank, page: u8) -> u32 {
    bank.base() + page as u32 * PAGE_SIZE
}

/// Start address of a page through the SECURE alias.
///
/// Use this wherever the accessing code is in the secure state AND the page is
/// covered by a secure watermark. [`page_addr`] answers the other case (bank 1
/// is already the secure alias; bank 2's is the NS one). Reading a secure page
/// through the NS alias from secure state returns zeros, silently.
#[must_use]
pub const fn page_addr_secure(bank: Bank, page: u8) -> u32 {
    let base = match bank {
        Bank::One => BANK1_BASE,
        Bank::Two => BANK2_SECURE_BASE,
    };
    base + page as u32 * PAGE_SIZE
}

/// End-exclusive address of a page.
pub const fn page_end(bank: Bank, page: u8) -> u32 {
    page_addr(bank, page) + PAGE_SIZE
}

/// The owner of one page, or `None` for an out-of-range page number.
pub const fn owner_of(bank: Bank, page: u8) -> Option<Owner> {
    let mut i = 0;
    while i < REGISTRY.len() {
        let row = &REGISTRY[i];
        if matches!(row.bank, b if b as u8 == bank as u8)
            && row.first_page <= page
            && page <= row.last_page
        {
            return Some(row.owner);
        }
        i += 1;
    }
    None
}

/// §5 updater rule: an update may erase/program only the inactive
/// manifest page and the inactive secure/nonsecure slot ranges; it MUST
/// preserve both FSBL copies, both Route-1 journal pages, bank-1 pages
/// 123–127, and bank-2 page 127.
pub const fn updater_must_preserve(bank: Bank, page: u8) -> bool {
    match owner_of(bank, page) {
        Some(Owner::Fsbl)
        | Some(Owner::Route1JournalA)
        | Some(Owner::Route1JournalB)
        | Some(Owner::OffchainJournal)
        | Some(Owner::McuPinState)
        | Some(Owner::AdminWipeDuress)
        | Some(Owner::WrappedBhk)
        | Some(Owner::FirstBootJournal)
        | Some(Owner::ReservedErased) => true,
        _ => false,
    }
}

/// Pages owned by a Route-1 rollback launch-journal (bank-1 only, a
/// symmetric pairwise-disjoint pair).
pub const ROUTE1_JOURNAL_PAGES: [u8; 2] = [64, 122];

/// First-boot provisioning journal page (bank-1 only).
pub const FIRST_BOOT_JOURNAL_PAGE: u8 = 127;

// ---------------------------------------------------------------------------
// Compile-time exact-once coverage proof.
// ---------------------------------------------------------------------------

/// True iff REGISTRY assigns every one of the 256 pages exactly one
/// owner: no gap, no overlap, no second owner, no out-of-bank range.
const fn covers_all_pages_exactly_once() -> bool {
    let mut covered = [false; 256];
    let mut i = 0;
    while i < REGISTRY.len() {
        let row = &REGISTRY[i];
        if row.first_page > row.last_page || row.last_page >= PAGES_PER_BANK {
            return false;
        }
        let mut page = row.first_page;
        loop {
            let idx = (row.bank as usize) * (PAGES_PER_BANK as usize) + page as usize;
            if covered[idx] {
                return false; // overlap / second owner
            }
            covered[idx] = true;
            if page == row.last_page {
                break;
            }
            page += 1;
        }
        i += 1;
    }
    let mut idx = 0;
    while idx < 256 {
        if !covered[idx] {
            return false; // gap
        }
        idx += 1;
    }
    true
}

/// True iff rows are sorted by (bank, first_page) and each row's first
/// page is exactly one past the previous row's last page within a bank
/// (contiguity — the prose counterpart of the bitmap proof above).
const fn rows_sorted_and_contiguous() -> bool {
    let mut i = 1;
    while i < REGISTRY.len() {
        let prev = &REGISTRY[i - 1];
        let row = &REGISTRY[i];
        if (prev.bank as u8) > (row.bank as u8) {
            return false;
        }
        if prev.bank as u8 == row.bank as u8 && row.first_page as u16 != prev.last_page as u16 + 1 {
            return false;
        }
        i += 1;
    }
    // First row starts each bank at page 0; last row of each bank ends at 127.
    if REGISTRY[0].first_page != 0 || REGISTRY[12].first_page != 0 {
        return false;
    }
    if REGISTRY[11].last_page != 127 || REGISTRY[15].last_page != 127 {
        return false;
    }
    true
}

const _: () = assert!(
    covers_all_pages_exactly_once(),
    "geometry registry must assign every one of the 256 pages exactly one owner"
);
const _: () = assert!(
    rows_sorted_and_contiguous(),
    "geometry registry rows must be sorted and contiguous per bank"
);
// Route-1 journal pages are a symmetric, pairwise-disjoint, bank-1 pair.
const _: () = assert!(
    matches!(owner_of(Bank::One, ROUTE1_JOURNAL_PAGES[0]), Some(Owner::Route1JournalA))
        && matches!(owner_of(Bank::One, ROUTE1_JOURNAL_PAGES[1]), Some(Owner::Route1JournalB)),
    "Route-1 journal pages 64/122 must be the bank-1 journal pair"
);
// The first-boot journal owns bank-1 page 127 outright.
const _: () = assert!(
    matches!(owner_of(Bank::One, FIRST_BOOT_JOURNAL_PAGE), Some(Owner::FirstBootJournal)),
    "bank-1 page 127 must be the first-boot provisioning journal"
);
// Bank-2 page 127 must remain erased under a retired-page owner.
const _: () = assert!(
    matches!(owner_of(Bank::Two, 127), Some(Owner::ReservedErased)),
    "bank-2 page 127 must be the reserved/retired page"
);
