//! Wire-format stability: byte-exact pins of every constant a deployed
//! DB blob or remote dapp depends on.
//!
//! The ERC-20 / names / selectors DBs are firmware-signed: every Merkle
//! root commits to canonical leaf bytes computed from these constants.
//! A "tidy-up" rename (`MAX_DISPLAY_FIELD` from 64 → 60) or constant
//! re-numbering would silently invalidate every signed blob shipped
//! against the previous values. These tests turn drift into an instant
//! red CI line citing the field that moved.

use pqsigner_tx::erc20::bundle::MAX_ERC20_BUNDLE_LEN;
use pqsigner_tx::erc20::calldata::{
    SELECTOR_APPROVE, SELECTOR_TRANSFER, SELECTOR_TRANSFER_FROM,
};
use pqsigner_tx::names::{MAX_NAME_BUNDLES, MAX_NAME_BUNDLE_LEN};
use pqsigner_tx::selectors::{MAX_SELECTOR_BUNDLE_LEN, MAX_SELF_ATTEST_BUNDLE_LEN};
use sphincs_tz_shared::db_format::{
    NAMES_MAX_LEN, NAMES_WILDCARD_CHAIN_ID, SELECTOR_TEXT_SIG_MAX_LEN,
};

#[test]
fn pin_erc20_selectors_exact_bytes() {
    // Every shipping ERC-20 implementation, every dapp's call-data
    // signer, and every test fixture in this repo encodes these
    // selectors. They are public, ossified, and irreversible.
    assert_eq!(SELECTOR_TRANSFER, [0xa9, 0x05, 0x9c, 0xbb]);
    assert_eq!(SELECTOR_TRANSFER_FROM, [0x23, 0xb8, 0x72, 0xdd]);
    assert_eq!(SELECTOR_APPROVE, [0x09, 0x5e, 0xa7, 0xb3]);
}

#[test]
fn pin_erc20_bundle_size_envelope() {
    // The MAX is documented as "~1.1 KB". Anything below 1 KB would
    // fail to fit a real curated entry; anything above 8 KB would mean
    // a stack-budget audit needs to happen.
    assert_eq!(MAX_ERC20_BUNDLE_LEN, 64 + 1024 + 32,
        "MAX_ERC20_BUNDLE_LEN drift breaks the secure-side stack buffer sizing");
}

#[test]
fn pin_name_bundle_size_envelope() {
    let expected = 8 + 20 + 1 + NAMES_MAX_LEN + 4 + 4 + 32 * 32;
    assert_eq!(MAX_NAME_BUNDLE_LEN, expected,
        "MAX_NAME_BUNDLE_LEN must remain {expected} bytes");
}

#[test]
fn pin_selector_bundle_size_envelope() {
    let expected_full = 4 + 1 + SELECTOR_TEXT_SIG_MAX_LEN + 4 + 4 + 32 * 32;
    assert_eq!(MAX_SELECTOR_BUNDLE_LEN, expected_full);
    let expected_self = 4 + 1 + SELECTOR_TEXT_SIG_MAX_LEN;
    assert_eq!(MAX_SELF_ATTEST_BUNDLE_LEN, expected_self);
}

#[test]
fn pin_resolver_capacity() {
    // MAX_NAME_BUNDLES = 4 is what the NS-side payload size caps on.
    // A larger value here without the NS / display update would mean
    // a hostile NS could exhaust the secure-side fixed buffer; a
    // smaller value would silently drop curated names.
    assert_eq!(MAX_NAME_BUNDLES, 4);
}

#[test]
fn pin_names_wildcard_sentinel_is_zero() {
    assert_eq!(NAMES_WILDCARD_CHAIN_ID, 0,
        "NAMES_WILDCARD_CHAIN_ID drift would break the phase-1-vs-phase-2 \
         resolver dispatch in NameResolver::lookup");
}

#[test]
fn pin_selector_text_sig_fits_in_u8_length() {
    // bundle.rs reads `text_sig_len` as a single `u8`. If
    // SELECTOR_TEXT_SIG_MAX_LEN ever exceeds 255 the wire parser
    // silently wraps modulo 256 and the new max becomes a different
    // value than the constant.
    assert!(SELECTOR_TEXT_SIG_MAX_LEN <= u8::MAX as usize,
        "selector text_sig length is a single u8 on the wire");
}

#[test]
fn pin_names_max_len_fits_in_u8_length() {
    assert!(NAMES_MAX_LEN <= u8::MAX as usize,
        "names name_len is a single u8 on the wire");
}
