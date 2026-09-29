//! Host-side positive + negative test suite for the
//! `secure-crypto-glue` slice.
//!
//! See `mod.rs` for what this file is, why it pins what it pins, and
//! which slice files are reachable on host vs. covered only by
//! `include_str!` source-text invariants.

#![cfg(test)]

use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::db_roots::{ERC20_DB_ROOT, NAMES_DB_ROOT, SELECTOR_DB_ROOT};

use super::offchain_state::{
    clamp_offchain_count, forced_capacity_receipt_from_snapshot,
    forced_final_tally_pair_proof, last_userop_count_read, last_userop_count_set,
    may_create_distinct_slot, offchain_count_bump, offchain_count_is_registered,
    offchain_count_promote_to, offchain_count_read, offchain_count_register_slot,
    slot_key_compute, ForcedCapacityError, ForcedCapacitySnapshot,
    FORCED_CAPACITY_REQUIRED_APPENDS, MAX_DISTINCT_SLOTS, OFFCHAIN_CAPACITY_QWS,
    OFFCHAIN_COUNT_CEILING,
};
use sphincs_tz_shared::MAX_SLOT_USES;
use std::sync::{Mutex, MutexGuard};

// The SRAM backend models firmware's single-threaded dispatcher with a
// `static mut` table. Host tests run in parallel, so every test that touches
// that table must serialize just as production does; otherwise a concurrent
// write can legitimately make the capacity helper's two snapshots disagree.
static OFFCHAIN_MOCK_TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock_offchain_mock() -> MutexGuard<'static, ()> {
    OFFCHAIN_MOCK_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ─────────────────────────────────────────────────────────────────────
// 0. Slice source-text fixtures.
// ─────────────────────────────────────────────────────────────────────

const CRYPTO_SRC: &str = include_str!("../crypto.rs");
const DUAL_SE_SRC: &str = include_str!("../dual_se.rs");
const OFFCHAIN_SRC: &str = include_str!("../offchain_state.rs");
// Flash-backed journal is stm32u585-only and host-untested at runtime; pin the
// Layer-2 distinct-slot cap wiring (page-123 exhaustion fix) as source text.
const FLASH_SRC: &str = include_str!("../hw/flash.rs");
const AA_SHIM_SRC: &str = include_str!("../aa/mod.rs");
const ERC20_SHIM_SRC: &str = include_str!("../erc20/mod.rs");
const NAMES_SHIM_SRC: &str = include_str!("../names/mod.rs");
const SELECTORS_SHIM_SRC: &str = include_str!("../selectors/mod.rs");
const DB_ROOTS_SRC: &str = include_str!("../db_roots.rs");

// =====================================================================
//  PART A — `db_roots.rs` (Merkle roots embedded in firmware).
// =====================================================================

#[test]
fn positive_all_db_roots_are_32_bytes() {
    assert_eq!(ERC20_DB_ROOT.len(), 32);
    assert_eq!(NAMES_DB_ROOT.len(), 32);
    assert_eq!(SELECTOR_DB_ROOT.len(), 32);
}

#[test]
fn positive_all_db_roots_are_non_zero() {
    // A zero root would match the merkle verifier's "no proof"
    // shortcut and let any bundle through. `dbgen` only emits a
    // zero root on an empty DB, which is never the production case.
    for (name, root) in &[
        ("ERC20_DB_ROOT", &ERC20_DB_ROOT),
        ("NAMES_DB_ROOT", &NAMES_DB_ROOT),
        ("SELECTOR_DB_ROOT", &SELECTOR_DB_ROOT),
    ] {
        let acc = root.iter().fold(0u8, |a, b| a | b);
        assert_ne!(
            acc, 0,
            "{name} is all-zero — every bundle would verify against an empty DB",
        );
    }
}

#[test]
fn positive_db_roots_are_pairwise_distinct() {
    // Each root anchors a distinct trust domain; aliasing two of them
    // (e.g. shipping the same blob for ERC20 + names) would let a
    // valid ERC20 bundle masquerade as a name resolution and vice
    // versa.
    let roots = [
        ("ERC20", &ERC20_DB_ROOT),
        ("NAMES", &NAMES_DB_ROOT),
        ("SELECTOR", &SELECTOR_DB_ROOT),
    ];
    for i in 0..roots.len() {
        for j in (i + 1)..roots.len() {
            let (a, b) = (roots[i], roots[j]);
            assert_ne!(
                a.1, b.1,
                "{} == {} — distinct trust domains must have distinct roots",
                a.0, b.0,
            );
        }
    }
}

#[test]
fn negative_selector_root_e2e_differs_from_production_root() {
    // The `e2e-test` Cargo feature swaps in a smaller selectors-DB
    // fixture root so the QEMU NS test driver can carry a tiny
    // companion-stub blob without overflowing flash. Pinning the
    // assumption: the two roots must NOT be equal — otherwise an
    // e2e-test build would silently accept production-curated
    // bundles (or vice versa), defeating the size optimisation and
    // its security goal.
    let prod_root: [u8; 32] = [
        0x75, 0x1c, 0xaf, 0x52, 0x05, 0xa4, 0xff, 0x59, 0x01, 0xab, 0x64, 0x78, 0xaf, 0x91, 0xff,
        0x36, 0x33, 0x8f, 0x87, 0x4b, 0x86, 0x83, 0x78, 0xc6, 0x10, 0xb6, 0x93, 0x94, 0x74, 0x56,
        0xe4, 0x6a,
    ];
    let e2e_root: [u8; 32] = [
        0xbd, 0x11, 0x0c, 0xa4, 0xc9, 0x16, 0x11, 0x7f, 0xe5, 0x11, 0x69, 0x06, 0x2d, 0x5f, 0xea,
        0xc0, 0x97, 0x8c, 0x41, 0x1f, 0x45, 0xea, 0xd0, 0xdc, 0xc0, 0x32, 0x9e, 0xb7, 0x0c, 0x14,
        0xc1, 0x99,
    ];
    assert_ne!(
        prod_root, e2e_root,
        "production + e2e selector roots collapsed to the same value — \
         the e2e fixture must remain distinct from the curated DB",
    );
}

#[test]
fn positive_db_roots_source_has_dbgen_provenance_comment() {
    // The roots are codegen output from `cargo run -p dbgen`. The
    // comment is load-bearing for the audit trail: it tells a future
    // reviewer the bytes are not hand-rolled and points at the
    // single source of truth. Pin it.
    assert!(
        DB_ROOTS_SRC.contains("DO NOT EDIT BY HAND"),
        "db_roots.rs must keep the hand-edit warning so the dbgen \
         provenance is unambiguous",
    );
    assert!(
        DB_ROOTS_SRC.contains("dbgen"),
        "db_roots.rs must name the generator (`dbgen`) for traceability",
    );
}

#[test]
fn positive_selector_root_is_cfg_gated_on_e2e_test() {
    // The Cargo feature `e2e-test` swaps the selector root with a
    // smaller fixture. The cfg-gate must be present + complementary
    // (one cfg(not(...)), one cfg(...)).
    assert!(
        DB_ROOTS_SRC.contains("#[cfg(not(feature = \"e2e-test\"))]"),
        "SELECTOR_DB_ROOT prod path missing #[cfg(not(feature = \"e2e-test\"))]",
    );
    assert!(
        DB_ROOTS_SRC.contains("#[cfg(feature = \"e2e-test\")]"),
        "SELECTOR_DB_ROOT e2e path missing #[cfg(feature = \"e2e-test\")]",
    );
}

// =====================================================================
//  PART B — `aa/mod.rs` (pure re-export shim over `pqsigner-aa`).
// =====================================================================

#[test]
fn positive_aa_shim_re_exports_three_submodules() {
    // The shim is intentionally tiny — three `pub use`s that map
    // pqsigner_aa's `userop`, `eip1271`, `eip6492` into the secure
    // crate's namespace. Drift breaks every gateway call site.
    assert!(AA_SHIM_SRC.contains("pub use pqsigner_aa::eip1271;"));
    assert!(AA_SHIM_SRC.contains("pub use pqsigner_aa::eip6492;"));
    assert!(AA_SHIM_SRC.contains("pub use pqsigner_aa::userop;"));
}

#[test]
fn positive_aa_userop_parse_header_re_export_resolves() {
    // Belt-and-braces: the secure-side path
    // `crate::aa::userop::parse_header` (which the fuzz harness and
    // gateway dispatch both call) is reachable. Short header → error.
    let short = vec![0u8; sphincs_tz_shared::USEROP_HEADER_LEN - 1];
    assert!(crate::aa::userop::parse_header(&short).is_err());
}

#[test]
fn positive_aa_userop_parse_header_minimum_length_accepted() {
    let buf = vec![0u8; sphincs_tz_shared::USEROP_HEADER_LEN];
    let parsed = crate::aa::userop::parse_header(&buf).expect("min-length header parses");
    assert_eq!(parsed.sender, [0u8; 20]);
    assert_eq!(parsed.chain_id, 0);
}

#[test]
fn negative_aa_userop_parse_header_empty_input_rejected() {
    // CLAUDE.md: NS pointers / NS buffers must never crash secure
    // parsers. Empty input is the smallest hostile case.
    let empty: &[u8] = &[];
    assert!(crate::aa::userop::parse_header(empty).is_err());
}

#[test]
fn positive_aa_eip1271_proxy_address_is_deterministic() {
    let seed = [0x11u8; 32];
    let root = [0x22u8; 32];
    let a = crate::aa::eip1271::proxy_address(&seed, &root);
    let b = crate::aa::eip1271::proxy_address(&seed, &root);
    assert_eq!(a, b, "proxy_address must be deterministic across calls");
}

#[test]
fn positive_aa_eip1271_proxy_address_depends_on_seed() {
    let seed_a = [0x11u8; 32];
    let seed_b = [0x12u8; 32];
    let root = [0x22u8; 32];
    let a = crate::aa::eip1271::proxy_address(&seed_a, &root);
    let b = crate::aa::eip1271::proxy_address(&seed_b, &root);
    assert_ne!(
        a, b,
        "different seeds must yield different proxy addresses; \
         invariant #6 (cross-chain address stability) depends on this",
    );
}

#[test]
fn positive_aa_eip1271_proxy_address_depends_on_root() {
    let seed = [0x11u8; 32];
    let root_a = [0x22u8; 32];
    let root_b = [0x23u8; 32];
    let a = crate::aa::eip1271::proxy_address(&seed, &root_a);
    let b = crate::aa::eip1271::proxy_address(&seed, &root_b);
    assert_ne!(
        a, b,
        "different roots must yield different proxy addresses",
    );
}

#[test]
fn positive_aa_eip1271_domain_separator_depends_on_chain_id() {
    let addr = [0x33u8; 20];
    let d1 = crate::aa::eip1271::domain_separator(1, &addr);
    let d137 = crate::aa::eip1271::domain_separator(137, &addr);
    assert_ne!(
        d1, d137,
        "domain separator must include chain_id — replay across chains otherwise possible",
    );
}

#[test]
fn positive_aa_eip1271_personal_sign_hash_replay_safe_includes_contract() {
    let addr_a = [0x33u8; 20];
    let addr_b = [0x34u8; 20];
    let h_a = crate::aa::eip1271::personal_sign_replay_safe_hash(1, &addr_a, b"hello");
    let h_b = crate::aa::eip1271::personal_sign_replay_safe_hash(1, &addr_b, b"hello");
    assert_ne!(
        h_a, h_b,
        "replay-safe hash must include verifyingContract — \
         signatures must not be cross-wallet-replayable",
    );
}

#[test]
fn positive_aa_eip1271_personal_sign_hash_includes_message() {
    let addr = [0x33u8; 20];
    let h_a = crate::aa::eip1271::personal_sign_replay_safe_hash(1, &addr, b"hello");
    let h_b = crate::aa::eip1271::personal_sign_replay_safe_hash(1, &addr, b"hellp");
    assert_ne!(h_a, h_b);
}

#[test]
fn positive_aa_userop_keccak_empty_is_known_constant() {
    // KECCAK_EMPTY is `keccak256("")`. Pinning the value here
    // catches a future "let's recompute it lazily" refactor that
    // accidentally produces sha256 or empty array zeroes.
    use sha3::{Digest as _, Keccak256};
    let mut k = Keccak256::new();
    k.update(b"");
    let expected: [u8; 32] = k.finalize().into();
    assert_eq!(
        crate::aa::userop::KECCAK_EMPTY,
        expected,
        "KECCAK_EMPTY constant has drifted from keccak256(\"\")",
    );
}

#[test]
fn positive_aa_userop_sha256_empty_is_known_constant() {
    // SHA256_EMPTY is `sha256("")`. EntryPoint v0.6 + the SHA-256
    // sphincs digest both substitute this for empty initCode /
    // paymasterAndData. A wrong value breaks every userOpHash.
    let mut h = Sha256::new();
    h.update(b"");
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(
        crate::aa::userop::SHA256_EMPTY,
        expected,
        "SHA256_EMPTY constant has drifted from sha256(\"\")",
    );
}

#[test]
fn positive_aa_userop_entry_point_v06_address_is_canonical() {
    // Invariant #6 from CLAUDE.md: EntryPoint v0.6 address is baked
    // into initCode + userOpHash preimage + factory. Bumping the
    // version changes the CREATE2 init-code hash and breaks
    // cross-chain address stability.
    let expected: [u8; 20] = [
        0x5F, 0xF1, 0x37, 0xD4, 0xb0, 0xFD, 0xCD, 0x49, 0xDc, 0xA3, 0x0c, 0x7C, 0xF5, 0x7E, 0x57,
        0x8a, 0x02, 0x6d, 0x27, 0x89,
    ];
    assert_eq!(
        crate::aa::userop::ENTRY_POINT_V06,
        expected,
        "EntryPoint v0.6 address changed — invariant #6 violated; \
         the v0.6 instance is the frozen target",
    );
}

#[test]
fn negative_aa_shim_contains_no_unused_re_exports() {
    // Pinning the shim's scope: it is a re-export shim, not a place
    // to add new logic. Anything that isn't a `pub use` is suspect.
    let nontrivial_lines: Vec<&str> = AA_SHIM_SRC
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with("//") && !t.starts_with("//!")
        })
        .collect();
    assert!(
        nontrivial_lines.len() <= 6,
        "aa/mod.rs grew beyond a re-export shim — {} non-trivial lines: {:?}. \
         Logic belongs in the pure-logic `pqsigner-aa` crate, not the secure-side shim.",
        nontrivial_lines.len(),
        nontrivial_lines,
    );
}

// =====================================================================
//  PART C — `erc20/mod.rs` shim + `db_roots`-threading wrapper.
// =====================================================================

// ── Minimal-but-real Merkle helpers, byte-compatible with
// `tx::erc20::merkle::verify_proof`. Lets us build verifying bundles
// against a *known* root, then prove the shim wrapper rejects them
// when threaded through `db_roots::ERC20_DB_ROOT` (which we don't
// know the preimage of). That proves the shim doesn't ignore the
// root parameter.

fn leaf_hash(canonical: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(canonical);
    h.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn single_leaf_tree(canonical: &[u8]) -> ([u8; 32], Vec<[u8; 32]>) {
    // Smallest balanced tree: duplicate the single leaf so the
    // verifier's `proof_depth = 1` walk converges to the root.
    let l = leaf_hash(canonical);
    let root = node_hash(&l, &l);
    (root, vec![l])
}

fn build_erc20_bundle(
    chain_id: u64,
    contract: [u8; 20],
    decimals: u8,
    name: &[u8],
    symbol: &[u8],
    leaf_index: u32,
    proof: &[[u8; 32]],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&chain_id.to_le_bytes());
    v.extend_from_slice(&contract);
    v.push(decimals);
    v.push(name.len() as u8);
    v.extend_from_slice(name);
    v.push(symbol.len() as u8);
    v.extend_from_slice(symbol);
    v.extend_from_slice(&leaf_index.to_le_bytes());
    v.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    for s in proof {
        v.extend_from_slice(s);
    }
    v
}

fn canonical_erc20_leaf(
    chain_id: u64,
    contract: &[u8; 20],
    decimals: u8,
    name: &[u8],
    symbol: &[u8],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&chain_id.to_le_bytes());
    v.extend_from_slice(contract);
    v.push(decimals);
    v.push(name.len() as u8);
    v.extend_from_slice(name);
    v.push(symbol.len() as u8);
    v.extend_from_slice(symbol);
    v
}

#[test]
fn positive_erc20_bundle_pure_verifier_round_trips_under_synthetic_root() {
    // Sanity: the underlying pure verifier accepts a self-consistent
    // bundle when given the matching root. The shim wrapper threads
    // a *different* root (the firmware-embedded one), which we test
    // against in the negative case below.
    let canonical = canonical_erc20_leaf(1, &[0x33; 20], 18, b"USD Coin", b"USDC");
    let (root, proof) = single_leaf_tree(&canonical);
    let bundle = build_erc20_bundle(1, [0x33; 20], 18, b"USD Coin", b"USDC", 0, &proof);

    let meta = pqsigner_tx::erc20::bundle::verify_erc20_bundle(&bundle, &root)
        .expect("pure verifier accepts self-consistent bundle");
    assert_eq!(meta.decimals, 18);
    assert_eq!(meta.name, b"USD Coin");
    assert_eq!(meta.symbol, b"USDC");
}

#[test]
fn negative_erc20_shim_rejects_bundle_built_under_a_different_root() {
    // Build a bundle that verifies under our synthetic test root
    // (we know its preimage). The shim wrapper threads
    // `db_roots::ERC20_DB_ROOT` (which is the firmware curated-DB
    // root, with no public preimage). The bundle MUST fail when
    // routed through the shim — otherwise the shim is ignoring the
    // root parameter and any NS-supplied bundle would be accepted.
    let canonical = canonical_erc20_leaf(1, &[0x33; 20], 18, b"USD Coin", b"USDC");
    let (_synthetic_root, proof) = single_leaf_tree(&canonical);
    let bundle = build_erc20_bundle(1, [0x33; 20], 18, b"USD Coin", b"USDC", 0, &proof);

    assert!(
        crate::erc20::bundle::verify_erc20_bundle(&bundle).is_none(),
        "erc20 shim accepted a bundle built under a non-firmware root — \
         the shim is not threading db_roots::ERC20_DB_ROOT",
    );
}

#[test]
fn negative_erc20_shim_rejects_empty_input() {
    assert!(crate::erc20::bundle::verify_erc20_bundle(&[]).is_none());
}

#[test]
fn negative_erc20_shim_rejects_truncated_bundle() {
    // Header is 8 (chain) + 20 (contract) + 1 (decimals) + 1
    // (name_len) = 30 bytes minimum. Anything shorter must fail
    // before the merkle walk.
    let buf = vec![0u8; 29];
    assert!(crate::erc20::bundle::verify_erc20_bundle(&buf).is_none());
}

#[test]
fn negative_erc20_shim_rejects_non_ascii_name() {
    // CLAUDE.md anti-spoof: every renderable name byte must be
    // printable ASCII. A 0xFF byte in `name` must be rejected even
    // before the merkle walk — the shim must enforce this via the
    // pure verifier.
    let bad_name: Vec<u8> = vec![b'U', 0xFF, b'D'];
    let mut bundle = Vec::new();
    bundle.extend_from_slice(&1u64.to_le_bytes());
    bundle.extend_from_slice(&[0x33u8; 20]);
    bundle.push(18);
    bundle.push(bad_name.len() as u8);
    bundle.extend_from_slice(&bad_name);
    bundle.push(4);
    bundle.extend_from_slice(b"USDC");
    bundle.extend_from_slice(&0u32.to_le_bytes());
    bundle.extend_from_slice(&0u32.to_le_bytes());
    assert!(crate::erc20::bundle::verify_erc20_bundle(&bundle).is_none());
}

#[test]
fn positive_erc20_shim_threads_db_roots_constant() {
    // Source-text pin: the shim wrapper must reference
    // `crate::db_roots::ERC20_DB_ROOT` as the threaded root. A
    // refactor that renames the constant must surface here before
    // hitting silicon.
    assert!(
        ERC20_SHIM_SRC.contains("crate::db_roots::ERC20_DB_ROOT")
            || ERC20_SHIM_SRC.contains("use crate::db_roots::ERC20_DB_ROOT"),
        "erc20 shim no longer threads db_roots::ERC20_DB_ROOT",
    );
}

// =====================================================================
//  PART D — `names/mod.rs` shim + `db_roots`-threading wrapper.
// =====================================================================

#[test]
fn negative_names_shim_rejects_bundle_built_under_a_different_root() {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(&1u64.to_le_bytes());
    canonical.extend_from_slice(&[0x44u8; 20]);
    canonical.push(5);
    canonical.extend_from_slice(b"Alice");
    let (_root, proof) = single_leaf_tree(&canonical);

    let mut bundle = Vec::new();
    bundle.extend_from_slice(&1u64.to_le_bytes());
    bundle.extend_from_slice(&[0x44u8; 20]);
    bundle.push(5);
    bundle.extend_from_slice(b"Alice");
    bundle.extend_from_slice(&0u32.to_le_bytes());
    bundle.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    for s in &proof {
        bundle.extend_from_slice(s);
    }

    assert!(
        crate::names::verify_name_bundle(&bundle).is_none(),
        "names shim accepted a bundle built under a non-firmware root — \
         the shim is not threading db_roots::NAMES_DB_ROOT",
    );
}

#[test]
fn negative_names_shim_rejects_empty_input() {
    assert!(crate::names::verify_name_bundle(&[]).is_none());
}

#[test]
fn positive_names_shim_threads_db_roots_constant() {
    assert!(
        NAMES_SHIM_SRC.contains("crate::db_roots::NAMES_DB_ROOT")
            || NAMES_SHIM_SRC.contains("use crate::db_roots::NAMES_DB_ROOT"),
        "names shim no longer threads db_roots::NAMES_DB_ROOT",
    );
}

// =====================================================================
//  PART E — `selectors/mod.rs` shim + `db_roots`-threading wrapper.
// =====================================================================

#[test]
fn negative_selectors_shim_rejects_bundle_built_under_a_different_root() {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    let text = b"transfer(address,uint256)";
    canonical.push(text.len() as u8);
    canonical.extend_from_slice(text);
    let (_root, proof) = single_leaf_tree(&canonical);

    let mut bundle = Vec::new();
    bundle.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    bundle.push(text.len() as u8);
    bundle.extend_from_slice(text);
    bundle.extend_from_slice(&0u32.to_le_bytes());
    bundle.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    for s in &proof {
        bundle.extend_from_slice(s);
    }

    assert!(
        crate::selectors::bundle::verify_selector_bundle(&bundle).is_none(),
        "selectors shim accepted a bundle built under a non-firmware root — \
         the shim is not threading db_roots::SELECTOR_DB_ROOT",
    );
}

#[test]
fn negative_selectors_shim_self_attest_parses_self_consistent_bundle() {
    // The self-attest bundle is parsed purely (no root threading),
    // so the shim doesn't have to refuse — but a malformed bundle
    // still must.
    let text = b"transfer(address,uint256)";
    let mut k = Keccak256::new();
    sha3::digest::Update::update(&mut k, text);
    let h = sha3::digest::FixedOutput::finalize_fixed(k);
    let sel: [u8; 4] = h[0..4].try_into().unwrap();

    let mut b = Vec::new();
    b.extend_from_slice(&sel);
    b.push(text.len() as u8);
    b.extend_from_slice(text);
    let meta = crate::selectors::bundle::parse_self_attest_bundle(&b).expect("self-attest happy");
    assert_eq!(meta.selector, sel);
    assert_eq!(meta.text_sig, text);
}

#[test]
fn negative_selectors_shim_self_attest_rejects_keccak_mismatch() {
    let text = b"transfer(address,uint256)";
    let wrong_sel = [0xde, 0xad, 0xbe, 0xef];
    let mut b = Vec::new();
    b.extend_from_slice(&wrong_sel);
    b.push(text.len() as u8);
    b.extend_from_slice(text);
    assert!(
        crate::selectors::bundle::parse_self_attest_bundle(&b).is_none(),
        "self-attest must verify keccak256(text_sig)[..4] == selector",
    );
}

#[test]
fn positive_selectors_shim_threads_db_roots_constant() {
    assert!(
        SELECTORS_SHIM_SRC.contains("crate::db_roots::SELECTOR_DB_ROOT"),
        "selectors shim no longer threads db_roots::SELECTOR_DB_ROOT",
    );
}

#[test]
fn positive_selectors_shim_exposes_compat_alias_bundle_module() {
    // Source pin: a nested `bundle` re-export is the back-compat
    // bridge for the secure-world call sites that import
    // `crate::selectors::bundle::verify_selector_bundle(...)`.
    // Removing it silently would compile-break only the call sites
    // that still use the alias path — surface that here.
    assert!(
        SELECTORS_SHIM_SRC.contains("pub mod bundle"),
        "selectors shim must keep the `bundle` back-compat alias",
    );
}

// ── Top-level `crate::selectors::verify_selector_bundle` (shim L17-19) ──
//
// The tests above only exercise the back-compat alias
// (`crate::selectors::bundle::verify_selector_bundle`); the top-level
// wrapper needs its own proof, including a POSITIVE one. A positive
// bundle must verify against the firmware-embedded `SELECTOR_DB_ROOT`,
// whose preimage is the checked-in corpus — so rebuild the Merkle DB
// with dbgen (already the suite's fixture compiler for the ERC-7730
// render tests) and extract a real (entry, proof) pair from it. The
// root-equality assert makes any corpus↔firmware drift fail loudly
// here rather than silently refusing every production bundle.

#[cfg(feature = "e2e-test")]
const SELECTORS_CORPUS_JSON: &str = "secure/data/selectors-e2e.json";
#[cfg(not(feature = "e2e-test"))]
const SELECTORS_CORPUS_JSON: &str = "secure/data/selectors.json";

fn selectors_workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("secure/ has a workspace parent")
        .to_path_buf()
}

/// Rebuild the selectors Merkle DB from the checked-in corpus, pin the
/// regenerated root to the firmware-embedded one, then assemble the
/// exact on-wire bundle for `want_selector`:
/// `selector(4) | text_sig_len(1) | text_sig | leaf_index(u32 LE) |
///  proof_depth(u32 LE) | proof`.
fn build_embedded_root_selector_bundle(want_selector: [u8; 4]) -> Vec<u8> {
    use sphincs_tz_shared::db_format::*;
    let res = dbgen::selectors::build_db(&selectors_workspace_root().join(SELECTORS_CORPUS_JSON))
        .expect("checked-in selectors corpus must rebuild");
    assert_eq!(
        res.root, SELECTOR_DB_ROOT,
        "checked-in selectors corpus and firmware-embedded SELECTOR_DB_ROOT drifted apart",
    );

    let blob = &res.blob;
    let entry_cnt = read_u32_le(blob, SELECTOR_HDR_OFF_ENTRY_CNT) as usize;
    let pool_off = read_u32_le(blob, SELECTOR_HDR_OFF_POOL_OFF) as usize;
    let proof_depth = read_u32_le(blob, SELECTOR_HDR_OFF_PROOF_DEPTH) as usize;
    let proofs_off = read_u32_le(blob, SELECTOR_HDR_OFF_PROOFS_OFF) as usize;

    // Entries are sorted by selector — binary-search the target.
    let mut lo = 0usize;
    let mut hi = entry_cnt;
    let index = loop {
        assert!(lo < hi, "selector {want_selector:02x?} missing from corpus");
        let mid = (lo + hi) / 2;
        let off = SELECTOR_DB_HEADER_LEN + mid * SELECTOR_DB_ENTRY_LEN;
        match blob[off..off + 4].cmp(want_selector.as_slice()) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => break mid,
        }
    };

    let entry_off = SELECTOR_DB_HEADER_LEN + index * SELECTOR_DB_ENTRY_LEN;
    let text_off = read_u32_le(blob, entry_off + SELECTOR_ENTRY_OFF_TEXT_OFF) as usize;
    let text_len = blob[pool_off + text_off] as usize;
    let text_sig = &blob[pool_off + text_off + 1..pool_off + text_off + 1 + text_len];

    let mut bundle = Vec::new();
    bundle.extend_from_slice(&want_selector);
    bundle.push(text_len as u8);
    bundle.extend_from_slice(text_sig);
    bundle.extend_from_slice(&(index as u32).to_le_bytes());
    bundle.extend_from_slice(&(proof_depth as u32).to_le_bytes());
    let proof_base = proofs_off + index * proof_depth * 32;
    bundle.extend_from_slice(&blob[proof_base..proof_base + proof_depth * 32]);
    bundle
}

#[test]
fn positive_selectors_shim_accepts_bundle_from_the_shipped_corpus() {
    // The positive counterpart to the synthetic-root rejection above:
    // the wrapper must not only refuse foreign roots, it must ACCEPT a
    // genuine curated entry — transfer(address,uint256), selector
    // 0xa9059cbb, present in both the production corpus and the e2e
    // fixture.
    let bundle = build_embedded_root_selector_bundle([0xa9, 0x05, 0x9c, 0xbb]);
    let meta = crate::selectors::verify_selector_bundle(&bundle)
        .expect("the shim must accept a bundle rooted at SELECTOR_DB_ROOT");
    assert_eq!(meta.selector, [0xa9, 0x05, 0x9c, 0xbb]);
    assert_eq!(meta.text_sig, b"transfer(address,uint256)");
    assert_eq!(
        meta.provenance,
        crate::selectors::SelectorProvenance::Curated
    );
}

#[test]
fn negative_selectors_shim_rejects_truncated_bundle() {
    // Chop the final proof byte: the exact-length gate
    // (`bundle.len() != off + proof_size`) must reject before the Merkle
    // walk. The empty input must not even pass the header parse.
    let bundle = build_embedded_root_selector_bundle([0xa9, 0x05, 0x9c, 0xbb]);
    let truncated = &bundle[..bundle.len() - 1];
    assert!(crate::selectors::verify_selector_bundle(truncated).is_none());
    assert!(crate::selectors::verify_selector_bundle(&[]).is_none());
}

#[test]
fn negative_selectors_shim_rejects_tampered_text_sig_and_proof() {
    let bundle = build_embedded_root_selector_bundle([0xa9, 0x05, 0x9c, 0xbb]);

    // Tampered payload: flip one text_sig byte to a DIFFERENT printable
    // ASCII byte, so the ASCII gate passes and the Merkle leaf-hash
    // check is the only thing left to reject it.
    let mut bad_text = bundle.clone();
    bad_text[5] ^= 0x02; // 't' (0x74) -> 'v' (0x76): still printable
    assert!(
        crate::selectors::verify_selector_bundle(&bad_text).is_none(),
        "a tampered text_sig must fail Merkle verification",
    );

    // Tampered proof: flip the last byte (inside the final proof
    // sibling).
    let mut bad_proof = bundle.clone();
    let last = bad_proof.len() - 1;
    bad_proof[last] ^= 0x01;
    assert!(
        crate::selectors::verify_selector_bundle(&bad_proof).is_none(),
        "a tampered proof sibling must fail Merkle verification",
    );

    // Sanity: the untouched bundle still verifies — the tampering, not
    // the fixture, caused the rejections.
    assert!(crate::selectors::verify_selector_bundle(&bundle).is_some());
}

// =====================================================================
//  PART F — `offchain_state.rs` (per-slot counter facade).
//
//  Runtime-exercise the host-side SRAM-mock backend that's selected
//  whenever `stm32u585` isn't enabled. Each test picks
//  a unique slot-key so it doesn't collide with siblings in the same
//  `static mut TABLE`.
// =====================================================================

#[test]
fn positive_slot_key_compute_is_8_bytes() {
    let k = slot_key_compute(0, 0, 0);
    assert_eq!(k.len(), 8);
}

#[test]
fn positive_slot_key_compute_is_deterministic() {
    let k1 = slot_key_compute(7, 0xdead_beef_dead_beef, 42);
    let k2 = slot_key_compute(7, 0xdead_beef_dead_beef, 42);
    assert_eq!(k1, k2, "slot_key_compute must be deterministic");
}

#[test]
fn positive_slot_key_compute_depends_on_account_index() {
    let a = slot_key_compute(0, 1, 0);
    let b = slot_key_compute(1, 1, 0);
    assert_ne!(a, b);
}

#[test]
fn positive_slot_key_compute_depends_on_chain_id() {
    let a = slot_key_compute(0, 1, 0);
    let b = slot_key_compute(0, 2, 0);
    assert_ne!(a, b, "chain-bound slot keys: per-chain slot must differ");
}

#[test]
fn positive_slot_key_compute_depends_on_slot_index() {
    let a = slot_key_compute(0, 1, 0);
    let b = slot_key_compute(0, 1, 1);
    assert_ne!(a, b);
}

#[test]
fn positive_slot_key_compute_first_8_bytes_of_sha256() {
    // Pin the exact recipe so a refactor to a different hash (or a
    // different concatenation order) is caught here. Mirror of the
    // docstring + body of `slot_key_compute`.
    let mut h = Sha256::new();
    h.update([3u8]);
    h.update(0x1122_3344_5566_7788u64.to_be_bytes());
    h.update(7u32.to_be_bytes());
    let d = h.finalize();
    let mut expected = [0u8; 8];
    expected.copy_from_slice(&d[..8]);
    assert_eq!(slot_key_compute(3, 0x1122_3344_5566_7788, 7), expected);
}

#[test]
fn positive_offchain_mock_initial_state_is_unregistered_and_zero() {
    let _guard = lock_offchain_mock();
    let key = slot_key_compute(10, 11, 12);
    unsafe {
        assert!(!offchain_count_is_registered(&key));
        assert_eq!(offchain_count_read(&key), 0);
        assert_eq!(last_userop_count_read(&key), 0);
    }
}

#[test]
fn positive_offchain_mock_register_then_is_registered_true() {
    let _guard = lock_offchain_mock();
    let key = slot_key_compute(20, 21, 22);
    unsafe {
        offchain_count_register_slot(&key).expect("register ok");
        assert!(offchain_count_is_registered(&key));
    }
}

#[test]
fn positive_offchain_mock_bump_increases_count() {
    let _guard = lock_offchain_mock();
    let key = slot_key_compute(30, 31, 32);
    unsafe {
        offchain_count_bump(&key, 1).expect("first bump ok");
        assert_eq!(offchain_count_read(&key), 1);
        offchain_count_bump(&key, 5).expect("strictly-greater bump ok");
        assert_eq!(offchain_count_read(&key), 5);
    }
}

#[test]
fn positive_offchain_mock_last_userop_set_is_monotonic() {
    let _guard = lock_offchain_mock();
    let key = slot_key_compute(40, 41, 42);
    unsafe {
        last_userop_count_set(&key, 10).expect("set ok");
        assert_eq!(last_userop_count_read(&key), 10);
        last_userop_count_set(&key, 100).expect("set higher ok");
        assert_eq!(last_userop_count_read(&key), 100);
    }
}

#[test]
fn positive_offchain_mock_promote_to_is_idempotent() {
    let _guard = lock_offchain_mock();
    let key = slot_key_compute(50, 51, 52);
    unsafe {
        offchain_count_promote_to(&key, 50).expect("first promote ok");
        assert_eq!(offchain_count_read(&key), 50);
        // Promoting to a lower target is a no-op.
        offchain_count_promote_to(&key, 25).expect("idempotent promote ok");
        assert_eq!(offchain_count_read(&key), 50);
        // Promoting to a higher target raises.
        offchain_count_promote_to(&key, 75).expect("higher promote ok");
        assert_eq!(offchain_count_read(&key), 75);
    }
}

// ── Negatives — monotonicity is the load-bearing invariant from
// CLAUDE.md ("Off-chain sig counter, combined cap" + "No new
// per-signature flash state"). A regression here would let an
// attacker rewind the off-chain counter and double-issue sigs that
// fall under the cap.

#[test]
fn negative_offchain_mock_bump_regression_rejected() {
    let _guard = lock_offchain_mock();
    let key = slot_key_compute(60, 61, 62);
    unsafe {
        offchain_count_bump(&key, 5).expect("first bump ok");
        // Attempt to rewind: new_count < current.
        assert!(
            offchain_count_bump(&key, 4).is_err(),
            "off-chain counter must reject regression — CLAUDE.md \
             invariant #9 (off-chain sig counter monotonic) violated",
        );
        // State is unchanged.
        assert_eq!(offchain_count_read(&key), 5);
    }
}

#[test]
fn negative_offchain_mock_bump_equal_value_rejected() {
    let _guard = lock_offchain_mock();
    // The bump semantics are `new_count > current` (strict). A
    // replay attacker re-issuing the same `new_count` must NOT be
    // tolerated as a no-op.
    let key = slot_key_compute(70, 71, 72);
    unsafe {
        offchain_count_bump(&key, 7).expect("first bump ok");
        assert!(
            offchain_count_bump(&key, 7).is_err(),
            "bump must be strictly increasing — equal value is replay",
        );
    }
}

#[test]
fn negative_offchain_mock_bump_from_zero_to_zero_rejected() {
    let _guard = lock_offchain_mock();
    // Even a fresh slot rejects bump(0): a 0 → 0 bump is the
    // pathological "no-op replay" attack and equally must fail.
    let key = slot_key_compute(80, 81, 82);
    unsafe {
        assert!(
            offchain_count_bump(&key, 0).is_err(),
            "bump(0) on a fresh slot must be rejected as non-monotonic",
        );
    }
}

#[test]
fn positive_offchain_mock_last_userop_set_tolerates_regression_as_noop() {
    let _guard = lock_offchain_mock();
    // Mirror of the in-file comment "Tolerant of `count <
    // last_userop`: no-op rather than error, mirroring the flash-
    // backed semantics so a stale caller cannot brick the slot."
    let key = slot_key_compute(90, 91, 92);
    unsafe {
        last_userop_count_set(&key, 100).expect("set ok");
        last_userop_count_set(&key, 50).expect("stale value is no-op, not error");
        assert_eq!(
            last_userop_count_read(&key),
            100,
            "last_userop_count must NOT regress on a stale set call",
        );
    }
}

// ── Value-inflation → consent-free durable slot brick fix
// (docs/security/vulns/VULN-offchain-sync-value-inflation-slot-brick.md). CMD_OFFCHAIN_SYNC
// writes an untrusted, unclamped `target_count` into `last_userop`; the sign
// paths promote it verbatim into the monotonic `offchain` counter, so a value
// `>= MAX_SLOT_USES` permanently trips the combined-cap gate — a seed-survivable,
// consent-free brick. The clamp to OFFCHAIN_COUNT_CEILING (= MAX_SLOT_USES - 1)
// at every durable writer makes that state unreachable. These pin the clamp.

#[test]
fn positive_offchain_ceiling_is_max_slot_uses_minus_one() {
    // The ceiling must be exactly one below the cap: the combined-cap gate
    // refuses at `>= MAX_SLOT_USES`, and a truthful on-chain `offchainSigCount`
    // (the only value a legitimate sync mirrors) is always `< MAX_SLOT_USES`
    // (strict on-chain cap `slotUses + offchainSigCount < MAX_SLOT_USES`). So
    // `MAX_SLOT_USES - 1` both blocks the brick and never clips an honest sync.
    assert_eq!(
        OFFCHAIN_COUNT_CEILING,
        MAX_SLOT_USES - 1,
        "ceiling must be MAX_SLOT_USES - 1 (off-by-one here re-opens the brick)",
    );
}

#[test]
fn positive_clamp_offchain_count_boundaries() {
    // Passthrough below/at the ceiling.
    assert_eq!(clamp_offchain_count(0), 0);
    assert_eq!(clamp_offchain_count(1), 1);
    assert_eq!(clamp_offchain_count(OFFCHAIN_COUNT_CEILING), OFFCHAIN_COUNT_CEILING);
    // Clip at and above the cap — the exact attack value MAX_SLOT_USES (the FI
    // double-read guard only rejects u64::MAX, so 65_536 would otherwise sail
    // through) and the saturating extreme.
    assert_eq!(clamp_offchain_count(MAX_SLOT_USES), OFFCHAIN_COUNT_CEILING);
    assert_eq!(clamp_offchain_count(MAX_SLOT_USES + 1), OFFCHAIN_COUNT_CEILING);
    assert_eq!(clamp_offchain_count(u64::MAX), OFFCHAIN_COUNT_CEILING);
}

#[test]
fn positive_clamped_counter_never_trips_combined_cap_gate() {
    // The combined-cap gate refuses when `userop_sigs + offchain >= MAX_SLOT_USES`
    // (cmd_sign_userop) / when `userop_sigs + (offchain+1) > MAX_SLOT_USES`
    // (cmd_sign_offchain). A slot whose off-chain counter was clamped (no Type-2
    // sigs yet, userop_sigs = 0) must remain signable, i.e. NOT bricked.
    let offchain = clamp_offchain_count(u64::MAX); // worst-case attacker input
    let userop_sigs = 0u64;
    assert!(
        userop_sigs.saturating_add(offchain) < MAX_SLOT_USES,
        "a clamped counter must leave the slot signable (userop gate)",
    );
    assert!(
        userop_sigs.saturating_add(offchain + 1) <= MAX_SLOT_USES,
        "a clamped counter must leave one off-chain sig (offchain gate)",
    );
}

#[test]
fn negative_offchain_mock_sync_inflation_cannot_brick_slot() {
    let _guard = lock_offchain_mock();
    // End-to-end reproduction of the vuln against the mock backend: an untrusted
    // sync sets `last_userop` to the exact attack value MAX_SLOT_USES; a
    // subsequent sign promotes it into `offchain`. Pre-fix, `offchain` would land
    // at MAX_SLOT_USES and the combined-cap gate would refuse forever. Post-fix,
    // both durable writers clamp, so the slot stays below the cap and signable.
    let key = slot_key_compute(201, 202, 203);
    unsafe {
        // Attacker's CMD_OFFCHAIN_SYNC path.
        last_userop_count_set(&key, MAX_SLOT_USES).expect("sync ok");
        assert!(
            last_userop_count_read(&key) < MAX_SLOT_USES,
            "sync must not durably store a counter at/above the cap",
        );
        // Sign-path repair branch promotes last_userop into offchain.
        let last = last_userop_count_read(&key);
        offchain_count_promote_to(&key, last).expect("promote ok");
        let offchain = offchain_count_read(&key);
        assert!(
            offchain < MAX_SLOT_USES,
            "promoted off-chain counter must stay below the cap (else permanent brick)",
        );
        // The combined-cap gate (userop_sigs = 0) still admits a signature.
        assert!(
            0u64.saturating_add(offchain) < MAX_SLOT_USES,
            "slot must remain signable after a hostile inflation sync",
        );
    }
}

#[test]
fn negative_sync_high_floor_with_prior_userop_refuses_before_promotion() {
    let _guard = lock_offchain_mock();
    use crate::aa::offchain_gate::{userop_cap_ok_with_floor, SlotLedger};

    // Regression for the sync→Type-2 ordering bug: a high synced floor plus
    // one already-produced Type-2 signature is exhausted even when the local
    // off-chain record has not yet been promoted. The shipped handler now uses
    // this effective-floor policy before it mutates flash or signs.
    let key = slot_key_compute(202, 0xA5A5_5A5A_0000_0001, 204);
    unsafe {
        super::offchain_state::userop_sigs_bump(&key, 1).expect("seed Type-2 tally");
        last_userop_count_set(&key, MAX_SLOT_USES - 1).expect("sync high floor");
    }

    let local = unsafe { offchain_count_read(&key) };
    let floor = unsafe { last_userop_count_read(&key) };
    let userops = unsafe { super::offchain_state::userop_sigs_read(&key) };
    assert_eq!((local, floor, userops), (0, MAX_SLOT_USES - 1, 1));
    assert!(
        !userop_cap_ok_with_floor(local, floor, userops),
        "Type-2 must refuse against max(local,floor), not stale local",
    );

    let mut model = SlotLedger {
        offchain: local,
        last_userop: floor,
        userop_sigs: userops,
        registered: true,
    };
    assert!(!model.apply_sign_userop());
    assert_eq!(model.offchain, 0, "rejection must precede promotion");
    assert_eq!(model.userop_sigs, 1, "rejection must precede release");
}

#[test]
fn negative_offchain_mock_promote_to_over_cap_is_clamped() {
    let _guard = lock_offchain_mock();
    // Direct guard on the sign-path promote chokepoint: even a promote target of
    // u64::MAX (a glitched/hostile last_userop snapshot) must clamp, never store
    // a value that trips the cap.
    let key = slot_key_compute(211, 212, 213);
    unsafe {
        offchain_count_promote_to(&key, u64::MAX).expect("promote ok");
        assert_eq!(
            offchain_count_read(&key),
            OFFCHAIN_COUNT_CEILING,
            "promote must clamp to the ceiling, not store an over-cap value",
        );
    }
}

// ── Source-text pins: the clamp must be wired at every durable writer, so a
// future refactor that drops a site surfaces here (defence-in-depth intent).

#[test]
fn positive_offchain_clamp_helper_and_ceiling_defined() {
    assert!(
        OFFCHAIN_SRC.contains("pub const fn clamp_offchain_count"),
        "offchain_state.rs must define the clamp_offchain_count chokepoint",
    );
    assert!(
        OFFCHAIN_SRC.contains("pub const OFFCHAIN_COUNT_CEILING: u64 = sphincs_tz_shared::MAX_SLOT_USES - 1;"),
        "OFFCHAIN_COUNT_CEILING must be MAX_SLOT_USES - 1 (off-by-one re-opens brick)",
    );
    // Both mock-backend durable setters must call the clamp.
    assert_eq!(
        OFFCHAIN_SRC.matches("super::clamp_offchain_count(").count(),
        2,
        "both mock durable setters (promote_to + last_userop_count_set) must clamp",
    );
}

#[test]
fn positive_flash_backend_clamps_both_durable_setters() {
    assert_eq!(
        FLASH_SRC
            .matches("crate::offchain_state::clamp_offchain_count(")
            .count(),
        2,
        "flash last_userop_count_set + offchain_count_promote_to must both clamp \
         (value-inflation brick defence)",
    );
}

// ── Source-text pins for `offchain_state.rs` — the mock must
// mirror the flash-backed semantics across the cfg-mux. Drift means
// the QEMU build's behaviour diverges from real silicon.

#[test]
fn positive_offchain_state_dual_backend_cfg_mux() {
    assert!(
        OFFCHAIN_SRC.contains("#[cfg(feature = \"stm32u585\")]"),
        "offchain_state.rs missing the flash-backed backend cfg gate",
    );
    assert!(
        OFFCHAIN_SRC.contains("#[cfg(not(feature = \"stm32u585\"))]"),
        "offchain_state.rs missing the SRAM-mock backend cfg gate",
    );
}

#[test]
fn positive_offchain_state_flash_backed_branch_routes_to_hw_flash() {
    assert!(
        OFFCHAIN_SRC.contains("crate::hw::flash::offchain_count_read"),
        "flash-backed offchain_count_read must delegate to crate::hw::flash",
    );
    assert!(
        OFFCHAIN_SRC.contains("crate::hw::flash::offchain_count_bump"),
        "flash-backed offchain_count_bump must delegate to crate::hw::flash",
    );
    assert!(
        OFFCHAIN_SRC.contains("crate::hw::flash::offchain_count_register_slot"),
        "flash-backed register_slot must delegate to crate::hw::flash",
    );
}

#[test]
fn positive_offchain_state_mock_max_slots_tracks_distinct_cap() {
    // Single source of truth: the mock table is sized to the shared
    // distinct-slot cap, so the host/QEMU backend fail-closes at exactly the
    // numeric budget the flash backend enforces (no host-vs-silicon drift).
    assert!(
        OFFCHAIN_SRC.contains("const MAX_SLOTS: usize = super::MAX_DISTINCT_SLOTS;"),
        "mock backend's MAX_SLOTS must derive from the shared MAX_DISTINCT_SLOTS cap",
    );
}

// ── page-123 exhaustion → permanent-brick fix
// (docs/security/vulns/VULN-offchain-sync-page123-exhaustion-brick.md). The journal can be
// wedged into a permanent signing brick by spraying distinct slot keys until
// compaction fail-closes. The structural cap makes that impossible by
// construction; these pin the cap and its policy.

#[test]
fn positive_offchain_distinct_cap_is_structurally_unwedgeable() {
    // A slot occupies ≤3 quad-words after compaction (COUNT / USEROP /
    // USEROP_SIGS) on a 512-QW page (hw::flash OFFCHAIN_CAPACITY), and
    // compaction projects into a 256-entry SRAM table (MAX_ACTIVE_SLOTS).
    // Capping distinct slots so BOTH hold makes compaction provably unable to
    // fail — which is exactly what removes the permanent-brick wedge.
    assert!(
        MAX_DISTINCT_SLOTS.checked_mul(3).expect("no overflow") <= 512,
        "MAX_DISTINCT_SLOTS*3 must fit the 512-QW page, else compaction can wedge",
    );
    assert!(
        MAX_DISTINCT_SLOTS <= 256,
        "MAX_DISTINCT_SLOTS must fit the 256-entry compaction projection table",
    );
    assert_eq!(
        MAX_DISTINCT_SLOTS, 128,
        "distinct-slot cap pinned to 128 (page-123 un-wedgeable budget)",
    );
}

#[test]
fn positive_offchain_may_create_distinct_slot_policy() {
    // An update to an ALREADY-PRESENT slot can never grow the distinct-slot
    // set, so it must never be refused — at any occupancy, even past the cap.
    for d in [
        0usize,
        1,
        MAX_DISTINCT_SLOTS - 1,
        MAX_DISTINCT_SLOTS,
        MAX_DISTINCT_SLOTS + 5,
    ] {
        assert!(
            may_create_distinct_slot(d, true),
            "update to a present slot must never be refused (distinct_live={d})",
        );
    }
    // A NEW slot is allowed iff strictly below the cap. Boundary at 127/128/129.
    assert!(may_create_distinct_slot(0, false));
    assert!(may_create_distinct_slot(MAX_DISTINCT_SLOTS - 1, false));
    assert!(
        !may_create_distinct_slot(MAX_DISTINCT_SLOTS, false),
        "the (cap+1)-th distinct slot MUST be refused — this is the brick backstop",
    );
    assert!(!may_create_distinct_slot(MAX_DISTINCT_SLOTS + 1, false));
}

fn capacity_snapshot(
    distinct_live: usize,
    projected_live_qws: usize,
    blank_qws: usize,
    slot_present: bool,
) -> ForcedCapacitySnapshot {
    ForcedCapacitySnapshot {
        state_sha256: [0x5a; 32],
        distinct_live,
        projected_live_qws,
        blank_qws,
        slot_present,
    }
}

#[test]
fn forced_capacity_constants_pin_two_appends_and_page_geometry() {
    assert_eq!(FORCED_CAPACITY_REQUIRED_APPENDS, 2);
    assert_eq!(OFFCHAIN_CAPACITY_QWS, 512);
    assert!(MAX_DISTINCT_SLOTS * 3 + FORCED_CAPACITY_REQUIRED_APPENDS <= OFFCHAIN_CAPACITY_QWS);
}

#[test]
fn forced_tally_pair_proof_accepts_only_two_exact_final_reads() {
    let expected = 41u64;
    assert_eq!(
        forced_final_tally_pair_proof(expected, expected, expected),
        crate::fi::OK_SENTINEL
    );

    for (first, second) in [
        (expected - 1, expected - 1),
        (0, 0),
        (expected, expected - 1),
        (expected - 1, expected),
        (expected + 1, expected + 1),
        (u64::MAX, u64::MAX),
    ] {
        assert_eq!(
            forced_final_tally_pair_proof(expected, first, second),
            crate::fi::FAIL_SENTINEL,
            "accepted non-authoritative final tally pair ({first}, {second})"
        );
    }
}

#[test]
fn forced_capacity_requires_registered_slot_and_valid_distinct_projection() {
    let key = [0x11; 8];
    let request = [0x22; 32];
    let at_127 = capacity_snapshot(MAX_DISTINCT_SLOTS - 1, 384, 128, false);
    assert_eq!(
        forced_capacity_receipt_from_snapshot(&key, &request, at_127),
        Err(ForcedCapacityError::SlotUnregistered)
    );

    let new_at_128 = capacity_snapshot(MAX_DISTINCT_SLOTS, 384, 128, false);
    assert_eq!(
        forced_capacity_receipt_from_snapshot(&key, &request, new_at_128),
        Err(ForcedCapacityError::SlotUnregistered)
    );
    let present_at_128 = capacity_snapshot(MAX_DISTINCT_SLOTS, 384, 128, true);
    assert!(forced_capacity_receipt_from_snapshot(&key, &request, present_at_128).is_ok());

    let corrupt_129 = capacity_snapshot(MAX_DISTINCT_SLOTS + 1, 387, 125, true);
    assert_eq!(
        forced_capacity_receipt_from_snapshot(&key, &request, corrupt_129),
        Err(ForcedCapacityError::InvalidProjection)
    );
}

#[test]
fn forced_capacity_projected_qw_boundary_is_exact() {
    let key = [0x33; 8];
    let request = [0x44; 32];
    let full_but_compactable = capacity_snapshot(1, 510, 0, true);
    assert_eq!(
        forced_capacity_receipt_from_snapshot(&key, &request, full_but_compactable),
        Err(ForcedCapacityError::CompactionRequired),
        "forced signing must not enter the single-page erase/replay compactor"
    );

    let one_qw_short = capacity_snapshot(1, 511, 1, true);
    assert_eq!(
        forced_capacity_receipt_from_snapshot(&key, &request, one_qw_short),
        Err(ForcedCapacityError::InsufficientCapacity)
    );

    let one_blank_but_compactable = capacity_snapshot(1, 3, 1, true);
    assert_eq!(
        forced_capacity_receipt_from_snapshot(&key, &request, one_blank_but_compactable),
        Err(ForcedCapacityError::CompactionRequired),
        "the fixed two-append reservation requires two already-erased QWs"
    );

    let direct = capacity_snapshot(1, 3, 2, true);
    let direct_receipt = forced_capacity_receipt_from_snapshot(&key, &request, direct)
        .expect("two blank QWs admit the direct path");
    assert!(!direct_receipt.requires_compaction());
    assert_eq!(direct_receipt.blank_qws(), 2);
}

#[test]
fn forced_capacity_receipt_binds_request_slot_and_state() {
    let snapshot = capacity_snapshot(7, 18, 494, true);
    let baseline = forced_capacity_receipt_from_snapshot(&[1; 8], &[2; 32], snapshot).unwrap();
    let other_request = forced_capacity_receipt_from_snapshot(&[1; 8], &[3; 32], snapshot).unwrap();
    let other_slot = forced_capacity_receipt_from_snapshot(&[4; 8], &[2; 32], snapshot).unwrap();
    let other_state = forced_capacity_receipt_from_snapshot(
        &[1; 8],
        &[2; 32],
        ForcedCapacitySnapshot {
            state_sha256: [9; 32],
            ..snapshot
        },
    )
    .unwrap();
    assert_ne!(baseline.receipt_sha256(), other_request.receipt_sha256());
    assert_ne!(baseline.receipt_sha256(), other_slot.receipt_sha256());
    assert_ne!(baseline.receipt_sha256(), other_state.receipt_sha256());
    assert_eq!(baseline.request_digest(), &[2; 32]);
    assert_eq!(baseline.state_sha256(), &[0x5a; 32]);
}

#[test]
fn forced_capacity_mock_snapshot_is_read_only_and_slot_bound() {
    let _guard = lock_offchain_mock();
    let key = slot_key_compute(221, 222, 223);
    let request = [0xa5; 32];
    let before =
        unsafe { super::offchain_state::forced_capacity_snapshot(&key) }.expect("mock projection");
    assert!(!before.slot_present);
    assert_eq!(
        forced_capacity_receipt_from_snapshot(&key, &request, before),
        Err(ForcedCapacityError::SlotUnregistered),
        "forced Type-2 must not create slot registration"
    );
    assert!(!unsafe { offchain_count_is_registered(&key) });

    unsafe { offchain_count_register_slot(&key).expect("register mock slot") };
    let after = unsafe { super::offchain_state::forced_capacity_snapshot(&key) }
        .expect("mock projection after registration");
    assert!(after.slot_present);
    assert_eq!(after.distinct_live, before.distinct_live + 1);
    assert!(unsafe { offchain_count_is_registered(&key) });
    let receipt = forced_capacity_receipt_from_snapshot(&key, &request, after)
        .expect("registered mock slot has capacity");
    assert!(receipt.slot_present());
}

#[test]
fn forced_capacity_flash_path_is_strict_full_scan_and_read_only() {
    let start = FLASH_SRC
        .find("pub unsafe fn forced_capacity_snapshot")
        .expect("hardware capacity helper");
    let end = FLASH_SRC[start..]
        .find("/// Append a journal entry")
        .map(|offset| start + offset)
        .expect("capacity helper end anchor");
    let helper = &FLASH_SRC[start..end];
    assert!(helper.contains("for index in 0..OFFCHAIN_CAPACITY"));
    assert!(helper.contains("if saw_blank"));
    assert!(helper.contains("type_masks[slot_index] |= type_mask"));
    assert!(!helper.contains("erase_offchain_page"));
    assert!(!helper.contains("write_quadword_verified"));
    assert!(OFFCHAIN_SRC.contains("SnapshotDisagreement"));
    assert!(OFFCHAIN_SRC.contains("forced_capacity_receipt_from_snapshot"));
    let preflight_start = OFFCHAIN_SRC
        .find("pub unsafe fn forced_capacity_preflight")
        .expect("forced capacity proof helper");
    let preflight = &OFFCHAIN_SRC[preflight_start..];
    assert_eq!(preflight.matches("backend::forced_capacity_snapshot(").count(), 2);
    assert_eq!(
        preflight
            .matches("forced_capacity_receipt_from_snapshot(")
            .count(),
        2
    );
    assert!(preflight.contains("core::ptr::write_volatile(verdict_out, verdict)"));
    assert!(OFFCHAIN_SRC.contains("CFI_FORCED_CAPACITY_EXPECTED"));
}

#[cfg(feature = "erc7730-forced-blind")]
#[test]
fn forced_capacity_preflight_publishes_distinct_verdict_and_cfi() {
    let _guard = lock_offchain_mock();
    let key = slot_key_compute(222, 223, 224);
    let request = [0x6c; 32];
    unsafe { offchain_count_register_slot(&key).expect("register forced Type-2 slot") };
    let mut verdict = crate::fi::FAIL_SENTINEL;
    let mut cfi = crate::fi::CfiCounter::new();
    let receipt = unsafe {
        super::offchain_state::forced_capacity_preflight(
            &key,
            &request,
            &mut verdict,
            &mut cfi,
        )
    }
    .expect("stable mock projection has capacity");
    assert_eq!(verdict, crate::fi::OK_SENTINEL);
    assert_eq!(
        cfi.check_into_sentinel(super::offchain_state::CFI_FORCED_CAPACITY_EXPECTED),
        crate::fi::OK_SENTINEL
    );
    assert_eq!(receipt.request_digest(), &request);
    assert!(receipt.slot_present());
}

#[test]
fn positive_flash_write_entry_gates_new_slots_through_shared_cap() {
    // flash.rs is stm32u585-only (host-untested at runtime), so pin the
    // chokepoint wiring as source text: the single durable-append site
    // (write_entry) must gate brand-new slot creation through the shared
    // policy fn + cap, using the lightweight distinct counter.
    assert!(
        FLASH_SRC.contains("fn write_entry"),
        "flash must keep write_entry as the single durable-append chokepoint",
    );
    assert!(
        FLASH_SRC.contains("may_create_distinct_slot"),
        "write_entry must gate new slots via the shared may_create_distinct_slot policy",
    );
    assert!(
        FLASH_SRC.contains("distinct_slot_count_capped"),
        "write_entry must count distinct slots (capped scan) for the gate",
    );
    assert!(
        FLASH_SRC.contains("MAX_DISTINCT_SLOTS"),
        "flash cap must reference the shared MAX_DISTINCT_SLOTS budget",
    );
}

#[test]
fn positive_offchain_state_mock_reset_for_test_is_e2e_gated() {
    assert!(
        OFFCHAIN_SRC.contains("#[cfg(feature = \"e2e-test\")]"),
        "mock backend's reset_for_test must be e2e-only — never in prod",
    );
    assert!(
        OFFCHAIN_SRC.contains("pub unsafe fn reset_for_test"),
        "reset_for_test signature must remain `pub unsafe fn`",
    );
}

#[test]
fn positive_offchain_state_slot_key_compute_uses_be_bytes() {
    // The key recipe is order-sensitive on the BE encoding. Pin it.
    assert!(
        OFFCHAIN_SRC.contains("chain_id.to_be_bytes()"),
        "slot_key_compute must hash chain_id as BE",
    );
    assert!(
        OFFCHAIN_SRC.contains("slot_index.to_be_bytes()"),
        "slot_key_compute must hash slot_index as BE",
    );
}

// =====================================================================
//  PART G — `crypto.rs` (FI-hardened sign + provisioning shim).
//  Source-text pins for the load-bearing FI / KDF / zeroize sites.
// =====================================================================

#[test]
fn positive_crypto_reexports_pqsigner_domain() {
    // The whole pure-logic surface (KDF, AES-GCM wrap, BIP-39 ↔ C10
    // derivation, slot derivation, PIN-state codec) lives in
    // `pqsigner_domain`. The shim must re-export it so existing
    // call sites resolve.
    assert!(
        CRYPTO_SRC.contains("pub use pqsigner_domain::*;"),
        "crypto.rs must re-export every pqsigner_domain public name",
    );
}

#[test]
fn positive_crypto_signing_uses_constant_time_compare() {
    // CLAUDE.md "Code Conventions": `subtle` for constant-time
    // compares; no `==` on secret-typed values. The 4008-byte sig
    // compare between the double-evaluation pair is exactly such a
    // secret-derived compare.
    assert!(
        CRYPTO_SRC.contains("use subtle::ConstantTimeEq;"),
        "crypto.rs must `use subtle::ConstantTimeEq` for sig compare",
    );
    assert!(
        CRYPTO_SRC.contains("sig_a[..].ct_eq(&sig_b[..])"),
        "crypto.rs must compare double-eval sigs via `.ct_eq()`",
    );
}

#[test]
fn negative_crypto_no_naive_equality_on_sig_pair() {
    // The complementary negative: a future "let me drop subtle, this
    // is just a sig" refactor would introduce `sig_a == sig_b` /
    // `sig_a[..] == sig_b[..]`. Pin that it does NOT appear.
    assert!(
        !CRYPTO_SRC.contains("sig_a == sig_b"),
        "crypto.rs must not naive-compare sig pair (timing side channel)",
    );
    assert!(
        !CRYPTO_SRC.contains("sig_a[..] == sig_b[..]"),
        "crypto.rs must not naive-compare sig pair via slice ==",
    );
}

#[test]
fn positive_crypto_double_compute_present() {
    // Verify-after-sign alone is insufficient (RFC 9814 §A.2). Two
    // signs over identical inputs MUST be byte-identical; a
    // divergence is diagnostic of a fault on one of them.
    assert!(
        CRYPTO_SRC.contains("let sig_a = sk.sign_with_shuffle"),
        "crypto.rs must compute sig_a as the first of the FI double-eval",
    );
    assert!(
        CRYPTO_SRC.contains("let sig_b = sk.sign_with_shuffle"),
        "crypto.rs must compute sig_b as the second of the FI double-eval",
    );
}

#[test]
fn positive_crypto_verify_before_release_present() {
    // The 2-gate chain ends in a `sphincs_c10::verify` against the
    // honest pubkey; a faulted sig that bypasses the ct_eq still
    // has to verify under that pubkey.
    assert!(
        CRYPTO_SRC.contains("sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), msg_hash, &sig_a)"),
        "crypto.rs must verify-before-release on the released sig",
    );
}

#[test]
fn positive_crypto_verify_gate_uses_f2_sentinel_idiom() {
    // F-2 hardening: the bool check is wrapped by
    // `fi::check_true_into_sentinel` so a single skip cannot fault
    // the boolean to `true`.
    assert!(
        CRYPTO_SRC
            .contains("crate::fi::check_true_into_sentinel(|| core::hint::black_box(v))"),
        "crypto.rs verify gate must use the F-2 sentinel idiom with black_box",
    );
    assert!(
        CRYPTO_SRC.contains("!= crate::fi::OK_SENTINEL"),
        "crypto.rs must fail-closed on a non-OK_SENTINEL return",
    );
}

#[test]
fn positive_crypto_wait_random_before_verify() {
    // `wait_random()` defeats clock-aligned fault bursts that time
    // their glitch to the verify's fixed-shape control flow.
    let pre_verify = CRYPTO_SRC.matches("crate::fi::wait_random()").count();
    assert!(
        pre_verify >= 2,
        "crypto.rs must call wait_random() ≥ 2× around the FI gates \
         (between signs, before verify); found {pre_verify}",
    );
}

#[test]
fn positive_crypto_uses_rng_strong_not_plain_rng() {
    // OptRand + shuffle seed are drawn from the 3-source XOR-folded
    // strong RNG (STM32 ⊕ OPTIGA ⊕ SE050). The plain `rng::fill`
    // path would re-introduce the single-TRNG-bias attack.
    assert!(
        CRYPTO_SRC.contains("crate::rng_strong::fill(&mut opt_rand_buf)"),
        "OptRand draw must use rng_strong::fill (3-source XOR)",
    );
    // sca-3: the FI double-compute draws an INDEPENDENT shuffle seed per
    // pass (SCA de-alignment + closes the deterministic HW-HASH-fault
    // seam). Both draws must use rng_strong::fill (3-source XOR), never
    // the single-TRNG `rng::fill`.
    assert!(
        CRYPTO_SRC.contains("crate::rng_strong::fill(&mut shuffle_seed_a)"),
        "Shuffle seed A must use rng_strong::fill (3-source XOR)",
    );
    assert!(
        CRYPTO_SRC.contains("crate::rng_strong::fill(&mut shuffle_seed_b)"),
        "Shuffle seed B must use rng_strong::fill (3-source XOR)",
    );
}

#[test]
fn positive_crypto_zeroizes_opt_rand_on_every_return() {
    // Every error / success path must zeroize the OptRand stack
    // local. `zeroize::Zeroize` + `crate::fi::zeroize_barrier`
    // immediately after.
    let zeroize_calls = CRYPTO_SRC.matches("opt_rand_buf.zeroize();").count();
    let barriers = CRYPTO_SRC.matches("crate::fi::zeroize_barrier()").count();
    assert!(
        zeroize_calls >= 5,
        "crypto.rs must zeroize opt_rand_buf on every return path (≥5); \
         found {zeroize_calls}",
    );
    assert!(
        barriers >= 5,
        "crypto.rs must follow each zeroize() with a zeroize_barrier() \
         (≥5); found {barriers}",
    );
}

#[test]
fn positive_crypto_relocks_on_confirmed_fault_only() {
    // fi-2 (Trezor-port): the THREE confirmed-fault branches (ct_eq mismatch,
    // verify-before-release mismatch, CFI-counter mismatch) must escalate past
    // "reject this sign" to a full RELOCK (`zeroize_sensitive_state` wipes
    // master + slot secrets and clears `pin_verified`). A glitch during signing
    // is an active attack; wiping forces a fresh PIN before the next sign.
    let relocks = CRYPTO_SRC
        .matches("crate::nsc::zeroize_sensitive_state();")
        .count();
    assert_eq!(
        relocks, 3,
        "fi-2: exactly 3 confirmed-fault relocks (ct_eq, verify-gate, CFI); found {relocks}",
    );
    // Each is firmware-only (the host test scaffold must not couple to nsc).
    assert!(
        CRYPTO_SRC.contains("#[cfg(not(test))]\n        crate::nsc::zeroize_sensitive_state();"),
        "fi-2: the confirmed-fault relock must be #[cfg(not(test))]-gated",
    );
    // DoS-EXCLUSION invariant: the relock must NEVER appear in the pre-sign
    // rng-fail / rate-limit reject paths (relocking on a transient RNG error or
    // a rate-limit would be a self-inflicted denial of service). Assert no
    // relock exists before the first `sign_with_shuffle` call.
    let first_sign = CRYPTO_SRC
        .find("let sig_a = sk.sign_with_shuffle")
        .expect("sig_a computed");
    assert!(
        !CRYPTO_SRC[..first_sign].contains("zeroize_sensitive_state"),
        "fi-2: relock must NOT be in the pre-sign rng-fail/rate-limit rejects (DoS)",
    );
}

#[test]
fn positive_crypto_cfi_counter_has_seven_distinct_steps() {
    // F-18: 7-step CFI counter with distinct 32-bit magics. A
    // glitch that skips any one bump leaves the counter short by
    // exactly that step's magic.
    let step_names = [
        "CFI_STEP_RATE_LIMIT",
        "CFI_STEP_OPT_RAND",
        "CFI_STEP_SHUFFLE",
        "CFI_STEP_SIGN_A",
        "CFI_STEP_SIGN_B",
        "CFI_STEP_CT_EQ",
        "CFI_STEP_VERIFY_GATE",
    ];
    for n in step_names.iter() {
        assert!(
            CRYPTO_SRC.contains(n),
            "F-18 CFI step `{n}` missing from crypto.rs",
        );
    }
    // Each step is bumped.
    for n in step_names.iter() {
        assert!(
            CRYPTO_SRC.contains(&format!("cfi.bump({n})")),
            "F-18 CFI step `{n}` declared but never bumped",
        );
    }
    // Final check uses the sentinel idiom too.
    assert!(
        CRYPTO_SRC.contains("cfi.check_into_sentinel(CFI_EXPECTED) != crate::fi::OK_SENTINEL"),
        "F-18 final CFI check must use the OK_SENTINEL idiom",
    );
}

#[test]
fn negative_crypto_cfi_magic_constants_must_be_distinct() {
    // Re-derive the seven magics from source so a refactor that
    // accidentally aliases two of them (e.g. copy-paste) is caught.
    let extract = |name: &str| -> Option<u32> {
        // Scan line-by-line for `const <name>: u32 = <hex>;` with
        // any whitespace between tokens. Tolerates `0xA1_5A_1357`
        // style numeric literals.
        for line in CRYPTO_SRC.lines() {
            let t = line.trim();
            if !t.starts_with("const ") || !t.contains(name) {
                continue;
            }
            // Slice after the `=`.
            let after_eq = t.split('=').nth(1)?.trim();
            // Strip trailing `;` and any comment.
            let val = after_eq.split(';').next()?.trim();
            let cleaned: String = val
                .trim_start_matches("0x")
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect();
            return u32::from_str_radix(&cleaned, 16).ok();
        }
        None
    };
    let magics: Vec<u32> = [
        "CFI_STEP_RATE_LIMIT",
        "CFI_STEP_OPT_RAND",
        "CFI_STEP_SHUFFLE",
        "CFI_STEP_SIGN_A",
        "CFI_STEP_SIGN_B",
        "CFI_STEP_CT_EQ",
        "CFI_STEP_VERIFY_GATE",
    ]
    .iter()
    .map(|n| extract(n).unwrap_or_else(|| panic!("could not extract magic for {n}")))
    .collect();
    let mut sorted = magics.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        7,
        "CFI step magics are not distinct: {magics:?} — \
         skipping two aliased bumps would zero the sum",
    );
}

#[test]
fn positive_crypto_sign_rate_limit_gates_call() {
    // F-17 SCA defence: `sign_rate::pre_sign()` enforces ≥1 s
    // between consecutive signs and a per-session 250-sign budget.
    // The double-compute below counts as ONE rate-limit charge.
    assert!(
        CRYPTO_SRC.contains("crate::sign_rate::pre_sign()"),
        "crypto.rs must gate sign on sign_rate::pre_sign() (F-17 SCA defence)",
    );
}

#[test]
fn forced_crypto_entrypoint_uses_request_bound_charge_before_the_shared_rate_cfi_step() {
    let ordinary_start = CRYPTO_SRC
        .find("pub fn c10_sign_verified_with_progress(")
        .expect("ordinary verified-sign entrypoint missing");
    let forced_start = CRYPTO_SRC
        .find("pub(crate) fn c10_sign_verified_forced_with_progress(")
        .expect("forced verified-sign entrypoint missing");
    let inner_start = CRYPTO_SRC
        .find("fn c10_sign_verified_with_progress_inner(")
        .expect("shared verified-sign body missing");
    let ordinary_wrapper = &CRYPTO_SRC[ordinary_start..forced_start];
    let forced_wrapper = &CRYPTO_SRC[forced_start..inner_start];

    let ordinary_charge = ordinary_wrapper
        .find("crate::sign_rate::pre_sign()?")
        .expect("ordinary entrypoint must retain the ordinary charge");
    let ordinary_readback = ordinary_wrapper
        .find("crate::sign_rate::signs_this_session() != signs_before.wrapping_add(1)")
        .expect("ordinary charge must prove the counter advanced by one");
    let ordinary_token = ordinary_wrapper
        .find("VerifiedRateCharge(crate::fi::OK_SENTINEL)")
        .expect("ordinary charge must mint the private verified token");
    assert!(ordinary_charge < ordinary_readback && ordinary_readback < ordinary_token);

    assert!(forced_wrapper.contains("rate_receipt: &crate::sign_rate::ForcedRateReceipt"));
    assert!(forced_wrapper.contains("request_digest: &[u8; 32]"));
    let forced_charge = forced_wrapper
        .find("crate::sign_rate::pre_sign_forced(rate_receipt, request_digest)")
        .expect("forced entrypoint must use the request-bound charge");
    let forced_readback = forced_wrapper
        .find("crate::sign_rate::signs_this_session() != signs_before.wrapping_add(1)")
        .expect("forced charge must independently prove the counter advanced by one");
    let forced_token = forced_wrapper
        .find("VerifiedRateCharge(crate::fi::OK_SENTINEL)")
        .expect("forced charge must mint the private verified token");
    assert!(forced_charge < forced_readback && forced_readback < forced_token);
    assert!(!forced_wrapper.contains("crate::sign_rate::pre_sign()?"));
    assert!(
        !CRYPTO_SRC.contains("SignRateMode"),
        "a runtime mode discriminator could fault forced signing into the ordinary path",
    );

    let first_key_use = CRYPTO_SRC[inner_start..]
        .find("let sig_a = sk.sign_with_shuffle")
        .map(|offset| inner_start + offset)
        .expect("first signing operation missing");
    let rate_region = &CRYPTO_SRC[inner_start..first_key_use];
    let verified_token = rate_region
        .find("core::hint::black_box(verified_rate_charge.0) == crate::fi::OK_SENTINEL")
        .expect("shared body must verify the private rate-charge token");
    let rate_cfi = rate_region
        .find("cfi.bump(CFI_STEP_RATE_LIMIT)")
        .expect("shared rate CFI step missing");
    assert!(verified_token < rate_cfi);
    assert_eq!(
        CRYPTO_SRC.matches("cfi.bump(CFI_STEP_RATE_LIMIT)").count(),
        1,
        "ordinary and forced entrypoints must converge on one rate CFI step",
    );
}

#[test]
fn positive_crypto_cfi_bumps_gated_on_verified_step_success() {
    // X17-FI2 (playbook FI11): the three fallible steps gate their
    // `cfi.bump` on the step's VERIFIED success — a glitch that skips
    // the fallible `bl` (stale-Ok return register) must not stamp the
    // step with an un-charged rate limit, an all-zero OptRand, or an
    // all-zero shuffle seed. Pin each acceptance check BEFORE its bump.
    let rate_check = CRYPTO_SRC
        .find("crate::sign_rate::signs_this_session() != signs_before.wrapping_add(1)")
        .expect("FI11: RATE_LIMIT bump must be gated on the session-counter +1 read-back");
    let rate_bump = CRYPTO_SRC
        .find("cfi.bump(CFI_STEP_RATE_LIMIT)")
        .expect("F-18: RATE_LIMIT bump missing");
    assert!(
        rate_check < rate_bump,
        "FI11: rate-limit read-back must precede cfi.bump(CFI_STEP_RATE_LIMIT)"
    );

    let opt_check = CRYPTO_SRC
        .find("if acc == 0 {")
        .expect("FI11: OPT_RAND bump must be gated on a post-fill nonzero acceptance check");
    let opt_bump = CRYPTO_SRC
        .find("cfi.bump(CFI_STEP_OPT_RAND)")
        .expect("F-18: OPT_RAND bump missing");
    assert!(
        opt_check < opt_bump,
        "FI11: OptRand acceptance check must precede cfi.bump(CFI_STEP_OPT_RAND)"
    );

    let shuffle_check = CRYPTO_SRC
        .find("if acc_a == 0 || acc_b == 0 {")
        .expect("FI11: SHUFFLE bump must be gated on a both-seeds-nonzero acceptance check");
    let shuffle_bump = CRYPTO_SRC
        .find("cfi.bump(CFI_STEP_SHUFFLE)")
        .expect("F-18: SHUFFLE bump missing");
    assert!(
        shuffle_check < shuffle_bump,
        "FI11: shuffle-seed acceptance check must precede cfi.bump(CFI_STEP_SHUFFLE)"
    );
}

#[test]
fn positive_crypto_sphincs_master_kdf_tag_is_exact() {
    // CLAUDE.md "What NOT to do — No casual KDF tag changes". The
    // bootstrap-derivation tag is the very first thing that breaks
    // every deployed wallet on rename.
    assert!(
        CRYPTO_SRC.contains("b\"sphincs-master\""),
        "crypto.rs must use the exact byte string `\"sphincs-master\"` \
         as the master KDF tag — CLAUDE.md forbids casual changes",
    );
}

#[test]
fn positive_crypto_provision_zeroizes_entropy_and_master_secret() {
    // Both are secrets and must be wiped on the success path.
    assert!(
        CRYPTO_SRC.contains("entropy.zeroize();"),
        "provision_from_mnemonic must zeroize entropy on the success path",
    );
    assert!(
        CRYPTO_SRC.contains("master_secret.zeroize();"),
        "provision_from_mnemonic must zeroize master_secret on the success path",
    );
}

#[test]
fn positive_crypto_provision_uses_mnemonic_to_entropy_with_panic_msg() {
    // The mnemonic is checksum-verified upstream; if `to_entropy()`
    // ever fails here it indicates a TOCTOU corruption, not a user
    // error. The `expect` message documents the assumption.
    assert!(
        CRYPTO_SRC.contains("mnemonic was already checksum-verified"),
        "crypto.rs must keep the checksum-already-verified docstring \
         on mnemonic.to_entropy().expect()",
    );
}

#[test]
fn positive_crypto_store_macd_runs_three_pass_macd_per_slot() {
    // Mac-and-destroy: init → pin → init, exactly three calls per
    // slot. Any other order leaves the slot in a recoverable state.
    let pattern = "se.mac_and_destroy(j as u16, &init_in).unwrap();";
    let count = CRYPTO_SRC.matches(pattern).count();
    assert_eq!(
        count, 2,
        "store_macd_encrypted must call init-side MACD twice per slot \
         (before + after PIN-side); found {count} occurrences",
    );
    assert!(
        CRYPTO_SRC.contains("se.mac_and_destroy(j as u16, &pin_in).unwrap();"),
        "store_macd_encrypted must run the PIN-side MACD pass",
    );
}

#[test]
fn positive_crypto_no_classical_signer_anywhere() {
    // CLAUDE.md invariant #5: "One signature primitive: SPHINCS+C10."
    // The shim must reference C10 only — no ECDSA, no Ed25519, no
    // FORS+C alias.
    for forbidden in &[
        "secp256k1",
        "Secp256k1",
        "ed25519",
        "Ed25519",
        "ecdsa::",
        "k256::",
        "p256::",
        "fors_c",
        "FORSC",
    ] {
        assert!(
            !CRYPTO_SRC.contains(forbidden),
            "crypto.rs references `{forbidden}` — CLAUDE.md invariant #5 \
             (one signature primitive: SPHINCS+C10) forbids classical signers",
        );
    }
}

// =====================================================================
//  PART H — `dual_se.rs` (XOR entropy split + dual-SE lockstep).
//  Source-text pins for the load-bearing invariants.
// =====================================================================

#[test]
fn positive_dual_se_xor_split_recipe_present() {
    // CLAUDE.md invariant #1: "BIP-39 entropy is XOR-split: half_O
    // on OPTIGA, half_E on SE050. Neither chip alone reveals any bit."
    assert!(
        DUAL_SE_SRC.contains("let half_e = Zeroizing::new(xor_32(entropy, &half_o));"),
        "dual_se.rs must compute half_e = entropy XOR half_o (invariant #1)",
    );
}

#[test]
fn positive_dual_se_three_source_random_for_half_o() {
    // half_o is drawn from STM32 TRNG ⊕ OPTIGA TRNG ⊕ SE050 TRNG so
    // that no single TRNG bias gives an attacker either half.
    assert!(DUAL_SE_SRC.contains(
        "crate::rng_strong::fill_with_store(&mut half_o, self).is_err()"
    ));
    assert!(DUAL_SE_SRC.contains(
        "strict STM32+OPTIGA+SE050 draw FAILED — refusing degraded split"
    ));
}

#[test]
fn positive_dual_se_half_o_stuck_at_zero_fails_closed() {
    // FI defense: if all three sources fail / produce zero, the
    // half_o accumulator is zero — the function must refuse to
    // provision rather than fall through with predictable entropy.
    assert!(DUAL_SE_SRC.contains("half_o.zeroize();"));
    assert!(DUAL_SE_SRC.contains("return Err(SeError::InternalError);"));
}

#[test]
fn negative_dual_se_provision_halves_auto_wipe_on_every_error_exit() {
    // A provisioning error on either chip (or either optional ML-KEM seal)
    // used to `return Err` before four reconstructing stack copies reached the
    // success-only zeroize block. Keep the whole operation inside a closure
    // whose Zeroizing locals drop before its Result is propagated.
    let start = DUAL_SE_SRC
        .find("    fn provision(\n")
        .expect("DualSecureElement::provision must exist");
    let end = DUAL_SE_SRC[start..]
        .find("    #[cfg(feature = \"duress-pin\")]\n")
        .map(|n| start + n)
        .expect("provision_duress boundary must exist");
    let body = &DUAL_SE_SRC[start..end];

    for required in [
        "let provision_result = (|| -> Result<(), SeError> {",
        "let half_o = Zeroizing::new(self.generate_split_half()?);",
        "let half_e = Zeroizing::new(xor_32(entropy, &half_o));",
        "Zeroizing::new(*half_o)",
        "Zeroizing::new(*half_e)",
    ] {
        assert!(
            body.contains(required),
            "provision must retain RAII wipe invariant `{required}` on every return"
        );
    }

    let closure_end = body
        .rfind("        })();")
        .expect("provision operation must be scoped in a drop boundary");
    let barrier = body
        .rfind("crate::fi::zeroize_barrier();")
        .expect("post-drop zeroize barrier must remain");
    let propagate = body
        .rfind("provision_result?;")
        .expect("provision must propagate only after the drop boundary");
    assert!(
        closure_end < barrier && barrier < propagate,
        "all Zeroizing split halves must drop, then hit the barrier, before Err propagation"
    );
}

#[test]
fn positive_dual_se_unlock_cross_verifies_master_secret() {
    // Unlock derives `master_secret` from the reconstructed full
    // entropy and cross-checks against the SE-stored value to
    // detect chip tampering / desync.
    assert!(
        DUAL_SE_SRC.contains("crypto::kdf(b\"sphincs-master\", &full_entropy, 0)"),
        "dual_se.rs unlock must derive master from full entropy via the same \
         `sphincs-master` KDF tag the rest of the firmware uses",
    );
}

#[test]
fn positive_dual_se_unlock_uses_two_pass_ct_eq_with_wait_random() {
    // FI hardening: two independent `ct_eq` compares with a
    // volatile delay between, gated through `check_true_into_sentinel`.
    assert!(
        DUAL_SE_SRC.contains("derived_master.ct_eq(&master_o).into();"),
        "dual_se.rs must constant-time compare derived_master against master_o",
    );
    let ct_eq_count = DUAL_SE_SRC.matches("derived_master.ct_eq(&master_o)").count();
    assert!(
        ct_eq_count >= 2,
        "dual_se.rs needs ≥2 ct_eq compares (F-2 double-check); found {ct_eq_count}",
    );
    assert!(
        DUAL_SE_SRC.contains("crate::fi::wait_random();"),
        "dual_se.rs must insert wait_random() between the two ct_eq compares",
    );
    assert!(
        DUAL_SE_SRC.contains("crate::fi::check_true_into_sentinel"),
        "dual_se.rs must route the boolean through check_true_into_sentinel",
    );
}

#[test]
fn positive_dual_se_xor_32_is_loop_constant_time() {
    // The hand-rolled XOR loop has no early-exit. A `if a[i] !=
    // b[i] { break }` regression would leak the first differing
    // index via cycle count.
    let xor_block_start = DUAL_SE_SRC
        .find("fn xor_32(")
        .expect("xor_32 must exist in dual_se.rs");
    let xor_block_end = DUAL_SE_SRC[xor_block_start..]
        .find("\n}\n")
        .map(|i| xor_block_start + i)
        .unwrap_or(DUAL_SE_SRC.len());
    let body = &DUAL_SE_SRC[xor_block_start..xor_block_end];
    assert!(
        !body.contains("break") && !body.contains("return"),
        "xor_32 must not early-exit (timing side channel); body: {body:?}",
    );
}

#[test]
fn positive_dual_se_unlock_zeroizes_full_entropy_and_halves() {
    // Unlock/duress and split-generation error paths manually wipe their
    // mutable locals. Main provisioning is separately pinned to Zeroizing
    // RAII above so early errors cannot bypass its wipe.
    let half_o_zeroize = DUAL_SE_SRC.matches("half_o.zeroize();").count();
    let half_e_zeroize = DUAL_SE_SRC.matches("half_e.zeroize();").count();
    let full_zeroize = DUAL_SE_SRC.matches("full_entropy.zeroize();").count();
    assert!(
        half_o_zeroize >= 2,
        "manual half_o paths must retain their explicit wipes; found {half_o_zeroize}",
    );
    assert!(
        half_e_zeroize >= 1,
        "half_e must be zeroized on the unlock path; found {half_e_zeroize}",
    );
    assert!(
        full_zeroize >= 2,
        "full_entropy must be zeroized on both success + failure paths; found {full_zeroize}",
    );
}

#[test]
fn negative_dual_se_provision_duress_zeroizes_original_half_e() {
    // X17-TUI2 family (playbook UI9): `half_e` must be zeroized in
    // place on every exit from provision_duress. Moving it into a
    // `he` copy and zeroizing that leaves the SE050 half live.
    assert!(
        DUAL_SE_SRC.contains("let mut half_e = xor_32(entropy, &half_o);"),
        "half_e must be a mutable binding so it can be wiped in place"
    );
    assert!(
        !DUAL_SE_SRC.contains("let mut he = half_e;"),
        "provision_duress must zeroize the original half_e binding, not a copy (X17-TUI2 family)"
    );
}

#[test]
fn positive_dual_se_factory_reset_admin_zeroizes_caches_even_on_error() {
    // The wipe path is best-effort across both chips — but SRAM
    // state must be wiped regardless of whether either chip
    // accepted the wipe. Otherwise a partial wipe leaves stale
    // secrets in SRAM.
    let body = DUAL_SE_SRC
        .find("fn factory_reset_admin")
        .map(|i| &DUAL_SE_SRC[i..])
        .expect("factory_reset_admin must exist");
    assert!(
        body.contains("self.zeroize_caches();"),
        "factory_reset_admin must call zeroize_caches() before propagating error",
    );
    assert!(
        body.find("self.zeroize_caches();").unwrap() < body.find("?").unwrap_or(usize::MAX),
        "zeroize_caches() must run BEFORE the early-return on either-chip error",
    );
}

#[test]
fn negative_dual_se_factory_reset_transient_auth_cannot_degrade_to_platform_rng() {
    // The temporary F1D0 value authorizes an E120 counter reset. It is still
    // an authorization secret even though the following wipe destroys it, so
    // the dual-SE owner must draw it through all three TRNGs before either chip
    // is wiped. If any source fails, the counter reset may be skipped, but the
    // destructive wipe must continue without minting a weaker local value.
    let helper_start = DUAL_SE_SRC
        .find("    pub(crate) fn reset_optiga_for_admin(&mut self) -> Result<(), SeError> {")
        .expect("dual-SE OPTIGA reset helper must exist");
    let helper_end = DUAL_SE_SRC[helper_start..]
        .find("\n    }\n}\n\nimpl WalletStore")
        .map(|n| helper_start + n)
        .expect("dual-SE OPTIGA reset helper boundary must exist");
    let body = &DUAL_SE_SRC[helper_start..helper_end];

    let zeroizing = body
        .find("Zeroizing::new([0u8; 32])")
        .expect("transient authorization owner must auto-wipe");
    let draw = body
        .find("crate::rng_strong::fill_with_store(&mut *transient_secret, self)")
        .expect("transient authorization must use the strict three-source facade");
    let success_gate = body[draw..]
        .find(".is_ok()")
        .map(|n| draw + n)
        .expect("only a successful strict draw may enter transient auth");
    let optiga_wipe = body
        .find("factory_reset_with_transient_secret(&mut *transient_secret)")
        .expect("the verified draw must be handed explicitly to OPTIGA");
    let failure_branch = body
        .find("} else {")
        .expect("failed strict draw must take an explicit fallback branch");
    let fallback_wipe = body
        .find("self.optiga.factory_reset_admin()")
        .expect("failed draw must still run OPTIGA wipe without transient auth");
    let zeroize = body
        .find("transient_secret.zeroize();")
        .expect("transient authorization must be explicitly wiped");
    let barrier = body
        .find("crate::fi::zeroize_barrier();")
        .expect("transient authorization wipe needs a compiler barrier");

    assert!(
        zeroizing < draw
            && draw < success_gate
            && success_gate < optiga_wipe
            && optiga_wipe < failure_branch
            && failure_branch < fallback_wipe
            && fallback_wipe < zeroize
            && zeroize < barrier
    );
    assert!(body.contains("strict transient-auth RNG failed"));
    assert!(!body.contains("return "));
    assert!(!body.contains('?'));
    assert!(
        !body.contains("crate::rng::fill"),
        "factory-reset authorization must never fall back to platform-only RNG"
    );

    let admin_start = DUAL_SE_SRC
        .find("    fn factory_reset_admin(&mut self) -> Result<(), SeError> {")
        .expect("DualSecureElement::factory_reset_admin must exist");
    let admin_body = &DUAL_SE_SRC[admin_start..];
    let optiga_call = admin_body
        .find("let optiga_result = self.reset_optiga_for_admin();")
        .expect("all dual-SE admin wipes must use the strong OPTIGA helper");
    let se050_call = admin_body
        .find("let se050_result = self.se050.factory_reset_admin();")
        .expect("SE050 wipe must remain best-effort after the OPTIGA leg");
    assert!(optiga_call < se050_call);
    assert!(!admin_body[..se050_call].contains("return "));
    assert!(!admin_body[..se050_call].contains('?'));
    assert!(!DUAL_SE_SRC.contains("self.optiga.factory_reset()"));
}

#[test]
fn positive_dual_se_remaining_attempts_takes_min_not_max() {
    // The user-facing remaining-attempts is the MIN over both SEs
    // (more restrictive). Flipping to MAX would let users keep
    // entering PINs after one chip already counted them out.
    assert!(
        DUAL_SE_SRC.contains("o.min(e)"),
        "remaining_attempts must return min(o,e), not max — the stricter chip wins",
    );
}

#[test]
fn positive_dual_se_pin_attempt_count_takes_max_not_min() {
    // The used-attempts counter is MAX over both SEs (higher =
    // closer to lockout). This is the tamper-detection axis; flipping
    // to MIN would let one chip mask the other's lockout.
    let pin_count_body_start = DUAL_SE_SRC
        .find("fn pin_attempt_count")
        .expect("pin_attempt_count must exist");
    let snippet = &DUAL_SE_SRC[pin_count_body_start..pin_count_body_start + 1500];
    assert!(
        snippet.contains("Some(a.max(b))"),
        "pin_attempt_count must take MAX over both SE used-counts \
         (stricter aggregate); body slice: {snippet:?}",
    );
}

#[test]
fn positive_dual_se_pin_attempt_counts_divergent_only_with_both_some() {
    // Asymmetric None must not surface as "divergent" — None means
    // "no comparison possible", not "tamper".
    let div_body_start = DUAL_SE_SRC
        .find("fn pin_attempt_counts_divergent")
        .expect("pin_attempt_counts_divergent must exist");
    let snippet = &DUAL_SE_SRC[div_body_start..div_body_start + 800];
    assert!(
        snippet.contains("(Some(a), Some(b)) => a != b,"),
        "pin_attempt_counts_divergent must flag divergence only when both Some",
    );
    assert!(
        snippet.contains("_ => false,"),
        "pin_attempt_counts_divergent must return false on any asymmetric None",
    );
}

#[test]
fn positive_dual_se_master_e_zeroized_after_decrypt() {
    // SE050's `master_e` is the decrypt key for SE050's entropy-blob
    // cache. It must be wiped immediately after use so it never
    // sits in SRAM across the rest of the unlock flow.
    assert!(
        DUAL_SE_SRC.contains("me.zeroize();"),
        "dual_se.rs must zeroize master_e (rebound to `me`) after decrypt",
    );
}

#[test]
fn positive_dual_se_optiga_rejected_path_zeroizes_se050_master() {
    // If OPTIGA rejected the PIN but SE050 incidentally returned a
    // master (pathological desync), the SE050 master must be wiped
    // BEFORE propagating OPTIGA's error. Otherwise a chip-swap
    // attack could harvest the SE050 master across the failed
    // attempt.
    assert!(
        DUAL_SE_SRC.contains("if let Some(Ok(mut me)) = se050_result {")
            && DUAL_SE_SRC.contains("me.zeroize();"),
        "dual_se.rs must zeroize SE050 master in the OPTIGA-rejected branch",
    );
}

#[test]
fn positive_dual_se_provision_passes_same_master_secret_to_both_chips() {
    // CLAUDE.md "Lifecycle / Dual-SE provision": "Both SEs store
    // the same master_secret (encrypted under their own per-SE
    // PIN scheme) so we can cross-verify". Confirm the source
    // wiring.
    // The two `.provision(...)` calls in order are OPTIGA then
    // SE050; both must take `master_secret` (not a per-chip
    // derivative).
    // The SE-facing halves are Zeroizing wrappers under both the direct and
    // ML-KEM arms; both calls must still receive the same master secret.
    assert!(
        DUAL_SE_SRC.contains(".provision(&se_half_o, master_secret, vk, bootstrap_vk, pin)"),
        "optiga.provision must receive the shared master_secret",
    );
    assert!(
        DUAL_SE_SRC.contains(".provision(&se_half_e, master_secret, vk, bootstrap_vk, pin)"),
        "se050.provision must receive the same shared master_secret",
    );
}

#[test]
fn positive_dual_se_unlock_calls_se050_on_pin_incorrect_too() {
    // Three-counter lockstep: SE050.unlock must be called even
    // when OPTIGA rejects the PIN, so SE050's silicon counter
    // advances in sync with MCU + OPTIGA.
    assert!(
        DUAL_SE_SRC
            .contains("Ok(_) | Err(UnlockError::PinIncorrect) => {")
            && DUAL_SE_SRC.contains("Some(self.se050.unlock(pin))"),
        "dual_se.rs must call SE050.unlock even on OPTIGA PinIncorrect \
         (three-counter lockstep)",
    );
}

#[test]
fn positive_dual_se_unlock_skips_se050_on_non_pin_error() {
    // Conversely, non-PIN OPTIGA errors (I2C / session faults)
    // must NOT burn an SE050 attempt — the comment explicitly
    // enforces "don't burn an SE050 silicon attempt slot for a
    // transient comm glitch".
    let body_start = DUAL_SE_SRC
        .find("let se050_result = match &optiga_result {")
        .expect("dual_se.rs unlock cascade must be present");
    let body = &DUAL_SE_SRC[body_start..body_start + 600];
    assert!(
        body.contains("Err(_) => None,"),
        "non-PIN OPTIGA errors must skip SE050 (don't burn attempt slot)",
    );
}

#[test]
fn positive_dual_se_blob_cache_uses_fih_bool() {
    // `blob_cached` is FI-hardened: a single skip of the "is the
    // blob ready" check shouldn't fault it to true. Pin the
    // FihBool typing.
    assert!(
        DUAL_SE_SRC.contains("blob_cached: crate::fih::FihBool,"),
        "DualSecureElement.blob_cached must be FihBool, not plain bool",
    );
    assert!(
        DUAL_SE_SRC.contains("self.blob_cached.is_true_fi()"),
        "blob_cached must be queried via is_true_fi (F-2 read path)",
    );
}

#[test]
fn negative_dual_se_no_full_entropy_handed_to_a_single_chip() {
    // Invariant #1 enforced by source: NEITHER `.provision` call
    // should receive `entropy` directly — they get half_o / half_e.
    // A future refactor that passes `entropy` to one chip would
    // collapse the dual-SE security model. Pin the absence.
    assert!(
        !DUAL_SE_SRC.contains("self.optiga.provision(&entropy"),
        "OPTIGA.provision must never receive the full entropy (invariant #1)",
    );
    assert!(
        !DUAL_SE_SRC.contains("self.se050.provision(&entropy"),
        "SE050.provision must never receive the full entropy (invariant #1)",
    );
}

#[test]
fn negative_dual_se_duress_no_full_entropy_to_a_single_chip() {
    // §32: invariant #1 applies to the DECOY too. The duress XOR split
    // must hand each chip a half (half_o / half_e), never the full decoy
    // entropy. A refactor passing `entropy` directly to one chip's
    // provision_duress would collapse the decoy's dual-SE security.
    assert!(
        !DUAL_SE_SRC.contains("self.optiga.provision_duress(&entropy"),
        "OPTIGA.provision_duress must never receive the full decoy entropy (invariant #1)",
    );
    assert!(
        !DUAL_SE_SRC.contains("self.se050.provision_duress(&entropy"),
        "SE050.provision_duress must never receive the full decoy entropy (invariant #1)",
    );
    // And it must positively pass the halves.
    assert!(
        DUAL_SE_SRC.contains("self.optiga.provision_duress(&half_o, master_secret, vk, bootstrap_vk, duress_pin)"),
        "OPTIGA.provision_duress must receive the OPTIGA half",
    );
    assert!(
        DUAL_SE_SRC.contains("self.se050.provision_duress(&half_e, master_secret, vk, bootstrap_vk, duress_pin)"),
        "SE050.provision_duress must receive the SE050 half",
    );
}

#[test]
fn positive_dual_se_unlock_duress_no_short_circuit_and_xor_reconstruct() {
    // §32 P3: unlock_duress must call BOTH chips' duress_read_half via
    // separate let-bindings (NOT `?` short-circuit) so a real-PIN entry
    // costs the same SE op-count on both chips as a duress entry — the
    // timing-uniformity property. And it must reconstruct the decoy
    // entropy by XOR of the two halves (invariant #1 for the decoy).
    assert!(
        DUAL_SE_SRC.contains("let ro = unsafe { self.optiga.duress_read_half(pin) };")
            && DUAL_SE_SRC.contains("let re = self.se050.duress_read_half(pin);"),
        "unlock_duress must read both halves into bindings (no `?` short-circuit) for timing uniformity",
    );
    assert!(
        DUAL_SE_SRC.contains("let mut full = xor_32(&half_o, &half_e);"),
        "unlock_duress must reconstruct the decoy entropy by XOR of both halves",
    );
    // The pad must hit BOTH chips so it twins the real unlock's two verifies.
    assert!(
        DUAL_SE_SRC.contains("self.optiga.duress_verify(pin)")
            && DUAL_SE_SRC.contains("self.se050.duress_verify(pin)"),
        "duress_pad must verify on both chips to match the real unlock's op-count",
    );
}

#[test]
fn positive_crypto_duress_always_provisions_decoy() {
    // §32: always-provision is load-bearing for deniability — the wizard
    // must provision a decoy even when the user declines (random PIN),
    // so "duress configured vs not" is indistinguishable on-chip. Pin the
    // unconditional call + the random-PIN-on-None path in source.
    assert!(
        CRYPTO_SRC.contains("provision_duress_wallet(store, duress_pin)"),
        "provision_from_mnemonic must always call provision_duress_wallet under the feature",
    );
    assert!(
        CRYPTO_SRC.contains("None => {")
            && CRYPTO_SRC.contains("fill_strong_with_store(store, &mut random_pin)"),
        "declined duress (None) must provision a decoy with a fresh random PIN, not skip",
    );
    // Decoy must be an INDEPENDENT fresh entropy (separate-entropy model),
    // not derived from the real seed.
    assert!(
        CRYPTO_SRC.contains("fill_strong_with_store(store, &mut decoy_entropy)?;"),
        "decoy entropy must be a fresh independent three-source draw",
    );
    assert!(CRYPTO_SRC.contains("crate::rng_strong::fill_with_store(out, store)"));
    assert!(!CRYPTO_SRC.contains("if store.random().is_ok()"));
}

#[test]
fn negative_dual_se_no_plaintext_kdf_tag_drift() {
    // The unlock cross-check derives master via the EXACT byte
    // string `"sphincs-master"`. A drift (sphincs_master,
    // sphincsmaster, …) would silently desync the cross-check.
    let count = DUAL_SE_SRC.matches("b\"sphincs-master\"").count();
    assert!(
        count >= 1,
        "dual_se.rs must reference the exact byte string b\"sphincs-master\" — \
         CLAUDE.md forbids casual KDF tag changes",
    );
}

#[test]
fn negative_dual_se_no_classical_signer_imports() {
    // Defence-in-depth: the dual-SE module has no business
    // touching classical signers. Pin the absence.
    for forbidden in &["secp256k1", "ed25519", "k256::", "p256::", "ecdsa::"] {
        assert!(
            !DUAL_SE_SRC.contains(forbidden),
            "dual_se.rs references `{forbidden}` — CLAUDE.md invariant #5 \
             (only SPHINCS+C10) violated",
        );
    }
}

// =====================================================================
//  PART I — Cross-module pins (invariants spanning multiple files).
// =====================================================================

#[test]
fn positive_kdf_tag_sphincs_master_is_shared_between_crypto_and_dual_se() {
    // The cross-verify works only if both files use the IDENTICAL
    // tag byte string. Drift between the two = master_secret
    // mismatch at unlock = wipe on every boot.
    let crypto_has = CRYPTO_SRC.contains("b\"sphincs-master\"");
    let dual_se_has = DUAL_SE_SRC.contains("b\"sphincs-master\"");
    assert!(
        crypto_has && dual_se_has,
        "Both crypto.rs (provision side) and dual_se.rs (unlock side) \
         must use the exact `b\"sphincs-master\"` tag",
    );
}

#[test]
fn positive_shims_are_all_thin_re_exports() {
    // The four shim files (aa/erc20/names/selectors) are all "thin
    // re-export shims" by design. Pin that they're each below a
    // reasonable line budget so logic never sneaks back into the
    // secure-side layer instead of the pure-logic crate.
    for (label, src, budget) in &[
        ("aa/mod.rs", AA_SHIM_SRC, 50usize),
        ("erc20/mod.rs", ERC20_SHIM_SRC, 60),
        ("names/mod.rs", NAMES_SHIM_SRC, 50),
        ("selectors/mod.rs", SELECTORS_SHIM_SRC, 80),
    ] {
        let lines = src.lines().count();
        assert!(
            lines <= *budget,
            "{label} grew to {lines} lines (budget {budget}); \
             logic belongs in the pure-logic workspace crate, not the shim",
        );
    }
}

#[test]
fn negative_crypto_glue_does_not_introduce_forbidden_admin_paths() {
    // CLAUDE.md "What NOT to do": no `rotateMasterKeys`,
    // `resetBootstrapUses`, `resetSlotUses`, or `increaseMax*`
    // anywhere in the slice. Pin the absence so a refactor can't
    // sneak one in via the crypto glue.
    for src in &[CRYPTO_SRC, DUAL_SE_SRC, OFFCHAIN_SRC] {
        for forbidden in &[
            "rotateMasterKeys",
            "resetBootstrapUses",
            "resetSlotUses",
            "increaseMax",
        ] {
            assert!(
                !src.contains(forbidden),
                "crypto-glue slice references forbidden admin path `{forbidden}`",
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Differential binding — `aa::offchain_gate` model  ⇔  shipped mock backend
// ─────────────────────────────────────────────────────────────────────
//
//  Anti-drift (work-todo §12e; the V9 "model ≠ artifact" defeater). The
//  sequence/interleave Kani proofs run over `aa::offchain_gate`'s owned
//  `SlotLedger`. This test pins that model to the counter policy the firmware
//  actually runs by:
//   (a) asserting the shared brick-defence constants + pure helpers are
//       byte-identical to `offchain_state` (value-inflation ceiling + clamp,
//       distinct-slot cap + admission policy);
//   (b) driving an interleaved sync / off-chain-sign sequence — composed from
//       the mock primitives EXACTLY as `cmd_sign_offchain` composes them
//       (repair → gate → durable bump) — through BOTH the model and the
//       static-mut mock, asserting the (offchain, last_userop, userop_sigs)
//       triple never diverges.
//
//  Complements the in-place gate wiring (`cmd_sign_offchain` calls
//  `check_offchain_gate` directly), which binds the GATE by construction; this
//  binds the TRANSITIONS. A pass also confirms the kernel's *internal* repair
//  (`max(offchain,last_userop)`) equals the gateway's *external* durable
//  promote — the two reach the same `new_count`.
#[test]
fn positive_offchain_gate_model_matches_mock_backend() {
    let _guard = lock_offchain_mock();
    use crate::aa::offchain_gate::{self as gate, check_offchain_gate, GateOutcome, SlotLedger};

    // (a) shared policy constants + pure helpers identical to the shipped backend.
    assert_eq!(gate::OFFCHAIN_COUNT_CEILING, OFFCHAIN_COUNT_CEILING);
    assert_eq!(gate::MAX_DISTINCT_SLOTS, MAX_DISTINCT_SLOTS);
    assert_eq!(gate::OFFCHAIN_COUNT_CEILING, MAX_SLOT_USES - 1);
    for c in [
        0u64,
        1,
        42,
        OFFCHAIN_COUNT_CEILING,
        OFFCHAIN_COUNT_CEILING + 1,
        u64::MAX,
    ] {
        assert_eq!(
            gate::clamp_offchain_count(c),
            clamp_offchain_count(c),
            "clamp helper diverged at {c}"
        );
    }
    for (live, present) in [
        (0usize, false),
        (MAX_DISTINCT_SLOTS - 1, false),
        (MAX_DISTINCT_SLOTS, false),
        (MAX_DISTINCT_SLOTS, true),
    ] {
        assert_eq!(
            gate::may_create_distinct_slot(live, present),
            may_create_distinct_slot(live, present),
            "distinct-slot policy diverged at ({live},{present})"
        );
    }

    // (b) executed differential on a test-unique key (a fresh static-mut slot).
    let key = slot_key_compute(211, 0xA5A5_0000_0000_1234, 7);
    let mut model = SlotLedger::default();

    // Seed the Type-2 tally identically so the combined-cap axis is live.
    unsafe {
        super::offchain_state::userop_sigs_bump(&key, 3).expect("seed userop_sigs");
    }
    model.userop_sigs = 3;
    model.registered = true;

    let read_triple = |k: &[u8; 8]| -> (u64, u64, u64) {
        unsafe {
            (
                offchain_count_read(k),
                last_userop_count_read(k),
                super::offchain_state::userop_sigs_read(k),
            )
        }
    };
    assert_eq!(
        read_triple(&key),
        (model.offchain, model.last_userop, model.userop_sigs),
        "seed state diverged"
    );

    // One off-chain sign, composed from the mock primitives EXACTLY as
    // cmd_sign_offchain does: repair (promote offchain up to last_userop) →
    // gate → durable bump to new_count.
    let mock_sign_offchain = |k: &[u8; 8]| unsafe {
        let last = last_userop_count_read(k);
        let mut off = offchain_count_read(k);
        if last > off {
            offchain_count_promote_to(k, last).expect("repair promote");
            off = last;
        }
        let us = super::offchain_state::userop_sigs_read(k);
        if let GateOutcome::Accept { new_count } = check_offchain_gate(off, last, us) {
            offchain_count_bump(k, new_count).expect("durable bump");
        }
    };

    // Interleaved sequence: sync-raises-floor, repair branch (offchain <
    // last_userop), gap growth, tolerant no-op sync.
    // 1) sync 50 → last_userop 50 (> offchain 0: repair territory).
    unsafe {
        last_userop_count_set(&key, 50).expect("sync");
    }
    model.apply_offchain_sync(50);
    assert_eq!(
        read_triple(&key),
        (model.offchain, model.last_userop, model.userop_sigs),
        "after sync(50)"
    );

    // 2) off-chain sign: repair to 50, new_count 51.
    mock_sign_offchain(&key);
    let _ = model.apply_sign_offchain();
    assert_eq!(
        read_triple(&key),
        (model.offchain, model.last_userop, model.userop_sigs),
        "after sign #1 (repair branch)"
    );

    // 3) off-chain sign: gap grows to 1, new_count 52.
    mock_sign_offchain(&key);
    let _ = model.apply_sign_offchain();
    assert_eq!(
        read_triple(&key),
        (model.offchain, model.last_userop, model.userop_sigs),
        "after sign #2"
    );

    // 4) stale sync (10 < 50): tolerant no-op on both.
    unsafe {
        last_userop_count_set(&key, 10).expect("stale sync noop");
    }
    model.apply_offchain_sync(10);
    assert_eq!(
        read_triple(&key),
        (model.offchain, model.last_userop, model.userop_sigs),
        "after stale sync(10)"
    );

    // 5) off-chain sign: gap 2, new_count 53.
    mock_sign_offchain(&key);
    let _ = model.apply_sign_offchain();
    assert_eq!(
        read_triple(&key),
        (model.offchain, model.last_userop, model.userop_sigs),
        "after sign #3"
    );

    // The model tracked the mock through 5 interleaved steps.
    assert_eq!((model.offchain, model.last_userop, model.userop_sigs), (53, 50, 3));
}

// ── c10_sign_verified_with_progress: the host-runnable signing path ──
//
// `crypto.rs` is compiled on host (ungated); the hardware-only peers
// (sign_rate, rng_strong, nsc relock) are `cfg(not(test))`-gated inside the
// function, so the genuine glue — double-compute + ct_eq + verify-before-
// release + CFI transcript + progress ramp — runs here against a real C10
// keypair. Under cfg(test) the OptRand and both shuffle seeds are all-zero,
// so output is fully deterministic.

const SIGN_TEST_SK_SEED: [u8; 32] = [0x42; 32];
const SIGN_TEST_PK_SEED: [u8; 16] = [0x24; 16];
const SIGN_TEST_MSG: [u8; 32] = [0xA5; 32];

fn sign_test_key() -> &'static sphincs_c10::SigningKey {
    // Keygen once per process (same discipline as sphincs-c10's own suite).
    static SK: std::sync::OnceLock<sphincs_c10::SigningKey> = std::sync::OnceLock::new();
    SK.get_or_init(|| {
        sphincs_c10::SigningKey::keygen(SIGN_TEST_SK_SEED, SIGN_TEST_PK_SEED)
    })
}

static PROGRESS_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PROGRESS_MONOTONIC: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);
static PROGRESS_LAST: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

fn record_progress(p: u8) {
    use std::sync::atomic::Ordering;
    let last = PROGRESS_LAST.load(Ordering::SeqCst);
    if p < last {
        PROGRESS_MONOTONIC.store(false, Ordering::SeqCst);
    }
    PROGRESS_LAST.store(p, Ordering::SeqCst);
    PROGRESS_CALLS.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn positive_c10_sign_verified_ok_len_and_independent_verify() {
    // NOTE: `|_| {}` here — only the ramp test drives `record_progress`
    // (the statics are shared; parallel tests must not interleave ramps).
    let sk = sign_test_key();
    let sig = crate::crypto::c10_sign_verified_with_progress(sk, &SIGN_TEST_MSG, crate::progress_halves!(nop_progress))
        .expect("signing path must succeed with valid key + msg");
    assert_eq!(sig.len(), sphincs_c10::params::SIGNATURE_LEN);
    // The released signature must verify under the honest public key through
    // the crate's own free verify (independent of the internal gate).
    assert!(
        sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), &SIGN_TEST_MSG, &sig),
        "released signature must verify under the honest verifying key"
    );
    // A passing call proves the full CFI transcript ran (rate charge →
    // OptRand → shuffle → sign A → sign B → ct_eq → verify gate).
}

/// Silent sink for the tests that do not inspect progress.
fn nop_progress(_pct: u8) {}

#[test]
fn positive_c10_sign_progress_ramps_monotonically_to_100() {
    use std::sync::atomic::Ordering;
    PROGRESS_CALLS.store(0, Ordering::SeqCst);
    PROGRESS_LAST.store(0, Ordering::SeqCst);
    PROGRESS_MONOTONIC.store(true, Ordering::SeqCst);

    let sk = sign_test_key();
    let _ = crate::crypto::c10_sign_verified_with_progress(sk, &SIGN_TEST_MSG, crate::progress_halves!(record_progress))
        .expect("sign must succeed");
    let calls = PROGRESS_CALLS.load(Ordering::SeqCst);
    assert!(calls >= 2, "progress must fire at each major phase, got {calls}");
    assert!(
        PROGRESS_MONOTONIC.load(Ordering::SeqCst),
        "progress must be non-decreasing (UI ramp)"
    );
    assert_eq!(
        PROGRESS_LAST.load(Ordering::SeqCst),
        100,
        "progress ramp must reach 100 on success"
    );
}

#[test]
fn positive_c10_sign_deterministic_given_zeroed_test_seeds() {
    // cfg(test) leaves OptRand and both shuffle seeds all-zero, so two calls
    // must produce byte-identical signatures — the same invariant the
    // production ct_eq gate relies on. NOTE: this pins the TEST harness,
    // not the production contract — production is the exact opposite:
    // `crypto.rs` draws a fresh OptRand per call via `rng_strong::fill`, so
    // two production signs over the same message MUST differ. If the test
    // posture is ever improved to seed OptRand under cfg(test), this test
    // must be updated to match (do not revert the improvement).
    let sk = sign_test_key();
    let sig_a = crate::crypto::c10_sign_verified_with_progress(sk, &SIGN_TEST_MSG, crate::progress_halves!(nop_progress))
        .expect("first sign");
    let sig_b = crate::crypto::c10_sign_verified_with_progress(sk, &SIGN_TEST_MSG, crate::progress_halves!(nop_progress))
        .expect("second sign");
    assert_eq!(sig_a, sig_b, "given identical (zeroed) seeds, signing must be deterministic");
}

#[test]
fn positive_c10_sign_distinct_shuffle_seeds_stay_byte_equal() {
    // The production F-16 configuration: each double-compute pass draws its
    // OWN nonzero shuffle seed, and the glue tests above only exercise the
    // degenerate all-zero-seed configuration under cfg(test). Assert the
    // load-bearing invariant directly: two DISTINCT nonzero seeds must
    // still produce byte-identical signatures (order-only shuffle) that
    // verify. Mirrors sphincs-c10/tests/shuffle_byte_equality.rs at the
    // glue level — a regression here false-rejects 100% of production
    // signs (signing DoS), never a forgery.
    let sk = sign_test_key();
    let opt_rand = [0x07u8; sphincs_c10::params::N];
    let sig_a = sk.sign_with_shuffle(
        &SIGN_TEST_MSG,
        Some(&opt_rand),
        &sphincs_c10::shuffle::ShuffleSeed([0x11; 32]),
        |_| {},
    );
    let sig_b = sk.sign_with_shuffle(
        &SIGN_TEST_MSG,
        Some(&opt_rand),
        &sphincs_c10::shuffle::ShuffleSeed([0x22; 32]),
        |_| {},
    );
    assert_eq!(
        sig_a, sig_b,
        "distinct nonzero shuffle seeds must not affect signature bytes"
    );
    assert!(sphincs_c10::verify(
        sk.pk_seed(),
        sk.pk_root(),
        &SIGN_TEST_MSG,
        &sig_a
    ));
}

#[test]
fn negative_c10_verify_gate_primitive_rejects_tampered_signature() {
    // The glue's negative branches (ct_eq mismatch / verify failure) are
    // FI-only paths — they need a fault to fire. What host testing CAN pin
    // is the gate primitive itself: a single-bit tamper of a genuinely
    // produced signature must fail `sphincs_c10::verify`, otherwise the
    // verify-before-release gate could never fire in production either.
    let sk = sign_test_key();
    let mut sig = crate::crypto::c10_sign_verified_with_progress(sk, &SIGN_TEST_MSG, crate::progress_halves!(nop_progress))
        .expect("sign must succeed");
    sig[123] ^= 0x01;
    assert!(
        !sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), &SIGN_TEST_MSG, &sig),
        "tampered signature must fail verification"
    );
    // And the wrong message must fail too (gate binds the message).
    let sig = crate::crypto::c10_sign_verified_with_progress(sk, &SIGN_TEST_MSG, crate::progress_halves!(nop_progress))
        .expect("sign must succeed");
    let wrong_msg = [0x5Au8; 32];
    assert!(
        !sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), &wrong_msg, &sig),
        "signature must not verify under a different message"
    );
}
