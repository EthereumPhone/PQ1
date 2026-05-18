//! Host-side positive + negative test suite for the
//! `secure-crypto-glue` slice.
//!
//! See `mod.rs` for what this file is, why it pins what it pins, and
//! which slice files are reachable on host vs. covered only by
//! `include_str!` source-text invariants.

#![cfg(test)]

use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::db_roots::{
    ERC20_DB_ROOT, ERC20_POSEIDON_ROOT, NAMES_DB_ROOT, SELECTOR_DB_ROOT, VK_DB_ROOT,
};

use super::offchain_state::{
    last_userop_count_read, last_userop_count_set, offchain_count_bump,
    offchain_count_is_registered, offchain_count_promote_to, offchain_count_read,
    offchain_count_register_slot, slot_key_compute,
};

// ─────────────────────────────────────────────────────────────────────
// 0. Slice source-text fixtures.
// ─────────────────────────────────────────────────────────────────────

const CRYPTO_SRC: &str = include_str!("../crypto.rs");
const DUAL_SE_SRC: &str = include_str!("../dual_se.rs");
const OFFCHAIN_SRC: &str = include_str!("../offchain_state.rs");
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
    assert_eq!(VK_DB_ROOT.len(), 32);
    assert_eq!(ERC20_POSEIDON_ROOT.len(), 32);
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
        ("VK_DB_ROOT", &VK_DB_ROOT),
        ("ERC20_POSEIDON_ROOT", &ERC20_POSEIDON_ROOT),
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
        ("VK", &VK_DB_ROOT),
        ("ERC20_POSEIDON", &ERC20_POSEIDON_ROOT),
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

// =====================================================================
//  PART F — `offchain_state.rs` (per-slot counter facade).
//
//  Runtime-exercise the host-side SRAM-mock backend that's selected
//  whenever `stm32u585` / `pka-accel` aren't enabled. Each test picks
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
    let key = slot_key_compute(10, 11, 12);
    unsafe {
        assert!(!offchain_count_is_registered(&key));
        assert_eq!(offchain_count_read(&key), 0);
        assert_eq!(last_userop_count_read(&key), 0);
    }
}

#[test]
fn positive_offchain_mock_register_then_is_registered_true() {
    let key = slot_key_compute(20, 21, 22);
    unsafe {
        offchain_count_register_slot(&key).expect("register ok");
        assert!(offchain_count_is_registered(&key));
    }
}

#[test]
fn positive_offchain_mock_bump_increases_count() {
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

// ── Source-text pins for `offchain_state.rs` — the mock must
// mirror the flash-backed semantics across the cfg-mux. Drift means
// the QEMU build's behaviour diverges from real silicon.

#[test]
fn positive_offchain_state_dual_backend_cfg_mux() {
    assert!(
        OFFCHAIN_SRC
            .contains("#[cfg(any(feature = \"stm32u585\", feature = \"pka-accel\"))]"),
        "offchain_state.rs missing the flash-backed backend cfg gate",
    );
    assert!(
        OFFCHAIN_SRC
            .contains("#[cfg(not(any(feature = \"stm32u585\", feature = \"pka-accel\")))]"),
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
fn positive_offchain_state_mock_max_slots_is_128() {
    assert!(
        OFFCHAIN_SRC.contains("const MAX_SLOTS: usize = 128;"),
        "mock backend's MAX_SLOTS must be 128 (matches QEMU test budget)",
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
    assert!(
        CRYPTO_SRC.contains("crate::rng_strong::fill(&mut shuffle_seed_buf)"),
        "Shuffle seed must use rng_strong::fill (3-source XOR)",
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
        DUAL_SE_SRC.contains("let half_e = xor_32(entropy, &half_o);"),
        "dual_se.rs must compute half_e = entropy XOR half_o (invariant #1)",
    );
}

#[test]
fn positive_dual_se_three_source_random_for_half_o() {
    // half_o is drawn from STM32 TRNG ⊕ OPTIGA TRNG ⊕ SE050 TRNG so
    // that no single TRNG bias gives an attacker either half.
    assert!(
        DUAL_SE_SRC.contains("crate::rng::fill(&mut half_o)"),
        "half_o must seed from STM32 TRNG",
    );
    assert!(
        DUAL_SE_SRC.contains("self.optiga.random(&mut se_buf)"),
        "half_o must mix in OPTIGA TRNG via .random()",
    );
    assert!(
        DUAL_SE_SRC.contains("self.se050.random(&mut se_buf)"),
        "half_o must mix in SE050 TRNG via .random()",
    );
}

#[test]
fn positive_dual_se_half_o_stuck_at_zero_fails_closed() {
    // FI defense: if all three sources fail / produce zero, the
    // half_o accumulator is zero — the function must refuse to
    // provision rather than fall through with predictable entropy.
    assert!(
        DUAL_SE_SRC.contains("if acc == 0"),
        "dual_se.rs must fail-closed when half_o is all-zero",
    );
    assert!(
        DUAL_SE_SRC.contains("[DUAL/prov] half_o stuck at zero — FI suspected"),
        "dual_se.rs must log the stuck-at-zero failure with the FI tag",
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
    // Every secret stack local is wiped before the function
    // returns, on both the success and failure paths.
    let half_o_zeroize = DUAL_SE_SRC.matches("half_o.zeroize();").count();
    let half_e_zeroize = DUAL_SE_SRC.matches("half_e.zeroize();").count();
    let full_zeroize = DUAL_SE_SRC.matches("full_entropy.zeroize();").count();
    assert!(
        half_o_zeroize >= 2,
        "half_o must be zeroized on both provision + unlock paths; found {half_o_zeroize}",
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
    assert!(
        DUAL_SE_SRC.contains("self.optiga.provision(&half_o, master_secret, vk, bootstrap_vk, pin)"),
        "optiga.provision must receive the shared master_secret",
    );
    assert!(
        DUAL_SE_SRC.contains("self.se050.provision(&half_e, master_secret, vk, bootstrap_vk, pin)"),
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
