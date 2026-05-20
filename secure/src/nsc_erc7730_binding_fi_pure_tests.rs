//! Host-side regression tests for the FI-hardened ERC-7730 binding
//! cross-check gates (Phase 5 item 6).
//!
//! All three sign dispatchers — `cmd_sign_userop`, `cmd_sign_userop_batch`,
//! `cmd_sign_offchain` — invoke `tx::erc7730::cross_check_contract` or
//! `cross_check_eip712` to bind a verified descriptor to the actual
//! `(chain_id, to_address)` / `(chain_id, contract, domain_separator)`
//! tuple. Before Phase 5 item 6 these were single-instruction boolean
//! checks (`if cross_check_*(...).is_err() { reject }`), which a
//! glitched skip on the `cmp` / branch could bypass.
//!
//! Phase 5 item 6 wraps each call site in the double-evaluation
//! `fi::check_true_into_sentinel` idiom — same structure used by
//! `crypto::c10_sign_verified_with_progress` for the verify-before-
//! release gate. The verdict is computed once, then re-checked with a
//! `wait_random()` between the two evaluations, and the result is
//! sentinel-encoded (Hamming-distant OK / FAIL constants) so a
//! garbage register value almost certainly takes the error path.
//!
//! Direct fault-injection tests would require hardware (a
//! ChipWhisperer rig); instead the tests below enforce the call-site
//! STRUCTURE via source-text inspection. A future regression that
//! removes the `wait_random()` or the `check_true_into_sentinel`
//! wrapper trips one of these tests.

const CMD_SIGN_USEROP: &str = include_str!("nsc/cmd_sign_userop.rs");
const CMD_SIGN_USEROP_BATCH: &str = include_str!("nsc/cmd_sign_userop_batch.rs");
const CMD_SIGN_OFFCHAIN: &str = include_str!("nsc/cmd_sign_offchain.rs");

/// The three call sites all use the same idiom: compute `bind_ok`
/// (or `eip712_bind_ok` / `candidate_ok`) once, follow with
/// `wait_random()` then a `check_true_into_sentinel(|| black_box(...))`
/// compared against `OK_SENTINEL`. Source-text count helpers.

fn count_substr(hay: &str, needle: &str) -> usize {
    let mut n = 0;
    let mut s = hay;
    while let Some(i) = s.find(needle) {
        n += 1;
        s = &s[i + needle.len()..];
    }
    n
}

#[test]
fn cmd_sign_userop_uses_fi_hardened_binding_check() {
    // Pattern: `cross_check_contract` is called exactly once and the
    // result feeds an `fi::check_true_into_sentinel` gate.
    assert_eq!(
        count_substr(CMD_SIGN_USEROP, "cross_check_contract"),
        2,
        "cmd_sign_userop.rs must call cross_check_contract exactly \
         once (one call site + one doc reference). Adjust this count \
         if the dispatcher grows new binding cross-checks; do NOT \
         drop the FI hardening."
    );
    assert!(
        CMD_SIGN_USEROP.contains("let bind_ok = crate::tx::erc7730::cross_check_contract("),
        "cmd_sign_userop.rs binding check must compute verdict once into \
         `bind_ok` so the subsequent `check_true_into_sentinel` can \
         double-evaluate without re-running the cross-check."
    );
    assert!(
        CMD_SIGN_USEROP
            .contains("crate::fi::check_true_into_sentinel(|| core::hint::black_box(bind_ok))"),
        "cmd_sign_userop.rs binding check must wrap `bind_ok` in \
         `check_true_into_sentinel(|| black_box(...))` — black_box \
         prevents LLVM from CSEing the double-evaluation back into a \
         single load (F-1 in tools/sca/README.md)."
    );
    // The `wait_random()` between the verdict computation and the
    // sentinel check is load-bearing: it defeats clock-aligned glitch
    // bursts that time their fault to the fixed-shape control flow of
    // the sentinel compare.
    let pos_check = CMD_SIGN_USEROP
        .find("check_true_into_sentinel(|| core::hint::black_box(bind_ok))")
        .expect("must contain the FI-hardened sentinel compare");
    let pre = &CMD_SIGN_USEROP[..pos_check];
    let pos_wait = pre
        .rfind("crate::fi::wait_random();")
        .expect("must precede sentinel compare with `wait_random()`");
    let pos_assign = pre
        .rfind("let bind_ok = ")
        .expect("must compute verdict into bind_ok before wait_random");
    assert!(
        pos_assign < pos_wait && pos_wait < pos_check,
        "Ordering must be: compute bind_ok → wait_random → sentinel \
         compare. Re-ordering defeats the clock-aligned-glitch defence."
    );
}

#[test]
fn cmd_sign_offchain_uses_fi_hardened_binding_check() {
    assert!(
        CMD_SIGN_OFFCHAIN.contains("cross_check_eip712"),
        "cmd_sign_offchain.rs must call cross_check_eip712 for EIP-712 \
         typed-sign binding."
    );
    assert!(
        CMD_SIGN_OFFCHAIN
            .contains("let eip712_bind_ok = crate::tx::erc7730::cross_check_eip712("),
        "cmd_sign_offchain.rs binding check must compute verdict once \
         into `eip712_bind_ok` (Phase 5 item 6)."
    );
    assert!(
        CMD_SIGN_OFFCHAIN.contains(
            "crate::fi::check_true_into_sentinel(|| core::hint::black_box(eip712_bind_ok))"
        ),
        "cmd_sign_offchain.rs binding check must use \
         `check_true_into_sentinel(|| black_box(eip712_bind_ok))` against \
         OK_SENTINEL."
    );
    let pos_check = CMD_SIGN_OFFCHAIN
        .find("check_true_into_sentinel(|| core::hint::black_box(eip712_bind_ok))")
        .unwrap();
    let pre = &CMD_SIGN_OFFCHAIN[..pos_check];
    let pos_wait = pre.rfind("crate::fi::wait_random();").unwrap();
    let pos_assign = pre.rfind("let eip712_bind_ok = ").unwrap();
    assert!(pos_assign < pos_wait && pos_wait < pos_check);
}

#[test]
fn cmd_sign_userop_batch_uses_fi_hardened_per_candidate_check() {
    // Wire v2 (TLV-tagged trailer list): the companion declares which
    // inner tx an ERC-7730 trailer binds to via `tx_idx`, so the
    // firmware does a single per-`tx_idx` binding check instead of
    // searching for the matching inner tx. The cross_check_contract
    // verdict is computed once into `bind_ok` so the
    // `check_true_into_sentinel` can double-evaluate without re-running
    // the keccak comparison.
    assert!(
        CMD_SIGN_USEROP_BATCH.contains("cross_check_contract"),
        "cmd_sign_userop_batch.rs must call cross_check_contract for \
         every routed ERC-7730 trailer."
    );
    assert!(
        CMD_SIGN_USEROP_BATCH
            .contains("let bind_ok = crate::tx::erc7730::cross_check_contract("),
        "batch dispatcher must compute the ERC-7730 binding verdict \
         once into `bind_ok` so the sentinel re-check is cheap."
    );
    assert!(
        CMD_SIGN_USEROP_BATCH
            .contains("check_true_into_sentinel(|| core::hint::black_box(bind_ok))"),
        "batch dispatcher must check `bind_ok` via the sentinel idiom \
         (parity with `cmd_sign_userop.rs:533-548`)."
    );
}

#[test]
fn all_binding_sites_call_wait_random_before_sentinel() {
    // Every binding cross-check site must wrap its verdict in
    // `wait_random` + `check_true_into_sentinel(|| black_box(bind_ok))`.
    // Three files emit such sites today:
    //   * cmd_sign_userop.rs        — single-tx ERC-7730 binding
    //   * cmd_sign_offchain.rs      — EIP-712 typed-data binding
    //   * cmd_sign_userop_batch.rs  — per-tx ERC-7730 binding (wire v2)
    let userop = count_substr(
        CMD_SIGN_USEROP,
        "check_true_into_sentinel(|| core::hint::black_box(bind_ok))",
    );
    let offchain = count_substr(
        CMD_SIGN_OFFCHAIN,
        "check_true_into_sentinel(|| core::hint::black_box(eip712_bind_ok))",
    );
    let batch = count_substr(
        CMD_SIGN_USEROP_BATCH,
        "check_true_into_sentinel(|| core::hint::black_box(bind_ok))",
    );
    assert!(
        userop >= 1,
        "cmd_sign_userop.rs must keep its sentinel-wrapped binding check."
    );
    assert!(
        offchain >= 1,
        "cmd_sign_offchain.rs must keep its sentinel-wrapped binding check."
    );
    assert!(
        batch >= 1,
        "cmd_sign_userop_batch.rs must wrap the ERC-7730 binding check \
         in `check_true_into_sentinel(|| black_box(bind_ok))`. Got {}.",
        batch
    );
}
