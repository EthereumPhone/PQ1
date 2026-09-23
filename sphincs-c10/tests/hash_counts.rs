//! Step (a) of the §18 SCA analysis: count how many hash calls per sign
//! touch `sk_seed` (the PRF — `wots_secret` / `fors_secret`) versus
//! operate on public pk_seed-derived data.
//!
//! This is the number that decides whether "mask only the
//! secret-touching subset" is feasible. The auth-path Merkle
//! reconstruction (`build_subtree_with_auth` regenerates every leaf of
//! every signed subtree) and the FORS tree construction (every leaf of
//! every FORS tree) both call the PRF per leaf — so the count is far
//! larger than a naive "one secret per signed chain" estimate.
//!
//! Run: `cargo test -p sphincs-c10 --features hash-counters --test hash_counts -- --nocapture`

#![cfg(feature = "hash-counters")]

use sphincs_c10::{counters, SigningKey};

/// The counters are process-global; the tests in this file reset and read
/// them, so they must not run concurrently.
static COUNTERS: std::sync::Mutex<()> = std::sync::Mutex::new(());

const SK_SEED: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];
const PK_SEED: [u8; 16] = [
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const MSG: [u8; 32] = *b"PQSigner C10 hash-count probe !1";

#[test]
fn count_secret_touching_hashes_per_sign() {
    // keygen() also calls the PRF heavily (compute_pk_root builds the
    // top subtree). Reset AFTER keygen so we measure SIGN only.
    let _serial = COUNTERS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let sk = SigningKey::keygen(SK_SEED, PK_SEED);
    counters::reset();

    let _sig = sk.sign(&MSG, None);
    let s = counters::snapshot();

    eprintln!("=== sphincs-c10 hash-call counts for ONE sign ===");
    eprintln!("  wots_secret (PRF, sk_seed): {}", s.wots_secret);
    eprintln!("  fors_secret (PRF, sk_seed): {}", s.fors_secret);
    eprintln!("  SECRET-touching total     : {}", s.secret_touching());
    eprintln!("  chain_hash (WOTS chain F) : {}", s.chain_hash);
    eprintln!("  th* (tree node hashing)   : {}", s.th);
    eprintln!("  other (h_msg/wots_digest) : {}", s.other);
    eprintln!("  TOTAL hash calls          : {}", s.total());
    let pct = (s.secret_touching() as f64 / s.total() as f64) * 100.0;
    eprintln!("  secret-touching fraction  : {pct:.2}%");

    // Sanity floors derived from C10 params (h=18, d=2 → 512 leaves/
    // subtree; k=13 FORS trees × 2^11 = 2048 leaves; L=43 WOTS chains):
    //   wots_secret ≈ D × SUBTREE_LEAVES × L = 2 × 512 × 43 = 44,032
    //   fors_secret ≈ K × FORS_LEAVES        = 13 × 2048    = 26,624
    // The point of this test is to CONFIRM the count is in the tens of
    // thousands (so "mask only the subset" is NOT cheap), not to pin an
    // exact value — assert generous lower bounds so a future param
    // change doesn't silently invalidate the §18 conclusion.
    assert!(
        s.wots_secret >= 40_000,
        "wots_secret PRF count {} unexpectedly low — re-check the §18 \
         'masking the subset is infeasible' conclusion",
        s.wots_secret
    );
    assert!(
        s.fors_secret >= 20_000,
        "fors_secret PRF count {} unexpectedly low — re-check §18",
        s.fors_secret
    );
    assert!(
        s.secret_touching() >= 60_000,
        "secret-touching total {} far below the ~70k expectation — the \
         'mask only the subset' plan's feasibility hinges on this number",
        s.secret_touching()
    );
}

/// The longest stretch of hash calls between two progress reports in one
/// sign. The pixel signing film only advances when the hook fires, so this
/// is the film's worst stall. Before the subtree builds reported inside
/// their leaf loop it was a whole hypertree layer (~200k hashes, ~200 ms
/// on the STM32U585), and the WOTS+C count grind added up to ~100k more in
/// its tail. Both now report from inside their loops; the measured worst
/// over these signs is ~11k (the FORS R-grind keeps a small, geometric
/// tail, so the bound leaves headroom).
#[test]
fn longest_hash_run_between_progress_reports() {
    use std::cell::Cell;
    thread_local! {
        static LAST: Cell<u64> = const { Cell::new(0) };
        static MAX: Cell<u64> = const { Cell::new(0) };
    }
    fn cb(_pct: u8) {
        let now = counters::snapshot().total() as u64;
        LAST.with(|l| {
            MAX.with(|m| m.set(m.get().max(now - l.get())));
            l.set(now);
        });
    }
    let _serial = COUNTERS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let sk = SigningKey::keygen(SK_SEED, PK_SEED);
    let mut worst = 0u64;
    for i in 0..8u8 {
        let mut msg = MSG;
        msg[0] = i;
        counters::reset();
        LAST.with(|l| l.set(0));
        MAX.with(|m| m.set(0));
        let _ = sk.sign_with_shuffle(&msg, None, &sphincs_c10::shuffle::ShuffleSeed::zero(), cb);
        worst = worst.max(MAX.with(Cell::get));
    }
    eprintln!("longest hash run between progress reports (8 signs): {worst}");
    assert!(worst < 40_000, "a progress gap of {worst} hashes stalls the signing film");
}
