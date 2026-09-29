//! Runtime tests for the mounted production `rng_strong` three-source fill:
//! the `static mut SOURCE_REPEAT_STATE` history, the busy guard, and the
//! volatile fail-initialized receipt ceremony — the `unsafe` surface the
//! firmware crate itself can only pin via source-text (it is
//! `#[cfg(not(test))]` there).
//!
//! Serialization and isolation: `make test-all` runs this crate under
//! `cargo test --workspace` with DEFAULT parallel threads, and the mounted
//! module has exactly one global history/guard pair, so every test holds
//! `SERIAL` for its whole body (the Makefile Miri leg additionally passes
//! `--test-threads=1`). libtest runs tests in sorted name order; the two
//! stuck-chip tests deliberately use DISTINCT constant streams (0x77 / 0x66)
//! so neither one's committed repetition history can satisfy the other's
//! assertion. A prior test can otherwise leave READY history for the same
//! constant and pass a test for the wrong reason.

use pqsigner_secure_miri_tests::{mock, rng, rng_strong};

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn reset_healthy() {
    rng::set_ok();
    mock::se_ok_unique(mock::OPTIGA);
    mock::se_ok_unique(mock::SE050);
}

fn assert_zeroed(buf: &[u8]) {
    assert!(buf.iter().all(|&b| b == 0), "failure path must wipe the buffer");
}

#[test]
fn positive_three_source_fill_succeeds_twice_and_differs() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    let mut a = [0xCCu8; 32];
    let mut b = [0xCCu8; 32];
    assert!(rng_strong::fill(&mut a).is_ok());
    assert!(rng_strong::fill(&mut b).is_ok());
    assert!(a.iter().any(|&x| x != 0));
    assert_ne!(a, b, "fresh counter streams must not repeat an output");
}

#[test]
fn positive_generic_lengths_8_32_33_65() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    for len in [8usize, 32, 33, 65] {
        let mut buf = vec![0u8; len];
        assert!(rng_strong::fill(&mut buf).is_ok(), "len {len} must fill");
        assert!(buf.iter().any(|&x| x != 0), "len {len} must be nonzero");
    }
}

#[test]
fn positive_empty_buffer_is_ok() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    assert!(rng_strong::fill(&mut []).is_ok());
}

#[test]
fn negative_too_short_buffer_fails_and_wipes() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    let mut buf = [0xAAu8; 7];
    assert!(rng_strong::fill(&mut buf).is_err());
    assert_zeroed(&buf);
}

#[test]
fn negative_platform_failure_fails_and_wipes() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    rng::set_fail();
    let mut buf = [0xAAu8; 16];
    assert!(rng_strong::fill(&mut buf).is_err());
    assert_zeroed(&buf);
}

#[test]
fn negative_platform_all_zero_fails_and_wipes() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    rng::set_zero();
    let mut buf = [0xAAu8; 16];
    assert!(rng_strong::fill(&mut buf).is_err());
    assert_zeroed(&buf);
}

#[test]
fn negative_optiga_failure_fails_and_wipes() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    mock::se_fail(mock::OPTIGA);
    let mut buf = [0xAAu8; 16];
    assert!(rng_strong::fill(&mut buf).is_err());
    assert_zeroed(&buf);
}

#[test]
fn negative_se050_failure_fails_and_wipes() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    mock::se_fail(mock::SE050);
    let mut buf = [0xAAu8; 16];
    assert!(rng_strong::fill(&mut buf).is_err());
    assert_zeroed(&buf);
}

#[test]
fn negative_zero_se_contribution_fails_and_wipes() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    mock::se_zero(mock::SE050);
    let mut buf = [0xAAu8; 16];
    assert!(rng_strong::fill(&mut buf).is_err());
    assert_zeroed(&buf);
}

#[test]
fn negative_equal_se_streams_cancel_and_fail() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    // Both chips returning the identical nonzero stream would XOR-cancel the
    // SE contribution; the pairwise-differ health gate must reject it.
    mock::se_stuck_const(mock::OPTIGA, 0x5A);
    mock::se_stuck_const(mock::SE050, 0x5A);
    let mut buf = [0xAAu8; 16];
    assert!(rng_strong::fill(&mut buf).is_err());
    assert_zeroed(&buf);
}

#[test]
fn negative_stuck_chip_caught_by_repetition_history() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    // A chip returning one fixed stream forever: the first call MUST pass
    // (asserted — if it failed, the second call would prove nothing), the
    // second MUST fail the continuous-repetition gate. 0x77 is unique to
    // this test; see the header note on distinct stuck-stream constants.
    mock::se_stuck_const(mock::OPTIGA, 0x77);
    let mut first = [0u8; 16];
    let mut second = [0xAAu8; 16];
    assert!(
        rng_strong::fill(&mut first).is_ok(),
        "first stuck-stream fill must pass (history fresh); a failure here invalidates the repetition assertion below"
    );
    assert!(
        rng_strong::fill(&mut second).is_err(),
        "repeated OPTIGA stream must trip the repetition history gate"
    );
    assert_zeroed(&second);
}

#[test]
fn negative_busy_guard_rejects_reentrant_fill() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    mock::se_reentrant(mock::OPTIGA);
    let mut buf = [0xAAu8; 16];
    // The outer fill fails because its OPTIGA draw propagated the nested
    // verdict; the security property is the nested result: a fill attempted
    // while one is already live MUST fail (single shared physical history).
    assert!(rng_strong::fill(&mut buf).is_err());
    assert_eq!(
        mock::reentrant_result(),
        Some(false),
        "re-entrant fill must be rejected by the busy guard"
    );
    assert_zeroed(&buf);
}

#[test]
fn negative_stuck_chip_multi_chunk_fails_within_the_first_fill() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    // 0x66 is unique to this test (see header note): no prior test can have
    // seeded READY history with it, so the first chunk CANNOT trip the
    // repetition gate — only chunk 2 repeating chunk 1's committed block can.
    mock::se_stuck_const(mock::OPTIGA, 0x66);
    // A >32-byte buffer takes two chunks: chunk 2's OPTIGA block repeats the
    // chunk-1 block committed to the repetition history, so even the FIRST
    // fill against a stuck chip must fail (no reliance on a second call).
    let mut buf = [0xAAu8; 33];
    assert!(rng_strong::fill(&mut buf).is_err());
    assert_zeroed(&buf);
}

#[test]
fn positive_busy_guard_released_after_failure() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset_healthy();
    mock::se_fail(mock::OPTIGA);
    let mut buf = [0xAAu8; 16];
    assert!(rng_strong::fill(&mut buf).is_err());
    assert_zeroed(&buf);
    // A guard leak would DoS every later draw; the error path must release.
    reset_healthy();
    assert!(rng_strong::fill(&mut buf).is_ok(), "guard must be released after a failed fill");
    assert!(buf.iter().any(|&x| x != 0));
}

// ── fill_with_store (the strict store-driven fill) ──

use pqsigner_secure_miri_tests::secure_element::{SeError, WalletStore};

struct MockStore {
    fail_optiga: bool,
    fail_se050: bool,
    counter: u32,
}

impl MockStore {
    fn healthy(seed: u32) -> Self {
        Self { fail_optiga: false, fail_se050: false, counter: seed }
    }
    fn draw(&mut self, complement: bool, buf: &mut [u8]) -> Result<(), SeError> {
        if (complement && self.fail_se050) || (!complement && self.fail_optiga) {
            return Err(SeError::Failed);
        }
        for b in buf.iter_mut() {
            self.counter = self.counter.wrapping_add(1);
            *b = if complement { !(self.counter as u8) } else { self.counter as u8 };
        }
        Ok(())
    }
}

impl WalletStore for MockStore {
    fn random_optiga(&mut self, buf: &mut [u8]) -> Result<(), SeError> {
        self.draw(false, buf)
    }
    fn random_se050(&mut self, buf: &mut [u8]) -> Result<(), SeError> {
        self.draw(true, buf)
    }
}

#[test]
fn positive_fill_with_store_succeeds() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    rng::set_ok();
    let mut store = MockStore::healthy(0x1000_0000);
    let mut buf = [0u8; 16];
    assert!(pqsigner_secure_miri_tests::fill_with_store(&mut buf, &mut store).is_ok());
    assert!(buf.iter().any(|&x| x != 0));
}

#[test]
fn negative_fill_with_store_optiga_failure_fails_and_wipes() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    rng::set_ok();
    let mut store = MockStore::healthy(0x2000_0000);
    store.fail_optiga = true;
    let mut buf = [0xAAu8; 16];
    assert!(pqsigner_secure_miri_tests::fill_with_store(&mut buf, &mut store).is_err());
    assert_zeroed(&buf);
}
