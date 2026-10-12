//! Actual Rust grinder: independent real-SHA search and controlled SHA outputs.
//! Controlled hooks exercise the real hardware adapter, not the peripheral.
#![cfg(feature = "sim-internals")]
use sphincs_c10::sim_internals::{find_count, make_adrs};

fn reference_digits(d: &[u8; 32]) -> [u8; 43] {
    std::array::from_fn(|i| {
        (0..3)
            .map(|j| ((d[31 - (3 * i + j) / 8] >> ((3 * i + j) % 8)) & 1) << j)
            .sum()
    })
}

#[cfg(not(feature = "hw-sha256"))]
#[test]
fn first_real_sha_success_matches_independent_reference() {
    use sha2::{Digest, Sha256};
    for (byte, layer, tree, kp) in [(0, 0, 0, 0), (0x81, 1, 0x1234_5678_9abc_def0, 511)] {
        let seed = [byte; 32];
        let message = [byte ^ 0x5a; 32];
        let adrs = make_adrs(layer, tree, 0, kp, 0, 0, 0);
        let expected = (0..10_000_000u32)
            .find_map(|count| {
                let mut input = [seed.as_slice(), adrs.as_slice(), message.as_slice()].concat();
                input.extend_from_slice(&[0; 28]);
                input.extend_from_slice(&count.to_be_bytes());
                let digest: [u8; 32] = Sha256::digest(input).into();
                let digits = reference_digits(&digest);
                (digits.iter().map(|&d| d as usize).sum::<usize>() == 205)
                    .then_some((count, digest, digits))
            })
            .expect("fixed real-SHA fixture must have a success");
        assert_eq!(find_count(&seed, layer, tree, kp, &message), expected);
        assert_eq!(
            sphincs_c10::sim_internals::extract_digits(&expected.1),
            expected.2
        );
    }
}

#[cfg(feature = "hw-sha256")]
mod controlled {
    use super::*;
    use std::cell::RefCell;
    struct State {
        accepted: Option<u32>,
        next: u32,
        input: Vec<u8>,
        good: [u8; 32],
        bad: [u8; 32],
    }
    thread_local! { static STATE: RefCell<Option<State>> = const { RefCell::new(None) }; }

    fn digest_with_sum(mut sum: usize) -> [u8; 32] {
        let mut out = [0; 32];
        for i in 0..43 {
            let d = sum.min(7) as u8;
            sum -= d as usize;
            for j in 0..3 {
                out[31 - (3 * i + j) / 8] |= ((d >> j) & 1) << ((3 * i + j) % 8);
            }
        }
        assert_eq!(sum, 0);
        out
    }

    #[no_mangle]
    extern "C" fn pqsigner_sha256_init() {
        STATE.with(|s| s.borrow_mut().as_mut().unwrap().input.clear());
    }
    #[no_mangle]
    unsafe extern "C" fn pqsigner_sha256_update(ptr: *const u8, len: usize) {
        // SAFETY: the actual adapter supplies a readable input slice.
        let input = unsafe { std::slice::from_raw_parts(ptr, len) };
        STATE.with(|s| {
            s.borrow_mut()
                .as_mut()
                .unwrap()
                .input
                .extend_from_slice(input)
        });
    }
    #[no_mangle]
    unsafe extern "C" fn pqsigner_sha256_final(out: *mut u8) {
        let digest = STATE.with(|s| {
            let mut s = s.borrow_mut();
            let s = s.as_mut().unwrap();
            assert_eq!(s.input.len(), 128);
            assert_eq!(&s.input[..32], &[0x81; 32]);
            assert_eq!(&s.input[32..64], &make_adrs(1, 0x1234, 0, 7, 0, 0, 0));
            assert_eq!(&s.input[64..96], &[0x5a; 32]);
            assert_eq!(&s.input[96..124], &[0; 28]);
            let count = u32::from_be_bytes(s.input[124..128].try_into().unwrap());
            assert_eq!(count, s.next, "no skipped, repeated, or extra trial");
            s.next += 1;
            if s.accepted == Some(count) {
                s.good
            } else {
                s.bad
            }
        });
        // SAFETY: the actual adapter supplies a writable 32-byte buffer.
        unsafe { std::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32) };
    }

    #[test]
    fn actual_search_first_boundary_last_and_exhaustion() {
        for (accepted, bad_sum) in [
            (Some(0), 204),
            (Some(1), 206),
            (Some(4095), 204),
            (Some(4096), 206),
            (Some(9_999_999), 204),
            (None, 206),
        ] {
            let good = digest_with_sum(205);
            let bad = digest_with_sum(bad_sum);
            assert_eq!(
                reference_digits(&good)
                    .iter()
                    .map(|&d| d as usize)
                    .sum::<usize>(),
                205
            );
            assert_eq!(
                reference_digits(&bad)
                    .iter()
                    .map(|&d| d as usize)
                    .sum::<usize>(),
                bad_sum
            );
            STATE.with(|s| {
                *s.borrow_mut() = Some(State {
                    accepted,
                    next: 0,
                    input: Vec::with_capacity(128),
                    good,
                    bad,
                })
            });
            let result =
                std::panic::catch_unwind(|| find_count(&[0x81; 32], 1, 0x1234, 7, &[0x5a; 32]));
            match accepted {
                Some(count) => assert_eq!(result.unwrap(), (count, good, reference_digits(&good))),
                None => {
                    let panic = result.expect_err("exhaustion must panic");
                    let text = panic
                        .downcast_ref::<&str>()
                        .copied()
                        .or_else(|| panic.downcast_ref::<String>().map(String::as_str));
                    assert_eq!(
                        text,
                        Some("WOTS+C count grinding failed after 10M iterations")
                    );
                }
            }
            STATE.with(|s| {
                assert_eq!(
                    s.borrow().as_ref().unwrap().next,
                    accepted.map_or(10_000_000, |c| c + 1)
                )
            });
        }
    }
}
