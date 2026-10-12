//! Actual FORS search: independent SHA reference and controlled adapter outputs.
//! Host hooks check every update; they do not exercise the STM32 peripheral.
#![cfg(feature = "sim-internals")]
use sphincs_c10::sim_internals::grind_r;

fn forced_zero(digest: &[u8; 32]) -> bool {
    (132..143).all(|bit| (digest[31 - bit / 8] >> (bit % 8)) & 1 == 0)
}

#[cfg(not(feature = "hw-sha256"))]
#[test]
fn first_real_sha_result_matches_independent_reference() {
    use sha2::{Digest, Sha256};
    for byte in [0u8, 0x81] {
        let sk = [byte; 32];
        let seed = [byte ^ 0xa1; 16];
        let root = [byte ^ 0x4c; 16];
        let message = [byte ^ 0x5a; 32];
        let rand = [byte ^ 0xef; 16];
        for opt in [None, Some(&rand)] {
            let expected = (0..10_000_000u32)
                .find_map(|nonce| {
                    let mut input = sk.to_vec();
                    input.extend_from_slice(b"R_grind");
                    if let Some(rand) = opt {
                        input.extend_from_slice(rand);
                    }
                    input.extend_from_slice(&message);
                    input.extend_from_slice(&[0; 28]);
                    input.extend_from_slice(&nonce.to_be_bytes());
                    let full: [u8; 32] = Sha256::digest(input).into();
                    let r: [u8; 16] = full[..16].try_into().unwrap();
                    let mut hmsg = Vec::new();
                    for word in [&seed, &root, &r] {
                        hmsg.extend_from_slice(word);
                        hmsg.extend_from_slice(&[0; 16]);
                    }
                    hmsg.extend_from_slice(&message);
                    hmsg.extend_from_slice(&[0xff; 32]);
                    let digest: [u8; 32] = Sha256::digest(hmsg).into();
                    forced_zero(&digest).then_some((r, digest))
                })
                .expect("fixed real-SHA fixture must find a result");
            assert_eq!(grind_r(&sk, &seed, &root, &message, opt), expected);
        }
    }
}

#[cfg(feature = "hw-sha256")]
mod controlled {
    use super::*;
    use std::cell::RefCell;
    struct State {
        accepted: Option<u32>,
        randomized: bool,
        next: u32,
        randomizer_stage: bool,
        input: Vec<u8>,
        lengths: Vec<usize>,
    }
    thread_local! { static STATE: RefCell<Option<State>> = const { RefCell::new(None) }; }
    fn randomizer_digest(nonce: u32) -> [u8; 32] {
        let mut digest = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(0x31));
        digest[..4].copy_from_slice(&nonce.to_be_bytes());
        digest
    }
    fn message_digest(nonce: u32, accept: bool) -> [u8; 32] {
        let mut digest = [0x9d; 32];
        for bit in 132..143 {
            digest[31 - bit / 8] &= !(1 << (bit % 8));
        }
        if !accept {
            let bit = 132 + nonce as usize % 11;
            digest[31 - bit / 8] |= 1 << (bit % 8);
        }
        digest[..4].copy_from_slice(&nonce.to_be_bytes());
        assert_eq!(forced_zero(&digest), accept);
        digest
    }
    #[no_mangle]
    extern "C" fn pqsigner_sha256_init() {
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            let s = s.as_mut().unwrap();
            s.input.clear();
            s.lengths.clear();
        });
    }
    #[no_mangle]
    unsafe extern "C" fn pqsigner_sha256_update(ptr: *const u8, len: usize) {
        // SAFETY: the actual adapter supplies a readable slice.
        let input = unsafe { std::slice::from_raw_parts(ptr, len) };
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            let s = s.as_mut().unwrap();
            s.input.extend_from_slice(input);
            s.lengths.push(len);
        });
    }
    #[no_mangle]
    unsafe extern "C" fn pqsigner_sha256_final(out: *mut u8) {
        let digest = STATE.with(|s| {
            let mut s = s.borrow_mut();
            let s = s.as_mut().unwrap();
            let nonce = s.next;
            assert!(nonce < 10_000_000, "no extra trial after exhaustion");
            if s.randomizer_stage {
                let offset = if s.randomized {
                    assert_eq!(s.lengths, [32, 7, 16, 32, 32]);
                    assert_eq!(&s.input[39..55], &[0xef; 16]);
                    55
                } else {
                    assert_eq!(s.lengths, [32, 7, 32, 32]);
                    39
                };
                assert_eq!(&s.input[..32], &[0x81; 32]);
                assert_eq!(&s.input[32..39], b"R_grind");
                assert_eq!(&s.input[offset..offset + 32], &[0x5a; 32]);
                assert_eq!(&s.input[offset + 32..offset + 60], &[0; 28]);
                assert_eq!(&s.input[offset + 60..], &nonce.to_be_bytes());
                s.randomizer_stage = false;
                randomizer_digest(nonce)
            } else {
                assert_eq!(s.lengths, [32; 5]);
                assert_eq!(&s.input[..16], &[0xa1; 16]);
                assert_eq!(&s.input[16..32], &[0; 16]);
                assert_eq!(&s.input[32..48], &[0x4c; 16]);
                assert_eq!(&s.input[48..64], &[0; 16]);
                assert_eq!(&s.input[64..80], &randomizer_digest(nonce)[..16]);
                assert_eq!(&s.input[80..96], &[0; 16]);
                assert_eq!(&s.input[96..128], &[0x5a; 32]);
                assert_eq!(&s.input[128..160], &[0xff; 32]);
                s.randomizer_stage = true;
                s.next += 1;
                message_digest(nonce, s.accepted == Some(nonce))
            }
        });
        // SAFETY: the actual adapter supplies a writable 32-byte output.
        unsafe { std::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32) };
    }
    #[test]
    fn actual_search_preimages_first_last_and_exhaustion() {
        for randomized in [false, true] {
            for accepted in [
                Some(0),
                Some(1),
                Some(255),
                Some(256),
                Some(9_999_999),
                None,
            ] {
                STATE.with(|s| {
                    *s.borrow_mut() = Some(State {
                        accepted,
                        randomized,
                        next: 0,
                        randomizer_stage: true,
                        input: Vec::with_capacity(160),
                        lengths: Vec::with_capacity(5),
                    })
                });
                let rand = [0xef; 16];
                let result = std::panic::catch_unwind(|| {
                    grind_r(
                        &[0x81; 32],
                        &[0xa1; 16],
                        &[0x4c; 16],
                        &[0x5a; 32],
                        randomized.then_some(&rand),
                    )
                });
                match accepted {
                    Some(nonce) => assert_eq!(
                        result.unwrap(),
                        (
                            randomizer_digest(nonce)[..16].try_into().unwrap(),
                            message_digest(nonce, true)
                        )
                    ),
                    None => {
                        let panic = result.expect_err("exhaustion must panic");
                        let text = panic
                            .downcast_ref::<&str>()
                            .copied()
                            .or_else(|| panic.downcast_ref::<String>().map(String::as_str));
                        assert_eq!(text, Some("R grinding failed after 10M iterations"));
                    }
                }
                STATE.with(|s| {
                    let s = s.borrow();
                    let s = s.as_ref().unwrap();
                    assert!(s.randomizer_stage);
                    assert_eq!(s.next, accepted.map_or(10_000_000, |n| n + 1));
                });
            }
        }
    }
}
