use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};

thread_local! { static INPUT: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) }; }
static CALLS: AtomicUsize = AtomicUsize::new(0);
static R_CALLS: AtomicUsize = AtomicUsize::new(0);
static HMSG_CALLS: AtomicUsize = AtomicUsize::new(0);
static PRIVATE: AtomicUsize = AtomicUsize::new(0);

#[no_mangle]
pub extern "C" fn pqsigner_sha256_init() {
    INPUT.with(|cell| { assert!(cell.borrow().is_none()); *cell.borrow_mut() = Some(Vec::new()); });
}
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_update(ptr: *const u8, len: usize) {
    // Called only by the local crate's synchronous borrowed-slice hook.
    let bytes = std::slice::from_raw_parts(ptr, len);
    INPUT.with(|cell| cell.borrow_mut().as_mut().unwrap().extend_from_slice(bytes));
}
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_final(out: *mut u8) {
    // The caller supplies a writable 32-byte digest buffer.
    let input = INPUT.with(|cell| cell.borrow_mut().take().unwrap());
    CALLS.fetch_add(1, Ordering::Relaxed);
    if input.len() == 80 && &input[32..36] == b"wots" {
        PRIVATE.fetch_add(1, Ordering::Relaxed);
    }
    if (input.len() == 103 || input.len() == 119) && &input[32..39] == b"R_grind" { R_CALLS.fetch_add(1, Ordering::Relaxed); }
    if input.len() == 160 && input[128..] == [255u8; 32] { HMSG_CALLS.fetch_add(1, Ordering::Relaxed); }
    let digest = Sha256::digest(&input);
    std::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32);
}

fn main() {
    for case in 0..5u8 {
        let mut sk = [0u8; 32];
        let mut seed = [0u8; 16];
        for (i, v) in sk.iter_mut().enumerate() {
            *v = match case { 0 => 0, 1 => 255, _ => (i as u8).wrapping_mul(37).wrapping_add(case.wrapping_mul(19)) };
        }
        for (i, v) in seed.iter_mut().enumerate() {
            *v = match case { 0 => 0, 1 => 255, _ => (i as u8).wrapping_mul(13).wrapping_add(case.wrapping_mul(23)) };
        }
        CALLS.store(0, Ordering::Relaxed);
        let key = sphincs_c10::SigningKey::keygen(sk, seed);
        let root = key.pk_root().iter().map(|b| format!("{b:02x}")).collect::<String>();
        println!("K {case} {root} {}", CALLS.load(Ordering::Relaxed));
        let message = [case.wrapping_mul(29).wrapping_add(7); 32];
        let random = [case.wrapping_mul(17).wrapping_add(11); 16];
        for run in 0..4 {
            CALLS.store(0, Ordering::Relaxed);
            R_CALLS.store(0, Ordering::Relaxed);
            HMSG_CALLS.store(0, Ordering::Relaxed);
            let shuffle = sphincs_c10::shuffle::ShuffleSeed(if run < 2 { [0;32] } else { [case+1;32] });
            let sig = key.sign_with_shuffle_silent(&message, if run % 2 == 1 { Some(&random) } else { None }, &shuffle);
            let calls = CALLS.load(Ordering::Relaxed);
            let rc = R_CALLS.load(Ordering::Relaxed);
            let hc = HMSG_CALLS.load(Ordering::Relaxed);
            CALLS.store(0, Ordering::Relaxed);
            assert!(key.verifying_key().verify(&message, &sig));
            let vc = CALLS.load(Ordering::Relaxed);
            let signature = sig.iter().map(|b| format!("{b:02x}")).collect::<String>();
            println!("S {case} {run} {signature} {calls} {rc} {hc} {vc}");
            for position in [-1i32, 0, 16, 224, 2336, 3024, 3028, 4007] {
                let mut bad_sig = sig;
                let mut bad_message = message;
                if position < 0 { bad_message[0] ^= 1; }
                else { bad_sig[position as usize] ^= 1; }
                CALLS.store(0, Ordering::Relaxed);
                let accepted = key.verifying_key().verify(&bad_message, &bad_sig);
                assert!(!accepted, "changed fixture unexpectedly verified");
                println!("N {case} {run} {position} {} {}", u8::from(accepted), CALLS.load(Ordering::Relaxed));
            }
        }
    }
}
