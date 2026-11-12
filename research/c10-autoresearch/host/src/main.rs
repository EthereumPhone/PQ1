//! Host golden generator / checker for the C10 autoresearch loop.
//! Builds sphincs-c10 with `hw-sha256-oneshot` (the secure image's code path) and supplies the
//! hash hooks in software, counting every SHA-256 digest exactly.
//! `c10-ar-host write <golden.bin>` writes pk_root + sigA(m0) + sigA(m1); `check <golden.bin>`
//! recomputes and compares byte-for-byte. Prints digest counts per segment as `COUNT name n`.
use sha2::{Digest, Sha256};
use sphincs_c10::{shuffle::ShuffleSeed, SigningKey};
use std::cell::RefCell;

include!("../../inputs.rs");

thread_local! {
    static CTX: RefCell<Option<Sha256>> = const { RefCell::new(None) };
    static N_DIGESTS: RefCell<u64> = const { RefCell::new(0) };
}
#[no_mangle]
pub extern "C" fn pqsigner_sha256_init() {
    CTX.with(|c| *c.borrow_mut() = Some(Sha256::new()));
}
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_update(p: *const u8, n: usize) {
    let s = unsafe { std::slice::from_raw_parts(p, n) };
    CTX.with(|c| c.borrow_mut().as_mut().expect("update before init").update(s));
}
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_final(out: *mut u8) {
    let d = CTX.with(|c| c.borrow_mut().take().expect("final before init").finalize());
    N_DIGESTS.with(|n| *n.borrow_mut() += 1);
    unsafe { std::ptr::copy_nonoverlapping(d.as_ptr(), out, 32) };
}
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_oneshot(p: *const u8, n: usize, out: *mut u8) {
    pqsigner_sha256_init();
    unsafe { pqsigner_sha256_update(p, n); pqsigner_sha256_final(out) };
}
/// 16-byte one-shot (driver `oneshot16`): software SHA-256, first 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_oneshot16(p: *const u8, n: usize, out: *mut u8) {
    let mut d = [0u8; 32];
    unsafe { pqsigner_sha256_oneshot(p, n, d.as_mut_ptr()); std::ptr::copy_nonoverlapping(d.as_ptr(), out, 16) };
}
fn take() -> u64 { N_DIGESTS.with(|n| std::mem::replace(&mut *n.borrow_mut(), 0)) }

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (mode, path) = (a.get(1).map(String::as_str).unwrap_or("check"), a.get(2).cloned().unwrap_or("golden.bin".into()));
    take();
    let sk = SigningKey::keygen(SK_SEED, PK_SEED);
    println!("COUNT keygen {}", take());
    let s0 = sk.sign_with_shuffle_silent(&MSG0, Some(&OPT_RAND), &ShuffleSeed(SHUFFLE_A));
    println!("COUNT signA_m0 {}", take());
    let s0b = sk.sign_with_shuffle_silent(&MSG0, Some(&OPT_RAND), &ShuffleSeed(SHUFFLE_B));
    println!("COUNT signB_m0 {}", take());
    let ok = sk.verifying_key().verify(&MSG0, &s0);
    println!("COUNT verify_m0 {}", take());
    let s1 = sk.sign_with_shuffle_silent(&MSG1, Some(&OPT_RAND), &ShuffleSeed(SHUFFLE_A));
    println!("COUNT signA_m1 {}", take());
    let ok1 = sk.verifying_key().verify(&MSG1, &s1);
    take();
    assert!(ok && ok1, "verify failed");
    assert_eq!(s0, s0b, "pass A != pass B");
    let mut g = Vec::new();
    g.extend_from_slice(sk.pk_root());
    g.extend_from_slice(&s0);
    g.extend_from_slice(&s1);
    println!("PK_ROOT {}", hex::encode(sk.pk_root()));
    println!("GOLDEN_SHA256 {}", hex::encode(Sha256::digest(&g)));
    match mode {
        "write" => { std::fs::write(&path, &g).unwrap(); println!("WROTE {path}"); }
        _ => {
            let want = std::fs::read(&path).expect("golden file");
            if want != g { println!("GOLDEN MISMATCH"); std::process::exit(1) }
            println!("GOLDEN OK");
        }
    }
}
