//! Host golden generator / checker for the C10 autoresearch loop.
//! Builds sphincs-c10 with `hw-sha256-oneshot` (the secure image's code path) and supplies the
//! hash hooks in software, counting every SHA-256 digest exactly.
//! `c10-ar-host write <golden.bin>` writes pk_root + sigA(m0) + sigA(m1); `check <golden.bin>`
//! recomputes and compares byte-for-byte. Prints digest counts per segment as `COUNT name n`.
use sha2::{Digest, Sha256};
use sphincs_c10::{shuffle::ShuffleSeed, SigningKey};
use std::cell::RefCell;

include!("../../inputs.rs");

static HOOKS: std::sync::Mutex<[u64; 8]> = std::sync::Mutex::new([0; 8]);
fn hook(i: usize, n: u64) { HOOKS.lock().unwrap()[i] += n; }
fn hooks_take() -> [u64; 8] { std::mem::replace(&mut *HOOKS.lock().unwrap(), [0; 8]) }
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
    hook(6, 1);
    let mut d = [0u8; 32];
    unsafe { pqsigner_sha256_oneshot(p, n, d.as_mut_ptr()); std::ptr::copy_nonoverlapping(d.as_ptr(), out, 16) };
}
/// WOTS chain hook (driver `chain16`): plain software SHA-256 per step.
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_chain16(buf: *mut u8, start: u32, steps: u32) {
    hook(0, steps as u64);
    let b = unsafe { std::slice::from_raw_parts_mut(buf, 96) };
    for i in 0..steps {
        b[56..60].copy_from_slice(&(start + i).to_be_bytes());
        let mut d = [0u8; 32];
        unsafe { pqsigner_sha256_oneshot(b.as_ptr(), 96, d.as_mut_ptr()) };
        b[64..80].copy_from_slice(&d[..16]);
    }
}
/// Counter search hook (driver `search128`): sequential software search.
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_search128(buf: *const u8, start: u32, n: u32,
    pred: unsafe extern "C" fn(*const u8) -> bool, out: *mut u8) -> u32 {
    let mut b = [0u8; 128];
    unsafe { std::ptr::copy_nonoverlapping(buf, b.as_mut_ptr(), 128) };
    for c in start..start + n {
        hook(1, 1);
        b[124..128].copy_from_slice(&c.to_be_bytes());
        let mut d = [0u8; 32];
        unsafe { pqsigner_sha256_oneshot(b.as_ptr(), 128, d.as_mut_ptr()) };
        if unsafe { pred(d.as_ptr()) } {
            unsafe { std::ptr::copy_nonoverlapping(d.as_ptr(), out, 32) };
            return c;
        }
    }
    start + n
}
/// Gather hooks (driver `gather`): software SHA-256 of the concatenated 32-byte parts, first 16 bytes.
unsafe fn gather(parts: &[*const u8], out: *mut u8) {
    hook(5, 1);
    let mut b = Vec::new();
    for p in parts { b.extend_from_slice(unsafe { std::slice::from_raw_parts(*p, 32) }); }
    let mut d = [0u8; 32];
    unsafe { pqsigner_sha256_oneshot(b.as_ptr(), b.len(), d.as_mut_ptr()); std::ptr::copy_nonoverlapping(d.as_ptr(), out, 16) };
}
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_3x32_16(a: *const u8, b: *const u8, c: *const u8, out: *mut u8) { unsafe { gather(&[a, b, c], out) } }
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_4x32_16(a: *const u8, b: *const u8, c: *const u8, d: *const u8, out: *mut u8) { unsafe { gather(&[a, b, c, d], out) } }
/// Fused WOTS PRF + chain hook (driver `prfchain`): software SHA-256.
#[no_mangle]
pub unsafe extern "C" fn pqsigner_wots_prf_chain16(sk: *const u8, tail: *const u8, sa: *const u8, steps: u32, out: *mut u8) {
    hook(4, 1);
    let mut p = Vec::new();
    p.extend_from_slice(unsafe { std::slice::from_raw_parts(sk, 32) });
    p.extend_from_slice(unsafe { std::slice::from_raw_parts(tail, 48) });
    let mut d = [0u8; 32];
    unsafe { pqsigner_sha256_oneshot(p.as_ptr(), 80, d.as_mut_ptr()) };
    let mut b = [0u8; 96];
    b[..64].copy_from_slice(unsafe { std::slice::from_raw_parts(sa, 64) });
    b[64..80].copy_from_slice(&d[..16]);
    unsafe { pqsigner_sha256_chain16(b.as_mut_ptr(), 0, steps); std::ptr::copy_nonoverlapping(b.as_ptr().add(64), out, 16) };
}
/// Fused FORS PRF + leaf hook (driver `forsleaf`): software SHA-256.
#[no_mangle]
pub unsafe extern "C" fn pqsigner_fors_leaf16(sk: *const u8, tail: *const u8, sa: *const u8, out: *mut u8) {
    hook(2, 1);
    let mut p = Vec::new();
    p.extend_from_slice(unsafe { std::slice::from_raw_parts(sk, 32) });
    p.extend_from_slice(unsafe { std::slice::from_raw_parts(tail, 16) });
    let mut d = [0u8; 32];
    unsafe { pqsigner_sha256_oneshot(p.as_ptr(), 48, d.as_mut_ptr()) };
    let mut b = [0u8; 96];
    b[..64].copy_from_slice(unsafe { std::slice::from_raw_parts(sa, 64) });
    b[64..80].copy_from_slice(&d[..16]);
    unsafe { pqsigner_sha256_oneshot(b.as_ptr(), 96, d.as_mut_ptr()); std::ptr::copy_nonoverlapping(d.as_ptr(), out, 16) };
}
/// Merkle node hook (driver `node16`): SHA-256(seed_adrs ‖ l ‖ 0^16 ‖ r ‖ 0^16)[..16].
#[no_mangle]
pub unsafe extern "C" fn pqsigner_node16(sa: *const u8, l: *const u8, r: *const u8, out: *mut u8) {
    hook(3, 1);
    let mut b = [0u8; 128];
    b[..64].copy_from_slice(unsafe { std::slice::from_raw_parts(sa, 64) });
    b[64..80].copy_from_slice(unsafe { std::slice::from_raw_parts(l, 16) });
    b[96..112].copy_from_slice(unsafe { std::slice::from_raw_parts(r, 16) });
    let mut d = [0u8; 32];
    unsafe { pqsigner_sha256_oneshot(b.as_ptr(), 128, d.as_mut_ptr()); std::ptr::copy_nonoverlapping(d.as_ptr(), out, 16) };
}
/// Per-key WOTS chains hook (driver `wots_chains16`): software, via the fused PRF+chain hook.
#[no_mangle]
pub unsafe extern "C" fn pqsigner_wots_chains16(sk: *const u8, tail: *const u8, sa: *const u8, order: *const u8,
    digits: *const u8, fixed: u32, n: u32, out: *mut u8) {
    for k in 0..n as usize {
        let i = if order.is_null() { k } else { unsafe { *order.add(k) } as usize };
        let steps = if digits.is_null() { fixed } else { unsafe { *digits.add(i) } as u32 };
        let mut t = [0u8; 48];
        t.copy_from_slice(unsafe { std::slice::from_raw_parts(tail, 48) });
        t[44..48].copy_from_slice(&(i as u32).to_be_bytes());
        let mut a = [0u8; 64];
        a.copy_from_slice(unsafe { std::slice::from_raw_parts(sa, 64) });
        a[52..56].copy_from_slice(&(i as u32).to_be_bytes());
        unsafe { pqsigner_wots_prf_chain16(sk, t.as_ptr(), a.as_ptr(), steps, out.add(16 * i)) };
    }
}
fn take() -> u64 { N_DIGESTS.with(|n| std::mem::replace(&mut *n.borrow_mut(), 0)) }

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (mode, path) = (a.get(1).map(String::as_str).unwrap_or("check"), a.get(2).cloned().unwrap_or("golden.bin".into()));
    take();
    let sk = SigningKey::keygen(SK_SEED, PK_SEED);
    println!("COUNT keygen {}", take());
    hooks_take();
    let s0 = sk.sign_with_shuffle_silent(&MSG0, Some(&OPT_RAND), &ShuffleSeed(SHUFFLE_A));
    println!("COUNT signA_m0 {}", take());
    { let h = hooks_take(); println!("HOOKS2 signA_m0 chain_steps={} search_tries={} fors_leaf={} node16={} prf_chain={} gather={} oneshot16={}", h[0], h[1], h[2], h[3], h[4], h[5], h[6]); }
    let s0b = sk.sign_with_shuffle_silent(&MSG0, Some(&OPT_RAND), &ShuffleSeed(SHUFFLE_B));
    println!("COUNT signB_m0 {}", take());
    let ok = sk.verifying_key().verify(&MSG0, &s0);
    println!("COUNT verify_m0 {}", take());
    hooks_take();
    let s1 = sk.sign_with_shuffle_silent(&MSG1, Some(&OPT_RAND), &ShuffleSeed(SHUFFLE_A));
    println!("COUNT signA_m1 {}", take());
    { let h = hooks_take(); println!("HOOKS2 signA_m1 chain_steps={} search_tries={} fors_leaf={} node16={} prf_chain={} gather={} oneshot16={}", h[0], h[1], h[2], h[3], h[4], h[5], h[6]); }
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
