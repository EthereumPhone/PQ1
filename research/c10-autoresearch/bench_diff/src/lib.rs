//! Kit differential: 32 cases (8 keys x 4 messages, diff_cases.rs) signed on the kit through the fast paths;
//! each signature hashed with SOFTWARE SHA-256 (independent of the HASH engine) into SIG0 as
//! [pk_root 16 | sig_sha256 32] x 32, compared on the host with ref-master's list. One pass per case.
#![no_std]
use sha2::{Digest, Sha256};
use sphincs_c10::{shuffle::ShuffleSeed, SigningKey};
include!("../../diff_cases.rs");
const OUT: *mut u32 = 0x3000_0100 as *mut u32;
const NCASE: u32 = 32;
const EVERY: u32 = 4;
#[used]
#[no_mangle]
pub static mut SIG0: [u8; 4008] = [0; 4008];
#[used]
#[no_mangle]
pub static mut SIG1: [u8; 4008] = [0; 4008];
extern "C" { fn bench_halt(code: u32) -> !; }
#[inline(always)] fn out(i: usize, v: u32) { unsafe { core::ptr::write_volatile(OUT.add(i), v) } }
#[no_mangle] pub extern "C" fn pqsigner_hash_fault() -> ! { unsafe { bench_halt(0x00F0) } }
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { unsafe { bench_halt(0x00F1) } }
#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 { out(i, 0); }
    out(0, 0x4331_3044); // 'C10D'
    unsafe { pqsigner_hw::hash::init_clock() };
    let mut key: Option<(u32, SigningKey)> = None;
    let mut ok = 0u32;
    for i in 0..NCASE {
        let c = case(i, EVERY);
        if key.as_ref().map(|k| k.0) != Some(i / EVERY) { key = Some((i / EVERY, SigningKey::keygen(c.sk_seed, c.pk_seed))); }
        let sk = &key.as_ref().unwrap().1;
        let sig = sk.sign_with_shuffle_silent(&c.msg, c.opt_rand.as_ref(), &ShuffleSeed(c.shuffle));
        if sk.verifying_key().verify(&c.msg, &sig) { ok += 1; }
        let h: [u8; 32] = Sha256::digest(sig).into();
        unsafe {
            let p = core::ptr::addr_of_mut!(SIG0).cast::<u8>().add(48 * i as usize);
            core::ptr::copy_nonoverlapping(sk.pk_root().as_ptr(), p, 16);
            core::ptr::copy_nonoverlapping(h.as_ptr(), p.add(16), 32);
        }
        out(2, i + 1);
    }
    out(3, ok);
    out(4, search_edges());
    out(1, 8);
}

extern "C" {
    fn pqsigner_sha256_search128(buf: *const u8, start: u32, n: u32, pred: unsafe extern "C" fn(*const u8) -> bool, out: *mut u8) -> u32;
    fn pqsigner_sha256_oneshot(p: *const u8, n: usize, out: *mut u8);
}
/// Test predicate, about 1 in 64: low 6 bits of the last digest byte are zero (bytes 12..32 only are
/// guaranteed in the search's read-out).
unsafe extern "C" fn pred64(d: *const u8) -> bool {
    unsafe { *d.add(31) & 0x3F == 0 }
}
fn plain(buf: &mut [u8; 128], c: u32) -> [u8; 32] {
    buf[124..128].copy_from_slice(&c.to_be_bytes());
    let mut d = [0u8; 32];
    unsafe { pqsigner_sha256_oneshot(buf.as_ptr(), 128, d.as_mut_ptr()) };
    d
}
/// search128 edge cases on silicon against a plain one-shot loop. Returns a bitmask of passed cases
/// (all 6 bits = 0x3F).
fn search_edges() -> u32 {
    let mut buf = [0u8; 128];
    for (i, b) in buf.iter_mut().enumerate().take(124) { *b = (i as u8).wrapping_mul(37) ^ 0x5A; }
    // reference: the first two hits from 0
    let mut hits = [0u32; 2];
    let mut k = 0;
    let mut c = 0u32;
    while k < 2 { if plain(&mut buf, c)[31] & 0x3F == 0 { hits[k] = c; k += 1; } c += 1; }
    let (h1, h2) = (hits[0], hits[1]);
    let d1 = plain(&mut buf, h1);
    let run = |start: u32, n: u32| -> (u32, [u8; 32]) {
        let mut d = [0u8; 32];
        let r = unsafe { pqsigner_sha256_search128(buf.as_ptr(), start, n, pred64, d.as_mut_ptr()) };
        (r, d)
    };
    let mut m = 0u32;
    let (r, d) = run(h1, 1); if r == h1 && d == d1 { m |= 1; }             // only try
    let (r, d) = run(h1, 5); if r == h1 && d == d1 { m |= 2; }             // first of chunk, speculative discarded
    if h1 >= 3 { let (r, d) = run(h1 - 3, 4); if r == h1 && d == d1 { m |= 4; } } else { m |= 4; } // last of chunk
    let (r, _) = run(h1 + 1, h2 - h1 - 1); if r == h2 { m |= 8; }          // absent: returns start + n
    let (r, _) = run(h1, 0); if r == h1 { m |= 16; }                       // empty chunk
    let (r, d) = run(0, h2 + 10); if r == h1 && d == d1 { m |= 32; }       // long chunk from 0
    m
}
