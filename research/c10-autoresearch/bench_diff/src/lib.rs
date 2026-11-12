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
    out(1, 8);
}
