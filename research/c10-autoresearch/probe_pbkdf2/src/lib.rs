//! Probe: BIP-39 PBKDF2 (2,048 x HMAC-SHA512) on the kit, the product's mnemonic->seed. OUT[2] = cycles of
//! to_seed(""); OUT[3] = cycles of one SHA-512 compression-equivalent (1,000 x Sha512 over 111 B = 1 block);
//! SIG0[0..64] = the seed (compared on the host).
#![no_std]
use sha2::{Digest, Sha512};
const OUT: *mut u32 = 0x3000_0100 as *mut u32;
#[used] #[no_mangle] pub static mut SIG0: [u8; 4008] = [0; 4008];
#[used] #[no_mangle] pub static mut SIG1: [u8; 4008] = [0; 4008];
extern "C" { fn bench_halt(code: u32) -> !; }
#[no_mangle] pub extern "C" fn pqsigner_hash_fault() -> ! { unsafe { bench_halt(0xF0) } }
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { unsafe { bench_halt(0xF1) } }
#[inline(always)] fn cyc() -> u32 { unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) } }
#[inline(always)] fn out(i: usize, v: u32) { unsafe { core::ptr::write_volatile(OUT.add(i), v) } }
#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 { out(i, 0); }
    out(0, 0x4331_3053);
    let entropy = *b"c10-autoresearch bip39 entropy!!";
    let m = sphincs_tz_bip39::Mnemonic::from_entropy(&entropy);
    let t = cyc();
    let seed = m.to_seed("");
    out(2, cyc().wrapping_sub(t));
    unsafe { core::ptr::copy_nonoverlapping(seed.as_ptr(), core::ptr::addr_of_mut!(SIG0).cast::<u8>(), 64) };
    let mut acc = [0u8; 64];
    let t = cyc();
    for i in 0..1000u32 {
        let mut h = Sha512::new();
        h.update(&acc[..48]);
        h.update(i.to_le_bytes());
        let d = h.finalize();
        acc.copy_from_slice(&d);
    }
    out(3, cyc().wrapping_sub(t) / 1000);
    out(4, acc[0] as u32);
    // software SHA-256, one 64-byte block per digest call (55-byte message) -> ~1 compression
    use sha2::Sha256;
    let mut a2 = [0u8; 32];
    let t = cyc();
    for i in 0..2000u32 {
        let mut h = Sha256::new();
        h.update(&a2[..28]);
        h.update(&a2[..23]);
        h.update(i.to_le_bytes());
        let d = h.finalize();
        a2.copy_from_slice(&d);
    }
    out(5, cyc().wrapping_sub(t) / 2000);
    out(6, a2[0] as u32);
    out(1, 8);
}
