// Round 6 "test zero": DWT cycles per digest of each fused v2 driver entry,
// in isolation, on fixed inputs. Not a gate (bench_v2drv checks the bytes).
// Result window (0x3000_0100): 0 magic 'MCR2', 1 stage (100 = done), then
// pairs (cycles, digests) per measurement from word 2.
#![no_std]

const OUT: *mut u32 = 0x3000_0100 as *mut u32;
extern "C" {
    fn bench_halt(code: u32) -> !;
    fn pqsigner_v2_chain16(seed: *const u8, val: *mut u8, a0: u32, low24: u32, start: u32, steps: u32);
    fn pqsigner_v2_node16(seed: *const u8, l: *const u8, r: *const u8, a0: u32, a1: u32, out: *mut u8);
    fn pqsigner_v2_wots_chains16(sk: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, low24: u32, steps: u32, out: *mut u8);
    fn pqsigner_v2_wots_pk16(sk: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, low24: u32, k0: u32, k1: u32, steps: u32, out: *mut u8);
    fn pqsigner_v2_fors_subtree16(sk: *const u8, seed: *const u8, p0: u32, p1: u32, a0: u32, a1: u32, j0: u32, h: u32, out: *mut u8);
    fn pqsigner_v2_search43_target(sm: *const u8, a0: u32, a1: u32, start: u32, n: u32, target: u32, out: *mut u8) -> u32;
}
#[no_mangle]
pub static mut SIG0: [u8; 4008] = [0; 4008];
#[no_mangle]
pub static mut SIG1: [u8; 4008] = [0; 4008];
#[no_mangle]
pub extern "C" fn pqsigner_hash_fault() -> ! {
    // SAFETY: harness halt.
    unsafe { bench_halt(0x00F0) }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: harness halt.
    unsafe { bench_halt(0x00F1) }
}
#[inline(always)]
fn out(i: usize, v: u32) {
    // SAFETY: the harness's result window.
    unsafe { core::ptr::write_volatile(OUT.add(i), v) }
}
#[inline(always)]
fn cyc() -> u32 {
    // SAFETY: DWT_CYCCNT, enabled by the harness.
    unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) }
}

#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 {
        out(i, 0);
    }
    out(0, 0x4D43_5232);
    // SAFETY: single-threaded; keeps the runner's symbols.
    unsafe {
        core::ptr::addr_of_mut!(SIG0).cast::<u8>().write_volatile(0);
        core::ptr::addr_of_mut!(SIG1).cast::<u8>().write_volatile(0);
        pqsigner_hw::hash::init_clock();
    }
    let s = [0x5Au8; 16];
    let sk = [0xA5u8; 32];
    let mut v = [0x11u8; 16];
    let mut o = [0u8; 688];
    let mut k = 2usize;
    let mut rec = |c: u32, d: u32| {
        out(k, c);
        out(k + 1, d);
        k += 2;
    };
    // SAFETY (all calls): the buffers above are large enough; arguments in range.
    unsafe {
        // 1. chain16, 15 steps per call (amortizes the entry), 2,000 calls.
        let t = cyc();
        for _ in 0..2000 {
            pqsigner_v2_chain16(s.as_ptr(), v.as_mut_ptr(), 0x0102_0304, 0x0000_0500, 0, 15);
        }
        rec(cyc().wrapping_sub(t), 30_000);
        // 2. chain16, 1 step per call (entry + one digest), 5,000 calls.
        let t = cyc();
        for _ in 0..5000 {
            pqsigner_v2_chain16(s.as_ptr(), v.as_mut_ptr(), 0x0102_0304, 0x0000_0500, 3, 1);
        }
        rec(cyc().wrapping_sub(t), 5_000);
        // 3. node16 (55 bytes), 5,000 calls.
        let t = cyc();
        for _ in 0..5000 {
            pqsigner_v2_node16(s.as_ptr(), v.as_ptr(), s.as_ptr(), 0x0102_0304, 0x0000_2500, o.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 5_000);
        // 4. wots_chains16, steps 7 (keygen shape): 43 x 8 digests per call, 200 calls.
        let t = cyc();
        for _ in 0..200 {
            pqsigner_v2_wots_chains16(sk.as_ptr(), 0x0102_0304, 0, s.as_ptr(), 0x0102_0305, 0, 7, o.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 200 * 344);
        // 5. wots_pk16 (chains + T_43), 200 calls.
        let t = cyc();
        for _ in 0..200 {
            pqsigner_v2_wots_pk16(sk.as_ptr(), 0x0102_0304, 0, s.as_ptr(), 0x0102_0305, 0, 0x0102_0306, 0, 7, o.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 200 * 345);
        // 6. fors_subtree16, h = 11 (6,143 digests), 4 calls.
        let t = cyc();
        for _ in 0..4 {
            pqsigner_v2_fors_subtree16(sk.as_ptr(), s.as_ptr(), 0x0102_0304, 0, 0x0102_0305, 0, 0, 11, o.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 4 * 6143);
        // 7. search43_target, impossible target: 20,000 tries.
        let mut d = [0u8; 32];
        let mut sm = [0x33u8; 32];
        sm[0] = 1;
        let t = cyc();
        let _ = pqsigner_v2_search43_target(sm.as_ptr(), 0x0102_0307, 0, 0, 20_000, 400, d.as_mut_ptr());
        rec(cyc().wrapping_sub(t), 20_000);
    }
    out(1, 100);
}
