// Round 9 standing gate: dead-stack residue scan (shared by bench_v1micro and bench_v2drv
// via `include!`). Around a driver call: build the patterns of every secret the call touches
// (computed in software BEFORE the call), zero the dead stack below sp, call, then look for
// any pattern in the dead stack. A pattern is every 4-byte window of the secret in memory
// order (any byte offset) and every aligned word byte-reversed (a raw HR value spilled before
// its `rev`). Zero windows are skipped (cleared memory). The scan and clear are inlined into
// the caller, whose frame is above sp, so the scanner never scans its own locals; the
// patterns live in a static, not on the stack.

const RES_DEPTH: usize = 4096;
const RES_MAX: usize = 4096;
static mut RES_PATS: [u32; RES_MAX] = [0; RES_MAX];
static mut RES_N: usize = 0;

#[inline(always)]
fn res_sp() -> usize {
    let sp: usize;
    // SAFETY: reads sp only.
    unsafe { core::arch::asm!("mov {0}, sp", out(reg) sp, options(nomem, nostack, preserves_flags)) };
    sp
}

/// Start a new pattern set.
fn res_reset() {
    // SAFETY: single-threaded bench.
    unsafe { core::ptr::addr_of_mut!(RES_N).write_volatile(0) };
}

fn res_push(w: u32) {
    if w == 0 {
        return;
    }
    // SAFETY: single-threaded bench; bounds checked.
    unsafe {
        let n = core::ptr::addr_of!(RES_N).read_volatile();
        if n < RES_MAX {
            core::ptr::addr_of_mut!(RES_PATS).cast::<u32>().add(n).write_volatile(w);
            core::ptr::addr_of_mut!(RES_N).write_volatile(n + 1);
        }
    }
}

/// Add one secret's patterns.
fn res_add(s: &[u8]) {
    for k in 0..=s.len() - 4 {
        res_push(u32::from_le_bytes([s[k], s[k + 1], s[k + 2], s[k + 3]]));
    }
    for k in 0..s.len() / 4 {
        res_push(u32::from_be_bytes([s[4 * k], s[4 * k + 1], s[4 * k + 2], s[4 * k + 3]]));
    }
}

/// Zero the dead stack below sp, up to sp itself. (Round 13: this used to stop 64 bytes short of
/// sp while `res_found` scanned that band, so the bench's own `res_add` frame could read as a
/// residue there; interrupts are masked and nothing below sp is live, so the band is cleared too.)
#[inline(always)]
fn res_clear() {
    let sp = res_sp();
    let mut a = (sp - RES_DEPTH) & !3;
    while a < sp {
        // SAFETY: secure SRAM below the live stack (bench: 128 KiB stack, interrupts masked).
        unsafe { core::ptr::write_volatile(a as *mut u32, 0) };
        a += 4;
    }
}

/// One word at `a` (any alignment) by a single `ldr`. Round 13: at opt-level "z" a
/// `read_volatile` of `[u8; 4]` is an out-of-line call, whose push lands in the band being
/// scanned and erases the words just below sp before they are read; inline asm cannot be a call.
#[inline(always)]
fn res_ld(a: usize) -> u32 {
    let w: u32;
    // SAFETY: secure SRAM below the live stack; unaligned `ldr` is legal on ARMv8-M Mainline
    // (nothing sets CCR.UNALIGN_TRP); reads only.
    unsafe { core::arch::asm!("ldr {0}, [{1}]", out(reg) w, in(reg) a, options(nostack, readonly, preserves_flags)) };
    w
}

/// Whether any pattern appears in the dead stack below sp.
#[inline(always)]
fn res_found() -> bool {
    let sp = res_sp();
    // SAFETY: single-threaded bench.
    let n = unsafe { core::ptr::addr_of!(RES_N).read_volatile() };
    // SAFETY: RES_PATS[..n] was written by `res_push`; nothing writes it during the scan.
    let pats = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(RES_PATS).cast::<u32>(), n) };
    // Round 13: through the word at sp - 4 (it was `a < sp - 4`, which skipped the word just below
    // sp, where a callee's first push lands).
    let mut a = sp - RES_DEPTH;
    while a <= sp - 4 {
        let w = res_ld(a);
        // A call-free test: a call here (`<[u32]>::contains`) would push into the band it scans and
        // erase the word at sp - 4 before reading it (round 13; the endpoint control fires now).
        if w != 0 {
            let mut k = 0;
            while k < pats.len() {
                if pats[k] == w {
                    return true;
                }
                k += 1;
            }
        }
        a += 1;
    }
    false
}

/// Diagnostic (round 13): the hit nearest sp, as (sp - address, word); (0, 0) when none.
#[inline(always)]
#[allow(dead_code)]
fn res_first_hit() -> (usize, u32) {
    let sp = res_sp();
    // SAFETY: as `res_found`.
    let n = unsafe { core::ptr::addr_of!(RES_N).read_volatile() };
    // SAFETY: as `res_found`.
    let pats = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(RES_PATS).cast::<u32>(), n) };
    let mut a = sp - 4;
    while a >= sp - RES_DEPTH {
        let w = res_ld(a);
        if w != 0 {
            let mut k = 0;
            while k < pats.len() {
                if pats[k] == w {
                    return (sp - a, w);
                }
                k += 1;
            }
        }
        a -= 1;
    }
    (0, 0)
}
