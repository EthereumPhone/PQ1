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

/// Zero the dead stack below sp (64-byte margin).
#[inline(always)]
fn res_clear() {
    let sp = res_sp();
    let mut a = (sp - RES_DEPTH) & !3;
    while a < sp - 64 {
        // SAFETY: secure SRAM below the live stack (bench: 128 KiB stack, interrupts masked).
        unsafe { core::ptr::write_volatile(a as *mut u32, 0) };
        a += 4;
    }
}

/// Whether any pattern appears in the dead stack below sp.
#[inline(always)]
fn res_found() -> bool {
    let sp = res_sp();
    // SAFETY: single-threaded bench.
    let n = unsafe { core::ptr::addr_of!(RES_N).read_volatile() };
    // SAFETY: RES_PATS[..n] was written by `res_push`; nothing writes it during the scan.
    let pats = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(RES_PATS).cast::<u32>(), n) };
    let mut a = sp - RES_DEPTH;
    while a < sp - 4 {
        // SAFETY: secure SRAM below the live stack; unaligned word reads are legal.
        let w = u32::from_le_bytes(unsafe { core::ptr::read_volatile(a as *const [u8; 4]) });
        if w != 0 && pats.contains(&w) {
            return true;
        }
        a += 1;
    }
    false
}
