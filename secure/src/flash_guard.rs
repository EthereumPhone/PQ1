//! Flash-timing guard: every entry into flash-resident secure code starts
//! in RAM (#1132).
//!
//! # Why
//!
//! `FLASH_ACR` cannot be made secure-only on STM32U585 (RM0456 §7.5.7: it is
//! gated by privilege, not by security state). Non-secure privileged code
//! writes `LATENCY`, and on EVT-3D21 (2026-11-10) at 160 MHz:
//!
//! * `LATENCY` = 1: flash reads return bit errors, some of them silently;
//! * `LATENCY` = 0: every 16-byte flash line read returns the PREVIOUS line
//!   read in the same bank, with no ECC flag, and ICACHE keeps the wrong line
//!   after the latency is put back.
//!
//! With the bank-1 output holding one gateway veneer line, a non-secure call
//! to another veneer executed the first one's `SG; b.w` and landed in the
//! middle of a secure function with the caller's registers. No register bit
//! closes that. What closes it is that no flash-resident secure instruction
//! is ever fetched while the latency may be wrong:
//!
//! 1. **Gateway veneers live in secure RAM.** Each `nscram_*` entry below is
//!    `SG` plus a few RAM instructions; the SAU marks exactly that range
//!    non-secure-callable (`sau.rs`, region 1). The linker's flash veneers
//!    for the Rust `nsc_*` functions still exist but are no longer in an NSC
//!    region, so the non-secure world cannot enter through them.
//! 2. **Secure exception vectors live in secure RAM.** `install` points
//!    `VTOR_S` at a RAM table whose every entry is one RAM trampoline; it
//!    looks the real handler up in a RAM copy of the flash table.
//! 3. **Both run the guard first.** It always writes the boot value of
//!    `FLASH_ACR` back and reads it back until it matches (the write applies
//!    only after one more access; seen on silicon), so no flash-resident
//!    secure instruction runs on any other value, whatever the register read
//!    before.
//! 4. **ICACHE is emptied whenever the non-secure world may have run since
//!    it was last emptied**: on every gateway entry, and on every secure
//!    exception taken outside a gateway call (`__pq_in_call` = 0). ICACHE
//!    also serves data reads of flash, and the non-secure world can leave
//!    lines for its own addresses that differ from the flash (a wrong
//!    latency, or reprogramming a page). After the guard, a secure read of
//!    non-secure flash returns the flash. Inside a gateway call the cache
//!    is left alone, so a sign is not slowed by its own SysTick.
//! 5. **Non-secure interrupts are masked for the whole gateway call**
//!    (`BASEPRI_S` = 0x80; with `AIRCR.PRIS` every non-secure exception has
//!    priority >= 0x80), so the non-secure world cannot change the latency
//!    or its flash while flash-resident secure code runs. Secure exceptions
//!    must therefore all sit below 0x80; `main::setup_systick` keeps PendSV
//!    there.
//!
//! # What it does not cover
//!
//! * The CONTENT of non-secure flash. It is the non-secure world's to
//!   write; the guard only makes a secure read return what the flash holds
//!   and keeps it stable for the length of one gateway call. Anything the
//!   secure world decides from it is still checked by content: the atlas
//!   by its hash, on a secure-RAM copy (`ui::px::assets`); a staged image
//!   by the FSBL at the next boot.
//! * A bank the non-secure world put in power-down (`PDREQ1`/`PDREQ2`) is
//!   woken by the flash interface on the next access (RM0456 §7.3.4); the
//!   guard does not wait for it. Exercised at speed on EVT-3D21, see below.
//! * The stock non-secure image has no exception handlers. A non-secure image
//!   that relied on its own interrupts during a gateway call no longer gets
//!   them (the `toctou`, `nested-gate` and `idle-hold` probe images do).
//!
//! # Evidence
//!
//! `tools/dvt/flash_acr_stress.sh` (RAM-only stub in the non-secure state,
//! at full speed, the 1 ms secure SysTick preempting it at arbitrary
//! points): for each of LATENCY 0 and 1, LPM, PRFTEN, SLEEP_PD, every
//! writable bit at once, PDREQ1, PDREQ2, both, and "LATENCY 0, then the boot
//! value written back with no readback", the stub writes `FLASH_ACR` and
//! calls a gateway entry; two more modes leave the bad value (or a
//! powered-down bank 1) for 7.5 ms per iteration and let the secure SysTick
//! run. EVT-3D21, 2026-11-10: every mode 2,000/2,000 with no wrong return
//! value and no reset, on `make build-hw-usb-test BOARD=pq1` and on a
//! `ui-px` `devunit-ab` image running from slot A and from slot B (secure
//! code in bank 2, the bank the non-secure slots share). Receipt:
//! `docs/hardware/dvt-silicon-test-checklist.md` row 3.15.

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

/// Core vectors (16) + the STM32U585's 126 interrupt lines (IRQ 0..=125).
const N_VECTORS: usize = 16 + 126;

/// `VTOR` keeps bits [31:7]; 1 KiB covers the table's own size rounding.
#[repr(C, align(1024))]
pub struct VectorTable([u32; N_VECTORS]);

/// The table `VTOR_S` points at after [`install`]: every entry is
/// `__pq_exc_tramp`.
#[no_mangle]
static mut __pq_ram_vectors: VectorTable = VectorTable([0; N_VECTORS]);
/// The flash table's contents, read once at [`install`] with the latency the
/// secure boot set and before the non-secure world exists.
#[no_mangle]
static mut __pq_orig_vectors: [u32; N_VECTORS] = [0; N_VECTORS];
/// `FLASH_ACR` as the secure boot left it.
#[no_mangle]
static mut __pq_flash_acr_expect: u32 = 0;
/// How many times the guard found `FLASH_ACR` changed (diagnostic).
#[no_mangle]
static mut __pq_flash_guard_hits: u32 = 0;
/// How many times the guard emptied ICACHE (diagnostic).
#[no_mangle]
static mut __pq_icache_flushes: u32 = 0;
/// 1 while a gateway call runs its flash-resident body: ICACHE was emptied
/// on the way in and non-secure interrupts are masked, so the non-secure
/// world has not run since. 0 at every other time. A secure exception taken
/// while it is 0 empties ICACHE before its handler runs.
#[no_mangle]
static mut __pq_in_call: u32 = 0;
/// The flash vector base the image booted from (what `VTOR_S` held).
static mut BOOT_VTOR: u32 = 0;

const SCB_VTOR: *mut u32 = 0xE000_ED08 as *mut u32;
const FLASH_ACR: *const u32 = 0x5002_2000 as *const u32;

extern "C" {
    fn __pq_exc_tramp();
    static __pq_nsc_base: u32;
    static __pq_nsc_limit: u32;
}

/// `[base, limit)` of the RAM gateway veneers, both 32-byte aligned (the SAU
/// granule), for SAU region 1.
pub fn nsc_region() -> (u32, u32) {
    // SAFETY: only the addresses of the two assembler labels are taken.
    unsafe { (addr_of!(__pq_nsc_base) as u32, addr_of!(__pq_nsc_limit) as u32) }
}

/// The flash address the secure vector table was booted from. `VTOR_S` no
/// longer holds it after [`install`]; `fw_update::running_slot` asks here.
pub fn boot_vector_base(vtor_now: u32) -> u32 {
    // SAFETY: written once in `install`, single-threaded boot; plain read.
    let b = unsafe { read_volatile(addr_of!(BOOT_VTOR)) };
    if b != 0 { b } else { vtor_now }
}

/// Times the guard found `FLASH_ACR` changed since boot.
pub fn hits() -> u32 {
    // SAFETY: a word the RAM guard increments; a torn read is impossible.
    unsafe { read_volatile(addr_of!(__pq_flash_guard_hits)) }
}

/// Times the guard emptied ICACHE since boot.
pub fn icache_flushes() -> u32 {
    // SAFETY: a word the RAM guard increments; a torn read is impossible.
    unsafe { read_volatile(addr_of!(__pq_icache_flushes)) }
}

/// Move the secure vector table to RAM and record the good `FLASH_ACR`.
///
/// Call once, after `rcc::init` (final latency) and before `VTOR_S` is locked
/// and the non-secure world boots. Halts if the result does not read back.
pub fn install() {
    cortex_m::interrupt::free(|_| {
        // SAFETY: single-threaded boot with interrupts masked; the statics
        // are written here only and read afterwards by the RAM stubs.
        // `VTOR_S` and `FLASH_ACR` are always-present registers. The flash
        // table has at least N_VECTORS entries (cortex-m-rt emits 16 + 240+).
        unsafe {
            let flash_vt = read_volatile(SCB_VTOR);
            write_volatile(addr_of_mut!(BOOT_VTOR), flash_vt);
            write_volatile(addr_of_mut!(__pq_flash_acr_expect), read_volatile(FLASH_ACR));
            let tramp = __pq_exc_tramp as *const () as usize as u32 | 1;
            let orig = addr_of_mut!(__pq_orig_vectors) as *mut u32;
            let ram = addr_of_mut!(__pq_ram_vectors) as *mut u32;
            for i in 0..N_VECTORS {
                let v = read_volatile((flash_vt as *const u32).add(i));
                write_volatile(orig.add(i), v);
                write_volatile(ram.add(i), if i == 0 { v } else { tramp });
            }
            write_volatile(SCB_VTOR, ram as u32);
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
            let (base, limit) = nsc_region();
            if read_volatile(SCB_VTOR) != ram as u32 || base >= limit || (base | limit) & 0x1F != 0 {
                loop {
                    cortex_m::asm::wfe();
                }
            }
        }
    });
}

// The guard, the exception trampoline and the common gateway tail. RAM
// (`.data.*` is copied by cortex-m-rt before `main`), outside the NSC range.
// `SG` and `BXNS` are emitted as opcodes: the assembler accepts the mnemonics
// only with the security extension enabled.
//
// `__pq_flash_guard` / `__pq_flash_guard_inv` preserve every register (the
// gateway path holds the caller's arguments in r0-r3). The first empties
// ICACHE only if `FLASH_ACR` had changed, the second always.
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .data.pqram.guard,"awx",%progbits
    .balign 4
    .thumb_func
    .global __pq_flash_guard_inv
    .type __pq_flash_guard_inv,%function
__pq_flash_guard_inv:
    push {{r0, r1, r2, r3}}
    movs r2, #1
    b 3f

    .balign 4
    .thumb_func
    .global __pq_flash_guard
    .type __pq_flash_guard,%function
__pq_flash_guard:
    push {{r0, r1, r2, r3}}
    movs r2, #0
3:
    ldr r1, =0x50022000
    ldr r0, =__pq_flash_acr_expect
    ldr r0, [r0]
    ldr r3, [r1]
    cmp r3, r0
    beq 4f
    movs r2, #1
    ldr r1, =__pq_flash_guard_hits
    ldr r3, [r1]
    adds r3, #1
    str r3, [r1]
    ldr r1, =0x50022000
4:
    str r0, [r1]
    ldr r3, [r1]
    cmp r3, r0
    bne 4b
    cbz r2, 5f
    ldr r1, =0x50030400
    ldr r0, [r1]
    orr r0, r0, #2
    str r0, [r1]
6:
    ldr r0, [r1, #4]
    tst r0, #1
    bne 6b
    dsb
    isb
    ldr r1, =__pq_icache_flushes
    ldr r0, [r1]
    adds r0, #1
    str r0, [r1]
5:
    pop {{r0, r1, r2, r3}}
    bx lr

    .balign 4
    .thumb_func
    .global __pq_exc_tramp
    .type __pq_exc_tramp,%function
__pq_exc_tramp:
    push {{r4, lr}}
    ldr r0, =__pq_in_call
    ldr r0, [r0]
    cbnz r0, 1f
    bl __pq_flash_guard_inv
    b 2f
1:
    bl __pq_flash_guard
2:
    pop {{r4, lr}}
    mrs r0, ipsr
    ldr r1, =__pq_orig_vectors
    ldr r1, [r1, r0, lsl #2]
    bx r1

    .balign 4
    .thumb_func
    .global __pq_nsc_common
    .type __pq_nsc_common,%function
__pq_nsc_common:
    mrs r4, basepri
    mov lr, #0x80
    msr basepri, lr
    bl __pq_flash_guard_inv
    push {{r0, r1}}
    ldr r0, =__pq_in_call
    movs r1, #1
    str r1, [r0]
    pop {{r0, r1}}
    blx r12
    ldr r1, =__pq_in_call
    movs r2, #0
    str r2, [r1]
    msr basepri, r4
    pop {{r4, lr}}
    mov r1, lr
    mov r2, lr
    mov r3, lr
    mov r12, lr
    msr apsr_nzcvq, lr
    .inst.n 0x4774
    .ltorg

    .section .data.pqram.nsc,"awx",%progbits
    .balign 32
    .global __pq_nsc_base
__pq_nsc_base:
"#
);

/// One RAM gateway entry: `SG`, save `r4`/`lr`, load the flash function's
/// address from the adjacent literal, continue in `__pq_nsc_common`. The
/// padding between entries is `nop`, so the only `SG` opcodes in the NSC
/// range are the entries.
macro_rules! ram_veneer {
    ($name:literal) => {
        core::arch::global_asm!(concat!(
            "    .syntax unified\n",
            "    .section .data.pqram.nsc,\"awx\",%progbits\n",
            "    .balign 16\n",
            "    .thumb_func\n",
            "    .global nscram_", $name, "\n",
            "    .type nscram_", $name, ",%function\n",
            "nscram_", $name, ":\n",
            "    .inst.w 0xe97fe97f\n",
            "    .thumb_func\n",
            "    .global __acle_se_nscram_", $name, "\n",
            "    .type __acle_se_nscram_", $name, ",%function\n",
            "__acle_se_nscram_", $name, ":\n",
            "    push {{r4, lr}}\n",
            "    nop\n",
            "    ldr.w r12, 9f\n",
            "    b.w __pq_nsc_common\n",
            "9:  .word __acle_se_nsc_", $name, "\n",
        ));
    };
}

// One entry per `extern "cmse-nonsecure-entry" fn nsc_*` in `nsc/mod.rs`,
// under the same cfg. A missing line is a non-secure link error (the
// non-secure image imports `nscram_*`), never a silent flash entry.
#[cfg(feature = "stm32u585")]
ram_veneer!("get_remaining_attempts");
#[cfg(feature = "stm32u585")]
ram_veneer!("request_unlock");
#[cfg(feature = "stm32u585")]
ram_veneer!("sign_userop");
#[cfg(feature = "stm32u585")]
ram_veneer!("sign_userop_batch");
#[cfg(feature = "stm32u585")]
ram_veneer!("is_unlocked");
#[cfg(feature = "stm32u585")]
ram_veneer!("lock");
#[cfg(all(feature = "stm32u585", feature = "iwdg"))]
ram_veneer!("register_heartbeat");
#[cfg(all(feature = "stm32u585", feature = "e2e-test"))]
ram_veneer!("test_pin_lockout");
#[cfg(all(feature = "stm32u585", feature = "e2e-test"))]
ram_veneer!("tzic_status");
#[cfg(feature = "stm32u585")]
ram_veneer!("get_pin_attempt_log");
#[cfg(all(feature = "stm32u585", feature = "prodtest"))]
ram_veneer!("prodtest_get_id");
#[cfg(all(feature = "stm32u585", feature = "prodtest"))]
ram_veneer!("prodtest_display_pattern");
#[cfg(all(feature = "stm32u585", feature = "prodtest"))]
ram_veneer!("prodtest_saes_selftest");
#[cfg(all(feature = "stm32u585", feature = "prodtest"))]
ram_veneer!("prodtest_bhk_selftest");
#[cfg(all(feature = "stm32u585", feature = "prodtest"))]
ram_veneer!("prodtest_flash_rw");
#[cfg(all(feature = "stm32u585", feature = "prodtest"))]
ram_veneer!("prodtest_trng_sample");
#[cfg(all(feature = "stm32u585", feature = "prodtest"))]
ram_veneer!("prodtest_optiga_handshake");
#[cfg(all(feature = "stm32u585", feature = "prodtest"))]
ram_veneer!("prodtest_se050_handshake");
#[cfg(all(feature = "stm32u585", feature = "prodtest"))]
ram_veneer!("prodtest_usb_loopback");
#[cfg(all(feature = "stm32u585", feature = "prodtest"))]
ram_veneer!("prodtest_button_test");
#[cfg(all(feature = "stm32u585", feature = "prodtest"))]
ram_veneer!("prodtest_rgb_test");
#[cfg(all(feature = "stm32u585", feature = "prodtest"))]
ram_veneer!("prodtest_rng_config");
#[cfg(all(feature = "stm32u585", feature = "prodtest"))]
ram_veneer!("prodtest_rgb_osd");
#[cfg(feature = "stm32u585")]
ram_veneer!("fw_begin");
#[cfg(feature = "stm32u585")]
ram_veneer!("fw_chunk");
#[cfg(feature = "stm32u585")]
ram_veneer!("fw_commit");
#[cfg(feature = "stm32u585")]
ram_veneer!("fw_status");
#[cfg(feature = "stm32u585")]
ram_veneer!("fw_abort");
#[cfg(feature = "stm32u585")]
ram_veneer!("get_wallet_address");
#[cfg(feature = "stm32u585")]
ram_veneer!("get_init_code");
#[cfg(feature = "stm32u585")]
ram_veneer!("sign_offchain");
#[cfg(feature = "stm32u585")]
ram_veneer!("offchain_status");
#[cfg(feature = "stm32u585")]
ram_veneer!("offchain_sync");

core::arch::global_asm!(
    r#"
    .section .data.pqram.nsc,"awx",%progbits
    .balign 32
    .global __pq_nsc_limit
__pq_nsc_limit:
"#
);
