/* Minimal SRAM-only startup for the STM32U585 (Cortex-M33, TrustZone on, core in Secure state).
 * Loaded by run_on_board.sh with OpenOCD load_image into the SECURE SRAM alias; never touches flash.
 * Entry: _start (the ELF entry). The debugger sets PC/MSP/xPSR/PRIMASK too; we repeat it here.
 * Does: cpsid i; SP = __stack_top; MSPLIM_S = __stack_limit; VTOR_S = our own table (so any fault
 * lands here, never in the board firmware's handlers); zero .bss; enable DWT CYCCNT; run bench_run();
 * record status + cycles in the results block; bkpt #0 (the debugger's wait_halt returns).
 * Only volatile core/debug registers are written (VTOR, MSPLIM, DEMCR, DWT_CTRL, DWT_CYCCNT). */
#include "bench.h"
extern uint32_t __bss_start__[], __bss_end__[], __stack_top[], __stack_limit[];
void _cstart(void);

__attribute__((naked, noreturn, section(".entry"))) void _start(void) {
  __asm volatile(
#ifdef NOWRITE_CONTROL
    "nop\n bkpt #3\n"   /* negative control: halt before writing anything (the nop is needed: OpenOCD resume
                            skips a BKPT that sits exactly at the resume PC, armv7m_maybe_skip_bkpt_inst) */
#endif
    "cpsid i\n"
    "movs r0, #0\n"
    "msr msplim, r0\n"
    "ldr r0, =__stack_top\n"
    "msr msp, r0\n"
    "mov sp, r0\n"
    "ldr r0, =__stack_limit\n"
    "msr msplim, r0\n"
    "b _cstart\n"
    ".ltorg\n");
}

__attribute__((naked, noreturn)) static void fault_entry(void) {
  __asm volatile("tst lr, #4\n ite eq\n mrseq r0, msp\n mrsne r0, psp\n mov r1, lr\n b fault_c\n");
}
__attribute__((used, noreturn)) void fault_c(uint32_t *frame, uint32_t exc_return) {
  uint32_t ipsr; __asm volatile("mrs %0, ipsr" : "=r"(ipsr));
  (void)exc_return;
  BENCH.fault[0] = *(volatile uint32_t *)0xE000ED28u;  /* CFSR */
  BENCH.fault[1] = *(volatile uint32_t *)0xE000ED2Cu;  /* HFSR */
  BENCH.fault[2] = *(volatile uint32_t *)0xE000ED38u;  /* BFAR */
  BENCH.fault[3] = *(volatile uint32_t *)0xE000ED34u;  /* MMFAR */
  BENCH.fault[4] = *(volatile uint32_t *)0xE000EDE4u;  /* SFSR */
  BENCH.fault[5] = *(volatile uint32_t *)0xE000EDE8u;  /* SFAR */
  BENCH.status = ST_FAULT | (ipsr & 0x1FFu);
  BENCH.fault[6] = frame[6];                           /* stacked PC (may itself fault on a bad SP) */
  BENCH.fault[7] = frame[5];                           /* stacked LR */
  for (;;) __asm volatile("bkpt #1");
}
/* 16 system + 128 external entries; VTOR needs alignment to the table size rounded up (<= 1 KiB here). */
__attribute__((section(".vtable"), used, aligned(1024)))
void (*const bench_vectors[16 + 128])(void) = {
  [0] = (void (*)(void))__stack_top, [1] = _start,
  [2 ... 16 + 127] = fault_entry,
};

#ifdef QEMU
volatile uint32_t bench_fake_cyc;
#endif
void bench_putc(char c) { uint32_t n = BENCH.text_len; if (n < sizeof BENCH.text) { BENCH.text[n] = c; BENCH.text_len = n + 1; } }
void bench_halt(uint32_t code) { BENCH.status = ST_HALT | (code & 0xFFFFu); for (;;) __asm volatile("bkpt #2"); }

__attribute__((noreturn, used)) void _cstart(void) {
  *(volatile uint32_t *)0xE000ED08u = (uint32_t)bench_vectors;          /* VTOR_S */
  __asm volatile("dsb\n isb" ::: "memory");
  for (uint32_t *p = __bss_start__; p < __bss_end__; ) *p++ = 0;
  for (uint32_t i = 0; i < BENCH_RESULTS_WORDS; i++) ((volatile uint32_t *)BENCH_RESULTS_ADDR)[i] = 0;
  BENCH.status = ST_STARTED;
#ifndef QEMU
  *(volatile uint32_t *)0xE000EDFCu |= 1u << 24;                       /* DEMCR.TRCENA */
  *(volatile uint32_t *)0xE0001004u = 0;                               /* DWT_CYCCNT */
  *(volatile uint32_t *)0xE0001000u |= 1u;                             /* DWT_CTRL.CYCCNTENA */
  BENCH.dwt_ctrl = *(volatile uint32_t *)0xE0001000u;
#endif
  uint32_t a = bench_cyc(), b = bench_cyc();
  BENCH.cyc_overhead = b - a;
  uint32_t t0 = bench_cyc();
  bench_run();
  uint32_t t1 = bench_cyc();
  BENCH.cyc_run = t1 - t0;
  BENCH.status = ST_DONE;
#ifdef QEMU   /* semihosting SYS_EXIT (QEMU only; the board build never uses semihosting) */
  { static uint32_t a[2] = {0x20026, 0}; register uint32_t r0 __asm__("r0") = 0x18; register void *r1 __asm__("r1") = a;
    __asm volatile("bkpt 0xab" : "+r"(r0) : "r"(r1) : "memory"); }
#endif
  for (;;) __asm volatile("bkpt #0");
}
