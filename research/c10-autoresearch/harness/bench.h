/* Results block shared by every SRAM-only board benchmark. Lives at a FIXED address
 * (0x30000000, secure SRAM1 alias, 256 bytes = 64 words); run_on_board.sh poisons it with
 * 0xDEADBEEF before each load, so any word still reading 0xDEADBEEF was never written. */
#ifndef BENCH_H
#define BENCH_H
#include <stdint.h>
#ifndef BENCH_RESULTS_ADDR
#define BENCH_RESULTS_ADDR 0x30000000u
#endif
#define BENCH_RESULTS_WORDS 64u
#define ST_STARTED 0x53545254u   /* 'STRT': entry reached, bench_run() running */
#define ST_DONE    0x444F4E45u   /* 'DONE': bench_run() returned */
#define ST_FAULT   0xFA170000u   /* | exception number (low 9 bits of IPSR) */
#define ST_HALT    0x48410000u   /* | code: program called bench_halt(code) */
typedef struct {
  volatile uint32_t status;      /* w0 */
  volatile uint32_t cyc_run;     /* w1: DWT cycles spent in bench_run() (startup -> return) */
  volatile uint32_t dwt_ctrl;    /* w2: DWT_CTRL readback after enable (bit0 must be 1) */
  volatile uint32_t cyc_overhead;/* w3: cycles for two back-to-back CYCCNT reads (subtract from short spans) */
  volatile uint32_t user[12];    /* w4..w15: program-defined values */
  volatile uint32_t fault[8];    /* w16..w23: CFSR HFSR BFAR MMFAR SFSR SFAR stacked_PC stacked_LR */
  volatile uint32_t text_len;    /* w24 */
  volatile char text[156];       /* w25..w63: bytes written with bench_putc() */
} bench_results_t;
#define BENCH (*(bench_results_t *)BENCH_RESULTS_ADDR)
#ifdef QEMU   /* QEMU instruction-count twin (qemu/link_qemu.ld): QEMU models no DWT; same code paths, no cycles */
static inline uint32_t bench_cyc(void) { extern volatile uint32_t bench_fake_cyc; return bench_fake_cyc; }
#else
static inline uint32_t bench_cyc(void) { return *(volatile uint32_t *)0xE0001004u; }  /* DWT_CYCCNT */
#endif
void bench_run(void);                    /* provided by each program */
void bench_putc(char c);                 /* appends to BENCH.text (truncates silently) */
__attribute__((noreturn)) void bench_halt(uint32_t code);  /* status = ST_HALT|code; bkpt */
#endif
