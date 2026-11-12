/* C10 autoresearch: clock raise to 160 MHz around the Rust bench (copied from the leanSPHINCS harness).
 * Clock-independence control: the SAME clock_up/clock_down code as ../rt_silicon.c (copied verbatim by script),
 * wrapped around the harness agent's unmodified rt_board.c bench_run (renamed bench_run_inner at compile time).
 * user[11] = RCC_CFGR1 after clock_up (0xF = PLL1; 0 = MSIS when CLK_ENABLE=0). */
#include <stdint.h>
#include "bench.h"
static void pq_halt(uint32_t c) { bench_halt(c); }
#define REG(a) (*(volatile uint32_t *)(a))
#define RCC_S 0x56020C00u
#define PWR_S 0x56020800u
#if defined(CLK160) && !defined(QEMU)
static uint32_t sv_ahb3, sv_pllcfgr, sv_plldivr, sv_vosr, sv_cr, sv_cfgr1;
#ifdef FLASHRUN
static uint32_t sv_acr;
#define FLASH_S 0x50022000u
#define ICACHE_S 0x50030400u
#endif
static void spin_until(uint32_t addr, uint32_t mask, uint32_t want, uint32_t code) {
  for (uint32_t i = 0; i < 20000000u; i++) if ((REG(addr) & mask) == want) return;
  pq_halt(code);
}
#ifndef CLK_ENABLE
#define CLK_ENABLE 1
#endif
static volatile uint32_t pq_clk_enable = CLK_ENABLE;   /* runtime switch: same code layout at 4 MHz and 160 MHz */
static uint32_t clk_on;
static void clock_up(void) {
  if (!pq_clk_enable) return;
  clk_on = 1;
  sv_ahb3 = REG(RCC_S + 0x94); sv_pllcfgr = REG(RCC_S + 0x28); sv_plldivr = REG(RCC_S + 0x34);
  sv_vosr = REG(PWR_S + 0x0C); sv_cr = REG(RCC_S + 0x00); sv_cfgr1 = REG(RCC_S + 0x1C);
  
  if ((sv_cfgr1 & 0xFu) != 0 || (sv_cr & 0x01000000u)) pq_halt(0xE0);   /* not MSIS / PLL1 already on: do nothing */
#ifdef FLASHRUN
  /* harness v3: flash latency 4 wait states (VOS1, 160 MHz) BEFORE the clock goes up, as rcc.rs does
   * (ICACHE off while the wait states change). FLASH_ACR and ICACHE_CR are volatile registers. */
  sv_acr = REG(FLASH_S + 0x00);
  REG(ICACHE_S) = 0u; __asm volatile("dsb\n isb");
  REG(FLASH_S + 0x00) = (sv_acr & ~0xFu) | 4u; while ((REG(FLASH_S + 0x00) & 0xFu) != 4u) {}
#endif
  REG(RCC_S + 0x94) = sv_ahb3 | 0x4u; (void)REG(RCC_S + 0x94);          /* AHB3ENR.PWREN */
  REG(PWR_S + 0x0C) |= 0x00030000u; spin_until(PWR_S + 0x0C, 0x8000u, 0x8000u, 0xE1);   /* VOS range 1, VOSRDY */
  REG(RCC_S + 0x28) = 0x00040009u;                                       /* PLL1: src MSIS, M=/1, REN, MBOOST=/1 */
  REG(PWR_S + 0x0C) |= 0x00040000u; spin_until(PWR_S + 0x0C, 0x4000u, 0x4000u, 0xE2);   /* BOOSTEN, BOOSTRDY */
  REG(RCC_S + 0x34) = 0x0101024Fu;                                       /* N=80, P=Q=R=/2 -> 160 MHz */
  REG(RCC_S + 0x00) |= 0x01000000u; spin_until(RCC_S + 0x00, 0x02000000u, 0x02000000u, 0xE3);   /* PLL1ON, PLL1RDY */
  REG(RCC_S + 0x1C) = (REG(RCC_S + 0x1C) & ~3u) | 3u; spin_until(RCC_S + 0x1C, 0xCu, 0xCu, 0xE4);  /* SW = PLL1 */
#ifdef FLASHRUN
  REG(ICACHE_S) = 1u;                                                    /* rcc.rs: ICACHE_CR = 1 (EN, 1-way) */
  BENCH.user[8] = REG(ICACHE_S) | (REG(FLASH_S + 0x00) << 8);
#endif
  BENCH.user[9] = REG(RCC_S + 0x1C); BENCH.user[10] = REG(PWR_S + 0x0C);
}
static void clock_down(void) {
  if (!clk_on) return;
  REG(RCC_S + 0x1C) &= ~3u; spin_until(RCC_S + 0x1C, 0xCu, 0x0u, 0xE5);          /* SW = MSIS */
  REG(RCC_S + 0x00) &= ~0x01000000u; spin_until(RCC_S + 0x00, 0x02000000u, 0, 0xE6);  /* PLL1 off */
  REG(RCC_S + 0x34) = sv_plldivr; REG(RCC_S + 0x28) = sv_pllcfgr;
  REG(PWR_S + 0x0C) &= ~0x00040000u;                                                /* BOOSTEN off */
  REG(PWR_S + 0x0C) = sv_vosr;                                                      /* VOS back */
  BENCH.user[11] = REG(RCC_S + 0x1C);
  REG(RCC_S + 0x94) = sv_ahb3;
#ifdef FLASHRUN
  REG(ICACHE_S) = 0u; __asm volatile("dsb\n isb");
  REG(FLASH_S + 0x00) = sv_acr;
#endif
}
#else
static void clock_up(void) {}
static void clock_down(void) {}
#endif


void c10_bench_main(void);
void bench_run(void) { clock_up(); c10_bench_main(); clock_down(); }
