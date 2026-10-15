#!/bin/bash
# DVT checklist 3.5 verdict: read the SECURE alias of every register the
# `gtzc-sys` phase-2 harness tried to change from non-secure code, and compare
# it with the value the secure boot leaves there.
#
# Run after `GTZC_HOLD=1 make gtzc-enforcement-hw BOARD=pq1 GTZC_NS_EXTRA=,gtzc-sys`
# while the NS side is parked (the make target's probe-rs session has exited).
# The expectations are for that image (mock-se, no `tamp`/`bhk`/`usb`): any
# register the NS probe managed to write differs from them.
set -u
C=${CHIP:-STM32U585CIUx}
fail=0
rd() { probe-rs read --chip "$C" b32 "$1" 1 2>&1 | tail -1 | tr -d ' \n'; }
# name addr mask expected  (checks (value & mask) == expected)
chk() {
    local v; v=$(rd "$2")
    if [ -z "$v" ] || ! [[ $v =~ ^[0-9a-fA-F]+$ ]]; then echo "ERR   $1: unreadable ($v)"; fail=1; return; fi
    local got=$(( 0x$v & $3 ))
    if [ "$got" -eq $(( $4 )) ]; then st=ok; else st=FAIL; fail=1; fi
    printf '%-5s %-22s %s = 0x%08x  (&0x%08x = 0x%08x, want 0x%08x)\n' "$st" "$1" "$2" "0x$v" "$3" "$got" "$(( $4 ))"
}
s=$(rd 0xE000EDF0)
echo "DHCSR=$s"
if (( (0x$s >> 25) & 1 )); then echo "S_RESET_ST set: the target reset since the run; values are boot values"; exit 2; fi
chk RCC_SECCFGR        0x56020D10 0xFFFFFFFF 0x1FFF
chk PWR_SECCFGR        0x56020830 0xFFFFFFFF 0xF0FF
chk RTC_SECCFGR        0x56007820 0xFFFFFFFF 0xE00F
chk TAMP_SECCFGR       0x56007C20 0xBFFFFFFF 0x80208020
chk EXTI_SECCFGR1      0x56022014 0xFFFFFFFF 0x00FFFFFF
chk EXTI_LOCKR         0x56022070 0x1        0x1
chk TZSC_SECCFGR1      0x50032410 0xFFFFFFFF 0x0009E003
chk RCC_APB3ENR.RTCAPB 0x56020CA8 0x00200000 0x00200000
chk RCC_AHB2ENR1.RNGEN 0x56020C8C 0x00040000 0x00040000
chk RCC_CR.HSI48ON     0x56020C00 0x00003000 0x00003000
chk RCC_CFGR3.PPRE3    0x56020C24 0x00000070 0x0
chk RCC_CFGR1.MCOSEL   0x56020C1C 0x0F000000 0x0
chk RCC_PLL1FRACR      0x56020C38 0x0000FFF8 0x0
chk RCC_BDCR.LSCOSEL   0x56020CF0 0x02000000 0x0
chk PWR_SVMCR.PVDE     0x56020810 0x00000010 0x0
chk PWR_DBPR.DBP       0x56020828 0x00000001 0x1
chk TAMP_FLTCR         0x56007C0C 0x00000003 0x0
chk TAMP_CR1.ITAMP5E   0x56007C00 0x00100000 0x0
chk TAMP_BKP0R         0x56007D00 0xFFFFFFFF 0x0
chk TAMP_BKP31R        0x56007D7C 0xFFFFFFFF 0x0
chk EXTI_RTSR1.L0L1    0x56022000 0x00000003 0x0
chk EXTI_EXTICR1.L0    0x56022060 0x000000FF 0x0
[ $fail -eq 0 ] && echo "=== gtzc-sys SWD verdict: PASS ===" || echo "=== gtzc-sys SWD verdict: FAIL ==="
exit $fail
