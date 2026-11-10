#!/bin/bash
# Regression probe: the non-secure world must not be able to program the
# ICACHE remap registers (TZSC_SECCFGR3 bit 6, ICACHE_REGSEC).
#
# Why: an ICACHE remap region rewrites the address of every access on the
# CPU's code bus, and on STM32U585 silicon its base may sit on the secure
# flash alias. With `ICACHE_CRR0 = 0x00708260` (0x0C00_0000 -> the SRAM code
# alias 0x0E00_0000) secure fetches and vector reads come from SRAM1
# (EVT-3D21, 2026-11-10). Left non-secure, ICACHE lets non-secure code do
# that to the secure world.
#
# What it does (RAM only; no flash write; ends with a reset):
#   1. attaches to the RUNNING firmware and halts it in the non-secure state;
#   2. plants a 4-instruction stub in non-secure SRAM2 and single-steps it in
#      the non-secure state: clear ICACHE_CR, write ICACHE_CRR0 with the
#      remap fields but REN = 0 (so a vulnerable image is not crashed), read
#      CRR0 back;
#   3. reads ICACHE_CR / CRR0 / TZSC_SECCFGR3 through the secure aliases.
# PASS: the non-secure writes changed nothing and SECCFGR3 has bits 6, 7, 22.
# FAIL: the non-secure world wrote the remap register (positive control: any
#       image before the fix prints `CRR0=00700260`).
#
# On an image built with `tzic-wipe` the non-secure access is a TZIC
# violation and the device wipes: run this on a bench image only.
#
# Usage: tools/dvt/icache_remap_probe.sh        (ST-LINK, any board)
set -u
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
cat > "$T/p.tcl" <<'TCL'
init
set tries 0
while {1} {
  halt
  wait_halt 2000
  # DSCSR.CDS (bit 16): 1 = the core is in the secure state.
  set dscsr [lindex [mdw 0xE000EE08] 1]
  if {![expr {("0x$dscsr" >> 16) & 1}]} { break }
  incr tries
  if {$tries > 20} { echo "PROBE: never caught the core in the non-secure state"; shutdown error }
  resume
  sleep 250
}
echo "PROBE: before  ICACHE_CR=[lindex [mdw 0x50030400] 1] CRR0=[lindex [mdw 0x50030420] 1]"
# str r1,[r0] ; str r2,[r0,#0x20] ; ldr r3,[r0,#0x20] ; bkpt
mww 0x20031000 0x62026001
mww 0x20031004 0xbe006a03
reg r0 0x40030400
reg r1 0
reg r2 0x00700260
reg r3 0x11111111
reg pc 0x20031000
step
step
step
echo "PROBE: ns_readback=[lindex [reg r3] 2]"
echo "PROBE: after   ICACHE_CR=[lindex [mdw 0x50030400] 1] CRR0=[lindex [mdw 0x50030420] 1] SECCFGR3=[lindex [mdw 0x50032418] 1]"
reset run
shutdown
TCL
out=$(timeout 60 openocd -f interface/stlink.cfg -f target/stm32u5x.cfg -f "$T/p.tcl" 2>&1 | grep "^PROBE")
echo "$out"
crr=$(echo "$out" | sed -n 's/.*after .*CRR0=\([0-9a-f]*\).*/\1/p')
cr=$(echo "$out" | sed -n 's/.*after   ICACHE_CR=\([0-9a-f]*\).*/\1/p')
sec=$(echo "$out" | sed -n 's/.*SECCFGR3=\([0-9a-f]*\).*/\1/p')
if [ -z "$crr" ] || [ -z "$sec" ]; then echo "=== icache-remap probe: ERROR (no reading) ==="; exit 2; fi
fail=0
[ "$crr" = "00700260" ] && { echo "FAIL: non-secure code wrote ICACHE_CRR0"; fail=1; }
(( (0x$cr & 1) == 1 )) || { echo "FAIL: non-secure code cleared ICACHE_CR.EN"; fail=1; }
(( (0x$sec & 0x004000C0) == 0x004000C0 )) || { echo "FAIL: TZSC_SECCFGR3=0x$sec lacks ICACHE_REG/DCACHE_REG/RAMCFG (bits 6, 7, 22)"; fail=1; }
[ $fail -eq 0 ] && echo "=== icache-remap probe: PASS ===" || echo "=== icache-remap probe: FAIL ==="
exit $fail
