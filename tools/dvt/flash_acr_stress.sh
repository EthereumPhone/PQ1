#!/bin/bash
# Stress probe for the flash-timing guard (#1132): non-secure code changes
# FLASH_ACR in every way it can, at speed, and then enters the secure world.
#
# Why: FLASH_ACR cannot be made secure-only on STM32U585. Non-secure
# privileged code writes LATENCY, PRFTEN, LPM and SLEEP_PD, and (after the
# PDKEYxR keys) PDREQ1/PDREQ2, which power a flash bank down. With a wrong
# LATENCY at 160 MHz flash reads return wrong data, so every entry into
# flash-resident secure code has to put the register back first
# (`secure/src/flash_guard.rs`).
#
# What it does (RAM only; no flash write; ends with a reset):
#   1. resets the board, lets the firmware boot, and halts it in the
#      non-secure state;
#   2. loads a stub into non-secure SRAM2 and runs it at full speed, once per
#      mode below. Each iteration: [optional priming call] -> write the
#      PDKEYs -> write FLASH_ACR -> [read it back] -> [wait for the PD flags]
#      -> [write the boot value back WITHOUT a readback] -> call a gateway
#      entry -> compare the return value. The 1 ms secure SysTick preempts the
#      stub at arbitrary points, so the exception entry is exercised too;
#   3. the "spin" modes do not call the gateway: they leave the bad value in
#      FLASH_ACR for a few milliseconds and count how often the secure
#      SysTick did not put it back.
# PASS: every mode completes all iterations, every call returns the control
#       value, the board never resets, FLASH_ACR ends at the boot value.
# FAIL: a wrong return value, a hang, or a reset (a wrong secure fetch ends
#       in the fault handler, which resets).
#
# Run it on a bench image only (mock-se, no tzic-wipe).
#
# Usage: tools/dvt/flash_acr_stress.sh [secure-elf] [iterations]
set -u
ELF=${1:-target/secure/thumbv8m.main-none-eabi/release/sphincs-tz-secure}
N=${2:-2000}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
sym() { arm-none-eabi-nm "$ELF" | awk -v s="$1" '$3==s {print "0x"$1}'; }
VA=$(sym nscram_get_remaining_attempts)
VB=$(sym nscram_is_unlocked)
HITS=$(sym __pq_flash_guard_hits)
# Images before the 2026-11-10 guard rework have no flush counter; the guard
# hit counter stands in so the script still runs on them.
FLUSH=$(sym __pq_icache_flushes)
[ -z "$FLUSH" ] && FLUSH=$HITS
if [ -z "$VA" ] || [ -z "$VB" ] || [ -z "$HITS" ]; then
  echo "=== flash-acr stress: ERROR (no nscram_* / guard symbols in $ELF) ==="; exit 2
fi

cat > "$T/stub.s" <<'ASM'
    .syntax unified
    .thumb
    .equ P_ACR,   0x00      @ value written to FLASH_ACR
    .equ P_FLAGS, 0x04      @ see the bits below
    .equ P_N,     0x08      @ iterations
    .equ P_VB,    0x0c      @ gateway entry called after the write (thumb)
    .equ P_EXP,   0x10      @ its expected return value
    .equ P_PDM,   0x14      @ FLASH_NSSR mask to wait for (PD1 = bit 20, PD2 = bit 21)
    .equ P_VA,    0x18      @ gateway entry for the priming call
    .equ P_SPIN,  0x1c      @ spin count (spin modes)
    .equ R_DONE,  0x20
    .equ R_BAD,   0x24
    .equ R_LAST,  0x28
    .equ R_STATE, 0x2c      @ 1 running, 2 done
    .equ R_NOTFIXED, 0x30   @ spin modes: FLASH_ACR still wrong after the spin
    .equ F_RB,    1         @ read FLASH_ACR back after the write
    .equ F_KEY1,  2         @ write the PDKEY1R keys first
    .equ F_KEY2,  4         @ write the PDKEY2R keys first
    .equ F_REST,  8         @ write 4 back, no readback, right before the call
    .equ F_WAITPD,16        @ wait until FLASH_NSSR & P_PDM == P_PDM
    .equ F_PRIME, 32        @ first: LATENCY=0, readback, call P_VA
    .equ F_SPIN,  64        @ no call: spin, then check FLASH_ACR
start:
    ldr r7, =0x20031400
    ldr r6, =0x40022000
    movs r5, #0
    movs r4, #0
    str r5, [r7, #R_DONE]
    str r5, [r7, #R_BAD]
    str r5, [r7, #R_NOTFIXED]
    movs r0, #1
    str r0, [r7, #R_STATE]
loop:
    ldr r0, [r7, #P_N]
    cmp r5, r0
    bhs done
    ldr r1, [r7, #P_FLAGS]
    tst r1, #F_PRIME
    beq 0f
    movs r0, #0
    str r0, [r6]
    ldr r0, [r6]
    ldr r3, [r7, #P_VA]
    blx r3
    ldr r1, [r7, #P_FLAGS]
0:  tst r1, #F_KEY1
    beq 1f
    ldr r0, =0x04152637
    str r0, [r6, #0x18]
    ldr r0, =0xFAFBFCFD
    str r0, [r6, #0x18]
1:  tst r1, #F_KEY2
    beq 2f
    ldr r0, =0x40516273
    str r0, [r6, #0x1c]
    ldr r0, =0xAFBFCFDF
    str r0, [r6, #0x1c]
2:  ldr r0, [r7, #P_ACR]
    str r0, [r6]
    tst r1, #F_RB
    beq 3f
    ldr r0, [r6]
3:  tst r1, #F_WAITPD
    beq 4f
    ldr r2, [r7, #P_PDM]
    movs r3, #0
5:  adds r3, #1
    cmp r3, #0x10000
    bhs 4f
    ldr r0, [r6, #0x20]
    ands r0, r2
    cmp r0, r2
    bne 5b
4:  tst r1, #F_SPIN
    bne spin
    tst r1, #F_REST
    beq 6f
    movs r0, #4
    str r0, [r6]
6:  ldr r3, [r7, #P_VB]
    blx r3
    str r0, [r7, #R_LAST]
    ldr r1, [r7, #P_EXP]
    cmp r0, r1
    beq 7f
    adds r4, #1
    str r4, [r7, #R_BAD]
7:  adds r5, #1
    str r5, [r7, #R_DONE]
    b loop
spin:
    ldr r0, [r7, #P_SPIN]
8:  subs r0, #1
    bne 8b
    ldr r0, [r6]
    cmp r0, #4
    beq 7b
    ldr r0, [r7, #R_NOTFIXED]
    adds r0, #1
    str r0, [r7, #R_NOTFIXED]
    movs r0, #4
    str r0, [r6]
    ldr r0, [r6]
    b 7b
done:
    movs r0, #2
    str r0, [r7, #R_STATE]
    bkpt 0
    b .
    .ltorg
ASM
arm-none-eabi-as -mcpu=cortex-m33 -o "$T/stub.o" "$T/stub.s" || exit 2
arm-none-eabi-objcopy -O binary "$T/stub.o" "$T/stub.bin" || exit 2

cat > "$T/p.tcl" <<TCL
init
arm semihosting enable
proc sr {a} { return [lindex [mdw \$a] 1] }
proc catch_ns {} {
  reset halt
  resume
  set tries 0
  while {1} {
    halt
    wait_halt 2000
    set dscsr [sr 0xE000EE08]
    if {![expr {("0x\$dscsr" >> 16) & 1}]} { break }
    incr tries
    if {\$tries > 240} { echo "STRESS: never caught the core in the non-secure state"; shutdown error }
    resume
    sleep 250
  }
}
# name acr flags n pdmask spin
proc run_mode {name acr flags n pdm spin} {
  global expect
  mww 0x20031400 \$acr
  mww 0x20031404 \$flags
  mww 0x20031408 \$n
  mww 0x2003140c [expr {$VB | 1}]
  mww 0x20031410 \$expect
  mww 0x20031414 \$pdm
  mww 0x20031418 [expr {$VA | 1}]
  mww 0x2003141c \$spin
  mww 0x2003142c 0
  set h0 [sr $HITS]
  set f0 [sr $FLUSH]
  mdw 0xE000EDF0
  reg pc 0x20031000
  resume
  set t 0
  set st 0
  while {\$t < 600} {
    sleep 100
    incr t
    set st [sr 0x2003142c]
    if {\$st == "00000002"} { break }
  }
  halt
  wait_halt 2000
  set dhcsr [sr 0xE000EDF0]
  set rst [expr {("0x\$dhcsr" >> 25) & 1}]
  set done [expr "0x[sr 0x20031420] + 0"]
  set bad [expr "0x[sr 0x20031424] + 0"]
  set nf [expr "0x[sr 0x20031430] + 0"]
  set h1 [sr $HITS]
  set dh [expr "0x\$h1 - 0x\$h0"]
  set df [expr "0x[sr $FLUSH] - 0x\$f0"]
  echo "STRESS: mode=\$name acr=\$acr flags=\$flags done=\$done/\$n bad=\$bad last=[sr 0x20031428] notfixed=\$nf guard_hits=+\$dh icache_flushes=+\$df ACR=[sr 0x50022000] NSSR=[sr 0x50022020] ECCR=[sr 0x50022030] reset=\$rst state=\$st"
  if {\$st != "00000002" || \$rst} {
    echo "STRESS: stopped: pc=[lindex [reg pc] 2] xPSR=[lindex [reg xPSR] 2] DSCSR=[sr 0xE000EE08] CFSR=[sr 0xE000ED28] SFSR=[sr 0xE000EDE4] HFSR=[sr 0xE000ED2C]"
  }
  return [sr 0x20031428]
}
catch_ns
load_image $T/stub.bin 0x20031000 bin
echo "STRESS: start  ACR=[sr 0x50022000] NSSR=[sr 0x50022020] ICACHE_CR=[sr 0x50030400] guard_hits=[sr $HITS]"
set expect 0
set expect "0x[run_mode calibrate 0x4 0 16 0 0]"
echo "STRESS: control return value = \$expect"
run_mode control      0x00000004 0  $N 0 0
run_mode latency0     0x00000000 1  $N 0 0
run_mode latency0_norb 0x00000000 0 $N 0 0
run_mode latency1     0x00000001 1  $N 0 0
run_mode restore_norb 0x00000000 41 $N 0 0
run_mode lpm          0x00000804 1  $N 0 0
run_mode prften       0x00000104 1  $N 0 0
run_mode sleep_pd     0x00004004 1  $N 0 0
run_mode pd1          0x00001004 51 $N 0x00100000 0
run_mode pd2          0x00002004 53 $N 0x00200000 0
run_mode pd12         0x00003004 55 $N 0x00300000 0
run_mode pd1_lat0     0x00001000 51 $N 0x00100000 0
run_mode all_bits     0x00007900 7  $N 0 0
run_mode spin_lat0    0x00000000 65 $N 0 400000
run_mode spin_pd1     0x00001004 83 $N 0x00100000 400000
echo "STRESS: end    ACR=[sr 0x50022000] NSSR=[sr 0x50022020] ICACHE_CR=[sr 0x50030400] guard_hits=[sr $HITS]"
# Leave the board running with debug off (DBGKEY, C_DEBUGEN = 0): with the
# bit left set, a USB image parks on its first semihosting print.
reset halt
mww 0xE000EDF0 0xA05F0000
shutdown
TCL
out=$(timeout 1500 openocd -f interface/stlink.cfg -f target/stm32u5x.cfg -f "$T/p.tcl" 2>&1)
echo "$out" | grep "^STRESS"
[ -n "${STRESS_RAW:-}" ] && echo "$out" > "$STRESS_RAW"
modes=$(echo "$out" | grep -c "^STRESS: mode=")
fail=0
[ "$modes" -eq 16 ] || { echo "FAIL: $modes of 16 modes reported"; fail=1; }
while read -r line; do
  name=$(echo "$line" | sed -n 's/.*mode=\([a-z0-9_]*\).*/\1/p')
  [ "$name" = calibrate ] && continue
  d=$(echo "$line" | sed -n 's/.* done=\([0-9]*\)\/\([0-9]*\).*/\1 \2/p')
  set -- $d
  [ "${1:-x}" = "${2:-y}" ] || { echo "FAIL: $name did not finish ($d)"; fail=1; }
  echo "$line" | grep -q " bad=0 " || { echo "FAIL: $name returned a wrong value"; fail=1; }
  echo "$line" | grep -q " notfixed=0 " || { echo "FAIL: $name: FLASH_ACR was left wrong across a secure SysTick"; fail=1; }
  echo "$line" | grep -q " reset=0 " || { echo "FAIL: $name: the board reset"; fail=1; }
  echo "$line" | grep -q " ACR=00000004 " || { echo "FAIL: $name: FLASH_ACR not the boot value afterwards"; fail=1; }
done < <(echo "$out" | grep "^STRESS: mode=")
[ $fail -eq 0 ] && echo "=== flash-acr stress: PASS ===" || echo "=== flash-acr stress: FAIL ==="
exit $fail
