#!/usr/bin/env bash
# run_c10.sh <elf> <result_addr> <result_words> [timeout_s]  (C10 autoresearch copy of run_on_board.sh:
# additionally reads the SIG0/SIG1 buffers as "SIG0_WORDS ..."/"SIG1_WORDS ..." lines)
#
# Runs an SRAM-only ELF (linked with link_sram.ld + startup.c) on the attached B-U585I-IOT02A and prints
# the result words. Volatile-only: OpenOCD init -> reset halt (core caught at the reset vector, Secure
# state, before the board firmware runs) -> clear AP HNONSEC -> poison the result words with 0xDEADBEEF ->
# load_image + verify_image into secure SRAM -> MSP/MSP_S/MSPLIM_S, xPSR=Thumb, PRIMASK=1, PC=entry ->
# resume -> wait_halt(timeout) [on timeout: halt] -> read PC + result words -> reset run -> shutdown.
# "reset run" + "shutdown" run on EVERY path (Tcl catch), so the board always boots its own firmware again.
# Never writes flash, option bytes, OTP or any non-volatile memory.
#
# Output (stdout): "PC_AT_HALT 0x...", "WAITHALT ok|TIMEOUT", one line "RESULT_WORDS w0 w1 ...",
# and, when the block is the standard bench.h layout (64 words at 0x30000000), a decoded summary.
# Exit status: 0 = halted in time and status word == DONE ('DONE' 0x444F4E45); 2 = other status; 3 = timeout;
# 4 = OpenOCD/run error. The full OpenOCD log is kept in <elf>.openocd.log.
set -u
ELF="$1"; ADDR="$2"; NW="$3"; TMO="${4:-60}"
[ -f "$ELF" ] || { echo "no such ELF: $ELF" >&2; exit 4; }
ELF="$(readlink -f "$ELF")"
ENTRY=$(arm-none-eabi-readelf -h "$ELF" | awk '/Entry point/ {print $4}')
ENTRY=$(printf '0x%08x' $(( ENTRY & ~1 )))
STOP=$(arm-none-eabi-nm "$ELF" | awk '$3=="__stack_top" {print "0x"$1}')
SLIM=$(arm-none-eabi-nm "$ELF" | awk '$3=="__stack_limit" {print "0x"$1}')
SIG0=$(arm-none-eabi-nm "$ELF" | awk '$3=="SIG0" {print "0x"$1}'); SIG1=$(arm-none-eabi-nm "$ELF" | awk '$3=="SIG1" {print "0x"$1}')
[ -n "$SIG0" ] && [ -n "$SIG1" ] || { echo "no SIG0/SIG1 symbols" >&2; exit 4; }
[ -n "$STOP" ] || STOP=0x300C0000; [ -n "$SLIM" ] || SLIM=0x00000000
# Refuse anything that would load outside the secure SRAM alias.
arm-none-eabi-readelf -lW "$ELF" | python3 -c '
import sys
bad = 0
for l in sys.stdin:
    f = l.split()
    if f and f[0] == "LOAD" and int(f[5], 16) > 0:
        # load (physical) address must be secure SRAM; the run address may be its C-bus alias (harness v2)
        a = int(f[3], 16); e = a + int(f[5], 16); v = int(f[2], 16); ve = v + int(f[5], 16)
        if a < 0x30000000 or e > 0x300C0000:
            print("REFUSE: LOAD segment 0x%x..0x%x outside secure SRAM 0x30000000..0x300C0000" % (a, e)); bad = 1
        if not ((0x30000000 <= v and ve <= 0x300C0000) or (0x0E000000 <= v and ve <= 0x0E030000 and v - 0x0E000000 == a - 0x30000000)):
            print("REFUSE: run address 0x%x..0x%x is neither secure SRAM nor its SRAM1 C-bus alias" % (v, ve)); bad = 1
sys.exit(bad)' || exit 4
TCL=$(mktemp --suffix=.tcl); LOG="$ELF.openocd.log"
cat > "$TCL" <<TCLEOF
# No target work area: stm32u5x.cfg puts a 64 KiB work area at 0x20000000, which is the NS alias of the
# SAME physical SRAM1 as 0x30000000; verify_image would run its CRC routine there and overwrite the
# result block (found by the no-write control). With size 0, verify_image reads the memory back instead.
stm32u5x.cpu configure -work-area-size 0
init
set run_err ""
set waited "NOTRUN"
set rc [catch {
  reset halt
  stm32u5x.dap apcsw 0x00000000 0x40000000
  mww $ADDR 0xDEADBEEF $NW
  load_image {$ELF} 0 elf
  verify_image {$ELF} 0 elf
  reg msplim_s 0
  reg msp_s $STOP
  reg msp $STOP
  reg msplim_s $SLIM
  reg xPSR 0x01000000
  reg primask 1
  reg pc $ENTRY
  resume
  if {[catch {wait_halt [expr {$TMO * 1000}]}]} { set waited "TIMEOUT"; halt } else { set waited "ok" }
} run_err]
if {\$rc} { echo "RUN_ERROR: \$run_err"; catch {halt} }
echo "WAITHALT \$waited"
catch { echo "PC_AT_HALT [lindex [capture {reg pc}] end]" }
set words {}
if {[catch {set words [read_memory $ADDR 32 $NW]} e2]} { echo "READ_ERROR: \$e2" }
set out "RESULT_WORDS"
foreach w \$words { append out [format " 0x%08x" \$w] }
echo \$out
foreach {nm a} {SIG0 $SIG0 SIG1 $SIG1} {
  set sw {}
  if {[catch {set sw [read_memory \$a 32 1002]} e3]} { echo "READ_ERROR: \$e3" }
  set o "\${nm}_WORDS"
  foreach w \$sw { append o [format " 0x%08x" \$w] }
  echo \$o
}
reset run
shutdown
TCLEOF
timeout $(( TMO + 120 )) openocd -f interface/stlink-dap.cfg -f target/stm32u5x.cfg \
  -c "gdb_port disabled" -c "tcl_port disabled" -c "telnet_port disabled" -f "$TCL" > "$LOG" 2>&1
orc=$?; rm -f "$TCL"
grep -E '^(WAITHALT|PC_AT_HALT|RUN_ERROR|READ_ERROR)' "$LOG"
grep -q 'shutdown command invoked' "$LOG" || echo "WARNING: OpenOCD did not reach shutdown (rc=$orc); check $LOG and re-run a plain 'reset run'"
grep -q '^RESULT_WORDS 0x' "$LOG" || exit 4
python3 - "$LOG" "$ADDR" "$NW" <<'PY'
import sys
log, addr, nw = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3])
w = [int(x, 16) for x in next(l for l in open(log) if l.startswith('RESULT_WORDS')).split()[1:]]
if addr != 0x30000000 or len(w) < 64: sys.exit(0)
st = w[0]
name = {0x53545254: 'STARTED(never returned)', 0x444F4E45: 'DONE', 0xDEADBEEF: 'POISON(never ran)'}.get(st)
if name is None: name = 'FAULT exc %d' % (st & 0x1ff) if st >> 16 == 0xFA17 else ('HALT code 0x%x' % (st & 0xffff) if st >> 16 == 0x4841 else 'UNKNOWN')
print('STATUS 0x%08x %s' % (st, name))
print('CYC_RUN %d  DWT_CTRL 0x%08x  CYC_OVERHEAD %d' % (w[1], w[2], w[3]))
print('USER ' + ' '.join(str(x) for x in w[4:16]))
if st >> 16 == 0xFA17: print('FAULT CFSR=0x%08x HFSR=0x%08x BFAR=0x%08x MMFAR=0x%08x SFSR=0x%08x SFAR=0x%08x PC=0x%08x LR=0x%08x' % tuple(w[16:24]))
n = w[24]
if n <= 156:
    b = b''.join(x.to_bytes(4, 'little') for x in w[25:64])[:n]
    print('TEXT ' + repr(b.decode('latin-1')))
PY
st=$(grep '^RESULT_WORDS' "$LOG" | awk '{print $2}')
grep -q '^WAITHALT TIMEOUT' "$LOG" && exit 3
[ "$st" = "0x444f4e45" ] && exit 0 || exit 2
