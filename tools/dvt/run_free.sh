#!/bin/bash
# Reset the board and let it run with debug switched off (DHCSR.C_DEBUGEN = 0).
#
# Why: a probe leaves C_DEBUGEN set after flashing. The non-secure USB image
# prints its pre-USB register dump over semihosting when it sees that bit, and
# with no semihosting host the BKPT parks the core before USB comes up: the
# device never enumerates. A plain `probe-rs reset` does not clear the bit.
#
# Usage: tools/dvt/run_free.sh          (ST-LINK, any board)
set -u
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
cat > "$T/p.tcl" <<'TCL'
init
reset halt
# DBGKEY | C_DEBUGEN = 0: the core leaves halt and runs with debug off.
mww 0xE000EDF0 0xA05F0000
shutdown
TCL
out=$(timeout 60 openocd -f interface/stlink.cfg -f target/stm32u5x.cfg -f "$T/p.tcl" 2>&1)
# Silence is not success: with the probe held by another process OpenOCD
# prints its banner and exits without a word about the target.
if echo "$out" | grep -q "shutdown command invoked" && ! echo "$out" | grep -qE "Error|error"; then
  exit 0
fi
echo "run_free: the reset did not go through (probe busy or target not found):" >&2
echo "$out" | tail -5 >&2
exit 1
