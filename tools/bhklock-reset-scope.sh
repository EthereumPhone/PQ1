#!/usr/bin/env bash
# bhklock-reset-scope.sh — does TAMP_SECCFGR.BHKLOCK survive a SYSTEM reset?
#
# WHY THIS MATTERS (issue #712): `first_boot` locks the BHK before committing
# its journal step, and on a retry it erases page 126, generates a NEW key, and
# writes it into the backup registers with `load_and_lock`, which never checks
# whether BHKLOCK is already set and returns Ok regardless. If BHKLOCK survives
# a system reset, those writes are ignored — SCP03 then rotates against the OLD
# active key while flash holds the NEW one, and the SE050 is stranded once the
# backup domain empties. Our code assumes the opposite: `main.rs:1301` says
# "BHKLOCK is write-once/boot" and `bhk.rs:32` says it clears on cold boot.
#
# This is a DEBUGGER-ONLY experiment: it touches TAMP/RCC/PWR registers only.
# No flash write, no OTP, no secure element, no provisioning. BHKLOCK lives in
# the backup domain, so a power cycle clears it — which is also the control.
#
# Usage: tools/bhklock-reset-scope.sh [phase1|phase2|phase3]
#   phase1  arm: prove pre-lock writes work, set BHKLOCK, prove writes ignored
#   phase2  after `probe-rs reset`: is BHKLOCK still set?      <-- the answer
#   phase3  after a POWER CYCLE: BHKLOCK must be clear         <-- the control
#
# RESULT 2026-09-21 on the bench board (UID 002f0023 30465002 2033314c):
#   BHKLOCK is STICKY and SURVIVES a system reset. Writing 0 does not clear it,
#   and after `probe-rs reset` it still reads set with DHCSR S_HALT=1 proving
#   the core was halted and no firmware ran. So `load_and_lock`'s writes on a
#   second call are silently ignored (#712).
#
# TWO TRAPS THAT PRODUCED WRONG ANSWERS BEFORE THEY WERE UNDERSTOOD — both cost
# a false conclusion during this investigation, so read them before rerunning:
#
#   1. CLOCK. A reset clears RCC.RTCAPBEN, and TAMP reads return 0x00000000
#      with the clock off. That is indistinguishable from "the lock cleared".
#      Every reading here is only valid AFTER enable_tamp_clock(); a raw
#      `probe-rs read` straight after a reset is meaningless.
#   2. FIRMWARE. `probe-rs reset` leaves the core HALTED (verify: DHCSR bit 17
#      S_HALT), but a POWER CYCLE lets firmware boot before you can attach. If
#      the flashed image sets the lock itself, phase 3 cannot distinguish that
#      from persistence. Check DHCSR before trusting any reading.
#
# STILL OPEN: phase 3 saw the bit still set after a power cycle while BKP8R had
# cleared, which the backup-domain model does not explain. Candidates: the
# debug probe keeping the target powered, or a tamper event erasing BKPxR
# without clearing SECCFGR. It does not weaken the finding above — it would only
# make the lock stickier than our code assumes.
set -uo pipefail

CHIP=${CHIP:-STM32U585CIUx}
P="probe-rs"

# Register addresses, taken from secure/src/hw/bhk.rs:91-118.
TAMP_S=0x56007C00;  TAMP_NS=0x40007C00
RCC_S=0x56020C00;   RCC_NS=0x46020C00
PWR_S=0x56020800;   PWR_NS=0x46020800
SECCFGR_OFF=0x20
BKP0R_OFF=0x100
APB3ENR_OFF=0xA8
DBPR_OFF=0x28
RTCAPBEN=$((1 << 21))
DBP=$((1 << 0))
BHKLOCK=$((1 << 30))

# `probe-rs read` prints "<addr>: <value>", so take the LAST hex token and
# normalise it. Returning the whole line would corrupt every $(( )) below.
rd() {
  local out tok
  out=$($P read --chip "$CHIP" b32 "$1" 1 2>/dev/null) || return 1
  tok=$(echo "$out" | tr ' \t' '\n\n' | grep -oE '[0-9a-fA-F]{8}' | tail -1)
  [ -n "$tok" ] || return 1
  echo "0x$tok"
}
wr() { $P write --chip "$CHIP" b32 "$1" "$2" >/dev/null 2>&1; }

# Readout validation. An unvalidated probe read has produced confident false
# findings on this project before, so prove the path works on a value we can
# recognise (the STM32 UID, RM0456 §28.10) before trusting any TAMP read.
validate_readout() {
  local uid0 uid1 uid2
  uid0=$(rd 0x0BFA0700); uid1=$(rd 0x0BFA0704); uid2=$(rd 0x0BFA0708)
  echo "  UID = ${uid0:-?} ${uid1:-?} ${uid2:-?}"
  if [ -z "$uid0" ] || [ "$uid0" = "0x00000000" ] || [ "$uid0" = "0xffffffff" ]; then
    echo "  !! UID read implausible — the readout path is not trustworthy. Stop." >&2
    return 1
  fi
  return 0
}

hex() { printf "0x%08x" "$1"; }

# Which alias answers? With TZEN=1 the secure alias is the live one; with TZEN=0
# only the non-secure alias exists. Probing avoids assuming the board's state.
pick_alias() {
  local v
  v=$(rd $((TAMP_S + SECCFGR_OFF)))
  if [ -n "$v" ]; then ALIAS=S; TAMP=$TAMP_S; RCC=$RCC_S; PWR=$PWR_S; return 0; fi
  v=$(rd $((TAMP_NS + SECCFGR_OFF)))
  if [ -n "$v" ]; then ALIAS=NS; TAMP=$TAMP_NS; RCC=$RCC_NS; PWR=$PWR_NS; return 0; fi
  echo "FATAL: TAMP_SECCFGR unreadable through either alias — board powered? SWD wired?" >&2
  return 1
}

enable_tamp_clock() {
  # A system reset clears RCC.RTCAPBEN. Without re-enabling it the TAMP
  # registers read as zero, which would look exactly like "BHKLOCK cleared" —
  # the single most likely way to get a FALSE answer out of this test.
  local cur
  cur=$(rd $((RCC + APB3ENR_OFF)))
  wr $((RCC + APB3ENR_OFF)) $(( ${cur:-0} | RTCAPBEN ))
  cur=$(rd $((PWR + DBPR_OFF)))
  wr $((PWR + DBPR_OFF)) $(( ${cur:-0} | DBP ))
  echo "  RCC_APB3ENR=$(rd $((RCC + APB3ENR_OFF)))  PWR_DBPR=$(rd $((PWR + DBPR_OFF)))"
}

# Is the core halted? If not, firmware may be the thing setting the lock, and
# no reading here distinguishes that from persistence. DHCSR bit 17 = S_HALT.
core_halted() {
  local v
  v=$(rd 0xE000EDF0) || { echo "UNKNOWN"; return; }
  if [ $(( v & (1 << 17) )) -ne 0 ]; then echo "HALTED"; else echo "RUNNING"; fi
}

bhklock_state() {
  local v
  v=$(rd $((TAMP + SECCFGR_OFF))) || { echo "UNREADABLE"; return; }
  if [ $(( v & BHKLOCK )) -ne 0 ]; then echo "SET"; else echo "CLEAR"; fi
}

phase=${1:-phase1}
echo "-- readout validation (before anything is trusted)"
validate_readout || exit 3
pick_alias || exit 1
echo "== alias=$ALIAS  TAMP=$(hex $TAMP)  chip=$CHIP"

case "$phase" in
phase1)
  echo "-- baseline"
  enable_tamp_clock
  echo "  SECCFGR=$(rd $((TAMP + SECCFGR_OFF)))  BHKLOCK=$(bhklock_state)"
  if [ "$(bhklock_state)" = "SET" ]; then
    echo "  !! BHKLOCK already SET before we touched it — power-cycle the board"
    echo "     first, or the baseline control is void."
    exit 2
  fi
  echo "-- control A: a backup register must be writable BEFORE the lock"
  wr $((TAMP + BKP0R_OFF)) 0xA5A50001
  got=$(rd $((TAMP + BKP0R_OFF)))
  echo "  BKP0R after write = $got (want 0xa5a50001)"
  echo "-- set BHKLOCK"
  cur=$(rd $((TAMP + SECCFGR_OFF)))
  wr $((TAMP + SECCFGR_OFF)) $(( cur | BHKLOCK ))
  echo "  SECCFGR=$(rd $((TAMP + SECCFGR_OFF)))  BHKLOCK=$(bhklock_state)"
  echo "-- control B: the same write must now be IGNORED"
  wr $((TAMP + BKP0R_OFF)) 0x5A5A0002
  echo "  BKP0R after locked write = $(rd $((TAMP + BKP0R_OFF))) (must NOT be 0x5a5a0002)"
  echo
  echo "ARMED. Now: $P reset --chip $CHIP   then: $0 phase2"
  ;;
phase2)
  echo "-- after SYSTEM reset (backup domain should be retained)"
  echo "  core is $(core_halted) (must be HALTED, or firmware could be the writer)"
  enable_tamp_clock
  state=$(bhklock_state)
  echo "  SECCFGR=$(rd $((TAMP + SECCFGR_OFF)))  BHKLOCK=$state"
  echo "  BKP0R=$(rd $((TAMP + BKP0R_OFF)))"
  echo "-- does a write land now?"
  wr $((TAMP + BKP0R_OFF)) 0xDEAD0003
  echo "  BKP0R after write = $(rd $((TAMP + BKP0R_OFF)))"
  echo
  if [ "$state" = "UNREADABLE" ]; then
    echo "RESULT: INCONCLUSIVE — SECCFGR unreadable after the reset."
    echo "  Most likely the TAMP APB clock did not come back; do not read this"
    echo "  as 'the lock cleared'."
    exit 4
  fi
  if [ "$state" = "SET" ]; then
    echo "RESULT: BHKLOCK SURVIVES a system reset."
    echo "  => #712 fires: a retry's load_and_lock() writes are silently ignored,"
    echo "     and our 'write-once/boot' assumption (main.rs:1301) is WRONG."
  else
    echo "RESULT: BHKLOCK CLEARED by the system reset."
    echo "  => the #712 mismatch trace does NOT fire by this mechanism."
    echo "     (load_and_lock still lacks verification — that defect stands.)"
  fi
  echo
  echo "Now POWER CYCLE the board and run: $0 phase3   (control)"
  ;;
phase3)
  echo "-- after POWER CYCLE (backup domain should be cleared)"
  # Did the power cycle actually happen? BKP8R is outside the BHK's BKP0..7 so
  # it stays writable under BHKLOCK; phase1/arming leaves 0xC0FFEE01 there, and
  # only a backup-domain reset clears it. Without this, "still locked" is
  # ambiguous between a failed control and a power cycle that never occurred.
  marker=$(rd $((TAMP + 0x120)) || echo "unreadable")
  echo "  BKP8R detector = $marker"
  if [ "$marker" = "0xc0ffee01" ]; then
    echo "  !! the backup domain was NOT cleared — the board was not power-cycled."
    echo "     This is not a control failure; re-run after actually cutting power."
    exit 5
  fi
  enable_tamp_clock
  state=$(bhklock_state)
  echo "  SECCFGR=$(rd $((TAMP + SECCFGR_OFF)))  BHKLOCK=$state"
  echo "  BKP0R=$(rd $((TAMP + BKP0R_OFF))) (want 0x00000000 — domain cleared)"
  echo
  if [ "$state" = "CLEAR" ]; then
    echo "CONTROL OK: the bit is backup-domain-scoped, so phase 2's reading was real."
  else
    echo "CONTROL FAILED: BHKLOCK still set after a power cycle. Either the board"
    echo "  retains the backup domain (VBAT), or this read is not measuring what we"
    echo "  think. Phase 2's result is NOT trustworthy until this is explained."
  fi
  ;;
*) echo "usage: $0 [phase1|phase2|phase3]" >&2; exit 2;;
esac
