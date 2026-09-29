#!/usr/bin/env bash
# Assert that a non-secure ELF calls the gateway at the addresses the secure ELF
# actually exports. Exit 0 = every nsc_* matches; exit 1 = mismatch; exit 2 = usage.
#
# WHY THIS EXISTS: cargo does not track files named in RUSTFLAGS link-args, so
# after a secure rebuild an unchanged NS is NOT relinked and keeps the PREVIOUS
# secure build's veneer addresses. Commit 3d8b014a guards most Makefile recipes
# with `rm -f $(NONSECURE_ELF) .../deps/sphincs_tz_nonsecure-*`, but not all
# (issue #690). On 2026-09-18 a pq1 bench image shipped with all 18 nsc_* calls
# +0x700 off: it booted and enumerated normally, then the FIRST APDU of any kind
# faulted into the secure world and reset the board. Sizes, the fwsign
# `verify: PASS` and the commit greps all passed on that image — this join is
# the only check that sees it.
#
# Fails closed on a count mismatch or an empty export set, so a wrong ELF (or a
# build with no CMSE entry points) cannot pass vacuously on an empty join.
#
# Usage: tools/check-gateway-abi.sh <secure-elf> <nonsecure-elf>

set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 <secure-elf> <nonsecure-elf>" >&2
  exit 2
fi
SEC_ELF="$1"
NS_ELF="$2"
for f in "$SEC_ELF" "$NS_ELF"; do
  [ -f "$f" ] || { echo "!! no such file: $f" >&2; exit 2; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Secure side: the entry functions themselves (T). NS side: the absolute
# symbols the CMSE import library injected at link time (A).
arm-none-eabi-nm "$SEC_ELF" | awk '$2=="T" && $3 ~ /^nsc_/ {print $3, $1}' | sort > "$tmp/sec"
arm-none-eabi-nm "$NS_ELF"  | awk '$2=="A" && $3 ~ /^nsc_/ {print $3, $1}' | sort > "$tmp/ns"

n_sec=$(wc -l < "$tmp/sec")
n_ns=$(wc -l < "$tmp/ns")
n_ok=$(join "$tmp/sec" "$tmp/ns" | awk '$2==$3' | wc -l)
echo "gateway ABI: secure exports=$n_sec  ns imports=$n_ns  matching=$n_ok"

if [ "$n_sec" -lt 1 ] || [ "$n_ok" -ne "$n_sec" ] || [ "$n_ok" -ne "$n_ns" ]; then
  echo "!! GATEWAY ABI MISMATCH — the NS was linked against a different secure build" >&2
  echo "   symbol  secure  ns" >&2
  join -a1 -a2 -e MISSING -o 0,1.2,2.2 "$tmp/sec" "$tmp/ns" | awk '$2!=$3 {print "  ", $0}' >&2
  exit 1
fi
echo "OK — every nsc_* import matches the secure export"
