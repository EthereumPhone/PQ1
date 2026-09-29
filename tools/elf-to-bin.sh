#!/usr/bin/env bash
# elf-to-bin.sh — turn a linked PQSigner ELF into a flashable raw binary, and
# PROVE the binary covers every byte the loader will need.
#
# WHY THIS EXISTS (2026-09-23, cost two device cycles).
#
# The two worlds need DIFFERENT objcopy invocations, and using one world's
# recipe on the other silently produces a broken image:
#
#   * NON-SECURE: its `.data` (0 B) and `.gnu.sgstubs` (0 B) are empty, but the
#     ELF still carries a LOAD segment for RAM at 0x2003_0000 with FileSiz 0.
#     Plain `-O binary` spans flash..RAM and emits a ~401 MB file padded with
#     0xFF. So the NS image must name its flash sections explicitly.
#
#   * SECURE: `.data` is ~10 KB with its LMA in flash (the initial values of
#     every non-zero static, copied to RAM by cortex-m-rt before main), and
#     `.gnu.sgstubs` holds the CMSE secure-gateway veneers. Its `.bss` carries
#     no contents, so plain `-O binary` is already correct. Applying the NS
#     section list here DROPS .data, the veneers and the three `.pqsigner.*`
#     provenance sections — about 11 KB.
#
# An image missing .data boots with garbage statics; one missing .gnu.sgstubs
# cannot service a single NS->S call. Neither failure announces itself: the
# flash verifies fine, because the device faithfully stores the wrong bytes.
# The observed symptom was a dark panel, which was then very nearly attributed
# to an unrelated firmware change under test.
#
# So this script does not hard-code either recipe. It selects sections by
# ADDRESS — every section with CONTENTS+ALLOC whose LMA lands in flash — which
# is the actual property that matters and is the same rule in both worlds.
# Naming sections was what made the two recipes diverge in the first place.
#
# It then GUARDS the result: the output must be exactly as large as the ELF's
# own flash span. That is a property of the file rather than of the recipe, so
# a dropped section is caught no matter where it happens.
#
# Note the rejected discriminator "does the ELF have a RAM LOAD segment": BOTH
# worlds do (secure's is .bss at 0x3000_2928), so it selects nothing.
#
# Usage:  tools/elf-to-bin.sh <elf> <out.bin>
set -euo pipefail

ELF=${1:?usage: $0 <elf> <out.bin>}
OUT=${2:?usage: $0 <elf> <out.bin>}
OBJCOPY=${OBJCOPY:-arm-none-eabi-objcopy}
OBJDUMP=${OBJDUMP:-arm-none-eabi-objdump}
READELF=${READELF:-arm-none-eabi-readelf}

# Flash starts here; anything at or above RAM_BASE is not part of the image.
FLASH_MAX=0x20000000

# Sections with CONTENTS+ALLOC, non-empty, LMA below RAM. `.bss`/`.uninit`
# have no CONTENTS and drop out; secure's `.data` (LMA in flash, VMA in RAM)
# correctly stays in. Parsed in python because mawk has no `strtonum`.
read -r LO HI SECTIONS < <("$OBJDUMP" -h "$ELF" | python3 -c '
import re, sys
lines = sys.stdin.read().splitlines()
lo, hi, names = None, 0, []
for i, l in enumerate(lines):
    m = re.match(r"\s+\d+\s+(\S+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)", l)
    if not m:
        continue
    name, size, lma = m.group(1), int(m.group(2), 16), int(m.group(3), 16)
    flags = lines[i + 1] if i + 1 < len(lines) else ""
    if "CONTENTS" not in flags or "ALLOC" not in flags:
        continue
    if size == 0 or lma >= 0x20000000:
        continue
    lo = lma if lo is None else min(lo, lma)
    hi = max(hi, lma + size)
    names.append(name)
print(lo or 0, hi, ",".join(names))
')
SPAN=$((HI - LO))
[ -n "$SECTIONS" ] || { echo "elf-to-bin: $ELF has no loadable flash sections" >&2; exit 1; }

JFLAGS=()
IFS=, read -ra NAMES <<< "$SECTIONS"
for n in "${NAMES[@]}"; do JFLAGS+=(-j "$n"); done

"$OBJCOPY" --gap-fill 0xFF -O binary "${JFLAGS[@]}" "$ELF" "$OUT"

GOT=$(stat -c %s "$OUT")
if [ "$GOT" -ne "$SPAN" ]; then
  echo "elf-to-bin: REFUSING $OUT — it is $GOT B but the ELF's flash span is $SPAN B" >&2
  printf '  (0x%08x .. 0x%08x), selected: %s\n' "$LO" "$HI" "$SECTIONS" >&2
  "$OBJDUMP" -h "$ELF" | grep -E "^ +[0-9]+ " >&2
  rm -f "$OUT"
  exit 1
fi

printf '%s: %d B, span 0x%08x..0x%08x, sections: %s\n' "$OUT" "$GOT" "$LO" "$HI" "$SECTIONS"
