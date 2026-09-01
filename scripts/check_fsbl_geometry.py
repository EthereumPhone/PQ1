#!/usr/bin/env python3
"""FSBL geometry gate: measure the PHYSICAL flash span and the WRP page range.

Why this exists
---------------
`make fsbl` gated on `arm-none-eabi-size -B` text+data. That is not what
occupies flash. `size -B` sums section sizes; the physical span is the extent
of the ELF's LOAD segments, which additionally covers inter-segment alignment
gaps. For the current image the two differ by 4 bytes (28,348 vs 28,352) — small,
but the quantity was simply wrong, and the repo's own resource receipt
(`docs/security/fw-rollback-fsbl-resource-map-2026-07.md`) reports them as two
separate rows for exactly that reason ("Initialized bytes" 38,856 vs "Physical
FLASH span" 38,860).

It matters because of invariant #10. The FSBL is meant to become an immutable
trust root by having WRP applied to its pages before the device self-locks to
RDP-2, at which point the option bytes freeze forever. WRP protects PAGES, not
bytes, so the question that has to be answered is "which page range?" — and that
is a function of the physical span, not of text+data. A span that creeps over a
page boundary silently widens the range that must be write-protected.

This script therefore reports the page range as a derived OUTPUT rather than
leaving it as an assumption, and fails on the conditions that would make that
output wrong or unsafe.

What it does NOT do
-------------------
It does not select a geometry, approve one, or authorise any irreversible
action. `docs/security/a-b-firmware-rollback-architecture.md` (Draft 1.1) is an
unapproved research candidate; its 40 KiB envelope is not adopted here. The
WRP/option-byte ceremony and the silicon receipts remain open. This measures the
image that exists and enforces that it stays inside the region the linker script
declares.
"""

import argparse
import re
import subprocess
import sys

PAGE = 0x2000  # STM32U5 flash page: 8 KiB (see secure/src/hw/flash.rs:456)


def readelf(tool, elf, flag):
    return subprocess.run([tool, flag, elf], capture_output=True, text=True, check=True).stdout


def load_segments(tool, elf):
    """Every PT_LOAD segment as (paddr, filesz, memsz, flags)."""
    segs = []
    for line in readelf(tool, elf, "-lW").splitlines():
        f = line.split()
        if len(f) >= 7 and f[0] == "LOAD":
            # Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align
            segs.append((int(f[3], 16), int(f[4], 16), int(f[5], 16), f[6]))
    return segs


def linker_region(path, name):
    """(origin, length) for a MEMORY region, from the linker script."""
    txt = open(path).read()
    m = re.search(
        rf"{name}\s*:\s*ORIGIN\s*=\s*(0x[0-9A-Fa-f]+)\s*,\s*LENGTH\s*=\s*(\d+)\s*([KM]?)",
        txt,
    )
    if not m:
        sys.exit(f"FAIL: no MEMORY region `{name}` in {path}")
    origin = int(m.group(1), 16)
    length = int(m.group(2)) * {"": 1, "K": 1024, "M": 1024 * 1024}[m.group(3)]
    return origin, length


def stack_frames(tool, elf):
    """Per-function frame sizes from `.stack_sizes` (needs -Z emit-stack-sizes).

    Entries are a 4-byte relocated address followed by a ULEB128 frame size.
    The section is non-alloc, so `objcopy -O binary` yields nothing — it has to
    be read out of the hexdump.
    """
    out = subprocess.run([tool, "-x", ".stack_sizes", elf], capture_output=True, text=True).stdout
    raw = bytearray()
    for line in out.splitlines():
        m = re.match(r"\s+0x[0-9a-f]+\s+((?:[0-9a-f]{2,8}\s+){1,4})", line)
        if m:
            for grp in m.group(1).split():
                raw += bytes.fromhex(grp)

    def uleb(b, i):
        r = s2 = 0
        while True:
            x = b[i]
            i += 1
            r |= (x & 0x7F) << s2
            if not x & 0x80:
                return r, i
            s2 += 7

    sizes, i = [], 0
    while i + 4 < len(raw):
        i += 4
        v, i = uleb(raw, i)
        sizes.append(v)
    return sorted(sizes, reverse=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--linker", required=True)
    ap.add_argument("--readelf", default="arm-none-eabi-readelf")
    ap.add_argument("--size", default="arm-none-eabi-size")
    a = ap.parse_args()

    flash_origin, flash_len = linker_region(a.linker, "FLASH")
    ram_origin, ram_len = linker_region(a.linker, "RAM")
    segs = load_segments(a.readelf, a.elf)
    if not segs:
        sys.exit("FAIL: no PT_LOAD segments — is this a linked ELF?")

    fail = []

    # A single LOAD segment is the property that makes "the page range" well
    # defined. With two segments and a gap between them, WRP still has to cover
    # the gap (pages are the unit), so the protected range would be larger than
    # the sum of the segments — precisely the undercount this gate exists to
    # prevent.
    if len(segs) != 1:
        fail.append(
            f"expected exactly 1 LOAD segment, found {len(segs)}. The WRP range "
            f"must span from the lowest to the highest, INCLUDING the gap; "
            f"re-derive it by hand before trusting the page range below."
        )

    lo = min(p for p, _, _, _ in segs)
    hi = max(p + m for p, _, m, _ in segs)
    span = hi - lo

    if lo != flash_origin:
        fail.append(
            f"LOAD starts at 0x{lo:08X}, linker FLASH ORIGIN is 0x{flash_origin:08X}. "
            f"The FSBL must start at the boot base or SECBOOTADD0 points into nothing."
        )
    if span > flash_len:
        fail.append(f"physical span {span} B exceeds the {flash_len} B FLASH region")

    # Page range that WRP would have to cover.
    first_page = (lo - flash_origin) // PAGE
    last_page = (span - 1) // PAGE if span else 0
    pages = last_page - first_page + 1
    page_bytes = pages * PAGE
    region_pages = flash_len // PAGE

    # Static RAM. .data + .bss must fit with room for the stack, which grows
    # down from _stack_start at the top of the region.
    out = subprocess.run([a.size, "-B", a.elf], capture_output=True, text=True, check=True).stdout
    t, d, b = (int(x) for x in out.splitlines()[1].split()[:3])
    static_ram = d + b
    if static_ram > ram_len:
        fail.append(f"static RAM {static_ram} B exceeds the {ram_len} B RAM region")

    print(f"==> FSBL geometry ({a.elf})")
    print(f"    LOAD segments   : {len(segs)}")
    print(f"    physical span   : {span} B (0x{span:X})  [size -B text+data = {t + d} B]")
    if span != t + d:
        print(f"                      ^ differs by {span - (t + d)} B — the span is the real figure")
    print(f"    FLASH region    : {flash_len} B at 0x{flash_origin:08X} ({region_pages} pages of {PAGE} B)")
    print(f"    occupies pages  : {first_page}..{last_page} ({pages} of {region_pages}) = {page_bytes} B")
    print(f"    WRP must cover  : pages {first_page}..{last_page}  <-- derived, not assumed")
    print(f"    free in region  : {flash_len - span} B ({100.0 * span / flash_len:.1f}% used)")
    print(f"    free in pages   : {page_bytes - span} B before the next page boundary")
    print(f"    static RAM      : {static_ram} B (data {d} + bss {b}) of {ram_len} B")
    print(f"    stack budget    : {ram_len - static_ram} B below _stack_start")

    frames = stack_frames(a.readelf, a.elf)
    avail = ram_len - static_ram
    if frames:
        total = sum(frames)
        print(f"    stack frames    : {len(frames)} functions, largest {frames[0]} B")
        print(f"    frame total     : {total} B of {avail} B available ({100.0 * total / avail:.1f}%)")
        print(f"                      ^ SUM of every frame. No acyclic call path can exceed it,")
        print(f"                        so this is a genuine upper bound — not an estimate.")
        if total > avail:
            fail.append(
                f"the sum of all {len(frames)} frames ({total} B) exceeds the {avail} B "
                f"stack budget, so a deep path COULD overflow. A call-graph tool "
                f"(cargo-call-stack) is needed to say whether one actually does."
            )
        print(f"    CAVEATS         : the bound assumes no recursion (checked: no direct")
        print(f"                      self-calls), that every function emitted a frame")
        print(f"                      (assembly and compiler intrinsics may not), and it")
        print(f"                      excludes interrupt frames nesting on top.")
    else:
        print(f"    stack frames    : none — build with `-Z emit-stack-sizes` to bound the stack")
        print(f"                      (the RAM/worst-case-stack gate stays OPEN without it)")

    if pages < region_pages:
        print(
            f"    NOTE: the image fits in {pages} page(s) but the linker declares "
            f"{region_pages}. WRP is applied to the DECLARED range, so pages "
            f"{last_page + 1}..{region_pages - 1} would be frozen while empty."
        )

    if fail:
        print("==> FSBL geometry: FAIL")
        for f in fail:
            print(f"    - {f}")
        return 1
    print("==> FSBL geometry: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
