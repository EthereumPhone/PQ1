#!/usr/bin/env python3
"""Read the `gtzc-ship` NS fixture's results over SWD (DVT row 3.2).

    tools/dvt/gtzc_ship.py --ns-elf <NS ELF> [--out results.json]

Per probe: the NS read must be RAZ (0) and raise one TZIC event; a write
probe (NS pre-read, write, post-read) must raise three more, leave the NS
view unchanged, and leave the toggled bit at 0 on the SECURE alias (read
here over SWD). The TZSC SECCFGR words are printed so the receipt shows which
peripherals this image actually secured.
"""
import argparse, json, subprocess, sys, time

NAMES = ["I2C1_CR1", "I2C2_CR1", "I2C4_CR1", "AES_CR", "HASH_CR", "RNG_CR", "PKA_CR", "SAES_CR",
         "TIM2_CR1", "TIM3_CR1", "UCPD1_CFG1", "CRS_CR", "SPI1_IER", "IWDG_PR", "SPI1_CFG1"]
ADDR = [0x40005400, 0x40005800, 0x40008400, 0x420C0000, 0x420C0400, 0x420C0800, 0x420C2000,
        0x420C0C00, 0x40000000, 0x40000400, 0x4000DC00, 0x40006000, 0x40013010, 0x40003004, 0x40013008]
MASK = [1 << 12, 1 << 12, 1 << 12, 1 << 1, 1 << 3, 1 << 3, 1 << 17, 1 << 1, 1 << 7, 1 << 7, 1, 1 << 3, 1, 0, 0]


def syms(elf):
    out = subprocess.run(["arm-none-eabi-nm", elf], check=True, capture_output=True, text=True).stdout
    return {p[2]: int(p[0], 16) for p in (l.split() for l in out.splitlines()) if len(p) == 3}


def rw(chip, addr, n, tries=5):
    """Read n words over SWD as hex text, retrying. (`--format binary` failed with
    SwdApWdataError on GTZC registers that the hex path reads every time.)"""
    for t in range(tries):
        r = subprocess.run(["probe-rs", "read", "--chip", chip, "b32", hex(addr), str(n)],
                           capture_output=True, text=True)
        words = r.stdout.split()
        if r.returncode == 0 and len(words) == n:
            return [int(w, 16) for w in words]
        time.sleep(1)
    raise SystemExit(f"SWD read of {addr:#x} failed {tries} times")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ns-elf", required=True)
    ap.add_argument("--out")
    ap.add_argument("--chip", default="STM32U585CIUx")
    a = ap.parse_args()
    s = syms(a.ns_elf)
    for _ in range(60):
        hdr = rw(a.chip, s["GTZC_SHIP_HDR"], 5)
        if hdr[0] == 0x67520302 and hdr[1] == len(NAMES) and hdr[3]:
            break
        time.sleep(1)
    sec = rw(a.chip, 0x50032410, 3)
    print(f"hdr magic={hdr[0]:#x} done={hdr[1]} tzic baseline={hdr[2]} final={hdr[3]} unlocked={hdr[4]}")
    print(f"TZSC SECCFGR1={sec[0]:#010x} SECCFGR2={sec[1]:#010x} SECCFGR3={sec[2]:#010x}")
    res = rw(a.chip, s["GTZC_SHIP_RES"], 5 * len(NAMES))
    ok, rows, prev = hdr[1] == len(NAMES), [], hdr[2]
    for i, n in enumerate(NAMES):
        v, t_read, pre, post, t_write = res[5 * i:5 * i + 5]
        d_read, d_write = t_read - prev, t_write - t_read
        prev = t_write
        good = v == 0 and d_read == 1
        sa = None
        if MASK[i]:
            sa = rw(a.chip, ADDR[i] | 0x10000000, 1)[0]
            good &= d_write == 3 and (pre ^ post) & MASK[i] == 0 and sa & MASK[i] == 0
        else:
            good &= d_write == 0
        ok &= good
        print(f"{i:2} {n:11} read={v:#010x} tzic+{d_read}" +
              (f"  write: ns pre={pre:#010x} post={post:#010x} tzic+{d_write} S-alias={sa:#010x} bit={'SET' if sa & MASK[i] else 'clear'}"
               if MASK[i] else "") + f"  -> {'ok' if good else 'UNEXPECTED'}")
        rows.append(dict(name=n, read=v, d_read=d_read, pre=pre, post=post, d_write=d_write, s_alias=sa, ok=bool(good)))
    print("VERDICT:", "PASS" if ok else "FAIL")
    if a.out:
        json.dump(dict(hdr=hdr, seccfgr=sec, rows=rows, verdict=bool(ok)), open(a.out, "w"), indent=1)
    sys.exit(0 if ok else 1)


main()
