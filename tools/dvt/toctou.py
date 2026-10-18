#!/usr/bin/env python3
"""Read the `toctou-test` NS runner's results over SWD (DVT row 3.11).

    tools/dvt/toctou.py --ns-elf <NS ELF> --dir <output dir>

Waits for the three signs, saves each response as <dir>/toctou_resp_<phase>.bin,
prints the interference counters, and runs tools/verify-c10-sig on the three
responses (it checks the ORIGINAL transaction verifies and the alternate one
does not). PASS when all three signs returned 0, the ISR phase flipped the
buffer, the DMA phase saw both patterns in the buffer during the call, and
the verifier passes on responses 0-2. Response 3 (DMA racing the entry copy)
is verified and printed but not judged.
"""
import argparse, os, subprocess, sys, time

PHASES = ["baseline", "ISR flips", "GPDMA loop", "DMA pre-entry"]
RESP_LEN = 4148


def syms(elf):
    out = subprocess.run(["arm-none-eabi-nm", elf], check=True, capture_output=True, text=True).stdout
    return {p[2]: int(p[0], 16) for p in (l.split() for l in out.splitlines()) if len(p) == 3}


def rw(chip, addr, n, tries=5):
    for _ in range(tries):
        r = subprocess.run(["probe-rs", "read", "--chip", chip, "b32", hex(addr), str(n)],
                           capture_output=True, text=True)
        w = r.stdout.split()
        if r.returncode == 0 and len(w) == n:
            return [int(x, 16) for x in w]
        time.sleep(1)
    raise SystemExit(f"SWD read of {addr:#x} failed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ns-elf", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--chip", default="STM32U585CIUx")
    ap.add_argument("--timeout", type=float, default=240)
    a = ap.parse_args()
    s = syms(a.ns_elf)
    t0 = time.time()
    while True:
        hdr = rw(a.chip, s["TOCTOU_HDR"], 4)
        if hdr[0] == 0x70C70311 and hdr[1] == len(PHASES):
            break
        if time.time() - t0 > a.timeout:
            raise SystemExit(f"timeout: hdr={[hex(x) for x in hdr]}")
        time.sleep(3)
    print(f"hdr magic={hdr[0]:#x} done={hdr[1]} unlocked={hdr[2]} PRIVCFGR={hdr[3]:#x}")
    res = rw(a.chip, s["TOCTOU_RES"], 8 * len(PHASES))
    ok = True
    for p, name in enumerate(PHASES):
        st, ms, flips, so, sa, sx, csr, ticks = res[8 * p:8 * p + 8]
        print(f"{p} {name:11} status={st} ms={ms} ticks={ticks} isr_flips={flips} "
              f"samples orig/alt/other={so}/{sa}/{sx} dma_csr={csr:#010x}")
        ok &= st == 0
        if p == 1:
            ok &= flips > 100
        if p in (2, 3):
            ok &= so > 0 and sa > 0
    words = (RESP_LEN + 3) // 4
    paths = []
    for p in range(len(PHASES)):
        w = rw(a.chip, s["TOCTOU_RESP"] + p * RESP_LEN, words)
        b = b"".join(x.to_bytes(4, "little") for x in w)[:RESP_LEN]
        path = os.path.join(a.dir, f"toctou_resp_{p}.bin")
        open(path, "wb").write(b)
        paths.append(os.path.abspath(path))
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    env = {k: v for k, v in os.environ.items() if k != "RUSTFLAGS"}
    r = subprocess.run(["cargo", "run", "--quiet", "--locked", "--release", "--manifest-path",
                        os.path.join(root, "tools/verify-c10-sig/Cargo.toml"), "--"] + paths[:3], env=env)
    ok &= r.returncode == 0
    print("\n==> phase 3 (DMA racing the entry copy; informational, expected to verify over neither):")
    subprocess.run(["cargo", "run", "--quiet", "--locked", "--release", "--manifest-path",
                    os.path.join(root, "tools/verify-c10-sig/Cargo.toml"), "--", paths[3]], env=env)
    print("VERDICT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


main()
