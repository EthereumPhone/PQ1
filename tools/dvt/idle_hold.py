#!/usr/bin/env python3
"""Watch the `idle-hold-test` NS fixture over SWD (DVT row 13.10).

    tools/dvt/idle_hold.py --ns-elf <NS ELF> --s-elf <secure ELF> [--secs 420] [--every 5] [--out log.jsonl]

Every `--every` seconds, reads (core running, no halt) the NS report block
`IHT`, the `.uninit` boot counter `IHT_BOOTS`, and on the secure side the
`pin_verified` pair inside `STATE`, `HANDLER_DEPTH`, the tick pair and
`LAST_ACTIVITY`, and the IWDG `BUSY_TICKS` / `STALL_TICKS`. One JSON line per
sample, plus a summary row on stdout.

`pin_verified` is a FihBool pair: TRUE = (0x1AAAAAAA, 0xE5555555),
FALSE = (0x15555555, 0xEAAAAAAA). `STATE` is not repr(C), so the pair is found
by scanning the whole static.
"""
import argparse
import json
import subprocess
import tempfile
import time

TRUE = (0x1AAAAAAA, 0xE5555555)
FALSE = (0x15555555, 0xEAAAAAAA)
PHASE = {0: "-", 1: "started", 2: "PARKED", 3: "park done", 4: "returned", 5: "sampling",
         0xE1: "addr fail"}


def syms(elf):
    out = subprocess.run(["arm-none-eabi-nm", "-C", "-S", elf], check=True, capture_output=True,
                         text=True).stdout
    d = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) == 4:
            d.setdefault(p[3], (int(p[0], 16), int(p[1], 16)))
    return d


def find(d, suffix):
    hits = [v for k, v in d.items() if k == suffix or k.endswith("::" + suffix)]
    if len(hits) != 1:
        raise SystemExit(f"symbol {suffix}: {len(hits)} matches")
    return hits[0]


def read_words(chip, addr, n):
    with tempfile.TemporaryDirectory() as td:
        path = f"{td}/w.bin"
        r = subprocess.run(["probe-rs", "read", "b32", hex(addr), str(n), "--chip", chip, "--output",
                            path, "--format", "binary"], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return None
        b = open(path, "rb").read()
    return [int.from_bytes(b[i:i + 4], "little") for i in range(0, len(b), 4)]


def pin_state(words):
    pairs = list(zip(words, words[1:]))
    if TRUE in pairs:
        return "UNLOCKED"
    if FALSE in pairs:
        return "locked"
    return "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ns-elf", required=True)
    ap.add_argument("--s-elf", required=True)
    ap.add_argument("--chip", default="STM32U585CIUx")
    ap.add_argument("--secs", type=float, default=420)
    ap.add_argument("--every", type=float, default=5)
    ap.add_argument("--out")
    a = ap.parse_args()
    ns, s = syms(a.ns_elf), syms(a.s_elf)
    iht, boots = find(ns, "IHT"), find(ns, "IHT_BOOTS")
    state = find(s, "nsc::state::STATE")
    depth = find(s, "nsc::HANDLER_DEPTH")
    ticks, last = find(s, "timeout::TICKS"), find(s, "timeout::LAST_ACTIVITY")
    busy, stall = find(s, "hw::iwdg::BUSY_TICKS"), find(s, "hw::iwdg::STALL_TICKS")
    out = open(a.out, "a") if a.out else None
    t0 = time.time()
    print(" t(s) | phase     | park_ms | bumps | st | unl0 unl1 | since_ret | smp | first_lock | boots | S pin    | depth | idle_ms | busy  | stall")
    while time.time() - t0 < a.secs:
        rec = {"t": round(time.time() - t0, 1)}
        w = read_words(a.chip, iht[0], 16)
        b = read_words(a.chip, boots[0], 2)
        st = read_words(a.chip, state[0], max(2, state[1] // 4))
        dp = read_words(a.chip, depth[0], 1)
        tk = read_words(a.chip, ticks[0], 1)
        la = read_words(a.chip, last[0], 1)
        bu = read_words(a.chip, busy[0], 1)
        sl = read_words(a.chip, stall[0], 1)
        if None in (w, b, st, dp, tk, la, bu, sl):
            rec["err"] = "read failed"
            print(f"{rec['t']:5} | read failed")
        else:
            rec.update(iht=w, boots=b, pin=pin_state(st), depth=dp[0], ticks=tk[0], last=la[0],
                       idle_ms=(tk[0] - la[0]) & 0xFFFFFFFF, busy=bu[0], stall=sl[0])
            fl = "-" if w[11] == 0xFFFFFFFF else w[11]
            print(f"{rec['t']:5} | {PHASE.get(w[1], hex(w[1])):9} | {w[2]:7} | {w[3]:5} | {w[4]:2} | "
                  f"{w[5]:4} {w[6]:4} | {w[9]:9} | {w[12]:3} | {fl!s:10} | {b[1]:5} | {rec['pin']:8} | "
                  f"{dp[0]:5} | {rec['idle_ms']:7} | {bu[0]:5} | {sl[0]}", flush=True)
        if out:
            out.write(json.dumps(rec) + "\n")
            out.flush()
        time.sleep(max(0.0, a.every - ((time.time() - t0) % a.every)))


if __name__ == "__main__":
    main()
