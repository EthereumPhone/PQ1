#!/usr/bin/env python3
"""build_options.py — size-vs-gas menu for the v2 0.3 verifier (#1155 gas track, batch 3).

Each option swaps only the generated chain block of src/verifiers/SPHINCsC10v2Asm.sol (the
FORS/Merkle walks stay as committed), then:
  * measures callee-only gas over the 6 KATs and the runtime size, at the default (runs=200)
    and the deploy (runs=999999) profile (C10GasBench.test_gas_v2);
  * runs the v2 equivalence + per-primitive + lanes gates (default profile, 64 fuzz runs), so
    every option in the table is a semantically equivalent candidate, not just a number.
The committed file is restored afterwards (also on error). Prints one markdown row per option.

Usage (worktree root): python3 research/c10-gas/build_options.py [option ...]
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SW = os.path.join(ROOT, "contracts", "smart-wallet")
V2 = os.path.join(SW, "src", "verifiers", "SPHINCsC10v2Asm.sol")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
DB = os.path.expanduser("~/.cache/c10-gas-deploy")
sys.path.insert(0, HERE)
import gen_v2_chains as g  # noqa: E402

OPTIONS = {
    "head": lambda: g.block_bytes(),               # unrolled chains, straight-line 4/2/1 blocks
    "no-blocks": lambda: g.block_bytes_loop(),     # unrolled chains, step loop (HEAD without B4)
    "rolled": lambda: g.block_bytes_rolled(),      # one loop over the chains, step loop
}


def bench(profile):
    cmd = [FORGE, "test", "--match-path", "test/gas/C10GasBench.t.sol", "--match-test", "test_gas_v2", "-vv"]
    env = dict(os.environ)
    if profile == "deploy":
        cmd[2:2] = ["--out", f"{DB}/out", "--cache-path", f"{DB}/cache"]
        env["FOUNDRY_PROFILE"] = "deploy"
    out = subprocess.run(cmd, cwd=SW, env=env, capture_output=True, text=True).stdout
    g_ = re.search(r"GAS v2 callee-only cand min/max (\d+) (\d+)", out)
    s_ = re.search(r"SIZE v2 runtime ref/cand \d+ (\d+)", out)
    if not (g_ and s_):
        raise SystemExit(f"bench failed ({profile}):\n{out[-2000:]}")
    return int(g_.group(1)), int(g_.group(2)), int(s_.group(1))


def gates():
    env = dict(os.environ, FOUNDRY_FUZZ_RUNS="64")
    p = subprocess.run([FORGE, "test", "--match-path", "test/gas/C10*.t.sol", "--match-contract",
                        "^(C10EquivalenceTest|C10PrimitiveTraceTest|C10LanesTest)$", "--match-test", "v2|recorder|anchors|raw|lanes"],
                       cwd=SW, env=env, capture_output=True, text=True)
    return p.returncode == 0


def main():
    sel = sys.argv[1:] or list(OPTIONS)
    orig = open(V2).read()
    rows = []
    try:
        for name in sel:
            open(V2, "w").write(g.splice(orig, OPTIONS[name]()))
            d = bench("default")
            dp = bench("deploy")
            ok = gates()
            rows.append(f"| {name} | {d[0]:,}..{d[1]:,} | {dp[0]:,}..{dp[1]:,} | {d[2]:,} | {dp[2]:,} | "
                        f"{'green' if ok else 'RED'} |")
            print(rows[-1], flush=True)
    finally:
        open(V2, "w").write(orig)
    print("| option | callee gas default | callee gas deploy | size default | size deploy | v2 gates |")
    print("|---|---:|---:|---:|---:|---|")
    print("\n".join(rows))


if __name__ == "__main__":
    main()
