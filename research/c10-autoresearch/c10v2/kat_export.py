#!/usr/bin/env python3
"""kat_export.py IN.json TAG — turn c10v2_ref.py's KAT JSON into the files the
Rust and Solidity tests read:

  c10v2/kat-v2-TAG.txt        sk pk_seed pk_root msg sig   (one vector per line)
  c10v2/nearmiss-v2-TAG.txt   kind pk_seed pk_root msg sig (kind has no spaces)
  contracts/smart-wallet/test/c10v2_kat_vectors.json      (v0.., n0.., spec)   TAG = draft03
  contracts/smart-wallet/test/c10v2_kat_vectors_TAG.json  (same shape)         any other TAG

Research only (#1155).
"""
import json
import os
import sys

src, tag = sys.argv[1], sys.argv[2]
here = os.path.dirname(os.path.abspath(__file__))
d = json.load(open(src))
pad = lambda h: "0x" + h + "0" * (64 - len(h))

with open(os.path.join(here, f"kat-v2-{tag}.txt"), "w") as f:
    for v in d["vectors"]:
        f.write(" ".join((v["sk_seed"], v["pk_seed"], v["pk_root"], v["msg"], v["sig"])) + "\n")

with open(os.path.join(here, f"nearmiss-v2-{tag}.txt"), "w") as f:
    for v in d["plus_c_near_misses"]:
        f.write(" ".join((v["kind"].replace(" ", ""), v["pk_seed"], v["pk_root"], v["msg"], v["sig"])) + "\n")

forge = {}
for i, v in enumerate(d["vectors"]):
    forge[f"v{i}"] = dict(pkSeed=pad(v["pk_seed"]), pkRoot=pad(v["pk_root"]), message="0x" + v["msg"],
                          signature="0x" + v["sig"])
for i, v in enumerate(d["plus_c_near_misses"]):
    forge[f"n{i}"] = dict(kind=v["kind"], pkSeed=pad(v["pk_seed"]), pkRoot=pad(v["pk_root"]),
                          message="0x" + v["msg"], signature="0x" + v["sig"])
forge["spec"] = d["spec"]
# Only draft 0.3 owns the plain name; variants must never overwrite it.
fname = "c10v2_kat_vectors.json" if tag == "draft03" else f"c10v2_kat_vectors_{tag}.json"
out = os.path.join(here, "..", "..", "..", "contracts", "smart-wallet", "test", fname)
with open(out, "w") as f:
    json.dump(forge, f, indent=1)
print(f"{len(d['vectors'])} KATs, {len(d['plus_c_near_misses'])} near-misses -> {tag}")
