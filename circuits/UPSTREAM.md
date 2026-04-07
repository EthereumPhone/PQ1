# Upstream provenance

The Aave V3 clear-signing circuit sources under `aave_v3/` are copied
from the ZKNoxHQ ZKlarity reference implementation:

- **Repository:** `https://github.com/ZKNoxHQ/ZKlarity`
- **Source path:** `circuits/`
- **Imported at commit:** `5e8b3f9` ("ledger app binary")
- **Import date:** 2026-04-07
- **License status:** the upstream repository contains **no `LICENSE`
  file** at the time of import. The user has elected to copy the
  sources in-tree with attribution while the licensing question is
  resolved with upstream. Treat this as a TEMPORARY arrangement; if
  upstream publishes an incompatible license later, this directory
  must be removed or relicensed.

## Files imported

| Local path                                          | Upstream path                       |
|-----------------------------------------------------|-------------------------------------|
| `aave_v3/abi_primitives.circom`                     | `circuits/abi_primitives.circom`    |
| `aave_v3/aave_abi_parsers.circom`                   | `circuits/aave_abi_parsers.circom`  |
| `aave_v3/clear_signing_proof.circom`                | `circuits/clear_signing_proof.circom`|
| `aave_v3/formatting.circom`                         | `circuits/formatting.circom`        |
| `aave_v3/string_assembly.circom`                    | `circuits/string_assembly.circom`   |
| `aave_v3/token_registry.circom`                     | `circuits/token_registry.circom`    |

## What was changed during import

- Each file received a per-file attribution header above its
  `pragma circom 2.0.0;` line, citing the upstream repository,
  commit hash, original file path, and the unresolved license note.
- All `include "..."` directives are unchanged: the upstream uses
  `include "../node_modules/...";` from a flat `circuits/` directory,
  and our layout (`sphincs_rust/circuits/aave_v3/file.circom` →
  `sphincs_rust/circuits/node_modules/...`) preserves the same
  one-up relative resolution.
- Sibling includes (`./abi_primitives.circom` etc.) work without
  modification because all six files live in `aave_v3/` together.
- No semantic edits. Compilation must produce a circuit logically
  equivalent to upstream; any divergence is a bug introduced by us
  during the copy and must be fixed before shipping.

## Reproducibility model

Upstream's `Makefile` uses *random* entropy for both the powers-of-tau
contribution and the circuit-specific zkey contribution
(`date +%s%N | sha256sum` and `openssl rand -hex 32`), and snarkjs
0.7.4's `zkey contribute` is also non-deterministic even when you
pin the entropy via `-e=<hex>` (verified empirically: three runs
with identical inputs produce three different zkeys).

Our workaround: the `circuit_final.zkey` file **itself** is
committed in-tree at `circuits/aave_v3/circuit_final.zkey`
(~3.8 MB). `tools/build_vks.sh` auto-detects this file and extracts
the 960-byte VK from it via `snarkjs zkey export verificationkey`
followed by `circuits/scripts/vk_json_to_bin.js`. The zkey is the
canonical pin; the `.vk.bin` output is byte-stable across any
developer running the script.

The committed aave_v3 zkey originated from ZKNoxHQ/ZKlarity commit
`5e8b3f9` — specifically, it was copied from
`/home/markus/Documents/zk_clear_signing/keys/circuit_final.zkey`
on the machine that performed this import. Anyone who wants to
audit the provenance can compare the committed zkey's SHA-256
against that upstream file.

No external sibling-directory dependency: the repo is
self-contained. The `local-fallback` entry in `ptau.lock` only
matters if you are AUTHORING a brand new circuit and running the
full compile + setup + contribute pipeline for the first time;
it's unused by the reproduction path.

## Trust model reminder

Reproducibility of the build is unrelated to the trust model of the
hardware wallet. The wallet trusts whatever VK bytes the
firmware-signing key signs; it does not re-derive the VK at
verification time. The Merkle root in `secure/src/db_roots.rs`
anchors `secure/data/vks/*.vk.bin` to the firmware release, and
that anchor is the entire chain of custody. There is NO on-chain
`clearSigningVKHash` comparison anywhere in this project.
