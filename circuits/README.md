# Circuits — ZK clear-signing source tree

This directory holds the Circom sources for every Groth16 verification
key used by the firmware's `CMD_CLEAR_SIGN` path. The host-side build
pipeline (`tools/build_vks.sh`) compiles these sources into the
960-byte `.vk.bin` files under `secure/data/vks/`, which `dbgen` then
folds into the Merkle-rooted VK DB consumed by the secure world.

```
                       ┌────────────────────┐
   .circom sources ───►│ tools/build_vks.sh │───► secure/data/vks/*.vk.bin
                       └────────────────────┘                │
                                                             ▼
                                              ┌────────────────────────┐
                                              │ cargo run -p dbgen     │
                                              └────────────────────────┘
                                                             │
                                                             ▼
                                       nonsecure/src/vk_db.bin  +
                                       secure/src/db_roots.rs (Merkle root)
```

`tools/build_vks.sh` is **opt-in**. `cargo run -p dbgen` does NOT
shell out to Node, circom, or snarkjs — it only consumes whatever
`.vk.bin` files happen to be sitting in `secure/data/vks/`. A clean
clone with cargo only can rebuild the firmware DB from the committed
binaries; the circuit toolchain is only needed when adding or
regenerating a circuit.

## Layout

| Path                            | Role                                            |
|---------------------------------|--------------------------------------------------|
| `circuits.json`                 | Single manifest. One row per circuit.           |
| `package.json`                  | Pinned npm deps (snarkjs, circomlib, ...).      |
| `.tool-versions`                | asdf/mise pins for `nodejs`, `circom`.          |
| `ptau.lock`                     | SHA-pinned powers-of-tau file (BLS12-381 pot14).|
| `UPSTREAM.md`                   | Provenance for circuits copied from upstream.    |
| `aave_v3/`                      | Aave V3 Pool clear-signing circuit (4 actions).  |
| `scripts/vk_json_to_bin.js`     | snarkjs `vk.json` → 960-byte BLS12-381 binary.   |
| `node_modules/`                 | Installed by `npm ci --prefix circuits`. Ignored.|

## Trust note

Trust in any VK ultimately comes from the firmware-signing key — that
key is the only thing the wallet relies on. **There is no on-chain
anchoring anywhere in this project**: the wallet trusts its own
`VK_DB_ROOT` and the firmware-signing key, full stop.

### Reproducibility model

snarkjs 0.7.4's `zkey contribute` is NOT deterministic even when you
pin the entropy via `-e=<hex>`: three runs with identical inputs
produce three different zkeys (verified empirically). We work
around this by treating the `circuit_final.zkey` itself as the
committed source of truth: every circuit ships a
`circuit_final.zkey` next to its `circuit.circom`. `tools/build_vks.sh`
auto-detects this file and extracts the VK from it directly,
skipping the (non-deterministic) compile + setup + contribute
pipeline. The `.vk.bin` output is then byte-stable across any
developer running the script.

This means authoring a new circuit has two phases:

1. **Initial build** — no committed zkey exists yet. Run
   `tools/build_vks.sh <id>`; the script warns loudly, runs the
   full pipeline, and deposits a fresh `circuit_final.zkey` at
   `build/circuits/<id>/circuit_final.zkey`. Review the VK and the
   constraint count, then copy the zkey into
   `circuits/<protocol>/<action>/circuit_final.zkey` and `git add`
   it. From this point on, that zkey is the pin.
2. **Subsequent rebuilds** — the committed zkey exists. The script
   picks it up automatically and produces a byte-identical
   `.vk.bin`. No circom invocation; no setup; no contribute.

The `contribution.seed` files stay as a best-effort audit record
("this 32-byte entropy was passed to snarkjs for the initial
contribute"), but they do NOT guarantee byte stability on their
own — only the committed `circuit_final.zkey` does.

If snarkjs ever makes `zkey contribute` deterministic, we can drop
the committed zkeys and pin via the seed alone.

## Adding a new protocol

1. Read `UPSTREAM.md` if you are bringing in third-party Circom code.
2. Create `circuits/<protocol>/<circuit>/` and write `circuit.circom`
   plus any helper templates. For circuits that share infrastructure
   with the Aave V3 work, you can `include "../../aave_v3/...";`
   directly — the include resolver is happy across siblings.
3. `head -c 32 /dev/urandom > circuits/<protocol>/<circuit>/contribution.seed`
   and `git add` it. This is the entropy pin for the deterministic
   phase-2 zkey contribution.
4. Add a row to `circuits.json` with `id`, `src`, `domain`, `out`,
   `n_public`. The `domain` field tells the build script which public
   input layout to expect (`poseidon_calldata` for the Aave-style
   circuits today; `eip712_digest` lands in M4).
5. Add a corresponding row to `secure/data/vks.json` (`protocol`,
   `vk_file`, `deployments`). The `vk_file` MUST equal the `out`
   field in `circuits.json`.
6. `tools/build_vks.sh <id>` to build just this circuit while
   iterating.
7. `cargo run -p dbgen` to regenerate `nonsecure/src/vk_db.bin`,
   `secure/src/db_roots.rs`, and `secure/data/vks.review.txt`.
8. `make e2e` to run the QEMU end-to-end test against the new entry.

## Toolchain installation

The script needs `circom 2.1.9`, `node 22.x`, and `snarkjs` (pulled
in via `package.json`). Recommended setup with `mise` or `asdf`:

```sh
cd circuits
mise install            # honours .tool-versions
npm ci                  # installs snarkjs + circomlib + ...
```

If you cannot use `mise` / `asdf`, install circom from source per
upstream instructions (`cargo install --git https://github.com/iden3/circom`)
and run `npm ci --prefix circuits` from the repo root.
