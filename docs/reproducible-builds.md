# Reproducible builds

## Why

Every shipped PQSigner firmware image carries an 8-BIP-39-word **measurement**
that the device displays at boot and on every firmware-update confirmation.
The whole authenticity story rests on anyone being able to re-derive those
words from the source tree and check that they match what the vendor
published — without that property the measurement is just a vendor
attestation, not an independently verifiable fingerprint.

Reproducibility is what makes the measurement a fingerprint rather than a
claim.

## What the build guarantees

Two independent clean builds of the same git commit, when run inside
the pinned Nix flake, produce **byte-for-byte identical** `secure.elf`
and `nonsecure.elf` on the same host architecture, and (per the CI
matrix) byte-identical thumbv8m output across host architectures too.
This means:

- `./measure.sh` (or `nix run .#measure`) prints the same 8 words on
  every supported host for a given commit.
- A vendor-signed release bundle (`.pqfw`) can be audited by anyone:
  rebuild the commit the vendor points to, run `./measure.sh`, and
  confirm the words match `measurement.txt` in the bundle.
- The FSBL's check `sha256(active_slot) == manifest.secure_hash`
  behaves identically on any hardware running any build of the same
  commit.

## What it requires

- **Pinned Rust toolchain**: `rust-toolchain.toml` pins
  `nightly-2026-04-06` with `thumbv8m.main-none-eabi` target and the
  `rust-src` + `llvm-tools` components. Every machine that builds
  releases must honour this (`rustup` does it automatically when the
  file is present).
- **Locked dependencies**: `Cargo.lock` is committed; all crates-io
  dependencies are pinned to exact versions. Any git dependency is
  pinned by commit hash (see `secure/Cargo.toml`'s `tropic01` entry).
- **Single-codegen-unit release profile**: `[profile.release]
  codegen-units = 1, lto = true` in the workspace `Cargo.toml` (already
  present before this work).
- **Path-remapped debug info + stripped build-id**: the Makefile's
  `REPRO_FLAGS` variable adds `--remap-path-prefix` for `$HOME/.cargo`,
  `$HOME/.rustup`, and `$CURDIR`, plus `-C link-arg=--build-id=none`.
  Both linker flags are fed to `arm-none-eabi-ld` directly (no `-Wl,`
  wrapper — the Rust linker driver invokes ld directly, not via gcc).
- **Deterministic build scripts**: `secure/build.rs` and
  `nonsecure/build.rs` were audited for non-determinism (timestamps,
  random IDs, directory iteration order) — none found. The QR-code
  generator pins a literal URL constant.
- **`SOURCE_DATE_EPOCH`**: exported from `git log -1 --format=%ct` by
  the Makefile, for any future build script that embeds a timestamp.
  Currently unused but the knob is wired up.

## Cross-platform reproducibility via Nix

The pinned `flake.nix` at the repo root is the canonical way to get the
same toolchain closure on every supported host: Linux x86_64, Linux
aarch64, macOS Intel, macOS Apple Silicon, and WSL2. It pins:

- `nixpkgs` to a specific commit (gives identical `gcc-arm-embedded` /
  `gnumake` / `coreutils` everywhere).
- `rust-overlay`, which reads `rust-toolchain.toml` directly so the
  channel + target + components stay in lockstep with the rustup-driven
  workflow.

`flake.lock` is committed and contains SHA-256 hashes for every input;
`nix run .#measure` against a given commit produces the same closure on
any host that can run Nix. The wrapper script (`./measure.sh`) installs
Nix via the Determinate Systems installer if it is missing.

Within a single host architecture the resulting `secure.elf` is
formally byte-identical (Cargo.lock-pinned deps + content-addressed
toolchain). Across host architectures (e.g. macOS aarch64 vs Linux
x86_64), byte-identity for thumbv8m output is empirically very likely
because the cross-compile path through LLVM is mostly deterministic,
but it rests on LLVM's cross-target codegen behaviour rather than a
formal guarantee. The CI matrix (Linux x86_64, Linux aarch64, macOS
Intel, macOS Apple Silicon) verifies this on every commit; a mismatch
there is a release blocker.

## The reproducibility gate

```
make verify-repro
```

Runs two isolated clean builds (in `target/repro-a/` and `target/repro-b/`)
and diffs the resulting ELFs byte-for-byte. The default feature set
(`FEATURES?=mock-se,debug-log,ui-semihosting`) is used; override via

```
make verify-repro FEATURES=stm32u585,se050,optiga-trust-m,dual-se,ui-oled
```

to check the production feature matrix.

**CI runs `verify-repro` on every PR.** A PR that breaks reproducibility
must be either fixed or explicitly marked "deliberately non-reproducible"
(which would almost always indicate a leak of build-host state into the
firmware and should be rejected).

## Release pipeline

```
make release RELEASE_FEATURES=stm32u585,se050,optiga-trust-m,dual-se,ui-oled
```

`make release` runs `verify-repro` first, then copies the verified ELFs to
`target/release/` and prints the secure + nonsecure measurement words.
These words feed directly into `fwsign sign` as the expected-measurement
payload committed inside the signed manifest.

## Independent verification workflow

A non-developer who wants to confirm the firmware on their device matches
the published source needs exactly two commands:

```
git clone https://github.com/<vendor>/sphincs_rust.git
cd sphincs_rust && git checkout <commit-from-release>
./measure.sh
```

`./measure.sh` installs Nix on first run (via the Determinate Systems
installer — Linux, macOS, WSL2 all use the same one-line invocation),
then runs `nix run .#measure` against the pinned flake. The 8 BIP-39
words it prints must match what the device's OLED shows at boot. They
must also match `measurement.txt` inside the released `.pqfw` bundle.

For deeper auditing — comparing both `secure.elf` and `nonsecure.elf`
byte-for-byte against the bundle, not just their measurement words —
the same hermetic environment is available via:

```
./measure.sh --shell           # drops into nix develop
make release RELEASE_FEATURES=stm32u585,se050,optiga-trust-m,dual-se,ui-oled
fwsign verify-release path/to/release.pqfw target/release/
```

A mismatch at any step means the bundle does not correspond to the source
tree the vendor claims it does. Do **not** load such a bundle on a device.

## Known non-goals

- **Vendored dependencies** (offline / air-gap builds): `Cargo.lock`
  pins every crates.io dep by SHA-256 and the one git dep (`tropic01`)
  by 40-char rev, so the build is bit-reproducible given `crates.io`
  reachability. For true air-gap audit support, `cargo vendor` (or
  crane-driven Nix vendoring) committed to the repo is the follow-up.
- **Native Windows builds**: use WSL2. The Nix flake works inside WSL2
  identically to native Linux; targeting native Windows would require a
  separate toolchain story with no benefit for measurement verification.

## Troubleshooting a reproducibility failure

If `make verify-repro` fails:

1. Run with `VERBOSE=1` to see full cargo logs.
2. Use `diffoscope` on the two ELFs to locate the diverging bytes.
3. Common culprits and fixes:
   - **Random symbol ordering** from multiple codegen units: LTO is on
     and `codegen-units = 1` is set. If somehow disabled, check the
     release profile in `Cargo.toml`.
   - **Absolute path leak**: something is embedding a path that
     `REPRO_REMAP` doesn't cover. Extend `REPRO_REMAP` in the Makefile.
   - **Timestamp in a build script**: check `build.rs` files under
     `secure/`, `nonsecure/`, `shared/` for `SystemTime`,
     `chrono::Utc::now`, etc. None exist today; a regression would be
     caught here.
   - **`env!("OUT_DIR")` embedded in a release binary**: would leak a
     per-build hash. Search `rg 'env!\("OUT_DIR"\)'` in the secure and
     nonsecure trees — any hit is a potential regression.
   - **File iteration order** in a build script: if a build script
     walks a directory, sort the results.

The build is reproducible today. Keeping it reproducible is an
invariant; any PR that breaks `verify-repro` is a bug.
