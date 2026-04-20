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

Two independent clean builds of the same git commit on the same host
architecture produce **byte-for-byte identical** `secure.elf` and
`nonsecure.elf`. This means:

- `make measure` prints the same 8 words on every machine for a given
  commit.
- A vendor-signed release bundle (`.pqfw`) can be audited by anyone: rebuild
  the commit the vendor points to, run `make measure`, and confirm the
  words match `measurement.txt` in the bundle.
- The FSBL's check `sha256(active_slot) == manifest.secure_hash` behaves
  identically on any hardware running any build of the same commit.

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

Auditors and security researchers verify a `.pqfw` bundle like this:

1. Install the pinned Rust toolchain:
   ```
   rustup default nightly-2026-04-06
   rustup target add thumbv8m.main-none-eabi
   rustup component add rust-src llvm-tools
   apt install gcc-arm-none-eabi   # for arm-none-eabi-ld
   ```
2. Clone the repo at the exact commit referenced by the release:
   ```
   git clone https://github.com/<vendor>/sphincs_rust.git
   cd sphincs_rust
   git checkout <commit-from-bundle>
   ```
3. Build reproducibly:
   ```
   make release RELEASE_FEATURES=stm32u585,se050,optiga-trust-m,dual-se,ui-oled
   ```
4. Compare the printed measurement words against `measurement.txt` inside
   the `.pqfw` bundle.
5. Compare the ELFs against the `secure.bin` / `nonsecure.bin` in the
   bundle after converting ELF → flat image (the `fwsign verify`
   sub-command does this check automatically).

A mismatch at any step means the bundle does not correspond to the source
tree the vendor claims it does. Do **not** load such a bundle on a device.

## Known non-goals

- **Cross-architecture reproducibility** (Apple Silicon vs x86_64 host):
  identical ELFs across different host CPUs are not currently guaranteed.
  The Rust toolchain's codegen is deterministic per target triple but
  LLVM itself has been known to produce slightly different output across
  host architectures in edge cases. The vendor build farm pins one host
  architecture (Linux x86_64) for official releases; auditors should use
  the same to compare byte-exact. Cross-architecture repro is a tracked
  follow-up.
- **Vendored dependencies** (offline builds): not committed today.
  Releases fetch from `crates.io` using `Cargo.lock` pins, which is
  bit-reproducible given `crates.io` stability. For true air-gap audit
  support, `cargo vendor` committed to the repo is the follow-up.
- **Docker-pinned build environment**: nice-to-have for reproducibility
  across Linux distributions; not currently part of the release
  pipeline. A `Dockerfile` plus `hadolint`'d base image is the intended
  follow-up.

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
