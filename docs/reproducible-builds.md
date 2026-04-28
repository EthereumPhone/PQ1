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

### How cross-host byte-identity is enforced

`packages.measure` is **always evaluated as an `x86_64-linux`
derivation**, regardless of the host running `nix build`. Every store
path in the build closure (rustc, arm-none-eabi-ld, glibc, …) hashes
identically on every host because the `system` argument is fixed —
nothing is sourced from the host's nixpkgs view. The build runs offline
inside the Nix sandbox with cargo dependencies vendored via
`rustPlatform.importCargoLock`, so there is no network-mediated source
of variance either. The derivation's output is plain text
(`words.txt`), which any host can `cat` regardless of architecture.

This means:

- **Linux x86_64** hosts build the derivation natively.
- **macOS** (Intel or Apple Silicon) and **Linux aarch64** hosts
  dispatch the build to a remote `x86_64-linux` builder. The
  capability ships with Determinate Nix on Apple Silicon but is **not
  enabled by default** — see the macOS setup section below. On Linux
  aarch64 a remote `x86_64-linux` builder must be configured
  separately (or `binfmt_misc` + `qemu-user` for transparent
  emulation).

### macOS setup: enable the linux-builder

On Apple Silicon Macs running Determinate Nix, the linux-builder is a
local VM (Apple Virtualization framework) that the Nix daemon can
delegate `x86_64-linux` builds to. It needs a one-time enablement.

The recommended path is via Determinate's own documentation:
**https://docs.determinate.systems/macos-linux-builder/**

If you use **nix-darwin**, add this to your configuration and run
`darwin-rebuild switch`:

```nix
nix.linux-builder.enable = true;
```

Either way, after enabling, `nix store ping --store
ssh-ng://linux-builder` should succeed and `./measure.sh` can dispatch
the build. The first run downloads + boots the VM and may take a few
minutes; subsequent runs reuse the live VM.

`./measure.sh` pre-flights this configuration and exits with a clear
remediation message if no `x86_64-linux` builder is available, so
users hitting this step do not need to parse the underlying Nix error
output.

Because the derivation closure is byte-identical on every host, the
output (`words.txt`) is byte-identical on every host by construction —
not by empirical observation of LLVM's cross-target codegen. The CI
matrix exists to catch regressions in the closure pinning, not to
discover whether reproducibility happens to hold this week.

### Caveat: the working tree must be committed

The flake measures the **git-committed state** of the repo. If you
have uncommitted modifications or untracked source files, they will
not appear in the sandbox build — `nix run .#measure` will either fail
with "file not found for module …" (if a tracked file references an
untracked one) or silently measure the older committed state. To get
a meaningful measurement you can compare with someone else, commit
your changes first.

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
- **Native Windows builds**: use WSL2. `measure.bat` at the repo root
  dispatches into WSL automatically (after a one-time `wsl --install`
  from an elevated PowerShell). The Nix flake works inside WSL2
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
