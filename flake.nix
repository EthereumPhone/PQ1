{
  description = "PQSigner OS — reproducible firmware measurement";

  # Reproducibility model
  # ---------------------
  # The previous version of this flake exposed `nix run .#measure` as a
  # bash wrapper around `make measure`. It pinned its inputs but ran the
  # build with the *host's* rustc + linker — and rust-overlay drops a
  # different prebuilt rustc per host triple, so Linux x86_64 and macOS
  # aarch64 evaluators saw different /nix/store/<hash>-rust-…/ paths.
  # `core` panic messages embed `file!()` strings pointing into the
  # sysroot, so the path leaked into .rodata of the secure ELF and the
  # 8 BIP-39 words diverged across hosts.
  #
  # This flake fixes that by making `measure` an actual Nix derivation
  # that ALWAYS evaluates against `x86_64-linux`, regardless of which
  # host invokes it. Every store path in the build closure (rustc,
  # arm-none-eabi-ld, glibc, …) is byte-identical on every host. The
  # build runs offline in the Nix sandbox with cargo dependencies
  # vendored via `importCargoLock`, so there is no network-mediated
  # source of variance. The derivation's output is plain text
  # (`words.txt`); any host can `cat` it.
  #
  # macOS / Linux aarch64 hosts dispatch the build to a remote
  # x86_64-linux builder. Determinate's installer enables a
  # linux-builder VM by default on Apple Silicon Macs, so this works
  # out of the box for that path. On Linux aarch64 hosts a remote
  # x86_64-linux builder must be configured separately.
  #
  # Verify reproducibility quickly: `nix build .#measure` on any host
  # and compare `result/words.txt` to what the device's OLED shows.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    let
      # Single source of truth for the build platform. Everything in the
      # measurement derivation's closure resolves through this — never
      # through the evaluating host's nixpkgs.
      buildSystem = "x86_64-linux";

      buildPkgs = import nixpkgs {
        system = buildSystem;
        overlays = [ (import rust-overlay) ];
      };

      rustToolchain =
        buildPkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

      # Vendor every cargo dep — crates.io entries from Cargo.lock plus
      # the one git pin (tropic01). Network is unavailable inside the
      # sandbox; cargo reads from $CARGO_HOME/config.toml that points at
      # the vendor directory installed by `cargoSetupHook`.
      cargoVendor = buildPkgs.rustPlatform.importCargoLock {
        lockFile = ./Cargo.lock;
        outputHashes = {
          "tropic01-0.1.0" =
            "sha256-6gGcHgTZyrEK9I4V3cQz9i9IlUDAx2aCr0S40UuHjOg=";
        };
      };

      measureDrv = buildPkgs.stdenv.mkDerivation {
        pname = "pqsigner-measurement";
        version = "0";

        # Use the actual on-disk working tree, not just git-tracked
        # files — measure.sh is meant to be runnable mid-development,
        # before every change has been committed. We still exclude
        # build outputs and editor noise so they don't perturb the
        # source-hash of the derivation.
        src = builtins.path {
          path = ./.;
          name = "pqsigner-source";
          filter = path: type:
            let base = baseNameOf (toString path); in
            !(builtins.elem base [
              "target" "result" ".direnv" ".git" "node_modules"
            ]);
        };

        nativeBuildInputs = [
          rustToolchain
          buildPkgs.gcc-arm-embedded
          buildPkgs.gnumake
          buildPkgs.coreutils
          buildPkgs.gnused
          buildPkgs.gnugrep
          buildPkgs.findutils
          buildPkgs.gawk
          buildPkgs.cacert
          buildPkgs.rustPlatform.cargoSetupHook
        ];

        cargoDeps = cargoVendor;

        # The Makefile's $(CURDIR) and `--remap-path-prefix=$(CURDIR)=...`
        # logic still applies inside the sandbox; the source is unpacked
        # under $NIX_BUILD_TOP/source and that is the working directory
        # mkDerivation hands to buildPhase.
        buildPhase = ''
          runHook preBuild

          # The Makefile reads $(HOME) for HOME-rooted remap rules and
          # falls back to a no-op if HOME is unset, but cargo also wants
          # somewhere writable. Point both at the per-build tmpdir.
          export HOME=$TMPDIR

          # `git log -1 --format=%ct` would fail in the sandbox; the
          # Makefile already accepts SOURCE_DATE_EPOCH from the env, so
          # set it deterministically here. Pre-supplying it stops the
          # `git log || echo 0` shell-out from running at all.
          export SOURCE_DATE_EPOCH=0

          # Run the same target the host workflow uses. Stdout has the
          # 8 numbered word lines; stderr has the SHA-256 + flash range.
          # Capture both so `nix log` shows the full picture.
          make measure 2>&1 | tee make-measure.out

          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall

          mkdir -p $out
          # `fwmeasure` prints "<n> <word>" lines to stdout. Keep just
          # those eight lines as the canonical output; the rest of the
          # build log lives in $out/build.log for transparency.
          ${buildPkgs.gnugrep}/bin/grep -E '^[1-8] [a-z]+' \
            make-measure.out > $out/words.txt
          cp make-measure.out $out/build.log

          runHook postInstall
        '';

        # Output is plain text — no ELF post-processing needed.
        dontStrip = true;
        dontPatchELF = true;
        dontFixup = true;
      };
    in
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ] (hostSystem:
      let
        hostPkgs = import nixpkgs { system = hostSystem; };

        # Host-native wrapper. Just prints the words file from the
        # sandbox-built derivation. The interpolation forces Nix to
        # build (or substitute) `measureDrv` for `buildSystem` first;
        # macOS evaluators dispatch that to their linux-builder.
        showWords = hostPkgs.writeShellApplication {
          name = "pqsigner-measure";
          runtimeInputs = [ hostPkgs.coreutils ];
          text = ''
            cat ${measureDrv}/words.txt
          '';
        };
      in {
        # `nix build .#measure` -> ./result/words.txt (8 BIP-39 words)
        packages.measure = measureDrv;
        packages.default = measureDrv;

        # `nix run .#measure` -> prints the words to stdout
        apps.measure = {
          type = "app";
          program = "${showWords}/bin/pqsigner-measure";
        };
        apps.default = self.apps.${hostSystem}.measure;

        # `nix develop` keeps working for auditors who want to poke at
        # intermediate Makefile targets (verify-repro, release, etc.).
        # Note: building inside this shell uses the host's toolchain
        # closure, NOT the cross-host-pinned `buildSystem` one — so the
        # words it produces will only match the canonical measurement
        # if the host happens to be x86_64-linux. Use `nix build
        # .#measure` for the canonical measurement on any other host.
        devShells.default = hostPkgs.mkShell {
          packages = [
            rustToolchain
            buildPkgs.gcc-arm-embedded
            buildPkgs.gnumake
          ];
          shellHook = ''
            echo "PQSigner reproducible build shell"
            echo "  rustc:        $(rustc --version 2>/dev/null || echo missing)"
            echo "  ld:           $(arm-none-eabi-ld --version 2>/dev/null | head -1 || echo missing)"
            echo "  build system: ${buildSystem} (host: ${hostSystem})"
            echo
            echo "For the canonical, host-independent measurement:"
            echo "  nix build .#measure && cat result/words.txt"
          '';
        };
      });
}
