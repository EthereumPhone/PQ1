{
  description = "PQSigner OS — reproducible firmware measurement";

  # All inputs are pinned by hash in flake.lock. Anyone running
  # `nix run .#measure` against this commit gets the exact same
  # closure of rustc + LLVM + arm-none-eabi-ld + GNU make, on any
  # supported host (Linux x86_64/aarch64, macOS Intel/Apple Silicon,
  # WSL2). See docs/reproducible-builds.md for the threat model and
  # the cross-platform byte-identity story.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        # Single source of truth for the Rust pin: rust-toolchain.toml.
        # rust-overlay reads the channel + targets + components straight
        # out of that file, so the flake never duplicates the version
        # string and stays in lockstep with the rustup-driven workflow.
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        # `make measure` shells out to: cargo, arm-none-eabi-ld, make,
        # plus the usual coreutils. Everything below comes from the
        # pinned nixpkgs revision in flake.lock — no host PATH leakage.
        measureDeps = [
          rustToolchain
          pkgs.gcc-arm-embedded
          pkgs.gnumake
          pkgs.coreutils
          pkgs.gnused
          pkgs.gnugrep
          pkgs.findutils
          pkgs.gawk
          pkgs.bash
          pkgs.cacert
          pkgs.curl
          pkgs.git
        ];

        measureScript = pkgs.writeShellApplication {
          name = "pqsigner-measure";
          runtimeInputs = measureDeps;
          text = ''
            set -euo pipefail

            if [ ! -f Cargo.toml ] || [ ! -f rust-toolchain.toml ]; then
              echo "ERROR: run this from the sphincs_rust repo root" >&2
              echo "       (must contain Cargo.toml + rust-toolchain.toml)." >&2
              exit 1
            fi

            # Isolate cargo state from the user's $HOME so the build is
            # hermetic against host-side cargo config drift. The output
            # ELF is path-remapped (Makefile REPRO_REMAP) so neither the
            # tempdir nor $HOME leaks into the binary.
            CARGO_HOME="$(mktemp -d)"
            export CARGO_HOME
            trap 'rm -rf "$CARGO_HOME"' EXIT

            export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt

            exec make measure
          '';
        };
      in {
        # `nix run .#measure` — produce the 8 BIP-39 words.
        apps.measure = {
          type = "app";
          program = "${measureScript}/bin/pqsigner-measure";
        };
        apps.default = self.apps.${system}.measure;

        # `nix build .#measure` — exposes the wrapper as a package, so
        # other flakes / Nix-aware tooling can reference it.
        packages.measure = measureScript;
        packages.default = measureScript;

        # `nix develop` — interactive shell for auditors who want to
        # poke at intermediate Makefile targets (verify-repro, release,
        # etc.) without committing to a single command.
        devShells.default = pkgs.mkShell {
          packages = measureDeps;
          shellHook = ''
            echo "PQSigner reproducible build shell"
            echo "  rustc: $(rustc --version 2>/dev/null || echo missing)"
            echo "  ld:    $(arm-none-eabi-ld --version 2>/dev/null | head -1 || echo missing)"
            echo
            echo "Try: make measure"
          '';
        };
      });
}
