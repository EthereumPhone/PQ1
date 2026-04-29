#!/usr/bin/env bash
# measure.sh — reproducibly compute the 8 BIP-39 firmware measurement words.
#
# Detects whether Nix is installed; if not, offers to install it via the
# Determinate Systems installer (works on Linux, macOS, WSL2 — single
# curl, ships an uninstaller). Then runs the pinned Nix flake, which
# builds the secure firmware in a hermetic environment and prints 8
# BIP-39 words. Compare those words to what the device's OLED shows
# at boot — match means the firmware on the device corresponds to this
# git commit. See docs/reproducible-builds.md for the threat model.
#
# All toolchain pinning lives in flake.nix + flake.lock. This script is
# only a thin bootstrap.
#
# Vanilla-macOS users (no Homebrew, no Docker, no Nix) can run
# ./measure.sh directly — first run auto-installs Nix and, if no
# x86_64-linux build capability is available, a Lima-managed Docker
# daemon (Lima + Rosetta + Docker CLI under $HOME/.local). All
# subsequent runs reuse the cached VM.
#
# Pass --yes / -y to auto-stage untracked flake files (otherwise the
# script prompts before running `git add`). Pass --shell to drop into
# `nix develop` instead of running the measurement immediately —
# useful if you want to poke at other Makefile targets in the same
# hermetic environment.

set -euo pipefail

cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")"

AUTO_YES=0
DEV_SHELL=0
for arg in "$@"; do
    case "$arg" in
        --yes|-y) AUTO_YES=1 ;;
        --shell) DEV_SHELL=1 ;;
        --help|-h)
            sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            echo "Usage: $0 [--yes] [--shell]" >&2
            exit 2
            ;;
    esac
done

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# run_docker_measure
#
# Runs the canonical x86_64-linux measurement build inside a Docker container.
# Used by the host-Docker fallback AND the macOS auto-install path. Mounting
# $PWD as /work lets the in-container nix see the host repo; the linux/amd64
# platform pin keeps the Nix sandbox identical across host architectures.
#
# safe.directory: the host repo is owned by the host user (uid 501 on macOS)
# but the container runs as root. libgit2 (used by Nix) refuses to open
# repos with a uid mismatch unless safe.directory is set, so write a global
# gitconfig before invoking nix.
#
# filter-syscalls = false: when the container runs linux/amd64 on an
# aarch64 host kernel via Rosetta 2 (Apple Silicon Lima/Docker Desktop),
# Nix's default seccomp BPF program is built against x86_64 syscall
# numbers but the kernel is aarch64, so loading it fails with
# `unable to load seccomp BPF program: Invalid argument`. Turning the
# syscall filter off removes the load step entirely. The hardening it
# provides (blocking setuid/setgid bits in build outputs) is irrelevant
# for our use case — we throw the build artifacts away and only keep
# the SHA-256-derived 8 BIP-39 words in `words.txt`. On native
# x86_64-linux hosts the flag is a no-op of equivalent safety since
# the same outputs would have been produced either way.
# ---------------------------------------------------------------------------
run_docker_measure() {
    exec docker run --rm --platform linux/amd64 \
        -v "$PWD:/work" -w /work \
        -e NIX_CONFIG=$'experimental-features = nix-command flakes\nfilter-syscalls = false' \
        -e HOME=/root \
        nixos/nix:latest \
        sh -c '
            set -e
            mkdir -p /root
            printf "[safe]\n\tdirectory = *\n" > /root/.gitconfig
            nix shell nixpkgs#git nixpkgs#cacert --command \
                sh -c "nix run /work#measure"
        '
}

# ---------------------------------------------------------------------------
# install_macos_lima_docker_stack
#
# Vanilla-macOS auto-install path: stand up a free, fully CLI-driven
# Lima-managed Docker daemon so our existing Docker dispatch works.
# Apple Silicon uses VZ + Rosetta for near-native linux/amd64 perf;
# Intel macOS uses VZ directly (no emulation needed).
#
# What gets installed:
#   - Rosetta 2 (Apple Silicon only; macOS-supplied, runs unattended)
#   - Lima (https://lima-vm.io)        -> $HOME/.local/bin/limactl
#   - Docker CLI (Docker official static tarball) -> $HOME/.local/bin/docker
#   - A Lima-managed Ubuntu+Docker VM named "pqsigner-builder-rootful"
#
# Nothing requires Homebrew, Docker Desktop, OrbStack, Xcode CLT, or any
# other pre-existing dev tooling beyond what stock macOS ships (curl, tar,
# softwareupdate). The whole stack lives under $HOME (no /Applications, no
# /usr/local writes) so it cleanly cohabits with whatever the user later
# installs themselves.
#
# Versions are pinned for reproducibility of the ./measure.sh experience —
# mismatched lima/docker pairings can produce confusing errors. Bump
# together when refreshing.
# ---------------------------------------------------------------------------
LIMA_VERSION="2.1.1"
DOCKER_CLI_VERSION="29.4.1"
# Bump the suffix when changing the Lima template (rootless→rootful, etc.)
# so legacy VMs from older measure.sh runs are migrated, not reused.
LIMA_VM_NAME="pqsigner-builder-rootful"
LIMA_LEGACY_VM_NAMES=("pqsigner-builder")

install_macos_lima_docker_stack() {
    say "Setting up linux/amd64 build capability via Lima + Docker."
    say "(One-time setup — first VM boot takes ~2-4 minutes.)"

    local arch lima_arch docker_arch
    case "$(uname -m)" in
        arm64)  arch=arm64;  lima_arch=Darwin-arm64;  docker_arch=aarch64 ;;
        x86_64) arch=x86_64; lima_arch=Darwin-x86_64; docker_arch=x86_64 ;;
        *) die "Unsupported macOS architecture: $(uname -m)" ;;
    esac

    mkdir -p "$HOME/.local/bin"
    export PATH="$HOME/.local/bin:$PATH"

    # ---- Rosetta 2 (Apple Silicon needs it for x86_64-linux under VZ) ----
    # Most reliable detection: try to run a known x86_64 binary slice via
    # `arch -x86_64`. /usr/bin/true is a fat binary on macOS — running its
    # x86_64 slice requires Rosetta. Returns non-zero if Rosetta is missing.
    if [ "$arch" = "arm64" ] \
        && ! /usr/bin/arch -x86_64 /usr/bin/true >/dev/null 2>&1; then
        say "Installing Rosetta 2 (one-time; required for x86_64 emulation)."
        # softwareupdate's --agree-to-license flag accepts Apple's EULA
        # without an interactive dialog; some macOS versions still want
        # sudo to actually drop the runtime into /Library/Apple, so we
        # try unprivileged first and only escalate if that fails.
        if ! /usr/sbin/softwareupdate --install-rosetta --agree-to-license >/dev/null 2>&1; then
            say "  (re-trying with sudo — you may be prompted for your macOS password)"
            sudo /usr/sbin/softwareupdate --install-rosetta --agree-to-license \
                || die "Rosetta install failed. Run manually: sudo softwareupdate --install-rosetta --agree-to-license"
        fi
    fi

    # ---- Lima ----
    if ! command -v limactl >/dev/null 2>&1 || ! limactl --version 2>/dev/null | grep -q "$LIMA_VERSION"; then
        local lima_url="https://github.com/lima-vm/lima/releases/download/v${LIMA_VERSION}/lima-${LIMA_VERSION}-${lima_arch}.tar.gz"
        say "Downloading Lima v${LIMA_VERSION}..."
        curl -fsSL "$lima_url" -o /tmp/lima.tgz \
            || die "Failed to download Lima from $lima_url"
        tar -xzf /tmp/lima.tgz -C "$HOME/.local"
        rm -f /tmp/lima.tgz
    fi
    command -v limactl >/dev/null 2>&1 \
        || die "Lima install failed: limactl not on PATH ($HOME/.local/bin)."

    # ---- Docker CLI ----
    # Docker's static tarball ships only the docker binary (no daemon,
    # no buildx) — exactly what we need. Lima provides the daemon.
    if ! command -v docker >/dev/null 2>&1; then
        local docker_url="https://download.docker.com/mac/static/stable/${docker_arch}/docker-${DOCKER_CLI_VERSION}.tgz"
        say "Downloading Docker CLI v${DOCKER_CLI_VERSION}..."
        curl -fsSL "$docker_url" -o /tmp/docker.tgz \
            || die "Failed to download Docker CLI from $docker_url"
        tar -xzf /tmp/docker.tgz -C /tmp/
        cp /tmp/docker/docker "$HOME/.local/bin/docker"
        chmod +x "$HOME/.local/bin/docker"
        rm -rf /tmp/docker /tmp/docker.tgz
    fi

    # ---- Lima Docker VM (linux/amd64 via VZ + Rosetta on Apple Silicon) ----
    # CRITICAL: on Apple Silicon, the VM's *kernel* must stay aarch64
    # (Apple's VZ framework can only host the host arch). Linux x86_64
    # USERSPACE binaries — including everything inside `docker run
    # --platform linux/amd64` — execute via Rosetta 2 binfmt translation
    # inside the aarch64 VM. Passing `--arch=x86_64` to `limactl create
    # --vm-type=vz` makes Lima reject the config with
    # `unsupported arch: "x86_64"`. Default arch = host arch is correct.
    #
    # On Intel macOS the VM kernel is x86_64 natively and Rosetta is
    # irrelevant.
    #
    # We use template:docker-ROOTFUL, not template:docker. The rootless
    # template stores its containerd metadata at ~/.local/share/docker
    # — and Lima mounts ~ from the host READ-ONLY by default, so
    # rootless dockerd dies with `Input/output error` the moment it
    # tries to write its boltdb. Rootful dockerd writes to
    # /var/lib/docker which lives on the VM's own writable disk.
    #
    # The 40 GiB disk gives Nix room to substitute its full closure
    # (~5–8 GiB) plus the nixos/nix Docker layer (~600 MiB) and build
    # scratch space without ENOSPC.
    create_lima_vm() {
        if [ "$arch" = "arm64" ]; then
            limactl create --name="$LIMA_VM_NAME" --tty=false \
                --vm-type=vz --rosetta \
                --cpus=2 --memory=4 --disk=40 \
                template:docker-rootful
        else
            limactl create --name="$LIMA_VM_NAME" --tty=false \
                --vm-type=vz \
                --cpus=2 --memory=4 --disk=40 \
                template:docker-rootful
        fi
    }

    # ---- Migrate legacy VMs from older measure.sh runs ----
    # Earlier ./measure.sh versions left behind rootless-Docker VMs
    # named "pqsigner-builder" that hit EIO on the read-only home mount.
    # Wipe them so a single `git pull && ./measure.sh` self-heals.
    for legacy in "${LIMA_LEGACY_VM_NAMES[@]}"; do
        if [ "$legacy" != "$LIMA_VM_NAME" ] \
            && limactl list -q 2>/dev/null | grep -qx "$legacy"; then
            warn "Removing legacy Lima VM '$legacy' (rootless-docker template, broken on Lima's read-only home mount)."
            limactl stop --force "$legacy" 2>/dev/null || true
            limactl delete --force "$legacy" 2>/dev/null || true
        fi
    done

    if ! limactl list -q 2>/dev/null | grep -qx "$LIMA_VM_NAME"; then
        say "Creating Lima Docker VM '$LIMA_VM_NAME'..."
        create_lima_vm || die "Lima VM creation failed."
    fi

    if ! limactl list 2>/dev/null \
        | awk -v name="$LIMA_VM_NAME" 'NR>1 && $1==name {print $2}' \
        | grep -qx 'Running'; then
        say "Starting Lima Docker VM (first boot takes ~2 minutes)..."
        if ! limactl start "$LIMA_VM_NAME" 2>&1; then
            # The most common cause is a broken VM left over from a
            # previous failed run (e.g., bad --arch flag in older
            # ./measure.sh). Self-heal: nuke and recreate, then retry.
            warn "VM '$LIMA_VM_NAME' won't start; recreating from clean state."
            limactl delete --force "$LIMA_VM_NAME" 2>/dev/null || true
            create_lima_vm || die "Lima VM re-creation failed."
            limactl start "$LIMA_VM_NAME" || die "Lima VM start failed even after clean recreate."
        fi
    fi

    # ---- Hand the docker CLI a path to Lima's daemon socket ----
    export DOCKER_HOST="unix://${HOME}/.lima/${LIMA_VM_NAME}/sock/docker.sock"

    # ---- Wait for daemon (the docker template installs+starts dockerd
    # in a systemd unit on first boot, which takes a few seconds after
    # the VM itself reports Running) ----
    say "Waiting for Docker daemon inside the VM..."
    local retries=120
    while [ "$retries" -gt 0 ]; do
        if docker info >/dev/null 2>&1; then
            say "Docker daemon ready."
            return 0
        fi
        sleep 1
        retries=$((retries - 1))
    done
    die "Docker daemon never came up. Try: limactl stop $LIMA_VM_NAME && limactl start $LIMA_VM_NAME"
}

# ---------------------------------------------------------------------------
# Refuse native Windows up front; everything below assumes a POSIX shell
# with curl + Nix.
# ---------------------------------------------------------------------------
case "$(uname -s 2>/dev/null || echo unknown)" in
    Linux|Darwin) ;;
    MINGW*|MSYS*|CYGWIN*)
        die "Native Windows shells are not supported. Use WSL2 (Ubuntu) and re-run."
        ;;
    *)
        warn "Unrecognised OS '$(uname -s)'. Continuing anyway — Nix may still work."
        ;;
esac

# ---------------------------------------------------------------------------
# Make Nix visible if it's installed but not on PATH (common after a
# fresh Determinate install in the same shell).
# ---------------------------------------------------------------------------
if ! command -v nix >/dev/null 2>&1; then
    for candidate in \
        /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh \
        "$HOME/.nix-profile/etc/profile.d/nix.sh"; do
        if [ -r "$candidate" ]; then
            # shellcheck disable=SC1090
            . "$candidate"
            break
        fi
    done
fi

# ---------------------------------------------------------------------------
# Install Nix if missing (Determinate Systems installer — well-trusted,
# works on Linux, macOS, and WSL2 in a single command, ships an
# uninstaller).
# ---------------------------------------------------------------------------
if ! command -v nix >/dev/null 2>&1; then
    warn "Nix is not installed — bootstrapping via Determinate's installer."
    cat <<EOF

This script uses Nix to build the firmware in a hermetic environment
pinned by hash, so the measurement words it prints are guaranteed to
match what the vendor published for this git commit (and what the
device's OLED shows after flashing).

Running Determinate Systems' Nix installer (Linux/macOS/WSL2; ships
with a clean uninstaller):

  curl -fsSL https://install.determinate.systems/nix | sh -s -- install --no-confirm

This is non-interactive — to abort, press Ctrl+C now. To skip this in
the future, pre-install Nix yourself before running ./measure.sh.

EOF

    say "Running Determinate Nix installer..."
    curl -fsSL https://install.determinate.systems/nix | sh -s -- install --no-confirm

    # Re-source profile so the freshly installed `nix` binary is on PATH.
    for candidate in \
        /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh \
        "$HOME/.nix-profile/etc/profile.d/nix.sh"; do
        if [ -r "$candidate" ]; then
            # shellcheck disable=SC1090
            . "$candidate"
            break
        fi
    done

    command -v nix >/dev/null 2>&1 \
        || die "Nix install completed but the 'nix' binary is not on PATH. Open a new shell and re-run ./measure.sh."
fi

say "Nix: $(nix --version)"

# ---------------------------------------------------------------------------
# Pre-flight: the canonical measurement is built inside a pinned
# x86_64-linux sandbox so every host (Linux, macOS, WSL2) gets the same
# closure of inputs and therefore byte-identical 8-word output. Hosts
# that are NOT x86_64-linux need a remote builder that can build for
# x86_64-linux. On Apple Silicon Macs this is normally satisfied by a
# local linux-builder VM; on Linux aarch64 by either a remote builder
# or binfmt_misc + qemu-user.
#
# Detect this up front and print remediation instead of letting Nix bury
# the user in a wall of "Required system: 'x86_64-linux'" errors.
# ---------------------------------------------------------------------------
host_system=$(nix --extra-experimental-features 'nix-command' eval \
    --impure --raw --expr 'builtins.currentSystem' 2>/dev/null || echo "unknown")

if [ "$host_system" != "x86_64-linux" ]; then
    nix_config=$(nix --extra-experimental-features 'nix-command' \
        show-config 2>/dev/null || true)
    has_linux_builder=0
    # `extra-platforms` covers binfmt-style native execution; `builders`
    # covers SSH / VM remote builders. Either is enough.
    if echo "$nix_config" | awk -F= '/^(extra-platforms|builders)\s*=/' \
        | grep -q 'x86_64-linux'; then
        has_linux_builder=1
    fi

    if [ "$has_linux_builder" -eq 0 ]; then
        # ---- macOS auto-install: Lima + Docker ---------------------------
        # On vanilla macOS (no Docker, no linux-builder), auto-stand-up a
        # Lima-managed Docker daemon. After this step Docker is on PATH
        # via $HOME/.local/bin and DOCKER_HOST is wired to Lima's socket,
        # so the existing Docker fallback below dispatches the build the
        # same way as if the user had installed Docker themselves.
        # ~/.local/bin gets prepended for the rest of this script as well
        # as future invocations (assuming the user's shell rc adds it).
        if [ "$(uname -s)" = "Darwin" ] \
            && ! { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }; then
            install_macos_lima_docker_stack
        fi

        # ---- Docker fallback --------------------------------------------
        # No linux-builder, but if Docker is up we can run the entire Nix
        # build inside a linux/amd64 container. Inside the container
        # `currentSystem == x86_64-linux` so the flake builds natively
        # against its own pinned closure — same bytes, same words, no
        # Mac-side Nix involved. On Apple Silicon, Docker Desktop and
        # OrbStack run linux/amd64 via Rosetta 2; works out of the box.
        if command -v docker >/dev/null 2>&1 \
            && docker info >/dev/null 2>&1; then
            say "No linux-builder; dispatching build through Docker (linux/amd64)…"
            say "First run downloads ~1 GB into Docker; subsequent runs cached."
            run_docker_measure
        fi

        # ---- Neither linux-builder nor Docker available -----------------
        cat >&2 <<EOF

$(printf '\033[1;31m==> Cannot build the reproducible measurement on this host.\033[0m')

This host is '$host_system'. The build is pinned to x86_64-linux so
every host gets byte-identical output. ./measure.sh can satisfy that
in two ways and neither is currently available:

  1. A configured x86_64-linux Nix builder (linux-builder VM, remote
     builder via /etc/nix/machines, or binfmt+qemu on Linux aarch64).

  2. A working Docker daemon. ./measure.sh will auto-dispatch the
     build into a linux/amd64 container if Docker is up.

EOF
        case "$(uname -s)" in
            Darwin)
                cat >&2 <<'EOF'
./measure.sh attempted to auto-install Lima + Docker but the daemon
did not come up. The most common reasons:
  - macOS < 13 (Apple Virtualization framework requires Ventura+).
  - Lima failed to download (check network).
  - The Docker daemon inside the VM did not start.

Try one of:
  - limactl stop pqsigner-builder-rootful && limactl start pqsigner-builder-rootful
  - Install Docker Desktop or OrbStack manually, then re-run.
EOF
                ;;
            Linux)
                cat >&2 <<'EOF'
Install Docker, OR enable binfmt_misc + qemu-user:

  sudo apt install qemu-user-static binfmt-support  # Debian/Ubuntu
  echo "extra-platforms = x86_64-linux" | sudo tee -a /etc/nix/nix.conf
  sudo systemctl restart nix-daemon

Then re-run ./measure.sh.
EOF
                ;;
            *)
                cat >&2 <<'EOF'
Install Docker, or configure a remote x86_64-linux builder via
/etc/nix/machines. Then re-run ./measure.sh.
EOF
                ;;
        esac
        exit 1
    fi
    say "x86_64-linux build capability available — dispatching sandbox build."
fi

# ---------------------------------------------------------------------------
# Nix flakes only see git-tracked (or staged) files when invoked from a
# git repo. If flake.nix or flake.lock are untracked here, the upstream
# error is cryptic ("Path 'flake.nix' is not tracked by Git"); pre-empt
# it with a clearer prompt + auto-fix offer.
# ---------------------------------------------------------------------------
if [ -d .git ] && command -v git >/dev/null 2>&1; then
    untracked=()
    for f in flake.nix flake.lock; do
        if [ -e "$f" ] && ! git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
            untracked+=("$f")
        fi
    done
    if [ "${#untracked[@]}" -gt 0 ]; then
        warn "Nix flake files are not tracked by git: ${untracked[*]}"
        echo "Nix only sees tracked files in a git repo. Stage them with:"
        echo "  git add ${untracked[*]}"
        echo
        if [ "$AUTO_YES" -eq 1 ]; then
            say "Staging (--yes was passed)…"
            git add "${untracked[@]}"
        else
            read -r -p "Stage them now? [Y/n] " ans
            case "$ans" in
                ""|y|Y|yes|YES) git add "${untracked[@]}" ;;
                *) die "Aborted. Stage the files yourself, then re-run ./measure.sh." ;;
            esac
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Run the flake. Determinate's installer enables flakes by default; the
# explicit --extra-experimental-features keeps things working on stock
# upstream Nix too.
# ---------------------------------------------------------------------------
NIX_OPTS=(--extra-experimental-features 'nix-command flakes')

# If flake.lock is missing entirely, generate it once before the build.
# The lock file is meant to be committed; auditors checking out a
# release commit will already have it.
if [ ! -f flake.lock ]; then
    say "flake.lock not found — generating it once (will be cached)."
    nix "${NIX_OPTS[@]}" flake lock
    if command -v git >/dev/null 2>&1 && git ls-files --error-unmatch flake.lock >/dev/null 2>&1; then
        :  # already tracked, nothing to do
    elif [ -d .git ] && command -v git >/dev/null 2>&1; then
        warn "Stage flake.lock too: git add flake.lock"
        git add flake.lock || true
    fi
fi

if [ "$DEV_SHELL" -eq 1 ]; then
    say "Entering hermetic dev shell. Type 'make measure' (or any other Makefile target)."
    exec nix "${NIX_OPTS[@]}" develop
fi

say "Building secure firmware in pinned environment (first run downloads ~1 GB)…"
exec nix "${NIX_OPTS[@]}" run .#measure
