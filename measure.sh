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
# install_macos_lima_nix_stack  +  run_in_lima_vm
#
# Vanilla-macOS auto-install path: stand up a Lima-managed Linux VM with
# Nix installed *inside* the VM, configured to dispatch x86_64-linux
# builds through Rosetta 2 binfmt. No Docker anywhere. This is the same
# pattern nix-darwin's `nix.linux-builder.enable = true` uses
# internally, just without requiring a nix-darwin install on the host.
#
# Why this and not Docker:
#
#   The earlier Docker-based path failed on Apple Silicon with
#   `Input/output error` writing to overlay2 and containerd's boltdb
#   when running linux/amd64 containers under Rosetta translation in
#   Lima's VM. Even after switching to rootful Docker (writes go to
#   /var/lib/docker on the VM's own disk, not the read-only home
#   mount), the container's writable layer hit EIO on chmod and
#   sqlite-fsync calls — a known Docker-on-Rosetta-on-VZ corner case.
#   Eliminating Docker eliminates the problem entirely: there is only
#   the VM, and Nix talks to its own /nix/store on a normal ext4
#   filesystem, no overlay involved.
#
# What gets installed:
#
#   - Rosetta 2 (Apple Silicon only; macOS-supplied, unattended).
#   - Lima (https://lima-vm.io) -> $HOME/.local/bin/limactl.
#   - A plain Ubuntu LTS Lima VM "pqsigner-builder-nix" with --rosetta
#     so the in-VM kernel registers Rosetta as the binfmt_misc handler
#     for x86_64 ELFs.
#   - Determinate Nix *inside* the VM, configured with
#     `extra-platforms = x86_64-linux` so a derivation pinned to
#     x86_64-linux builds locally on this aarch64 host and the build's
#     x86_64 binaries (rustc, ld, …) execute via Rosetta translation.
#
# Nothing requires Homebrew, Docker Desktop, OrbStack, Xcode CLT, or
# any other pre-existing dev tooling beyond what stock macOS ships
# (curl, tar, softwareupdate). The whole stack lives under $HOME (no
# /Applications, no /usr/local writes) and cohabits cleanly with
# whatever container tooling the user installs later.
#
# Versions are pinned for reproducibility of the ./measure.sh
# experience. Bump LIMA_VERSION when refreshing.
# ---------------------------------------------------------------------------
LIMA_VERSION="2.1.1"
# Bump the suffix when changing the Lima template or in-VM provisioning
# so legacy VMs from older measure.sh runs are migrated, not reused.
LIMA_VM_NAME="pqsigner-builder-nix"
LIMA_LEGACY_VM_NAMES=("pqsigner-builder" "pqsigner-builder-rootful")

install_macos_lima_nix_stack() {
    say "Setting up x86_64-linux build capability via Lima + Nix-in-VM."
    say "(One-time setup — first VM boot + Nix install takes ~3-5 minutes.)"

    local arch lima_arch
    case "$(uname -m)" in
        arm64)  arch=arm64;  lima_arch=Darwin-arm64 ;;
        x86_64) arch=x86_64; lima_arch=Darwin-x86_64 ;;
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
        if ! /usr/sbin/softwareupdate --install-rosetta --agree-to-license >/dev/null 2>&1; then
            say "  (re-trying with sudo — you may be prompted for your macOS password)"
            sudo /usr/sbin/softwareupdate --install-rosetta --agree-to-license \
                || die "Rosetta install failed. Run manually: sudo softwareupdate --install-rosetta --agree-to-license"
        fi
    fi

    # ---- Lima ----
    if ! command -v limactl >/dev/null 2>&1 \
        || ! limactl --version 2>/dev/null | grep -q "$LIMA_VERSION"; then
        local lima_url="https://github.com/lima-vm/lima/releases/download/v${LIMA_VERSION}/lima-${LIMA_VERSION}-${lima_arch}.tar.gz"
        say "Downloading Lima v${LIMA_VERSION}..."
        curl -fsSL "$lima_url" -o /tmp/lima.tgz \
            || die "Failed to download Lima from $lima_url"
        tar -xzf /tmp/lima.tgz -C "$HOME/.local"
        rm -f /tmp/lima.tgz
    fi
    command -v limactl >/dev/null 2>&1 \
        || die "Lima install failed: limactl not on PATH ($HOME/.local/bin)."

    # ---- Lima VM (plain Ubuntu LTS + --rosetta on Apple Silicon) --------
    # CRITICAL: on Apple Silicon, the VM kernel must stay aarch64 (Apple's
    # VZ framework can only host the host arch). The --rosetta flag
    # registers Rosetta as the binfmt_misc handler for x86_64 ELFs in the
    # VM, so x86_64 USERSPACE — including the rustc/ld/cc that Nix
    # invokes during the x86_64-linux build — runs at near-native speed.
    # Passing --arch=x86_64 to vz makes Lima reject the config with
    # `unsupported arch: "x86_64"`; default arch = host arch is correct.
    #
    # 40 GiB disk: x86_64 Nix substitution closure (~5-8 GiB) + sandbox
    # build scratch + headroom. 6 GiB RAM: enough for a parallel rustc
    # invocation without thrashing.
    create_lima_vm() {
        if [ "$arch" = "arm64" ]; then
            limactl create --name="$LIMA_VM_NAME" --tty=false \
                --vm-type=vz --rosetta \
                --cpus=4 --memory=6 --disk=40 \
                template:default
        else
            limactl create --name="$LIMA_VM_NAME" --tty=false \
                --vm-type=vz \
                --cpus=4 --memory=6 --disk=40 \
                template:default
        fi
    }

    # ---- Migrate legacy VMs from older measure.sh runs ----
    # Earlier ./measure.sh versions used rootless-Docker / rootful-Docker
    # templates that hit different EIO modes under Rosetta+overlay2.
    # Wipe them so a single `git pull && ./measure.sh` self-heals.
    for legacy in "${LIMA_LEGACY_VM_NAMES[@]}"; do
        if [ "$legacy" != "$LIMA_VM_NAME" ] \
            && limactl list -q 2>/dev/null | grep -qx "$legacy"; then
            warn "Removing legacy Lima VM '$legacy' (Docker-based template, deprecated)."
            limactl stop --force "$legacy" 2>/dev/null || true
            limactl delete --force "$legacy" 2>/dev/null || true
        fi
    done

    if ! limactl list -q 2>/dev/null | grep -qx "$LIMA_VM_NAME"; then
        say "Creating Lima VM '$LIMA_VM_NAME'..."
        create_lima_vm || die "Lima VM creation failed."
    fi

    if ! limactl list 2>/dev/null \
        | awk -v name="$LIMA_VM_NAME" 'NR>1 && $1==name {print $2}' \
        | grep -qx 'Running'; then
        say "Starting Lima VM (first boot takes ~1-2 minutes)..."
        if ! limactl start "$LIMA_VM_NAME" 2>&1; then
            # Self-heal: nuke and recreate if start fails.
            warn "VM '$LIMA_VM_NAME' won't start; recreating from clean state."
            limactl delete --force "$LIMA_VM_NAME" 2>/dev/null || true
            create_lima_vm || die "Lima VM re-creation failed."
            limactl start "$LIMA_VM_NAME" || die "Lima VM start failed even after clean recreate."
        fi
    fi

    # ---- Provision Nix inside the VM ----------------------------------
    # Determinate Nix MANAGES /etc/nix/nix.conf — that file gets
    # regenerated from Determinate's template on every daemon restart,
    # so anything we append directly there is wiped when the daemon
    # picks up our changes. The supported user-customization channel
    # is /etc/nix/nix.custom.conf, which the managed nix.conf
    # `!include`s near its top. We write all our overrides there.
    #
    # Three settings the daemon needs:
    #   - extra-platforms = x86_64-linux  (so the daemon accepts
    #     x86_64-linux derivations on this aarch64 host; kernel's
    #     binfmt_misc → Rosetta executes the x86_64 ELFs).
    #   - trusted-users = root @sudo @wheel  (so the lima user can
    #     override these via --option as a belt-and-braces fallback;
    #     extra-platforms is a "restricted" setting so unprivileged
    #     clients can't set it without being trusted).
    #   - extra-experimental-features = nix-command flakes  (already
    #     in Determinate's managed config, but harmless to repeat).
    #
    # After writing nix.custom.conf we restart the daemon (trying both
    # standard and Determinate-named services) and verify via
    # `nix show-config` that extra-platforms actually became visible.
    say "Provisioning Nix inside the VM (skipped if already installed)..."
    limactl shell "$LIMA_VM_NAME" bash -c '
        set -e
        if ! command -v nix >/dev/null 2>&1 && [ ! -d /nix ]; then
            echo "[provision] Installing Determinate Nix..."
            curl -fsSL https://install.determinate.systems/nix \
                | sh -s -- install --no-confirm
        fi
        # Source the daemon profile script so this shell can see nix.
        if [ -f /etc/profile.d/nix-daemon.sh ]; then
            # shellcheck disable=SC1091
            . /etc/profile.d/nix-daemon.sh
        fi

        # Pick the right config target. Determinate uses
        # /etc/nix/nix.custom.conf (referenced via "!include
        # nix.custom.conf" near the top of /etc/nix/nix.conf).
        # Vanilla Nix has no such convention; fall back to writing to
        # /etc/nix/nix.conf in that case.
        custom_conf=/etc/nix/nix.custom.conf
        if sudo grep -q "^!include[[:space:]]\+nix.custom.conf" \
            /etc/nix/nix.conf 2>/dev/null; then
            target_conf=$custom_conf
            sudo touch "$custom_conf"
        else
            target_conf=/etc/nix/nix.conf
        fi
        echo "[provision] Writing user overrides to $target_conf"

        # Idempotent setting writer. Leading "\n" guarantees we never
        # glue onto the previous line if the file lacks a trailing
        # newline.
        ensure_setting() {
            local key=$1 value=$2
            if ! sudo grep -qE "^[[:space:]]*${key}[[:space:]]*=" \
                "$target_conf" 2>/dev/null; then
                printf "\n%s = %s\n" "$key" "$value" \
                    | sudo tee -a "$target_conf" >/dev/null
                echo "[provision]   + $key = $value"
                return 0   # changed
            fi
            return 1       # already set
        }
        changed=0
        ensure_setting extra-platforms x86_64-linux         && changed=1
        ensure_setting trusted-users   "root @sudo @wheel"  && changed=1
        ensure_setting extra-experimental-features "nix-command flakes" && changed=1

        if [ "$changed" -eq 1 ]; then
            echo "[provision] Restarting nix-daemon to pick up new config..."
            restarted=0
            for svc in nix-daemon.service determinate-nixd.service; do
                if sudo systemctl restart "$svc" 2>/dev/null; then
                    echo "[provision] Restarted $svc."
                    restarted=1
                    break
                fi
            done
            if [ "$restarted" -eq 0 ]; then
                echo "[provision] systemctl restart didnt match a known service name; killing daemon to force reload."
                sudo pkill -TERM -f "nix-daemon|determinate-nixd" 2>/dev/null || true
            fi
            for _i in $(seq 30); do
                [ -S /nix/var/nix/daemon-socket/socket ] && break
                sleep 1
            done
            sleep 2
        fi

        # Verify the daemon actually serves x86_64-linux now. We
        # query through the daemon (not just the parsed config file)
        # so the check is honest about runtime state.
        if nix --extra-experimental-features nix-command show-config 2>/dev/null \
            | grep -E "^extra-platforms" | grep -q "x86_64-linux"; then
            echo "[provision] OK: extra-platforms = x86_64-linux is active."
        else
            echo "[provision] ERROR: extra-platforms still not visible after restart." >&2
            echo "[provision] $target_conf contents:" >&2
            sudo cat "$target_conf" >&2
            echo "[provision] nix show-config | grep platform:" >&2
            nix --extra-experimental-features nix-command show-config 2>/dev/null \
                | grep -i platform >&2 || true
            exit 1
        fi
    ' || die "Nix provisioning inside the Lima VM failed."

    say "Lima VM is up with Nix + Rosetta-x86_64-linux build capability."
}

# ---------------------------------------------------------------------------
# run_in_lima_vm
#
# Dispatch the measurement build into the already-provisioned Lima VM.
# --workdir cd's the VM-side shell to the same path the host is at;
# Lima's default `~` mount makes the host repo accessible inside the VM
# at the identical path (read-only, which is fine — Nix only *reads*
# source from $PWD and writes its outputs into the VM's /nix/store).
#
# On the very first build the in-VM Nix substitutes ~5-8 GiB of x86_64
# closure from cache.nixos.org. Subsequent runs are sub-minute.
# ---------------------------------------------------------------------------
run_in_lima_vm() {
    # --option extra-platforms x86_64-linux is belt-and-braces: even if
    # /etc/nix/nix.conf lost the setting somehow, the lima user is in
    # trusted-users (set during provisioning) so this --option override
    # will be honored by the daemon for this build.
    exec limactl shell --workdir "$PWD" "$LIMA_VM_NAME" bash -c '
        set -e
        if [ -f /etc/profile.d/nix-daemon.sh ]; then
            # shellcheck disable=SC1091
            . /etc/profile.d/nix-daemon.sh
        elif [ -f "$HOME/.nix-profile/etc/profile.d/nix.sh" ]; then
            # shellcheck disable=SC1091
            . "$HOME/.nix-profile/etc/profile.d/nix.sh"
        fi
        exec nix --extra-experimental-features "nix-command flakes" \
            --option extra-platforms x86_64-linux \
            run .#measure
    '
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
        # ---- macOS auto-install: Lima VM + Nix-in-VM via Rosetta ---------
        # On macOS (Intel or Apple Silicon), bring up a Lima VM, install
        # Nix inside it, and dispatch the build into the VM via
        # `limactl shell`. No Docker layer involved — this avoids the
        # overlay2/containerd EIO failures that plagued the Docker-based
        # path under Rosetta translation.
        if [ "$(uname -s)" = "Darwin" ]; then
            install_macos_lima_nix_stack
            run_in_lima_vm
            # run_in_lima_vm exec's; control never returns here.
        fi

        # ---- Docker fallback (Linux aarch64 / WSL2 / other) --------------
        # If we got here, we're not on macOS. Try host Docker as a generic
        # fallback for Linux aarch64 hosts that can't natively build
        # x86_64-linux derivations.
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
via:

  1. A native x86_64-linux Nix builder (linux-builder VM, remote
     builder via /etc/nix/machines, or binfmt+qemu on Linux aarch64).
  2. A working Docker daemon (auto-dispatches into linux/amd64).
  3. (macOS only) A Lima VM with Nix-in-VM + Rosetta — auto-installed
     by ./measure.sh.

EOF
        case "$(uname -s)" in
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
