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
# Pass --yes / -y to install Nix non-interactively (for CI / scripted
# use). Pass --shell to drop into `nix develop` instead of running the
# measurement immediately — useful if you want to poke at other
# Makefile targets in the same hermetic environment.

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
    warn "Nix is not installed."
    cat <<EOF

This script uses Nix to build the firmware in a hermetic environment
pinned by hash, so the measurement words it prints are guaranteed to
match what the vendor published for this git commit (and what the
device's OLED shows after flashing).

Suggested installer (Determinate Systems — the recommended Nix
installer for Linux/macOS/WSL2; ships with an uninstaller):

  curl -fsSL https://install.determinate.systems/nix | sh -s -- install

EOF

    if [ "$AUTO_YES" -eq 1 ]; then
        say "Running Determinate Nix installer (--yes was passed)…"
        curl -fsSL https://install.determinate.systems/nix | sh -s -- install --no-confirm
    else
        read -r -p "Install Nix now? [y/N] " ans
        case "$ans" in
            y|Y|yes|YES)
                curl -fsSL https://install.determinate.systems/nix | sh -s -- install ;;
            *)
                echo "Aborted. Install Nix manually, then re-run ./measure.sh." >&2
                exit 1 ;;
        esac
    fi

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
        cat >&2 <<EOF

$(printf '\033[1;31m==> No x86_64-linux builder is configured.\033[0m')

This host is '$host_system'. The reproducible measurement is built
inside a pinned x86_64-linux sandbox so every host gets byte-identical
output. To dispatch the build off-box you need either:

EOF
        case "$(uname -s)" in
            Darwin)
                cat >&2 <<'EOF'
  ► On Apple Silicon: enable Determinate Nix's built-in linux-builder.
    Documentation:  https://docs.determinate.systems/macos-linux-builder/

    If you use nix-darwin, add to your configuration:
        nix.linux-builder.enable = true;
    then run:  darwin-rebuild switch

  ► Otherwise: follow Determinate's linux-builder setup, or configure a
    remote x86_64-linux builder via /etc/nix/machines.

After enabling, re-run ./measure.sh.
EOF
                ;;
            Linux)
                cat >&2 <<'EOF'
  ► binfmt_misc + qemu-user (transparent x86_64 emulation under Linux):
        sudo apt install qemu-user-static binfmt-support  # Debian/Ubuntu
    then add to /etc/nix/nix.conf:
        extra-platforms = x86_64-linux
    and restart nix-daemon.

  ► Or configure a remote x86_64-linux builder via /etc/nix/machines.

After enabling, re-run ./measure.sh.
EOF
                ;;
            *)
                cat >&2 <<'EOF'
  ► Configure a remote x86_64-linux builder via /etc/nix/machines or
    your platform's equivalent. See the Nix manual on remote builds.

After enabling, re-run ./measure.sh.
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
