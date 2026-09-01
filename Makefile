# `make` / `make help` lists every runnable target that carries a `## ` blurb
# (self-documenting — derived from the Makefile itself, so it can't drift the
# way a hand-maintained count does). Add `## one-liner` to a target's rule line
# to surface it. `make help` also appends the FV / spec-assurance suite from
# contracts/verification/; `make help-verify` shows just that suite.
.DEFAULT_GOAL := help
.PHONY: help help-verify
help: ## Show the main runnable targets (root + the FV suite below)
	@grep -hE '^[a-zA-Z0-9_.-]+:.*## ' $(MAKEFILE_LIST) | sort | awk -F':.*## ' '!seen[$$1]++ {printf "  \033[36m%-26s\033[0m %s\n", $$1, $$2}'
	@printf '\n  \033[1mFV / spec-assurance\033[0m  (run with: make -C contracts/verification <target>)\n'
	@$(MAKE) --no-print-directory -C contracts/verification help | grep -v 'runnable FV targets' || true

help-verify: ## Show only the FV / spec-assurance targets (contracts/verification)
	@$(MAKE) --no-print-directory -C contracts/verification help

TARGET = thumbv8m.main-none-eabi

# ---------------------------------------------------------------------------
# Board / target selection
# ---------------------------------------------------------------------------
# BOARD picks the physical board a hardware target is built and flashed for.
#
#   iota2  (default) — ST B-U585I-IOT02A dev board, STM32U585AII6 (169-pin).
#                      Every existing bench flow assumes this; nothing changes.
#   pq1              — AL_A66_MB_V10 production board, STM32U585CIU6 (48-pin).
#                      Only ports A, B and PC13 are bonded — see
#                      `secure/src/board/` for the pin map.
#
# Usage:  make test-key-speed BOARD=pq1
#
# CHIP and BOARD_FEATURE are derived from BOARD with `override`, which is
# load-bearing: a plain `?=` (or even `:=`) loses to a command-line assignment,
# because make gives command-line variables precedence over every makefile
# assignment except an overridden one. Before 2026-08-31 both used `?=`, so
#
#     make flash-hw-usb-test BOARD=pq1 BOARD_FEATURE=board-iota2
#
# selected the pq1 probe target and compiled the iota2 pin map — handing
# PA15/PB5/PB15 (SE_RST, SE1_EN, LCM_EN on that board) to the non-secure world
# on pq1 silicon. The Rust exact-one fence in `secure/src/board/mod.rs` cannot
# catch that: it sees exactly one board feature and passes. The two must not be
# separable, so they no longer are.
BOARD ?= iota2

ifeq ($(BOARD),iota2)
override CHIP          := STM32U585AIIx
override BOARD_FEATURE := board-iota2
else ifeq ($(BOARD),pq1)
override CHIP          := STM32U585CIUx
override BOARD_FEATURE := board-pq1
else
$(error BOARD must be `iota2` or `pq1`, got `$(BOARD)`)
endif

# STM32CubeProgrammer CLI. Not always on PATH (the default install lands in
# ~/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin); override with
#   make <target> STM32_PROG=/path/to/STM32_Programmer_CLI
STM32_PROG ?= $(firstword $(wildcard \
        $(HOME)/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI) \
        STM32_Programmer_CLI)
RUSTFLAGS_VAR = CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS
VENEERS = $(CURDIR)/target/veneers.o

# CMSE veneers only exist on the real STM32U585 build path (the QEMU
# `mps2-an505` transport uses a shared-memory mailbox instead). The
# linker rejects `--cmse-implib` if no `cmse-nonsecure-entry` symbols
# are present in the secure binary, so we only emit the implib when the
# `stm32u585` cargo feature is selected.
ifneq (,$(findstring stm32u585,$(FEATURES)))
SECURE_CMSE_FLAGS = -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)
NS_VENEERS_FLAG   = -C link-arg=$(VENEERS)
else
SECURE_CMSE_FLAGS =
NS_VENEERS_FLAG   =
endif

# Reproducible-build flags. Rebuilding the same commit on a different
# laptop (or inside CI) must produce byte-identical ELFs so that
# `make measure` yields the same 8 BIP-39 words. The flags below
# normalize three sources of build-host variance:
#
#   1. --remap-path-prefix rewrites any absolute file paths that end up
#      in panic messages / debug info / OUT_DIR references to a stable
#      prefix. Without this, two laptops with different $HOME values
#      produce different ELFs. The /nix/store rule covers the rustc
#      sysroot path embedded by `core` panic messages: under the
#      flake, rust-overlay downloads a per-host prebuilt rustc, so
#      the store hash differs between Linux x86_64 and macOS aarch64
#      and would otherwise leak into .rodata.
#   2. -Wl,--build-id=none strips the GNU build-id note, which is a
#      hash over the other note sections and shifts with any re-link.
#   3. -Wl,--no-insert-timestamp prevents the linker from stamping
#      build time into the PE-ish note sections (ld is usually quiet
#      about this on ELF, but we still pass the flag as a belt-and-
#      braces measure).
#
# SOURCE_DATE_EPOCH is exported for any build script that embeds a
# timestamp. When built from a git checkout it's the commit time
# (deterministic for a given commit); otherwise it falls back to the
# POSIX epoch.
REPRO_REMAP = --remap-path-prefix=$(HOME)/.cargo=/cargo \
              --remap-path-prefix=$(HOME)/.rustup=/rustup \
              --remap-path-prefix=/nix/store=/nix-store \
              --remap-path-prefix=$(CURDIR)=/pqsigner
# The Makefile invokes arm-none-eabi-ld directly (no gcc driver), so linker
# flags are passed bare — not wrapped in -Wl,. arm-none-eabi-ld has
# --build-id= but not --no-insert-timestamp (that one's PE-only).
REPRO_LINK  = -C link-arg=--build-id=none
REPRO_FLAGS = $(REPRO_REMAP) $(REPRO_LINK)

export SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)

# Factored RUSTFLAGS strings for the two firmware worlds. Every target
# that invokes cargo on the ARM tree uses one of these variables so
# reproducibility flags are applied consistently and can't drift.
# Cargo gives CARGO_TARGET_<TRIPLE>_RUSTFLAGS precedence over
# `.cargo/config.toml`, so that file is only a fallback for ad-hoc
# `cargo build` invocations — the canonical flags live here.
RUSTFLAGS_SECURE    = -C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS) $(SECURE_CMSE_FLAGS)
RUSTFLAGS_NONSECURE = -C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS) $(NS_VENEERS_FLAG)
# Variants for hardware targets that unconditionally emit CMSE veneers
# (independent of the $(FEATURES) content — used by the hw- targets).
RUSTFLAGS_SECURE_HW    = -C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS) -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)
RUSTFLAGS_NONSECURE_HW = -C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS) -C link-arg=$(VENEERS)

SECURE_ELF   = target/secure/$(TARGET)/release/sphincs-tz-secure
NONSECURE_ELF = target/nonsecure/$(TARGET)/release/sphincs-tz-nonsecure
FSBL_ELF      = target/fsbl/$(TARGET)/release/pqsigner-fsbl
RELEASE_FSBL_ELF = target/release-fsbl/$(TARGET)/release/pqsigner-fsbl
PRODUCTION_VENDOR_KEY_POLICY = $(CURDIR)/config/production-firmware-vendor-key.sha256
DEVELOPMENT_VENDOR_KEY_POLICY = $(CURDIR)/config/development-firmware-vendor-pubkey.hex
RELEASE_VENDOR_KEY_SNAPSHOT = $(CURDIR)/target/release-input/vendor-pubkey.bin
RELEASE_ARTIFACT_DIR = $(CURDIR)/target/pqsigner-release
RELEASE_ARTIFACT_TMP = $(CURDIR)/target/pqsigner-release.tmp

# Default: mock secure element + semihosting UI mock (no real hardware needed)
# debug-log enables semihosting output from the secure world.
# Remove it for production builds to eliminate all debug strings.
FEATURES ?= mock-se,debug-log,ui-semihosting

# The generated review file is the host-readable provenance companion to the
# root/fences in secure/src/db_roots.rs. When the selected root is explicitly
# dev-unattested, canonical Make-driven dev builds automatically enable the
# matching trusted-display warning. A production feature set never gets that
# feature: `prod-erc7730-provenance-check` and the generated Rust fence reject
# the root instead. The rollback quarantine remains an independent ship gate.
# These values are security policy inputs, not caller configuration.  GNU
# make command-line assignments normally override ordinary makefile values;
# use `override` so an invocation cannot make this process gate false-green
# while the generated Rust fence still embeds the dev catalogue.
override ERC7730_REVIEW := secure/data/erc7730.review.txt
override ERC7730_E2E_GENERATOR_FEATURE := nested-calldata-test-fixture
override ERC7730_CATALOGUE_PROVENANCE := $(strip $(shell awk '/^\# Provenance: / { print $$3; exit }' $(ERC7730_REVIEW) 2>/dev/null))
ifeq ($(ERC7730_CATALOGUE_PROVENANCE),dev-unattested)
ifeq (,$(findstring mode-production,$(FEATURES)))
ifeq (,$(findstring erc7730-dev-unattested,$(FEATURES)))
override FEATURES := $(FEATURES),erc7730-dev-unattested
endif
endif
endif

# Thread the board selection into every $(FEATURES)-driven secure build.
# Only hardware builds have a board: the QEMU mps2-an505 target has no pin
# map, and `secure/src/board/` is gated on `stm32u585`.
#
# `board-iota2` is NOT "inert by construction" — that was the retracted
# opt-in-to-pq1 model, and believing it is what left seven recipes without a
# board term. Since a15561b4 naming a board is mandatory and `board-iota2` is
# load-bearing.
#
# If FEATURES already names a board we do not append, but we no longer stay
# silent about it either: a FEATURES board that disagrees with BOARD is the
# same wrong-image hazard as the BOARD_FEATURE override closed above, and it
# is a hard error rather than a silently mismatched build.
ifneq (,$(findstring stm32u585,$(FEATURES)))
ifeq (,$(findstring board-,$(FEATURES)))
override FEATURES := $(FEATURES),$(BOARD_FEATURE)
else
ifeq (,$(findstring $(BOARD_FEATURE),$(FEATURES)))
$(error FEATURES names a board that disagrees with BOARD=$(BOARD). \
  FEATURES=$(FEATURES) but BOARD implies $(BOARD_FEATURE). \
  CHIP would be $(CHIP) while the image is built for the other board's pin map. \
  Drop the board- token from FEATURES and select with BOARD=iota2|pq1.)
endif
endif
endif

# Extract features relevant to the nonsecure crate (it doesn't know about
# mock-se, debug-log, ui-semihosting, etc. — only the shared platform,
# transport, test, and watchdog features below).
#
# The board is forwarded too (2026-08-31). It was not, so `make e2e-hw BOARD=pq1`
# built secure=pq1 against NS=implicit-iota2 — and `nonsecure/src/gtzc_test.rs`
# treats "not board-pq1" as iota2, so its denial probe silently skipped pq1's
# I2C4 (the SE050's own bus) while reporting a pass. Only the gtzc recipe passed
# the board by hand. Two worlds in one image must not disagree about the board.
NS_FEATURES_LIST := $(strip $(foreach f,stm32u585 e2e-test usb iwdg,$(if $(findstring $(f),$(FEATURES)),$(f))) \
  $(if $(findstring stm32u585,$(FEATURES)),$(BOARD_FEATURE)))
comma := ,
empty :=
space := $(empty) $(empty)
NS_FEATURES_ARG = $(if $(NS_FEATURES_LIST),--features $(subst $(space),$(comma),$(NS_FEATURES_LIST)),)

.PHONY: all clean secure nonsecure run play play-hw-display run-hw e2e e2e-hw e2e-erc7730-hw e2e-hw-display e2e-hw-dual-se build-hw flash-hw test test-unit test-solidity test-formal-verification verify-theft-free test-key-speed test-update-hw measure factory-reset optiga-reset-oids flash-hw-optiga-reset verify-pins

# Supply-chain audit. Hard-fails if any dependency is not cryptographically
# pinned (Cargo.lock checksums, git rev= pins, foundry.lock matching
# checked-out submodules, dated-nightly rust-toolchain). See
# tools/verify_pins.sh for the exact rules. Every release-path target
# below depends on this.
verify-pins: ## Certify deployed-bytecode codehash pins
	@tools/verify_pins.sh

all: verify-pins secure nonsecure

secure:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features $(FEATURES)
	@echo "==> Secure world built (features: $(FEATURES))."

nonsecure: secure
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure $(NS_FEATURES_ARG)
	@echo "==> Non-secure world built."

# Run with mock SE (no real secure element needed).
# We attach semihosting to a dedicated stdio chardev so SYS_READC can read
# from the host terminal — this is what the secure UI mock uses to receive
# "button" input ('l'/'h' = short, 'L'/'H' = long).
run: all ## Non-interactive QEMU smoke (mock SE)
	qemu-system-arm \
		-M mps2-an505 \
		-monitor null \
		-serial null \
		-chardev stdio,id=hostio \
		-semihosting-config enable=on,target=native,chardev=hostio \
		-kernel $(SECURE_ELF) \
		-device loader,file=$(NONSECURE_ELF)

# Interactive two-button hardware-wallet emulation. Maps your laptop's
# arrow keys to the two physical buttons:
#   <-           Left button (back / scroll down)
#   ->           Right button (next / scroll up)
#   <- + ->      Confirm (press both arrows together within 150 ms)
#   Esc          Cancel / back
#   Ctrl-C       Quit
# tools/wallet_run.py spawns QEMU under the hood, owns the terminal in
# raw mode, and forwards button events through the existing semihosting
# single-char protocol.
play: all ## Interactive QEMU (arrow-key UI)
	@python3 tools/wallet_run.py

# Interactive two-button wallet on real STM32U585 with SSD1306 OLED display.
# Same arrow-key mapping as `play` (QEMU version), but runs on real hardware.
# Display renders on the physical OLED; button input comes from your laptop
# keyboard via probe-rs semihosting READC.
# Requires: ST-LINK connected, SSD1306 OLED wired to PB8/PB9/3V3/GND.
play-hw-display: ## Interactive OLED + arrow-key forwarding (HW)
	@echo "==> Building secure + nonsecure for interactive OLED play"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-lcd,stm32u585,dev-testkey,gpio-buttons,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Starting interactive wallet (Ctrl-C to quit)..."
	@python3 tools/wallet_run_hw.py

# Interactive two-button wallet on the NV3007 SPI LCD — the PRODUCTION display
# path (`ui-lcd` is the shipping backend as of 2026-06-09). Runs the FULL real
# wizard / PIN / confirm flow (no `lcd-test` short-circuit). Input from the
# physical gpio-buttons (LEFT=PC1/D8, RIGHT=PA8/D9). `ui-lcd` pulls in
# `gpio-buttons` + `spi1-arduino`. Requires: ST-LINK + the NV3007 wired per
# docs/hardware/nv3007-wiring.md (SPI on CN13 D10/D11/D13, DC=PE7/D4, RES→3V3, VCC+BLK→3V3,
# GND) + two buttons on the gpio-buttons pins. The OLED equivalent is
# `play-hw-display` (kept for SSD1306 dev boards).
play-hw-lcd:
	@echo "==> Building secure + nonsecure for interactive LCD play (NV3007)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-lcd,stm32u585,dev-testkey,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Drive the wizard with the physical buttons; streaming logs (Ctrl-C to quit)..."
	@python3 tools/wallet_run_hw.py

# §32 P4/P5 interactive UI test — drive JUST the duress-PIN setup dialogs
# on the real OLED. No SE, no provisioning (mock-se + duress-ui-test
# short-circuits into a dialog loop at boot). Driven by the PHYSICAL
# perfboard buttons (gpio-buttons: LEFT=PC1/D8, RIGHT=PA8/D9; both = OK,
# long-left = cancel) — same input path as `play-hw-display`, so no host
# key-forwarder is needed. wallet_run_hw.py still streams the OLED debug
# lines if you want them.
play-hw-duress-ui:
	@echo "==> Building §32 duress-PIN UI harness (mock-se, dialogs only)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-lcd,stm32u585,dev-testkey,duress-ui-test,gpio-buttons,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Starting interactive duress-UI harness (Ctrl-C to quit)..."
	@python3 tools/wallet_run_hw.py

# One-time chip hardening: set brown-out supervision + SRAM2 auto-erase
# option bytes. Run once per device during provisioning; no need to
# repeat unless the chip has been fully option-byte-reset.
#
# Changes:
#   BOR_LEV   = 3 (~2.7V)   — flash writes abort cleanly below this
#   SRAM2_RST = 0            — silicon erases SRAM2 on every reset
#                              (POR, BOR, SW, watchdog)
#
# Triggers an Option Byte Load (OBL_LAUNCH), which resets the chip.
# Expected side effects: next boot classifies as ResetCause::OptionByte
# in the semihosting log.
#
# After running this once, every subsequent reset hardware-zeroizes
# SRAM2 — put sensitive active-window state there (Stage 2 of the
# brownout hardening roadmap; see docs/security/brownout-hardening.md).
stm32-harden-opts:
	@echo "==> Configuring brown-out supervision + SRAM2 auto-erase"
	@echo "    BOR_LEV=3 (~2.7V), SRAM2_RST=0 (auto-erase on reset)"
	@echo "    This triggers an Option Byte Load — the chip will reset."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes BOR_LEV=3 SRAM2_RST=0
	@echo "==> Option bytes written. Reset triggered. Chip state: hardened."

# Real STM32U585 hardware build (full): real chips + real LCD + real buttons.
# This target only BUILDS — flashing is done with probe-rs / openocd / etc.
run-hw: ## Run on real hardware via probe-rs
	$(MAKE) FEATURES=dual-se,ui-lcd,consumption-mask,stm32u585,legacy-fw-rollback-unsafe all

# Real STM32U585 hardware build (semihosting smoke): mock SE + semihosting UI.
# The `e2e-test` escape is REQUIRED, not optional: this is a RELEASE (debug_assertions
# OFF) stm32u585 build carrying dev-only features (mock-se/debug-log/ui-semihosting),
# which the nsc/mod.rs ship-blocker fences correctly reject without a non-shippable
# marker; `e2e-test` defuses both fences AND short-circuits enter_pin() so the image
# doesn't hang on probe-rs's missing SYS_READC (the CLAUDE.md HW gotcha) — mirrors the
# known-good `test-key-speed` target. Both `e2e-test` and `dev-testkey` are on the CI
# production-OFF denylist, so the image stays un-shippable by construction. For an
# INTERACTIVE hardware session, use `play-hw-lcd` (real LCD + arrow-key buttons).
build-hw: ## Build the real-hardware STM32U585 smoke image (non-shippable)
	$(MAKE) FEATURES=mock-se,debug-log,ui-semihosting,e2e-test,stm32u585 all

# Flash and run on real STM32U585 via probe-rs + OpenOCD.
# Requires: ST-LINK connected, openocd installed.
#
# Workflow:
#   1. Flash both ELFs via probe-rs (it may clear TZEN during flash)
#   2. (Re-)configure TrustZone option bytes via OpenOCD
#   3. Run the secure world with semihosting I/O
#
# The option byte setup (TZEN, SECWM, SECBOOTADD0) only needs to be done
# once after a chip erase. Subsequent flashes can skip step 2 if OBs are
# already configured.
flash-hw: build-hw ## Flash + run on real STM32U585 (probe-rs/OpenOCD)
	probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching (Ctrl-C to quit)..."
	probe-rs reset --chip $(CHIP)
	probe-rs attach --chip $(CHIP) $(SECURE_ELF)

# Non-interactive automated end-to-end test for the sign dispatch logic.
# Builds both worlds with the `e2e-test` cargo feature, runs them in QEMU
# with stdin closed (no semihosting input needed), captures stdout, and
# asserts that the secure-world dispatcher routed each scenario to the
# right TxKind variant + that every scenario returned its expected status
# (positive cases `Ok`; negative binding/framing cases the pinned refusal).
#
# The authoritative scenario list is the `for line in ...` assertion
# block below (Scenarios 0a–6, including every emitted Scenario 5
# sub-scenario currently present in the firmware test driver). It
# covers value transfers, known/unknown ERC-20, blind-sign, slot
# rotation, Safe approveHash / exec clear-sign, selector + self-attest
# + ERC-7730 typed render, atomic batch sign, and Safe-wrapped CoW
# pre-sign, all through on-device native decode.
#
# Pass → exits 0. Any missing assertion or non-zero status → exits 1.
e2e: ## Automated unified-sign E2E (QEMU)
	@echo "==> Building secure + nonsecure with e2e-test feature (QEMU mailbox transport)"
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test
	@echo "==> Running e2e suite under QEMU"
	@# Route semihosting output through a stdio chardev so we see live
	@# progress AND can grep for assertions. `chardev null` (the previous
	@# setting) silently discarded every `hprintln!` line, which masked
	@# real test failures and made hangs invisible. The NS panic handler
	@# uses panic-semihosting's `exit` feature (enabled via the
	@# `e2e-test` cargo feature) so a failed assertion terminates QEMU
	@# instead of looping forever — without that, this target would
	@# never return on any test bug.
	@log=$$(mktemp); \
	qemu-system-arm \
		-M mps2-an505 \
		-monitor null \
		-serial null \
		-nographic \
		-chardev stdio,id=hostio \
		-semihosting-config enable=on,target=native,chardev=hostio \
		-kernel $(SECURE_ELF) \
		-device loader,file=$(NONSECURE_ELF) </dev/null 2>&1 | tee $$log; \
	echo "===================================="; \
	fail=0; \
	for line in \
		"\\[NS\\]\\[e2e\\] Scenario 0a: mismatched single sender is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 0b: mismatched batch sender is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 0c: cross-account sender is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 0d: mismatched single EntryPoint is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 0e: mismatched batch EntryPoint is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 0f: selector-only Safe exec is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 0g: selector-only Safe exec batch is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 0h: canonical Safe exec remains signable" \
		"\\[NS\\]\\[e2e\\] Scenario 1: register slot 1 on chain A" \
		"\\[NS\\]\\[e2e\\] Scenario 2: repeat sign on chain A slot 1" \
		"\\[NS\\]\\[e2e\\] Scenario 3: rotate to slot 2 on chain A" \
		"\\[NS\\]\\[e2e\\] Scenario 4: register slot 1 on chain B" \
		"\\[NS\\]\\[e2e\\] Scenario 5: Safe approveHash clear-sign" \
		"\\[NS\\]\\[e2e\\] Scenario 5b: verified function-selector bundle" \
		"\\[NS\\]\\[e2e\\] Scenario 5v: companion-supplied ERC-20 metadata trailer" \
		"\\[NS\\]\\[e2e\\] Scenario 5w: companion-supplied address-name trailer" \
		"\\[NS\\]\\[e2e\\] Scenario 5c: cross-check rejects mismatched selector" \
		"\\[NS\\]\\[e2e\\] Scenario 5d: typed walker declines, blind-sign fallback" \
		"\\[NS\\]\\[e2e\\] Scenario 5e: atomic batch sign" \
		"\\[NS\\]\\[e2e\\] Scenario 5e-7730: batch ERC-7730 trailer matches + signs" \
		"\\[NS\\]\\[e2e\\] Scenario 5e-rt-erc20: invalid Safe cannot gate ERC-7730 token metadata" \
		"\\[NS\\]\\[e2e\\] Scenario 5e-7730-mismatch: batch mis-bound descriptor is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 5f: degenerate 1-tx batch" \
		"\\[NS\\]\\[e2e\\] Scenario 5g: max-size batch" \
		"\\[NS\\]\\[e2e\\] Scenario 5h: empty batch is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 5i: truncated inner-tx block is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 5j: self-attest typed render" \
		"\\[NS\\]\\[e2e\\] Scenario 5k: self-attest keccak mismatch dropped" \
		"\\[NS\\]\\[e2e\\] Scenario 5l: both selector trailers refused" \
		"\\[NS\\]\\[e2e\\] Scenario 5m: ERC-7730 trailer matches + signs" \
		"\\[NS\\]\\[e2e\\] Scenario 5m-nested: ERC-7730 nested proof set matches + signs" \
		"\\[NS\\]\\[e2e\\] Scenario 5m-multi-tail: ERC-7730 two-string tails match + signs" \
		"\\[NS\\]\\[e2e\\] Scenario 5p: EIP-712 typed sign + binding differential" \
		"\\[NS\\]\\[e2e\\] Scenario 5n: known-call mis-bound descriptor is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 5q: Safe-wrapped CoW presign clear-sign" \
		"\\[NS\\]\\[e2e\\] Scenario 5r: safe-wrapped presign without cow_order is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 5s: multiSend (approve+presign) safe-wrapped CoW clear-sign" \
		"\\[NS\\]\\[e2e\\] Scenario 5t: multiSend with a delegatecall record is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 5u: multiSend presign without cow_order is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 6: brute-force protection" \
		"\\[NS\\]\\[e2e\\] === All scenarios passed! ==="; do \
		if grep -q "$$line" $$log; then \
			echo "  PASS  $$line"; \
		else \
			echo "  MISS  $$line"; \
			fail=1; \
		fi; \
	done; \
	names_region=$$(mktemp); \
	awk '/Scenario 5w:/{capture=1} capture{print} /names bundle verified/{exit}' $$log > $$names_region; \
	for text in \
		"+ Uniswap V3 Rou" \
		" ter" \
		"0xE59242..861564" \
		"0.000001 ETH"; do \
		if ! grep -Fq "$$text" $$names_region; then \
			echo "  MISS  names trailer trusted row: $$text"; \
			fail=1; \
		fi; \
	done; \
	rm -f $$names_region; \
	if ! grep -q "\\[ERC-7730\\] matched: chain=31337 contract=0x34343434..34343434 .* nested=true" $$log; then \
		echo "  MISS  secure nested ERC-7730 dispatch receipt"; fail=1; \
	fi; \
	rt_region=$$(mktemp); \
	awk '/Scenario 5e-rt-erc20:/{capture=1} capture{print} /RT-ERC20 trusted pages complete/{exit}' $$log > $$rt_region; \
	for text in \
		"0x1CDD2EaB611126" \
		"97626F7b4bB0e23D" \
		"a4FeBF7B7C" \
		"0xdAC17F958D2ee5" \
		"23a2206206994597" \
		"C13D831ec7"; do \
		if ! grep -Fq "$$text" $$rt_region; then \
			echo "  MISS  RT-ERC20 trusted row: $$text"; \
			fail=1; \
		fi; \
	done; \
	if [ $$(grep -Fc "Token contract" $$rt_region) -lt 2 ]; then \
		echo "  MISS  RT-ERC20 two exact token-identity pages"; fail=1; \
	fi; \
	if [ $$(grep -Fc "Amount" $$rt_region) -lt 2 ] || [ $$(grep -Fc "USDT" $$rt_region) -lt 2 ]; then \
		echo "  MISS  RT-ERC20 two decoded amount+ticker displays"; fail=1; \
	fi; \
	if grep -Fq "Token (UNVERI" $$rt_region || grep -Fq "Approve Safe TX" $$rt_region; then \
		echo "  FAIL  RT-ERC20 regressed to unverified or Safe-attributed display"; fail=1; \
	fi; \
	rm -f $$rt_region; \
	rm -f $$log; \
	if [ $$fail -eq 0 ]; then \
		echo "==> e2e: ALL ASSERTIONS PASSED"; \
		exit 0; \
	else \
		echo "==> e2e: ASSERTIONS FAILED"; \
		exit 1; \
	fi

# Fully-automated signing benchmark on real STM32U585.
#
# Clocks the MCU to 160 MHz (hw::rcc::init, the default for the stm32u585
# build path) and uses the DWT cycle counter (armed in secure main.rs
# before booting NS) to measure wall-clock time for:
#
#   A) first-sign on a fresh chain  — Type 1 (C11) + slot keygen + Type 2
#   B) 5 x subsequent signs on same chain — Type 2 only (slot cached)
#   C) first-sign on a second chain — another Type 1 data point
#
# The secure crate builds with `e2e-test` so the wallet auto-provisions
# a fixed mnemonic and pre-unlocks the gateway (no PIN UI).  The NS crate
# builds with `bench-key-speed`, which swaps main() for the bench runner
# in `nonsecure/src/bench_key_speed.rs`.
#
# Why this exists: motivates evaluating the SHA-256 hash variant (see
# `docs/SHA256_VARIANT.md`), where the STM32U585 HASH peripheral would
# accelerate signing ~10x vs software Keccak.  This target establishes
# the baseline number.
#
# Requires: ST-LINK connected, $(STM32_PROG) on PATH.
# Pass: exits 0 with "[NS][bench] === PASS ===" on stdout.
# Fail: exits 1 if any sign returns non-Ok or the PASS line is missing.
test-key-speed: ## DWT-timed signing bench on HW
	@echo "==> Building secure (e2e-test auto-provision) + NS (bench-key-speed) + SHA-256 HW accel"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test,stm32u585,hw-sha256,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features bench-key-speed,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running key-speed bench on hardware (160 MHz)..."
	@echo "    (streaming semihosting output; each [NS][bench] line = one measurement)"
	@log=$$(mktemp -t test-key-speed.XXXXXX.log); \
	trap 'rm -f "$$log"' EXIT; \
	rc_file=$$(mktemp -t test-key-speed-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ probe-rs run --chip $(CHIP) $(SECURE_ELF) 2>&1; echo $$? >"$$rc_file"; } | tee "$$log"; \
	rc=$$(cat "$$rc_file"); \
	echo "===================================="; \
	if [ "$$rc" != "0" ] && [ "$$rc" != "130" ]; then \
		echo "==> test-key-speed: FAIL (probe-rs exited $$rc)"; \
		exit 1; \
	fi; \
	if grep -q "\[NS\]\[bench\] === PASS ===" "$$log"; then \
		echo "==> test-key-speed: PASS"; \
		exit 0; \
	else \
		echo "==> test-key-speed: FAIL (missing PASS marker)"; \
		exit 1; \
	fi

# Automated, non-destructive test of the firmware-update (CMD_FW_*)
# logic on real STM32U585 hardware.  NS side runs `fwup_hw_test.rs`,
# which walks every FW_* command through its verify chain and rejects
# paths — including a full-chain "valid-but-rollback-rejected" manifest
# that proves structural + CRC + digest + vendor-fpr all work end-to-end.
#
# WHAT THIS DOES NOT DO (on purpose — both are irreversible / destructive
# to the currently-running firmware on the pre-A/B-split branch):
#
#   * Never calls CMD_FW_COMMIT → no OTP program command is launched.
#     The legacy per-bit tally is invalid on STM32U585 ECC quad-words and is
#     production-fenced; this test neither exercises nor consumes the still-
#     open Draft-1.1 research-candidate epoch-floor backend.
#   * Never lets CMD_FW_BEGIN reach `flash::erase_slot(inactive)`.  On
#     the current linker layout the inactive slot's manifest page (page
#     5 @ 0x0C00_A000) still sits inside the running secure firmware's
#     .text region — erasing it would hard-fault the CPU.  We craft the
#     happy-path test manifest with fw_version=0 so it exercises
#     structural / CRC / digest / fpr checks and then rejects at the
#     rollback-floor gate (fw_version > floor is strict, floor >= 0),
#     which is the last check before `erase_slot` would run.
#
# The only first-boot one-way side-effect is `otp::ensure_device_master`
# (burns the per-device OTP master key on first-boot of a blank MCU —
# this happens on every hardware boot of this firmware, not just this
# target, so there is nothing new here).
#
# Requires: ST-LINK connected, $(STM32_PROG) on PATH.
# Pass: exits 0 with "[NS][fwup-test] === PASS ===" on stdout.
# Fail: exits 1 if any test case fails or the PASS marker is missing.
test-update-hw: ## Firmware-update (CMD_FW_*) E2E on HW (non-destructive)
	@echo "==> Building secure (e2e-test auto-unlock) + NS (fwup-hw-test) + SHA-256 HW accel"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test,stm32u585,hw-sha256,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features fwup-hw-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running firmware-update logic test (safe mode)..."
	@echo "    (no COMMIT, no slot erase — nothing irreversible will happen)"
	@log=$$(mktemp -t test-update-hw.XXXXXX.log); \
	rc_file=$$(mktemp -t test-update-hw-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ probe-rs run --chip $(CHIP) $(SECURE_ELF) 2>&1; echo $$? >"$$rc_file"; } | tee "$$log"; \
	rc=$$(cat "$$rc_file"); \
	echo "===================================="; \
	if [ "$$rc" != "0" ] && [ "$$rc" != "130" ]; then \
		echo "==> test-update-hw: FAIL (probe-rs exited $$rc)"; \
		exit 1; \
	fi; \
	if grep -q "\[NS\]\[fwup-test\] === PASS ===" "$$log"; then \
		echo "==> test-update-hw: PASS"; \
		exit 0; \
	else \
		echo "==> test-update-hw: FAIL (missing PASS marker)"; \
		exit 1; \
	fi

# Same e2e suite but on real STM32U585 hardware via probe-rs semihosting.
# Requires: ST-LINK connected, $(STM32_PROG) on PATH.
# Phase 5 item 8 — ERC-7730 e2e on real STM32U585 hardware. Drives the
# Scenario 5m + 5p clear-signing paths through probe-rs semihosting +
# arrow-key forwarder. Requires the same hardware bench as `e2e-hw`
# plus a UI device for descriptor confirmation. Stubbed — implementation
# defers to the Phase 5+ EIP-712 descriptor mirror landing first so
# Scenario 5p has a happy path to assert against.
e2e-erc7730-hw:
	@echo "HW required — run on STM32U585 host with probe-rs + ST-LINK +"
	@echo "  the Phase 5+ EIP-712 descriptor mirror landed (handoff item 2)."
	@echo "Until then this target fails by design so CI doesn't silently skip"
	@echo "  the hardware parity gate. See docs/archive/handoff-erc7730-phase5.md item 8."
	@false

e2e-hw: ## Unified-sign E2E on real STM32U585 (probe-rs)
	@echo "==> Building e2e + stm32u585"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test,stm32u585,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running e2e on hardware (Ctrl-C to abort)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Same e2e suite on real STM32U585, but with OLED display output.
# The SSD1306 128x64 OLED is driven via I2C1 (PB8=SCL, PB9=SDA).
# Uses ui-lcd instead of ui-semihosting so the UI renders on the
# physical display rather than the probe-rs console.
# Requires: ST-LINK connected, SSD1306 OLED wired to PB8/PB9/3V3/GND.
e2e-hw-display:
	@echo "==> Building e2e + stm32u585 + OLED display"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-lcd,e2e-test,stm32u585,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running e2e on hardware with OLED display (Ctrl-C to abort)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Full sign e2e on real STM32U585 with *both* real SEs (OPTIGA
# Trust M + SE050, XOR-split entropy) driving the SSD1306 OLED.
#
# Exercises the post-cutover stateless-slot flow (Type 1 + Type 2,
# cross-chain slot rotation) end-to-end through real silicon:
#   * dual-se   — OPTIGA + SE050 XOR-split provision + unlock
#   * ui-lcd   — status on the physical SSD1306 (PB8=SCL, PB9=SDA)
#   * e2e-test  — auto-provisions fixed mnemonic + PIN, pre-unlocks
#                 the gateway (probe-rs cannot serve SYS_READC)
#   * otp-hardcoded-master-key — avoids burning real OTP each run
#                                (same choice as dual-se-admin-wipe-e2e)
#
# Requires: ST-LINK, $(STM32_PROG), OPTIGA Trust M + SE050 on
# the I2C bus, SSD1306 OLED wired to PB8/PB9/3V3/GND.
#
# Watch semihosting for "[NS][e2e] === All scenarios passed! ===".
# OLED will show "e2e Sign N/4" + "T1+T2"/"T2 only" on each sign.
e2e-hw-dual-se:
	@echo "==> Building e2e + stm32u585 + dual-SE (OPTIGA + SE050) + OLED"
	@echo "    WARNING: re-provisions wallet state on BOTH chips with the"
	@echo "    fixed e2e test mnemonic (abandon × 23 || art, PIN 00000000)."
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features dual-se,ui-lcd,debug-log,e2e-test,e2e-skip-admin-wipe,stm32u585,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running dual-SE e2e on hardware..."
	@echo "    (streaming semihosting; looks for 'All scenarios passed!'"
	@echo "     then exits — hit Ctrl-C if it hangs past 2 min)"
	@log=$$(mktemp -t e2e-hw-dual-se.XXXXXX.log); \
	rc_file=$$(mktemp -t e2e-hw-dual-se-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ timeout 300 probe-rs run --chip $(CHIP) $(SECURE_ELF) 2>&1; \
	  echo $$? >"$$rc_file"; } | tee "$$log"; \
	rc=$$(cat "$$rc_file"); \
	echo "===================================="; \
	if grep -q "All scenarios passed!" "$$log"; then \
		echo "==> e2e-hw-dual-se: PASS"; \
		exit 0; \
	elif grep -q "PANIC\|FAIL" "$$log"; then \
		echo "==> e2e-hw-dual-se: FAIL (see log above)"; \
		exit 1; \
	else \
		echo "==> e2e-hw-dual-se: FAIL (no PASS/FAIL marker; rc=$$rc)"; \
		exit 1; \
	fi

# GTZC1 TZSC + TZIC enforcement validation on real STM32U585 silicon.
#
# Production gate for invariant #4 ("all secrets live ONLY in TrustZone
# secure world"). NS probes each peripheral the secure-world boot path
# marked SECURE in `secure/src/sau.rs` (I2C1/2, AES, HASH, RNG, PKA,
# SAES) via its NS-aliased control register. Each access should be
# RAZ-gated by the AHB bridge and raise NVIC IRQ 8 (GTZC), bumping the
# secure-world `hw::tzic::VIOLATION_COUNT`. The NS driver reads the
# counter back via `nsc_tzic_status` CMSE veneer and asserts.
#
# Secure side:
#   mock-se          — skips dual-SE provisioning (we're not signing)
#   ui-semihosting   — secure-side `[S][TZIC]` lines come out on probe-rs
#   debug-log        — `secure_log!` enabled
#   e2e-test         — pre-unlock + exposes `nsc_tzic_status` veneer
#   stm32u585        — real GTZC1 (not the QEMU MPC fallback)
#   otp-hardcoded-master-key — stable OTP master across re-flashes
#
# NS side:
#   gtzc-test        — replaces interactive main() with probe + assert
#   stm32u585        — real hardware target
#
# Greps for `[NS][gtzc] === PASS ===` on stdout; missing marker = FAIL.
#
# Requires: ST-LINK on B-U585I-IOT02A. Non-destructive (no SE writes,
# no PIN attempts). Safe to re-run.
# Non-destructive secure-element address probe.
#
# Answers exactly one question per chip: does it ACK its I2C address? Every
# probe is a ZERO-DATA-BYTE transfer (NBYTES=0 + AUTOEND), so not one payload
# byte reaches either part — no register pointer, no APDU, no T=1' frame, no
# lifecycle transition. That is the whole point: on a production board the
# OPTIGA is virgin and its pairing/lifecycle steps are irreversible, so this
# is the one SE check that is safe to run on hardware you cannot replace.
#
# It runs BEFORE anything else addresses the buses, right after
# `hw::se_power::init()` brings up the SE rail, so on pq1 it also proves the
# LDO2_EN path. Reads back the GPIO AF nibbles too, which is what separates
# "configured right, nobody answered" from "AF typo put the SE050 on the
# OPTIGA bus".
#
# Reading a failure:
#   both addresses NACK   -> VDD1_3V3 never rose; check LDO2_EN (PA8), meter it
#   only 0x48 NACKs       -> SE1_EN (PB5), or probed before the SE050 booted
#   only 0x30 NACKs       -> I2C1 pins/AF, or SE_RST
#   ACK on a late attempt -> part is fine, settle time is short
#
#   make se-i2c-probe-hw BOARD=pq1
# Bench-only SSD1306 OLED over BIT-BANGED I2C.
#
# Exists because the pq1 board exposes almost nothing — a 2x5 debug header and
# four pads — so until the NV3007 panel is fitted there is no way to see the
# trusted UI on the device itself. It validates NOTHING about the shipping
# display path (different bus, driver, geometry), and while a debugger is
# attached `ui-semihosting` shows the identical 16x4 text for free. It wins
# only untethered, or at RDP >= 1 where SWD and semihosting are both gone.
#
# Wiring (pq1) — three of four connections are on the debug header:
#     OLED VCC -> header VDD        OLED SCL -> header SWO  (PB3)
#     OLED GND -> header GND        OLED SDA -> RX pad      (PA3)
#
# Those are the only two free GPIOs the board brings out, and no I2C
# peripheral can reach the pair (PB3's AF4 is I2C1_SDA — the OPTIGA's
# peripheral — and PA3 has no I2C AF at all), hence software I2C.
#
# The driver auto-probes 0x3C then 0x3D and skips cleanly if neither answers,
# so a wrong-address module shows up in the log rather than hanging.
#
#   make oled-bench-hw BOARD=pq1
oled-bench-hw: ## Bench SSD1306 over bit-banged I2C on PB3/PA3 (HW)
	@echo "==> Building bench OLED image ($(BOARD_FEATURE), bit-banged I2C)"
	@echo "    Wiring: VCC->VDD  GND->GND  SCL->SWO(PB3)  SDA->RX pad(PA3)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,ui-oled-bench,gpio-buttons,debug-log,dev-testkey,stm32u585,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running (Ctrl-C to quit). Look for '[S][OLED] found display at 0x..'"
	@echo "    'no display at 0x3C/0x3D' => check wiring, or the module is at another address"
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

se-i2c-probe-hw: ## Non-destructive SE I2C address probe: does each chip ACK? (HW)
	@echo "==> Building SE I2C probe (dual-se + se-i2c-probe + $(BOARD_FEATURE))"
	@echo "    NOTE: read-only. Zero data bytes reach either secure element."
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features dual-se,ui-semihosting,debug-log,e2e-test,stm32u585,otp-hardcoded-master-key,se-i2c-probe,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Probing secure-element buses on hardware..."
	@log=$$(mktemp -t se-i2c-probe.XXXXXX.log); \
	rc_file=$$(mktemp -t se-i2c-probe-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ timeout 120 probe-rs run --chip $(CHIP) $(SECURE_ELF) 2>&1; \
	  echo $$? >"$$rc_file"; } | tee "$$log"; \
	echo "===================================="; \
	if grep -q "\[S\]\[se-probe\] === PASS ===" "$$log"; then \
		echo "==> se-i2c-probe-hw: PASS — every expected SE address acknowledged"; \
		exit 0; \
	elif grep -q "\[S\]\[se-probe\] === FAIL ===" "$$log"; then \
		echo "==> se-i2c-probe-hw: FAIL — see the per-address lines above."; \
		echo "    both NACK => meter VDD1_3V3 (LDO2_EN/PA8 never enabled the rail)"; \
		exit 1; \
	else \
		echo "==> se-i2c-probe-hw: INCONCLUSIVE — no probe verdict in the log."; \
		echo "    The image may not have reached the probe; check for an earlier halt."; \
		exit 1; \
	fi

gtzc-enforcement-hw: ## 7/7 secure-peripheral RAZ-fault on NS access (HW)
	@echo "==> Building GTZC1 enforcement test (secure + stm32u585 + e2e-test + mock-se)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,ui-semihosting,debug-log,e2e-test,stm32u585,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@echo "==> Building GTZC1 enforcement test (NS + gtzc-test + stm32u585)"
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features gtzc-test,stm32u585,,$(BOARD_FEATURE)$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running GTZC enforcement validation on hardware..."
	@log=$$(mktemp -t gtzc-enforcement-hw.XXXXXX.log); \
	rc_file=$$(mktemp -t gtzc-enforcement-hw-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ timeout 120 probe-rs run --chip $(CHIP) $(SECURE_ELF) 2>&1; \
	  echo $$? >"$$rc_file"; } | tee "$$log"; \
	rc=$$(cat "$$rc_file"); \
	echo "===================================="; \
	if grep -q "\[NS\]\[gtzc\] === PASS ===" "$$log"; then \
		echo "==> gtzc-enforcement-hw: PASS — GTZC1 TZSC + TZIC enforcement confirmed"; \
		exit 0; \
	elif grep -q "\[NS\]\[gtzc\] === FAIL" "$$log"; then \
		echo "==> gtzc-enforcement-hw: FAIL — violation counter mismatch (see log above)"; \
		exit 1; \
	else \
		echo "==> gtzc-enforcement-hw: FAIL (no PASS/FAIL marker; rc=$$rc)"; \
		exit 1; \
	fi

# Slice 2 demo: GTZC1 illegal-access → wipe escalation on real
# STM32U585 silicon.
#
# Builds with `tzic-wipe` ON in the secure crate. NS does a single
# probe of HASH_CR's NS alias; the TZIC IRQ fires, runs
# `hw::tzic::trigger_tzic_wipe()` (zeroize SRAM → arm page-125 wipe
# flag → SCB::sys_reset). The NS driver never reaches its
# `SURVIVED` log line — its absence is the pass marker.
#
# probe-rs note: `probe-rs run` arms vector-catch-on-reset, so a
# successful `SCB::sys_reset` from the IRQ is intercepted and
# surfaces as "Firmware exited unexpectedly: Exception" rather
# than a clean reboot loop. That's the EXPECTED success state for
# this harness — the chip *did* reset, probe-rs just caught it.
# On stand-alone power-up the chip reboots normally and the boot-
# time wipe-resume path drives the full SE wipe.
#
# Pass criteria (host-side):
#   * `[NS][gtzc-wipe] probing`  appears exactly 1 time
#   * `[NS][gtzc-wipe] SURVIVED` appears 0 times (wipe preempted)
#
# Side-effect: leaves the page-125 wipe-armed flag set. Subsequent
# boots of a `se050` or `dual-se` build will finish the SE wipe on
# the next boot. Run `make wipe-for-wizard` to clear deliberately,
# or any normal e2e target that includes `factory_reset_admin`.
#
# Requires: ST-LINK on B-U585I-IOT02A.
tzic-wipe-hw:
	@echo "==> Building TZIC wipe demo (secure + stm32u585 + tzic-wipe + e2e-test + mock-se)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,ui-semihosting,debug-log,e2e-test,stm32u585,otp-hardcoded-master-key,tzic-wipe,$(BOARD_FEATURE)
	@echo "==> Building TZIC wipe demo (NS + tzic-wipe-test + stm32u585)"
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features tzic-wipe-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running TZIC wipe demo on hardware (30 s probe-then-reset)..."
	@log=$$(mktemp -t tzic-wipe-hw.XXXXXX.log); \
	trap 'rm -f "$$log"' EXIT; \
	timeout 30 probe-rs run --chip $(CHIP) $(SECURE_ELF) 2>&1 | tee "$$log" || true; \
	probes=$$(grep -c '\[NS\]\[gtzc-wipe\] probing' "$$log" || true); \
	survived=$$(grep -c '\[NS\]\[gtzc-wipe\] SURVIVED' "$$log" || true); \
	reset_seen=$$(grep -c 'Exception\|Firmware exited' "$$log" || true); \
	echo "===================================="; \
	echo "==> Observed: probes=$$probes  survived=$$survived  reset_intercepted=$$reset_seen"; \
	if [ "$$survived" -gt 0 ]; then \
		echo "==> tzic-wipe-hw: FAIL — saw SURVIVED line; IRQ did not preempt"; \
		exit 1; \
	elif [ "$$probes" -ge 1 ] && [ "$$reset_seen" -ge 1 ]; then \
		echo "==> tzic-wipe-hw: PASS — TZIC IRQ ran wipe path and chip reset (probe-rs intercepted)"; \
		exit 0; \
	else \
		echo "==> tzic-wipe-hw: FAIL — probes=$$probes reset_seen=$$reset_seen"; \
		exit 1; \
	fi

# Real STM32U585 hardware build with USB HID host communication.
# Uses mock SE + semihosting debug output + USB transport.
build-hw-usb:
	$(MAKE) FEATURES=mock-se,debug-log,ui-semihosting,stm32u585,usb all

# USB build with auto-provisioning for standalone testing.
# No debug-log (semihosting BKPT faults without debugger attached).
# Secure world: e2e-test auto-provisions, ui-semihosting for compile compat.
# NS world: usb feature for USB HID main loop.
build-hw-usb-test:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features mock-se,ui-noop,stm32u585,usb,e2e-test,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> USB test build ready (auto-provisioned, no semihosting)."

# Flash auto-provisioned USB build.
flash-hw-usb-test: build-hw-usb-test
	probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching (Ctrl-C to quit)..."
	probe-rs reset --chip $(CHIP)
	probe-rs attach --chip $(CHIP) $(SECURE_ELF)

# mock-se USB build WITH debug-log — boot-trace the USB path over probe-rs
# semihosting (does boot reach USB init / does it fault?). Diagnostic only.
build-hw-usb-test-debug:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features mock-se,ui-noop,stm32u585,usb,e2e-test,debug-log,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> mock-se USB test (debug) build ready."

# SE050 + USB build with auto-provisioning for testing.
# Secure world: se050 (real SE via I2C1), ui-noop, USB hardware init, e2e-test auto-provision.
# NS world: usb feature for USB HID main loop.
build-hw-se050-usb-test:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,ui-noop,stm32u585,usb,e2e-test,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> SE050 + USB test build ready."

flash-hw-se050-usb-test: build-hw-se050-usb-test
	probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching (Ctrl-C to quit)..."
	probe-rs reset --chip $(CHIP)
	probe-rs attach --chip $(CHIP) $(SECURE_ELF)

# SE050 + USB test with semihosting debug output (requires probe-rs attach).
build-hw-se050-usb-test-debug:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,ui-noop,stm32u585,usb,e2e-test,debug-log,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> SE050 + USB test (debug) build ready."

flash-hw-se050-usb-test-debug: build-hw-se050-usb-test-debug
	probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching with semihosting (Ctrl-C to quit)..."
	probe-rs reset --chip $(CHIP)
	probe-rs attach --chip $(CHIP) $(SECURE_ELF)

# Real SE050 + GPIO hardware buttons + semihosting display.
# The SE050 runs over I2C1 (PB8/PB9 on the Arduino shield), buttons on
# CN13 D8/D9 jumper wires, and the UI renders via probe-rs semihosting.
# Interactive: PIN entry, seed wizard, signing — all on real hardware.
flash-hw-se050-buttons:
	@echo "==> Building SE050 + GPIO buttons + semihosting UI"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,debug-log,ui-semihosting,stm32u585,usb,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running SE050 + buttons wallet (Ctrl-C to quit)..."
	@echo "    LEFT=CN13 pin1 (D8), RIGHT=CN13 pin2 (D9), GND=CN13 pin7"
	probe-rs run --chip $(CHIP) $(SECURE_ELF)

# GPIO button test: scan Arduino header pins, then test debounced events.
# Requires: jumper wires on CN14 (D8=LEFT, D9=RIGHT, pin7=GND).
button-test:
	@echo "==> Building GPIO button test firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features button-test,debug-log,ui-semihosting
	@echo "==> Flashing button test firmware..."
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Running button test (Ctrl-C to quit)..."
	probe-rs run --chip $(CHIP) $(SECURE_ELF)

# STSAFE-A110 I2C2 bus probe: detect on-board secure element.
# Scans I2C2 (PH4/PH5) for the STSAFE-A110 at 0x20 and any other devices.
stsafe-probe:
	@echo "==> Building STSAFE-A110 I2C2 probe firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features stsafe-probe,debug-log,ui-semihosting
	@echo "==> Flashing probe firmware..."
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Running I2C2 bus scan (Ctrl-C to quit)..."
	probe-rs run --chip $(CHIP) $(SECURE_ELF)

# SE050 factory reset: wipe all objects, then halt.
# Run this once to clear stale SE050 state, then flash normal firmware.
# The firmware sweeps UserIDs 0x7B10_0000 (current v6 range), 0x7B0E_0000,
# 0x7B06_0000, 0x7B00_2000 (legacy) against PINs {00000000, 12345678,
# 11111111}. Each wrong attempt consumes one of the SE050's 10 PIN tries
# against that UserID; a correct PIN auto-resets the counter. Status
# reported on LCD + semihosting: clean / wrong-PIN / blocked.
#
# Feature notes: this is a hardware (stm32u585) release image, so it MUST
# carry `dev-testkey` to clear the `nsc/mod.rs` ship-blocker fences
# (debug-log / factory-default-SCP03 / consumption-mask) — the same fences
# the normal `*-standalone-debug` builds satisfy. It also needs `usb` so
# `hw::usb_hw` (referenced unconditionally by cmd_fw_begin/commit) compiles.
# `dev-testkey` substitutes the OTP master with the same compile-time
# constant the bench firmware uses, so the SCP03 channel + admin keys match
# the provisioned chip. The wipe itself only needs the user PIN, not admin.
se050-reset:
	@echo "==> Building SE050 factory-reset firmware..."
	@echo "    Sweeps UserIDs {0x7B10_0000, 0x7B0E_0000, 0x7B06_0000, 0x7B00_2000}"
	@echo "    against dev PINs {00000000, 12345678, 11111111}."
	@# Redirect the CMSE import-library to a reset-specific path so this
	@# secure relink does NOT clobber the shared $(VENEERS). Otherwise a
	@# later cache-HIT `flash-hw-*` (secure not rebuilt → veneers.o NOT
	@# regenerated) would link the NS image against THIS build's veneer
	@# addresses → NS calls land on non-SG addresses → SecureFault INVEP
	@# at the first gateway call. (Hit on bench board #1, 2026-06-29.)
	$(RUSTFLAGS_VAR)="$(subst $(VENEERS),$(CURDIR)/target/veneers-se050-reset.o,$(RUSTFLAGS_SECURE_HW))" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features se050-factory-reset,dev-testkey,ui-lcd,stm32u585,usb,debug-log,$(BOARD_FEATURE)
	@echo "==> Flashing reset firmware..."
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Running factory reset (150s timeout; watch LCD + semihosting for clean/wrong-PIN/blocked)..."
	@echo "    (heavily-reused bench chips hold many objects; the authenticated"
	@echo "     pass + UserID self-delete can take a while across all UserID/PIN combos)"
	-@timeout 150 probe-rs run --chip $(CHIP) $(SECURE_ELF) || true
	@echo "==> Reset run finished. Re-flash normal firmware, e.g.:"
	@echo "      make flash-hw-dual-se-lcd-standalone-debug"

# Full device factory reset: wipe every piece of persistent state that
# accumulates during provisioning + signing, so the device returns to a
# fresh unprovisioned state (as if it had just come off the programming
# line).
#
# What gets wiped:
#   * SE050 data objects — entropy half_E, UserID/PIN, gated objects.
#     Reuses the se050-factory-reset firmware (assumes dev PIN in
#     {00000000, 12345678, 11111111}; a wrong guess consumes one of the
#     SE050's 10 PIN attempts).
#   * All STM32 secure flash — mass-erased via $(STM32_PROG),
#     which clears:
#       - page 124 — MCU PIN-attempt counter (one programmed QW per
#                    attempt; capacity 32, lockout at 10)
#       - page 125 — SE050 admin PIN + crash-safety wipe flag
#       - page 126 — DHUK-wrapped SE050 BHK when `bhk` is enabled
#       - page 127 — first-boot provisioning journal (KEY_PAGE)
#     plus all firmware code — so you WILL need to re-flash afterwards.
#
# What does NOT get wiped:
#   * OPTIGA Trust M internal objects (half_O, auth refs). The firmware
#     currently has no OPTIGA reset path. The PBS bytes are not stored verbatim,
#     but the `rdp2-self-lock` final PBS depends on the salt in page 127; erasing
#     it makes that OPTIGA pairing unrecoverable. Erasing page 126 likewise
#     loses the wrapped SE050 BHK and its final pairing. Both chips still retain
#     their internal objects until an authenticated reset reaches them.
#   * Option bytes (TZEN / SECWM / SECBOOTADD0). Those survive mass
#     erase and the normal flash-hw-* targets re-assert them anyway.
#
# Prompts for confirmation. Requires ST-LINK connected and
# $(STM32_PROG) on PATH.
factory-reset: ## Full device factory reset — wipe all persistent state (HW)
	@echo "==> FACTORY RESET"
	@echo "    Wipes: SE050 data objects + all STM32 flash (pages 123-127 + firmware)"
	@echo "    You MUST re-flash firmware afterwards — the chip will be blank."
	@printf "    Proceed? [y/N] "; \
		read ans; \
		[ "$$ans" = "y" ] || [ "$$ans" = "Y" ] || { echo "    Aborted."; exit 1; }
	@echo ""
	@echo "==> Step 1/2: building + running SE050 factory-reset firmware"
	@echo "    (20s timeout — proceeds even if SE050 isn't attached)"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features se050-factory-reset,ui-noop,stm32u585,debug-log,$(BOARD_FEATURE)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	-@timeout 20 probe-rs run --chip $(CHIP) $(SECURE_ELF) || true
	@echo ""
	@echo "==> Step 2/2: STM32 mass-erase (wipes all flash pages + firmware)"
	@$(STM32_PROG) --connect port=SWD mode=UR -e all
	@echo ""
	@echo "==> Factory reset complete. Chip is blank."
	@echo "    Re-flash firmware to use the device again, e.g.:"
	@echo "      make flash-hw-se050-oled-standalone   # SE050 + OLED, production"
	@echo "      make flash-hw-optiga-oled-standalone  # OPTIGA Trust M + OLED (LcsO=Creation)"
	@echo "      make optiga-factory-reset-hw          # OPTIGA wipe -> next boot = fresh wizard"
	@echo "      make optiga-preprovision-hw           # OPTIGA pre-provisioned w/ PIN=00000000"
	@echo "      make flash-hw-se050-usb-test          # SE050 + USB, auto-provisioned test"

# SE050 factory-reset roundtrip e2e test on real hardware.
# Provisions a fresh test UserID + 2 gated data objects, exercises
# user_factory_reset, then verifies all three objects are gone.
# Uses test object IDs (0x7B07_xxxx) so it doesn't touch any real
# wallet provisioning. Repeatable on the same chip.
# Watch semihosting for "[E2E] FACTORY-RESET ROUNDTRIP: PASS"/"FAIL".
se050-reset-e2e: ## SE050 factory-reset roundtrip (HW)
	@echo "==> Building SE050 reset-roundtrip e2e firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050-reset-e2e,ui-noop,stm32u585,debug-log,$(BOARD_FEATURE)
	@echo "==> Flashing e2e firmware..."
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Running e2e (watch semihosting output)..."
	probe-rs run --chip $(CHIP) $(SECURE_ELF)

# SE050 crash-safety (power-loss mid-wipe) e2e test.
# Two-phase: phase 1 provisions test objects at 0x7B0A_xxxx, writes a
# test admin PIN to flash page 125, arms the wipe flag, deletes ONLY
# the data object, halts. User/Makefile resets the board, simulating
# power loss. Phase 2 boots, detects armed flag, verifies expected
# mid-wipe state, finishes the wipe, erases page 125, reports PASS.
# WARNING: overwrites flash page 125 admin PIN. Only run on a chip
# that hasn't been through first-boot wizard on production firmware.
# Watch semihosting for "PHASE 2 — CRASH-SAFETY RESUME: PASS"/"FAIL".
se050-crash-safety-e2e:
	@echo "==> Building SE050 crash-safety e2e firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050-crash-safety-e2e,ui-noop,stm32u585,debug-log,$(BOARD_FEATURE)
	@echo "==> Flashing crash-safety firmware..."
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo ""
	@echo "==> PHASE 1: provision + partial wipe + halt"
	@echo "    (Watching for 'PHASE 1 COMPLETE' — 30s timeout)..."
	-timeout 30 probe-rs run --chip $(CHIP) $(SECURE_ELF) || true
	@echo ""
	@echo "==> Resetting board (simulated power cycle)..."
	probe-rs reset --chip $(CHIP)
	@echo ""
	@echo "==> PHASE 2: boot-time resume"
	@echo "    (Watching for 'CRASH-SAFETY RESUME: PASS' — 30s timeout)..."
	-timeout 30 probe-rs run --chip $(CHIP) $(SECURE_ELF) || true

# SE050 admin-auth wipe e2e test.
# Exercises the exact path PIN-lockout factory reset uses: admin UserID
# auth deleting user-gated objects without knowing the user PIN. Uses
# OID range 0x7B09_xxxx so it doesn't touch real provisioning or the
# user-reset e2e range (0x7B07_xxxx). Repeatable on the same chip.
# Watch semihosting for "[E2E-ADMIN] ADMIN-WIPE ROUNDTRIP: PASS"/"FAIL".
se050-admin-wipe-e2e:
	@echo "==> Building SE050 admin-wipe e2e firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050-admin-wipe-e2e,ui-noop,stm32u585,debug-log,e2e-test,$(BOARD_FEATURE)
	@echo "==> Flashing admin-wipe e2e firmware..."
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Running admin-wipe e2e (watch semihosting output)..."
	probe-rs run --chip $(CHIP) $(SECURE_ELF)

# ---------------------------------------------------------------------------
# SE050 on-silicon stress-test harness — `make se050-stress*`
# ---------------------------------------------------------------------------
# Catalog-driven runner that exercises the SE050 driver against real
# silicon. Tests live under `secure/src/se050_stress/tests/*.rs`;
# adding one is a function + a `stress_test!` macro line + a one-row
# append to `secure/src/se050_stress/tests/mod.rs::ALL_TESTS`. No
# Cargo.toml / Makefile edits per test.
#
# Output channel: `secure_log!` semihosting (probe-rs stdout). The
# recipes scrape the log for `=== SUMMARY: P PASS / F FAIL / S SKIP ===`
# and exit 0 only when F=0.
#
# Carve-out OIDs `0x7B5F_*`; production `0x7B10_*` is never touched.
# Prereq: board has been through `make flash-hw-dual-se-oled-standalone`
# at least once so TrustZone option bytes are set. The recipes below
# do NOT reconfigure them.
#
# `make se050-stress`              — run all Tier::Safe tests
# `make se050-stress-destructive`  — Safe + Destructive (drives UserID
#                                    attempt counters to lockout)
# `make se050-stress-only-<name>`  — single test by name (rebuilt with
#                                    SE050_STRESS_ONLY filter)
# `make se050-stress-list`         — host-side catalog dump (no flash)

SE050_STRESS_FEATURES = se050-stress,ui-lcd,stm32u585,debug-log,e2e-test,otp-hardcoded-master-key,usb,$(BOARD_FEATURE)

# Cache-bust the secure-crate build whenever the SE050_STRESS_* env vars
# change. cargo doesn't include env vars in its fingerprint, so without
# this a re-run with a different filter would silently reuse the prior
# binary. `date +%s` makes every invocation a distinct cfg flag.
#
# Name-only cfg (no `=value`): rustc nightly (≥2026-04 verified) rejects
# `--cfg=name=value` unless the value is a quoted string, and the double
# quotes get stripped by the shell when the variable is interpolated
# inside the recipe's `RUSTFLAGS="..."` assignment. A name-only cfg
# avoids the quoting tangle entirely while still being a unique-per-
# second cargo fingerprint input — the cfg name itself is never queried
# in source code, it just exists to invalidate the build cache.
SE050_STRESS_RUSTFLAGS = $(RUSTFLAGS_SECURE_HW) --cfg=stress_build_$(shell date +%s)

.PHONY: se050-stress se050-stress-destructive se050-stress-list

# Common pass/fail scrape — runs probe-rs, captures stdout, returns
# 0 iff `=== SUMMARY:` appears AND the FAIL count is 0. Parameterised
# so all three recipes share the same shell logic.
#  $(1) = display label
define SE050_STRESS_RUN
	@log=$$(mktemp); rc_file=$$(mktemp); \
	{ timeout 1200 probe-rs run --chip $(CHIP) $(SECURE_ELF) 2>&1; echo $$? >"$$rc_file"; } | tee "$$log"; \
	rc=$$(cat "$$rc_file"); \
	if ! grep -q "=== SUMMARY:" "$$log"; then \
		echo "==> $(1): FAIL (no SUMMARY line, probe-rs rc=$$rc, log=$$log)"; exit 1; \
	fi; \
	fail_count=$$(grep "=== SUMMARY:" "$$log" | head -1 | sed -E 's/.* ([0-9]+) FAIL .*/\1/'); \
	if [ "$$fail_count" = "0" ]; then \
		echo "==> $(1): PASS"; rm -f "$$log" "$$rc_file"; exit 0; \
	fi; \
	echo "==> $(1): FAIL ($$fail_count test failures, probe-rs rc=$$rc, log=$$log)"; exit 1
endef

# Run the full Tier::Safe catalog.
se050-stress: ## SE050 on-silicon stress catalog (HW)
	@echo "==> Building SE050 stress firmware (Tier::Safe)..."
	$(RUSTFLAGS_VAR)="$(SE050_STRESS_RUSTFLAGS)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features $(SE050_STRESS_FEATURES)
	@echo "==> Flashing stress firmware..."
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Running stress catalog (watch semihosting output)..."
	$(call SE050_STRESS_RUN,se050-stress)

# Run Safe + Destructive tiers (includes UserID-lockout tests).
se050-stress-destructive:
	@echo "==> Building SE050 stress firmware (Safe + Destructive)..."
	SE050_STRESS_TIER=destructive \
	$(RUSTFLAGS_VAR)="$(SE050_STRESS_RUSTFLAGS)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features $(SE050_STRESS_FEATURES)
	@echo "==> Flashing stress firmware..."
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Running stress catalog (Safe + Destructive)..."
	$(call SE050_STRESS_RUN,se050-stress-destructive)

# Single-test runner — pattern target. Usage:
#   make se050-stress-only-scp03_response_encryption_verify
# Selection happens at build time via `SE050_STRESS_ONLY=<name>`,
# baked into the firmware through `option_env!`. The Tier filter is
# also disabled (`all`) so destructive single-test runs work without
# the user remembering to flip a second flag.
se050-stress-only-%:
	@echo "==> Building SE050 stress firmware (single: $*)..."
	SE050_STRESS_ONLY="$*" SE050_STRESS_TIER=all \
	$(RUSTFLAGS_VAR)="$(SE050_STRESS_RUSTFLAGS)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features $(SE050_STRESS_FEATURES)
	@echo "==> Flashing stress firmware..."
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Running stress test '$*' (watch semihosting output)..."
	$(call SE050_STRESS_RUN,se050-stress-only-$*)

# Host-side catalog listing — no hardware, no flash. Greps the seed
# catalog files for `stress_test!(IDENT, "name", Tier::X, …)` lines
# and prints them as "[tier] name".
se050-stress-list:
	@echo "==> SE050 stress catalog:"
	@grep -hE '^[[:space:]]*stress_test!\(' secure/src/se050_stress/tests/*.rs 2>/dev/null \
		| sed -E 's/^[[:space:]]*stress_test!\([A-Z0-9_]+,[[:space:]]*"([^"]+)",[[:space:]]*Tier::([A-Za-z]+).*/[\2]\t\1/' \
		| sort -k1,1 -k2,2 \
		| awk -F'\t' '{printf "  %-14s %s\n", $$1, $$2}' \
		|| echo "  (no tests found)"

# SE050 SCP03 platform-key rotation ceremony (work-todo #20 Stage B).
#
# *** IRREVERSIBLE — DO NOT RUN ON A WORKING BENCH SE050 ***
# One-shot GP PUT KEY: replaces SCP03 keyset 0x0B in place with this
# device's derived keys (secret_keys::se050_scp03_*_key, BHK-rooted), then
# halts. The published AN12436 factory keys are GONE after this — the chip
# only opens with firmware that re-derives the matching keys, so:
#  - on a board that ever gets RDP-regressed, the BHK is mass-erased => dead
#    SE050 => half_E unrecoverable. SACRIFICIAL BENCH/FACTORY EVIDENCE ONLY;
#    this deterministic path is not the production-final fresh-TRNG rotation.
#    Never flash it to a board you still RDP-bounce or intend to ship.
#  - the PUT KEY APDU framing in scp03::build_put_key_apdu is best-effort
#    from GP 2.3 / AN12436 -- VALIDATE ON SACRIFICIAL PARTS before any real
#    provisioning run (the chip recomputes the KCV/fields and rejects on
#    mismatch, so a rehearsal that returns SW=0x9000 is the real proof).
# Pre-conditions: RDP already at >=1 (so the BHK is its final per-die-DHUK
# value), BHK provisioned, chip factory-fresh. See docs/archive/production-todo-retired-2026-07-19.md
# §"SE050 - SCP03 + ADMIN provisioning" + docs/archive/work-todo-retired-2026-07-19.md #20.
# Watch the OLED / semihosting for "[SCP03-ROTATE] PUT KEY OK" / "FAIL".
# SE050 SCP03-rotation ceremony feature set (single source of truth — consumed
# by the flash target below AND the `se050-scp03-axis-parity` gate, finding F7,
# so the two can never drift). `bhk` keeps the Tier-2 split (owner decision
# 2026-07-14: SE050 on BHK, OPTIGA PBS on DHUK).
SE050_ROTATE_FEATURES := se050-rotate-scp03,bhk,stm32u585,ui-lcd,debug-log,e2e-test,$(BOARD_FEATURE)

.PHONY: se050-scp03-axis-parity
se050-scp03-axis-parity: ## F7: SE050 SCP03 ceremony-vs-ship key-derivation axis parity gate
	@echo "==> [F7] SE050 SCP03 key-derivation axis parity (ceremony vs ship):"
	@python3 tools/check_se050_scp03_axis_parity.py "$(SE050_ROTATE_FEATURES)" "$(PROD_SHIP_FEATURES)"

flash-hw-se050-rotate-scp03:
	@echo "==> *** IRREVERSIBLE SCP03 KEY ROTATION -- Ctrl-C now if this is your working bench SE050 ***"
	@echo "==> Building SE050 SCP03-rotation ceremony firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features $(SE050_ROTATE_FEATURES)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running SCP03 rotation ceremony (watch for [SCP03-ROTATE] PUT KEY OK)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# SE050 admin-extract-attempt e2e — NEGATIVE security test.
# Falsifies the load-bearing claim that the two-entry TAG_POLICY (user →
# READ|WRITE|DELETE, admin → DELETE only) is silicon-enforced. Provisions
# a 32-B sentinel on isolated OID range 0x7B0B_xxxx under user-PIN gating,
# then:
#   step 3: user-auth READ must return the sentinel (test setup valid)
#   step 4: admin-auth READ must be REFUSED  ← the security property
#   step 5: same admin session DELETEs all 3 objects (proves admin was real)
# PASS = chip silicon enforced the read deny. FAIL = security regression
# (admin extracted a user-PIN-gated secret — would mean a DHUK/BHK leak
# could drain funds, contrary to the threat model in CLAUDE.md §"Hardware
# PIN gating and three-way per-attempt consumption").
# Watch semihosting for "[E2E-EXTRACT] ADMIN-EXTRACT ATTEMPT: PASS"/"FAIL".
# Repeatable on the same chip (step 1 cleans up prior residue).
se050-admin-extract-attempt-e2e:
	@echo "==> Building SE050 admin-extract-attempt e2e firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features se050-admin-extract-attempt-e2e,ui-noop,stm32u585,debug-log,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@echo "==> Flashing admin-extract-attempt e2e firmware..."
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Running admin-extract-attempt e2e (watch semihosting output)..."
	probe-rs run --chip $(CHIP) $(SECURE_ELF)

# SE050 + OLED interactive build (real SE050, real OLED display, real buttons).
# Full first-boot wizard: user enters PIN and creates/restores mnemonic.
# Both the SSD1306 OLED and SE050 share I2C1 (PB8/PB9) at 400 kHz.
build-hw-se050-oled:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,ui-lcd,stm32u585,usb,debug-log,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> SE050 + OLED interactive build ready."

# Standalone build: no debug-log, no semihosting. Safe to run with only
# USB-C power and no debugger attached. BKPT-free.
build-hw-se050-oled-standalone:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,ui-lcd,stm32u585,usb,legacy-fw-rollback-unsafe,erc7730-dev-unattested,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> Standalone build ready (no semihosting, USB-C only)."

flash-hw-se050-oled-standalone: build-hw-se050-oled-standalone
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip $(CHIP)
	@echo "==> Flashed and reset. Disconnect ST-LINK, connect only USB-C if desired."
	@echo "    Set JP4 to 5V_UCPD for USB-C power (or keep 5V_USB_STLK if using both cables)."

# Dual-SE + OLED standalone — production-shape dual-chip build (OPTIGA
# Trust M + SE050, XOR entropy split across both). Mirrors the
# `wipe-for-wizard` feature set so the admin PIN is derived from the
# same OTP source and wipe-for-wizard can delete what this target
# provisioned (and vice versa). No semihosting, no debug-log — safe to
# run on USB-C power alone with no debugger attached.
#
# Feature set: `dual-se` (= optiga-trust-m + se050), `optiga-hw-counter`
# (OPTIGA E120 for the PIN-attempt counter), `dev-testkey` (stable OTP
# master across flashes so the derived SE050 admin PIN matches what
# wipe-for-wizard derives), `ui-lcd`, `gpio-buttons`, `stm32u585`,
# `usb`. Deliberately DOES NOT include `optiga-lock-operational`;
# every OPTIGA user OID stays at LcsO=Creation through provisioning.
#
# Invariants respected:
#   #1 dual-chip seed split (half_O on OPTIGA, half_E on SE050).
#   #2 hardware-level PIN gating (OPTIGA auth-ref + SE050 UserID).
#   #3 E2E encrypted tunnels (Shielded Connection + SCP03) — STRUCTURE only on
#      this BENCH target: `dev-testkey` roots the OPTIGA PBS in a compile-time
#      constant and `se050-derived-scp03` is OFF, so the SE050 SCP03 channel runs
#      on the PUBLISHED AN12436 factory keys. Both are bus-sniffable here — fine
#      for bench (dev-testkey is a non-shipping marker), NOT confidential. A
#      candidate quarantine build must add `se050-derived-scp03`
#      (+ saes-dhuk/bhk PBS) and a rotated chip; the `nsc/mod.rs` HIGH-1 fence
#      enforces only that deterministic baseline. The separate journaled
#      `rdp2-self-lock` path and its remaining production gates are not
#      exercised by this bench target.
#   #4/#5/#6/#7/#8 — all in force; this is just a feature-set wrapper.
#
# Intended workflow for bench iteration:
#   1. `make wipe-for-wizard`   — nukes OPTIGA F1Dx/E1Ex + SE050
#                                 user+admin+canary objects, halts.
#   2. Disconnect ST-LINK and USB-C, reconnect USB-C only.
#   3. `make flash-hw-dual-se-oled-standalone` (this target) — flashes
#      the standalone firmware. First boot: chip is unprovisioned, OLED
#      shows the first-boot wizard, user enters a mnemonic + PIN,
#      firmware provisions both chips with the XOR-split entropy.
#      Subsequent boots: OLED shows the unlock dialog.
#   4. Use the wallet via USB HID from the companion app.
build-hw-dual-se-oled-standalone:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se,optiga-hw-counter,dev-testkey,gpio-buttons,ui-lcd,stm32u585,usb,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> Dual-SE standalone build ready (no semihosting, USB-C only, LcsO=Creation)."

flash-hw-dual-se-oled-standalone: build-hw-dual-se-oled-standalone
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip $(CHIP)
	@echo "==> Flashed and reset. Disconnect ST-LINK, connect only USB-C if desired."
	@echo "    Set JP4 to 5V_UCPD for USB-C power (or keep 5V_USB_STLK if using both cables)."

# Same full standalone firmware as `flash-hw-dual-se-oled-standalone`,
# but on the NV3007 SPI LCD (`ui-lcd` — the shipping display backend as
# of 2026-06-09) instead of the OLED. `ui-lcd` pulls in `gpio-buttons`
# + `spi1-arduino`. Requires the NV3007 wired per docs/hardware/nv3007-wiring.md.
# All the caveats on the OLED target (bench-only #3 tunnel keys via
# dev-testkey, LcsO=Creation, wipe-for-wizard workflow) apply unchanged.
build-hw-dual-se-lcd-standalone:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se,optiga-hw-counter,dev-testkey,ui-lcd,stm32u585,usb,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> Dual-SE LCD standalone build ready (no semihosting, USB-C only, LcsO=Creation)."

flash-hw-dual-se-lcd-standalone: build-hw-dual-se-lcd-standalone
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip $(CHIP)
	@echo "==> Flashed and reset. Disconnect ST-LINK, connect only USB-C if desired."
	@echo "    Set JP4 to 5V_UCPD for USB-C power (or keep 5V_USB_STLK if using both cables)."

# Same build as `flash-hw-dual-se-lcd-standalone` PLUS `debug-log`,
# attached over the ST-LINK micro-USB (`probe-rs run` at the end keeps
# the debugger connected and streams every secure-world log line to
# this terminal). Board powers from the programmer — no USB-C needed.
# NOT for production: `debug-log` leaks device-internal state (the
# wizard prints mnemonic words) over semihosting.
build-hw-dual-se-lcd-standalone-debug:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se,optiga-hw-counter,dev-testkey,ui-lcd,stm32u585,usb,debug-log,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> Dual-SE LCD standalone DEBUG build ready (debug-log ON, ST-LINK powered)."

flash-hw-dual-se-lcd-standalone-debug: build-hw-dual-se-lcd-standalone-debug
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Attaching probe-rs run — semihosting stream follows. Ctrl-C to detach."
	@echo "    Wizard + PIN entry are driven by the physical buttons as usual;"
	@echo "    probe-rs only captures stdout."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Same build as `flash-hw-dual-se-oled-standalone` PLUS `debug-log`, so
# `secure_log!` / `hprintln!` output streams over the ST-LINK SWO/SWD
# semihosting channel. Flashes with `probe-rs run` at the end — that
# command keeps the debugger attached and forwards every secure-world
# log line to this terminal, so you can cold-power-cycle the board
# (long-press RESET or pull+reinsert VCC) while watching the host
# stdout to see exactly which branch of `is_provisioned()` / wizard /
# unlock path fires.
#
# Use this to diagnose the "wizard re-runs after a successful setup"
# class of bug: on the second boot, look for one of:
#   [S] Device already provisioned — requesting PIN unlock
#   [S] Unprovisioned — running first-boot wizard
# and the `[OPTIGA] Init: ...` + `[SE050] Init: ...` breadcrumbs above
# it to see whether one of the SE `init()` calls is timing out on cold
# boot.
#
# NOT for production — `debug-log` leaks device-internal state over
# semihosting (mnemonic words are printed when the wizard runs, per
# `main.rs`'s debug-only log block). Keep ST-LINK attached throughout;
# disconnecting kills the semihosting channel but the device will
# continue to run. Safe against the `probe-rs` `SYS_READC` gap (see
# CLAUDE.md "Hardware testing under probe-rs") because this build uses
# `gpio-buttons` + `ui-lcd` — PIN / mnemonic entry goes through real
# button presses, not semihosting input.
build-hw-dual-se-oled-standalone-debug:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se,optiga-hw-counter,dev-testkey,gpio-buttons,ui-lcd,stm32u585,usb,debug-log,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> Dual-SE standalone DEBUG build ready (debug-log ON, USB-C + ST-LINK)."

flash-hw-dual-se-oled-standalone-debug: build-hw-dual-se-oled-standalone-debug
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Attaching probe-rs run — semihosting stream follows. Ctrl-C to detach."
	@echo "    Power-cycle the board (pull+replug USB-C, or press the B2 RESET button)"
	@echo "    to see the full boot sequence. Wizard + PIN entry are driven by the"
	@echo "    physical buttons as usual; probe-rs only captures stdout."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# OPTIGA Trust M + OLED standalone — single-SE variant of the SE050
# standalone target above. Uses Infineon OPTIGA Trust M V3 on I2C1
# (TRUSTMV3SHIELDTOBO1 on Arduino R3 headers). No semihosting, USB-C
# only. Deliberately does NOT include `optiga-lock-operational`, so the
# protected user OIDs F1D0..F1D4 and F1E1 stay at LcsO=Creation throughout
# provisioning — metadata remains mutable, data rewriteable, and no
# irreversible protected-object LcsO bump occurs. E140 is unchanged by both
# this target and ordinary pairing; its factory actor/order remains OPEN.
# This build is intended for
# bench/dev use; see docs/secure-elements/optiga-brick-postmortem.md §5 + §7.
# Do not add `optiga-lock-operational` to a unit intended to ship merely to
# ratchet protected objects: the full S-1/S-2 ceremony and E140's actor/order
# relative to the final rotation remain OPEN.
#
# NOTE: this target violates invariant #1 (dual-chip seed split) — the
# full entropy lives on OPTIGA alone. It is the single-SE OPTIGA twin of
# `flash-hw-se050-oled-standalone`, not a production dual-SE build.
build-hw-optiga-oled-standalone:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features optiga-trust-m,gpio-buttons,ui-lcd,stm32u585,usb,legacy-fw-rollback-unsafe,erc7730-dev-unattested,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> Standalone OPTIGA build ready (no semihosting, USB-C only, LcsO=Creation)."

flash-hw-optiga-oled-standalone: build-hw-optiga-oled-standalone
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip $(CHIP)
	@echo "==> Flashed and reset. Disconnect ST-LINK, connect only USB-C if desired."
	@echo "    Set JP4 to 5V_UCPD for USB-C power (or keep 5V_USB_STLK if using both cables)."

# ---------------------------------------------------------------------------
# OPTIGA Trust M dev-convenience helpers for the standalone target.
#
# Both targets assume the same hardware shape as `flash-hw-optiga-oled-
# standalone`: STM32U585 + OPTIGA Trust M V3 on I2C1 + SSD1306 OLED +
# GPIO buttons. Neither target uses `otp-hardcoded-master-key`, so OTP is
# burned from TRNG on first boot and every subsequent reflash (including
# back to the real standalone target) derives the same PBS from the same
# OTP master — i.e. shield handshake and PIN auth remain consistent
# across reflashes.
#
# LcsO-safety: neither target includes `optiga-lock-operational`. Every
# OID stays at LcsO=Creation; nothing is ratcheted to Operational.
# ---------------------------------------------------------------------------

# Factory-reset the connected board's OPTIGA chip so the next standalone
# boot sees it as never-provisioned. Reuses the `optiga-admin-wipe-e2e`
# exercise, which provisions throwaway test data, verifies unlock, then
# calls `factory_reset` — ending with F1D5 = RESET_SENTINEL (0xFF) and
# F1D0..F1D4 blanked. Post-state: `check_provisioned()` returns false →
# first-boot wizard runs on the next `flash-hw-optiga-oled-standalone`.
#
# Typical usage after the wizard got into a bad state:
#   make optiga-factory-reset-hw            # wipes OPTIGA, watch OLED
#   make flash-hw-optiga-oled-standalone    # reflash; wizard runs fresh
#
# Runs non-interactively: `probe-rs reset` starts the firmware, OLED
# shows "OPTIGA wipe: running..." → "OPTIGA wipe: PASS" (or FAIL), then
# the device halts in `wfi`. The $(STM32_PROG) call re-asserts the
# TZ option bytes (safe to repeat; ST-LINK may reset them between runs).
optiga-factory-reset-hw:
	@echo "==> Building OPTIGA factory-reset firmware (nuclear path)..."
	@echo "    Writes 0xFF to F1E1 (counter sentinel) via plaintext APDUs."
	@echo "    Skips OTP burn, PBS derivation, shielded connection, and"
	@echo "    the provision-first dance — so it works on boards where"
	@echo "    the OTP master can't be programmed."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-nuclear-reset,stm32u585,ui-lcd,gpio-buttons,debug-log,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo ""
	@echo "==> Running with semihosting attached. Watch for:"
	@echo "      [OPTIGA/prov] step: ..."
	@echo "      [OPTIGA-E2E-ADMIN] ADMIN-WIPE ROUNDTRIP: PASS/FAIL"
	@echo "    Ctrl+C to detach once PASS/FAIL lines appear."
	@echo ""
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Pre-provision the connected board's OPTIGA chip with a known mnemonic
# + PIN, skipping the interactive wizard. Uses the `e2e-test` fast-path
# (fixed test mnemonic + PIN baked into `secure/src/main.rs`) plus
# `e2e-skip-unlock`, which halts right after `provision_from_mnemonic`
# returns so the gateway never auto-unlocks.
#
# Bake-in credentials:
#   PIN:      00000000  (type "0" eight times in the PIN UI)
#   Mnemonic: abandon x23 + "art"  (standard BIP-39 test vector)
#
# After this target runs, the OPTIGA chip is in the same state a real
# user would leave it in by typing those credentials into the wizard.
# Reflash `flash-hw-optiga-oled-standalone` and the next boot skips the
# wizard, prompts "Enter PIN", and accepts 00000000.
#
# Typical usage to skip the wizard on a fresh board:
#   make optiga-preprovision-hw             # provisions OPTIGA, halts
#   make flash-hw-optiga-oled-standalone    # reflash
#   <type 00000000 at the PIN prompt>       # device unlocks
#
# OTP handling: no `otp-hardcoded-master-key`, so OTP burns real TRNG on
# first boot. The standalone build reflashed afterwards reads the same
# OTP key and derives the same PBS — shield handshake and PIN-derived
# auth secret stay consistent across the reflash.
optiga-preprovision-hw:
	@echo "==> Building OPTIGA pre-provision firmware (testkey PBS)..."
	@echo "    Adds otp-hardcoded-master-key so provisioning works on boards"
	@echo "    where OTP burn is blocked. Must be paired with the testkey"
	@echo "    standalone variant below so both firmwares derive the same PBS."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,stm32u585,ui-lcd,gpio-buttons,e2e-test,e2e-skip-unlock,otp-hardcoded-master-key,debug-log,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,e2e-test,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo ""
	@echo "==> Running with semihosting — watch for PBS fingerprint + provision OK."
	@echo "    Ctrl+C once you see '[OPTIGA] Provisioning complete' + halt."
	@echo ""
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Testkey standalone build — byte-for-byte the interactive
# `flash-hw-optiga-oled-standalone` flow, with the single difference
# that `otp-hardcoded-master-key` replaces the per-device OTP master
# with a compile-time constant so the PBS derives without needing OTP
# to be programmable. The dev-testkey feature is the explicit opt-out
# from the `nsc/mod.rs` production guard that would otherwise refuse
# to compile `otp-hardcoded-master-key` in a non-e2e-test release.
#
# Interactive: first boot runs the seed wizard (PIN + mnemonic),
# subsequent boots prompt "Enter PIN" like the real standalone build.
# No auto-provision, no auto-unlock.
#
# Use this on boards where OTP writes fail (WRPERR at 0x0BFA_0080)
# so the normal OTP-burn path can't run. PBS is the shared test
# constant across every dev board built with this feature — NEVER
# promote this target into production.
flash-hw-optiga-oled-standalone-testkey:
	@echo "==> Building OPTIGA standalone w/ dev-testkey (interactive, hardcoded PBS)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,gpio-buttons,ui-lcd,stm32u585,usb,dev-testkey,debug-log,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip $(CHIP)
	@echo "==> Flashed. Interactive first-boot wizard runs on a blank chip."
	@echo "    PBS is the shared dev-testkey constant (NOT device-unique)."
	@echo "    To wipe wallet state:           make optiga-factory-reset-hw"
	@echo "    To see semihosting output:      probe-rs run --chip $(CHIP) $(SECURE_ELF)"

# Same interactive dev-testkey build as above, but flashes and then
# stays attached via `probe-rs run` so semihosting (`secure_log!`,
# debug-log prints) streams live to the terminal while the firmware
# executes. Hardware buttons (PC1/PA8) still drive the UI — the
# semihosting channel is read-only for logs, not for input.
#
# Use when you need to watch the boot flow during bench iteration.
# Ctrl+C to detach (leaves firmware running on-device).
flash-hw-optiga-oled-testkey:
	@echo "==> Building OPTIGA dev-testkey (interactive, hardcoded PBS, debug-log)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,gpio-buttons,ui-lcd,stm32u585,usb,dev-testkey,debug-log,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo ""
	@echo "==> Running with semihosting attached. Ctrl+C to detach."
	@echo "    Hardware buttons (PC1 LEFT / PA8 RIGHT) drive the UI."
	@echo ""
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

flash-hw-se050-oled: build-hw-se050-oled
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Starting interactive SE050 wallet (Ctrl-C to quit)..."
	@echo "    Button input via keyboard: h/l=short left/right, H/L=long left/right"
	@python3 tools/wallet_run_hw.py

# Flash USB-enabled build to real STM32U585.
flash-hw-usb: build-hw-usb ## Flash the USB-HID build to STM32U585
	probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching (Ctrl-C to quit)..."
	probe-rs reset --chip $(CHIP)
	probe-rs attach --chip $(CHIP) $(SECURE_ELF)

# Run all three test layers: Rust unit tests, Foundry Solidity tests, and
# the full e2e suite under QEMU.
test: test-unit test-solidity e2e ## Host test bundle: unit + solidity + e2e
	@echo "==> ALL TEST LAYERS PASSED"

# Host-side Rust unit tests for pure logic (aa, tx modules).
#
# Explicit `--no-default-features --features ...` because the secure crate
# now defaults to no features (Phase-2 of the modularity refactor). Without
# an explicit feature set, dead-code warnings on unreachable feature-gated
# modules would either litter the output or, under `-D warnings`, fail the
# build outright.
test-unit: ## Rust workspace unit tests (host)
	@echo "==> Running Rust unit tests (host)"
	@cargo test --locked -p sphincs-tz-secure \
	    --no-default-features \
	    --features mock-se,debug-log,ui-semihosting
	@echo "==> Running pure-logic crate tests (host, --tests: unit + integration)"
	@# `--tests` (NOT `--lib`) so the tests/ integration suites run too — the
	@# frozen-format, KDF-tag-stability, and RAW32-forgery regressions live there.
	@# Kept in lockstep with the CI host-tests job (.github/workflows/ci.yml).
	@cargo test --locked --tests \
	    -p pqsigner-proto -p pqsigner-tx-core -p pqsigner-aa \
	    -p pqsigner-domain -p pqsigner-tx -p pqsigner-erc7730 \
	    -p sphincs-c10 -p pqsigner-fi \
	    -p sphincs-tz-bip39 -p fw-manifest -p sphincs-tz-shared \
	    -p pqsigner-hal -p pqsigner-pq-seal -p masked-sha2 -p pqsigner-xtask
	@echo "==> Running dbgen ERC-7730 round-trip integration tests (host)"
	@cargo test --locked -p dbgen --test erc7730_roundtrip
	@$(MAKE) --no-print-directory erc8176-coverage-test

# CI gate: every checked-in generated artifact must round-trip
# byte-for-byte. New artifacts get a parallel diff target here so a
# stale `dbgen` / `xtask` run can't slip past review.
#
# Mirrors the existing `gen-solidity-constants --check` pattern: each
# subcommand rebuilds its outputs in-memory and exits non-zero on drift.
#
# Run manually:
#   make check-codegen
#
# Or as part of `make prod-erc7730-provenance-check` (Phase 2 onwards).
.PHONY: check-codegen generate-erc7730-descriptors check-erc7730-build-input-shadows check-erc7730-descriptors check-erc7730-forced-eligible-binding cross-parity-erc7730 cross-parity-erc8213 erc7730-cross-parity test-erc7730-proxy-drift erc7730-proxy-drift check-solidity-constants check-research-bundles erc8176-coverage erc8176-coverage-test
check-codegen: check-erc7730-descriptors check-solidity-constants check-research-bundles
	@echo "==> codegen artifacts in sync"

cross-parity-erc8213: ## Compare live PQ1 ERC-8213 hashes with a lock-pinned independent Keccak implementation
	@command -v uv >/dev/null 2>&1 || { echo "cross-parity-erc8213: FAIL — uv is required" >&2; exit 1; }
	@uv run --frozen --project tools/erc7730-parity python tools/cross_parity_erc8213.py

cross-parity-erc7730: ## Compare production semantics with the official resolver and run PQ1 render conformance
	@command -v uv >/dev/null 2>&1 || { echo "cross-parity-erc7730: FAIL — uv is required" >&2; exit 1; }
	@uv run --frozen --project tools/erc7730-parity python tools/cross_parity_erc7730.py

erc7730-cross-parity: cross-parity-erc8213 cross-parity-erc7730 ## Combined clear-signing cross-implementation parity gate
	@uv run --frozen --project tools/erc7730-parity python tools/erc7730-parity/test_parity_gates.py
	@echo "==> erc7730-cross-parity: PASS"

test-erc7730-proxy-drift: ## Run the offline advisory proxy-monitor suite
	@PYTHONDONTWRITEBYTECODE=1 python3 tools/test_erc7730_proxy_drift.py

erc7730-proxy-drift: ## Observe evidence-bound Ethereum proxies (advisory only; requires ERC7730_RPC_1)
	@test -n "$$ERC7730_RPC_1" || { echo "erc7730-proxy-drift: FAIL — set ERC7730_RPC_1" >&2; exit 1; }
	@PYTHONDONTWRITEBYTECODE=1 python3 tools/erc7730_proxy_drift.py \
	    --rpc "1=$$ERC7730_RPC_1" --output target/erc7730-proxy-drift.json
	@echo "==> advisory report: target/erc7730-proxy-drift.json"

generate-erc7730-descriptors: check-erc7730-build-input-shadows ## Regenerate DBs with the explicit nested-calldata E2E fixture
	@cargo run --locked -q -p dbgen --features $(ERC7730_E2E_GENERATOR_FEATURE)

check-erc7730-build-input-shadows:
	@set -eu; \
	for path in .cargo/config rust-toolchain; do \
	    if [ -e "$$path" ] || [ -L "$$path" ]; then \
	        echo "ERROR: legacy ERC-7730 build-input shadow '$$path' is forbidden" >&2; \
	        exit 1; \
	    fi; \
	done

check-erc7730-descriptors: check-erc7730-build-input-shadows
	@echo "==> Checking ERC-7730 descriptor catalog (xtask --check)"
	@cargo run --locked -q -p pqsigner-xtask \
	    --features $(ERC7730_E2E_GENERATOR_FEATURE) -- \
	    gen-erc7730-descriptors --check
	@echo "==> Checking companion ERC-7730 catalogue/status preflight"
	@PYTHONDONTWRITEBYTECODE=1 python3 tools/companion-stub/test_erc7730_trailer.py

check-erc7730-forced-eligible-binding: ## Verify P73K parser, release, and secure exact-membership binding
	@echo "==> Checking ERC-7730 forced-eligible parser and release binding"
	@cargo test --locked -q -p pqsigner-erc7730 forced_eligible
	@cargo test --locked -q -p fwsign
	@cargo test --locked -q -p sphincs-tz-secure --no-default-features \
	    --features mock-se,debug-log,ui-semihosting,erc7730-forced-blind forced_eligible

check-research-bundles:
	@echo "==> Checking generated security research bundles"
	@bash docs/security/research-bundles/build.sh --check

# proto -> Solidity freshness gate: the generated PqsignerProto.sol must be a
# byte-for-byte render of the current pqsigner-proto constants. `--check` prints
# the fresh render to stdout; we diff it against the checked-in copy so a
# forgotten `gen-solidity-constants` after a proto edit fails closed (the
# on-chain verifier depends on these constants). Was previously claimed to run
# in CI but was wired nowhere (fixed 2026-07-02).
check-solidity-constants:
	@echo "==> Checking proto -> Solidity constants (PqsignerProto.sol drift)"
	@cargo run --locked -q -p pqsigner-xtask -- gen-solidity-constants --check \
	    | diff - contracts/smart-wallet/src/generated/PqsignerProto.sol \
	    || { echo "PqsignerProto.sol is stale — run: cargo run -p pqsigner-xtask -- gen-solidity-constants"; exit 1; }

erc8176-coverage: ## Report ERC-8176 (EAS) attestation coverage of the ERC-7730 corpus
	@echo "==> Querying EAS for ERC-8176 attestation coverage (needs network)"
	@python3 tools/erc8176_eas_coverage.py

erc8176-coverage-test: ## Run deterministic offline ERC-8176 coverage-checker tests
	@echo "==> Testing ERC-8176 coverage checker (offline)"
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tools/test_erc8176_eas_coverage.py

# Foundry tests for the PQ smart-wallet contracts.
test-solidity: ## Foundry tests for the smart-wallet contracts
	@echo "==> Running Foundry tests"
	@cd contracts/smart-wallet && forge test

# Lean 4 formal verification — type-checks the SphincsCVerify project.
# See contracts/verification/README.md for what this proves and what it
# leaves to the TCB.
test-formal-verification: ## Lean FV suite + axiom audit
	@echo "==> Building SphincsCVerify Lean project"
	@$(MAKE) -C contracts/verification verify
	@echo "==> Auditing axioms + sorry inventory"
	@$(MAKE) -C contracts/verification verify-audit

# `verify-theft-free` — end-to-end machine check of the headline theorem
# `SphincsCVerify.Spec.Theorems.theft_free`, plus an HONEST per-axiom
# discharge-status report.
#
# Pipeline:
#   1. Install the pinned Lean toolchain (idempotent; elan caches it).
#   2. `lake build` — the kernel re-checks every closed theorem in the
#      SphincsCVerify project, including `Spec.Theorems.theft_free` and
#      wallet invariants I-1..I-8.
#   3. Audit the axiom dependency closure of `theft_free` and diff it
#      against the expected set. Any drift fails the target.
#   4. Run `lint_axioms.sh` — fails on any newly-introduced `True`-typed
#      axiom or `True := trivial` placeholder theorem outside the
#      allowlists in `contracts/verification/scripts/`.
#   5. Print the per-axiom status table sourced from
#      `contracts/verification/docs/AXIOM_STATUS.json`. The previous
#      headline "An adversary cannot cause ... balance to decrease" line
#      overclaimed: three of the bridge axioms have type `True` and do
#      not constrain the deployed bytecode. The status table tells you
#      WHICH axioms are placeholders vs cited-TCB vs discharged.
#
# See `contracts/verification/docs/DISCHARGE_PLAN.md` for the tiered
# plan to turn placeholders into discharged content.
# Trust boundary: contracts/verification/docs/TRUST_ASSUMPTIONS.md.
.PHONY: verify-theft-free
verify-theft-free: export PATH := $(HOME)/.elan/bin:$(PATH)
verify-theft-free:
	@command -v elan >/dev/null || { \
	  echo "ERROR: elan not found. Install with:"; \
	  echo "  curl https://elan.lean-lang.org/elan-init.sh -sSf | sh -s -- -y"; \
	  exit 1; \
	}
	@echo "==> [1/5] Pinning Lean toolchain"
	@cd contracts/verification/lean && elan toolchain install "$$(cat lean-toolchain)" >/dev/null 2>&1 || true
	@echo "==> [2/5] lake build (kernel-checks every closed theorem)"
	@$(MAKE) -s -C contracts/verification verify-build
	@echo "==> [3/5] Auditing axiom closure of theft_free"
	@cd contracts/verification/lean && \
	  lake env lean scripts/dump_axioms.lean 2>/dev/null > /tmp/theft_free_axioms.txt
	@awk "/^'SphincsCVerify\\.Spec\\.Theorems\\.theft_free' depends on axioms:/{flag=1} flag{print} flag&&/\\]/{exit}" \
	    /tmp/theft_free_axioms.txt \
	  | tr -d ' \n' \
	  | sed -e 's/.*\[//' -e 's/\]$$//' \
	  | tr ',' '\n' \
	  | sort -u > /tmp/theft_free_seen.txt
	@printf '%s\n' \
	    Classical.choice \
	    Quot.sound \
	    SphincsCVerify.Bridge.EntryPoint.entrypoint_honest \
	    SphincsCVerify.Bridge.evm_bytecode_executes_correctly \
	    SphincsCVerify.Bridge.precompile_0x02_is_FIPS_180_4 \
	    SphincsCVerify.Bridge.solidityVerifier_compiles_correctly \
	    SphincsCVerify.Crypto.EUF_CMA_SPHINCSplusC \
	    SphincsCVerify.Crypto.ITSR_F \
	    SphincsCVerify.Crypto.SM_DT_TCR_F \
	    SphincsCVerify.Crypto.hMsg_random_oracle \
	    propext \
	  | sort -u > /tmp/theft_free_expected.txt
	@if ! diff -u /tmp/theft_free_expected.txt /tmp/theft_free_seen.txt; then \
	  echo ""; \
	  echo "FAIL: theft_free's axiom closure drifted from the expected set."; \
	  echo "Full dump: /tmp/theft_free_axioms.txt"; \
	  echo "If you intentionally added/removed an axiom, update BOTH the"; \
	  echo "expected list in this Makefile target AND the corresponding"; \
	  echo "entry in contracts/verification/docs/AXIOM_STATUS.json."; \
	  exit 1; \
	fi
	@echo "    closure matches the documented set (A1..A5 + Lean kernel built-ins)"
	@echo "==> [4/5] Linting for placeholder axioms / True := trivial theorems"
	@bash contracts/verification/scripts/lint_axioms.sh
	@echo "==> [5/5] Honest per-axiom discharge status"
	@python3 contracts/verification/scripts/format_axiom_status.py

# `test-all` — run every host-runnable test suite in the repo with one
# command. Streams one progress line per suite (suite name, then
# PASS/FAIL with test count when it finishes), keeps going past
# failures, and exits non-zero with a per-suite summary at the end if
# anything broke. Per-suite output is captured to
# `/tmp/test-all.<suite>.log` and the log path is shown for any FAIL.
#
# Covers (no opt-in needed):
#   1. Pure-logic workspace crates (`cargo test --workspace`, minus the
#      firmware-only bins that don't link on host).
#   2. `sphincs-tz-secure` host-testable subset behind `--features mock-se`.
#   3. Standalone `fuzz/` workspace (harness + structure tests).
#   4. Solidity contracts under `contracts/smart-wallet` via `forge test`
#      (auto-skipped with a SKIP line if `forge` is not on PATH).
#
# NOT included (these are slow QEMU/HW integration tests, not unit tests):
#   make e2e, make e2e-hw, make play, make run, make test-key-speed,
#   make pin-gate-*-hw, make optiga-hw-counter-e2e, ...
.PHONY: test-all
test-all: SHELL := /usr/bin/env bash ## Everything host-runnable
test-all: ## Everything host-runnable
	@set -uo pipefail; \
	pass=0; fail=0; failed=(); idx=0; \
	run() { \
	  idx=$$((idx+1)); \
	  local name="$$1"; shift; \
	  local slug=$$(echo "$$name" | tr ' /()' '____'); \
	  local log="/tmp/test-all.$$slug.log"; \
	  printf "[%2d] %-46s " "$$idx" "$$name"; \
	  if "$$@" >"$$log" 2>&1; then \
	    local n; n=$$(grep -E '^(test|Suite) result' "$$log" | awk '{tot+=$$4} END {print tot+0}'); \
	    [ -z "$$n" ] && n="?"; \
	    printf "PASS  (%s tests)\n" "$$n"; \
	    pass=$$((pass+1)); \
	    rm -f "$$log"; \
	  else \
	    printf "FAIL  (log: %s)\n" "$$log"; \
	    fail=$$((fail+1)); \
	    failed+=("$$name -> $$log"); \
	  fi; \
	}; \
	echo "=== running all host-runnable test suites ==="; \
	run "workspace host crates" cargo test --workspace --tests --no-fail-fast --quiet \
	    --exclude sphincs-tz-secure --exclude sphincs-tz-nonsecure --exclude pqsigner-fsbl; \
	run "sphincs-tz-secure --features mock-se" cargo test -p sphincs-tz-secure --tests \
	    --features mock-se --no-fail-fast --quiet; \
	run "fuzz workspace" bash -c "cd fuzz && cargo test --tests --no-fail-fast --quiet"; \
	run "secure-miri-tests (rng_strong + ui_lcd mounts)" bash -c "cd secure-miri-tests && cargo test --tests --no-fail-fast --quiet"; \
	if command -v forge >/dev/null 2>&1; then \
	  run "contracts/smart-wallet forge" bash -c "cd contracts/smart-wallet && forge test"; \
	else \
	  idx=$$((idx+1)); \
	  printf "[%2d] %-46s SKIP  (forge not on PATH)\n" "$$idx" "contracts/smart-wallet forge"; \
	fi; \
	echo; \
	if [ "$$fail" -eq 0 ]; then \
	  echo "==== ALL $$pass SUITES PASSED ===="; \
	else \
	  echo "==== $$fail / $$((pass+fail)) SUITE(S) FAILED ===="; \
	  for s in "$${failed[@]}"; do echo "  FAIL  $$s"; done; \
	  exit 1; \
	fi

# Compute firmware measurement words from the secure ELF.
# Displays the same 8 BIP-39 words the device shows at boot.
#
# Uses the same secure-world build as `flash-hw-dual-se-oled-standalone`
# (features: dual-se,optiga-hw-counter,dev-testkey,gpio-buttons,ui-lcd,
# stm32u585,usb), so the words printed here match what the OLED shows
# after that flash target runs. To measure a different feature matrix
# (e.g. the production set without `dev-testkey`), use `make release`
# instead — it runs `verify-repro` and prints both secure + nonsecure
# measurements from the verified ELFs.
measure: build-hw-dual-se-oled-standalone ## Build + print the 8 BIP-39 measurement words
	cargo run --locked -p fwmeasure -- $(SECURE_ELF)

# Build the first-stage bootloader for real STM32U585 hardware.
#
# FSBL_VENDOR_PUBKEY: path to the 32-byte vendor pubkey (`pk_seed[16]
# || pk_root[16]`, produced by `fwsign pubkey`). If unset, a fixed dev
# fixture key is derived inline by fsbl/build.rs — the resulting FSBL
# is for development use only and will not accept production-signed
# firmware, and vice versa.
#
# Legacy bench budget: 32 KB at 0x0C00_0000 (pages 0–3 of bank 1). This target
# is not the Draft-1.1 candidate resource gate: that candidate proposes a
# 40,960-byte hard ceiling plus separate physical LOAD-span and RAM/stack gates.
.PHONY: fsbl
fsbl: ## Build legacy bench FSBL (32 KB regression gate; not candidate approval)
	@echo "==> Building FSBL (FSBL_VENDOR_PUBKEY=$${FSBL_VENDOR_PUBKEY:-<dev fixture>})"
	@# FSBL_ALLOW_DEV_KEY opts this dev target into fsbl/build.rs's committed
	@# dev vendor key when FSBL_VENDOR_PUBKEY is unset (finding F2). A bare
	@# `cargo build -p pqsigner-fsbl` without either env var now fails the
	@# build instead of silently embedding the public dev key; `fsbl-release`
	@# sets neither and supplies a real pubkey via FSBL_VENDOR_PUBKEY.
	@# `-Z emit-stack-sizes` adds a NON-ALLOC `.stack_sizes` section carrying one
	@# frame size per function, which the geometry gate below turns into an upper
	@# bound on stack depth. Verified non-perturbing: the LOAD span is byte-identical
	@# with and without it (0x06EC0 both ways), so the flag cannot change the thing
	@# it is there to measure.
	@FSBL_ALLOW_DEV_KEY=1 $(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS) -Z emit-stack-sizes" \
		cargo build --locked --release --target $(TARGET) --target-dir target/fsbl \
			-p pqsigner-fsbl --features legacy-fw-rollback-unsafe
	@echo "==> FSBL built: $(FSBL_ELF)"
	@# Geometry gate. Measures the PHYSICAL LOAD span (not `size -B` text+data,
	@# which undercounts by any inter-segment alignment gap) and derives the
	@# flash PAGE RANGE that WRP would have to cover — the quantity invariant #10
	@# actually depends on, since WRP protects pages and RDP-2 freezes the option
	@# bytes forever. Neither selects nor approves a geometry: Draft 1.1's 40 KiB
	@# envelope is not adopted, and the WRP/option-byte ceremony stays open.
	@python3 scripts/check_fsbl_geometry.py $(FSBL_ELF) --linker fsbl/memory-stm32u585.x
	@# Budget warning against the declared region, kept from the previous gate.
	@arm-none-eabi-size -B $(FSBL_ELF) | awk -v cap=32768 -v warn=95 'NR==2 { \
	  used=$$1+$$2; pct=used*100.0/cap; \
	  if (pct>=warn) { printf "==> FSBL: WARN — over %d%% of the legacy bench budget (only %d B headroom)\n", warn, cap-used } \
	}'

# Isolated NV3007 LCD bring-up test for the FSBL display port. Builds the FSBL
# with the `lcd-test` feature (short-circuits boot into `nv3007::lcd_test_loop`
# — NO signed slot needed) and runs it on real silicon via probe-rs. Watch the
# LCD: full-screen green -> red -> blue, then a sample 8-word fingerprint,
# repeating. The FSBL links at the boot base 0x0C000000 (= SECBOOTADD0 word
# 0x180000), same as the `*-standalone` secure builds, so this assumes the
# board is already TZEN=1 with that SECBOOTADD0 (the state any
# `flash-hw-*-standalone` / `lcd-test-hw` target leaves). If the LCD stays
# dark, run one standalone target once to set the option bytes, then re-run
# this. Re-flash the real secure world afterwards to restore normal boot.
# Requires the NV3007 wired per docs/hardware/nv3007-wiring.md. Ctrl-C to detach.
.PHONY: fsbl-lcd-test-hw
fsbl-lcd-test-hw:
	@echo "==> Building FSBL NV3007 LCD bring-up test (lcd-test short-circuit)..."
	@FSBL_ALLOW_DEV_KEY=1 $(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/fsbl \
			-p pqsigner-fsbl --features lcd-test,legacy-fw-rollback-unsafe
	@size $(FSBL_ELF) 2>/dev/null || arm-none-eabi-size $(FSBL_ELF)
	@echo "==> Flashing FSBL to the boot base + running. Watch the LCD:"
	@echo "    green -> red -> blue, then 8 words, repeating. Ctrl-C to detach."
	@probe-rs run --chip $(CHIP) $(FSBL_ELF)

# Production-only: refuse to build the FSBL without FSBL_VENDOR_PUBKEY.
# Use this in the release pipeline.
.PHONY: fsbl-release
fsbl-release: ## Build the release FSBL (blocked until rollback backend closure)
	@$(error fsbl-release: FAIL — production firmware rollback backend is not implemented; Draft 1.1 is an unapproved research candidate)

# One key path must feed both secure/build.rs and fsbl/build.rs.  This gate is
# deliberately a release dependency (not just an FSBL convenience check): an
# otherwise valid production secure image built with the old all-zero fallback
# can never accept a field update after RDP-2/WRP lockdown.
.PHONY: release-pubkey-check
release-pubkey-check:
	@if [ -z "$${FSBL_VENDOR_PUBKEY}" ]; then \
		echo "ERROR: production release requires FSBL_VENDOR_PUBKEY=path/to/pubkey.bin"; \
		exit 1; \
	fi
	@if [ ! -f "$${FSBL_VENDOR_PUBKEY}" ]; then \
		echo "ERROR: FSBL_VENDOR_PUBKEY is not a regular file: $${FSBL_VENDOR_PUBKEY}"; \
		exit 1; \
	fi
	@size=$$(wc -c < "$${FSBL_VENDOR_PUBKEY}" | tr -d '[:space:]'); \
	if [ "$$size" != "32" ]; then \
		echo "ERROR: FSBL_VENDOR_PUBKEY must be exactly 32 bytes (got $$size)"; \
		exit 1; \
	fi
	@key_hex=$$(od -An -v -tx1 "$${FSBL_VENDOR_PUBKEY}" | tr -d '[:space:]'); \
	if [ "$$key_hex" = "0000000000000000000000000000000000000000000000000000000000000000" ]; then \
		echo "ERROR: FSBL_VENDOR_PUBKEY must not be the all-zero disabled-update placeholder"; \
		exit 1; \
	fi
	@actual=$$(sha256sum "$${FSBL_VENDOR_PUBKEY}" | awk '{print $$1}'); \
	key_hex=$$(od -An -v -tx1 "$${FSBL_VENDOR_PUBKEY}" | tr -d '[:space:]'); \
	dev_hex=$$(tr -d '[:space:]' < "$(DEVELOPMENT_VENDOR_KEY_POLICY)"); \
	if ! printf '%s\n' "$$dev_hex" | grep -Eq '^[0-9a-f]{64}$$'; then \
		echo "ERROR: malformed development firmware-key policy"; \
		exit 1; \
	fi; \
	if [ "$$key_hex" = "$$dev_hex" ]; then \
		echo "ERROR: the public in-tree development firmware key must never ship"; \
		exit 1; \
	fi; \
	expected=$$(tr -d '[:space:]' < "$(PRODUCTION_VENDOR_KEY_POLICY)"); \
	if ! printf '%s\n' "$$expected" | grep -Eq '^[0-9a-f]{64}$$'; then \
		echo "ERROR: production firmware key policy is UNPROVISIONED or malformed:"; \
		echo "       $(PRODUCTION_VENDOR_KEY_POLICY)"; \
		echo "       Complete the HSM ceremony and commit the reviewed public-key SHA-256."; \
		exit 1; \
	fi; \
	if [ "$$actual" != "$$expected" ]; then \
		echo "ERROR: firmware public key does not match reviewed production policy"; \
		echo "       expected $$expected"; \
		echo "       got      $$actual"; \
		exit 1; \
	fi

# Copy the reviewed public key exactly once. Both firmware builds receive this
# absolute, read-only snapshot; the source pathname is never consulted again.
# A second hash check after the copy closes source-file replacement during the
# first gate. The final-ELF section comparison below closes build/cache drift.
.PHONY: release-key-snapshot
release-key-snapshot: release-pubkey-check
	@rm -rf $(CURDIR)/target/release-input
	@install -d -m 0700 $(CURDIR)/target/release-input
	@src=$$(realpath "$${FSBL_VENDOR_PUBKEY}"); \
		install -m 0444 "$$src" "$(RELEASE_VENDOR_KEY_SNAPSHOT).tmp"; \
		expected=$$(tr -d '[:space:]' < "$(PRODUCTION_VENDOR_KEY_POLICY)"); \
		actual=$$(sha256sum "$(RELEASE_VENDOR_KEY_SNAPSHOT).tmp" | awk '{print $$1}'); \
		if [ "$$actual" != "$$expected" ]; then \
			rm -f "$(RELEASE_VENDOR_KEY_SNAPSHOT).tmp"; \
			echo "ERROR: firmware key changed while creating the release snapshot"; \
			exit 1; \
		fi; \
		mv "$(RELEASE_VENDOR_KEY_SNAPSHOT).tmp" "$(RELEASE_VENDOR_KEY_SNAPSHOT)"

# Verify byte-for-byte reproducibility of the secure + nonsecure ELFs.
#
# Builds each world twice in isolated target directories with the same
# FEATURES + toolchain, then diffs the resulting ELFs. Any divergence
# means some source of non-determinism has leaked into the build — the
# release is not safe to ship because an independent rebuild would
# produce different measurement words than the vendor publishes.
#
# This target is the canonical reproducibility gate. The nightly CI
# workflow runs it (.github/workflows/nightly.yml, the `verify-repro`
# job); the release pipeline runs it before signing. It is NOT a
# per-PR gate — two full release cross-builds are too slow for that.
#
# Two builds share the same VENEERS path (build A writes it, build B
# links against the identical file), which is fine: linking the same
# implib into identical NS crates yields an identical NS ELF, so the
# whole reproducibility story holds.
.PHONY: verify-repro
verify-repro: ## Reproducible-build byte-diff of secure+nonsecure (slow)
	@echo "==> Reproducibility check (FEATURES=$(FEATURES))"
	@rm -rf target/repro-a target/repro-b
	@$(MAKE) --no-print-directory _repro_one \
		OUT=target/repro-a VENEERS=$(CURDIR)/target/repro-a/veneers.o FEATURES="$(FEATURES)"
	@$(MAKE) --no-print-directory _repro_one \
		OUT=target/repro-b VENEERS=$(CURDIR)/target/repro-b/veneers.o FEATURES="$(FEATURES)"
	@echo "==> Comparing ELFs"
	@if cmp -s target/repro-a/secure/$(TARGET)/release/sphincs-tz-secure \
	           target/repro-b/secure/$(TARGET)/release/sphincs-tz-secure; then \
		echo "    secure.elf:    IDENTICAL"; \
	else \
		echo "    secure.elf:    DIFFERS — reproducibility broken"; \
		echo "    Re-run with VERBOSE=1 and inspect with diffoscope"; \
		exit 1; \
	fi
	@if cmp -s target/repro-a/nonsecure/$(TARGET)/release/sphincs-tz-nonsecure \
	           target/repro-b/nonsecure/$(TARGET)/release/sphincs-tz-nonsecure; then \
		echo "    nonsecure.elf: IDENTICAL"; \
	else \
		echo "    nonsecure.elf: DIFFERS — reproducibility broken"; \
		exit 1; \
	fi
	@echo "==> verify-repro: PASS"

# Internal helper — one end-to-end build into $(OUT). Invoked twice by
# verify-repro with different OUT dirs and different VENEERS paths.
# Reuses the canonical RUSTFLAGS_SECURE / RUSTFLAGS_NONSECURE variables
# (which honour the $(FEATURES) gate that decides whether --cmse-implib
# is emitted), so we implicitly get correct behaviour for both QEMU
# and STM32U585 feature sets.
.PHONY: _repro_one
_repro_one:
	@mkdir -p $(OUT)
	@echo "==> Build $(OUT): secure"
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE)" \
		cargo build --locked --release --target $(TARGET) --target-dir $(OUT)/secure \
			-p sphincs-tz-secure --no-default-features --features $(FEATURES)
	@echo "==> Build $(OUT): nonsecure"
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE)" \
		cargo build --locked --release --target $(TARGET) --target-dir $(OUT)/nonsecure \
			-p sphincs-tz-nonsecure $(NS_FEATURES_ARG)

# Release build: reproducibility-verified secure + nonsecure ELFs plus
# their measurement words. This is what the vendor's release-signing
# pipeline consumes as input. Atomically publishes artifacts to
# target/pqsigner-release/ (separate from Cargo's target/release cache).
#
# Note: --features are taken from $(RELEASE_FEATURES); the default is
# the production feature set (no debug-log, no e2e-test, no mock-se).
# Pass RELEASE_FEATURES=... on the command line to override.
#
# Tier-1 channel-key roots (finding F8c): `saes-dhuk` routes
# hw::secret_keys::derive_into through SAES-CMAC(DHUK) instead of the legacy
# OTP-master + HKDF arm, and `se050-derived-scp03` makes SE050 SCP03 use
# per-device derived keys instead of the published AN12436 factory constants.
# Without these a default `make release` shipped non-Tier-1 roots, contrary to
# invariant #3; the nsc/mod.rs require-fence now makes that a build error.
# `rdp2-self-lock` (work-todo #36) adds the first-boot RDP-2 self-lock +
# on-device pairing rotation, and pulls in `bhk` (Tier-2 SE050 split). This is
# the candidate envelope because #36 Phase B owns phase-2B BHK provisioning
# (BHK first-write + load-lock happen on the first field boot, before the
# wizard), so the earlier "bhk yields zero-keyed derivations without phase-2B"
# caveat no longer applies. It is not correct-to-ship evidence: handoff,
# recovery/KVN, E140 ordering, and silicon gates remain open.
RELEASE_FEATURES ?= stm32u585,se050,optiga-trust-m,dual-se,ui-lcd,usb,iwdg,saes-dhuk,se050-derived-scp03,mode-production,optiga-lock-operational,optiga-hw-counter,consumption-mask,tamp,tamp-wipe,tzic-wipe,bhk,rdp2-self-lock,$(BOARD_FEATURE)

# MED-2 ship gate (audits/tz-tamper-debug-20260611). Resolve the ACTUAL feature
# set cargo would compile for the shipping image and fail if any never-ship
# feature is active — including TRANSITIVELY (ui-capture→debug-log,
# dev-testkey→otp-hardcoded-master-key). `cargo tree --depth 0 -f "{f}"` prints
# the secure crate's fully-resolved feature list; we scan it against the
# forbidden set. Independent of the `mode-production` compile fences in
# nsc/mod.rs: this also catches a release built as `stm32u585,…` WITHOUT
# mode-production. `make release` depends on it; CI runs it as a fast gate.
override PROD_FORBIDDEN := e2e-test dev-testkey mock-se debug-log otp-hardcoded-master-key \
                 ui-capture bhk-hardcoded-master-key uart-console \
                 boot-pulse sca-trigger erc7730-dev-unattested optiga-reset-oids \
                 erc7730-forced-blind \
                 fw-rollback-e2e fwup-transport-e2e se050-scp03-allow-factory-fallback \
                 legacy-fw-rollback-unsafe prodtest factory-provisioning \
                 factory-provisioning-rehearsal factory-production-irreversible-im-sure \
                 se050-factory-reset se050-reset-e2e se050-admin-wipe-e2e \
                 se050-crash-safety-e2e se050-admin-extract-attempt-e2e se050-stress \
                 optiga-admin-wipe-e2e optiga-nuclear-reset dual-se-admin-wipe-e2e \
                 optiga-hw-counter-e2e duress-probe-e2e duress-provision-e2e \
                 pin-gate-e2e dual-se-multi-unlock-e2e se-i2c-probe ui-oled-bench

# HIGH-1 compile-time baseline (audit pin-unlock 20260625): the denylist above
# stops never-ship features, but a denylist CANNOT express "a required
# hardening feature is MISSING". This allowlist proves only that the current
# deterministic transport helpers are selected; it does NOT close or implement
# the production-final fresh-TRNG per-device rotation, durable public state,
# cut recovery, or E140 ordering. Those remain production blockers. The S-1
# OPTIGA-lockdown fence (nsc/mod.rs) is keyed on
# `mode-production` ALONE (the current candidate envelope includes the
# IRREVERSIBLE LcsO ratchet feature, whose final actor/order is still OPEN, so
# it must never auto-fire on dev/test RELEASE hardware), so a release built WITHOUT
# `mode-production` previously slipped through every gate while shipping F1D0
# `Change=ALW` + mutable metadata — a desolder-bench seed-extraction path
# (shared-PIN cascade across both SEs). This allowlist makes that omission a
# LOUD build failure for the current quarantined candidate envelope. It does
# not establish the final shipping feature set or authorize the ratchet.
# (Dev/bench hardware uses the `flash-hw-*` / `*-e2e` targets, NOT
# `make release` / `prod-check`, so it is unaffected.)
override PROD_REQUIRED := mode-production stm32u585 se050 optiga-trust-m dual-se \
                optiga-lock-operational optiga-hw-counter \
                consumption-mask tamp tamp-wipe tzic-wipe iwdg \
                saes-dhuk se050-derived-scp03 bhk rdp2-self-lock

# Candidate production feature envelope used by the negative ship-quarantine
# gates. It is necessary but explicitly not sufficient for a real shipping
# image: HIGH-1's candidate implementation still lacks approved handoff,
# recovery/KVN, E140-order, and silicon closure; other named ship blockers also
# remain open. Kept on ONE line so the
# comma list survives `make` variable expansion (a backslash-newline would
# inject a stray space into the feature string). NOTE: enabling
# `optiga-lock-operational` exposes the irreversible OPTIGA LcsO ratchet; the
# exact actor/order relative to the final pairing rotation is OPEN, so this
# feature list grants no authority to flash or ratchet hardware. See
# secure/Cargo.toml and docs/archive/production-todo-retired-2026-07-19.md.
override PROD_SHIP_FEATURES := stm32u585,se050,optiga-trust-m,dual-se,ui-lcd,usb,iwdg,saes-dhuk,se050-derived-scp03,mode-production,optiga-lock-operational,optiga-hw-counter,consumption-mask,tamp,tamp-wipe,tzic-wipe,bhk,rdp2-self-lock,$(BOARD_FEATURE)

# Exact machine-readable provenance string emitted by dbgen only after a real
# ERC-8176 EAS verification implementation has authenticated every leaf.
override PROD_ERC7730_PROVENANCE := erc8176-verified

.PHONY: prod-erc7730-provenance-check
ifeq ($(ERC7730_CATALOGUE_PROVENANCE),$(PROD_ERC7730_PROVENANCE))
prod-erc7730-provenance-check: check-erc7730-descriptors check-erc7730-forced-eligible-binding ## Validate production ERC-7730 catalogue provenance
	@echo "==> prod-erc7730-provenance-check: PASS — production catalogue provenance verified"
else
prod-erc7730-provenance-check: check-erc7730-descriptors check-erc7730-forced-eligible-binding ## Validate production ERC-7730 catalogue provenance
	@$(error prod-erc7730-provenance-check: FAIL — ERC-7730 catalogue provenance is '$(ERC7730_CATALOGUE_PROVENANCE)'; required '$(PROD_ERC7730_PROVENANCE)'; Draft catalogue has no production authority)
endif

.PHONY: rng-consumer-audit prod-feature-check prod-check
rng-consumer-audit: ## Refuse unreviewed direct platform-RNG consumers
	@python3 scripts/rng_consumer_audit.py

prod-feature-check: rng-consumer-audit ## Resolve and validate the production hardening feature set
	@echo "==> prod-feature-check (MED-2 / HIGH-1): resolving shipping feature set"
	@echo "    RELEASE_FEATURES = $(RELEASE_FEATURES)"
	@feats=$$(cargo tree -p sphincs-tz-secure --no-default-features \
		--features "$(RELEASE_FEATURES)" --target $(TARGET) \
		-e features -f "{f}" --depth 0 2>/dev/null | tr ',' '\n' | tr -d ' ' | sort -u); \
	bad=""; \
	for f in $(PROD_FORBIDDEN); do \
		echo "$$feats" | grep -qx "$$f" && bad="$$bad $$f"; \
	done; \
	if [ -n "$$bad" ]; then \
		echo "==> prod-feature-check: FAIL — shipping feature set enables never-ship feature(s):$$bad"; \
		echo "    forbidden set: $(PROD_FORBIDDEN)"; \
		exit 1; \
	fi; \
	missing=""; \
	for f in $(PROD_REQUIRED); do \
		echo "$$feats" | grep -qx "$$f" || missing="$$missing $$f"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "==> prod-feature-check: FAIL — shipping feature set is MISSING required hardening feature(s):$$missing"; \
		echo "    required set : $(PROD_REQUIRED)"; \
		echo "    (S-1/S-2 OPTIGA lockdown, hw PIN counter, SCA mask, tamper-wipe, Tier-1 SE keys)"; \
		echo "    Validate the canonical feature set with:"; \
		echo "      make prod-feature-check RELEASE_FEATURES=\"$(PROD_SHIP_FEATURES)\""; \
		echo "    prod-check-ship remains expected to stop at the rollback quarantine."; \
		exit 1; \
	fi; \
	echo "==> prod-feature-check: PASS — required/forbidden feature policy is intact"

# Keep checking feature-policy drift throughout the rollback quarantine, then
# fail with a make-time error that `make -i` cannot ignore.
prod-check: prod-feature-check ## Production-readiness gate (blocked after feature validation)
	@$(error prod-check: FAIL — reviewed production rollback backend is not implemented; Draft 1.1 remains unapproved and grants no ship authority)

# Shipping-config gate: resolve and validate the canonical PROD_SHIP_FEATURES.
# No production image is built while the rollback backend remains quarantined.
.PHONY: prod-check-ship
prod-check-ship: override RELEASE_FEATURES := $(PROD_SHIP_FEATURES)
prod-check-ship: prod-feature-check ## Strict ship gate — feature-check, then rollback refusal
	@$(error prod-check-ship: FAIL — reviewed production rollback backend is not implemented; Draft 1.1 remains unapproved and grants no ship authority)

# work-todo #36 anti-footgun gate: prove a non-production configuration cannot
# compile the irreversible `rdp2-self-lock` path. Positive hardware-path
# compilation remains behind `mode-production`, which is independently blocked
# until the rollback architecture is approved. Pure first-boot logic remains
# host-tested without producing a flashable self-lock image.
.PHONY: build-rdp2-self-lock
build-rdp2-self-lock: ## Prove self-lock is rejected outside mode-production (work-todo #36)
	@echo "==> build-rdp2-self-lock: checking non-production anti-footgun"
	@set -eu; out="$$(mktemp)"; trap 'rm -f "$$out"' EXIT; \
		if cargo check -p sphincs-tz-secure --no-default-features \
			--features "stm32u585,dual-se,ui-lcd,usb,saes-dhuk,se050-derived-scp03,bhk,rdp2-self-lock,iwdg,legacy-fw-rollback-unsafe,erc7730-dev-unattested,$(BOARD_FEATURE)" \
			--target $(TARGET) >"$$out" 2>&1; then \
			cat "$$out"; \
			echo "build-rdp2-self-lock: FAIL — unsafe non-production self-lock build succeeded" >&2; \
			exit 1; \
		fi; \
		grep -Fq "RDP2_SELF_LOCK_REQUIRES_MODE_PRODUCTION" "$$out" || { cat "$$out"; exit 1; }; \
		echo "==> build-rdp2-self-lock: PASS — non-production self-lock build rejected"

# Image size / budget report. The secure image must fit its 464 KB A/B slot.
# The non-overrideable capacity lives in fw-manifest and is enforced by
# fwmeasure, fwsign, the updater, and FSBL. This Make target is a diagnostic
# receipt, not release authority; fwsign enforces the bound before signing.
# The NS world runs on the stack left over after .bss/.data in its 64 KB SRAM2
# (nonsecure/memory-stm32u585.x), which is already tight. This target surfaces
# both before a flash. Run it standalone against a prepared artifact directory;
# the quarantined `release` target intentionally publishes nothing. Any future
# reviewed release pipeline must invoke the signer-side capacity gate as part
# of its atomic package operation. (2026-07-02: nothing printed image size.)
NS_SRAM_CAP := 65536
NS_STACK_WARN := 12288
NS_STACK_MIN := 2048
.PHONY: size-report
size-report: ## Report secure/NS/FSBL image sizes against their flash/SRAM budgets
	$(if $(findstring i,$(filter-out --%,$(firstword $(MAKEFLAGS)) $(firstword $(MFLAGS)))),$(error size-report refuses make --ignore-errors; a capacity failure must propagate))
	$(if $(wildcard $(RELEASE_ARTIFACT_DIR)/secure.elf),,$(error size-report: missing required $(RELEASE_ARTIFACT_DIR)/secure.elf))
	@echo "==> Image size report"
	@report=$$(cargo run --locked --quiet -p fwmeasure -- \
	  "$(RELEASE_ARTIFACT_DIR)/secure.elf" --require-secure-slot \
	  2>&1 >/dev/null) || { \
	    echo "    secure : FAIL — strict fwmeasure/capacity check rejected the ELF"; \
	    printf '%s\n' "$$report" >&2; \
	    exit 1; \
	  }; \
	used=$$(printf '%s\n' "$$report" | \
	  sed -n 's/^Flash end:.*(\([0-9][0-9]*\) bytes)$$/\1/p'); \
	cap=$$(printf '%s\n' "$$report" | \
	  sed -n 's/^Flash limit: \([0-9][0-9]*\) bytes (secure slot)$$/\1/p'); \
	case "$$used" in \
	  ''|*[!0-9]*) \
	    echo "    secure : FAIL — could not parse strict fwmeasure receipt"; \
	    printf '%s\n' "$$report" >&2; \
	    exit 1 ;; \
	esac; \
	case "$$cap" in \
	  ''|*[!0-9]*) \
	    echo "    secure : FAIL — could not parse strict fwmeasure receipt"; \
	    printf '%s\n' "$$report" >&2; \
	    exit 1 ;; \
	esac; \
	awk -v used="$$used" -v cap="$$cap" 'BEGIN { \
	  pct=used*100.0/cap; \
	  printf "    secure : %d B physical span of %d B slot (%.1f%%), %d B free\n", used, cap, pct, cap-used; \
	  if (used>cap) { print "    secure : FAIL — image exceeds the 464 KB A/B slot"; exit 1 } \
	  if (pct>=85) { printf "    secure : WARN — over 85%% of the slot\n" } }'
	@if [ -f $(RELEASE_ARTIFACT_DIR)/nonsecure.elf ]; then \
	  arm-none-eabi-size -B $(RELEASE_ARTIFACT_DIR)/nonsecure.elf | awk -v cap=$(NS_SRAM_CAP) -v warn=$(NS_STACK_WARN) -v min=$(NS_STACK_MIN) 'NR==2 { \
	    stat=$$2+$$3; free=cap-stat; \
	    printf "    ns     : %d B static (.data+.bss) of %d B SRAM2, %d B left for stack\n", stat, cap, free; \
	    if (free<min) { printf "    ns     : FAIL — under %d B stack reserve\n", min; exit 1 } \
	    if (free<warn) { printf "    ns     : WARN — under %d B stack headroom (NS SRAM2 is tight)\n", warn } }'; \
	else echo "    ns     : (no $(RELEASE_ARTIFACT_DIR)/nonsecure.elf — run make release)"; fi
	@if [ -f $(RELEASE_ARTIFACT_DIR)/fsbl.elf ]; then \
	  arm-none-eabi-size -B $(RELEASE_ARTIFACT_DIR)/fsbl.elf | awk 'NR==2 { u=$$1+$$2; printf "    fsbl   : %d B of 32768 B legacy bench region (%.1f%%), %d B free\n", u, u*100.0/32768, 32768-u }'; \
	elif [ -f $(FSBL_ELF) ]; then \
	  arm-none-eabi-size -B $(FSBL_ELF) | awk 'NR==2 { u=$$1+$$2; printf "    fsbl   : %d B of 32768 B legacy bench region (%.1f%%), %d B free\n", u, u*100.0/32768, 32768-u }'; \
	fi

.PHONY: release _release
# Refusal-only while the rollback implementation is quarantined. Keeping the
# old cleanup/package recipe here would let `make -i` ignore a prerequisite
# failure and publish stale artifacts. Restore the reviewed pipeline only with
# the replacement backend and its production approval.
release: ## Build and atomically publish the signed release package (blocked)
	@$(error release: FAIL — production firmware rollback backend is not implemented; Existing release artifacts were not removed or modified)

_release:
	@$(error _release: REFUSED — internal production packaging is quarantined)

# Hardware bring-up test for the OTP-derived OPTIGA Shielded Connection
# path landed in work-todo #24.
#
# Build config:
#   - optiga-trust-m + stm32u585   : real chip over I2C1 (no SE050 needed)
#   - otp-hardcoded-master-key     : PBS derives from the fixed ASCII
#                                    constant, no real OTP is burned — the
#                                    chip can be re-paired across multiple
#                                    reflashes with a *stable* PBS. This is
#                                    the test we couldn't run before #24.
#   - e2e-test                     : pre-provisions the test mnemonic +
#                                    auto-verifies the PIN, so the OPTIGA
#                                    provisioning pipeline runs end-to-end
#                                    without interactive input.
#   - optiga-lock-operational      : deliberately NOT set. E140 stays at
#                                    LcsO=Creation so the chip is rewriteable
#                                    if anything in the derivation needs
#                                    iterating.
#
# What to watch for on the probe-rs semihosting stream:
#   [OPTIGA] PBS derived from hardware root and loaded
#   [OPTIGA/prov] step 1: setup_pbs_no_handshake
#   [OPTIGA/prov] E140 lifecycle unchanged; factory-side ratchet is a separate OPEN ceremony
#   [OPTIGA/shield] establish: start
#   [OPTIGA/shield] sending MasterHello
#   [OPTIGA/shield] MasterHello response n=38
#   [OPTIGA/shield] PRL handshake OK — encrypted I2C active
#   [OPTIGA] Provisioning complete (6 OIDs written + locked)
#   [S][e2e] gateway pre-unlocked, ready for tests
#
# Rebuild-stability test: after the first successful run, edit any comment
# in the source, rerun `make flash-hw-optiga-bringup`, and confirm the
# same markers appear again. The chip still holds the PBS from the first
# run; the MCU re-derives the same 32 bytes from the hardcoded master;
# the handshake succeeds with the existing chip-side pairing state.
# That's the concrete proof that the firmware_hash-in-wrap-key brick
# class is gone.
flash-hw-optiga-bringup:
	@echo "==> Building OPTIGA Stage-1 bring-up test (Phase B: full PRL)"
	@echo "    (optiga-trust-m + otp-hardcoded-master-key + e2e-test)"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching — watch for PRL handshake markers."
	@echo "    (Ctrl-C to abort; rerun the target after a code change to"
	@echo "     prove the PBS is stable across rebuilds.)"
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Phase A of the OPTIGA Stage-1 hardware validation.
#
# Same build as `flash-hw-optiga-bringup` PLUS `e2e-skip-unlock`, which
# halts the boot flow immediately after `provision_from_mnemonic` returns
# and BEFORE `SE.unlock` runs. The practical effect:
#
#   - `setup_pbs_no_handshake` WRITES the 64-byte PBS to OID E140 via
#     plaintext APDU. The chip records it at LcsO=Creation (rewriteable).
#   - Each user OID (F1D0..F1E1) is provisioned plaintext, LcsO=Creation.
#   - `authenticate_and_read` / `ensure_shield` / `shield.establish` are
#     NEVER called. Ordinary pairing no longer invokes the separately retained,
#     unwired E140 lifecycle primitive in any case. The chip remains fully
#     recoverable.
#
# If the write succeeds, we see `[OPTIGA] PBS provisioned (handshake
# deferred)` followed by `[S][e2e] e2e-skip-unlock active: halting after
# provisioning`. At that point the chip holds our PBS but is still rewrite-
# able via plaintext I2C (LcsO<op), so Phase B can test PRL without a lifecycle
# change, or a re-run with a different PBS can overwrite it.
#
# If the write FAILS (e.g., the chip refuses the 64-byte size, or some
# APDU-level error), we see a `set_data_object FAILED` line and Phase B
# is definitively off the table until the root cause is understood.
flash-hw-optiga-bringup-write-only:
	@echo "==> Building OPTIGA Stage-1 bring-up test (Phase A: write + halt)"
	@echo "    (optiga-trust-m + otp-hardcoded-master-key + e2e-test + e2e-skip-unlock)"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,e2e-skip-unlock,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching — Phase-A validation (no LcsO=op bump)."
	@echo "    Watch for the PBS fingerprint + '[OPTIGA] PBS provisioned'"
	@echo "    followed by 'e2e-skip-unlock active: halting after provisioning'."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Full unlock test: provision + verify_pin + read all secrets through
# the Shielded Connection. Identical features to
# `flash-hw-optiga-bringup-write-only` minus `e2e-skip-unlock` so the
# e2e runner falls through to `SE.unlock(pin)`, which exercises:
#   - `ensure_shield` (handshake / re-handshake)
#   - counter bump + readback (F1E1, data only)
#   - GetRandom → DecryptSym HMAC-verify against F1D0 (silicon PIN gate)
#   - Auto(F1D0)-gated reads of F1D1..F1D4
#   - counter reset to 0 on success
# Critically: `optiga-lock-operational` stays OUT of the feature set,
# so `lock_oid` is a no-op and nothing bumps any OID to Operational.
# No `set_metadata` call is reachable on this path either.
flash-hw-optiga-unlock-test:
	@echo "==> Building OPTIGA unlock test (provision → verify_pin → read secrets)"
	@echo "    Features match bringup-write-only MINUS e2e-skip-unlock."
	@echo "    LcsO on every OID stays at whatever it was on entry."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching — expect 'gateway pre-unlocked, ready for tests'"
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# OPTIGA factory_reset roundtrip e2e. Exercises `factory_reset` end-to-end
# on the real chip: provision F1D0..F1D4 + F1E1 with known test vectors,
# unlock, factory_reset, then verify the counter == RESET_SENTINEL + unlock
# returns NotProvisioned + check_provisioned() == false.
#
# !!! WARNING: this target DESTROYS any wallet state on the chip !!!
# `factory_reset` hardcodes the production OIDs (F1D0..F1D4 + F1E1), so
# the test wipes them. Re-run `make flash-hw-optiga-unlock-test` or the
# real first-boot wizard afterwards to restore. Safe to run on any dev
# bench chip; idempotent across repeated runs.
#
# Scope: exercises the factory_reset PRIMITIVE, NOT the PIN-lockout→wipe
# integration path (that's a separate deferred test).
#
# LcsO-safety: deliberately does NOT include `optiga-lock-operational`.
# Every metadata write in the provisioning step goes via
# `build_metadata_auth_ref` / `build_metadata_user_oid` /
# `build_metadata_counter` (no LCS tag), and `lock_oid` is a no-op. No
# OID is promoted to LcsO=Operational by running this target.
#
# `e2e-test` is required because `otp-hardcoded-master-key` trips the
# production guard in nsc/mod.rs unless the unambiguous "not-shippable"
# marker is set. The e2e-test fast-path itself is dead code here — our
# dispatcher at main.rs halts before the fast-path ever runs.
#
# Watch semihosting for "[E2E-OPTIGA-ADMIN] ADMIN-WIPE ROUNDTRIP: PASS"/"FAIL".
optiga-hw-counter-e2e: ## Provision E120 LUC + drive PIN cycles (HW)
	@echo "==> Building OPTIGA hardware PIN counter (E120 + LUC) e2e firmware..."
	@echo "    This rewrites F1D0 metadata to the LUC-binding variant and"
	@echo "    provisions E120 as the silicon PIN counter. LcsO stays at"
	@echo "    Creation on every touched OID (optiga-lock-operational OFF)."
	@echo "    If F1D0 is somehow already at LcsO=Operational with legacy"
	@echo "    non-LUC metadata the firmware aborts loudly (Status 0xE0) —"
	@echo "    stop and preserve the part; optiga-reset-oids is retired."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-hw-counter-e2e,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running hw-counter e2e (watch semihosting for PASS/FAIL)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

optiga-admin-wipe-e2e:
	@echo "==> Building OPTIGA factory_reset roundtrip e2e firmware..."
	@echo "    WARNING: this build will WIPE any wallet state on the target chip."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-admin-wipe-e2e,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running admin-wipe e2e (watch semihosting for PASS/FAIL)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Dual-SE (OPTIGA + SE050) admin-wipe roundtrip e2e. Exercises
# `DualSecureElement::provision` + `DualSecureElement::unlock` end-to-end:
# pre-clean both chips (tolerates prior test contamination via a
# three-stage cascade: admin-PIN → user-PIN candidates → unauthenticated
# sweep), provision fresh test entropy XOR-split across the two,
# unlock and verify the master_secret reconstructs byte-exact.
#
# !!! WARNING: this target DESTROYS wallet state on BOTH chips !!!
# Pre-clean wipes OPTIGA F1D0..F1D4 + F1E1 and every deletable SE050
# object in the 0x7B0E_xxxx (v5) range. Re-run the normal first-boot wizard
# afterwards to restore. Idempotent across repeated runs on the same
# chip (pre-clean handles each re-invocation).
#
# Scope: exercises the XOR entropy reconstruction — the unique dual-SE
# value-add not covered by either single-SE test. Does NOT exercise
# `factory_reset_admin`; see `make optiga-admin-wipe-e2e` +
# `make se050-admin-wipe-e2e` for those primitives individually, and
# note that the full dual-SE admin-wipe integration is intentionally
# DEFERRED (requires a fresh SE050 whose admin UserID PIN matches
# page-125 flash; cross-test contamination on dev chips desyncs the
# two and makes the test unrunnable without fresh silicon).
#
# LcsO-safety: `optiga-lock-operational` deliberately NOT included.
# OPTIGA stays at Creation throughout. SE050 has no LcsO concept. The
# only "slot commitments" on SE050 are policy installs on freshly-
# created objects within the 0x7B0E_xxxx (v5) range; `store_objects`
# skips creation if objects already exist, so repeat runs don't write
# new policies. Stuck SE050 objects outside 0x7B0E_xxxx (v3 + older)
# are not touched.
#
# `e2e-test` is required because `otp-hardcoded-master-key` trips the
# production guard in nsc/mod.rs. The e2e-test fast-path itself is
# dead code here — our dispatcher halts before it runs.
#
# Watch semihosting for "[E2E-DUAL-ADMIN] DUAL-WIPE ROUNDTRIP: PASS"/"FAIL".
# Multi-unlock / cross-reboot validation for the SE050-corruption fix.
# First cold boot: provisions both chips with a fixed test mnemonic+PIN,
# then does 5 consecutive unlock+XOR-reconstruct+verify cycles.
# Subsequent cold boots: detects the provisioned state, skips
# re-provisioning, does another 5 unlocks. Across the 3 runs below =
# 15 unlocks spread over 3 full power-cycle equivalents (probe-rs reset
# + run). PASS on all three proves SE050 ENTROPY_OBJ survives the full
# provisioning pulse sequence AND stays stable across reboots — the
# exact "works once, fails on reboot" scenario from the old cross-
# coupling bug. Use `make dual-se-multi-unlock-e2e`.
dual-se-multi-unlock-e2e:
	@echo "==> Building dual-SE multi-unlock / reboot e2e firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se-multi-unlock-e2e,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo ""
	@for n in 1 2 3; do \
		echo "==> Boot $$n/3..."; \
		log=$$(mktemp -t dual-se-multi-b$$n.XXXXXX.log); \
		probe-rs run --chip $(CHIP) $(SECURE_ELF) 2>&1 | tee "$$log"; \
		sleep 3; \
		if grep -q "MULTI-UNLOCK ROUNDTRIP: PASS" "$$log"; then \
			echo "==> Boot $$n PASS"; \
			rm -f "$$log"; \
		else \
			echo "==> Boot $$n FAIL"; rm -f "$$log"; exit 1; \
		fi; \
		echo ""; \
	done
	@echo "==> ALL 3 BOOTS PASS — 15 unlocks across 3 cold reboots"
	@echo ""
	@echo "==> ALL 3 BOOTS PASS — 15 unlocks across 3 cold reboots, master_secret reproduces every time"

dual-se-admin-wipe-e2e:
	@echo "==> Building dual-SE unlock roundtrip e2e firmware..."
	@echo "    WARNING: this build will WIPE wallet state on BOTH chips."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se-admin-wipe-e2e,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running dual-SE unlock e2e (watch semihosting for PASS/FAIL)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Tier-2 silicon-root variant of dual-se-admin-wipe-e2e: exercises the
# SAME dual-SE unlock roundtrip + admin-wipe cascade, but with the real
# hardware HUK roots — `saes-dhuk` (OPTIGA PBS over SAES-CMAC(DHUK)) and
# `bhk` (SE050 SCP03 + admin PIN over SAES-CMAC(BHK)). No hardcoded test
# keys: `otp-hardcoded-master-key` and `bhk-hardcoded-master-key` are
# BOTH off, so this is the closest thing to the shipping derivation we
# can run on the bench.
#
# What it does on first boot:
#   - `[S] SAES initialised (Tier-1 DHUK path)`
#   - if flash page 126 is blank: `[S] BHK provisioned (first boot)` —
#     generates 32 TRNG bytes, DHUK-ECB-wraps them, writes page 126.
#     REVERSIBLE: page 126 is mass-erasable (RDP regression / explicit
#     `flash::erase_secure_page(126)`); an RDP regression on a bhk-active
#     device just means the SE050 needs re-pairing afterward (OPTIGA's
#     PBS is on DHUK directly and survives). No OTP is touched — with
#     `saes-dhuk` on, `secret_keys::derive_into` routes to SAES-CMAC,
#     never `otp::ensure_device_master` (pre-flight audit confirmed).
#   - else: `[S] BHK loaded + BHKLOCK set` — unwraps page 126 into
#     TAMP BKP0R..7R, sets BHKLOCK.
#   - then the usual pre-clean cascade (`se050.factory_reset_admin()`
#     re-derives the admin PIN via the real BHK), fresh provision, and
#     the dual-SE unlock roundtrip.
#
# WIPES wallet state on BOTH chips (same as dual-se-admin-wipe-e2e).
# Watch semihosting for the dual-SE PASS line.
dual-se-bhk-e2e:
	@echo "==> Building dual-SE Tier-2 (real DHUK+BHK) unlock roundtrip e2e firmware..."
	@echo "    WARNING: this build will WIPE wallet state on BOTH chips,"
	@echo "             and (on first boot) provision a DHUK-wrapped BHK to flash page 126."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se-admin-wipe-e2e,stm32u585,ui-lcd,debug-log,e2e-test,saes-dhuk,bhk,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running dual-SE Tier-2 e2e (watch semihosting for SAES/BHK init lines + PASS/FAIL)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# PIN-gate roundtrip e2e. Direct non-interactive test of the MCU-side
# PIN attempt counter at flash page 124 + the `nsc::gated_unlock`
# pre-commit pattern. No buttons, no USB — hardcoded right/wrong PINs
# + semihosting PASS/FAIL.
#
# Validates work-todo #4 Phase 1 (dual-SE PIN lockout sync): counter
# bumps on wrong PIN, counter resets to 0 on correct PIN, cycle is
# repeatable. Does not test the PinLocked path (would burn SE050's
# silicon retry counter and brick the v5 UserID for an otherwise-
# provable inspection-only check).
#
# Destroys any wallet state on both chips (the initial factory_reset_
# admin + fresh provision with a test PIN). Re-run the normal first-
# boot wizard afterwards to restore.
#
# Watch semihosting for "[E2E-PIN-GATE] PIN-GATE ROUNDTRIP: PASS".
# §32 duress-PIN feasibility probe. Provisions a SECOND OPTIGA AuthRef
# (F1D8, Execute=ALW / no E120 binding) + a SECOND SE050 UserID
# (max_attempts=0) alongside the real credentials, and asserts they
# coexist AND that the duress OPTIGA auth leaves E120 untouched. Stays
# LcsO=Creation on every OID (never locks → fully recoverable).
# Reprovisions the bench chips with test data, like the other SE e2es.
#
# Pass: semihosting ends with "DURESS COEXISTENCE PROBE: PASS".
# §32 timing-channel measurement (decides the P3 drift fix). Same
# firmware as duress-probe-hw but built WITHOUT debug-log so the
# measured SE verifies run at production speed (no per-I²C-transaction
# semihosting). The coexistence steps run silently; the
# [DURESS-TIMING] lines print via unconditional hprintln!. Watch for
# the OPTIGA/SE050 per-verify latency + the "EXTRA real-verify cost".
duress-timing-hw:
	@echo "==> Building §32 timing-channel measurement firmware (no debug-log → production-speed verifies)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features duress-probe-e2e,stm32u585,ui-lcd,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running timing measurement (watch for [DURESS-TIMING] lines)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

duress-probe-hw:
	@echo "==> Building §32 duress-PIN coexistence probe firmware..."
	@echo "    Adds a 2nd OPTIGA AuthRef (F1D8, no E120) + 2nd SE050 UserID"
	@echo "    (unlimited) next to the real credentials. NEVER locks an OID;"
	@echo "    every credential stays LcsO=Creation / re-writable."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features duress-probe-e2e,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running duress-PIN coexistence probe (watch for DURESS COEXISTENCE PROBE: PASS)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

duress-provision-hw:
	@echo "==> Building §32 P2 full provision_duress silicon-validation firmware..."
	@echo "    Provisions a real wallet + an independent decoy via the PRODUCTION"
	@echo "    provision/provision_duress path, then reads both decoy halves and"
	@echo "    asserts half_o XOR half_e == the known decoy entropy + E121-only bump"
	@echo "    + real wallet still unlocks. Stays LcsO=Creation (never locks)."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features duress-provision-e2e,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running duress provision validation (watch for DURESS PROVISION VALIDATION: PASS)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

pin-gate-hw-counter-e2e: ## Three-way MCU+OPTIGA+SE050 PIN-sync E2E (HW)
	@echo "==> Building combined sync + desync recovery e2e firmware..."
	@echo "    Exercises MCU page-124 + OPTIGA E120 + SE050 UserID counters"
	@echo "    together under dual-se + optiga-hw-counter. WIPES wallet state"
	@echo "    on BOTH chips. Does NOT bump any OID to LcsO=Operational."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features pin-gate-hw-counter-e2e,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running combined sync + desync e2e (watch for SYNC+DESYNC ROUNDTRIP: PASS)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

pin-gate-wipe-e2e: ## 10 wrong PINs -> factory-reset both SEs (HW)
	@echo "==> Building MCU-MAX-ATTEMPTS lockout-wipe dispatch e2e firmware..."
	@echo "    DESTRUCTIVE: burns 10 wrong PINs → SE050 UserID silicon-locks,"
	@echo "    MCU counter saturates, E120 LUC at 10. Then fires"
	@echo "    factory_reset_admin + pin_attempts_reset to prove the lockout-"
	@echo "    wipe dispatch path end-to-end. Re-provisions at the end to"
	@echo "    prove recovery. Does NOT bump any OID to LcsO=Operational."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features pin-gate-wipe-e2e,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running wipe dispatch e2e (watch for WIPE+RECOVERY ROUNDTRIP: PASS)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Re-run the currently-flashed wipe-for-wizard firmware under probe-rs
# with semihosting, WITHOUT rebuilding, re-downloading non-secure, or
# re-configuring TrustZone option bytes. The normal `make wipe-for-
# wizard` flow detaches probe-rs right after the "WIPED — power-cycle
# me" halt, so the subsequent physical power-cycle boots blind — there
# is no semihosting sink attached to capture the wizard path's output.
#
# This target re-enters the flow by issuing an SWD reset through
# probe-rs and streaming the new boot's logs. Functionally equivalent
# to a physical power-cycle with the probe still attached. The secure
# ELF is re-downloaded (same image — effectively a no-op) so we can
# piggyback `probe-rs run`'s built-in reset + attach sequence; the
# non-secure ELF stays whatever was last flashed by `wipe-for-wizard`.
#
# Pre-req: a prior `make wipe-for-wizard` (or any target that flashed
# both secure + non-secure ELFs and set TZEN/SECBOOTADD0). Use this
# when you see a successful wipe halt but nothing visible on the next
# boot — the semihosting trace will show whether the chip is in the
# "nothing to wipe → fall through to wizard" branch or failing earlier.
wipe-for-wizard-rerun:
	@echo "==> Re-running already-flashed wipe-for-wizard firmware under probe-rs semihosting..."
	@echo "    (no rebuild, no NS re-flash, no TZ option-byte rewrite)"
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

wipe-for-wizard: ## Dev: wipe both SEs + page 124, halt (HW)
	@echo "==> Building dev wipe-for-wizard firmware..."
	@echo "    DESTRUCTIVE (wallet state): wipes OPTIGA user OIDs,"
	@echo "    SE050 user objects + admin UserID, MCU page 124."
	@echo "    PRESERVES: STM32 OTP master, OPTIGA E140 PBS, all OID"
	@echo "    metadata (LcsO stays at Creation), resident firmware."
	@echo "    Boot 1: wipes + halts on 'WIPED — power-cycle me'."
	@echo "    Boot 2 (after power-cycle): drops into interactive"
	@echo "    first-boot wizard for fresh mnemonic + PIN entry."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features wipe-for-wizard,stm32u585,debug-log,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running wipe (watch OLED for 'WIPED — power-cycle me')..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# One-shot D6 pin-identification diagnostic.
# Builds a minimal secure-world firmware that runs `pin_diag::run()`
# at the top of `main()` (pulsing PA4/PD5/PE0/PE4/PE5/PB6 with
# distinct widths) and then parks the CPU in `wfe`. No provisioning,
# no SE init beyond the GPIO toggling — safe to flash over any
# existing state.
# Workflow:
#   1. `sigrok-cli --driver kingst-la2016 --channels CH3 --time 5000 \
#          --config samplerate=1m -o /tmp/d6.sr` in one terminal
#   2. `make pin-diag-boot-hw` in another (flashes + runs)
#   3. The width visible on CH3 identifies the STM32 pin on D6.
pin-diag-boot-hw:
	@echo "==> Building pin-diag-boot firmware (one-shot D6 finder)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features pin-diag-boot,debug-log,ui-noop
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running (pulses fire once, then CPU halts in wfe)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# One-shot SAES self-test on real silicon. Boots the firmware just far
# enough to init SAES (Tier 1 of work-todo #7), runs the software-key
# round-trip + DHUK-vs-SW domain-separation + DHUK round-trip self-
# tests, prints an 8-byte DHUK fingerprint, then exits cleanly via
# SYS_EXIT. No OTP burn, no flash writes, no TAMP access, no SE I/O.
# Cross-boot check: run this twice on the same board — the DHUK
# fingerprint must be byte-identical across reboots. Running on
# different boards should yield different fingerprints.
# Masked-SHA-256 overhead bench (work-todo §18 SHAKE-vs-SHA2 #2
# measurement). Builds the bench firmware, flashes, configures TZ,
# streams the DWT-timed results over semihosting. Reports the
# projected masked-SHA-256-block slowdown vs the HASH peripheral.
#
# `e2e-test` escapes the production fence + permits `mock-se` (the
# bench short-circuits before any SE access). `ui-noop` is headless.
# `bench-masked-sha` implies stm32u585 (→ hw-sha256), so the
# HASH-peripheral baseline is real silicon, not software.
#
# NOTE: deliberately NO `debug-log`. `hw::rng::fill` emits a
# `secure_log!("[S] rng::fill entry ...")` on EVERY call when debug-log
# is on; the bench draws the TRNG hundreds of thousands of times, so
# debug-log floods the semihosting channel (one slow probe round-trip
# per draw) and the bench crawls. The bench prints its results via
# unconditional `hprintln!`, which works under probe-rs regardless of
# debug-log — so dropping it keeps the results AND kills the flood.
#
# Pass: streams `[BENCH] ...` lines ending in
#       `=== masked-sha2 bench complete ===`, then SYS_EXITs.
bench-masked-sha-hw:
	@echo "==> Building masked-SHA-256 overhead bench firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features bench-masked-sha,ui-noop,e2e-test,mock-se
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running masked-SHA-256 bench (streaming results)..."
	@log=$$(mktemp -t bench-masked-sha.XXXXXX.log); \
	trap 'rm -f "$$log"' EXIT; \
	probe-rs run --chip $(CHIP) $(SECURE_ELF) 2>&1 | tee "$$log"; \
	echo "===================================="; \
	if grep -q "=== masked-sha2 bench complete ===" "$$log"; then \
		echo "==> bench-masked-sha: DONE"; exit 0; \
	else \
		echo "==> bench-masked-sha: FAIL (missing completion marker)"; exit 1; \
	fi

saes-self-test-hw: ## SAES SW + DHUK round-trip + fingerprint (HW)
	@echo "==> Building SAES Tier-1 self-test firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features saes-self-test,debug-log,ui-noop,e2e-test,mock-se
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running SAES self-test..."
	@log=$$(mktemp -t saes-self-test.XXXXXX.log); \
	trap 'rm -f "$$log"' EXIT; \
	probe-rs run --chip $(CHIP) $(SECURE_ELF) 2>&1 | tee "$$log"; \
	echo "===================================="; \
	if grep -q "=== self_test PASS ===" "$$log"; then \
		echo "==> saes-self-test: PASS"; exit 0; \
	else \
		echo "==> saes-self-test: FAIL (missing PASS marker)"; exit 1; \
	fi

# RDP1 variant of the SAES self-test — captures the REAL per-die DHUK
# fingerprint by stepping the chip to RDP1 (where ST activates the real
# DHUK, instead of the RDP0 placeholder constant shared across every
# STM32U585). Because RDP1 disables SWD debug, semihosting / probe-rs
# can't see the output — we route the PASS line over USART1 → ST-LINK
# VCP instead. The ST-LINK's VCP is a feature of the on-board debugger
# MCU and works independently of the target's RDP level.
#
# Flow:
#   1. Build firmware with `uart-console` so the fp goes out PA9.
#   2. Flash firmware at RDP0 (the only RDP where flash-via-SWD works
#      without OEM keys).
#   3. Start capturing /dev/serial/by-id/*STLINK* in the background.
#   4. Program RDP=0xBB to step to RDP1 — the chip resets, firmware
#      re-runs with the real per-die DHUK.
#   5. Wait ~5 seconds for the fp line, then kill capture.
#   6. Grep for the PASS line + extract the fingerprint.
#
# IMPORTANT: run `make saes-self-test-hw-rdp0-regress` afterward to
# restore the board to RDP0 for normal dev iteration. Leaving a board
# at RDP1 is fine (reversible), but you can't re-flash via probe-rs
# until you regress.
saes-self-test-hw-rdp1:
	@echo "==> Building SAES Tier-1 self-test firmware (UART console)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features saes-self-test,uart-console,debug-log,ui-noop,e2e-test,mock-se
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing at RDP0..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Ensuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@set -e; \
	vcp=$$(ls /dev/serial/by-id/*STLINK*-if02* 2>/dev/null | head -1); \
	if [ -z "$$vcp" ]; then \
		vcp=$$(ls /dev/serial/by-id/*STLINK* 2>/dev/null | head -1); \
	fi; \
	if [ -z "$$vcp" ]; then \
		echo "==> saes-self-test-hw-rdp1: FAIL — no ST-LINK VCP at /dev/serial/by-id/*STLINK*"; \
		exit 1; \
	fi; \
	echo "==> Using ST-LINK VCP: $$vcp"; \
	stty -F "$$vcp" 115200 cs8 -cstopb -parenb raw -echo -ixon -ixoff 2>/dev/null || true; \
	log=$$(mktemp -t saes-rdp1.XXXXXX.log); \
	timeout 8 cat "$$vcp" > "$$log" 2>&1 & \
	cat_pid=$$!; \
	sleep 0.3; \
	echo "==> Stepping chip to RDP1 (RDP=0xBB) — chip resets + firmware runs at RDP1..."; \
	$(STM32_PROG) --connect port=SWD mode=UR --optionbytes RDP=0xBB || \
		$(STM32_PROG) --connect port=SWD mode=HotPlug --optionbytes RDP=0xBB || true; \
	wait $$cat_pid 2>/dev/null || true; \
	echo "===================================="; \
	echo "==> ST-LINK VCP capture:"; \
	cat "$$log"; \
	echo "===================================="; \
	ret=1; \
	if grep -q "self_test PASS" "$$log"; then \
		fp=$$(grep "DHUK(fp)=" "$$log" | head -1 | sed 's/.*DHUK(fp)=//;s/[^0-9a-f].*//'); \
		echo "==> saes-self-test-hw-rdp1: PASS"; \
		echo "==> RDP1 DHUK fingerprint: $$fp"; \
		echo "==> Board is now at RDP1. Run 'make saes-self-test-hw-rdp0-regress' to return to RDP0."; \
		ret=0; \
	else \
		echo "==> saes-self-test-hw-rdp1: FAIL — no PASS line captured on VCP."; \
		echo "==> Chip may be at RDP1 now; 'make saes-self-test-hw-rdp0-regress' will recover."; \
	fi; \
	rm -f "$$log"; \
	exit $$ret

# Regress a board from RDP1 (or above, with OEM2 password) back to RDP0.
# Mirrors ST's own `Projects/B-U585I-IOT02A/Applications/SBSFU/SBSFU_Boot/
# STM32CubeIDE/regression.sh` pattern: writes RDP=0xAA, strips WRP1/WRP2
# + SECWM, forces an `-e all` mass erase, and restores default option
# bytes. ST's OpenBootloader source confirms: "Going from RDP level 1 to
# RDP level 0 erase all the flash" (Middlewares/ST/OpenBootloader/
# Modules/I2C/openbl_i2c_cmd.c:399).
#
# Caveats:
#   - Mass-erases both flash banks. MCU-side wallet state (pages 123-125)
#     is wiped; OTP survives (OTP is silicon-level one-way, not tied to
#     RDP). SE050 / OPTIGA NVM is untouched (separate chips).
#   - No OEM2 password is set or expected. If you've ever burnt one, you
#     need to add `--readunprotect <password>` or similar to the CLI call.
#   - Does NOT step RDP2 → RDP1 (RDP2 is permanent). Only RDP1 → RDP0.
saes-self-test-hw-rdp0-regress:
	@echo "==> Regressing RDP1 → RDP0 (mass-erase will wipe flash banks 1+2)..."
	@echo "    Note: OTP survives; SE050 / OPTIGA NVM are separate chips and unaffected."
	@$(STM32_PROG) --connect port=SWD mode=UR --optionbytes RDP=0xAA \
		UNLOCK_1A=1 UNLOCK_1B=1 UNLOCK_2A=1 UNLOCK_2B=1 || \
		$(STM32_PROG) --connect port=SWD mode=HotPlug --optionbytes RDP=0xAA \
			UNLOCK_1A=1 UNLOCK_1B=1 UNLOCK_2A=1 UNLOCK_2B=1
	@echo "==> Stripping write-protect + secure watermarks..."
	@$(STM32_PROG) --connect port=SWD --optionbytes \
		WRP1A_PSTRT=0x7F WRP1A_PEND=0x0 WRP1B_PSTRT=0x7F WRP1B_PEND=0x0 \
		WRP2A_PSTRT=0x7F WRP2A_PEND=0x0 WRP2B_PSTRT=0x7F WRP2B_PEND=0x0 \
		SECWM1_PSTRT=0x7F SECWM1_PEND=0x0 SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 || true
	@echo "==> Mass-erase both banks..."
	@$(STM32_PROG) --connect port=SWD -e all
	@echo "==> Restoring default option bytes (TZEN=1 + full-secure banks + SECBOOTADD0)..."
	@$(STM32_PROG) --connect port=SWD --optionbytes \
		TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Regression complete — board is back at RDP0."

pin-gate-e2e: ## MCU PIN pre-commit/reset E2E (HW; no E120 counter or reboot reconcile)
	@echo "==> Building PIN-gate roundtrip e2e firmware..."
	@echo "    WARNING: this build will WIPE wallet state on BOTH chips."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features pin-gate-e2e,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running PIN-gate e2e (watch semihosting for PASS/FAIL)..."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Shield-handshake-only test. Skips `provision_from_mnemonic` entirely
# and runs `init` → `load_pbs_from_device_root` → `ensure_shield` against an
# already-provisioned chip. Use this to validate the Shielded Connection
# handshake in isolation without re-writing any F1Dx state. The chip's
# E140 must already have the matching device-root-derived PBS from a prior run of
# `flash-hw-optiga-bringup-write-only`; the PBS itself is reproduced
# deterministically from the configured device root on every boot (DHUK in the
# current bring-up/candidate transport path; OTP only in explicit dev/legacy
# builds). This target does not exercise or approve the journaled
# `rdp2-self-lock` final-rotation candidate.
flash-hw-optiga-shield-handshake-only:
	@echo "==> Building OPTIGA shield-handshake-only test"
	@echo "    (e2e-skip-provision: reuses existing E140 PBS, tests PRL only)"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,e2e-skip-unlock,e2e-skip-provision,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching — expect '[S][e2e] SHIELD UP — PRL handshake succeeded'."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Retired OPTIGA SetObjectProtected experiment: regenerate the historical
# manifest bytes for incident/evidence reproducibility only. This target does
# not build firmware, flash a board, change option bytes, or grant recovery
# authority. The paired flash target below refuses unconditionally.
optiga-reset-oids:
	@echo "==> Regenerating reset manifests (requires built tool)"
	@test -x /home/nicola/repos/optiga-trust-m/examples/tools/protected_update_data_set/bin/protected_update_data_set \
		|| (echo "Build the tool first: make -C /home/nicola/repos/optiga-trust-m/examples/tools/protected_update_data_set" && exit 1)
	@python3 tools/optiga_reset/gen_reset_manifests.py

flash-hw-optiga-reset:
	@echo "REFUSED: the retired E0E3 sample-anchor recovery path is mis-targeted"
	@echo "for the observed OPTIGA SKU/revision and has no reviewed replacement."
	@echo "It must not build, flash, or touch option bytes. See docs/archive/production-todo-retired-2026-07-19.md S-2."
	@false

# Coverage-guided libFuzzer harnesses (`fuzz/`, kept as a standalone
# workspace since cargo-fuzz needs nightly + libFuzzer + sanitizers).
# Pure-logic parsers only — the proptest sibling that always runs is
# in `secure/src/fuzz_props.rs`. See `fuzz/README.md` for setup and
# `docs/architecture/trezor-comparison.md §2.4` for the rationale.
#
# Usage:
#   make fuzz-list                 -- list available targets
#   make fuzz-aa-userop-parse [TIME=600]
#   make fuzz-rlp-decode-item [TIME=600]
#   make fuzz-eip1559-parse [TIME=600]
#   make fuzz-erc20-calldata [TIME=600]
#   make fuzz-erc20-bundle [TIME=600]
#   make fuzz-apdu-parse-header [TIME=600]
#   make fuzz-hid-frame-assembler [TIME=600]
#   make fuzz-optiga-response-parse [TIME=600]
#
# TIME (seconds) bounds the libFuzzer run; omit for unbounded.
FUZZ_TIME ?= $(TIME)
FUZZ_LIBFUZZER_ARGS = $(if $(FUZZ_TIME),-- -max_total_time=$(FUZZ_TIME),)

# On a nix-based toolchain the libFuzzer binary can't find libstdc++ at runtime
# (the system libstdc++ is GLIBC-incompatible with the nix-built cargo-fuzz).
# Auto-prepend the nix gcc-lib dir if present; empty on a standard glibc env
# (where the binaries link the system libstdc++ and just run).
FUZZ_LD := $(shell ls -d /nix/store/*gcc-1[45]*-lib/lib 2>/dev/null | head -1)
# Prefer a versioned symbolizer whose matching libLLVM is installed.  Some
# hosts expose `/usr/bin/llvm-symbolizer` from LLVM 18 even though its shared
# library is absent; libFuzzer then exits during its first NEW_FUNC report.
# Keep this overrideable for Nix/CI images with a different known-good binary.
FUZZ_SYMBOLIZER ?= $(shell command -v llvm-symbolizer-17 2>/dev/null || command -v llvm-symbolizer 2>/dev/null || true)
FUZZ_ENV := $(if $(FUZZ_LD),LD_LIBRARY_PATH=$(FUZZ_LD),) $(if $(FUZZ_SYMBOLIZER),ASAN_SYMBOLIZER_PATH=$(FUZZ_SYMBOLIZER),)

# Net-isolation (SOTA 2026-06 §7 egress discipline): the fuzzer RUN phase has no
# business reaching the network, so wrap it in tools/sca/run-isolated.sh
# (bwrap --unshare-net, fails closed). The BUILD stays networked (it's not
# wrapped). Composed via `env` so it coexists with the optional FUZZ_ENV LD
# prefix. Override with `make fuzz-all FUZZ_ISOLATE=` to disable (e.g. a host
# without bwrap, or inside a CI container that already drops the network).
FUZZ_ISOLATE ?= $(CURDIR)/tools/sca/run-isolated.sh

.PHONY: fuzz-list fuzz-all fuzz-aa-userop-parse fuzz-rlp-decode-item fuzz-eip1559-parse fuzz-erc20-calldata fuzz-erc20-bundle fuzz-apdu-parse-header fuzz-hid-frame-assembler fuzz-optiga-response-parse

# Smoke the whole adversarial parse surface: run every target for FUZZ_TIME
# seconds (default 30) against its seed corpus. Coverage-guided libFuzzer; a
# crash drops an artifact under fuzz/artifacts/<target>/ to triage (these parsers
# are Kani-proven panic-free on bounded input, so a crash = a real unbounded-path
# bug OR a harness artifact — decide which before "fixing"). Last full run
# (2026-07-13): all 12 targets non-vacuous, 0 artifact files of any kind.
fuzz-all: SHELL := /usr/bin/env bash
fuzz-all: ## Run every cargo-fuzz target for FUZZ_TIME
	@cd fuzz && cargo +nightly fuzz build
	@set -o pipefail; cd fuzz && \
	if ! targets=$$(cargo +nightly fuzz list); then \
	  echo "FAIL: cargo-fuzz could not enumerate targets"; \
	  exit 1; \
	fi; \
	if [ -z "$$(printf '%s' "$$targets" | tr -d '[:space:]')" ]; then \
	  echo "FAIL: cargo-fuzz enumerated zero targets"; \
	  exit 1; \
	fi; \
	run_count=0; \
	for t in $$targets; do \
	  run_count=$$((run_count + 1)); \
	  echo "==> fuzz $$t ($(or $(FUZZ_TIME),30)s)"; \
	  mkdir -p corpus/$$t artifacts/$$t; \
	  if ! $(FUZZ_ISOLATE) env $(FUZZ_ENV) target/x86_64-unknown-linux-gnu/release/$$t corpus/$$t \
	    -max_total_time=$(or $(FUZZ_TIME),30) -rss_limit_mb=2048 -artifact_prefix=artifacts/$$t/ \
	    2>&1 | grep -E "DONE|cov: [0-9]+ ft:|crash|deadly signal|SUMMARY" | tail -2; then \
	    echo "FAIL: fuzz target $$t exited non-zero or never reached a reportable verdict"; \
	    exit 1; \
	  fi; \
	done; \
	c=$$(find artifacts -type f 2>/dev/null | wc -l); \
	if [ "$$c" -ne 0 ]; then \
	  echo "FAIL: fuzz-all produced $$c artifact(s) under fuzz/artifacts/"; \
	  exit 1; \
	fi; \
	echo "==> fuzz-all done; $$run_count target(s); artifacts: 0"

fuzz-list: ## List the cargo-fuzz targets
	@echo "Available fuzz targets (see fuzz/README.md):"
	@cd fuzz && cargo +nightly fuzz list 2>/dev/null || \
		(echo "  cargo-fuzz not installed. Install with:"; \
		 echo "    cargo install cargo-fuzz"; \
		 echo "    rustup install nightly"; \
		 echo "  Then re-run \`make fuzz-list\`."; exit 1)

fuzz-aa-userop-parse:
	cd fuzz && cargo +nightly fuzz run aa_userop_parse_header $(FUZZ_LIBFUZZER_ARGS)

fuzz-rlp-decode-item:
	cd fuzz && cargo +nightly fuzz run tx_core_rlp_decode_item $(FUZZ_LIBFUZZER_ARGS)

fuzz-eip1559-parse:
	cd fuzz && cargo +nightly fuzz run tx_core_eip1559_parse $(FUZZ_LIBFUZZER_ARGS)

fuzz-erc20-calldata:
	cd fuzz && cargo +nightly fuzz run tx_erc20_parse_calldata $(FUZZ_LIBFUZZER_ARGS)

fuzz-erc20-bundle:
	cd fuzz && cargo +nightly fuzz run tx_erc20_verify_bundle $(FUZZ_LIBFUZZER_ARGS)

fuzz-apdu-parse-header:
	cd fuzz && cargo +nightly fuzz run apdu_parse_header $(FUZZ_LIBFUZZER_ARGS)

fuzz-optiga-response-parse:
	cd fuzz && cargo +nightly fuzz run optiga_response_parse $(FUZZ_LIBFUZZER_ARGS)

fuzz-hid-frame-assembler:
	cd fuzz && cargo +nightly fuzz run hid_frame_assembler $(FUZZ_LIBFUZZER_ARGS)

fuzz-erc7730-verify-bundle:
	cd fuzz && cargo +nightly fuzz run erc7730_verify_bundle $(FUZZ_LIBFUZZER_ARGS)

fuzz-erc7730-ir-parse:
	cd fuzz && cargo +nightly fuzz run erc7730_ir_parse $(FUZZ_LIBFUZZER_ARGS)

fuzz-erc7730-render-dispatch:
	cd fuzz && cargo +nightly fuzz run erc7730_render_dispatch $(FUZZ_LIBFUZZER_ARGS)

# Populate the render-dispatch corpus from the current pinned ERC-7730 catalogue
# (the current generated registry IR corpus) so the fuzzer starts from valid
# descriptors. Coverage numbers
# are root/source-tree specific; regenerate and rerun after every root rotation
# before reporting them. See docs/erc7730-renderer-fuzzability.md.
fuzz-seed-erc7730-render:
	cd fuzz && cargo test --test gen_render_seeds -- --ignored --nocapture

fuzz-erc7730-display-primitives:
	cd fuzz && cargo +nightly fuzz run erc7730_display_primitives $(FUZZ_LIBFUZZER_ARGS)

fuzz-multisend-decode:
	cd fuzz && cargo +nightly fuzz run multisend_decode $(FUZZ_LIBFUZZER_ARGS)

# F-24 stage E Phase 1 — hardware flicker validation harness for the
# decoy-mnemonic-frame defense. Builds a minimal secure firmware that
# short-circuits `main()` into `ui::seed_wizard::decoy_flicker_test_loop`
# (renders page 0 of a fixed test mnemonic interleaved with 4 fixed
# decoys at the production 5:1 = 200ms:40ms cadence, forever). No
# wizard, no buttons, no SE access. A bench user stares at the OLED
# and reports whether the cadence is visually readable.
#
# Expected screen: row 0 = "Phrase 1/8" title, rows 1-3 = three words
# from the test mnemonic (varying every ~240 ms cycle between real
# and one of 4 decoys). If the flicker is acceptable, ship as-is. If
# distracting, bump REAL_FRAME_HOLD_MS in
# `secure/src/ui/seed_wizard.rs:129` to 400-500 (smooths visual at
# cost of decoy coverage).
decoy-flicker-hw:
	@echo "==> Building decoy-flicker-test firmware..."
	@echo "    Renders page 0 forever with 5:1 real:decoy cadence."
	@echo "    No buttons, no wizard, no SE — just OLED rendering."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features decoy-flicker-test,mock-se,debug-log,ui-lcd,stm32u585,dev-testkey,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running — watch the OLED. Ctrl-C to detach."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Decoy-flicker test on the NV3007 LCD (Phase D — F-24 stage E sub-channel 4).
# Same harness as decoy-flicker-hw but `ui-lcd`. The LCD's slow-response pixels
# (Tr+Tf ~35 ms) are the whole point: a decoy painted briefly then overwritten
# by the next real frame may never fully transition (subliminal to the eye)
# while the SPI bus still carries it (the defense). The loop SWEEPS DECOY_HOLD =
# 40/25/15/8/3/0 ms (~4-5 s each, logged) so you can find the subliminal
# threshold. Builds + flashes; then run + watch the panel:
#   probe-rs run --chip $(CHIP) $(SECURE_ELF)
# Requires the NV3007 wired per docs/hardware/nv3007-wiring.md.
decoy-flicker-lcd-hw:
	@echo "==> Building decoy-flicker-test firmware for the NV3007 LCD..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features decoy-flicker-test,mock-se,debug-log,ui-lcd,stm32u585,dev-testkey,usb,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Flashed. Run + watch the LCD (log prints the active DECOY_HOLD):"
	@echo "    probe-rs run --chip $(CHIP) $(SECURE_ELF)"

# Factory production-line test (prodtest) firmware. Single-purpose,
# reversible acceptance-test candidate; a pass does NOT authorize or chain the
# quarantined factory_provisioning ceremony. Sits in WFI after boot, waiting
# for the factory fixture to drive each component test via USB. See
# `docs/provisioning/factory-prodtest.md` for the command reference + fixture
# integration guide.
#
# Phase A (landed 2026-05-19): CMD_PRODTEST_GET_ID +
#                              CMD_PRODTEST_DISPLAY_PATTERN
# The supported profile requires SAES/DHUK, but deliberately keeps BHK and
# FLASH_RW unsupported: their wire commands are negative capability checks,
# not passing component tests. Communication and button tests are required.
# Keep these feature lists exact and synchronized with the machine-readable
# receipt emitted by tools/factory-prodtest-runner.py.
override PRODTEST_SECURE_FEATURES := prodtest,dev-testkey,saes-dhuk,$(BOARD_FEATURE)
override PRODTEST_NONSECURE_FEATURES := stm32u585,usb,prodtest
#
# Use this target to validate the prodtest build compiles cleanly;
# silicon validation is Phase B work in work-todo §30.
build-hw-prodtest:
	@echo "==> Building prodtest firmware..."
	@echo "    Boot sequence:"
	@echo "      1. Normal STM32 + SE + button + USB init"
	@echo "      2. Display 'PRODTEST READY' on NV3007 LCD"
	@echo "      3. Launch NS world (USB stack)"
	@echo "      4. Wait for USB INSes (INS_V2_PRODTEST_* 0x80-0x89)"
	@echo "    Factory fixture drives the test sequence via USB HID."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features $(PRODTEST_SECURE_FEATURES)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --no-default-features \
		--features $(PRODTEST_NONSECURE_FEATURES)
	@echo "==> Prodtest build ready."
	@echo "    Host fixture runner at tools/factory-prodtest-runner.py"

# Factory provisioning firmware (QUARANTINED). The historical design below
# is retained for review context; the target is refusal-only because the
# receipt QW is programmed at entry and then illegally reprogrammed at
# completion. Direct Cargo builds are compile-blocked too.
# Single-purpose build the factory
# operator flashes to a fresh device. Runs the
# `factory_provisioning::run_and_halt` state machine — validates
# hardware, provisions OPTIGA + SE050 infrastructure, wipes the
# dummy user state, cross-validates, and halts on a "FACTORY OK"
# or "FACTORY FAIL @ STEP X" OLED panel.
#
# Build profile:
#   - dual-se (required): both SEs must be alive to be provisioned.
#   - stm32u585 (required): real silicon target.
#   - ui-lcd (required): the operator needs the OLED panel.
#   - dev-testkey: factory uses the deterministic OTP-master constant
#     during bring-up of this target. **REMOVE for real production**
#     once the OTP-burn-from-TRNG path has been bench-validated.
#   - NO debug-log: production-fence-compatible, no semihosting leaks.
#   - NO e2e-test: ceremony runs the real provision path.
#
# After flashing, the factory operator:
#   1. Power-cycles the device.
#   2. Watches the OLED panel.
#   3. Reports the displayed status (success or numbered fail).
#
# Error code lookup table + operator manual:
#   docs/provisioning/factory-provisioning.md
#
# No factory image is currently buildable or authorized.
.PHONY: build-hw-factory-provisioning flash-hw-factory-provisioning \
	build-hw-factory-provisioning-rehearsal \
	flash-hw-factory-provisioning-rehearsal bump-rdp2-after-factory \
	factory-status-hw
build-hw-factory-provisioning:
	@$(error FAIL — factory provisioning is quarantined: its OTP receipt reprograms one write-once QW; no build or hardware action was run)

# Flash the production factory-provisioning firmware + configure
# TZ option bytes + reset + verify the OTP sentinel via probe-rs.
# Does NOT bump RDP2 — that's a separate deliberate step. Operator
# (or the factory's automated fixture) inspects the verifier
# output, then runs the bump target only when confident.
#
# Historical intended flow only. The target is refusal-only and contains no
# probe, option-byte, reset, or verifier command.
flash-hw-factory-provisioning:
	@$(error REFUSED — factory provisioning flash path is quarantined; no probe, option-byte, reset, or OTP command was run)

# Historical rehearsal flow. This target is also refusal-only: rehearsal
# consumes the same broken receipt QW and is not safe to run.
# Steps 4-6 SKIP their destructive calls; OTP sentinel records
# BIT_REHEARSAL (not BIT_PRODUCTION). Useful for OLED panel layout
# iteration without burning SE-side state on dev chips.
flash-hw-factory-provisioning-rehearsal:
	@$(error REFUSED — factory rehearsal flash path is quarantined; no probe, option-byte, reset, or OTP command was run)

# Historical irreversible target name retained for discoverability. The
# legacy receipt grants no eligibility, and make-time `$(error ...)` prevents
# this target from running even under `make -i`.
bump-rdp2-after-factory:
	@$(error REFUSED — factory OTP receipt is quarantined; RDP2 authority is disabled — and per work-todo #36 devices ship at RDP-0 and self-lock to RDP-2 on first field boot, so no fixture RDP2 bump exists; no irreversible command was run)

# Read-only inspection target: report the legacy OTP factory sentinel without
# flashing. Every decoded state is explicitly non-authoritative and exits
# nonzero.
factory-status-hw:
	@tools/factory-provisioning-verify.sh

# Quarantined legacy rehearsal target. Historically it skipped SE calls but
# still consumed the broken receipt QW. Every legacy receipt state is now
# non-authoritative; the make-time refusal runs before any build or hardware
# action.
#
# Do not use this for display iteration; the current target refuses before any
# build or hardware action.
#
# Historical panel text is retained in the source for review only.
build-hw-factory-provisioning-rehearsal:
	@$(error FAIL — factory rehearsal is quarantined: it also consumes/reprograms the receipt QW; no build or hardware action was run)

# LCD bring-up — Phase A check. Compiles the secure-world firmware
# with the `ui-lcd` feature enabled so the NV3007 SPI LCD driver
# (`secure/src/hw/lcd_nv3007.rs`) lands in the binary. The wizard UI
# still runs over the existing `ui-noop` Display backend (Phase C
# will wire the LCD into the Display trait); for Phase B bring-up
# you'd call `hw::lcd_nv3007::init()` + `fill_screen(0x07E0)` (green)
# from `main()` to verify SPI signalling + reset timing on the bench.
#
# Pin wiring (B-U585I-IOT02A → ZT165M017AT FPC):
#   PE12 → CS    (Arduino D10)
#   PE13 → SCL   (Arduino D13, AF5)
#   PE15 → SDA   (Arduino D11, AF5)
#   PE3  → D/CX  (jumper, free GPIO)
#   PE1  → RES   (jumper, free GPIO)
#   3V3  → VCC_2V8 + VLED+
#   GND  → GND   + VLED-
#
# Use this target to verify the firmware compiles cleanly; the actual
# LCD init/fill sanity check needs a Phase B short-circuit in main.rs
# (analogous to `decoy-flicker-hw`).
build-hw-lcd-bringup:
	@echo "==> Building secure firmware with ui-lcd driver (Phase A scaffold)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features ui-lcd,ui-noop,mock-se,debug-log,stm32u585,dev-testkey,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,$(BOARD_FEATURE)
	@echo "==> LCD bring-up build ready (Phase A — no init call site yet)."
	@echo "    Next: add a hw::lcd_nv3007::init() + fill_screen() call"
	@echo "    in main.rs behind a lcd-test feature gate, mirror"
	@echo "    decoy-flicker-hw's short-circuit pattern."

# Phase-B LCD bring-up (NV3007). Flashes a firmware that short-circuits
# main() into hw::lcd_nv3007::lcd_test_loop — the screen cycles
# green -> red -> blue (~1 s each) forever. First on-silicon confirmation
# that the wiring + the ported init sequence work. Wiring: docs/hardware/nv3007-wiring.md
# (SPI on CN13 D10/D11/D13, DC=PE7/D4, RES=PD15/D2, VCC+BLK=3V3, GND).
# Assumes TZ option bytes are already set (run any *-hw target once first).
lcd-test-hw:
	@echo "==> Building LCD UI bring-up test (NV3007 ui::Display 16x4 text)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features lcd-test,mock-se,debug-log,stm32u585,dev-testkey,usb,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Running — watch the LCD: green -> red -> blue cycling. Ctrl-C to detach."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

# Animated splash-screen preview (NV3007). Flashes a firmware that short-circuits
# main() into ui::splash_test::run — the three assets/splash-1{6,7,8}-*.html
# revisions (hyperspace -> horizon -> nebula), ported to no_std, cycle on the
# LCD ~12 s each forever so you can judge how each looks on the real panel.
# Same wiring as lcd-test-hw (docs/hardware/nv3007-wiring.md): SPI on CN13 D10/D11/D13,
# DC=PE7/D4, RES=3V3, VCC+BLK=3V3, GND. Assumes TZ option bytes are already set
# (run any *-hw target once first). The first build pulls `micromath` into
# Cargo.lock (cached locally, so it resolves offline).
splash-test-hw:
	@echo "==> Building animated splash preview (NV3007: hyperspace/horizon/nebula)..."
	@echo "    (with hardware FPU: -C target-feature=+fp-armv8d16sp; CPACR enabled at runtime)"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW) -C target-feature=+fp-armv8d16sp" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features splash-test,mock-se,debug-log,stm32u585,dev-testkey,usb,$(BOARD_FEATURE)
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Running — watch the LCD cycle the 3 splash revisions. Ctrl-C to detach."
	@probe-rs run --chip $(CHIP) $(SECURE_ELF)

clean: ## Remove build artifacts
	rm -rf target/secure target/nonsecure target/veneers.o


# Firmware anti-rollback test on real STM32U585 silicon — REVERSIBLE.
#
# Proves downgrade rejection (v1 install OK; v2 update OK; v2->v1 downgrade
# REJECTED; same-version reinstall REJECTED; forward v3 OK; forged signature
# REJECTED) by driving the REAL fw_update::verify_manifest chain (the exact
# function CMD_FW_BEGIN runs: structural -> CRC -> digest -> vendor-fpr ->
# FI-hardened SPHINCS+C10 signature -> rollback floor) with dev-key-signed
# manifests against literal test floors passed as a function argument.
#
# REVERSIBLE — burns NOTHING: no OTP rollback-floor bump, no flash erase, no
# boot-state write, no reboot, no USB. The chip stays fully reflashable.
# (Production OTP-burn FW-update validation is deferred to dedicated HW.)
#
# Greps for `[S][fwrb] === PASS ===`. Requires ST-LINK on B-U585I-IOT02A.
# Uses `probe-rs run` (NOT reset — reset leaves the core halted on this setup).
fw-rollback-hw: dev-pubkey-fixture
	@echo "==> Building FW anti-rollback test (secure + stm32u585 + fw-rollback-e2e + mock-se)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
	  -p sphincs-tz-secure --no-default-features --features mock-se,ui-noop,stm32u585,fw-rollback-e2e,$(BOARD_FEATURE)
	@echo "==> Building minimal NS image (stm32u585; not reached, flashed for layout)"
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
	  -p sphincs-tz-nonsecure --features stm32u585,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
	  --optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
	  SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running FW anti-rollback test on hardware (~10s; signs 4 manifests)..."
	@log=$$(mktemp -t fw-rollback-hw.XXXXXX.log); \
	rc_file=$$(mktemp -t fw-rollback-hw-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ timeout 120 probe-rs run --chip $(CHIP) $(SECURE_ELF) 2>&1; \
	  echo $$? >"$$rc_file"; } | tee "$$log"; \
	rc=$$(cat "$$rc_file"); \
	echo "===================================="; \
	if grep -q "\[S\]\[fwrb\] === PASS ===" "$$log"; then \
	  echo "==> fw-rollback-hw: PASS — downgrade rejected, forward allowed, forged sig rejected"; \
	  exit 0; \
	elif grep -q "\[S\]\[fwrb\] === FAIL ===" "$$log"; then \
	  echo "==> fw-rollback-hw: FAIL — an anti-rollback assertion mismatched (see log)"; \
	  exit 1; \
	else \
	  echo "==> fw-rollback-hw: FAIL (no PASS/FAIL marker; rc=$$rc)"; \
	  exit 1; \
	fi

# DEV vendor pubkey fixture (32 bytes = pk_seed[16] || pk_root[16]) derived
# from the built-in dev seed via `fwsign dev-pubkey` and checked against the
# single committed public value under `config/`. The secure crate has no
# sphincs-c10 build-dep (feature unification would leak host features into
# the firmware target), so `secure/build.rs` cannot compute this itself — it
# reads `FSBL_VENDOR_PUBKEY` instead. This target writes that checked dev
# pubkey to a stable path the test/dev builds can point at.
DEV_VENDOR_PUBKEY := $(CURDIR)/target/dev_vendor_pubkey.bin

dev-pubkey-fixture: $(DEV_VENDOR_PUBKEY)

$(DEV_VENDOR_PUBKEY):
	@mkdir -p $(@D)
	@cargo run --release -p fwsign --quiet -- dev-pubkey --out $@

# Fuzz the fw-manifest verify chain (the trust decision the USB FW-update
# path makes at CMD_FW_BEGIN). Standalone cargo-fuzz workspace under
# `fw-manifest/fuzz/`. Requires:
#   rustup toolchain install nightly
#   cargo install cargo-fuzz
# Then:
#   make fuzz-manifest                 # full verify-chain fuzz (slower)
#   make fuzz-manifest-crc             # structural+CRC only (faster)
# Or build-check only (CI-friendly, no nightly required if libfuzzer-sys
# can be compiled with stable; otherwise needs nightly):
#   make fuzz-manifest-build
fuzz-manifest:
	cd fw-manifest && cargo +nightly fuzz run fuzz_target_verify_manifest

fuzz-manifest-crc:
	cd fw-manifest && cargo +nightly fuzz run fuzz_target_structural_crc

fuzz-manifest-build:
	cd fw-manifest/fuzz && cargo +nightly build --release

# Over-USB FW-update transport e2e test on real STM32U585 silicon —
# REVERSIBLE (no OTP burn, no reset; chip stays reflashable).
#
# The host driver (tools/fwup-transport-test.py) sends a dev-signed
# v1 manifest + small QW-aligned image chunks + FW_COMMIT over real
# USB HID. The device runs the FULL state machine + verify_manifest +
# verify_images, then STOPS at COMMIT before OTP/boot-state/sys_reset
# under the `fwup-transport-e2e` feature.
#
# Catches transport-layer bugs (APDU chaining, HID framing, chunk
# header parsing, BEGIN -> CHUNK -> COMMIT ordering) that the device-
# side make-fw-rollback-hw test can't see (because that one bypasses
# the gateway and calls verify_manifest directly).
#
# Requires:
#   * ST-LINK + USB-C cable both connected (see USB-C enumeration
#     work — `5V_UCPD` jumper is OK; ST-LINK provides probe-rs access).
#   * udev rule installed for 1209:7051 (tools/99-pqsigner.rules) so
#     /dev/hidrawN is rw-accessible without root.
#   * `make dev-pubkey-fixture` populated (target/dev_vendor_pubkey.bin).
#
# Build features:
#   secure: mock-se,ui-noop,stm32u585,usb,fwup-transport-e2e
#     (fwup-transport-e2e implies e2e-test — auto-provision + skip PIN;
#      deliberately does NOT imply debug-log because semihosting BKPTs
#      under probe-rs run break USB timing — see the USB-C enumeration
#      lesson + the reference_probe_rs_reset_halts_core memory.)
#   NS: stm32u585,usb (the standard USB-HID host-facing build).
FWUP_FIXTURE_DIR := $(CURDIR)/target/fwup-test
FWUP_FIXTURE_FILES := $(FWUP_FIXTURE_DIR)/manifest.bin $(FWUP_FIXTURE_DIR)/secure.bin $(FWUP_FIXTURE_DIR)/nonsecure.bin

fwup-transport-fixture: $(FWUP_FIXTURE_FILES)

$(FWUP_FIXTURE_FILES) &:
	@mkdir -p $(FWUP_FIXTURE_DIR)
	@cargo run --release -p fwsign --quiet -- gen-test-fixture \
	  --version 1 --secure-len 240 --nonsecure-len 240 \
	  --out-dir $(FWUP_FIXTURE_DIR)

fwup-transport-hw: dev-pubkey-fixture fwup-transport-fixture
	@echo "==> Building secure (fwup-transport-e2e + usb + mock-se)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	  cargo build --locked --release --target $(TARGET) --target-dir target/secure \
	    -p sphincs-tz-secure --no-default-features \
	    --features mock-se,ui-noop,stm32u585,usb,fwup-transport-e2e,$(BOARD_FEATURE)
	@echo "==> Building NS (usb)"
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	  cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
	    -p sphincs-tz-nonsecure --features stm32u585,usb,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
	  --optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
	  SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> probe-rs run (background) — letting the device boot + USB enumerate..."
	@(timeout 120 probe-rs run --chip $(CHIP) $(SECURE_ELF) > /tmp/fwup-transport-run.log 2>&1 &)
	@for i in $$(seq 1 25); do \
	  if lsusb 2>/dev/null | grep -qi '1209:7051'; then echo "==> Enumerated (~$${i}s)"; break; fi; \
	  sleep 1; \
	done
	@if ! lsusb 2>/dev/null | grep -qi '1209:7051'; then \
	  echo "ERROR: 1209:7051 did not enumerate within 25s — is the USB-C cable plugged into the host?"; \
	  pkill -f "probe-rs run --chip $(CHIP)" 2>/dev/null; \
	  cat /tmp/fwup-transport-run.log | tail -20; \
	  exit 1; \
	fi
	@echo "==> Running transport e2e test (tools/fwup-transport-test.py)..."
	@rc=0; python3 tools/fwup-transport-test.py --fixture-dir $(FWUP_FIXTURE_DIR) || rc=$$?; \
	pkill -f "probe-rs run --chip $(CHIP)" 2>/dev/null || true; \
	echo "===================================="; \
	if [ $$rc -eq 0 ]; then \
	  echo "==> fwup-transport-hw: PASS — full BEGIN+CHUNK+COMMIT round-trip green"; \
	  exit 0; \
	else \
	  echo "==> fwup-transport-hw: FAIL (python rc=$$rc)"; \
	  cat /tmp/fwup-transport-run.log | tail -20; \
	  exit 1; \
	fi

# IWDG validation variant of fwup-transport-hw. Same flow but builds
# BOTH worlds with the `iwdg` feature ON, and inserts a 12 s idle-
# survival check before the transport test. This is the on-silicon
# proof that the USB-path watchdog:
#   * does NOT false-fire during normal idle (the device stays
#     enumerated through the 12 s window — NS heartbeat keeps the IWDG
#     fed), and
#   * does NOT false-fire during the multi-second BEGIN erase
#     (handler_is_busy() keeps it fed) — the full BEGIN+CHUNK+COMMIT,
#     fail-path, and repeated-invalid non-destruction sequence stays green.
# The e2e feature auto-confirms trusted UI, so this target covers the
# noninteractive busy bound. Host source/unit tests separately pin the
# idle-bounded TrustedUiWaitGuard wiring; a manual 120 s button-wait soak is
# still required when validating a new physical input backend.
# (Deliberately reuses fwup-transport-e2e on the secure side so the
#  device auto-provisions + enumerates; iwdg is added on TOP of it
#  purely for this validation — production ships iwdg WITHOUT e2e.)
fwup-transport-hw-iwdg: dev-pubkey-fixture fwup-transport-fixture
	@echo "==> Building secure (fwup-transport-e2e + usb + mock-se + IWDG)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	  cargo build --locked --release --target $(TARGET) --target-dir target/secure \
	    -p sphincs-tz-secure --no-default-features \
	    --features mock-se,ui-noop,stm32u585,usb,fwup-transport-e2e,iwdg,$(BOARD_FEATURE)
	@echo "==> Building NS (usb + IWDG)"
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	  cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
	    -p sphincs-tz-nonsecure --features stm32u585,usb,iwdg,$(BOARD_FEATURE)
	@echo "==> Flashing..."
	@probe-rs download --chip $(CHIP) $(NONSECURE_ELF)
	@probe-rs download --chip $(CHIP) $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@$(STM32_PROG) --connect port=SWD \
	  --optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
	  SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> probe-rs run (background) — letting the device boot + USB enumerate..."
	@(timeout 120 probe-rs run --chip $(CHIP) $(SECURE_ELF) > /tmp/fwup-transport-run.log 2>&1 &)
	@for i in $$(seq 1 25); do \
	  if lsusb 2>/dev/null | grep -qi '1209:7051'; then echo "==> Enumerated (~$${i}s)"; break; fi; \
	  sleep 1; \
	done
	@if ! lsusb 2>/dev/null | grep -qi '1209:7051'; then \
	  echo "ERROR: 1209:7051 did not enumerate within 25s"; \
	  pkill -f "probe-rs run --chip $(CHIP)" 2>/dev/null; \
	  cat /tmp/fwup-transport-run.log | tail -20; \
	  exit 1; \
	fi
	@echo "==> IWDG idle-survival: device must stay enumerated for 12 s (no watchdog false-fire while idle)..."
	@sleep 12
	@if ! lsusb 2>/dev/null | grep -qi '1209:7051'; then \
	  echo "==> fwup-transport-hw-iwdg: FAIL — device dropped off USB during idle (IWDG false-fired)"; \
	  pkill -f "probe-rs run --chip $(CHIP)" 2>/dev/null; \
	  exit 1; \
	fi
	@echo "==> Still enumerated after 12 s idle — no false-fire ✓"
	@echo "==> Running transport e2e test (tools/fwup-transport-test.py)..."
	@rc=0; python3 tools/fwup-transport-test.py --fixture-dir $(FWUP_FIXTURE_DIR) || rc=$$?; \
	pkill -f "probe-rs run --chip $(CHIP)" 2>/dev/null || true; \
	echo "===================================="; \
	if [ $$rc -eq 0 ]; then \
	  echo "==> fwup-transport-hw-iwdg: PASS — idle-survival + full round-trip green with IWDG ON"; \
	  exit 0; \
	else \
	  echo "==> fwup-transport-hw-iwdg: FAIL (python rc=$$rc)"; \
	  cat /tmp/fwup-transport-run.log | tail -20; \
	  exit 1; \
	fi

# ── Invariant gates: machine-enforce CLAUDE.md non-negotiable invariants ──
# #5 one PQ signer · #6 immutable bootstrap keys · #7 monotonic unresettable caps.
# Deps gated by cargo-deny [bans] plus the exact host-only ERC-8176 verifier
# boundary; source gated by .semgrep/pqsigner-invariants.yml.
.PHONY: classical-crypto-boundary optiga-oid-ceremony invariant-gates
classical-crypto-boundary: ## Pin host-only ERC-8176 ECDSA verification outside signing graphs
	python3 scripts/check_classical_crypto_boundary.py

optiga-oid-ceremony: ## Fail closed if a live doc carries a stale (destructive) OPTIGA S-2 ceremony instruction
	python3 scripts/check_optiga_oid_ceremony.py

SEMGREP ?= $(shell command -v semgrep 2>/dev/null || echo $(HOME)/.venvs/semgrep/bin/semgrep)
prod-symbol-audit: ## Binary-level audit of a firmware ELF for never-ship symbols/strings (ELF=path)
	@echo "==> prod-symbol-audit: self-test first (a detector nobody has watched"
	@echo "    fire is not a detector), then the artifact itself"
	scripts/prod_symbol_audit.sh --self-test
	@test -n "$(ELF)" || { echo "ERROR: pass ELF=<path>. Example:"; \
		echo "  make prod-symbol-audit ELF=target/pqsigner-release/secure.elf"; exit 2; }
	scripts/prod_symbol_audit.sh "$(ELF)"

prod-symbol-audit-selftest: ## Prove the binary audit can fail (two-sided control)
	scripts/prod_symbol_audit.sh --self-test

.PHONY: check-fi-ir
check-fi-ir: ## IR gate: fi_min's FI recompute guard must survive -O (issue #130)
	@echo "==> check-fi-ir: self-test first (a detector nobody has watched"
	@echo "    fire is not a detector), then the real crate"
	scripts/check_fi_ir.sh --self-test
	scripts/check_fi_ir.sh

invisible-unicode: ## Refuse zero-width / bidi-override codepoints in tracked text files
	@echo "==> invisible-unicode: zero-width + Trojan-Source bidi scan"
	@echo "    (self-test first — a gate nobody has watched fail is a gate"
	@echo "     nobody knows works)"
	python3 scripts/check_invisible_unicode.py --self-test
	python3 scripts/check_invisible_unicode.py

invariant-gates: ## Local invariant gates (cargo-deny + semgrep + transcription)
	@echo "==> [1/5] supply-chain (deps): cargo deny check advisories bans sources"
	@echo "    bans=invariant #5 (no classical signer); advisories=real CVEs"
	@echo "    (unmaintained is workspace-scoped); sources=registry/remote guard."
	cargo deny check advisories bans sources
	@echo "==> [2/5] exact host-only ERC-8176 verifier boundary:"
	$(MAKE) classical-crypto-boundary
	@echo "==> [3/5] OPTIGA S-2 doc<->code anchor inventory (IRREVERSIBLE LcsO):"
	$(MAKE) optiga-oid-ceremony
	@command -v "$(SEMGREP)" >/dev/null 2>&1 || { echo "ERROR: semgrep not found ($(SEMGREP)). Install: python3 -m venv ~/.venvs/semgrep && ~/.venvs/semgrep/bin/pip install semgrep"; exit 1; }
	@echo "==> [4/5] invariants #5/#6/#7 (source, ERROR-level fails the build):"
	"$(SEMGREP)" --config .semgrep/pqsigner-invariants.yml --severity ERROR --error --metrics off --quiet
	@echo "    guard: unsafe-ban exclude allowlist is exactly the 3 documented files:"
	@python3 .semgrep/check_unsafe_exclude_allowlist.py
	@echo "==> [5/5] advisory warnings (non-blocking):"
	-@"$(SEMGREP)" --config .semgrep/pqsigner-invariants.yml --severity WARNING --metrics off --quiet
	@echo "==> invariant-gates: PASS"

# cargo-vet: dependency audit-ATTESTATION gate (SOTA §8 — complements cargo-deny's
# bans/advisories/sources). Every dep must be either trusted-audited (we import
# the Mozilla / Google / Bytecode-Alliance / Embark audit sets, pinned in
# supply-chain/imports.lock) or explicitly exempted in supply-chain/config.toml,
# so a NEW transitive dep forces an audit-or-exempt decision in a reviewable diff.
# Audit down the exemption list over time: `cargo vet certify <crate> <ver>`.
.PHONY: vet
vet:
	@command -v cargo-vet >/dev/null 2>&1 || { echo "ERROR: cargo-vet not found. Install: cargo install --locked cargo-vet"; exit 1; }
	cargo vet --locked

# Supply-chain SBOM (CycloneDX) — a release SIDECAR capturing the full dep tree
# + licenses. NOT embedded in firmware (the secure-world binary is size-critical;
# pair an external SBOM with the FSBL-measured hash, per the SOTA report §8).
# Licenses are RECORDED here, not gated (a license gate is a compliance tripwire,
# not a security property — see deny.toml). Output `*.cdx.json` is gitignored.
.PHONY: sbom
sbom: ## Generate the software bill of materials
	@command -v cargo-cyclonedx >/dev/null 2>&1 || { echo "ERROR: cargo-cyclonedx not found. Install: cargo install cargo-cyclonedx"; exit 1; }
	cargo cyclonedx --format json --all
	@echo "==> sbom: wrote <crate>.cdx.json per workspace member (release sidecars)"

# FIRMWARE SBOM keyed to the FSBL-measured hash (SOTA §8). `make sbom` answers
# "what deps does this crate pull"; this answers "what deps went into THIS
# firmware image" — it stamps the secure-world dep SBOM's root component with
# the built ELF's measured SHA-256 (the value the FSBL measures + the device
# shows at boot, via fwmeasure) so the manifest is provably the one that
# produced the image. Build the firmware first so $(SECURE_ELF) exists (e.g.
# `make e2e`, or `make release` with the shipping feature set + optiga-hw-counter).
.PHONY: sbom-firmware
sbom-firmware:
	@command -v cargo-cyclonedx >/dev/null 2>&1 || { echo "ERROR: cargo-cyclonedx not found. Install: cargo install cargo-cyclonedx"; exit 1; }
	@test -f $(SECURE_ELF) || { echo "ERROR: $(SECURE_ELF) not built — run 'make e2e' / 'make release' first"; exit 1; }
	cargo build -p fwmeasure --release
	cargo cyclonedx --format json --manifest-path secure/Cargo.toml
	@mkdir -p $(RELEASE_ARTIFACT_DIR)
	python3 tools/sbom_firmware.py $(SECURE_ELF) secure/sphincs-tz-secure.cdx.json $(RELEASE_ARTIFACT_DIR)/secure-firmware.cdx.json

# ---------------------------------------------------------------------------
# Host Rust formal verification (SOTA 2026-06 §1 adopt-now; work-todo §34).
#   kani = bounded model-checking (panic / arithmetic-overflow / slice-OOB
#          freedom) of the untrusted-companion-bytes parse surface.
#   miri = UB detection on the host-reachable `unsafe` (the FI volatile
#          helpers + the decoders).
# SCOPE: host toolchain over HOST-REACHABLE logic. The CMSE veneers, raw
# MMIO, and NS-pointer deref are thumbv8m/hardware-cfg'd OUT of the host
# build, so these do NOT cover those — see work-todo §34.
# ---------------------------------------------------------------------------
.PHONY: kani miri ui-golden
kani-heavy: ## Kani harnesses excluded from `make kani` (peak RSS near the 16 GB runner ceiling)
	@command -v cargo-kani >/dev/null 2>&1 || { echo "ERROR: cargo-kani not found. Install: cargo install --locked kani-verifier && cargo kani setup"; exit 1; }
	@echo "==> Kani (HEAVY): harnesses whose peak RSS sits near the hosted-runner"
	@echo "    ceiling. Measured 2026-07-31, both VERIFY SUCCESSFULLY:"
	@echo "      cow_presign_precedence  11.5  GiB, 3m56s"
	@echo "      no_hidden_value         13.05 GiB, 7m55s"
	@echo "    A public-repo runner has 16 GB RAM and 14 GB disk. These are UNDER"
	@echo "    16 GB, so 'needs >=32 GB' would be an overclaim - the actual kill"
	@echo "    mechanism (RAM headroom vs disk) is instrumented in nightly.yml and"
	@echo "    not yet settled. They are excluded because an OOM kills the runner"
	@echo "    and suppresses the rest of the job's evidence, not because a bigger"
	@echo "    number has been proven necessary."
	cargo kani -p pqsigner-tx --features kani-heavy \
		--harness per_record_page_bound --harness no_hidden_value \
		--harness cow_presign_precedence
	@# anti-vacuity for the same cfg(kani-heavy)-gated surface (issue #662):
	@# canary + the heavy mutation tier (local-only, same RSS ceiling).
	$(MAKE) verify-kani-mutation-heavy

kani: ## Bounded model-checking on firmware decoders/counters
	@command -v cargo-kani >/dev/null 2>&1 || { echo "ERROR: cargo-kani not found. Install: cargo install --locked kani-verifier && cargo kani setup"; exit 1; }
	@echo "==> Kani: tx-core RLP parsers (decode_item used<=len, bytes_to_u256)"
	cargo kani -p pqsigner-tx-core
	@echo "==> Kani: domain recovery parser (deserialize_pin_state)"
	cargo kani -p pqsigner-domain --harness deserialize_pin_state_panic_free
	@echo "==> Kani: ERC-20 calldata decoder (panic-free + transfer no-misdecode)"
	@echo "         + Safe multiSend decoder (outer-frame canonical-acceptance soundness + inner record-walk exact-tiling/partition + field-fidelity soundness + page-budget classification: per-record page bound + no-hidden-value WYSIWYS + CoW-first precedence [records_pages_total panic-freedom compositional] + accept/reject controls)"
	@echo "         + CoW GPv2Order canonical decode (decode-soundness: accept<=>enum-in-range, verbatim field offsets + accept/reject controls)"
	@echo "         + typed-call ABI walker (no-read-past-end soundness + accept/reject controls)"
	@echo "         + Safe SafeTx decode (canonical typed-data: accept<=>operation-in-range, verbatim offsets; execTransaction: no-read-past-end + fixed-field soundness + accept/reject controls)"
	@echo "         + Safe management-op decoder (classify_safe_mgmt: accept => length-exact + selector-match + canonical address words + faithful threshold, reconstructed from original bytes; selector-gating reject + accept/reject controls)"
	cargo kani -p pqsigner-tx
	@echo "==> Kani: ERC-7730 IR header parser (offset-bounds safety)"
	@echo "         + TLV param parser (panic/OOB-free over symbolic pool+offset; per-tag width/value soundness: enum_ref/decimals/token/visibility; reject unknown-tag + out-of-range visibility byte)"
	@echo "         + visibility evaluator (should_render_with_mode total + spec-exact over all (visibility,compact))"
	cargo kani -p pqsigner-erc7730
	@echo "==> Kani: NS-pointer validation (window soundness: accept => in-NS, no-wrap, mailbox-disjoint, no usize->u32 trunc; unbounded/loop-free + accept/reject controls)"
	cargo kani -p sphincs-tz-shared
	@echo "==> Kani: unified sign-input header kernels (decode_flags total+bitfield-bounded; validate_data_len keeps the inner-tx slice in-bounds — used in place by nsc::cmd_sign_userop) + reconstruct_execute_calldata (panic/OOB-freedom + byte-exact execute(...) ABI-layout soundness — the calldata the on-chain wallet executes)"
	@echo "         + off-chain counter policy (offchain_gate): single-gate soundness (accept => new_count=max(off,last)+1, gap<=100, combined-cap respected) + verdict-exact accept/reject control + sequence/interleave (2-step gap+cap limit-slicing, single-op monotonicity, slot isolation) + both bricks unreachable (value-inflation sync-no-brick + distinct-slot graceful cap) — the extracted `check_offchain_gate` used in place by nsc::cmd_sign_offchain (work-todo §12e)"
	cargo kani -p pqsigner-aa
	@echo "==> Kani: FW-update manifest AUTHORITY gates (rollback-boundary biconditional [pins > not >=]; signed-preimage layout exhaustive) — gate DECISIONS, complementing the proptest/libfuzzer panic-freedom + fuzz coverage of the structural/CRC/crypto gates"
	cargo kani -p fw-manifest
	@echo "==> kani: PASS"

# Kani-side anti-vacuity gate — the mirror of the Lean `verify-proof-mutation`
# (contracts/verification). For each entry in scripts/kani_mutations.json it
# breaks a decoder/gate function the way a specific harness is supposed to catch
# and asserts that harness flips to VERIFICATION:- FAILED — a green-when-it-
# should-be-red = a vacuous / under-constrained Kani proof. Institutionalises
# the per-slice manual mutation checks (work-todo §35 P3). Slow (recompiles a
# crate + runs one harness per mutation, ~1-4 min each) → nightly, not per-PR.
#   make verify-kani-mutation                 # quick + default mutation tiers
#   make verify-kani-mutation MUTATIONS=quick # canary + the fast fw-manifest/aa ones
#   make verify-kani-mutation-heavy           # canary + the heavy tier (LOCAL ONLY)
.PHONY: verify-kani-mutation verify-kani-mutation-heavy
# C2: hand-transcribed MMIO base addresses vs ST's OWN CMSIS header. Peripheral
# bases are typed in by hand from RM0456 and a wrong nibble is SILENT — the TAMP
# driver sat at the wrong base for an unknown period precisely because nothing
# compared it to anything. External artifact that can disagree; there is no
# proof to be had here, just a diff. SKIPs (exit 0) when STM32CubeU5 is absent:
# a missing vendor SDK is a setup gap, not a code defect.
.PHONY: verify-mmio-addresses
verify-mmio-addresses: ## hand-typed MMIO bases vs ST's CMSIS stm32u585xx.h
	@python3 scripts/check_mmio_addresses.py --self-test
	@python3 scripts/check_mmio_addresses.py

verify-kani-mutation: ## anti-vacuity: break a decoder, expect a Kani harness to turn red
	@command -v cargo-kani >/dev/null 2>&1 || { echo "ERROR: cargo-kani not found. Install: cargo install --locked kani-verifier && cargo kani setup"; exit 1; }
	python3 scripts/check_kani_mutations.py

# Heavy-tier twin (issue #662): entries whose harnesses are cfg(feature =
# "kani-heavy")-gated — the default/nightly tier compiles those OUT and dies
# with a HarnessError, so they live in a non-cumulative heavy tier. Peak RSS
# (no_hidden_value 13.05 GiB / 7m55s, measured 2026-07-31) sits near the 16 GB
# hosted-runner ceiling: LOCAL ONLY, never wire into CI — an OOM kills the
# runner and suppresses the rest of the job's evidence (same reasoning as
# kani-heavy / verify-extracted-heavy). Also runs as the tail of `make kani-heavy`.
verify-kani-mutation-heavy: ## anti-vacuity for the cfg(kani-heavy)-gated harnesses (LOCAL ONLY, ~13 GiB peak RSS)
	@command -v cargo-kani >/dev/null 2>&1 || { echo "ERROR: cargo-kani not found. Install: cargo install --locked kani-verifier && cargo kani setup"; exit 1; }
	python3 scripts/check_kani_mutations.py --tier heavy

# F11 (2026-07-16) — SOURCE-GENERATED Kani harness census. The published counts
# (173 harnesses / 27 files; 11 harnesses in 6 files with no mutation coverage)
# were hand-maintained prose that drifted (gate_enforcement.json said 93/17).
# kani_mutations.json is only the load-bearing MUTATION manifest — it can't encode
# the full census. This regenerates exact file/function identities from active,
# standalone #[kani::proof] attributes in git-tracked sources, derives the
# mutation-enrolled/outside split, cross-checks the manifest for rot, and diffs
# vs scripts/kani_census.lock.json. Pure Python (NO
# cargo kani) → fast per-PR gate, unlike verify-kani-mutation (slow nightly).
.PHONY: verify-kani-census
verify-kani-census: ## source-generated Kani harness census vs kani_census.lock.json (fast, no Kani toolchain)
	@PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/test_kani_census.py
	@PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/kani_census.py --check

miri: ## Miri UB check on host crates
	@rustup component list --toolchain nightly --installed 2>/dev/null | grep -q '^miri' || rustup component add miri --toolchain nightly
	@echo "==> Miri: FI volatile helpers"
	cargo +nightly miri test -p pqsigner-fi
	@echo "==> Miri: tx-core decoders (RLP / EIP-1559 / keccak)"
	cargo +nightly miri test -p pqsigner-tx-core
	@echo "==> Miri: ERC-7730 display/render volatile canary + transcript-poison (the crate's only unsafe)"
	@# Filter `display` matches every module containing the crate's 10 unsafe blocks;
	@# the rest is safe code. Full-crate Miri is ~8.5 min — filtered leg is ~4 min.
	@# ignore-leaks: test fixtures use Box::leak for &'static [u8] IR pools (intentional).
	MIRIFLAGS="-Zmiri-ignore-leaks" cargo +nightly miri test -p pqsigner-erc7730 --lib -- display
	@echo "==> Miri: secure-world NS-pointer deref + validation (the genuine host-reachable unsafe)"
	@# permissive-provenance: the NS-ptr boundary is a legitimate int->ptr cast.
	MIRIFLAGS="-Zmiri-permissive-provenance" cargo +nightly miri test -p sphincs-tz-secure --no-default-features --features mock-se,debug-log,ui-semihosting -- ns_ptr ptr_validate
	@echo "==> Miri: extracted fold/exact/PRNG pure modules (strict provenance — no int->ptr boundary here)"
	cargo +nightly miri test -p sphincs-tz-secure --no-default-features --features mock-se,debug-log,ui-semihosting -- rng_strong_fold rng_exact consumption_mask_prng
	@echo "==> Miri (tree-borrows): shared NS-pointer deref primitives over a REAL allocation"
	@# the secure-crate pass above can't deref (its addr is a u32, never a host ptr); the
	@# extracted shared primitives run read_volatile/write_volatile/from_raw_parts on a real
	@# stack allocation, so tree-borrows actually vets the deref for aliasing/provenance UB.
	MIRIFLAGS="-Zmiri-tree-borrows" cargo +nightly miri test -p sphincs-tz-shared -- ns_ptr_validate
	@echo "==> Miri: secure-miri-tests (rng_strong production-arm fill + ui_lcd rasterizer mounts)"
	@# secure-miri-tests mounts the firmware's #[cfg(not(test))] rng_strong surface
	@# against mock platform/SE draws; the strict three-source path is what runs.
	@# It also mounts the ui-lcd-gated NV3007 rasterizer (ui/lcd.rs) against a
	@# recording lcd_nv3007 stub for the pixel-level differential/FLIP/bounds/
	@# CT-discipline tests. It is its own workspace so it cannot perturb the
	@# ERC-7730-bound root Cargo.toml/Cargo.lock. Serial: shared statics.
	cd secure-miri-tests && cargo +nightly miri test -- --test-threads=1
	@echo "==> miri: PASS"

# Mutation testing (SOTA 2026-06 §11 mutation-testing pilot): measures TEST
# STRENGTH — cargo-mutants perturbs each function (flip </<=, >/>=, -/+, drop a
# return value, …) and checks the test suite catches it. A "MISSED" mutant = a
# behaviour the tests don't pin. Scope to the security-relevant pure-logic
# crates (the adversarial parse + key-derivation surface). NOTE: many "missed"
# mutants live in functions that are KANI-PROVEN (rlp decode_item /
# bytes_to_u256 have #[kani::proof] harnesses cargo-mutants does NOT run) — so
# read MISSED ∩ not-Kani-covered as the real gap. 2026-06-26 baseline:
# pqsigner-tx-core 210/239 caught (88%); the real gap is U256::format_decimal
# boundary conditions (the amount-display / WYSIWYS path) — hardening tracked.
.PHONY: mutants
mutants: ## cargo-mutants on the firmware logic crates
	@command -v cargo-mutants >/dev/null 2>&1 || { echo "ERROR: cargo-mutants not found. Install: cargo install --locked cargo-mutants"; exit 1; }
	cargo mutants $(or $(MUTANTS_ARGS),--package pqsigner-tx-core --package pqsigner-domain) -j4

# UI golden-screenshot gate (Trezor-port, SOTA 2026-06 §6). Builds the e2e
# suite with the `ui-capture` feature so every secure-world Display::flush()
# emits a `[UI-FP] <idx> <sha256>` line (secure/src/ui/capture.rs), runs it
# under QEMU, and diffs the captured per-frame fingerprints against the
# committed tests/ui_fixtures.json. A render regression (layout / text /
# byte drift) flips a hash → tools/ui_fixture.py exits 1. Same trust
# boundary as the display: the fingerprint is produced INSIDE the secure
# world, so it hashes exactly what the trusted UI rendered.
#
#   make ui-golden                          # check against committed fixtures
#   make ui-golden GOLDEN_MODE=--regenerate # re-baseline after an intentional UI change
#
# LOCAL / MANUAL gate (not in CI). ROOT CAUSE (measured 2026-06-18): the
# slowness is NOT the frame emit — it's that this captures frames WHILE running
# the full 24-scenario sign-e2e, and each scenario's SPHINCS+C10 sign over
# QEMU's SOFTWARE SHA-256 is seconds-to-minutes. A 150s bounded run reached
# only Scenario 1 (≈ a full run would be ~60 min). The CI-viable redesign is a
# dedicated RENDER-ONLY harness: render a curated set of representative screens
# (measured-boot fingerprint + a handful of confirm dialogs) directly via the
# display renderers, with NO signing — fast because it skips the C10 signs.
# That harness (~a new `ui-golden`-mode entry that constructs representative
# display inputs + flushes) is the unfinished piece; until then this target
# runs the slow full-e2e capture and is local/manual only. Regenerate fixtures
# only from a clean, intentional render.
GOLDEN_MODE ?= --check
ui-golden:
	@echo "==> Building e2e suite with ui-capture (frame-fingerprint emitter)"
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,ui-capture,e2e-test
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test
	@echo "==> Running e2e under QEMU, capturing [UI-FP] frame fingerprints"
	@log=$$(mktemp); \
	qemu-system-arm \
		-M mps2-an505 -monitor null -serial null -nographic \
		-chardev stdio,id=hostio \
		-semihosting-config enable=on,target=native,chardev=hostio \
		-kernel $(SECURE_ELF) \
		-device loader,file=$(NONSECURE_ELF) </dev/null 2>&1 | tee $$log >/dev/null; \
	echo "==> ui-golden ($(GOLDEN_MODE)) vs tests/ui_fixtures.json"; \
	rc=0; python3 tools/ui_fixture.py $(GOLDEN_MODE) tests/ui_fixtures.json < $$log || rc=$$?; \
	rm -f $$log; \
	if [ $$rc -eq 0 ]; then echo "==> ui-golden: PASS"; else echo "==> ui-golden: FAIL (rc=$$rc)"; fi; \
	exit $$rc

# Render-only golden gate (#21) — a FAST ui-golden. Renders the curated screen
# corpus through the production renderers (`ui::golden`) + captures [UI-FP],
# with NO C10 keygen/sign — the e2e-based `ui-golden` above is slow (signs over
# QEMU software SHA-256 dominate: it reached one scenario in ~150 s). The secure
# image halts right after rendering, so the NS image is only a loader payload
# (never executed). Catches renderer regressions (layout / text / byte drift)
# in seconds.
#   make ui-golden-render               # check vs tests/ui_golden_render_fixtures.json
#   make ui-golden-render-bless         # re-baseline after an intentional UI change
.PHONY: ui-golden-render ui-golden-render-bless
ui-golden-render: ## Render UI golden frames + compare to baseline
	@echo "==> Building secure (ui-golden-render harness) + NS loader payload"
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,ui-golden-render
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test
	@echo "==> Rendering the curated screen corpus under QEMU, capturing [UI-FP]"
	@log=$$(mktemp); \
	qemu-system-arm \
		-M mps2-an505 -monitor null -serial null -nographic \
		-chardev stdio,id=hostio \
		-semihosting-config enable=on,target=native,chardev=hostio \
		-kernel $(SECURE_ELF) \
		-device loader,file=$(NONSECURE_ELF) </dev/null 2>&1 | tee $$log >/dev/null; \
	echo "==> ui-golden-render ($(GOLDEN_MODE)) vs tests/ui_golden_render_fixtures.json"; \
	rc=0; python3 tools/ui_fixture.py $(GOLDEN_MODE) tests/ui_golden_render_fixtures.json < $$log || rc=$$?; \
	rm -f $$log; \
	if [ $$rc -eq 0 ]; then echo "==> ui-golden-render: PASS"; else echo "==> ui-golden-render: FAIL (rc=$$rc)"; fi; \
	exit $$rc

ui-golden-render-bless:
	@$(MAKE) ui-golden-render GOLDEN_MODE=--regenerate

# Symbolic-model (ProVerif, Dolev-Yao) proof of the dual-SE seed-unlock protocol:
# seed secrecy under partial compromise (Claims 1/2) + the PIN-gate authentication
# + the anti-vacuity positive control. See contracts/verification/proverif/README.md.
.PHONY: proverif
proverif: ## ProVerif symbolic protocol-model verification
	@command -v proverif >/dev/null 2>&1 || { echo "ERROR: proverif not found. Install: opam install --assume-depexts proverif (CLI build needs no GTK)"; exit 1; }
	@echo "==> ProVerif: dual-SE seed-unlock (secrecy + PIN-gate auth)"
	proverif contracts/verification/proverif/dual_se_unlock.pv
	@echo "==> ProVerif: SE050 SCP03 handshake (session-key secrecy + mutual auth + static-leak residual)"
	proverif contracts/verification/proverif/scp03_handshake.pv
	@echo "==> ProVerif: OPTIGA Shielded Connection handshake (half_O secrecy + mutual auth + PBS-leak residual)"
	proverif contracts/verification/proverif/optiga_shield_handshake.pv
	proverif contracts/verification/proverif/optiga_shield_handshake_vendor.pv
	@echo "==> ProVerif: SCP03 within-session no-forgery (companion to the Tamarin no-replay)"
	proverif contracts/verification/proverif/scp03_replay.pv
	@echo "==> ProVerif: firmware-update authenticity (vendor-signed manifest, domain-separated)"
	proverif contracts/verification/proverif/fw_update_authenticity.pv

# Idealized symmetric three-counter Tamarin research model. It is a contrast
# model, not a proof of the deployed directional page124/E120 boot check or of
# an SE050 boot counter read. See contracts/verification/tamarin/README.md.
.PHONY: tamarin
tamarin: ## Tamarin symbolic protocol-model verification
	@command -v tamarin-prover >/dev/null 2>&1 || { echo "ERROR: tamarin-prover not found. Install the prebuilt linux64 binary + the maude backend (both need no sudo/GHC; see contracts/verification/tamarin/README.md)"; exit 1; }
	@echo "==> Tamarin: idealized symmetric three-counter PIN model"
	tamarin-prover --prove contracts/verification/tamarin/pin_lockstep.spthy
	@echo "==> Tamarin: SCP03 within-session no-replay (counter)"
	tamarin-prover --prove contracts/verification/tamarin/scp03_replay.spthy
	@echo "==> Tamarin: dual-SE XOR seed-split secrecy (one-time-pad, info-theoretic)"
	tamarin-prover --prove contracts/verification/tamarin/seed_split_xor.spthy

# CryptoVerif: the COMPUTATIONAL (game-based) companion to the symbolic models.
# Proves dual-SE XOR seed-split secrecy with advantage 0 (a one-time pad, not a
# computational assumption) — an UNCONDITIONAL bound, hence quantum-sound: a
# CRQC cannot recover the seed from a single half. Runs via `cryptoverif` on
# PATH or `nix-shell -p cryptoverif`.
.PHONY: cryptoverif
cryptoverif: ## CryptoVerif computational protocol proof
	@echo "==> CryptoVerif: dual-SE XOR seed-split secrecy (computational; OTP advantage 0 ⇒ quantum-sound)"
	@# F7 (2026-07-16): the default library lives at `libexec/default` on a nix
	@# install but `bin/default` on an opam switch — probe BOTH documented
	@# layouts (plus `lib/cryptoverif`) instead of hard-coding one, and PROPAGATE
	@# cryptoverif's exit code (the old `| grep` masked it) so verify-protocol-
	@# models sees a failed run as a failure, not a silent skip.
	@if command -v cryptoverif >/dev/null 2>&1; then \
	  p=$$(dirname $$(dirname $$(readlink -f $$(command -v cryptoverif)))); \
	  lib=""; for cand in $$p/libexec/default $$p/bin/default $$p/lib/cryptoverif/default; do \
	    if [ -f "$$cand.cvl" ]; then lib="$$cand"; break; fi; done; \
	  if [ -z "$$lib" ]; then echo "ERROR: no default.cvl under $$p (tried libexec/, bin/, lib/cryptoverif/)"; exit 1; fi; \
	  out=$$(cryptoverif -lib "$$lib" contracts/verification/cryptoverif/seed_split_secrecy.cv 2>&1); rc=$$?; \
	  echo "$$out" | grep -E 'RESULT|proved'; \
	  if [ $$rc -ne 0 ]; then echo "ERROR: cryptoverif exited $$rc"; exit $$rc; fi; \
	elif command -v nix-shell >/dev/null 2>&1; then \
	  nix-shell -p cryptoverif --run 'p=$$(dirname $$(dirname $$(readlink -f $$(command -v cryptoverif)))); for cand in $$p/libexec/default $$p/bin/default; do [ -f "$$cand.cvl" ] && lib="$$cand" && break; done; cryptoverif -lib "$$lib" contracts/verification/cryptoverif/seed_split_secrecy.cv' | grep -E 'RESULT|proved'; \
	else echo "ERROR: cryptoverif not found (try: nix-shell -p cryptoverif, or opam install cryptoverif)"; exit 1; fi

# Protocol-model regression GATE — the third anti-vacuity sibling of
# verify-proof-mutation (Lean) + verify-kani-mutation (firmware harnesses).
# `make proverif`/`tamarin`/`cryptoverif` RUN the tools but exit 0 whether a
# query is true or false, and the models carry DESIGNED `is false` residuals —
# so a bare run is not a gate. This asserts each model's verdict pattern vs a
# committed per-file baseline (scripts/check_protocol_models.py) and exits
# non-zero on any drift (a true->false flip, a falsified lemma, a lost proof).
# Select families with PROTOCOL_MODELS (default all); CI runs proverif,tamarin
# (the 8 symbolic models) — cryptoverif is local-only (nix-`-lib` install).
#   make verify-protocol-models                                 # all 3 families (needs nix for cryptoverif)
#   make verify-protocol-models PROTOCOL_MODELS=proverif,tamarin # the CI subset
PROTOCOL_MODELS ?= proverif,tamarin,cryptoverif
.PHONY: verify-protocol-models
verify-protocol-models: ## anti-vacuity: assert the protocol models' verdicts vs baseline
	PROTOCOL_MODELS="$(PROTOCOL_MODELS)" python3 scripts/check_protocol_models.py

# Gate-enforcement lint — closes catalog class G1 (fv-adversarial-review-playbook
# Part A2). Asserts every soundness gate in scripts/gate_enforcement.json actually
# FIRES on the diff it polices (invoked by a job, path-triggered on its surface,
# blocking) — a gate that is green-when-run but never RUNS is false assurance (the
# 2026-07-01 F1 finding: verify-ledger-consistency never fired on ledger-only edits).
# Fast (grep + YAML parse, no build) → per-PR. `--self-test` = negative control.
# F53: the self-test runs FIRST, like every sibling gate — an unwired negative
# control leaves a silent regression of this meta-gate detected by nothing.
.PHONY: verify-gate-enforcement
verify-gate-enforcement: ## G1: assert every soundness gate is actually CI-enforced on its surface
	@python3 scripts/check_gate_enforcement.py --self-test
	python3 scripts/check_gate_enforcement.py

# ---------------------------------------------------------------------------
# Discoverability wrappers for the off-Makefile verification tools (SOTA
# 2026-06 §1/§4; docs/tooling-and-systems.md §B). These four were installed
# but had NO root make target, so an agent inventorying `make` targets missed
# them. Each delegates to the canonical runner / vendored harness — the runner
# scripts + tools/sca/DONJON-RUST-TOOLING.md remain the source of truth.
#   halmos  = symbolic EVM execution of the deployed wallet bytecode (A3.* bridge)
#   kontrol = KEVM proofs of the bootstrap-unremovable / owner-table invariants
#   checkct = binsec relational CT proof of the secret primitives on thumbv8m
#   muscat  = Donjon SCA (Welch-T TVLA / CPA) over the rainbow shuffle traces
# ---------------------------------------------------------------------------
.PHONY: halmos kontrol checkct muscat

halmos: ## Halmos symbolic exec (smart-wallet harnesses)
	$(MAKE) -C contracts/verification verify-halmos

kontrol: ## Kontrol/KEVM proofs on the deployed bytecode
	$(MAKE) -C contracts/verification verify-kontrol

# binsec is OCaml + a local opam switch; ~/checkct_env.sh sets the nix PATH,
# OPAMROOT, the `checkct` switch + gmp store paths (DONJON-RUST-TOOLING §1).
# cargo-checkct lives in ~/repos/cargo-checkct (not on PATH). Five drivers
# prove SECURE (kdf/fors/th/saes/ct_eq — DONJON-RUST-TOOLING §1); the `driver`
# (fisher_yates shuffle) is INSECURE BY DESIGN (the address-channel +
# statistical-misalignment control, not bitwise CT) so the suite exits
# non-zero — the five green drivers are the signal, not the exit.
checkct: ## Constant-time check (cargo-checkct)
	@test -f $(HOME)/checkct_env.sh || { echo "ERROR: ~/checkct_env.sh not found — see tools/sca/DONJON-RUST-TOOLING.md §1 (install binsec + the opam switch)"; exit 1; }
	@test -x $(HOME)/repos/cargo-checkct/target/release/cargo-checkct || { echo "ERROR: cargo-checkct not built — git clone https://github.com/Ledger-Donjon/cargo-checkct ~/repos/cargo-checkct && cargo build --release"; exit 1; }
	@echo "==> cargo-checkct: relational CT proof of kdf/fors/th/saes/ct_eq (+ by-design-INSECURE fisher_yates shuffle control) on thumbv8m"
	@bash -c 'source $(HOME)/checkct_env.sh && export PATH="$(HOME)/repos/cargo-checkct/target/release:$(HOME)/.cargo/bin:$$PATH" && cargo-checkct run --dir tools/sca --timeout 300'

# Muscat (Donjon SCA, successor to lascar): Welch-T TVLA + CPA. With TRACES_DIR
# set, runs over those real .npy traces (see DONJON-RUST-TOOLING §2 for the
# f9_traces.npz -> .npy pipeline). With no TRACES_DIR, generates the synthetic
# self-test (ground-truth leaky S-box: TVLA fires, CPA recovers KEY[0]=0x2b) —
# a standalone CI smoke that needs no rainbow run. Override the repo with
# MUSCAT_DIR=...; first run builds the example (~10s).
MUSCAT_DIR ?= $(HOME)/repos/muscat
muscat: ## MUSCAT side-channel (SCA) analysis
	@test -f $(MUSCAT_DIR)/examples/pqsigner_tvla_cpa.rs || { echo "ERROR: muscat harness missing at $(MUSCAT_DIR) — git clone https://github.com/Ledger-Donjon/muscat ~/repos/muscat && cp tools/sca/muscat/pqsigner_tvla_cpa.rs $(MUSCAT_DIR)/examples/ (+ the [[example]] stanza)"; exit 1; }
ifeq ($(TRACES_DIR),)
	@echo "==> Muscat: no TRACES_DIR — synthetic self-test (ground-truth leaky S-box)"
	@rm -rf /tmp/pq1-muscat-selftest && mkdir -p /tmp/pq1-muscat-selftest/muscat_demo
	cd /tmp/pq1-muscat-selftest && python3 $(CURDIR)/tools/sca/muscat/gen_pqsigner_shape.py
	cd $(MUSCAT_DIR) && TRACES_DIR=/tmp/pq1-muscat-selftest/muscat_demo cargo run --release --example pqsigner_tvla_cpa
else
	@echo "==> Muscat: Welch-T TVLA + CPA over $(TRACES_DIR)"
	cd $(MUSCAT_DIR) && TRACES_DIR=$(TRACES_DIR) cargo run --release --example pqsigner_tvla_cpa
endif
