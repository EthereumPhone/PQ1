TARGET = thumbv8m.main-none-eabi
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
#      produce different ELFs.
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

# Default: mock secure element + semihosting UI mock (no real hardware needed)
# debug-log enables semihosting output from the secure world.
# Remove it for production builds to eliminate all debug strings.
FEATURES ?= mock-se,debug-log,ui-semihosting

# Extract features relevant to the nonsecure crate (it doesn't know about
# mock-se, debug-log, ui-semihosting, etc. — only e2e-test and stm32u585).
NS_FEATURES_LIST := $(strip $(foreach f,stm32u585 e2e-test usb,$(if $(findstring $(f),$(FEATURES)),$(f))))
comma := ,
empty :=
space := $(empty) $(empty)
NS_FEATURES_ARG = $(if $(NS_FEATURES_LIST),--features $(subst $(space),$(comma),$(NS_FEATURES_LIST)),)

.PHONY: all clean secure nonsecure run play play-hw-display run-tropic01 run-hw setup-serial e2e e2e-hw e2e-hw-display e2e-hw-dual-se build-hw flash-hw test test-unit test-solidity test-key-speed test-update-hw qr-screen measure factory-reset optiga-reset-oids flash-hw-optiga-reset verify-pins

# Supply-chain audit. Hard-fails if any dependency is not cryptographically
# pinned (Cargo.lock checksums, git rev= pins, foundry.lock matching
# checked-out submodules, circuits/package-lock.json SRI integrity,
# dated-nightly rust-toolchain). See tools/verify_pins.sh for the exact
# rules. Every release-path target below depends on this.
verify-pins:
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

# Run with mock SE (no real TROPIC01 chip needed).
# We attach semihosting to a dedicated stdio chardev so SYS_READC can read
# from the host terminal — this is what the secure UI mock uses to receive
# "button" input ('l'/'h' = short, 'L'/'H' = long).
run: all
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
play: all
	@python3 tools/wallet_run.py

# Interactive two-button wallet on real STM32U585 with SSD1306 OLED display.
# Same arrow-key mapping as `play` (QEMU version), but runs on real hardware.
# Display renders on the physical OLED; button input comes from your laptop
# keyboard via probe-rs semihosting READC.
# Requires: ST-LINK connected, SSD1306 OLED wired to PB8/PB9/3V3/GND.
play-hw-display:
	@echo "==> Building secure + nonsecure for interactive OLED play"
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-oled,stm32u585
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Starting interactive wallet (Ctrl-C to quit)..."
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
# brownout hardening roadmap; see docs/brownout-hardening.md).
stm32-harden-opts:
	@echo "==> Configuring brown-out supervision + SRAM2 auto-erase"
	@echo "    BOR_LEV=3 (~2.7V), SRAM2_RST=0 (auto-erase on reset)"
	@echo "    This triggers an Option Byte Load — the chip will reset."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes BOR_LEV=3 SRAM2_RST=0
	@echo "==> Option bytes written. Reset triggered. Chip state: hardened."

# Configure /dev/ttyACM0 for TROPIC01 communication
setup-serial:
	@echo "Configuring /dev/ttyACM0 for TROPIC01..."
	stty -F /dev/ttyACM0 115200 raw -echo cs8 -cstopb -parenb
	@echo "Serial port ready."

# Build + run with real TROPIC01 chip via semihosting SPI bridge.
# UI is still mocked over semihosting (the OLED + buttons live on real HW).
# Requires: TROPIC01 TS1302 devkit connected at /dev/ttyACM0
run-tropic01: setup-serial
	$(MAKE) FEATURES=tropic01-se,debug-log,ui-semihosting all
	qemu-system-arm \
		-M mps2-an505 \
		-monitor null \
		-serial null \
		-chardev stdio,id=hostio \
		-semihosting-config enable=on,target=native,chardev=hostio \
		-kernel $(SECURE_ELF) \
		-device loader,file=$(NONSECURE_ELF)

# Real STM32U585 hardware build (full): real chip + real OLED + real buttons.
# This target only BUILDS — flashing is done with probe-rs / openocd / etc.
# It will not link until the ui-oled backend is fully wired up.
run-hw:
	$(MAKE) FEATURES=tropic01-se,ui-oled,pka-accel,stm32u585 all

# Real STM32U585 hardware build (semihosting): mock SE + semihosting UI.
# Uses probe-rs semihosting for I/O — same interactive model as QEMU
# but running on the real Cortex-M33.
build-hw:
	$(MAKE) FEATURES=mock-se,debug-log,ui-semihosting,stm32u585 all

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
flash-hw: build-hw
	probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching (Ctrl-C to quit)..."
	probe-rs reset --chip STM32U585AIIx
	probe-rs attach --chip STM32U585AIIx $(SECURE_ELF)

# Non-interactive automated end-to-end test for the sign dispatch logic.
# Builds both worlds with the `e2e-test` cargo feature, runs them in QEMU
# with stdin closed (no semihosting input needed), captures stdout, and
# asserts that the secure-world dispatcher routed each scenario to the
# right TxKind variant + that every scenario returned NscStatus::Ok.
#
# Scenarios:
#   1. value_transfer   → ValueTransfer
#   2. erc20_known      → Erc20Known     (USDC mainnet, bundle from NS DB)
#   3. blind_sign       → ContractCall   (Uniswap router selector only)
#   4. zk_clear_sign    → ZkClearSign    (Aave V3 supply, VK bundle from NS DB)
#   5. cowswap_pre_sign → ZkClearSign    (GPv2Settlement.setPreSignature,
#                                         in-tree Circom circuit, VK bundle
#                                         from NS DB)
#   6. cowswap_eip712_order → ZkClearSignMsg
#                                       (CowSwap GPv2Order EIP-712 typed-data
#                                        message signing — M4. Native keccak
#                                        digest in the secure world, bound
#                                        to a Poseidon-hashed canonical
#                                        encoding via Groth16. No on-chain
#                                        tx envelope.)
#
# Pass → exits 0. Any missing assertion or non-zero status → exits 1.
e2e:
	@echo "==> Building secure + nonsecure with e2e-test feature (QEMU mailbox transport)"
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test
	@echo "==> Running e2e suite under QEMU"
	@out=$$(qemu-system-arm \
		-M mps2-an505 \
		-monitor null \
		-serial null \
                -nographic \
		-chardev null,id=hostio \
		-semihosting-config enable=on,target=native,chardev=hostio \
		-kernel $(SECURE_ELF) \
		-device loader,file=$(NONSECURE_ELF) 2>&1); \
	echo "$$out"; \
	echo "===================================="; \
	fail=0; \
	for line in \
		"\\[S\\]\\[e2e\\] cmd_clear_sign dispatch = ZkClearSign" \
		"\\[S\\]\\[e2e\\] cmd_clear_sign_msg dispatch = ZkClearSignMsg" \
		"\\[S\\]\\[e2e\\] cmd_sign_userop dispatch = ValueTransfer" \
		"\\[S\\]\\[e2e\\] cmd_sign_userop dispatch = Erc20Known" \
		"\\[E2E\\] zk_clear_sign = PASS" \
		"\\[E2E\\] cowswap_pre_sign = PASS" \
		"\\[E2E\\] cowswap_eip712_order = PASS" \
		"\\[E2E\\] userop_value_transfer = PASS" \
		"\\[E2E\\] userop_erc20 = PASS" \
		"\\[E2E\\] neg_chain_id_mismatch = PASS" \
		"\\[E2E\\] neg_tx_len_zero = PASS" \
		"\\[E2E\\] neg_tx_len_overflow = PASS" \
		"\\[E2E\\] neg_truncated_payload = PASS" \
		"\\[E2E\\] neg_contract_creation = PASS" \
		"\\[E2E\\] neg_bad_envelope = PASS" \
		"\\[E2E\\] ALL TESTS PASSED"; do \
		if echo "$$out" | grep -q "$$line"; then \
			echo "  PASS  $$line"; \
		else \
			echo "  MISS  $$line"; \
			fail=1; \
		fi; \
	done; \
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
# Requires: ST-LINK connected, STM32_Programmer_CLI on PATH.
# Pass: exits 0 with "[NS][bench] === PASS ===" on stdout.
# Fail: exits 1 if any sign returns non-Ok or the PASS line is missing.
test-key-speed:
	@echo "==> Building secure (e2e-test auto-provision) + NS (bench-key-speed) + SHA-256 HW accel"
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test,stm32u585,hw-sha256
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features bench-key-speed,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running key-speed bench on hardware (160 MHz)..."
	@echo "    (streaming semihosting output; each [NS][bench] line = one measurement)"
	@log=$$(mktemp -t test-key-speed.XXXXXX.log); \
	trap 'rm -f "$$log"' EXIT; \
	rc_file=$$(mktemp -t test-key-speed-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1; echo $$? >"$$rc_file"; } | tee "$$log"; \
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
#   * Never calls CMD_FW_COMMIT → no OTP rollback bit is burned.
#     (1024 bits of OTP budget per device.  Each COMMIT burns at least
#      one bit, permanently.  This test burns zero.)
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
# Requires: ST-LINK connected, STM32_Programmer_CLI on PATH.
# Pass: exits 0 with "[NS][fwup-test] === PASS ===" on stdout.
# Fail: exits 1 if any test case fails or the PASS marker is missing.
test-update-hw:
	@echo "==> Building secure (e2e-test auto-unlock) + NS (fwup-hw-test) + SHA-256 HW accel"
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test,stm32u585,hw-sha256
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features fwup-hw-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running firmware-update logic test (safe mode)..."
	@echo "    (no COMMIT, no slot erase — nothing irreversible will happen)"
	@log=$$(mktemp -t test-update-hw.XXXXXX.log); \
	rc_file=$$(mktemp -t test-update-hw-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1; echo $$? >"$$rc_file"; } | tee "$$log"; \
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
# Requires: ST-LINK connected, STM32_Programmer_CLI on PATH.
e2e-hw:
	@echo "==> Building e2e + stm32u585"
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test,stm32u585
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running e2e on hardware (Ctrl-C to abort)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Same e2e suite on real STM32U585, but with OLED display output.
# The SSD1306 128x64 OLED is driven via I2C1 (PB8=SCL, PB9=SDA).
# Uses ui-oled instead of ui-semihosting so the UI renders on the
# physical display rather than the probe-rs console.
# Requires: ST-LINK connected, SSD1306 OLED wired to PB8/PB9/3V3/GND.
e2e-hw-display:
	@echo "==> Building e2e + stm32u585 + OLED display"
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-oled,e2e-test,stm32u585
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running e2e on hardware with OLED display (Ctrl-C to abort)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Full sign e2e on real STM32U585 with *both* real SEs (OPTIGA
# Trust M + SE050, XOR-split entropy) driving the SSD1306 OLED.
#
# Exercises the post-cutover stateless-slot flow (Type 1 + Type 2,
# cross-chain slot rotation) end-to-end through real silicon:
#   * dual-se   — OPTIGA + SE050 XOR-split provision + unlock
#   * ui-oled   — status on the physical SSD1306 (PB8=SCL, PB9=SDA)
#   * e2e-test  — auto-provisions fixed mnemonic + PIN, pre-unlocks
#                 the gateway (probe-rs cannot serve SYS_READC)
#   * otp-hardcoded-master-key — avoids burning real OTP each run
#                                (same choice as dual-se-admin-wipe-e2e)
#
# Requires: ST-LINK, STM32_Programmer_CLI, OPTIGA Trust M + SE050 on
# the I2C bus, SSD1306 OLED wired to PB8/PB9/3V3/GND.
#
# Watch semihosting for "[NS][e2e] === All scenarios passed! ===".
# OLED will show "e2e Sign N/4" + "T1+T2"/"T2 only" on each sign.
e2e-hw-dual-se:
	@echo "==> Building e2e + stm32u585 + dual-SE (OPTIGA + SE050) + OLED"
	@echo "    WARNING: re-provisions wallet state on BOTH chips with the"
	@echo "    fixed e2e test mnemonic (abandon × 23 || art, PIN 00000000)."
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features dual-se,ui-oled,debug-log,e2e-test,e2e-skip-admin-wipe,stm32u585,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running dual-SE e2e on hardware..."
	@echo "    (streaming semihosting; looks for 'All scenarios passed!'"
	@echo "     then exits — hit Ctrl-C if it hangs past 2 min)"
	@log=$$(mktemp -t e2e-hw-dual-se.XXXXXX.log); \
	rc_file=$$(mktemp -t e2e-hw-dual-se-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ timeout 300 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1; \
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
		-p sphincs-tz-secure --no-default-features --features mock-se,ui-noop,stm32u585,usb,e2e-test
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> USB test build ready (auto-provisioned, no semihosting)."

# Flash auto-provisioned USB build.
flash-hw-usb-test: build-hw-usb-test
	probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching (Ctrl-C to quit)..."
	probe-rs reset --chip STM32U585AIIx
	probe-rs attach --chip STM32U585AIIx $(SECURE_ELF)

# SE050 + USB build with auto-provisioning for testing.
# Secure world: se050 (real SE via I2C1), ui-noop, USB hardware init, e2e-test auto-provision.
# NS world: usb feature for USB HID main loop.
build-hw-se050-usb-test:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,ui-noop,stm32u585,usb,e2e-test
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> SE050 + USB test build ready."

flash-hw-se050-usb-test: build-hw-se050-usb-test
	probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching (Ctrl-C to quit)..."
	probe-rs reset --chip STM32U585AIIx
	probe-rs attach --chip STM32U585AIIx $(SECURE_ELF)

# SE050 + USB test with semihosting debug output (requires probe-rs attach).
build-hw-se050-usb-test-debug:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,ui-noop,stm32u585,usb,e2e-test,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> SE050 + USB test (debug) build ready."

flash-hw-se050-usb-test-debug: build-hw-se050-usb-test-debug
	probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching with semihosting (Ctrl-C to quit)..."
	probe-rs reset --chip STM32U585AIIx
	probe-rs attach --chip STM32U585AIIx $(SECURE_ELF)

# Real SE050 + GPIO hardware buttons + semihosting display.
# The SE050 runs over I2C1 (PB8/PB9 on the Arduino shield), buttons on
# CN13 D8/D9 jumper wires, and the UI renders via probe-rs semihosting.
# Interactive: PIN entry, seed wizard, signing — all on real hardware.
flash-hw-se050-buttons:
	@echo "==> Building SE050 + GPIO buttons + semihosting UI"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,debug-log,ui-semihosting,stm32u585,usb
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running SE050 + buttons wallet (Ctrl-C to quit)..."
	@echo "    LEFT=CN13 pin1 (D8), RIGHT=CN13 pin2 (D9), GND=CN13 pin7"
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# GPIO button test: scan Arduino header pins, then test debounced events.
# Requires: jumper wires on CN14 (D8=LEFT, D9=RIGHT, pin7=GND).
button-test:
	@echo "==> Building GPIO button test firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features button-test,debug-log,ui-semihosting
	@echo "==> Flashing button test firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running button test (Ctrl-C to quit)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Companion-app QR-code screen in isolation: flash a firmware that
# renders the QR + install URL on the OLED at boot and halts. Nothing
# else runs — no SEs, no PIN flow, no NS world. Power-cycle or press
# reset to re-run. Requires the SSD1306 OLED on I2C1 (PB8/PB9).
qr-screen:
	@echo "==> Building QR-screen test firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features qr-screen-test,debug-log
	@echo "==> Flashing QR-screen firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running QR screen (Ctrl-C to quit; the OLED holds the image)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# STSAFE-A110 I2C2 bus probe: detect on-board secure element.
# Scans I2C2 (PH4/PH5) for the STSAFE-A110 at 0x20 and any other devices.
stsafe-probe:
	@echo "==> Building STSAFE-A110 I2C2 probe firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features stsafe-probe,debug-log,ui-semihosting
	@echo "==> Flashing probe firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running I2C2 bus scan (Ctrl-C to quit)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# SE050 factory reset: wipe all objects, then halt.
# Run this once to clear stale SE050 state, then flash normal firmware.
# Assumes the stale UserID is at 0x7B06_0000 or 0x7B00_2000 (legacy) and
# the PIN is one of: 00000000, 12345678, 11111111. Each wrong attempt
# consumes one of the SE050's 10 PIN tries against that UserID; a correct
# PIN auto-resets the counter. Status reported on OLED + semihosting:
# clean / wrong-PIN / blocked.
se050-reset:
	@echo "==> Building SE050 factory-reset firmware..."
	@echo "    Assumes dev PIN in {00000000, 12345678, 11111111}"
	@echo "    and stale UserID at 0x7B06_0000 or 0x7B00_2000."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050-factory-reset,ui-noop,stm32u585,debug-log
	@echo "==> Flashing reset firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running factory reset (watch semihosting output)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

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
#   * All STM32 secure flash — mass-erased via STM32_Programmer_CLI,
#     which clears:
#       - page 124 — MCU PIN-attempt counter (one programmed QW per
#                    attempt; capacity 32, lockout at 10)
#       - page 125 — SE050 admin PIN + crash-safety wipe flag
#       - page 126 — OPTIGA Trust M Platform Binding Secret
#       - page 127 — Tropic01 pairing key slot
#     plus all firmware code — so you WILL need to re-flash afterwards.
#
# What does NOT get wiped:
#   * OPTIGA Trust M internal objects (half_O, auth refs). The firmware
#     currently has no OPTIGA reset path. Losing the PBS on STM32 page
#     126 means the MCU can no longer open a Shielded Connection against
#     those objects, so in practice the OPTIGA side is inert after this
#     target runs, but its silicon still holds the entropy half.
#   * Option bytes (TZEN / SECWM / SECBOOTADD0). Those survive mass
#     erase and the normal flash-hw-* targets re-assert them anyway.
#
# Prompts for confirmation. Requires ST-LINK connected and
# STM32_Programmer_CLI on PATH.
factory-reset:
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
			--features se050-factory-reset,ui-noop,stm32u585,debug-log
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	-@timeout 20 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) || true
	@echo ""
	@echo "==> Step 2/2: STM32 mass-erase (wipes all flash pages + firmware)"
	@STM32_Programmer_CLI --connect port=SWD mode=UR -e all
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
se050-reset-e2e:
	@echo "==> Building SE050 reset-roundtrip e2e firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050-reset-e2e,ui-noop,stm32u585,debug-log
	@echo "==> Flashing e2e firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running e2e (watch semihosting output)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

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
		-p sphincs-tz-secure --no-default-features --features se050-crash-safety-e2e,ui-noop,stm32u585,debug-log
	@echo "==> Flashing crash-safety firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo ""
	@echo "==> PHASE 1: provision + partial wipe + halt"
	@echo "    (Watching for 'PHASE 1 COMPLETE' — 30s timeout)..."
	-timeout 30 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) || true
	@echo ""
	@echo "==> Resetting board (simulated power cycle)..."
	probe-rs reset --chip STM32U585AIIx
	@echo ""
	@echo "==> PHASE 2: boot-time resume"
	@echo "    (Watching for 'CRASH-SAFETY RESUME: PASS' — 30s timeout)..."
	-timeout 30 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) || true

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
		-p sphincs-tz-secure --no-default-features --features se050-admin-wipe-e2e,ui-noop,stm32u585,debug-log
	@echo "==> Flashing admin-wipe e2e firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running admin-wipe e2e (watch semihosting output)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# SE050 + OLED interactive build (real SE050, real OLED display, real buttons).
# Full first-boot wizard: user enters PIN and creates/restores mnemonic.
# Both the SSD1306 OLED and SE050 share I2C1 (PB8/PB9) at 400 kHz.
build-hw-se050-oled:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,ui-oled,stm32u585,usb,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> SE050 + OLED interactive build ready."

# Standalone build: no debug-log, no semihosting. Safe to run with only
# USB-C power and no debugger attached. BKPT-free.
build-hw-se050-oled-standalone:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,ui-oled,stm32u585,usb
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Standalone build ready (no semihosting, USB-C only)."

flash-hw-se050-oled-standalone: build-hw-se050-oled-standalone
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip STM32U585AIIx
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
# wipe-for-wizard derives), `ui-oled`, `gpio-buttons`, `stm32u585`,
# `usb`. Deliberately DOES NOT include `optiga-lock-operational`;
# every OPTIGA user OID stays at LcsO=Creation through provisioning.
#
# Invariants respected:
#   #1 dual-chip seed split (half_O on OPTIGA, half_E on SE050).
#   #2 hardware-level PIN gating (OPTIGA auth-ref + SE050 UserID).
#   #3 E2E encrypted tunnels (Shielded Connection + SCP03).
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
		--features dual-se,optiga-hw-counter,dev-testkey,gpio-buttons,ui-oled,stm32u585,usb
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Dual-SE standalone build ready (no semihosting, USB-C only, LcsO=Creation)."

flash-hw-dual-se-oled-standalone: build-hw-dual-se-oled-standalone
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip STM32U585AIIx
	@echo "==> Flashed and reset. Disconnect ST-LINK, connect only USB-C if desired."
	@echo "    Set JP4 to 5V_UCPD for USB-C power (or keep 5V_USB_STLK if using both cables)."

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
# `gpio-buttons` + `ui-oled` — PIN / mnemonic entry goes through real
# button presses, not semihosting input.
build-hw-dual-se-oled-standalone-debug:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se,optiga-hw-counter,dev-testkey,gpio-buttons,ui-oled,stm32u585,usb,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Dual-SE standalone DEBUG build ready (debug-log ON, USB-C + ST-LINK)."

flash-hw-dual-se-oled-standalone-debug: build-hw-dual-se-oled-standalone-debug
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Attaching probe-rs run — semihosting stream follows. Ctrl-C to detach."
	@echo "    Power-cycle the board (pull+replug USB-C, or press the B2 RESET button)"
	@echo "    to see the full boot sequence. Wizard + PIN entry are driven by the"
	@echo "    physical buttons as usual; probe-rs only captures stdout."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# OPTIGA Trust M + OLED standalone — single-SE variant of the SE050
# standalone target above. Uses Infineon OPTIGA Trust M V3 on I2C1
# (TRUSTMV3SHIELDTOBO1 on Arduino R3 headers). No semihosting, USB-C
# only. Deliberately does NOT include `optiga-lock-operational`, so
# every user OID (E140, F1D0..F1D4, F1E1) stays at LcsO=Creation
# throughout provisioning — metadata remains mutable, data rewriteable,
# no irreversible LcsO=Operational bump. This build is intended for
# bench/dev use; see docs/optiga-brick-postmortem.md §5 + §7 before
# adding `optiga-lock-operational` for a real production unit.
#
# NOTE: this target violates invariant #1 (dual-chip seed split) — the
# full entropy lives on OPTIGA alone. It is the single-SE OPTIGA twin of
# `flash-hw-se050-oled-standalone`, not a production dual-SE build.
build-hw-optiga-oled-standalone:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features optiga-trust-m,gpio-buttons,ui-oled,stm32u585,usb
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Standalone OPTIGA build ready (no semihosting, USB-C only, LcsO=Creation)."

flash-hw-optiga-oled-standalone: build-hw-optiga-oled-standalone
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip STM32U585AIIx
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
# the device halts in `wfi`. The STM32_Programmer_CLI call re-asserts the
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
		--features optiga-nuclear-reset,stm32u585,ui-oled,gpio-buttons,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo ""
	@echo "==> Running with semihosting attached. Watch for:"
	@echo "      [OPTIGA/prov] step: ..."
	@echo "      [OPTIGA-E2E-ADMIN] ADMIN-WIPE ROUNDTRIP: PASS/FAIL"
	@echo "    Ctrl+C to detach once PASS/FAIL lines appear."
	@echo ""
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

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
		--features optiga-trust-m,stm32u585,ui-oled,gpio-buttons,e2e-test,e2e-skip-unlock,otp-hardcoded-master-key,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,e2e-test
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo ""
	@echo "==> Running with semihosting — watch for PBS fingerprint + provision OK."
	@echo "    Ctrl+C once you see '[OPTIGA] Provisioning complete' + halt."
	@echo ""
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

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
		--features optiga-trust-m,gpio-buttons,ui-oled,stm32u585,usb,dev-testkey,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip STM32U585AIIx
	@echo "==> Flashed. Interactive first-boot wizard runs on a blank chip."
	@echo "    PBS is the shared dev-testkey constant (NOT device-unique)."
	@echo "    To wipe wallet state:           make optiga-factory-reset-hw"
	@echo "    To see semihosting output:      probe-rs run --chip STM32U585AIIx $(SECURE_ELF)"

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
		--features optiga-trust-m,gpio-buttons,ui-oled,stm32u585,usb,dev-testkey,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo ""
	@echo "==> Running with semihosting attached. Ctrl+C to detach."
	@echo "    Hardware buttons (PC1 LEFT / PA8 RIGHT) drive the UI."
	@echo ""
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

flash-hw-se050-oled: build-hw-se050-oled
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Starting interactive SE050 wallet (Ctrl-C to quit)..."
	@echo "    Button input via keyboard: h/l=short left/right, H/L=long left/right"
	@python3 tools/wallet_run_hw.py

# Flash USB-enabled build to real STM32U585.
flash-hw-usb: build-hw-usb
	probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching (Ctrl-C to quit)..."
	probe-rs reset --chip STM32U585AIIx
	probe-rs attach --chip STM32U585AIIx $(SECURE_ELF)

# Run all three test layers: Rust unit tests, Foundry Solidity tests, and
# the full e2e suite under QEMU.
test: test-unit test-solidity e2e
	@echo "==> ALL TEST LAYERS PASSED"

# Host-side Rust unit tests for pure logic (aa, tx modules).
test-unit:
	@echo "==> Running Rust unit tests (host)"
	@cargo test --locked -p sphincs-tz-secure

# Foundry tests for the PQ smart-wallet contracts.
test-solidity:
	@echo "==> Running Foundry tests"
	@cd contracts/smart-wallet && forge test

# Compute firmware measurement words from the secure ELF.
# Displays the same 8 BIP-39 words the device shows at boot.
measure: secure
	cargo run --locked -p fwmeasure -- $(SECURE_ELF)

# Build the first-stage bootloader for real STM32U585 hardware.
#
# FSBL_VENDOR_PUBKEY: path to the 32-byte vendor pubkey (`pk_seed[16]
# || pk_root[16]`, produced by `fwsign pubkey`). If unset, a fixed dev
# fixture key is derived inline by fsbl/build.rs — the resulting FSBL
# is for development use only and will not accept production-signed
# firmware, and vice versa.
#
# Budget: 32 KB at 0x0C00_0000 (pages 0–3 of bank 1). Current footprint
# is ~18 KB with software SHA-256.
.PHONY: fsbl
fsbl:
	@echo "==> Building FSBL (FSBL_VENDOR_PUBKEY=$${FSBL_VENDOR_PUBKEY:-<dev fixture>})"
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/fsbl -p pqsigner-fsbl
	@echo "==> FSBL built: $(FSBL_ELF)"
	@size $(FSBL_ELF) 2>/dev/null || arm-none-eabi-size $(FSBL_ELF)

# Production-only: refuse to build the FSBL without FSBL_VENDOR_PUBKEY.
# Use this in the release pipeline.
.PHONY: fsbl-release
fsbl-release:
	@if [ -z "$${FSBL_VENDOR_PUBKEY}" ]; then \
		echo "ERROR: fsbl-release requires FSBL_VENDOR_PUBKEY=path/to/pubkey.bin"; \
		echo "       Use 'make fsbl' for dev builds with the built-in fixture."; \
		exit 1; \
	fi
	@$(MAKE) fsbl

# Verify byte-for-byte reproducibility of the secure + nonsecure ELFs.
#
# Builds each world twice in isolated target directories with the same
# FEATURES + toolchain, then diffs the resulting ELFs. Any divergence
# means some source of non-determinism has leaked into the build — the
# release is not safe to ship because an independent rebuild would
# produce different measurement words than the vendor publishes.
#
# This target is the canonical reproducibility gate. CI runs it on
# every PR; the release pipeline runs it before signing.
#
# Two builds share the same VENEERS path (build A writes it, build B
# links against the identical file), which is fine: linking the same
# implib into identical NS crates yields an identical NS ELF, so the
# whole reproducibility story holds.
.PHONY: verify-repro
verify-repro:
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
# pipeline consumes as input. Writes artifacts to target/release/.
#
# Note: --features are taken from $(RELEASE_FEATURES); the default is
# the production feature set (no debug-log, no e2e-test, no mock-se).
# Pass RELEASE_FEATURES=... on the command line to override.
RELEASE_FEATURES ?= stm32u585,se050,optiga-trust-m,dual-se,ui-oled
.PHONY: release
release:
	@echo "==> Release build (features: $(RELEASE_FEATURES))"
	@echo "==> SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)"
	@$(MAKE) verify-repro FEATURES=$(RELEASE_FEATURES)
	@mkdir -p target/release
	@cp target/repro-a/secure/$(TARGET)/release/sphincs-tz-secure \
	    target/release/secure.elf
	@cp target/repro-a/nonsecure/$(TARGET)/release/sphincs-tz-nonsecure \
	    target/release/nonsecure.elf
	@echo ""
	@echo "==> Secure measurement:"
	@cargo run --locked -q -p fwmeasure -- target/release/secure.elf 2>/dev/null | sed 's/^/    /'
	@echo ""
	@echo "==> Nonsecure measurement:"
	@cargo run --locked -q -p fwmeasure -- target/release/nonsecure.elf 2>/dev/null | sed 's/^/    /'
	@echo ""
	@echo "==> Release artifacts in target/release/"
	@echo "    Next: fwsign sign --key vendor-key.enc --version N ..."

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
#   [OPTIGA] PBS derived from OTP master and loaded
#   [OPTIGA/prov] step 1: setup_pbs_no_handshake
#   [OPTIGA/prov] E140 LcsO bump SKIPPED (optiga-lock-operational OFF; ...)
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
		--features optiga-trust-m,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching — watch for PRL handshake markers."
	@echo "    (Ctrl-C to abort; rerun the target after a code change to"
	@echo "     prove the PBS is stable across rebuilds.)"
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

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
#     NEVER called, so `ensure_pbs_lcso_operational` cannot bump E140 to
#     LcsO=Operational. The chip remains fully recoverable.
#
# If the write succeeds, we see `[OPTIGA] PBS provisioned (handshake
# deferred)` followed by `[S][e2e] e2e-skip-unlock active: halting after
# provisioning`. At that point the chip holds our PBS but is still rewrite-
# able via plaintext I2C (LcsO<op), so Phase B's PRL test can commit it
# properly, or a re-run with a different PBS can overwrite it.
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
		--features optiga-trust-m,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key,e2e-skip-unlock
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching — Phase-A validation (no LcsO=op bump)."
	@echo "    Watch for the PBS fingerprint + '[OPTIGA] PBS provisioned'"
	@echo "    followed by 'e2e-skip-unlock active: halting after provisioning'."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

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
		--features optiga-trust-m,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching — expect 'gateway pre-unlocked, ready for tests'"
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

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
optiga-hw-counter-e2e:
	@echo "==> Building OPTIGA hardware PIN counter (E120 + LUC) e2e firmware..."
	@echo "    This rewrites F1D0 metadata to the LUC-binding variant and"
	@echo "    provisions E120 as the silicon PIN counter. LcsO stays at"
	@echo "    Creation on every touched OID (optiga-lock-operational OFF)."
	@echo "    If F1D0 is somehow already at LcsO=Operational with legacy"
	@echo "    non-LUC metadata the firmware aborts loudly (Status 0xE0) —"
	@echo "    run optiga-reset-oids first in that case."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-hw-counter-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running hw-counter e2e (watch semihosting for PASS/FAIL)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

optiga-admin-wipe-e2e:
	@echo "==> Building OPTIGA factory_reset roundtrip e2e firmware..."
	@echo "    WARNING: this build will WIPE any wallet state on the target chip."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-admin-wipe-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running admin-wipe e2e (watch semihosting for PASS/FAIL)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

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
		--features dual-se-multi-unlock-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo ""
	@for n in 1 2 3; do \
		echo "==> Boot $$n/3..."; \
		log=$$(mktemp -t dual-se-multi-b$$n.XXXXXX.log); \
		probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1 | tee "$$log"; \
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
		--features dual-se-admin-wipe-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running dual-SE unlock e2e (watch semihosting for PASS/FAIL)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# PIN-gate roundtrip e2e. Direct non-interactive test of the MCU-side
# PIN attempt counter at flash page 126 + the `nsc::gated_unlock`
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
pin-gate-hw-counter-e2e:
	@echo "==> Building combined sync + desync recovery e2e firmware..."
	@echo "    Exercises MCU page-124 + OPTIGA E120 + SE050 UserID counters"
	@echo "    together under dual-se + optiga-hw-counter. WIPES wallet state"
	@echo "    on BOTH chips. Does NOT bump any OID to LcsO=Operational."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features pin-gate-hw-counter-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running combined sync + desync e2e (watch for SYNC+DESYNC ROUNDTRIP: PASS)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

pin-gate-wipe-e2e:
	@echo "==> Building MCU-MAX-ATTEMPTS lockout-wipe dispatch e2e firmware..."
	@echo "    DESTRUCTIVE: burns 10 wrong PINs → SE050 UserID silicon-locks,"
	@echo "    MCU counter saturates, E120 LUC at 10. Then fires"
	@echo "    factory_reset_admin + pin_attempts_reset to prove the lockout-"
	@echo "    wipe dispatch path end-to-end. Re-provisions at the end to"
	@echo "    prove recovery. Does NOT bump any OID to LcsO=Operational."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features pin-gate-wipe-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running wipe dispatch e2e (watch for WIPE+RECOVERY ROUNDTRIP: PASS)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

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
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

wipe-for-wizard:
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
		--features wipe-for-wizard,stm32u585,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running wipe (watch OLED for 'WIPED — power-cycle me')..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

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
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running (pulses fire once, then CPU halts in wfe)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# One-shot SAES self-test on real silicon. Boots the firmware just far
# enough to init SAES (Tier 1 of work-todo #7), runs the software-key
# round-trip + DHUK-vs-SW domain-separation + DHUK round-trip self-
# tests, prints an 8-byte DHUK fingerprint, then exits cleanly via
# SYS_EXIT. No OTP burn, no flash writes, no TAMP access, no SE I/O.
# Cross-boot check: run this twice on the same board — the DHUK
# fingerprint must be byte-identical across reboots. Running on
# different boards should yield different fingerprints.
saes-self-test-hw:
	@echo "==> Building SAES Tier-1 self-test firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features saes-self-test,debug-log,ui-noop,e2e-test,mock-se
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running SAES self-test..."
	@log=$$(mktemp -t saes-self-test.XXXXXX.log); \
	trap 'rm -f "$$log"' EXIT; \
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1 | tee "$$log"; \
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
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing at RDP0..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Ensuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
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
	STM32_Programmer_CLI --connect port=SWD mode=UR --optionbytes RDP=0xBB || \
		STM32_Programmer_CLI --connect port=SWD mode=HotPlug --optionbytes RDP=0xBB || true; \
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
	@STM32_Programmer_CLI --connect port=SWD mode=UR --optionbytes RDP=0xAA \
		UNLOCK_1A=1 UNLOCK_1B=1 UNLOCK_2A=1 UNLOCK_2B=1 || \
		STM32_Programmer_CLI --connect port=SWD mode=HotPlug --optionbytes RDP=0xAA \
			UNLOCK_1A=1 UNLOCK_1B=1 UNLOCK_2A=1 UNLOCK_2B=1
	@echo "==> Stripping write-protect + secure watermarks..."
	@STM32_Programmer_CLI --connect port=SWD --optionbytes \
		WRP1A_PSTRT=0x7F WRP1A_PEND=0x0 WRP1B_PSTRT=0x7F WRP1B_PEND=0x0 \
		WRP2A_PSTRT=0x7F WRP2A_PEND=0x0 WRP2B_PSTRT=0x7F WRP2B_PEND=0x0 \
		SECWM1_PSTRT=0x7F SECWM1_PEND=0x0 SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 || true
	@echo "==> Mass-erase both banks..."
	@STM32_Programmer_CLI --connect port=SWD -e all
	@echo "==> Restoring default option bytes (TZEN=1 + full-secure banks + SECBOOTADD0)..."
	@STM32_Programmer_CLI --connect port=SWD --optionbytes \
		TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Regression complete — board is back at RDP0."

pin-gate-e2e:
	@echo "==> Building PIN-gate roundtrip e2e firmware..."
	@echo "    WARNING: this build will WIPE wallet state on BOTH chips."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features pin-gate-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running PIN-gate e2e (watch semihosting for PASS/FAIL)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Shield-handshake-only test. Skips `provision_from_mnemonic` entirely
# and runs `init` → `load_pbs_from_otp` → `ensure_shield` against an
# already-provisioned chip. Use this to validate the Shielded Connection
# handshake in isolation without re-writing any F1Dx state. The chip's
# E140 must already have the OTP-derived PBS from a prior run of
# `flash-hw-optiga-bringup-write-only`; the PBS itself is reproduced
# deterministically from the STM32U585's OTP master on every boot.
flash-hw-optiga-shield-handshake-only:
	@echo "==> Building OPTIGA shield-handshake-only test"
	@echo "    (e2e-skip-provision: reuses existing E140 PBS, tests PRL only)"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key,e2e-skip-unlock,e2e-skip-provision
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching — expect '[S][e2e] SHIELD UP — PRL handshake succeeded'."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# One-shot OPTIGA Trust M OID recovery. Regenerates reset manifests from
# the Infineon protected_update_data_set tool, builds firmware with the
# optiga-reset-oids feature, flashes the STM32U585, and attaches probe-rs
# so the reset log is visible. Drop the feature from the regular flash
# targets after the chip reports all OIDs reset OK.
optiga-reset-oids:
	@echo "==> Regenerating reset manifests (requires built tool)"
	@test -x /home/nicola/repos/optiga-trust-m/examples/tools/protected_update_data_set/bin/protected_update_data_set \
		|| (echo "Build the tool first: make -C /home/nicola/repos/optiga-trust-m/examples/tools/protected_update_data_set" && exit 1)
	@python3 tools/optiga_reset/gen_reset_manifests.py

flash-hw-optiga-reset: optiga-reset-oids
	@echo "==> Building firmware with optiga-reset-oids"
	@echo ""
	@echo "    ### DOES NOT WORK ON TRUSTMV3SHIELDTOBO1 ###"
	@echo "    Verified 2026-04-22: all 17 target OIDs return Status(0xFF)"
	@echo "    because E0E3 on this shield is Infineon's device cert slot"
	@echo "    (DataType 0x12), not a mutable Trust Anchor slot (0x11)."
	@echo "    SetDataObject accepts our TA cert bytes but the chip does"
	@echo "    not promote the slot to act as a TA, so every subsequent"
	@echo "    SetObjectProtected manifest fails signature verification."
	@echo "    See memory/project_optiga_reset_oids.md for full trace."
	@echo ""
	@echo "    Continue only if you have a DIFFERENT OPTIGA chip where"
	@echo "    E0E3 is known-blank (fresh engineering samples). Ctrl-C"
	@echo "    now to abort."
	@echo ""
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW) -C debug-assertions=on" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se,optiga-reset-oids,stm32u585,ui-oled,debug-log,usb
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Attaching probe-rs so the reset log is visible (Ctrl-C to quit)..."
	@probe-rs reset --chip STM32U585AIIx
	@probe-rs attach --chip STM32U585AIIx $(SECURE_ELF)

clean:
	rm -rf target/secure target/nonsecure target/veneers.o
