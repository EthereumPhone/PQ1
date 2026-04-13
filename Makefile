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

SECURE_ELF   = target/secure/$(TARGET)/release/sphincs-tz-secure
NONSECURE_ELF = target/nonsecure/$(TARGET)/release/sphincs-tz-nonsecure

# Default: mock secure element + semihosting UI mock (no real hardware needed)
# debug-log enables semihosting output from the secure world.
# Remove it for production builds to eliminate all debug strings.
FEATURES ?= mock-se,debug-log,ui-semihosting

# ---- Mirror mode --------------------------------------------------------
# Stream the SSD1306 OLED contents to a scaled host window (via RTT)
# instead of relying on the physical OLED. The firmware is built with the
# `ui-mirror` feature and `debug-log` is dropped — semihosting BKPT
# syscalls block forever without a host to service them, and the mirror
# tool isn't one. Any target that wants to support mirror mode uses the
# `RUN_OR_MIRROR` recipe below.
#
# Two equivalent ways to enable it:
#    make qr-screen mirror       # extra goal — recommended ergonomics
#    make qr-screen MIRROR=1     # explicit variable form
MIRROR ?= 0
ifneq (,$(filter mirror,$(MAKECMDGOALS)))
  MIRROR := 1
endif

# No-op goal. Its presence on the command line flips MIRROR above; the
# recipe itself does nothing so the "real" target next to it runs.
.PHONY: mirror
mirror:
	@:

# Extract features relevant to the nonsecure crate (it doesn't know about
# mock-se, debug-log, ui-semihosting, etc. — only e2e-test and stm32u585).
NS_FEATURES_LIST := $(strip $(foreach f,stm32u585 e2e-test usb,$(if $(findstring $(f),$(FEATURES)),$(f))))
comma := ,
empty :=
space := $(empty) $(empty)
NS_FEATURES_ARG = $(if $(NS_FEATURES_LIST),--features $(subst $(space),$(comma),$(NS_FEATURES_LIST)),)

.PHONY: all clean secure nonsecure run play play-hw-display run-tropic01 run-hw setup-serial e2e e2e-hw e2e-hw-display build-hw flash-hw test test-unit test-solidity qr-screen prod-check

all: secure nonsecure

secure:
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(SECURE_CMSE_FLAGS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features $(FEATURES)
	@echo "==> Secure world built (features: $(FEATURES))."

nonsecure: secure
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(NS_VENEERS_FLAG)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure $(NS_FEATURES_ARG)
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

# Feature set for `play-hw-display`. Mirror mode swaps `debug-log` (which
# would block on semihosting BKPTs) for `ui-mirror`; buttons arrive over
# the RTT down-channel from the host tool.
ifeq ($(MIRROR),1)
  PLAY_HW_FEATURES := mock-se,ui-oled,stm32u585,ui-mirror
else
  PLAY_HW_FEATURES := mock-se,debug-log,ui-oled,stm32u585
endif

# Interactive two-button wallet on real STM32U585 with SSD1306 OLED display.
# Same arrow-key mapping as `play` (QEMU version), but runs on real hardware.
# Display renders on the physical OLED; button input comes from your laptop
# keyboard via probe-rs semihosting READC.
# Requires: ST-LINK connected, SSD1306 OLED wired to PB8/PB9/3V3/GND.
#
# Append `mirror` to stream the OLED to a host window and drive buttons
# via the window's keyboard focus (arrow keys, Shift+arrow for long press):
#   make play-hw-display mirror
play-hw-display:
	@echo "==> Building secure + nonsecure for interactive OLED play (features: $(PLAY_HW_FEATURES))"
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
		cargo build --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features $(PLAY_HW_FEATURES)
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
		cargo build --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
ifeq ($(MIRROR),1)
	$(call RUN_OR_MIRROR,$(SECURE_ELF))
else
	@echo "==> Starting interactive wallet (Ctrl-C to quit)..."
	@python3 tools/wallet_run_hw.py
endif

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
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x" \
		cargo build --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x" \
		cargo build --release --target $(TARGET) --target-dir target/nonsecure \
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

# Same e2e suite but on real STM32U585 hardware via probe-rs semihosting.
# Requires: ST-LINK connected, STM32_Programmer_CLI on PATH.
e2e-hw:
	@echo "==> Building e2e + stm32u585"
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
		cargo build --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test,stm32u585
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
		cargo build --release --target $(TARGET) --target-dir target/nonsecure \
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
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
		cargo build --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-oled,e2e-test,stm32u585
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
		cargo build --release --target $(TARGET) --target-dir target/nonsecure \
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

# Real STM32U585 hardware build with USB HID host communication.
# Uses mock SE + semihosting debug output + USB transport.
build-hw-usb:
	$(MAKE) FEATURES=mock-se,debug-log,ui-semihosting,stm32u585,usb all

# USB build with auto-provisioning for standalone testing.
# No debug-log (semihosting BKPT faults without debugger attached).
# Secure world: e2e-test auto-provisions, ui-semihosting for compile compat.
# NS world: usb feature for USB HID main loop.
build-hw-usb-test:
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features mock-se,ui-noop,stm32u585,usb,e2e-test
	@rm -f $(NONSECURE_ELF)
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb
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
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,ui-noop,stm32u585,usb,e2e-test
	@rm -f $(NONSECURE_ELF)
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb
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
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,ui-noop,stm32u585,usb,e2e-test,debug-log
	@rm -f $(NONSECURE_ELF)
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb
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
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,debug-log,ui-semihosting,stm32u585,usb
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb
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
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features button-test,debug-log,ui-semihosting
	@echo "==> Flashing button test firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running button test (Ctrl-C to quit)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Feature-set selection for targets that support MIRROR=1. Dropping
# `debug-log` here isn't optional: with `ui-mirror` enabled and no host
# servicing semihosting BKPTs, any `secure_log!` call hangs the MCU.
ifeq ($(MIRROR),1)
  QR_SCREEN_FEATURES := qr-screen-test,ui-mirror
else
  QR_SCREEN_FEATURES := qr-screen-test,debug-log
endif

# Canned recipe used by any target that wants MIRROR=1 support. Called
# AFTER `probe-rs download`. Argument: $(1) = path to the flashed ELF.
# Resets the target (the mirror tool does this) and either launches the
# host window or hands off to `probe-rs run`.
define RUN_OR_MIRROR
@if [ "$(MIRROR)" = "1" ]; then \
    echo "==> Building oled-mirror host tool..."; \
    cargo build --release --manifest-path tools/oled-mirror/Cargo.toml; \
    RTT_ADDR=$$(arm-none-eabi-nm $(1) | awk '/ _SEGGER_RTT$$/ {print "0x"$$1}'); \
    echo "==> Streaming OLED to window (rtt @ $$RTT_ADDR; close window or Esc to quit)..."; \
    ./tools/oled-mirror/target/release/oled-mirror --chip STM32U585AIIx --rtt-addr $$RTT_ADDR; \
 else \
    echo "==> Running (Ctrl-C to quit)..."; \
    probe-rs run --chip STM32U585AIIx $(1); \
 fi
endef

# Companion-app QR-code screen in isolation: flash a firmware that
# renders the QR + install URL on the OLED at boot and halts. Nothing
# else runs — no SEs, no PIN flow, no NS world. Power-cycle or press
# reset to re-run. Requires the SSD1306 OLED on I2C1 (PB8/PB9).
#
# Append `mirror` to stream the OLED contents to a host window instead:
#   make qr-screen mirror
qr-screen:
	@echo "==> Building QR-screen test firmware (features: $(QR_SCREEN_FEATURES))..."
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features $(QR_SCREEN_FEATURES)
	@echo "==> Flashing QR-screen firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	$(call RUN_OR_MIRROR,$(SECURE_ELF))

# Production gate: refuse to build if any debug-only Cargo feature is in
# the FEATURES list. Run this from CI before any release artifact is
# produced. The forbidden set must stay in lockstep with the "NEVER ship"
# features called out in CLAUDE.md and secure/Cargo.toml.
FORBIDDEN_FEATURES := debug-log e2e-test ui-mirror mock-se se050-factory-reset se050-reset-e2e qr-screen-test stsafe-probe button-test
prod-check:
	@bad=""; \
	for f in $(FORBIDDEN_FEATURES); do \
		case ",$(FEATURES)," in \
			*,$$f,*) bad="$$bad $$f" ;; \
		esac; \
	done; \
	if [ -n "$$bad" ]; then \
		echo "ERROR: production build contains forbidden feature(s):$$bad"; \
		echo "       FEATURES=$(FEATURES)"; \
		exit 1; \
	fi; \
	echo "==> prod-check OK (no forbidden features in: $(FEATURES))"

# STSAFE-A110 I2C2 bus probe: detect on-board secure element.
# Scans I2C2 (PH4/PH5) for the STSAFE-A110 at 0x20 and any other devices.
stsafe-probe:
	@echo "==> Building STSAFE-A110 I2C2 probe firmware..."
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features stsafe-probe,debug-log,ui-semihosting
	@echo "==> Flashing probe firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running I2C2 bus scan (Ctrl-C to quit)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# SE050 factory reset: wipe all objects, then halt.
# Run this once to clear stale SE050 state, then flash normal firmware.
se050-reset:
	@echo "==> Building SE050 factory-reset firmware..."
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050-factory-reset,ui-noop,stm32u585,debug-log
	@echo "==> Flashing reset firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running factory reset (watch semihosting output)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# SE050 factory-reset roundtrip e2e test on real hardware.
# Provisions a fresh test UserID + 2 gated data objects, exercises
# user_factory_reset, then verifies all three objects are gone.
# Uses test object IDs (0x7B07_xxxx) so it doesn't touch any real
# wallet provisioning. Repeatable on the same chip.
# Watch semihosting for "[E2E] FACTORY-RESET ROUNDTRIP: PASS"/"FAIL".
se050-reset-e2e:
	@echo "==> Building SE050 reset-roundtrip e2e firmware..."
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050-reset-e2e,ui-noop,stm32u585,debug-log
	@echo "==> Flashing e2e firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running e2e (watch semihosting output)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# SE050 + OLED interactive build (real SE050, real OLED display, real buttons).
# Full first-boot wizard: user enters PIN and creates/restores mnemonic.
# Both the SSD1306 OLED and SE050 share I2C1 (PB8/PB9) at 400 kHz.
build-hw-se050-oled:
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,ui-oled,stm32u585,usb,debug-log
	@rm -f $(NONSECURE_ELF)
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> SE050 + OLED interactive build ready."

# Standalone build: no debug-log, no semihosting. Safe to run with only
# USB-C power and no debugger attached. BKPT-free.
build-hw-se050-oled-standalone:
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,ui-oled,stm32u585,usb
	@rm -f $(NONSECURE_ELF)
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Standalone build ready (no semihosting, USB-C only)."

# WebHID test build: SE050 + OLED + USB + auto-provision/auto-confirm.
# No debug-log → no semihosting, safe without debugger. The e2e-test
# feature auto-provisions with a fixed test mnemonic and auto-confirms
# every signing dialog, so WebHID can round-trip sign requests without
# physical button presses.
build-hw-se050-oled-usb-test:
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,ui-oled,stm32u585,usb,e2e-test
	@rm -f $(NONSECURE_ELF)
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> SE050 + OLED + USB test build ready (auto-provisioned, auto-confirm, no semihosting)."

flash-hw-se050-oled-usb-test: build-hw-se050-oled-usb-test
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Flashed. Ready for WebHID testing."
	@echo "    Device auto-provisions and auto-confirms. No button presses needed."

flash-hw-se050-oled-standalone: build-hw-se050-oled-standalone
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Flashed. Disconnect ST-LINK, connect only USB-C."
	@echo "    Set JP4 to 5V_UCPD for USB-C power (or keep 5V_USB_STLK if using both cables)."

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
	@cargo test -p sphincs-tz-secure

# Foundry tests for the PQ smart-wallet contracts.
test-solidity:
	@echo "==> Running Foundry tests"
	@cd contracts/smart-wallet && forge test

clean:
	rm -rf target/secure target/nonsecure target/veneers.o
