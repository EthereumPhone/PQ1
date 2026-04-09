TARGET = thumbv8m.main-none-eabi
RUSTFLAGS_VAR = CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS
VENEERS = $(CURDIR)/target/veneers.o

SECURE_ELF   = target/secure/$(TARGET)/release/sphincs-tz-secure
NONSECURE_ELF = target/nonsecure/$(TARGET)/release/sphincs-tz-nonsecure

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

.PHONY: all clean secure nonsecure run play run-tropic01 run-hw setup-serial e2e e2e-hw build-hw flash-hw

all: secure nonsecure

secure:
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features $(FEATURES)
	@echo "==> Secure world built (features: $(FEATURES)). Veneers: $(VENEERS)"

nonsecure: secure
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
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
	@echo "==> Building secure + nonsecure with e2e-test feature"
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
		cargo build --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
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
		"\\[S\\]\\[e2e\\] cmd_sign dispatch = ValueTransfer" \
		"\\[S\\]\\[e2e\\] cmd_sign dispatch = Erc20Known" \
		"\\[S\\]\\[e2e\\] cmd_sign dispatch = ContractCall" \
		"\\[S\\]\\[e2e\\] cmd_clear_sign dispatch = ZkClearSign" \
		"\\[S\\]\\[e2e\\] cmd_clear_sign_msg dispatch = ZkClearSignMsg" \
		"\\[E2E\\] value_transfer = PASS" \
		"\\[E2E\\] erc20_known = PASS" \
		"\\[E2E\\] blind_sign = PASS" \
		"\\[E2E\\] zk_clear_sign = PASS" \
		"\\[E2E\\] cowswap_pre_sign = PASS" \
		"\\[E2E\\] cowswap_eip712_order = PASS" \
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
	@probe-rs reset --chip STM32U585AIIx
	@probe-rs attach --chip STM32U585AIIx $(SECURE_ELF)

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

clean:
	rm -rf target/secure target/nonsecure target/veneers.o
