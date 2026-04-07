TARGET = thumbv8m.main-none-eabi
RUSTFLAGS_VAR = CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS
VENEERS = $(CURDIR)/target/veneers.o

SECURE_ELF   = target/secure/$(TARGET)/release/sphincs-tz-secure
NONSECURE_ELF = target/nonsecure/$(TARGET)/release/sphincs-tz-nonsecure

# Default: mock secure element + semihosting UI mock (no real hardware needed)
# debug-log enables semihosting output from the secure world.
# Remove it for production builds to eliminate all debug strings.
FEATURES ?= mock-se,debug-log,ui-semihosting

.PHONY: all clean secure nonsecure run play run-tropic01 run-hw setup-serial

all: secure nonsecure

secure:
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features $(FEATURES)
	@echo "==> Secure world built (features: $(FEATURES)). Veneers: $(VENEERS)"

nonsecure: secure
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure
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

# Real STM32U585 hardware build: real chip + real OLED + real buttons.
# This target only BUILDS — flashing is done with probe-rs / openocd / etc.
# It will not link until secure/src/hw/stm32u585.rs is filled in.
run-hw:
	$(MAKE) FEATURES=tropic01-se,ui-oled,pka-accel all

clean:
	rm -rf target/secure target/nonsecure target/veneers.o
