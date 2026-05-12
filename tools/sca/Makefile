# Side-channel / fault-injection self-tests for PQSigner, driven by the Ledger
# Donjon toolchain (rainbow + lascar) via the `donjon-sca` CLI. See ./README.md.
#
# Requires `donjon-sca` on PATH:
#   git clone https://github.com/Nicola-Ceornea/my-claude-skills.git ~/repos/my-claude-skills
#   ~/repos/my-claude-skills/setup.sh
#
# Targets:
#   make build    build the thumbv8m fault-injection target ELF (sca-fi-target)
#   make fi        build + run the FI-guard fault sweep (fi.rs: check_true / wait_random)
#   make doctor    `donjon-sca doctor` — is the toolchain installed?
#   make clean     cargo clean the target crate

TARGET := thumbv8m.main-none-eabi
FI_DIR := fi_target
FI_ELF := $(FI_DIR)/target/$(TARGET)/release/sca-fi-target
DONJON ?= donjon-sca

.PHONY: build fi doctor clean

build: $(FI_ELF)

$(FI_ELF): $(FI_DIR)/src/main.rs $(FI_DIR)/memory.x $(FI_DIR)/build.rs $(FI_DIR)/Cargo.toml ../../secure/src/fi.rs
	cargo build --release --target $(TARGET) --manifest-path $(FI_DIR)/Cargo.toml

fi: build
	$(DONJON) run fault_sweep_fi.py

doctor:
	$(DONJON) doctor

clean:
	cargo clean --manifest-path $(FI_DIR)/Cargo.toml
