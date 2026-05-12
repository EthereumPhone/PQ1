# Side-channel / fault-injection self-tests for PQSigner, driven by the Ledger
# Donjon toolchain (rainbow + lascar) via the `donjon-sca` CLI. See ./README.md.
#
# Requires `donjon-sca` on PATH:
#   git clone https://github.com/Nicola-Ceornea/my-claude-skills.git ~/repos/my-claude-skills
#   ~/repos/my-claude-skills/setup.sh
#
# Targets:
#   make build       build the thumbv8m fault-sweep target ELF (sca-fi-target)
#   make build-kdf   build the thumbv8m leakage target ELF (sca-kdf-target)
#   make build-c10v  build the thumbv8m real-C10-verify target ELF (sca-c10v-target)
#   make fi           build + run the FI-guard fault sweep (fi.rs: check_true / wait_random)
#   make c10          build + run the C10 verify-before-release *gate* fault sweep (sign/verify stubbed)
#   make pin          build + run the PIN-attempt pre-commit gate fault sweep
#   make c10v         build + run the fault sweep over the *real* sphincs_c10::verify (forge-a-sig direction)
#   make kdf          build + run the lascar leakage analysis (AES / AES-GCM entropy wrap + a positive control)
#   make sweeps       fi + c10 + pin  (the fast fault sweeps; `c10v` and `kdf` are slower — run them on their own)
#   make doctor       `donjon-sca doctor` — is the toolchain installed?
#   make clean        cargo clean the target crates

TARGET   := thumbv8m.main-none-eabi
FI_DIR   := fi_target
FI_ELF   := $(FI_DIR)/target/$(TARGET)/release/sca-fi-target
KDF_DIR  := kdf_target
KDF_ELF  := $(KDF_DIR)/target/$(TARGET)/release/sca-kdf-target
C10V_DIR := c10v_target
C10V_ELF := $(C10V_DIR)/target/$(TARGET)/release/sca-c10v-target
DONJON   ?= donjon-sca

.PHONY: build build-kdf build-c10v fi c10 pin c10v kdf sweeps doctor clean

build: $(FI_ELF)

$(FI_ELF): $(FI_DIR)/src/main.rs $(FI_DIR)/memory.x $(FI_DIR)/build.rs $(FI_DIR)/Cargo.toml ../../secure/src/fi.rs
	cargo build --release --target $(TARGET) --manifest-path $(FI_DIR)/Cargo.toml

build-kdf: $(KDF_ELF)

$(KDF_ELF): $(KDF_DIR)/src/main.rs $(KDF_DIR)/memory.x $(KDF_DIR)/build.rs $(KDF_DIR)/Cargo.toml
	cargo build --release --target $(TARGET) --manifest-path $(KDF_DIR)/Cargo.toml

build-c10v: $(C10V_ELF)

$(C10V_ELF): $(C10V_DIR)/src/main.rs $(C10V_DIR)/memory.x $(C10V_DIR)/build.rs $(C10V_DIR)/Cargo.toml ../../sphincs-c10/src/lib.rs
	cargo build --release --target $(TARGET) --manifest-path $(C10V_DIR)/Cargo.toml

fi: build
	$(DONJON) run fault_sweep_fi.py

c10: build
	$(DONJON) run fault_sweep_c10_verify.py

pin: build
	$(DONJON) run fault_sweep_pin.py

c10v: build-c10v
	$(DONJON) run fault_sweep_c10v.py

kdf: build-kdf
	$(DONJON) run leakage_kdf.py

sweeps: fi c10 pin

doctor:
	$(DONJON) doctor

clean:
	cargo clean --manifest-path $(FI_DIR)/Cargo.toml
	cargo clean --manifest-path $(KDF_DIR)/Cargo.toml
	cargo clean --manifest-path $(C10V_DIR)/Cargo.toml
