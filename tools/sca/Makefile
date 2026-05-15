# Side-channel / fault-injection self-tests for PQSigner, driven by the Ledger
# Donjon toolchain (rainbow + lascar) via the `donjon-sca` CLI. See ./README.md.
#
# Requires `donjon-sca` on PATH:
#   git clone https://github.com/Nicola-Ceornea/my-claude-skills.git ~/repos/my-claude-skills
#   ~/repos/my-claude-skills/setup.sh
#
# Targets:
#   make build              build the thumbv8m fault-sweep target ELF (sca-fi-target)
#   make build-kdf          build the thumbv8m leakage target ELF (sca-kdf-target)
#   make build-c10v         build the thumbv8m real-C10-verify target ELF (sca-c10v-target)
#   make build-fw-verify    build the thumbv8m FW-manifest-verify target ELF (sca-fw-verify-target)
#   make fi           build + run the FI-guard fault sweep (fi.rs: check_true / wait_random; 3 single-fault models)
#   make fi-twofault  build + run the FI-guard sweep PLUS the [skip,skip] two-fault pair sweep over check_true (slower)
#   make c10          build + run the C10 verify-before-release *gate* fault sweep (sign/verify stubbed)
#   make pin          build + run the PIN-attempt pre-commit gate fault sweep
#   make c10v         build + run the fault sweep over the *real* sphincs_c10::verify (forge-a-sig direction)
#   make fw-verify    build + run the FI sweep over the *real* fw-manifest verify chain (FW-update bypass)
#   make kdf          build + run the lascar leakage analysis (AES / AES-GCM entropy wrap + a positive control)
#   make sweeps       fi + c10 + pin + fw-verify  (the FI fault sweeps; `c10v` and `kdf` are slower — run them on their own)
#   make doctor       `donjon-sca doctor` — is the toolchain installed?
#   make clean        cargo clean the target crates

TARGET   := thumbv8m.main-none-eabi
FI_DIR   := fi_target
FI_ELF   := $(FI_DIR)/target/$(TARGET)/release/sca-fi-target
KDF_DIR  := kdf_target
KDF_ELF  := $(KDF_DIR)/target/$(TARGET)/release/sca-kdf-target
C10V_DIR := c10v_target
C10V_ELF := $(C10V_DIR)/target/$(TARGET)/release/sca-c10v-target
FWV_DIR  := fw_verify_target
FWV_ELF  := $(FWV_DIR)/target/$(TARGET)/release/sca-fw-verify-target
NSP_DIR  := ns_ptr_target
NSP_ELF  := $(NSP_DIR)/target/$(TARGET)/release/sca-ns-ptr-target
C10S_DIR := c10_sign_target
C10S_ELF := $(C10S_DIR)/target/$(TARGET)/release/sca-c10-sign-target
CAP_DIR  := cap_target
CAP_ELF  := $(CAP_DIR)/target/$(TARGET)/release/sca-cap-target
DISP_DIR := dispatch_target
DISP_ELF := $(DISP_DIR)/target/$(TARGET)/release/sca-dispatch-target
FCT_DIR  := flashctr_target
FCT_ELF  := $(FCT_DIR)/target/$(TARGET)/release/sca-flashctr-target
DONJON   ?= donjon-sca

.PHONY: build build-kdf build-c10v build-fw-verify build-ns-ptr build-c10-sign build-cap build-dispatch build-flashctr fi fi-twofault c10 pin c10v fw-verify ns-ptr c10-sign cap dispatch flashctr kdf sweeps doctor clean

build: $(FI_ELF)

$(FI_ELF): $(FI_DIR)/src/main.rs $(FI_DIR)/memory.x $(FI_DIR)/build.rs $(FI_DIR)/Cargo.toml ../../secure/src/fi.rs
	cargo build --release --target $(TARGET) --manifest-path $(FI_DIR)/Cargo.toml

build-kdf: $(KDF_ELF)

$(KDF_ELF): $(KDF_DIR)/src/main.rs $(KDF_DIR)/memory.x $(KDF_DIR)/build.rs $(KDF_DIR)/Cargo.toml
	cargo build --release --target $(TARGET) --manifest-path $(KDF_DIR)/Cargo.toml

build-c10v: $(C10V_ELF)

$(C10V_ELF): $(C10V_DIR)/src/main.rs $(C10V_DIR)/memory.x $(C10V_DIR)/build.rs $(C10V_DIR)/Cargo.toml ../../sphincs-c10/src/lib.rs
	cargo build --release --target $(TARGET) --manifest-path $(C10V_DIR)/Cargo.toml

build-fw-verify: $(FWV_ELF)

$(FWV_ELF): $(FWV_DIR)/src/main.rs $(FWV_DIR)/memory.x $(FWV_DIR)/build.rs $(FWV_DIR)/Cargo.toml ../../fw-manifest/src/lib.rs ../../sphincs-c10/src/lib.rs ../../secure/src/fi.rs ../../secure/src/fw_update/mod.rs
	cargo build --release --target $(TARGET) --manifest-path $(FWV_DIR)/Cargo.toml

build-ns-ptr: $(NSP_ELF)

$(NSP_ELF): $(NSP_DIR)/src/main.rs $(NSP_DIR)/memory.x $(NSP_DIR)/build.rs $(NSP_DIR)/Cargo.toml ../../secure/src/nsc/ptr_validate.rs ../../secure/src/fi.rs
	cargo build --release --target $(TARGET) --manifest-path $(NSP_DIR)/Cargo.toml

build-c10-sign: $(C10S_ELF)

$(C10S_ELF): $(C10S_DIR)/src/main.rs $(C10S_DIR)/memory.x $(C10S_DIR)/build.rs $(C10S_DIR)/Cargo.toml ../../sphincs-c10/src/lib.rs ../../secure/src/fi.rs
	cargo build --release --target $(TARGET) --manifest-path $(C10S_DIR)/Cargo.toml

build-cap: $(CAP_ELF)

$(CAP_ELF): $(CAP_DIR)/src/main.rs $(CAP_DIR)/memory.x $(CAP_DIR)/build.rs $(CAP_DIR)/Cargo.toml ../../pqsigner-fi/src/lib.rs
	cargo build --release --target $(TARGET) --manifest-path $(CAP_DIR)/Cargo.toml

build-dispatch: $(DISP_ELF)

$(DISP_ELF): $(DISP_DIR)/src/main.rs $(DISP_DIR)/memory.x $(DISP_DIR)/build.rs $(DISP_DIR)/Cargo.toml ../../pqsigner-fi/src/lib.rs
	cargo build --release --target $(TARGET) --manifest-path $(DISP_DIR)/Cargo.toml

build-flashctr: $(FCT_ELF)

$(FCT_ELF): $(FCT_DIR)/src/main.rs $(FCT_DIR)/memory.x $(FCT_DIR)/build.rs $(FCT_DIR)/Cargo.toml ../../pqsigner-fi/src/lib.rs ../../secure/src/hw/flash.rs
	cargo build --release --target $(TARGET) --manifest-path $(FCT_DIR)/Cargo.toml

fi: build
	$(DONJON) run fault_sweep_fi.py

fi-twofault: build
	$(DONJON) run fault_sweep_fi.py --two-fault

c10: build
	$(DONJON) run fault_sweep_c10_verify.py

pin: build
	$(DONJON) run fault_sweep_pin.py

c10v: build-c10v
	$(DONJON) run fault_sweep_c10v.py

fw-verify: build-fw-verify
	$(DONJON) run fault_sweep_fw_verify.py

ns-ptr: build-ns-ptr
	$(DONJON) run fault_sweep_ns_ptr.py

c10-sign: build-c10-sign
	$(DONJON) run fault_sweep_c10_sign.py

cap: build-cap
	$(DONJON) run fault_sweep_cap.py

dispatch: build-dispatch
	$(DONJON) run fault_sweep_dispatch.py

flashctr: build-flashctr
	$(DONJON) run fault_sweep_flashctr.py

kdf: build-kdf
	$(DONJON) run leakage_kdf.py

# F-9 re-test: did F-16's shuffle mask the FORS-leaf-index mem_address leak?
# Compares post-F-16 max|t| against F-9's recorded baseline of 40.71.
f9-retest: build-kdf
	$(DONJON) run f9_retest.py

# F-9 deeper sweep: tests F-16 on the SECRET-bearing region (FORS + WOTS sign)
# past grind_r. Uses stride=10 + 30 M samples to cover ~300 M mem events
# without OOM. Drops to 200 traces (vs F-9's 600) to stay in 64 GB RAM.
f9-deeper: build-kdf
	$(DONJON) run f9_deeper.py

sweeps: fi c10 pin fw-verify ns-ptr

doctor:
	$(DONJON) doctor

clean:
	cargo clean --manifest-path $(FI_DIR)/Cargo.toml
	cargo clean --manifest-path $(KDF_DIR)/Cargo.toml
	cargo clean --manifest-path $(C10V_DIR)/Cargo.toml
	cargo clean --manifest-path $(FWV_DIR)/Cargo.toml
	cargo clean --manifest-path $(NSP_DIR)/Cargo.toml
	cargo clean --manifest-path $(C10S_DIR)/Cargo.toml
