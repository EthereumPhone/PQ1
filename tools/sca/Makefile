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
SKDF_DIR := saes_kdf_target
SKDF_ELF := $(SKDF_DIR)/target/$(TARGET)/release/sca-saes-kdf-target
DONJON   ?= donjon-sca
SCARED   ?= scared-sca

.PHONY: build build-kdf build-c10v build-fw-verify build-ns-ptr build-c10-sign build-cap build-dispatch build-flashctr build-saes-kdf build-groth16 fi fi-twofault c10 pin c10v fw-verify ns-ptr c10-sign cap dispatch flashctr kdf saes-kdf wait-random-leak bip39-leak seed-deriv-leak recovery-leak seedwizard-exact-leak groth16 groth16-full f9-retest f9-deeper f9-scared-collect f9-scared sweeps doctor clean

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

GROTH16_DIR := groth16_target
GROTH16_ELF := $(GROTH16_DIR)/target/$(TARGET)/release/sca-groth16-target
build-groth16: $(GROTH16_ELF)
$(GROTH16_ELF): $(GROTH16_DIR)/src/main.rs $(GROTH16_DIR)/memory.x $(GROTH16_DIR)/build.rs $(GROTH16_DIR)/Cargo.toml ../../bls12_381_pka/src/lib.rs
	cargo build --release --target $(TARGET) --manifest-path $(GROTH16_DIR)/Cargo.toml

# Fault-injection sweep over the real Groth16 verifier. Targets the
# clear-sign feature (Aave / CowSwap / etc.) — a fault that flips a
# reject into an accept lets an attacker forge ZK clear-sign verifications.
#
# `make groth16`       — baseline validator + sparse skip-fault sweep
#                        (164 positions in [bad_total-5K, bad_total-900)
#                        at step 25). ~13 min total.
# `make groth16-full`  — full 30K-insn × 3-fault-model sweep. ~25-100h.
#                        Intended for overnight runs; tee stdout to a log.
groth16: build-groth16
	$(DONJON) run fault_sweep_groth16.py

groth16-full: build-groth16
	$(DONJON) run fault_sweep_groth16.py --full

build-saes-kdf: $(SKDF_ELF)

# Rebuilds when the production cmac.rs changes (it's `#[path]`-included).
$(SKDF_ELF): $(SKDF_DIR)/src/main.rs $(SKDF_DIR)/memory.x $(SKDF_DIR)/build.rs $(SKDF_DIR)/Cargo.toml ../../secure/src/cmac.rs
	cargo build --release --target $(TARGET) --manifest-path $(SKDF_DIR)/Cargo.toml

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

# SAES-CMAC wrapper leakage analysis (cmac_generic + kdf_cmac_counter_generic).
# Four TVLA modes: vary-key / vary-msg × cmac_generic / kdf wrapper. Software
# AES-256 stands in for the production SAES coprocessor (which rainbow/Unicorn
# cannot model). See `leakage_saes_kdf.py` for the production-interpretation.
saes-kdf: build-saes-kdf
	$(DONJON) run leakage_saes_kdf.py

# wait_random loop-count leakage: does fi::wait_random's body have any
# mem_address pattern that depends on the loop counter? Re-uses fi_target's
# new `sca_fi_wait_random_n(byte)` symbol.
wait-random-leak: build
	$(DONJON) run leakage_wait_random.py

# BIP-39 entropy → seed: does `Mnemonic::from_entropy(entropy).to_seed("")`
# leak entropy bits via WORDLIST[index] address-keyed loads?
bip39-leak: build-kdf
	$(DONJON) run leakage_bip39.py

# F-22 follow-up: audit the OTHER secret-bearing derivation paths
# (`slhdsa_seed_from_bip39`, `bootstrap_seed_from_bip39`,
# `slot_master_entropy_from_bip39`) for similar leaks.
seed-deriv-leak: build-kdf
	$(DONJON) run leakage_seed_derivation.py

# Recovery-path leakage: does bip39::lookup_prefix leak the typed
# mnemonic-word prefix via binary-search address dependence?
recovery-leak: build-kdf
	$(DONJON) run leakage_recovery.py

# F-27: does seed_wizard.rs::prefix_is_exact_word's *second* binary search
# (the one F-25 didn't reach — used inside the candidate-pick gate) leak
# the typed prefix? Same shape as F-25.
seedwizard-exact-leak: build-kdf
	$(DONJON) run leakage_seedwizard_exact.py

# F-9 re-test: did F-16's shuffle mask the FORS-leaf-index mem_address leak?
# Compares post-F-16 max|t| against F-9's recorded baseline of 40.71.
f9-retest: build-kdf
	$(DONJON) run f9_retest.py

# F-9 deeper sweep: tests F-16 on the SECRET-bearing region (FORS + WOTS sign)
# past grind_r. Uses stride=10 + 30 M samples to cover ~300 M mem events
# without OOM. Drops to 200 traces (vs F-9's 600) to stay in 64 GB RAM.
f9-deeper: build-kdf
	$(DONJON) run f9_deeper.py

# F-9 scared convergence — two stages:
#   (1) f9-scared-collect: runs in donjon-sca venv (lascar + rainbow),
#       captures 600 × 10M × stride=1 traces, dumps to out/f9_traces.npz
#       (≈ 4 GB on disk). Re-uses f9_retest.py's input generator.
#   (2) f9-scared:         runs in scared-sca venv (numpy 2 + scared 1.2),
#       loads the .npz, runs TTestAnalysis with convergence_step=20,
#       plots max|t| vs #traces, prints rank.
# Env overrides: F9_SCARED_N (default 600), F9_SCARED_MAX_SAMPLES (10M),
#   F9_SCARED_STRIDE (1), F9_SCARED_STEP (20).
f9-scared-collect: build-kdf
	$(DONJON) run f9_collect_for_scared.py

f9-scared:
	$(SCARED) run f9_scared_convergence.py

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
