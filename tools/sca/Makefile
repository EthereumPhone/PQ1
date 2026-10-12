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
#   make scp03-fi     build + run the FI sweep over the SE050 SCP03 R-MAC verify gate (forged-response bypass)
#   make scp03-leakage build + run the TVLA leakage analysis on the SCP03 R-ENC decrypt + R-MAC CMAC
#   make rng-strong   build + run the FI sweep over rng_strong.rs's strict fail-closed multi-source fold
#   make optiga-lock  build + run the FI sweep over the OPTIGA verify_and_lock LcsO-ratchet read-back gate
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
SCP03_DIR := scp03_target
SCP03_ELF := $(SCP03_DIR)/target/$(TARGET)/release/sca-scp03-target
RS_DIR   := rng_strong_target
RS_ELF   := $(RS_DIR)/target/$(TARGET)/release/sca-rng-strong-target
OPTL_DIR := optiga_lock_target
OPTL_ELF := $(OPTL_DIR)/target/$(TARGET)/release/sca-optiga-lock-target
DONJON   ?= donjon-sca
SCARED   ?= scared-sca

.PHONY: build build-kdf build-c10v build-fw-verify build-ns-ptr build-c10-sign build-cap build-dispatch build-flashctr build-saes-kdf build-scp03 build-rng-strong build-optiga-lock fi fi-twofault c10 pin c10v fw-verify ns-ptr c10-sign cap dispatch flashctr kdf saes-kdf scp03-fi scp03-leakage rng-strong optiga-lock wait-random-leak bip39-leak seed-deriv-leak recovery-leak seedwizard-exact-leak glyph-leak f9-retest f9-deeper f9-scared-collect f9-scared sweeps doctor clean

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

.PHONY: c10-sign-cargo-check
c10-sign-cargo-check:

$(C10S_ELF): c10-sign-cargo-check
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

build-saes-kdf: $(SKDF_ELF)

# Rebuilds when the production cmac.rs changes (it's `#[path]`-included).
$(SKDF_ELF): $(SKDF_DIR)/src/main.rs $(SKDF_DIR)/memory.x $(SKDF_DIR)/build.rs $(SKDF_DIR)/Cargo.toml ../../secure/src/cmac.rs
	cargo build --release --target $(TARGET) --manifest-path $(SKDF_DIR)/Cargo.toml

build-scp03: $(SCP03_ELF)

# Rebuilds when the production scp03_logic.rs changes (it's `#[path]`-included;
# the unwrap_response wrapper is a kept-in-sync copy of se050/scp03.rs).
$(SCP03_ELF): $(SCP03_DIR)/src/main.rs $(SCP03_DIR)/memory.x $(SCP03_DIR)/build.rs $(SCP03_DIR)/Cargo.toml ../../secure/src/scp03_logic.rs
	cargo build --release --target $(TARGET) --manifest-path $(SCP03_DIR)/Cargo.toml

build-rng-strong: $(RS_ELF)

# Rebuilds when the production rng_strong.rs changes (it's `#[path]`-included).
$(RS_ELF): $(RS_DIR)/src/main.rs $(RS_DIR)/memory.x $(RS_DIR)/build.rs $(RS_DIR)/Cargo.toml ../../secure/src/rng_strong.rs
	cargo build --release --target $(TARGET) --manifest-path $(RS_DIR)/Cargo.toml

build-optiga-lock: $(OPTL_ELF)

# The pure metadata parser/comparator is copied verbatim into the target;
# list the source so a change signals a human to re-sync (it won't auto-update).
$(OPTL_ELF): $(OPTL_DIR)/src/main.rs $(OPTL_DIR)/memory.x $(OPTL_DIR)/build.rs $(OPTL_DIR)/Cargo.toml ../../secure/src/optiga/apdu.rs ../../secure/src/optiga/mod.rs
	cargo build --release --target $(TARGET) --manifest-path $(OPTL_DIR)/Cargo.toml

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
	python3 test_c10_sign_sweep.py
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

# SE050 SCP03 response-unwrap (R-MAC verify gate + R-ENC AES-128-CBC decrypt)
# — work-todo §18b RANK 1. Wraps the real secure/src/scp03_logic.rs primitives.
#
# scp03-fi       single-fault sweep over the R-MAC verify gate: can a fault make
#                unwrap_response accept a FORGED response (wrong R-MAC) and release
#                an attacker-chosen half_E? Exhaustive by default (~tens of k
#                positions × 3 models); SCP03_STRIDE=N for a quick smoke run.
# scp03-leakage  TVLA on aes128_cbc_decrypt + cmac_aes128 (vary key / half_E /
#                msg) — expects flat on mem_address (bitsliced AES, no T-tables).
#                Builds kdf_target too for the leaky-S-box positive control.
scp03-fi: build-scp03
	$(DONJON) run fault_sweep_scp03.py

scp03-leakage: build-scp03 build-kdf
	$(DONJON) run leakage_scp03.py

# rng_strong.rs strict fail-closed (bb2615f6): single-fault sweep confirming a
# faulted/forced "SE-TRNG-OK" can't let a weakened/all-zero XOR-fold through.
# work-todo §18b RANK 2. Audit-only (exits 0; reports the F-2/F-4 residual class).
rng-strong: build-rng-strong
	$(DONJON) run fault_sweep_rng_strong.py

# OPTIGA verify_and_lock LcsO-ratchet read-back gate (S-1/S-2/S-3 provisioning
# hardening): single-fault check that the irreversible lock can't fire on a chip
# whose AC readback didn't match the intent. work-todo §18b RANK 3 (lowest
# priority). Audit-only (exits 0): provisioning-time, run-once, trusted-factory.
optiga-lock: build-optiga-lock
	$(DONJON) run fault_sweep_optiga_lock.py

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

# F-24: does the trusted-display secret glyph-render path (secret_text.rs
# ct_glyph_col 96-entry scan + the branchless lcd.rs::blit_glyph expansion)
# leak the rendered secret character via mem_address? Regression sentinel:
# the pre-CT DIRECT FONT[(ch-0x20)][col] fetch (EXPECTED to leak) vs the
# constant-time scan (EXPECTED flat).
glyph-leak: build-kdf
	$(DONJON) run leakage_glyph.py

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
	cargo clean --manifest-path $(SCP03_DIR)/Cargo.toml
	cargo clean --manifest-path $(RS_DIR)/Cargo.toml
	cargo clean --manifest-path $(OPTL_DIR)/Cargo.toml
