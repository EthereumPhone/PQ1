# PQSmartWallet formal-verification project (Lean 4).
#
# Targets:
#   make verify              — build the Lean project and run the executable.
#   make verify-build        — just type-check the Lean project.
#   make verify-audit        — print the sorry count + every axiom each headline
#                              theorem transitively depends on.
#   make verify-three-claims — run the full end-to-end three-claim pipeline
#                              (Lean + Foundry + Halmos-if-installed +
#                               Certora-if-licensed).
#   make verify-exec-gate    — focused build + axiom dump for Claim 4
#                              (execution-gate non-bypass): TxFlow.lean +
#                              every_call_gated_by_verifier + corollary.
#   make verify-clean        — remove build artefacts.

LEAN_DIR := lean
LAKE     ?= $(shell command -v lake 2>/dev/null || echo $$HOME/.elan/bin/lake)

.PHONY: verify verify-build verify-audit verify-three-claims verify-exec-gate verify-clean

verify: verify-build
	@cd $(LEAN_DIR) && $(LAKE) exe verify-test-vectors

verify-build:
	@cd $(LEAN_DIR) && $(LAKE) build

verify-audit:
	@echo "=== Pending sorry tactics ==="
	@cd $(LEAN_DIR) && $(LAKE) env lean --run scripts/check_no_sorry.lean
	@echo ""
	@echo "=== Axiom dependency of headline theorems ==="
	@cd $(LEAN_DIR) && $(LAKE) env lean scripts/dump_axioms.lean || true

verify-three-claims:
	@bash scripts/verify-three-claims.sh

verify-exec-gate:
	@echo "=== Building TxFlow + Spec.Theorems (Claim 4 dep closure) ==="
	@cd $(LEAN_DIR) && $(LAKE) build SphincsCVerify.Wallet.TxFlow SphincsCVerify.Spec.Theorems
	@echo ""
	@echo "=== Axiom closure for Claim 4 theorems ==="
	@echo "Expected closure: { propext, Classical.choice, Quot.sound } (kernel-only)"
	@echo ""
	@cd $(LEAN_DIR) && $(LAKE) env lean scripts/dump_axioms_claim4.lean

verify-clean:
	@cd $(LEAN_DIR) && rm -rf .lake build
