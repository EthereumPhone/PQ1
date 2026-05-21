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
#   make verify-clean        — remove build artefacts.

LEAN_DIR := lean
LAKE     ?= $(shell command -v lake 2>/dev/null || echo $$HOME/.elan/bin/lake)

.PHONY: verify verify-build verify-audit verify-three-claims verify-clean

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

verify-clean:
	@cd $(LEAN_DIR) && rm -rf .lake build
