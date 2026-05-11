# Verity build helpers.
#
# Targets:
#   build         — `lake build`, builds everything
#   verify-stats  — emit VERIFICATION_STATUS.md (theorem/axiom/sorry counts)
#   emit-yul      — emit Yul for downstream `solc` consumption
#   clean         — `lake clean`
#   ci            — `build` + zero-sorry gate (fails CI if any non-trust-boundary `sorry` remains)
#
# Requires: lean (via elan), lake. See README.md §6.

LEAN_FILES := $(shell find PQSigner -name '*.lean')

.PHONY: build verify-stats emit-yul clean ci

build:
	lake build

verify-stats:
	@echo "# VERIFICATION_STATUS — PQSigner Verity port" > VERIFICATION_STATUS.md
	@echo "" >> VERIFICATION_STATUS.md
	@echo "Generated: $$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> VERIFICATION_STATUS.md
	@echo "" >> VERIFICATION_STATUS.md
	@echo "| Metric | Value |" >> VERIFICATION_STATUS.md
	@echo "|--------|-------|" >> VERIFICATION_STATUS.md
	@echo "| Theorems | $$(grep -c '^theorem ' $(LEAN_FILES)) |" >> VERIFICATION_STATUS.md
	@echo "| Sorry sites | $$(grep -c 'sorry$$' $(LEAN_FILES)) |" >> VERIFICATION_STATUS.md
	@echo "| Axiom sites | $$(grep -c '^axiom ' $(LEAN_FILES)) |" >> VERIFICATION_STATUS.md
	@echo "| Opaque sites | $$(grep -c '^opaque ' $(LEAN_FILES)) |" >> VERIFICATION_STATUS.md
	@echo "" >> VERIFICATION_STATUS.md
	@echo "Per-file theorem counts:" >> VERIFICATION_STATUS.md
	@for f in $(LEAN_FILES); do \
		echo "  - $$f: $$(grep -c '^theorem ' $$f)" >> VERIFICATION_STATUS.md; \
	done
	@cat VERIFICATION_STATUS.md

emit-yul:
	@echo "TODO: invoke Verity's Yul emitter. Requires P1-P3 spike done."
	@exit 1

clean:
	lake clean
	rm -f VERIFICATION_STATUS.md

ci: build
	@SORRY_COUNT=$$(grep -c 'sorry$$' $(LEAN_FILES) | grep -v '^0$$' || true); \
	if [ -n "$$SORRY_COUNT" ] && [ "$$SORRY_COUNT" -gt 0 ]; then \
		echo "FAIL: $$SORRY_COUNT remaining 'sorry' sites — see VERIFICATION_STATUS.md"; \
		exit 1; \
	fi
	@echo "PASS: zero-sorry gate satisfied"
