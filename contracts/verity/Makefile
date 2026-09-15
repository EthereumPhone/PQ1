# Verity build helpers.
#
# Targets:
#   build         — `lake build`, builds everything
#   verify-stats  — emit VERIFICATION_STATUS.md (theorem/axiom/sorry counts)
#   emit-yul      — emit Yul for downstream `solc` consumption
#   clean         — `lake clean`
#   ci            — `build` + sorry ratchet (fails if any file's sorry count
#                   exceeds its baseline — census 12 on 2026-08-20, issue #673)
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

# ── Sorry ratchet (issue #673) ─────────────────────────────────────────
# Baseline census 2026-08-20: 12 live sorries — PQSigner/Theorems.lean ×11,
# PQSigner/Verifier/Merkle.lean ×1 (yul_swap_selector_in_known_set;
# documented, non-essential). Do NOT add to these; discharging one only
# ever lowers a count — that is always allowed, bump the baseline down in
# the same commit.
#
# Why not `grep -c 'sorry$'`: over multiple files that yields one
# `path:count` line per file, so `[ "$SORRY_COUNT" -gt 0 ]` errored into
# PASS (12 live sorries once passed this gate); `sorry$` also misses
# trailing-comment sites (`:= sorry  -- note`, e.g. Theorems.lean:297),
# and a bare word-grep would count comment prose (Theorems.lean:9,16).
# Every raw sorry/admit mention counts, including comments and strings. Source
# prose uses other wording to avoid false positives. There are no comment
# allowances or lexical guesses. Per-file budgets include unbuilt Part A.
ci: build
	@/usr/bin/python3 -E -S ../verification/scripts/check_verity_holes.py
