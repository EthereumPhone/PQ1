# Part B is pure Lean. Part A remains an unbuildable, source-pinned scaffold.
.PHONY: build verify-stats verify-verity-census test-census emit-yul clean ci

build:
	lake build

# Authoritative, fresh eight-module build + semantic census + Part A quarantine.
# Does not read Lake caches or download/build the unused Verity dependency.
verify-verity-census:
	@/usr/bin/python3 -E -S ../verification/scripts/check_verity_inventory.py

verify-stats: verify-verity-census

test-census:
	@/usr/bin/python3 -E -S ../verification/scripts/test_axiom_inventory.py
	@/usr/bin/python3 -E -S ../verification/scripts/test_verity_inventory.py

emit-yul:
	@echo "TODO: invoke Verity's Yul emitter. Requires P1-P3 spike done."
	@exit 1

clean:
	lake clean
	rm -f VERIFICATION_STATUS.md

ci: verify-verity-census test-census
