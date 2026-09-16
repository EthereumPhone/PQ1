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

# Fail pipelines on the first failing stage, not just the last (finding P4).
# The `extract-*` gates run `charon ... 2>&1 | tail -1`; without pipefail the
# pipeline's exit status is `tail`'s (always 0), so a Charon failure was masked
# and the recipe proceeded to run Aeneas on the STALE .llbc — regenerating the
# previously-committed Lean, matching the diff, and printing "OK" while the Rust
# had actually drifted. With pipefail the failing Charon exit propagates and
# make aborts the recipe before the stale .llbc is consumed. (Also un-masks the
# `lake env lean ... | tee` axiom-check gates below.) bash is required because
# POSIX sh does not guarantee `pipefail`.
SHELL        := /usr/bin/bash
.SHELLFLAGS  := -o pipefail -c

# Preserve the pre-override origins so security-sensitive targets can reject a
# caller that tried to replace the recipe interpreter or its execution flags.
# Capture Bash startup-option hooks before removing them from every recipe
# environment, then hard-bind every recipe to the reviewed Bash + pipefail
# configuration.  The replay uses one reviewed GNU Make binary rather than the
# caller-derived MAKE/MAKE_COMMAND values (including a forged argv[0]).
override _FV_RECIPE_SHELL_ORIGIN := $(origin SHELL)
override _FV_RECIPE_SHELLFLAGS_ORIGIN := $(origin .SHELLFLAGS)
override _FV_INHERITED_SHELLOPTS := $(value SHELLOPTS)
override _FV_INHERITED_BASHOPTS := $(value BASHOPTS)
override _FV_INHERITED_BASH_ENV := $(value BASH_ENV)
override _FV_INHERITED_ENV := $(value ENV)
override _FV_INHERITED_MAKEFILES := $(value MAKEFILES)
override _FV_MAKEFILE_LIST_AT_ENTRY := $(value MAKEFILE_LIST)
override _FV_MAKEFLAGS_ORIGIN := $(origin MAKEFLAGS)
override _FV_MAKE_SHORT_FLAGS := $(if $(filter -%,$(firstword $(MAKEFLAGS))),,$(firstword $(MAKEFLAGS)))
override _FV_MAKE_EVAL_FLAGS := $(value -*-eval-flags-*-)
override _FV_LAKE_ORIGIN := $(origin LAKE)
override _FV_PQLEAN_ORIGIN := $(origin PQLEAN)
override _FV_EXTRACTED_DIR_ORIGIN := $(origin EXTRACTED_DIR)
override _FV_REPO_ROOT_ORIGIN := $(origin REPO_ROOT)
override _FV_LEAN_DIR_ORIGIN := $(origin LEAN_DIR)
unexport SHELLOPTS BASHOPTS BASH_ENV ENV MAKEFILES
override SHELL := /usr/bin/bash
override .SHELLFLAGS := -o pipefail -c
override _FV_GNU_MAKE := /usr/bin/make

# This verification Makefile has no legitimate startup/include or --eval
# extension surface.  Reject those parser-level code-injection channels before
# any recipe can inherit `.IGNORE`, replace a target, or preseed an internal
# receipt variable.  MAKEFILES is captured before being unexported so the fixed
# recursive Make invocations start clean as well.
ifneq ($(strip $(_FV_INHERITED_MAKEFILES)),)
$(error refusing inherited MAKEFILES startup files for verification Makefile)
endif
ifneq ($(strip $(_FV_INHERITED_SHELLOPTS)),)
$(error refusing inherited SHELLOPTS for verification Makefile)
endif
ifneq ($(strip $(_FV_INHERITED_BASHOPTS)),)
$(error refusing inherited BASHOPTS for verification Makefile)
endif
ifneq ($(strip $(_FV_INHERITED_BASH_ENV)),)
$(error refusing inherited BASH_ENV for verification Makefile)
endif
ifneq ($(strip $(_FV_INHERITED_ENV)),)
$(error refusing inherited ENV for verification Makefile)
endif
# Exported Bash functions are an interpreter-startup code-injection channel
# into every recipe shell: SHELL is /usr/bin/bash, which imports BASH_FUNC_*
# variables from the environment, and `$(shell command -v …)` resolves to an
# exported function too.  A caller-exported no-op `lake`/`python3` function
# made evidence gates exit 0 while producing no evidence (reproduced by all
# three 2026-07-25 reviewers).  GNU Make imports every environment variable,
# so detect them purely: any environment-origin BASH_FUNC_* variable rejects
# the parse before `command -v` or any recipe can inherit it.  The same
# startup-hook class for the evidence interpreter — PYTHONPATH/PYTHONHOME/
# PYTHONSTARTUP/PYTHONINSPECT steer python3 startup/module resolution — is
# rejected alongside (recipes additionally invoke the interpreter with -E -S).
override _FV_INHERITED_BASH_FUNCS := $(foreach v,$(.VARIABLES),$(if $(filter environment,$(origin $v)),$(filter BASH_FUNC_%,$v)))
ifneq ($(strip $(_FV_INHERITED_BASH_FUNCS)),)
$(error refusing inherited exported Bash functions ($(strip $(_FV_INHERITED_BASH_FUNCS))) for verification Makefile)
endif
ifneq ($(filter environment environment override command line,$(origin PYTHONPATH)),)
$(error refusing caller-set PYTHONPATH for verification Makefile)
endif
ifneq ($(filter environment environment override command line,$(origin PYTHONHOME)),)
$(error refusing caller-set PYTHONHOME for verification Makefile)
endif
ifneq ($(filter environment environment override command line,$(origin PYTHONSTARTUP)),)
$(error refusing caller-set PYTHONSTARTUP for verification Makefile)
endif
ifneq ($(filter environment environment override command line,$(origin PYTHONINSPECT)),)
$(error refusing caller-set PYTHONINSPECT for verification Makefile)
endif
unexport PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONINSPECT
# The dynamic-loader members of the same startup-injection class map a
# caller-chosen library into EVERY pinned trust-root binary (make, pwd,
# stat, python3, bash) before any guard runs — strictly stronger than the
# exported-Bash-function channel and a direct defeat of the pinned
# binaries' own behavior (wave-7 Opus 5 BLOCKER, coordinator-verified:
# `LD_PRELOAD=/nonexistent.so /usr/bin/python3 -I …` reaches the loader
# regardless of Python-level isolation).  Reject and scrub them at parse
# time alongside the interpreter hooks.
ifneq ($(filter environment environment override command line,$(origin LD_PRELOAD)),)
$(error refusing caller-set LD_PRELOAD for verification Makefile)
endif
ifneq ($(filter environment environment override command line,$(origin LD_AUDIT)),)
$(error refusing caller-set LD_AUDIT for verification Makefile)
endif
ifneq ($(filter environment environment override command line,$(origin LD_LIBRARY_PATH)),)
$(error refusing caller-set LD_LIBRARY_PATH for verification Makefile)
endif
unexport LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH
# GNU Make appends each parsed makefile to MAKEFILE_LIST itself (origin
# `file`).  An `override MAKEFILE_LIST := ...` in an earlier `-f` file (origin
# `override`) or a command-line `MAKEFILE_LIST=...` assignment (origin
# `command line`) outranks that append and freezes the list: the word-count
# check below then sees one word while the caller fully controls every
# MAKEFILE_LIST-derived fact.  Reject a noncanonical origin before the value
# is trusted.  An environment-seeded MAKEFILE_LIST self-heals to origin `file`
# with the correct value on the first internal append, so documented
# invocations (`make`, `make -C contracts/verification <target>`) are
# unaffected.
ifneq ($(origin MAKEFILE_LIST),file)
$(error refusing caller-mutated MAKEFILE_LIST (origin $(origin MAKEFILE_LIST)) for verification Makefile)
endif
ifneq ($(words $(_FV_MAKEFILE_LIST_AT_ENTRY)),1)
$(error refusing additional parsed makefiles: $(_FV_MAKEFILE_LIST_AT_ENTRY))
endif
# Every evidence path below (the argv-guard checker, the extracted Lean
# project, the closure manifests, the extraction regen counterpart) is
# repository-relative, so the trusted directory is this Make process's
# PHYSICAL working directory.  A foreign cwd — `cd /attacker && make -f
# /reviewed/Makefile [-f evil.mk]` — would let a planted
# scripts/check_make_argv.py print `ok` for the guard and put attacker files
# behind every relative recipe path.  MAKEFILE_LIST has passed the origin and
# word-count guards, so its sole entry is this file.  Resolving only the
# entry's DIRECTORY is not enough: a symlink named `Makefile` planted in the
# attacker cwd makes the entry's spelling `./Makefile`, whose directory's
# realpath is the attacker cwd itself, so a dir-only comparison passes while
# every relative recipe path rebinds to the foreign tree (reproduced by all
# three 2026-07-25 reviewers).  Resolve the makefile FILE first (following
# the symlink to the real file), then require the physical cwd to be that
# file's physical directory (satisfied by `make`, `make -f Makefile`, and
# `make -C <dir>`; a symlinked invocation dir still resolves consistently).
override _FV_PHYSICAL_CWD := $(shell /usr/bin/pwd -P)
ifneq ($(_FV_PHYSICAL_CWD),$(realpath $(dir $(realpath $(_FV_MAKEFILE_LIST_AT_ENTRY)))))
$(error refusing foreign working directory ($(_FV_PHYSICAL_CWD)) for verification Makefile; run from the Makefile directory or via make -C)
endif
# `realpath` resolves symlinks, not hard links: a hard-linked copy of this
# file planted in an attacker directory satisfies the comparison above (the
# "resolved" file's directory IS the attacker cwd) while every relative
# evidence path — the argv checker, scripts/*.py, lean/, the manifests —
# rebinds to that tree (wave-1 Opus 5 MEDIUM, same rebinding class as the
# symlink case).  Reject a multiply-linked makefile.  A hard-linking checkout
# mechanism (e.g. `cp -al` workspaces) is NOT a supported invocation for the
# evidence gates; use a real checkout (git checkouts/worktrees and plain
# copies carry link count 1).
# The link-count stat below and the argv-guard checker path further down
# shell-interpolate the resolved makefile path.  Inside single quotes the
# ONLY breakout character is a single quote — a metacharacter path component
# such as `x'>/dev/null;echo${IFS}1;#` makes the stat return `1` without
# ever statting the file (wave-2 SOL HIGH, coordinator-reproduced) — so
# reject that path class outright instead of trying to quote around it.
ifneq ($(findstring ',$(realpath $(_FV_MAKEFILE_LIST_AT_ENTRY))),)
$(error refusing verification Makefile path containing a single quote)
endif
ifneq ($(shell /usr/bin/stat -c %h '$(realpath $(_FV_MAKEFILE_LIST_AT_ENTRY))'),1)
$(error refusing multiply-linked verification Makefile (hard-link count is not 1))
endif
# The toolchain and evidence roots are assigned below with `override`, but a
# caller preseeding one (command line, environment, or an earlier makefile)
# must be rejected loudly rather than silently overridden: PQLEAN is the
# charon/aeneas toolchain path, EXTRACTED_DIR roots the diff counterpart and
# the closure manifests, REPO_ROOT roots the Rust sources being replayed, and
# LEAN_DIR roots the ledger's live axiom dump.
ifneq ($(_FV_PQLEAN_ORIGIN),undefined)
$(error refusing caller-overridden PQLEAN (origin $(_FV_PQLEAN_ORIGIN)) for verification Makefile)
endif
ifneq ($(_FV_EXTRACTED_DIR_ORIGIN),undefined)
$(error refusing caller-overridden EXTRACTED_DIR (origin $(_FV_EXTRACTED_DIR_ORIGIN)) for verification Makefile)
endif
ifneq ($(_FV_REPO_ROOT_ORIGIN),undefined)
$(error refusing caller-overridden REPO_ROOT (origin $(_FV_REPO_ROOT_ORIGIN)) for verification Makefile)
endif
ifneq ($(_FV_LEAN_DIR_ORIGIN),undefined)
$(error refusing caller-overridden LEAN_DIR (origin $(_FV_LEAN_DIR_ORIGIN)) for verification Makefile)
endif
ifneq ($(strip $(_FV_MAKE_EVAL_FLAGS)),)
$(error refusing Make --eval for verification Makefile)
endif
ifneq ($(findstring i,$(_FV_MAKE_SHORT_FLAGS)),)
$(error refusing Make ignore-errors mode for verification Makefile)
endif
ifneq ($(findstring t,$(_FV_MAKE_SHORT_FLAGS)),)
$(error refusing Make touch mode for verification Makefile)
endif
# Recipe-suppression / no-execute modes are the same fail-open class as -i/-t:
# `make -n <evidence-target>` prints the recipes and exits 0 without producing
# evidence, `-q` only reports status, and `-o`/`-W` mark targets assumed
# old/new.  GNU Make normalizes every no-argument spelling (including
# unambiguous long-option prefixes like --jus) into the first-word short-flag
# bundle, and environment-injected MAKEFLAGS land there too (their origin
# stays `file`, so the origin guard below cannot see them — scan the VALUE
# unconditionally).  The argument-taking forms (-o/--assume-old, -W) are
# consumed before MAKEFLAGS is reconstructed and never appear here; those are
# rejected by the argv/environ guard below.  `w` (print-directory, implied by
# -C) is not a suppression flag and stays accepted.
ifneq ($(findstring n,$(_FV_MAKE_SHORT_FLAGS))$(findstring o,$(_FV_MAKE_SHORT_FLAGS))$(findstring q,$(_FV_MAKE_SHORT_FLAGS))$(findstring W,$(_FV_MAKE_SHORT_FLAGS)),)
$(error refusing Make no-execute/assume mode (dry-run/question/assume-old/what-if) for verification Makefile)
endif
# Defense in depth for long-option spellings if a Make version ever keeps
# them verbatim in MAKEFLAGS instead of normalizing into the bundle.
override _FV_MAKEFLAGS_BAD_LONG := $(filter --just-print% --dry-run% --recon% --question% --touch% --ignore-errors% --old-file% --assume-old% --new-file% --assume-new% --what-if%,$(MAKEFLAGS))
ifneq ($(strip $(_FV_MAKEFLAGS_BAD_LONG)),)
$(error refusing Make no-execute/assume long option ($(_FV_MAKEFLAGS_BAD_LONG)) for verification Makefile)
endif
ifneq ($(_FV_MAKEFLAGS_ORIGIN),file)
$(error refusing caller-overridden MAKEFLAGS (origin $(_FV_MAKEFLAGS_ORIGIN)) for verification Makefile)
endif
# GNU Make >= 4.4 additionally decodes GNUMAKEFLAGS into switches — on that
# documented bare-`make` path (e.g. nix-profile make 4.4.1) an environment
# `GNUMAKEFLAGS='o <target>'` retires an evidence target with exit 0 and no
# recipe execution, invisible to the in-Make MAKEFLAGS value (wave-5 Opus 5
# BLOCKER, coordinator-reproduced on both make binaries here).  The
# argv/environ checker below therefore scans BOTH flag variables; a
# command-line GNUMAKEFLAGS assignment is rejected symmetrically here.
ifneq ($(filter command line,$(origin GNUMAKEFLAGS)),)
$(error refusing caller-overridden GNUMAKEFLAGS (origin $(origin GNUMAKEFLAGS)) for verification Makefile)
endif
ifneq ($(_FV_LAKE_ORIGIN),undefined)
$(error refusing caller-overridden LAKE (origin $(_FV_LAKE_ORIGIN)) for verification Makefile)
endif

override LEAN_DIR := lean
# The Lean toolchain path is part of the evidence trust root and must NOT
# resolve through caller-mutable state.  `command -v lake` accepts any
# absolute existing file, so a PATH-planted no-op `lake` exited 0 in place of
# the kernel gate (wave-1 Opus 5 HIGH, coordinator-reproduced); HOME is
# equally caller-mutable (`HOME=/tmp/evil make …` rebinds a $HOME-derived
# fallback).  Pin LAKE to the elan shim under the password-database home
# (derived through the pinned interpreter) and require it to exist, so the
# resolution fails closed at parse time.
override _FV_USER_HOME := $(shell /usr/bin/python3 -I -c 'import os,pwd;print(pwd.getpwuid(os.getuid()).pw_dir)')
override LAKE := $(_FV_USER_HOME)/.elan/bin/lake
ifeq ($(wildcard $(LAKE)),)
$(error LAKE not found at $(LAKE); install the elan Lean 4 toolchain for verification Makefile)
endif
# Pinning the shim's PATH is not enough: the elan dispatcher re-roots its
# toolchain resolution from caller-mutable ELAN_HOME (and falls back to
# HOME) at exec time, so a planted $ELAN_HOME/toolchains/<name>/bin/lake
# still answered the kernel gate with a forged stub (wave-3 Opus 5 + Kimi
# K3 HIGH, coordinator-reproduced).  Force both variables to the
# password-database home for every recipe, and reject an explicit
# toolchain-selection override — each project pins its toolchain via its
# own lean-toolchain file, so a caller-set ELAN_TOOLCHAIN can only be a
# selection attack on the pinned evidence toolchain.
override ELAN_HOME := $(_FV_USER_HOME)/.elan
override HOME := $(_FV_USER_HOME)
export ELAN_HOME HOME
ifneq ($(filter environment environment override command line,$(origin ELAN_TOOLCHAIN)),)
$(error refusing caller-set ELAN_TOOLCHAIN for verification Makefile)
endif
unexport ELAN_TOOLCHAIN
# Pin the evidence interpreter.  A bare `python3` re-resolves through the
# caller's PATH on every recipe line (and, before the BASH_FUNC_* rejection
# above, through exported Bash functions); `-E -S` additionally isolates it
# from PYTHONPATH/PYTHONHOME/PYTHONSTARTUP interpreter-startup injection and
# from sitecustomize/usercustomize/.pth hooks, while still allowing the
# checker scripts' sibling imports (plain `-I` would strip the script's own
# directory from sys.path).  The argv guard below already hard-requires this
# exact binary.
ifeq ($(wildcard /usr/bin/python3),)
$(error /usr/bin/python3 is required as the pinned verification interpreter)
endif
override _FV_PYTHON3 := /usr/bin/python3 -E -S

# `make` / `make help` lists every runnable target that carries a `## ` blurb
# (the self-documenting convention — it can't drift from reality the way a
# hand-maintained list does). Add `## one-liner` to a target's rule line to
# surface it here.
.DEFAULT_GOAL := help
.PHONY: help
help: ## Show the runnable FV targets (those with a description)
	@grep -hE '^[a-zA-Z0-9_.-]+:.*## ' $(MAKEFILE_LIST) | sort | awk -F':.*## ' '!seen[$$1]++ {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'

override _FV_EVIDENCE_TARGETS := \
	verify verify-storage-mutators verify-lean-proto-domain verify-fv-lints \
	verify-ledger-consistency verify-hw-assumptions verify-tla verify-linker-map \
	verify-verus verify-crux-ns-ptr verify-easycrypt verify-easycrypt-full \
	verify-easycrypt-pins verify-easycrypt-split-pins verify-easycrypt-split verify-easycrypt-docker verify-forsc-margin \
	verify-proof-mutation verify-lean4checker verify-kontrol verify-halmos \
	verify-bulk verify-interp verify-transcription verify-parse-transcription \
	verify-independent-signer verify-primitive-kat verify-cavp verify-build \
	verify-audit verify-three-claims verify-exec-gate verify-bytecode-setup \
	verify-bytecode verify-clean verify-extraction-freshness \
	verify-extraction-regen verify-extraction-regen-self-test \
	verify-extract-differential verify-extracted verify-extracted-heavy \
	verify-spec-vendored-fidelity verify-rollback-freeze-pin
# This is also the exact parser-guard inventory below.  Its self-test compares
# it bidirectionally with every concrete `verify*:` definition in this file.
.PHONY: $(_FV_EVIDENCE_TARGETS)

# NOTE: verify-build (the `lake build` this bundle depends on) now also
# kernel-checks the A3.1 in-kernel parse theorem + elision bridge (the root
# module imports Interpreter/{YulParse,C10Source,C10Parse}); the byte-pin
# below keeps the embedded c10Source literal honest against the .sol.
verify: verify-build ## Default FV bundle: build + transcription + KAT + mutant-corpus
	@$(_FV_PYTHON3) scripts/check_c10_transcription.py
	@$(_FV_PYTHON3) scripts/check_c10_transcription_ast.py
	@$(_FV_PYTHON3) scripts/test_c10_transcription_ast_negative.py
	@$(_FV_PYTHON3) scripts/check_c10_source_pin.py
	@$(_FV_PYTHON3) scripts/check_lean_proto_domain.py
	@cd $(LEAN_DIR) && $(LAKE) exe verify-test-vectors
	@cd $(LEAN_DIR) && $(LAKE) exe verify-mutant-corpus

# I-3 closed-world gate: `no_reset_path` (Wallet/Invariants.lean) proves the
# KNOWN Storage counter-mutators are non-decreasing, but "these are the ONLY
# mutators" is an out-of-Lean assertion. This lint extracts every
# Storage-returning / `{ s with }`-updating def in Wallet/Storage.lean and
# FAILS if the set drifts from the pinned allow-list — so adding a new mutator
# forces a conscious allow-list update + a matching no-decrease lemma. Pure
# source lint (no lake build); positive=current tree PASS, negative=fake
# resetter FAIL. See scripts/check_storage_mutators.sh.
verify-storage-mutators: ## I-3 closed-world Storage-mutator allowlist gate
	@/usr/bin/bash scripts/check_storage_mutators.sh

# P7 source lint (no lake build): the Lean factory add-slot domain tag must be
# byte-identical to proto::FACTORY_ADD_SLOT_DOMAIN, so the squat-defence proof
# (invariant #6) stays bound to the digest the device actually signs. Closes
# the "Lean-only domain drift undetected by the bytecode harnesses" residual.
verify-lean-proto-domain: ## Lean factory domain tag == proto (P7)
	@$(_FV_PYTHON3) scripts/check_lean_proto_domain.py

# FV-invariant escape-hatch gate: fails CI on the audit anti-patterns over the
# lean/ + extracted/ Lean SOURCE (comment-stripped). Four sub-lints:
#   (a) no proof-path escape hatches (native_decide / decide +native / @[csimp]
#       / @[implemented_by] / @[extern] / unsafe / partial / reduceBool);
#   (b) BreaksHash firewall (no `¬ BreaksHash` / `BreaksHash → False`);
#   (c) Gap-3 + theft_free axiom-closure tripwire (dump_axioms.lean must show
#       keccak_sha256_cross_separation in the offchain closure + the expected
#       A1/A2/A3.1/A4/A5 + kernel premises in theft_free's closure);
#   (d) opaque-guard (`trivial` must NOT inhabit Bridge.evmDeliversCall default
#       — catches an opaque→def A4 regression that #print-axioms misses).
# Sub-lints (c)/(d) read the built oleans, so this depends on verify-build.
# See scripts/lint_fv_invariants.sh (positive=clean tree PASS; negative trips
# documented in the script header).
verify-fv-lints: verify-build ## FV anti-vacuity sub-lints (escape-hatch/closures/opaque-guard)
	@/usr/bin/bash scripts/lint_fv_invariants.sh
	@$(_FV_PYTHON3) scripts/test_axiom_inventory.py
	@evilbin=$$(mktemp -d /tmp/pq-fvlint-planted-python3.XXXXXX); \
	sentinel=$$(mktemp -u /tmp/pq-fvlint-planted-sentinel.XXXXXX); \
	printf '#!/bin/sh\ntouch "%s"\nexit 0\n' "$$sentinel" >$$evilbin/python3; \
	chmod +x $$evilbin/python3; \
	out=$$(mktemp /tmp/pq-fvlint-planted-out.XXXXXX); \
	PATH="$$evilbin:/usr/bin:/bin" /usr/bin/bash scripts/lint_fv_invariants.sh >$$out 2>&1; \
	rc=$$?; \
	if [ $$rc -ne 0 ]; then \
	  echo "CONTROL FAILURE: verify-fv-lints failed under a planted-PATH python3" >&2; \
	  sed -n '1,60p' $$out >&2; rm -rf $$out $$evilbin $$sentinel; exit 1; \
	elif [ -e "$$sentinel" ]; then \
	  echo "CONTROL FAILURE: the lint comment-stripper resolved python3 through the caller PATH" >&2; \
	  sed -n '1,60p' $$out >&2; rm -rf $$out $$evilbin $$sentinel; exit 1; \
	elif ! grep -Fq 'lint_fv] PASS — all five FV-invariant sub-lints green' $$out; then \
	  echo "CONTROL FAILURE: verify-fv-lints did not complete its real sub-lints" >&2; \
	  sed -n '1,60p' $$out >&2; rm -rf $$out $$evilbin $$sentinel; exit 1; \
	fi; \
	rm -rf $$out $$evilbin $$sentinel; \
	echo "  ok: the lint comment-stripper ignores a PATH-planted python3"

# LEDGER-CONSISTENCY gate (anti-vacuity class V5: "advertised != actual"). Makes
# the human-facing assurance ledger (docs/AXIOM_STATUS.json) FALSIFIABLE against
# the live Lean truth: cross-checks the advertised `closures` (exact-set, per
# theorem), the headline `signature_pins` (statement-shape — catches a
# re-introduced raw hypothesis like the EF P1/hInv finding, invisible to closure
# checks), the per-status summary COUNTS, the no-undocumented / no-phantom axiom
# invariants, status hygiene, and C9 ENFORCED non-vacuity-witness coverage (the
# `witness_coverage` block: every headline hypothesis has a kernel-only witness
# lemma present in the dump — closes the playbook §B gap #3) — against
# `dump_axioms.lean` + the Lean source +
# the lint_fv THEFT_EXPECTED pin (single authoritative source). Reads the built
# oleans (runs the dump), so depends on verify-build. Ships its own WIRED-IN
# NEGATIVE CONTROL: `python3 scripts/check_ledger_consistency.py --self-test`
# corrupts each check's input and asserts it fires (proves the gate is not vacuous).
# CAVEAT: the live source is `#print axioms`, which under-reports in lean v4.22.0;
# verify-lean4checker is NOT the completeness backstop (corrected 2026-08-11:
# same-kernel replay, blind to the #8840 omission shape). See the script header and
# docs/verification/fv-adversarial-review-playbook.md §B.
# This is the implementation target.  An authoritative local/CI receipt MUST
# enter through scripts/run_authoritative_make.sh using the documented setuid
# sudo -> same-UID `env -i` boundary.  A direct hostile environment can make
# the dynamic loader suppress /usr/bin/make before any in-Make guard executes.
verify-ledger-consistency: verify-build ## AXIOM_STATUS.json falsifiable vs live dump (closures/pins/witnesses)
	@$(_FV_PYTHON3) scripts/check_ledger_consistency.py --self-test
	@evilbin=$$(mktemp -d /tmp/pq-ledger-planted-lake.XXXXXX); \
	printf '#!/bin/sh\necho FORGED-DUMP\n' >$$evilbin/lake; \
	chmod +x $$evilbin/lake; \
	out=$$(mktemp /tmp/pq-ledger-planted-lake-out.XXXXXX); \
	if ! PATH="$$evilbin:/usr/bin:/bin" $(_FV_PYTHON3) scripts/check_ledger_consistency.py >$$out 2>&1; then \
	  echo "CONTROL FAILURE: ledger gate did not run under a planted-PATH lake" >&2; \
	  sed -n '1,60p' $$out >&2; rm -rf $$out $$evilbin; exit 1; \
	elif grep -Fq 'FORGED-DUMP' $$out; then \
	  echo "CONTROL FAILURE: the live axiom dump resolved lake through the caller PATH" >&2; \
	  sed -n '1,60p' $$out >&2; rm -rf $$out $$evilbin; exit 1; \
	elif ! grep -Fq 'OK: every advertised closure' $$out; then \
	  echo "CONTROL FAILURE: ledger gate did not complete its real checks" >&2; \
	  sed -n '1,60p' $$out >&2; rm -rf $$out $$evilbin; exit 1; \
	fi; \
	rm -rf $$out $$evilbin; \
	echo "  ok: the live axiom dump ignores a PATH-planted lake"
	@evilroot=$$(mktemp -d /tmp/pq-ledger-planted-elan.XXXXXX); \
	tc=leanprover--lean4---v4.22.0; \
	mkdir -p $$evilroot/toolchains/$$tc/bin; \
	printf '#!/bin/sh\necho FORGED-ELAN-DUMP\n' >$$evilroot/toolchains/$$tc/bin/lake; \
	chmod +x $$evilroot/toolchains/$$tc/bin/lake; \
	out=$$(mktemp /tmp/pq-ledger-planted-elan-out.XXXXXX); \
	if ! ELAN_HOME=$$evilroot HOME=$$evilroot $(_FV_PYTHON3) scripts/check_ledger_consistency.py >$$out 2>&1; then \
	  echo "CONTROL FAILURE: ledger gate did not run under a planted ELAN_HOME toolchain" >&2; \
	  sed -n '1,60p' $$out >&2; rm -rf $$out $$evilroot; exit 1; \
	elif grep -Fq 'FORGED-ELAN-DUMP' $$out; then \
	  echo "CONTROL FAILURE: the live axiom dump re-rooted through caller ELAN_HOME" >&2; \
	  sed -n '1,60p' $$out >&2; rm -rf $$out $$evilroot; exit 1; \
	elif ! grep -Fq 'OK: every advertised closure' $$out; then \
	  echo "CONTROL FAILURE: ledger gate did not complete its real checks" >&2; \
	  sed -n '1,60p' $$out >&2; rm -rf $$out $$evilroot; exit 1; \
	fi; \
	rm -rf $$out $$evilroot; \
	echo "  ok: the live axiom dump ignores a planted ELAN_HOME toolchain"
	@$(_FV_PYTHON3) scripts/check_ledger_consistency.py

# HARDWARE-ASSUMPTION ledger hygiene. The firmware-side counterpart to
# verify-ledger-consistency, for the premises that have NO machine truth to be
# checked against (there is no `#print axioms` for a die). It checks the
# ledger's hygiene — anchors resolve, claimed make-targets are real, and the
# HW-ASSUME id set is EXACTLY the set cited across the tree (OpenTitan's
# bidirectional cross-check; an unledgered citation and a dead row both fail).
# It never checks the premises themselves: no amount of green here makes a
# claim about silicon true.
# Needs no build — pure ledger/source inspection.
.PHONY: verify-hw-assumptions
verify-hw-assumptions: ## HW-ASSUME ledger falsifiable: anchors resolve, tests real, ids bidirectional
	@$(_FV_PYTHON3) scripts/check_hw_assumptions.py --self-test
	@$(_FV_PYTHON3) scripts/check_hw_assumptions.py

# Frozen Draft 1.1 + Draft 1.2 rollback/lock pair. Those documents are reviewed
# at an EXACT DIGEST and the 2026-07-26 owner ratification says any byte change
# reopens the gate — but nothing enforced it, so the HW-CONFIRM->HW-ASSUME
# rename in `fb66a1e5` silently reopened a ratified gate for six days. The
# receipt's "## Frozen pair" table is the single source of truth; this target
# recomputes both digests against it. Re-pinning is therefore a deliberate edit
# to the receipt, not an invisible side effect of editing a draft.
# Needs no build — pure digest/source inspection. It says NOTHING about whether
# the current bytes are approved; read the receipt's gate-state note for that.
# Ships its own --self-test negative control (asserted first, same pattern as
# verify-hw-assumptions): the parser must fail closed on a battery of in-memory
# mutations, so a later edit that weakens the parser turns this target red.
.PHONY: verify-rollback-freeze-pin
verify-rollback-freeze-pin: ## Draft 1.1/1.2 frozen pair still matches its receipt digests
	@$(_FV_PYTHON3) scripts/check_rollback_freeze_pin.py --self-test
	@$(_FV_PYTHON3) scripts/check_rollback_freeze_pin.py

# TLA+/TLC models. Until now these had NO make target and the only tla2tools.jar
# on the box lived in a scratch directory belonging to a session that no longer
# exists — so three committed model-checking results, each cited in docs, could
# not be re-run by anyone. A pilot result that cannot be re-run is a
# verification claim with no executable evidence, which is exactly what
# verify-ledger-consistency exists to prevent (work-todo C5).
#
# Each run_*.sh is self-checking: it asserts an EXPECTED verdict per config,
# including the deliberate VIOLATED ones that are the negative controls (a
# wrong-order variant must break; a symmetric PIN model must false-wipe). So a
# green here means "all expected outcomes matched", not "no violations found".
#
# The jar is NOT vendored (4.3 MB of third-party binary) and NOT auto-fetched:
# the validated build is a tlaplus NIGHTLY, so a hard hash-pin against
# "download latest" would fail for everyone. Instead: fail loudly when absent,
# print the jar hash, and warn when it is not the build these results were
# obtained with. Attribution over false precision.
TLA_DIR       := tla
TLA_JAR       ?= $(or $(TLA2TOOLS),$(HOME)/tla2tools.jar)
# SHA-256 of the tla2tools build the committed results were obtained with
# (TLA+ Tools nightly, Build-TimeStamp 2026-07-15T13:43:31Z).
TLA_JAR_SHA256 := 58d44845a37a8d776deaf8cf3a623213b59d311bc0ec287bcdfbe148dd11bb3d

.PHONY: verify-tla
verify-tla: ## TLA+/TLC models (page-123 crash-atomicity, combined budget, PIN reconcile)
	@$(_FV_PYTHON3) tla/check_tlc.py --self-test
	@command -v java >/dev/null 2>&1 || { echo "ERROR: java not found — TLC needs a JRE."; exit 1; }
	@if [ ! -f "$(TLA_JAR)" ]; then \
		echo "ERROR: tla2tools.jar not found at $(TLA_JAR)."; \
		echo "  Set TLA2TOOLS=/path/to/tla2tools.jar, or drop it at \$$HOME/tla2tools.jar."; \
		echo "  Fetch: https://github.com/tlaplus/tlaplus/releases"; \
		echo "  The committed results used sha256 $(TLA_JAR_SHA256)."; \
		exit 1; \
	fi
	@got=$$(sha256sum "$(TLA_JAR)" | cut -d' ' -f1); \
	if [ "$$got" != "$(TLA_JAR_SHA256)" ]; then \
		echo "WARNING: tla2tools.jar sha256 $$got"; \
		echo "         differs from the build these results were validated against"; \
		echo "         ($(TLA_JAR_SHA256)). A different TLC is a different tool —"; \
		echo "         a green below is not attributable to the committed pilot."; \
	else \
		echo "tla2tools.jar sha256 matches the validated build."; \
	fi
	@rc=0; \
	TLA2TOOLS="$(TLA_JAR)" $(TLA_DIR)/run.sh          || rc=1; \
	TLA2TOOLS="$(TLA_JAR)" $(TLA_DIR)/run_combined.sh || rc=1; \
	TLA2TOOLS="$(TLA_JAR)" $(TLA_DIR)/run_pin.sh      || rc=1; \
	exit $$rc

# P1.9 TrustZone memory-map source-binding drift gate. The region literals are
# triplicated by hand across the linker .x files, proto/src/lib.rs, and
# secure/src/sau.rs with no cross-family check — editing a .x MEMORY number
# without updating proto/sau.rs silently overlaps secure data into an SAU-NS
# region. This binds all three families to each other AND to the Lean
# Platform/MemoryMap.lean literals (so its accept=>∉secure disjointness proof is
# about the real map). --self-test is the negative control: an injected .x/secure
# overlap MUST be caught. Pure source parse, no build.
.PHONY: verify-linker-map
verify-linker-map: ## TrustZone memory-map drift gate: .x == proto == sau.rs == Lean (P1.9)
	@$(_FV_PYTHON3) scripts/check_linker_memory_map.py --self-test
	@$(_FV_PYTHON3) scripts/check_linker_memory_map.py

# Verus (verified Rust) flash-journal crash-safety pilot — an ALL-LENGTH proof of the
# page-123 SIGS-first compaction-local no-rollback property (INV_SIGS_COMPACTION_LOCAL),
# complementing the bounded TLA+ Page123Compaction pilot. Proves a Rust MODEL (not the
# firmware) under named STM32-flash silicon axioms; the model<->firmware link is cited-TCB.
# Verus is NOT vendored (rustc-pinned prebuilt); set VERUS_DIR or see
# scripts/fv-external-tools.env. `cargo verus verify` exits non-zero on any failed proof.
VERUS_DIR ?= $(HOME)/Downloads/verus-0.2026.07.12.0b42f4c-x86-linux/verus-x86-linux
.PHONY: verify-verus
verify-verus: ## Verus page-123 flash-journal crash-safety pilot (all-length; needs local Verus)
	@test -x "$(VERUS_DIR)/cargo-verus" || { echo "ERROR: cargo-verus not at $(VERUS_DIR)."; \
	  echo "  Install Verus (rustc-pinned prebuilt) + set VERUS_DIR=<verus-x86-linux dir>."; \
	  echo "  See contracts/verification/scripts/fv-external-tools.env."; exit 1; }
	@# `cargo verus verify` exits non-zero on ANY failed proof — that exit code IS the gate.
	@# Clean just this crate first so it always re-verifies + prints "N verified, 0 errors"
	@# (cargo caches a prior success and would otherwise only print "Finished").
	@cd verus && cargo clean -p pq1-flash-journal-verus 2>/dev/null; true
	@cd verus && PATH="$(VERUS_DIR):$$HOME/.cargo/bin:$$PATH" cargo verus verify

# crux-mir (Galois) implementation-diversity check on the NS-pointer window validator: a
# SECOND symbolic engine (vs the Kani harnesses) proving the validator EQUIVALENT to an
# independent u64 oracle (covers completeness, not just Kani's soundness). Needs the
# schema-8 mir-json build + the SAW-bundle crux-mir-comp; NOT vendored (see
# scripts/fv-external-tools.env). `cargo crux-test` exits non-zero on any disproved goal.
CRUX_RLIBS  ?= $(HOME)/repos/mir-json/rlibs
SAW_BIN_DIR ?= $(HOME)/Downloads/saw-1.5.1-ubuntu-24.04-X64-with-solvers/bin
.PHONY: verify-crux-ns-ptr
verify-crux-ns-ptr: ## crux-mir diversity check of ns_ptr_validate vs an independent oracle
	@test -x "$(SAW_BIN_DIR)/crux-mir-comp" && test -d "$(CRUX_RLIBS)" || { \
	  echo "ERROR: crux-mir-comp / mir-json rlibs not found ($(SAW_BIN_DIR), $(CRUX_RLIBS))."; \
	  echo "  See contracts/verification/scripts/fv-external-tools.env."; exit 1; }
	@cd crux/ns_ptr_diversity && env -u LD_LIBRARY_PATH \
	  PATH="$$HOME/.cargo/bin:$(SAW_BIN_DIR):/usr/bin:/bin" \
	  CRUX_RUST_LIBRARY_PATH="$(CRUX_RLIBS)" cargo crux-test

# EASYCRYPT PORT gate. Two axioms in theft_free's closure (A5-EUFCMA, A5-ITSR)
# cite this development as evidence; until 2026-07-10 it lived in a remote-less
# local repo, so nobody but its author could check it. Compiles EVERY .ec AS A
# TARGET -- mandatory, because EasyCrypt's `require` does NOT re-verify a
# dependency's proofs (a file can require a broken theory and still exit 0), and
# `admit` compiles exit 0 silently. Also asserts the pinned admit/axiom ledger
# with a NESTING-AWARE sweeper (scripts/ec_sweep.py).
# NOT CI-gated: needs an opam switch with EasyCrypt r2026.02 + Alt-Ergo 2.6.0.
# `make verify-easycrypt-pins` checks the ledger with no toolchain at all.
.PHONY: verify-easycrypt verify-easycrypt-full verify-easycrypt-pins
verify-easycrypt: ## HISTORICAL drafts PARTIAL compile (stdlib +C chain; MM45-chain SKIPPED loudly) + pins
	@/usr/bin/bash scripts/check_easycrypt.sh

# F5 (2026-07-16): "full" is now DISTINCT from partial and HONEST — it requires
# all 21 .ec compiled with ZERO skips (implies FORCE_MM45=1) and FAILS if the
# MM45 reference proofs / toolchain are absent, instead of the old behaviour
# where a skipped-11-of-21 run could still print a success banner.
verify-easycrypt-full: ## HISTORICAL drafts FULL verification — 21/21, zero skips (needs MM45 toolchain)
	@/usr/bin/bash scripts/check_easycrypt.sh --full

# F5: ledger (admit/axiom COUNT + SEMANTIC name->statement pin) with NO toolchain,
# preceded by the wired-in negative control (a `dmkey_ll : false` weakening and a
# delete-one-add-one, both count-preserving, MUST fire the semantic pin).
verify-easycrypt-pins: ## HISTORICAL drafts admit/axiom + semantic pin ledger (no toolchain) + negative control
	@/usr/bin/bash scripts/check_easycrypt.sh --self-test
	@/usr/bin/bash scripts/check_easycrypt.sh --dry-run

# 2026-07-17: the C10-CONCRETE capstone (easycrypt/drafts/SPHINCS_C_c10.ec — the FORS leg
# routed through the concrete FORS_C10_Multi, not the abstract FORS_C_Multi) is VERIFIED only
# in MM45's confirmed toolchain (EC r2026.02 + Z3 4.13.4 + Alt-Ergo 2.6.0), which does NOT build
# locally. This target reproduces the container gate: compile EVERY closure file AS A TARGET
# (sound — EC `require` does not re-verify deps) + 3 honesty controls (htree, ITSRC10, good_pos
# strict-positivity). Needs a local MM45 checkout (C10_PORT_DIR, with its FV-SPHINCSPLUS-EC
# submodule — third-party, NOT vendored) + docker. Absent either, it prints the committed
# receipt, which is the primary evidence. STILL a conditional composition (hfx/hbridge/htree
# carried); see easycrypt/docker/GATE-RECEIPT-2026-07-17.log.
C10_PORT_DIR ?= $(HOME)/repos/c10-eufcma-port
DOCKER ?= docker
.PHONY: verify-easycrypt-docker
verify-easycrypt-docker: ## HISTORICAL external C10-capstone gate in MM45's r2026.02 docker image (needs C10_PORT_DIR + docker)
	@if ! $(DOCKER) info >/dev/null 2>&1; then \
	  echo "ERROR: docker unavailable; historical receipt is not a new verification"; exit 1; fi
	@if [ ! -d "$(C10_PORT_DIR)/FV-SPHINCSPLUS-EC/proofs" ]; then \
	  echo "ERROR: historical MM45 base absent at $(C10_PORT_DIR)"; exit 1; fi
	$(DOCKER) build -t fv-sphincsplus-ec:r2026.02 "$(C10_PORT_DIR)/FV-SPHINCSPLUS-EC"
	@B64=$$(base64 -w0 easycrypt/docker/gate-c10-capstone.sh); \
	 $(DOCKER) run --rm -v "$(C10_PORT_DIR)":/work:ro fv-sphincsplus-ec:r2026.02 \
	   bash -c "echo $$B64 | base64 -d > /tmp/g.sh && bash /tmp/g.sh"

# FORS+C GRINDING MARGIN (bounds the blast radius of the A5-ITSR literature gap:
# the published SPHINCS+C paper has NO FORS+C security theorem). Pins that FORS+C
# is never weaker than plain FORS at C10's params, and FAILS if the removed
# forced-zero tree is ever shrunk (t_last < t), which would invert the inequality.
# No Lean build needed — pure arithmetic over params.rs constants.
.PHONY: verify-forsc-margin
verify-forsc-margin: ## FORS+C never weaker than plain FORS at C10 params (guardrails t_last>=t, ratio<=1)
	@$(_FV_PYTHON3) scripts/forsc_grinding_margin.py --self-test
	@$(_FV_PYTHON3) scripts/forsc_grinding_margin.py

# PROOF-MUTATION gate (anti-vacuity class V4: "dead conjunct / vacuous lemma").
# The proof-side analogue of cargo-mutants: for each entry in
# lean/scripts/proof_mutations.json it DELETES (by rename) a load-bearing axiom
# or WEAKENS a lemma and asserts the rebuild REACTS as the ledger claims — a
# load-bearing axiom's removal must break the build; a non-consumed marker's
# removal must leave it green AND drop EXACTLY the advertised axiom from the
# closure; a zero-consumer axiom (A3.4) must stay green. A green-when-it-should-
# be-red is a vacuity, caught. Each mutation asserts it MATERIALLY changed the
# file (no-op = HARD FAIL, never a skip), fully rebuilds (no stale-cache false
# pass), and ALWAYS reverts; a permanent CANARY must trip or the harness is void.
# SLOW (each mutation = a full `lake build SphincsCVerify`). The authoritative
# Make target is ALWAYS the curated default tier (8); a caller environment must
# not silently shrink its evidence. For non-authoritative local exploration,
# invoke the checker directly with `--tier quick` (2) or `--tier full` (13).
# Does NOT catch V7 (latent-FALSE axiom — still type-checks) or V11 (wrong spec).
# See scripts/check_proof_mutations.py + docs/verification/fv-adversarial-review-playbook.md §B.
ifneq ($(strip $(filter verify-proof-mutation,$(MAKECMDGOALS))),)
ifneq ($(origin MUTATIONS),undefined)
$(error refusing caller-set MUTATIONS for authoritative verify-proof-mutation; use the direct checker with an explicit --tier for exploratory runs)
endif
endif
verify-proof-mutation: verify-build ## Proof-side cargo-mutants: delete axiom/weaken lemma, expect break (SLOW)
	@$(_FV_PYTHON3) scripts/check_proof_mutations.py --tier default

# EXTERNAL kernel re-check gate (deep-research rec #1). lean/ is Lean v4.22.0,
# inside the pre-#8842 collectAxioms under-report window, so `#print axioms`
# (verify-audit) can under-report the trust base. lean4checker independently
# replays the whole SphincsCVerify environment back through the Lean kernel —
# non-zero exit on any rejected declaration. SCOPE (2026-07-19, FV review F5):
# this is an independent kernel/environment REPLAY, NOT an axiom-closure
# recomputation — its Replay re-adds referenced .axiomInfo as legal axioms, so
# the #8840 omission shape survives it (see scripts/run_lean4checker.sh header).
# Needs a version-matched lean4checker at ~/lean4checker (see scripts/run_lean4checker.sh
# header for the one-time build: git clone + checkout v4.22.0 + lake build);
# override the location with LEAN4CHECKER_DIR=...
verify-lean4checker: ## Independent kernel/environment replay (SLOW, manual pre-release)
	@/usr/bin/bash scripts/run_lean4checker.sh

# Model-to-bytecode (D): Kontrol/KEVM symbolic-execution proofs DIRECTLY against
# the deployed contract bytecode — an engine independent of Halmos, with no
# hand-written LeanModel.sol mirror in the loop. Currently proves the
# bootstrap-unremovable owner-table slice (A3.4 / invariant #6). Requires a K
# backend (`kup install kontrol` via Nix, or the RV Docker image); ~5 min
# build+prove. See kontrol/run_kontrol.sh + docs/KONTROL_SCOPING.md.
verify-kontrol: ## Kontrol/KEVM symbolic proofs on deployed bytecode (heavy)
	@/usr/bin/bash kontrol/run_kontrol.sh

# Halmos bytecode-level discharge of the A3.* bridge axioms: certifies the
# compiled runtime codehashes match the pins, then symbolically executes the
# deployed wallet/factory/verifier bytecode over the full check_* rule suite
# (both compiler profiles). Source of truth: halmos/run_halmos.sh.
verify-halmos: ## Halmos symbolic discharge of A3.* bridge axioms (heavy)
	@/usr/bin/bash halmos/run_halmos.sh

# Bulk executable-spec differential (A3.1 follow-up): regenerate the random
# corpus from the Rust signer (slow; gated behind GEN=1), embed it, and run
# Spec.Signature.verify over every vector, asserting it matches the Rust
# oracle's verdict. Non-zero exit on any mismatch. `bulk_vectors.json` is an
# ignored `GEN=1` intermediate; the committed `BulkVectors.lean` artifact makes
# the default run reproducible without re-signing.
verify-bulk: ## Bulk executable-spec differential (Lean vs Rust oracle)
ifeq ($(GEN),1)
	@cd $(REPO_ROOT) && cargo test -p sphincs-c10 --test gen_bulk_vectors --release -- --nocapture
	@cd $(LEAN_DIR) && $(_FV_PYTHON3) scripts/gen_bulk_lean.py
endif
	@cd $(LEAN_DIR) && $(LAKE) exe verify-bulk

# A3.1 full-(a) empirical interpreter↔bytecode bridge: replays the KAT + bulk
# corpus THROUGH the transcribed Yul interpreter (Interpreter/C10Program.lean,
# under the real Spec.Sha256Impl oracle) and asserts execC10Asm ==
# Spec.Signature.verify AND == the KAT/bulk ground-truth verdict on every vector.
# The load-bearing precondition for the interpreter-refinement proof (see
# docs/A3_1_CLOSURE_PATH.md §8). HARD CHECK (non-zero exit on any mismatch).
verify-interp: ## A3.1 interpreter<->bytecode KAT+bulk replay
	@cd $(LEAN_DIR) && $(LAKE) exe verify-interp

# A3.1 transcription-fidelity lint (POSITIONAL). Cross-checks the hand transcription
# c10Program (lean/SphincsCVerify/Interpreter/C10Program.lean) against the deployed
# verifier SOURCE (../smart-wallet/src/verifiers/SPHINCsC10Asm.sol) — the single
# residual the kernel proof `execC10Asm_eq` cannot see (it relates c10Program<->spec,
# never c10Program<->.sol). Three checks: (A) POSITIONAL constant cross-check per the
# `-- L<n>` anchors (catches a constant in the WRONG fragment — a cross-fragment swap —
# which a flat/global check misses); (B) global constant-set equality; (C) statement-kind
# histogram. Pure source lint, no lake build. A REGRESSION GATE, not a proof.
# Negative-controls (a mutated constant; a cross-fragment swap) verified to FAIL it.
#
# The STATISTICAL lint's documented hole — an intra-fragment edit that preserves the
# constant-set + kind-histogram + gate-vars (a same-kind statement REORDER, a non-gate
# var swap, a non-commutative operand-order swap) — is now closed by the STRUCTURAL check
# `check_c10_transcription_ast.py`: it PARSES both sides into the `Interpreter.Yul` AST and
# asserts TREE EQUALITY, so a reorder/var-swap/operand-swap flips the tree and fails. The
# negative-control harness `test_c10_transcription_ast_negative.py` proves 3 such mutants are
# invisible to the statistical lint yet caught by the structural check. HONEST SCOPE: this
# upgrades the source<->AST leg from statistical to STRUCTURAL; it does NOT close R1 — the
# solc source->deployed-bytecode leg is untouched, and the parser + its 2 normalization rules
# (error-string mstore elision; return-var init) are themselves the TCB. See
# docs/findings/A3_1_ADVERSARIAL_REVIEW_2026-06-18.md + docs/A3_1_CLOSURE_PATH.md §8.
verify-transcription: ## A3.1 c10Program <-> .sol transcription checks (positional + structural + source byte-pin) + P1.7 digest field-order pin
	@$(_FV_PYTHON3) scripts/check_c10_transcription.py
	@$(_FV_PYTHON3) scripts/check_c10_transcription_ast.py
	@$(_FV_PYTHON3) scripts/test_c10_transcription_ast_negative.py
	@$(_FV_PYTHON3) scripts/check_c10_source_pin.py
	@# P1.7 (2026-07-16): the digest the FIRMWARE signs (compute_sphincs_digest_v06)
	@# and the digest the wallet RECOMPUTES on-chain (sphincsDigest) must list the
	@# same 12 preimage fields in the same order — a source-level pin a regenerated
	@# vector can't see (self-test asserts a reorder/drop fires). See
	@# docs/verification/fv-pilot-signed-digest-correspondence-2026-07-16.md.
	@$(_FV_PYTHON3) scripts/check_sphincs_digest_field_order.py --self-test
	@$(_FV_PYTHON3) scripts/check_sphincs_digest_field_order.py

# A3.1 R1a IN-KERNEL parser leg (2026-07-04). Lake-builds the Lean Yul-subset
# parser (Interpreter/YulParse.lean), the pinned byte-exact source + faithful
# parse target (Interpreter/C10Source.lean), and the kernel theorems
# (Interpreter/C10Parse.lean):
#   parse_c10                  : parseYul c10Source = some c10ProgramFull  (rfl, NO axioms)
#   execFrom_c10ProgramFull_eq : the N1/N2 elision bridge (verdict-equal to c10Program
#                                for every oracle/sig/env/mem)
#   execC10Asm_eq_parsed_source: ANY successful parse of the pinned source runs as
#                                execC10Asm — chaining into execC10Asm_eq = Spec.verify
# The ~9K-char kernel reduction needs --tstack=32768, wired via the lakefile's
# moreLeanArgs (so a plain `lake build` — and hence `verify-build` and the
# `verify` bundle, whose verify-build dependency compiles these modules via the
# root import — gets it automatically). The byte-pin (check_c10_source_pin.py,
# pure Python) asserting the embedded c10Source literal == .sol L37-230 runs in
# CI via verify-transcription / a31-transcription.yml; the LAKE proof itself is
# a LOCAL gate (CI has no Lean toolchain).
verify-parse-transcription: ## A3.1 in-kernel Yul parse: parseYul c10Source = some c10ProgramFull (kernel rfl) + elision bridge
	@$(_FV_PYTHON3) scripts/check_c10_source_pin.py
	@cd $(LEAN_DIR) && $(LAKE) build SphincsCVerify.Interpreter.YulParse SphincsCVerify.Interpreter.C10Source SphincsCVerify.Interpreter.C10Parse
	@echo "PASS: parse_c10 + elision bridge + execC10Asm_eq_parsed_source kernel-checked"
	@echo "      (SphincsCVerify/Interpreter/C10Parse.lean; axiom closure: parse_c10 NONE,"
	@echo "       bridge/corollary [propext, Classical.choice, Quot.sound] — see verify-audit)"

# A3.1 INDEPENDENT-SOURCE KAT leg (work-todo #7). A clean-room SHA-256 C10 signer
# (scripts/independent_c10_signer.py) written from the deployed SPHINCsC10Asm.sol +
# the documented PRF preimages — NOT transliterated from the Rust `sphincs-c10`
# signer — giving implementation diversity for the differential oracle (today's
# 3-way Lean/Yul/Rust vectors all originate from the ONE Rust signer). Two checks:
#  (1) byte-equivalence — the independent signer reproduces the Rust pk_root + all 4
#      valid KAT vectors BYTE-FOR-BYTE + round-trips fresh messages (pure Python, ~5s);
#  (2) cross-verifier — the EXISTING Rust verifier accepts FRESH independent-signer
#      output (the genuine independence guard vs a shared Python sign+verify bug).
# Honest scope: diversity over the shared C10 spec, not a second spec. Needs python3.
verify-independent-signer: ## Clean-room C10 signer cross-check
	@$(_FV_PYTHON3) scripts/independent_c10_signer.py
	@cd $(REPO_ROOT) && cargo test -p sphincs-c10 --test independent_signer_xcheck --release -- --nocapture

# Per-primitive component KAT (ETHFALCON-port R1). Golden intermediate-value
# vectors for each C10 tweakable-hash primitive (th/th_pair/th_multi/h_msg/
# chain_hash/wots_digest + the wots_secret/fors_secret PRFs), cross-checked across
# THREE independent implementations: Rust `sphincs-c10` (recompute regression pin),
# the clean-room Python signer (independence guard), and the on-chain Yul verifier's
# SHA-256 preimage layout via the precompile (Foundry, the 6 verify-side primitives).
# Localizes an A3.1-class per-primitive divergence to the exact boundary. Golden is
# self-generated + N-way cross-checked; NOT externally conformant — C10 shares only
# raw SHA-256 with any standard (that layer is anchored to NIST CAVP). Regenerate
# with `C10_KAT_REGEN=1 cargo test -p sphincs-c10 --features sim-internals \
# --test primitive_kat --release`. Needs python3 + forge on PATH.
# See docs/verification/external-kat-provenance-and-ethfalcon-port-2026-07.md.
verify-primitive-kat: ## Per-primitive tweakable-hash KAT (Rust<->Python<->Yul)
	@cd $(REPO_ROOT) && cargo test -p sphincs-c10 --features sim-internals --test primitive_kat --release
	@$(_FV_PYTHON3) scripts/independent_c10_signer.py --check-primitives $(REPO_ROOT)/contracts/smart-wallet/test/c10_primitive_kat_vectors.json
	@cd $(REPO_ROOT)/contracts/smart-wallet && forge test --match-contract C10PrimitiveKat

# NIST CAVP SHA-256 conformance: regenerate the embedded vector module from
# the official byte-oriented .rsp suite (cavp/ — idempotent) and replay ALL
# ShortMsg + LongMsg vectors plus the full SHAVS Monte Carlo procedure
# through the executable FIPS 180-4 spec (Spec/Sha256Impl.lean). Compiled
# IO-level comparison; non-zero exit on any mismatch so CI can gate.
verify-cavp: ## NIST CAVP SHA-256 conformance over the FIPS spec
	@$(_FV_PYTHON3) scripts/gen_cavp_vectors.py
	@cd $(LEAN_DIR) && $(LAKE) exe verify-cavp

verify-build: ## lake build SphincsCVerify (the kernel gate)
	@cd $(LEAN_DIR) && $(LAKE) build

verify-audit: ## no-sorryAx + #print-axioms closure dump
	@echo "=== Build + capture compiler 'declaration uses sorry' warnings (P8: authoritative sorry gate) ==="
	@cd $(LEAN_DIR) && $(LAKE) build 2>&1 | tee /tmp/pq_audit_build.out
	@if grep -E "declaration uses 'sorry'" /tmp/pq_audit_build.out; then \
	  echo "FAIL: a SphincsCVerify declaration uses 'sorry' (incomplete proof — the compiler caught it regardless of source position)"; exit 1; fi
	@echo ""
	@echo "=== Pending sorry tactics (textual belt-and-braces) ==="
	@cd $(LEAN_DIR) && $(LAKE) env lean --run scripts/check_no_sorry.lean
	@echo ""
	@echo "=== Axiom dependency of headline theorems (P8: fail on sorryAx / elaboration error) ==="
	@cd $(LEAN_DIR) && $(LAKE) env lean scripts/dump_axioms.lean > /tmp/pq_audit_axioms.out 2>&1; \
	  status=$$?; cat /tmp/pq_audit_axioms.out; \
	  if [ $$status -ne 0 ]; then echo "FAIL: dump_axioms.lean elaboration error (a pinned theorem may be renamed/missing — the dump no longer covers the headline closure)"; exit 1; fi
	@if grep -q sorryAx /tmp/pq_audit_axioms.out; then \
	  echo "FAIL: sorryAx in a headline/corollary axiom closure — a proof is incomplete"; exit 1; fi
	@echo "OK: build emitted no 'uses sorry' warning and no headline/corollary closure contains sorryAx."

verify-three-claims: ## The three security-claim summary
	@/usr/bin/bash scripts/verify-three-claims.sh

verify-exec-gate: ## Claim-4 trace gate closure (kernel-only)
	@echo "=== Building TxFlow + Spec.Theorems (Claim 4 dep closure) ==="
	@cd $(LEAN_DIR) && $(LAKE) build SphincsCVerify.Wallet.TxFlow SphincsCVerify.Spec.Theorems
	@echo ""
	@echo "=== Axiom closure for Claim 4 theorems ==="
	@echo "Expected closure: { propext, Classical.choice, Quot.sound } (kernel-only)"
	@echo ""
	@cd $(LEAN_DIR) && $(LAKE) env lean scripts/dump_axioms_claim4.lean > /tmp/pq_claim4_axioms.out 2>&1; \
	  status=$$?; cat /tmp/pq_claim4_axioms.out; \
	  if [ $$status -ne 0 ]; then echo "FAIL: Claim-4 axiom dump elaboration error"; exit 1; fi
	@# P8: actually ENFORCE kernel-only (was print-only). Fail on sorryAx or any
	@# non-kernel axiom (bridge/crypto) entering a Claim-4 closure — e.g. if the
	@# trace gate were ever pinned to the deployed verifier (which would pull in
	@# A1/A3.1/A4 and is the P13 over-claim this gate now catches). The python
	@# helper flattens `#print axioms`'s wrapped output before parsing.
	@$(_FV_PYTHON3) scripts/check_axiom_closure.py --manifest $(LEAN_DIR)/scripts/axiom_closure_claim4_manifest.txt /tmp/pq_claim4_axioms.out

verify-bytecode-setup: ## One-time Halmos setup
	@/usr/bin/bash halmos/setup_halmos.sh

# Bytecode-level discharge of the A3.* bridge axioms: certifies the
# compiled runtime codehashes match PINNED_CODEHASHES.md (BOTH the default
# runs=200 and deploy runs=999999 profiles) + the immutable-window lemma,
# then symbolically executes the deployed PQSmartWallet / factory / verifier
# bytecode with the patched Halmos — including the full pointwise-equivalence
# session for A3.2. Run `make verify-bytecode-setup` once first.
# Set PQ1_HALMOS_BOTH_PROFILES=1 to also re-run the symbolic suite under the
# deploy profile.
verify-bytecode: ## Halmos bytecode-level A3.* discharge (heavy)
	@/usr/bin/bash halmos/run_halmos.sh

verify-clean: ## rm -rf .lake build
	@cd $(LEAN_DIR) && rm -rf .lake build

# ---------------------------------------------------------------------------
# §33 — Aeneas-extracted firmware code (contracts/verification/extracted/)
#
#   make verify-extracted        — type-check the extracted-code project
#                                  (generated Lean + equivalence theorems +
#                                   axiom check). Needs elan; first run pulls
#                                  mathlib from the cloud cache.
#   make extract-sphincs-adrs    — REGENERATE the scoped address.rs extraction
#                                  and fail if it drifts from the committed
#                                  Extracted/Adrs.lean (proof-rot guard).
#                                  Needs the §33 toolchain in
#                                  ~/.local/share/pqsigner-lean (charon
#                                  nightly-2026.06.08 + aeneas
#                                  nightly-2026.06.10 + rustup
#                                  nightly-2026-06-01).
# ---------------------------------------------------------------------------

override EXTRACTED_DIR := extracted
override PQLEAN        := $(HOME)/.local/share/pqsigner-lean
override REPO_ROOT     := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)

override _EXTRACTION_TARGETS := extract-sphincs-adrs extract-aa-userop extract-fors-index extract-merkle-verify extract-wots-pkfromsig extract-hash-fns extract-bip39-roundtrip extract-decode-item extract-u256-mul extract-format-decimal extract-fwmanifest-preimage extract-wots-digits extract-aa-eip1271 extract-txcore-rlp extract-pinstate extract-slotkdf extract-tx-merkle
override _EXTRACTION_IMPL_TARGETS := $(addprefix _,$(addsuffix -impl,$(_EXTRACTION_TARGETS)))
.PHONY: verify-extracted verify-extract-differential verify-extraction-freshness verify-extraction-regen verify-extraction-regen-self-test _verify-extraction-regen-loop _verify-extraction-regen-loop-self-test _verify-extraction-regen-wrong-waiver-self-test _verify-extraction-make-path-self-test _verify-extraction-workspace-inner-self-test _verify-extraction-alias-dryrun-self-test $(_EXTRACTION_TARGETS) $(_EXTRACTION_IMPL_TARGETS)

# MAKECMDGOALS selects the replay-only rejection checks below, but GNU Make lets
# a caller override even this built-in variable.  Reject any non-default origin
# before consulting it.  Extraction workspace allocation itself is target-bound
# below and does not depend on the requested top-level goal text.
ifeq ($(filter default undefined,$(origin MAKECMDGOALS)),)
$(error refusing caller-overridden MAKECMDGOALS (origin $(origin MAKECMDGOALS)) for extraction assurance)
endif

# The authoritative replay must recurse through the reviewed GNU Make binary.
# Reject ambient executor and Bash-startup overrides as an additional fail-loud
# receipt.  Internal helper goals are guarded too.
override _EXTRACTION_REGEN_GUARDED_GOALS := verify-extraction-regen verify-extraction-regen-self-test _verify-extraction-regen-loop _verify-extraction-regen-loop-self-test _verify-extraction-regen-wrong-waiver-self-test _verify-extraction-make-path-self-test _verify-extraction-workspace-inner-self-test _verify-extraction-alias-delegation-self-test _verify-lake-path-self-test
override _EXTRACTION_CONTEXT_GOALS := $(_EXTRACTION_REGEN_GUARDED_GOALS) $(_EXTRACTION_TARGETS)
override _EXTRACTION_ALL_GUARDED_TARGETS := $(_EXTRACTION_CONTEXT_GOALS) $(_EXTRACTION_IMPL_TARGETS)
override _FV_ALL_PARSER_GUARDED_TARGETS := $(_FV_EVIDENCE_TARGETS) $(_EXTRACTION_ALL_GUARDED_TARGETS)

# The immediate MAKEFILE_LIST check above catches startup files and any `-f`
# parsed before this Makefile. The procfs argv guard catches multiple explicit
# makefiles before a trailing file can mutate MAKEFILE_LIST. Secondary expansion
# remains defense in depth after GNU Make has parsed the complete input list.
# Parser expansion errors cannot be suppressed by an injected `.IGNORE`.
.SECONDEXPANSION:
$(_FV_ALL_PARSER_GUARDED_TARGETS): $$(if $$(filter 1,$$(words $$(MAKEFILE_LIST))),,$$(error refusing additional parsed makefiles [$$(MAKEFILE_LIST)]))

ifneq ($(strip $(filter $(_EXTRACTION_CONTEXT_GOALS),$(MAKECMDGOALS))),)
ifneq ($(_FV_RECIPE_SHELL_ORIGIN),file)
$(error refusing caller-overridden SHELL (origin $(_FV_RECIPE_SHELL_ORIGIN)) for authoritative extraction replay)
endif
ifneq ($(_FV_RECIPE_SHELLFLAGS_ORIGIN),file)
$(error refusing caller-overridden .SHELLFLAGS (origin $(_FV_RECIPE_SHELLFLAGS_ORIGIN)) for authoritative extraction replay)
endif
ifneq ($(origin MAKE),default)
$(error refusing caller-overridden MAKE (origin $(origin MAKE)) for authoritative extraction replay)
endif
ifneq ($(origin MAKE_COMMAND),default)
$(error refusing caller-overridden MAKE_COMMAND (origin $(origin MAKE_COMMAND)) for authoritative extraction replay)
endif
endif

# The global startup-hook rejections above ensure Bash cannot suppress or forge
# this parser process. This is still evaluated while the main Makefile is being
# parsed, before GNU Make opens any later explicit makefile. Python isolated
# mode also removes ambient module/startup injection from this trust decision.
# The checker path is resolved from the VALIDATED sole makefile entry:
# MAKEFILE_LIST has passed the origin and word-count guards, so its single
# entry is this file, and `realpath` anchors the checker under this file's
# physical directory — independent of the process cwd, of MAKEFILE_LIST (no
# longer caller-mutable), and of $(CURDIR) (a command-line-assignable Make
# variable).  The foreign-working-directory guard above additionally pins the
# process cwd to that same directory, so a planted foreign
# scripts/check_make_argv.py is never on either path.  The checker inspects
# BOTH channels that carry Make execution flags: the process argv (explicit
# -f count and no-execute/assume options) and the at-exec environment via
# /proc/<pid>/environ (an environment-injected MAKEFLAGS, e.g. `o <target>`,
# is consumed and stripped before the in-Make MAKEFLAGS value is rebuilt, so
# only the raw environ still shows it).
override _FV_MAKE_ARGV_GUARD := $(shell /usr/bin/python3 -I '$(dir $(realpath $(_FV_MAKEFILE_LIST_AT_ENTRY)))scripts/check_make_argv.py' /proc/$$PPID/cmdline /proc/$$PPID/environ)
ifneq ($(_FV_MAKE_ARGV_GUARD),ok)
$(error refusing unsafe Make invocation for verification Makefile ($(_FV_MAKE_ARGV_GUARD)))
endif

# Keep direct multi-goal requests fail-loud: the aggregate replay deliberately
# forks one Make process per registry target.  This is a policy check, not the
# workspace trust root; an indirect alias still receives a private root when the
# concrete extract-* target executes.
override _EXTRACTION_REQUESTED_GOALS := $(filter extract-%,$(MAKECMDGOALS))
ifneq ($(strip $(word 2,$(_EXTRACTION_REQUESTED_GOALS))),)
$(error refusing multiple extract-* targets in one Make invocation; invoke one target per process)
endif

# Public extract-* targets enter one fixed, environment-scrubbed inner Make
# process.  The inner recipe uses .ONESHELL so its workspace exists only as a
# readonly shell variable; no Make variable origin is trusted for allocation or
# cleanup.  A caller can neither preseed the path nor make separate recipe
# shells disagree about it.  The delegation line is one define so the
# alias-wiring self-test can print EXACTLY the command the alias executes —
# Make dry-run mode is itself rejected above as a no-execute channel, so the
# self-test cannot inspect the expansion with `-n`.
override define _fv_extraction_delegate
/usr/bin/env -u SHELLOPTS -u BASHOPTS -u BASH_ENV -u ENV \
  -u MAKE -u MAKE_COMMAND -u MAKEFLAGS -u MFLAGS -u GNUMAKEFLAGS -u MAKEFILES \
  $(_FV_GNU_MAKE) --no-print-directory "_$(1)-impl" _FV_EXTRACTION_INNER=1
endef
$(_EXTRACTION_TARGETS):
	@$(call _fv_extraction_delegate,$@)

ifeq ($(_FV_EXTRACTION_INNER),1)
.ONESHELL:
override .SHELLFLAGS := -e -o pipefail -c
endif

override define _begin_private_extraction
umask 077
EXTRACTION_TMP_ROOT=$$(/usr/bin/mktemp -d /tmp/pqsigner-extract.XXXXXXXX)
readonly EXTRACTION_TMP_ROOT
_fv_cleanup_extraction_tmp() {
  rc=$$?
  trap - EXIT
  if [[ "$${EXTRACTION_TMP_ROOT}" =~ ^/tmp/pqsigner-extract\.[A-Za-z0-9]{8}$$ ]] \
      && [ -O "$${EXTRACTION_TMP_ROOT}" ]; then
    if [ "$$rc" -eq 0 ]; then
      /usr/bin/rm -rf -- "$${EXTRACTION_TMP_ROOT}"
    else
      echo "retaining failed private extraction workspace: $${EXTRACTION_TMP_ROOT}" >&2
    fi
  else
    echo "refusing to clean invalid extraction workspace: $${EXTRACTION_TMP_ROOT}" >&2
    rc=1
  fi
  exit "$$rc"
}
trap _fv_cleanup_extraction_tmp EXIT
if [ ! -d "$${EXTRACTION_TMP_ROOT}" ] \
    || [ ! -O "$${EXTRACTION_TMP_ROOT}" ] \
    || [ "$$(/usr/bin/stat -c '%a' -- "$${EXTRACTION_TMP_ROOT}")" != 700 ]; then
  echo "private extraction workspace is not an owner-only mode-0700 directory" >&2
  exit 1
fi
endef

_verify-extraction-workspace-inner-self-test:
	@$(_begin_private_extraction)
	@printf 'private=%s mode=%s\n' "$${EXTRACTION_TMP_ROOT}" \
	  "$$(/usr/bin/stat -c '%a' -- "$${EXTRACTION_TMP_ROOT}")"

# Prints exactly the command the public alias delegates to (same $(call)), so
# the self-test can assert the fixed wiring without Make dry-run mode.
_verify-extraction-alias-delegation-self-test:
	@printf '%s\n' '$(call _fv_extraction_delegate,extract-sphincs-adrs)'

# The sole stale waiver is for one exact Aeneas translator defect.  The marker
# is emitted only when that stage reproduces its pinned Unreachable diagnostic;
# a missing tool, Charon failure, recovered generator, diff drift, or checker
# failure is a different outcome and must fail the aggregate replay.
override _TX_MERKLE_WAIVER_MARKER := PQ1_EXPECTED_WAIVER_STAGE: extract-tx-merkle Aeneas Unreachable at merkle.rs:53:4-72:1

# F1 (2026-07-16) — TOOLCHAIN-FREE extraction freshness tripwire. The extract-*
# regen-diff targets below are the REAL freshness check but need the §33
# charon/aeneas toolchain (~/.local/share/pqsigner-lean), so they cannot run on a
# stock CI runner — and without them current Rust can drift from the committed
# extraction while verify-build/verify-extracted stay green on the stale .lean
# (4 of 15 extractions were already stale when this gate was written). This pins
# sha256(committed generated Lean) + sha256(mirrored Rust file) per extraction,
# plus checker-bound raw-generator output hashes used by the local complete-output
# regen check (extraction_registry.json). It FAILS on drift, forcing a
# re-extraction. Ships a
# wired-in negative control (the PQFW_V1->PQFW_V2 domain-tag flip must fire both
# tripwire halves). CI-runnable (pure Python). See scripts/check_extraction_freshness.py.
verify-extraction-freshness: ## F1 toolchain-free extraction freshness tripwire (sha256 pins) + negative control
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py --self-test
	@$(_FV_PYTHON3) scripts/check_extraction_freshness.py --self-test
	@$(_FV_PYTHON3) scripts/check_extraction_freshness.py

# F1 — the REAL regen check (LOCAL, needs the charon/aeneas toolchain): re-run
# every extract-* target and compare the exact raw Aeneas module inventory/hashes
# plus deterministically normalized Funs/Types against the committed extraction.
# A `fresh:true`
# registry entry that drifts is a FAILURE; the `fresh:false` waived entry
# (tx-merkle — Aeneas can no longer translate it) is EXPECTED to fail and only
# flags if it unexpectedly re-extracts (bump it to fresh + `--update <target>` then).
verify-extraction-regen: verify-extraction-freshness verify-extraction-regen-self-test ## F1 REAL regen: re-run every extract-* + diff (needs charon/aeneas toolchain)
	+@$(_FV_GNU_MAKE) --no-print-directory _verify-extraction-regen-loop

verify-extraction-regen-self-test: ## Negative controls for signature/value parity + recovered-waiver failure
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py --self-test-lean
	@$(_FV_PYTHON3) scripts/check_make_argv.py --self-test
	@actual=$$(sed -nE 's/^(verify[-A-Za-z0-9_.]*):.*/\1/p' Makefile | LC_ALL=C sort -u); \
	expected=$$(printf '%s\n' $(_FV_EVIDENCE_TARGETS) | LC_ALL=C sort -u); \
	if [ "$$actual" != "$$expected" ]; then \
	  echo "CONTROL FAILURE: _FV_EVIDENCE_TARGETS does not exactly cover every verify* target" >&2; \
	  diff -u <(printf '%s\n' "$$expected") <(printf '%s\n' "$$actual") >&2 || true; \
	  exit 1; \
	fi; \
	echo "  ok: every verify* target is in the complete parser-guard inventory"
	+@out=$$(mktemp /tmp/pq-extraction-shell-override-selftest.XXXXXX); \
	if $(_FV_GNU_MAKE) --no-print-directory SHELL=/bin/true _verify-extraction-regen-loop >$$out 2>&1; then \
	  echo "CONTROL FAILURE: caller-overridden SHELL suppressed authoritative extraction replay" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-overridden SHELL ' $$out; then \
	  echo "CONTROL FAILURE: SHELL override was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: caller-overridden recipe SHELL is CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-shellflags-override-selftest.XXXXXX); \
	if $(_FV_GNU_MAKE) --no-print-directory '.SHELLFLAGS=-n -c' _verify-extraction-regen-loop >$$out 2>&1; then \
	  echo "CONTROL FAILURE: caller-overridden .SHELLFLAGS suppressed authoritative extraction replay" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-overridden .SHELLFLAGS ' $$out; then \
	  echo "CONTROL FAILURE: .SHELLFLAGS override was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: caller-overridden recipe .SHELLFLAGS are CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-bash-hook-selftest.XXXXXX); \
	for hook in SHELLOPTS BASHOPTS BASH_ENV ENV; do \
	  case "$$hook" in \
	    SHELLOPTS) value=noexec ;; \
	    BASHOPTS) value=sourcepath ;; \
	    BASH_ENV|ENV) value=/dev/null ;; \
	  esac; \
	  if /usr/bin/env "$$hook=$$value" $(_FV_GNU_MAKE) --no-print-directory _verify-extraction-regen-loop >$$out 2>&1; then \
	    echo "CONTROL FAILURE: inherited $$hook bypassed authoritative extraction replay" >&2; \
	    sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	  elif ! grep -Fq "refusing inherited $$hook " $$out; then \
	    echo "CONTROL FAILURE: inherited $$hook was rejected for the wrong reason" >&2; \
	    sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	  fi; \
	done; \
	rm -f $$out; \
	echo "  ok: inherited SHELLOPTS/BASHOPTS/BASH_ENV/ENV hooks are CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-make-mode-selftest.XXXXXX); \
	if $(_FV_GNU_MAKE) --no-print-directory -i _verify-extraction-regen-loop >$$out 2>&1; then \
	  echo "CONTROL FAILURE: Make ignore-errors mode bypassed authoritative extraction replay" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing Make ignore-errors mode ' $$out; then \
	  echo "CONTROL FAILURE: Make ignore-errors mode was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory -t verify-extracted >$$out 2>&1; then \
	  echo "CONTROL FAILURE: Make touch mode suppressed the extracted-closure gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing Make touch mode ' $$out; then \
	  echo "CONTROL FAILURE: Make touch mode was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if /usr/bin/env MAKEFLAGS=-t $(_FV_GNU_MAKE) --no-print-directory \
	    verify-ledger-consistency >$$out 2>&1; then \
	  echo "CONTROL FAILURE: ambient Make touch mode suppressed the ledger gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing Make touch mode ' $$out; then \
	  echo "CONTROL FAILURE: ambient Make touch mode was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory --eval='.IGNORE:' _verify-extraction-regen-loop >$$out 2>&1; then \
	  echo "CONTROL FAILURE: Make --eval installed a global ignore-errors bypass" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing Make --eval ' $$out; then \
	  echo "CONTROL FAILURE: Make --eval was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory MAKEFLAGS= _verify-extraction-regen-loop >$$out 2>&1; then \
	  echo "CONTROL FAILURE: caller-overridden MAKEFLAGS bypassed authoritative extraction replay" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-overridden MAKEFLAGS ' $$out; then \
	  echo "CONTROL FAILURE: MAKEFLAGS override was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: Make ignore-errors/touch/eval/MAKEFLAGS bypasses are CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-noexec-selftest.XXXXXX); \
	if $(_FV_GNU_MAKE) --no-print-directory -n verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: Make dry-run mode suppressed an evidence gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing Make no-execute/assume mode ' $$out; then \
	  echo "CONTROL FAILURE: Make dry-run mode was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory -q verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: Make question mode suppressed an evidence gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing Make no-execute/assume mode ' $$out; then \
	  echo "CONTROL FAILURE: Make question mode was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory -o verify-hw-assumptions verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: Make assume-old mode retired an evidence gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'no-execute-mode' $$out; then \
	  echo "CONTROL FAILURE: Make assume-old mode was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory --assume-old=verify-hw-assumptions verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: Make --assume-old retired an evidence gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'no-execute-mode' $$out; then \
	  echo "CONTROL FAILURE: Make --assume-old was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory -W Makefile verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: Make what-if mode reached an evidence gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'no-execute-mode' $$out; then \
	  echo "CONTROL FAILURE: Make what-if mode was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if /usr/bin/env MAKEFLAGS=n $(_FV_GNU_MAKE) --no-print-directory \
	    verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: ambient Make dry-run mode suppressed an evidence gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing Make no-execute/assume mode ' $$out; then \
	  echo "CONTROL FAILURE: ambient Make dry-run mode was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if /usr/bin/env 'MAKEFLAGS=o verify-hw-assumptions' $(_FV_GNU_MAKE) --no-print-directory \
	    verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: ambient Make assume-old mode retired an evidence gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'no-execute-mode' $$out; then \
	  echo "CONTROL FAILURE: ambient Make assume-old mode was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if /usr/bin/env GNUMAKEFLAGS=n $(_FV_GNU_MAKE) --no-print-directory \
	    verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: ambient GNUMAKEFLAGS dry-run mode suppressed an evidence gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing Make no-execute/assume mode ' $$out \
	    && ! grep -Fq 'no-execute-mode' $$out; then \
	  echo "CONTROL FAILURE: ambient GNUMAKEFLAGS dry-run mode was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if /usr/bin/env 'GNUMAKEFLAGS=o verify-hw-assumptions' $(_FV_GNU_MAKE) --no-print-directory \
	    verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: ambient GNUMAKEFLAGS assume-old mode retired an evidence gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'no-execute-mode' $$out; then \
	  echo "CONTROL FAILURE: ambient GNUMAKEFLAGS assume-old mode was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if /usr/bin/env 'MAKEFLAGS=-I. --assume-old=verify-hw-assumptions' $(_FV_GNU_MAKE) --no-print-directory \
	    verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: an attached-argument word blinded the MAKEFLAGS suppression scan" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'no-execute-mode' $$out; then \
	  echo "CONTROL FAILURE: attached-argument MAKEFLAGS suppression was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: Make dry-run/question/assume-old/what-if modes (argv and ambient MAKEFLAGS/GNUMAKEFLAGS) are CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-bashfunc-selftest.XXXXXX); \
	if /usr/bin/env 'BASH_FUNC_lake%%=() { :; }' 'BASH_FUNC_python3%%=() { :; }' \
	    $(_FV_GNU_MAKE) --no-print-directory verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: exported Bash functions intercepted the evidence tools" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing inherited exported Bash functions ' $$out; then \
	  echo "CONTROL FAILURE: exported Bash functions were rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if /usr/bin/env PYTHONPATH=/tmp/pq-caller-controlled $(_FV_GNU_MAKE) --no-print-directory \
	    verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: inherited PYTHONPATH steered the evidence interpreter" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-set PYTHONPATH ' $$out; then \
	  echo "CONTROL FAILURE: inherited PYTHONPATH was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	for ldvar in LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH; do \
	  if /usr/bin/env "$$ldvar=/nonexistent-pq-check.so" $(_FV_GNU_MAKE) --no-print-directory \
	      verify-hw-assumptions >$$out 2>&1; then \
	    echo "CONTROL FAILURE: caller-set $$ldvar injected the loader into the trust-root binaries" >&2; \
	    sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	  elif ! grep -Fq "refusing caller-set $$ldvar " $$out; then \
	    echo "CONTROL FAILURE: caller-set $$ldvar was rejected for the wrong reason" >&2; \
	    sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	  fi; \
	done; \
	rm -f $$out; \
	echo "  ok: exported Bash functions, Python startup hooks, and dynamic-loader preloads are CAUGHT"
	+@out=$$(mktemp /tmp/pq-three-claims-path-selftest.XXXXXX); \
	evilbin=$$(mktemp -d /tmp/pq-three-claims-path-planted.XXXXXX); \
	real_script=$$(/usr/bin/readlink -f -- scripts/verify-three-claims.sh); \
	expected_script_dir=$$(/usr/bin/pwd -P)/scripts; \
	expected_repo_root=$$(builtin cd -P -- ../.. && /usr/bin/pwd -P); \
	printf '#!/bin/sh\necho SPOOFED-DIRNAME >&2\nprintf "/tmp/pq-attacker-root/scripts\\n"\n' >$$evilbin/dirname; \
	chmod +x $$evilbin/dirname; \
	if ! PATH="$$evilbin:/usr/bin:/bin" CDPATH=/tmp/pq-attacker-cdpath \
	    /usr/bin/bash scripts/verify-three-claims.sh --self-test-path-resolution \
	    >$$out 2>&1; then \
	  echo "CONTROL FAILURE: verify-three-claims trust-root self-test did not run" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilbin; exit 1; \
	elif grep -Fq 'SPOOFED-DIRNAME' $$out; then \
	  echo "CONTROL FAILURE: verify-three-claims resolved dirname through caller PATH" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilbin; exit 1; \
	elif [ "$$(sed -n 's/^script_file=//p' $$out)" != "$$real_script" ] \
	    || [ "$$(sed -n 's/^script_dir=//p' $$out)" != "$$expected_script_dir" ] \
	    || [ "$$(sed -n 's/^repo_root=//p' $$out)" != "$$expected_repo_root" ]; then \
	  echo "CONTROL FAILURE: verify-three-claims resolved an unexpected physical trust root" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilbin; exit 1; \
	fi; \
	linkroot=$$(mktemp -d /tmp/pq-three-claims-link-selftest.XXXXXX); \
	mkdir -p \
	  $$linkroot/symlink/contracts/verification/scripts \
	  $$linkroot/symlink/contracts/smart-wallet \
	  $$linkroot/hardlink/contracts/verification/scripts \
	  $$linkroot/hardlink/contracts/smart-wallet; \
	: >$$linkroot/symlink/contracts/verification/Makefile; \
	: >$$linkroot/hardlink/contracts/verification/Makefile; \
	ln -s "$$real_script" \
	  $$linkroot/symlink/contracts/verification/scripts/verify-three-claims.sh; \
	if ! /usr/bin/bash \
	    $$linkroot/symlink/contracts/verification/scripts/verify-three-claims.sh \
	    --self-test-path-resolution >$$out 2>&1; then \
	  echo "CONTROL FAILURE: symlinked verify-three-claims did not resolve safely" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilbin $$linkroot; exit 1; \
	elif [ "$$(sed -n 's/^script_file=//p' $$out)" != "$$real_script" ] \
	    || [ "$$(sed -n 's/^script_dir=//p' $$out)" != "$$expected_script_dir" ] \
	    || [ "$$(sed -n 's/^repo_root=//p' $$out)" != "$$expected_repo_root" ]; then \
	  echo "CONTROL FAILURE: symlinked verify-three-claims rebound the trust root" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilbin $$linkroot; exit 1; \
	fi; \
	if ! ln "$$real_script" \
	    $$linkroot/hardlink/contracts/verification/scripts/verify-three-claims.sh; then \
	  echo "CONTROL FAILURE: could not create verify-three-claims hard-link fixture" >&2; \
	  rm -rf $$out $$evilbin $$linkroot; exit 1; \
	elif /usr/bin/bash \
	    $$linkroot/hardlink/contracts/verification/scripts/verify-three-claims.sh \
	    --self-test-path-resolution >$$out 2>&1; then \
	  echo "CONTROL FAILURE: hard-linked verify-three-claims rebound the trust root" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilbin $$linkroot; exit 1; \
	elif ! grep -Fq 'refusing multiply-linked verification script' $$out; then \
	  echo "CONTROL FAILURE: hard-linked verify-three-claims failed for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilbin $$linkroot; exit 1; \
	fi; \
	rm -rf $$out $$evilbin $$linkroot; \
	if [ "$$(/usr/bin/stat -c '%h' -- "$$real_script")" -ne 1 ]; then \
	  echo "CONTROL FAILURE: verify-three-claims hard-link fixture was not removed" >&2; \
	  exit 1; \
	fi; \
	echo "  ok: verify-three-claims ignores PATH/CDPATH, resolves symlinks physically, and rejects hard links"
	+@out=$$(mktemp /tmp/pq-extraction-symlinked-makefile-selftest.XXXXXX); \
	evildir=$$(mktemp -d /tmp/pq-extraction-symlinked-makefile.XXXXXX); \
	mkdir -p $$evildir/scripts; \
	printf 'print("ok")\n' >$$evildir/scripts/check_make_argv.py; \
	printf 'print("SPOOFED-CWD")\n' >$$evildir/scripts/check_hw_assumptions.py; \
	ln -s "$$(pwd)/Makefile" $$evildir/Makefile; \
	if ( cd $$evildir && $(_FV_GNU_MAKE) --no-print-directory verify-hw-assumptions ) >$$out 2>&1; then \
	  echo "CONTROL FAILURE: a symlinked Makefile anchored the trust root to a foreign working directory" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evildir; exit 1; \
	elif grep -Fq 'SPOOFED-CWD' $$out \
	    || ! grep -Fq 'refusing foreign working directory ' $$out; then \
	  echo "CONTROL FAILURE: symlinked-Makefile attack was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evildir; exit 1; \
	fi; \
	linkparent=$$(mktemp -d /tmp/pq-extraction-symlinked-dir.XXXXXX); \
	ln -s "$$(pwd)" $$linkparent/link; \
	if ! ( cd $$linkparent/link && $(_FV_GNU_MAKE) --no-print-directory help >/dev/null 2>&1 ); then \
	  echo "CONTROL FAILURE: a symlinked invocation directory no longer resolves consistently" >&2; \
	  rm -rf $$out $$evildir $$linkparent; exit 1; \
	fi; \
	rm -rf $$out $$evildir $$linkparent; \
	echo "  ok: a symlinked Makefile in a foreign cwd is CAUGHT; a symlinked invocation dir still works"
	+@out=$$(mktemp /tmp/pq-extraction-hardlinked-makefile-selftest.XXXXXX); \
	evildir=$$(mktemp -d /tmp/pq-extraction-hardlinked-makefile.XXXXXX); \
	mkdir -p $$evildir/scripts; \
	printf 'print("ok")\n' >$$evildir/scripts/check_make_argv.py; \
	printf 'print("SPOOFED-CWD")\n' >$$evildir/scripts/check_hw_assumptions.py; \
	if ! ln "$$(pwd)/Makefile" $$evildir/Makefile; then \
	  echo "CONTROL FAILURE: could not create the hard-linked Makefile fixture" >&2; \
	  rm -rf $$out $$evildir; exit 1; \
	fi; \
	if ( cd $$evildir && $(_FV_GNU_MAKE) --no-print-directory verify-hw-assumptions ) >$$out 2>&1; then \
	  echo "CONTROL FAILURE: a hard-linked Makefile anchored the trust root to a foreign working directory" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evildir; exit 1; \
	elif grep -Fq 'SPOOFED-CWD' $$out \
	    || ! grep -Fq 'refusing multiply-linked verification Makefile ' $$out; then \
	  echo "CONTROL FAILURE: hard-linked-Makefile attack was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evildir; exit 1; \
	fi; \
	rm -rf $$out $$evildir; \
	echo "  ok: a hard-linked Makefile in a foreign cwd is CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-metachar-selftest.XXXXXX); \
	evilbase=$$(mktemp -d /tmp/pq-extraction-metachar.XXXXXX); \
	evildir="$$evilbase/q'x"; \
	mkdir -p "$$evildir/scripts"; \
	printf 'print("ok")\n' >"$$evildir/scripts/check_make_argv.py"; \
	printf 'print("SPOOFED-CWD")\n' >"$$evildir/scripts/check_hw_assumptions.py"; \
	if ! ln "$$(pwd)/Makefile" "$$evildir/Makefile"; then \
	  echo "CONTROL FAILURE: could not create the metachar-path Makefile fixture" >&2; \
	  rm -rf $$out $$evilbase; exit 1; \
	fi; \
	if ( cd "$$evildir" && $(_FV_GNU_MAKE) --no-print-directory verify-hw-assumptions ) >$$out 2>&1; then \
	  echo "CONTROL FAILURE: a single-quote path component defeated the trust-root guards" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilbase; exit 1; \
	elif grep -Fq 'SPOOFED-CWD' $$out \
	    || ! grep -Fq 'refusing verification Makefile path containing a single quote' $$out; then \
	  echo "CONTROL FAILURE: metachar-path attack was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilbase; exit 1; \
	fi; \
	rm -rf $$out $$evilbase; \
	echo "  ok: a single-quote path component is rejected before any shell interpolation"
	+@out=$$(mktemp /tmp/pq-extraction-lake-override-selftest.XXXXXX); \
	if /usr/bin/env LAKE=/bin/true $(_FV_GNU_MAKE) --no-print-directory \
	    verify-build >$$out 2>&1; then \
	  echo "CONTROL FAILURE: inherited LAKE suppressed the Lean build gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-overridden LAKE (origin environment)' $$out; then \
	  echo "CONTROL FAILURE: inherited LAKE was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory LAKE=/bin/true \
	    verify-build >$$out 2>&1; then \
	  echo "CONTROL FAILURE: command-line LAKE suppressed the Lean build gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-overridden LAKE (origin command line)' $$out; then \
	  echo "CONTROL FAILURE: command-line LAKE was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: inherited and command-line LAKE overrides are CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-lake-path-selftest.XXXXXX); \
	evilbin=$$(mktemp -d /tmp/pq-lake-path-planted.XXXXXX); \
	printf '#!/bin/sh\necho SPOOFED-LAKE\n' >$$evilbin/lake; \
	chmod +x $$evilbin/lake; \
	if ! PATH="$$evilbin:/usr/bin:/bin" $(_FV_GNU_MAKE) --no-print-directory \
	    _verify-lake-path-self-test >$$out 2>&1; then \
	  echo "CONTROL FAILURE: lake-path print target did not run" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilbin; exit 1; \
	elif grep -Fq 'SPOOFED-LAKE' $$out; then \
	  echo "CONTROL FAILURE: LAKE resolved through the caller PATH to a planted tool" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilbin; exit 1; \
	elif ! lake_line=$$(sed -n 's/^lake=//p' $$out) \
	    || ! elan_line=$$(sed -n 's/^elan=//p' $$out) \
	    || [ -z "$$lake_line" ] || [ "$$lake_line" != "$$elan_line" ]; then \
	  echo "CONTROL FAILURE: LAKE is not pinned to the password-database elan shim" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilbin; exit 1; \
	fi; \
	rm -rf $$out $$evilbin; \
	echo "  ok: LAKE ignores a PATH-planted lake and stays on the pinned elan shim"
	+@out=$$(mktemp /tmp/pq-extraction-elan-root-selftest.XXXXXX); \
	evilroot=$$(mktemp -d /tmp/pq-elan-root-planted.XXXXXX); \
	if ! ELAN_HOME="$$evilroot" HOME="$$evilroot" $(_FV_GNU_MAKE) --no-print-directory \
	    _verify-lake-path-self-test >$$out 2>&1; then \
	  echo "CONTROL FAILURE: lake-path print target did not run" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilroot; exit 1; \
	elif ! elan_home_line=$$(sed -n 's/^elan_home=//p' $$out) \
	    || ! home_line=$$(sed -n 's/^home=//p' $$out) \
	    || ! pw_line=$$(sed -n 's/^pw_home=//p' $$out) \
	    || [ -z "$$pw_line" ] || [ "$$elan_home_line" != "$$pw_line/.elan" ] \
	    || [ "$$home_line" != "$$pw_line" ]; then \
	  echo "CONTROL FAILURE: ELAN_HOME/HOME stayed caller-mutable for evidence recipes" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilroot; exit 1; \
	fi; \
	if /usr/bin/env ELAN_TOOLCHAIN=anything $(_FV_GNU_MAKE) --no-print-directory \
	    _verify-lake-path-self-test >$$out 2>&1; then \
	  echo "CONTROL FAILURE: a caller-set ELAN_TOOLCHAIN selected the evidence toolchain" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilroot; exit 1; \
	elif ! grep -Fq 'refusing caller-set ELAN_TOOLCHAIN ' $$out; then \
	  echo "CONTROL FAILURE: ELAN_TOOLCHAIN was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evilroot; exit 1; \
	fi; \
	rm -rf $$out $$evilroot; \
	echo "  ok: ELAN_HOME/HOME are force-pinned for recipes and ELAN_TOOLCHAIN is CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-goal-executor-selftest.XXXXXX); \
	if $(_FV_GNU_MAKE) --no-print-directory MAKECMDGOALS=not-guarded MAKE=/bin/true _verify-extraction-regen-loop >$$out 2>&1; then \
	  echo "CONTROL FAILURE: spoofed MAKECMDGOALS suppressed the recursive-executor guard" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-overridden MAKECMDGOALS ' $$out; then \
	  echo "CONTROL FAILURE: executor-side MAKECMDGOALS spoof was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: executor-side MAKECMDGOALS spoof is CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-goal-workspace-selftest.XXXXXX); \
	if $(_FV_GNU_MAKE) --no-print-directory MAKECMDGOALS=not-guarded EXTRACTION_TMP_ROOT=/tmp/pq-caller-controlled extract-sphincs-adrs >$$out 2>&1; then \
	  echo "CONTROL FAILURE: spoofed MAKECMDGOALS enabled a caller-selected extraction workspace" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-overridden MAKECMDGOALS ' $$out; then \
	  echo "CONTROL FAILURE: workspace-side MAKECMDGOALS spoof was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: workspace-side MAKECMDGOALS spoof is CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-indirect-workspace-selftest.XXXXXX); \
	if ! $(_FV_GNU_MAKE) --no-print-directory \
	    EXTRACTION_TMP_ROOT=/tmp/pqsigner-extract.AttackerChosen \
	    _verify-extraction-alias-delegation-self-test >$$out 2>&1; then \
	  echo "CONTROL FAILURE: indirect extraction alias did not expand safely" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif grep -Fq '/tmp/pqsigner-extract.AttackerChosen' $$out; then \
	  echo "CONTROL FAILURE: indirect extraction alias retained a caller-selected workspace" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq '_extract-sphincs-adrs-impl' $$out; then \
	  echo "CONTROL FAILURE: indirect extraction alias bypassed the fixed private delegator" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if ! sed -n '/^$$(_EXTRACTION_TARGETS):$$/{n;p;}' Makefile \
	    | grep -Fqx '	@$$(call _fv_extraction_delegate,$$@)'; then \
	  echo "CONTROL FAILURE: the public extract-* recipe no longer delegates through the scrubbed define" >&2; \
	  sed -n '/^$$(_EXTRACTION_TARGETS):$$/,+2p' Makefile >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: indirect extraction alias reaches the fixed private delegator and its recipe stays bound to it"
	+@out=$$(mktemp /tmp/pq-extraction-shell-workspace-selftest.XXXXXX); \
	if ! /usr/bin/env -u MAKEFLAGS -u MFLAGS -u GNUMAKEFLAGS -u MAKEFILES \
	    $(_FV_GNU_MAKE) --no-print-directory \
	    _verify-extraction-workspace-inner-self-test _FV_EXTRACTION_INNER=1 \
	    >$$out 2>&1; then \
	  echo "CONTROL FAILURE: shell-owned workspace allocator did not run" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	root=$$(sed -n 's/^private=\([^ ]*\) mode=700$$/\1/p' $$out); \
	if [[ ! "$$root" =~ ^/tmp/pqsigner-extract\.[A-Za-z0-9]{8}$$ ]] \
	    || [ -e "$$root" ]; then \
	  echo "CONTROL FAILURE: private workspace was not mode 0700 or was not cleaned" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: shell owns a fresh mode-0700 workspace and cleans that exact root"
	+@out=$$(mktemp /tmp/pq-extraction-makefiles-selftest.XXXXXX); \
	startup=$$(mktemp /tmp/pq-extraction-startup.XXXXXX.mk); \
	printf '.IGNORE:\n' >$$startup; \
	if /usr/bin/env MAKEFILES=$$startup $(_FV_GNU_MAKE) --no-print-directory \
	    _verify-extraction-regen-wrong-waiver-self-test >$$out 2>&1; then \
	  echo "CONTROL FAILURE: MAKEFILES injected .IGNORE into authoritative replay" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out $$startup; exit 1; \
	elif ! grep -Fq 'refusing inherited MAKEFILES startup files ' $$out; then \
	  echo "CONTROL FAILURE: MAKEFILES startup injection was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out $$startup; exit 1; \
	fi; \
	printf 'override _FV_EXTRACTION_TMP_ROOT_extract_sphincs_adrs := /tmp/pqsigner-extract.CCCCCCCC\n' >$$startup; \
	if /usr/bin/env MAKEFILES=$$startup $(_FV_GNU_MAKE) --no-print-directory \
	    _verify-extraction-alias-delegation-self-test >$$out 2>&1; then \
	  echo "CONTROL FAILURE: MAKEFILES preseeded an extraction workspace" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out $$startup; exit 1; \
	elif grep -Fq '/tmp/pqsigner-extract.CCCCCCCC' $$out \
	    || ! grep -Fq 'refusing inherited MAKEFILES startup files ' $$out; then \
	  echo "CONTROL FAILURE: MAKEFILES workspace injection was not fail-closed" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out $$startup; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory \
	    --eval='override _FV_EXTRACTION_TMP_ROOT_extract_sphincs_adrs := /tmp/pqsigner-extract.AAAAAAAA' \
	    _verify-extraction-alias-delegation-self-test >$$out 2>&1; then \
	  echo "CONTROL FAILURE: --eval preseeded an extraction workspace" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out $$startup; exit 1; \
	elif grep -Fq '/tmp/pqsigner-extract.AAAAAAAA' $$out \
	    || ! grep -Fq 'refusing Make --eval for verification Makefile' $$out; then \
	  echo "CONTROL FAILURE: --eval workspace injection was not fail-closed" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out $$startup; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory -f Makefile -f /dev/null \
	    _verify-extraction-alias-delegation-self-test >$$out 2>&1; then \
	  echo "CONTROL FAILURE: a trailing -f makefile escaped the complete-list guard" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out $$startup; exit 1; \
	elif ! grep -Fq 'multiple-makefiles' $$out; then \
	  echo "CONTROL FAILURE: a trailing -f makefile was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out $$startup; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory -f Makefile -f /dev/null \
	    verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: a trailing -f makefile escaped the verification-gate guard" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out $$startup; exit 1; \
	elif ! grep -Fq 'multiple-makefiles' $$out; then \
	  echo "CONTROL FAILURE: a trailing -f verification makefile was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out $$startup; exit 1; \
	fi; \
	printf 'override MAKEFILE_LIST := Makefile\nverify-extracted:\n\t@echo SPOOFED\n' >$$startup; \
	if $(_FV_GNU_MAKE) --no-print-directory -f Makefile -f $$startup \
	    verify-extracted >$$out 2>&1; then \
	  echo "CONTROL FAILURE: a trailing makefile rewrote MAKEFILE_LIST and replaced a gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out $$startup; exit 1; \
	elif grep -Fq 'SPOOFED' $$out \
	    || ! grep -Fq 'multiple-makefiles' $$out; then \
	  echo "CONTROL FAILURE: mutable MAKEFILE_LIST attack was not rejected before parsing" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out $$startup; exit 1; \
	fi; \
	rm -f $$out $$startup; \
	echo "  ok: MAKEFILES/eval/trailing--f parser channels cannot suppress verification or extraction"
	+@out=$$(mktemp /tmp/pq-extraction-mflist-selftest.XXXXXX); \
	evildir=$$(mktemp -d /tmp/pq-extraction-evil-first.XXXXXX); \
	mkdir -p $$evildir/scripts; \
	printf 'print("ok")\n' >$$evildir/scripts/check_make_argv.py; \
	printf 'override MAKEFILE_LIST := %s/Makefile\n.IGNORE:\n' "$$evildir" >$$evildir/first.mk; \
	if $(_FV_GNU_MAKE) --no-print-directory -f $$evildir/first.mk -f Makefile \
	    verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: an earlier -f makefile froze MAKEFILE_LIST and bypassed the parser guards" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evildir; exit 1; \
	elif ! grep -Fq 'refusing caller-mutated MAKEFILE_LIST ' $$out; then \
	  echo "CONTROL FAILURE: earlier--f MAKEFILE_LIST override was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evildir; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory MAKEFILE_LIST=$$evildir/Makefile -f Makefile \
	    verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: a command-line MAKEFILE_LIST assignment bypassed the parser guards" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evildir; exit 1; \
	elif ! grep -Fq 'refusing caller-mutated MAKEFILE_LIST ' $$out; then \
	  echo "CONTROL FAILURE: command-line MAKEFILE_LIST manipulation was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evildir; exit 1; \
	fi; \
	rm -rf $$out $$evildir; \
	echo "  ok: earlier--f override and command-line MAKEFILE_LIST manipulation are CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-foreign-cwd-selftest.XXXXXX); \
	evildir=$$(mktemp -d /tmp/pq-extraction-foreign-cwd.XXXXXX); \
	realmake=$$(pwd)/Makefile; \
	mkdir -p $$evildir/scripts; \
	printf 'print("ok")\n' >$$evildir/scripts/check_make_argv.py; \
	printf 'override MAKEFILE_LIST := %s/Makefile\nverify-extracted:\n\t@echo SPOOFED-GATE\n' "$$evildir" >$$evildir/evil.mk; \
	if ( cd $$evildir && $(_FV_GNU_MAKE) --no-print-directory \
	    -f $$realmake -f $$evildir/evil.mk verify-extracted ) >$$out 2>&1; then \
	  echo "CONTROL FAILURE: foreign-cwd planted checker + trailing override spoofed a gate" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evildir; exit 1; \
	elif grep -Fq 'SPOOFED-GATE' $$out \
	    || ! grep -Fq 'refusing foreign working directory ' $$out; then \
	  echo "CONTROL FAILURE: foreign-cwd checker-spoof attack was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evildir; exit 1; \
	fi; \
	if ( cd $$evildir && $(_FV_GNU_MAKE) --no-print-directory \
	    -f $$realmake verify-extracted ) >$$out 2>&1; then \
	  echo "CONTROL FAILURE: a foreign working directory reached the evidence recipes" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evildir; exit 1; \
	elif ! grep -Fq 'refusing foreign working directory ' $$out; then \
	  echo "CONTROL FAILURE: foreign cwd was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -rf $$out $$evildir; exit 1; \
	fi; \
	rm -rf $$out $$evildir; \
	echo "  ok: foreign-cwd checker spoofing and foreign working directories are CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-root-override-selftest.XXXXXX); \
	if $(_FV_GNU_MAKE) --no-print-directory PQLEAN=/tmp/fake verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: caller-overridden PQLEAN reached the authoritative extraction replay" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-overridden PQLEAN ' $$out; then \
	  echo "CONTROL FAILURE: PQLEAN override was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory EXTRACTED_DIR=/tmp/fake verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: caller-overridden EXTRACTED_DIR relocated the closure evidence root" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-overridden EXTRACTED_DIR ' $$out; then \
	  echo "CONTROL FAILURE: EXTRACTED_DIR override was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory REPO_ROOT=/tmp/fake verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: caller-overridden REPO_ROOT relocated the replayed Rust sources" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-overridden REPO_ROOT ' $$out; then \
	  echo "CONTROL FAILURE: REPO_ROOT override was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	if $(_FV_GNU_MAKE) --no-print-directory LEAN_DIR=/tmp/fake verify-hw-assumptions >$$out 2>&1; then \
	  echo "CONTROL FAILURE: caller-overridden LEAN_DIR relocated the ledger live dump" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-overridden LEAN_DIR ' $$out; then \
	  echo "CONTROL FAILURE: LEAN_DIR override was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: caller-overridden PQLEAN/EXTRACTED_DIR/REPO_ROOT/LEAN_DIR are CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-make-override-selftest.XXXXXX); \
	if $(_FV_GNU_MAKE) --no-print-directory MAKE=/bin/true _verify-extraction-regen-loop >$$out 2>&1; then \
	  echo "CONTROL FAILURE: caller-overridden MAKE bypassed authoritative extraction replay" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-overridden MAKE ' $$out; then \
	  echo "CONTROL FAILURE: MAKE override was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: caller-overridden MAKE is CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-make-command-override-selftest.XXXXXX); \
	if $(_FV_GNU_MAKE) --no-print-directory MAKE_COMMAND=/bin/true _verify-extraction-regen-loop >$$out 2>&1; then \
	  echo "CONTROL FAILURE: caller-overridden MAKE_COMMAND bypassed authoritative extraction replay" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing caller-overridden MAKE_COMMAND ' $$out; then \
	  echo "CONTROL FAILURE: MAKE_COMMAND override was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: caller-overridden MAKE_COMMAND is CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-make-argv0-selftest.XXXXXX); \
	if ! /usr/bin/bash -c 'exec -a /tmp/pq-caller-picked-make /usr/bin/make --no-print-directory _verify-extraction-make-path-self-test' >$$out 2>&1; then \
	  echo "CONTROL FAILURE: forged Make argv[0] control did not run" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fxq 'trusted=/usr/bin/make' $$out || ! grep -Fxq 'ambient=/tmp/pq-caller-picked-make' $$out; then \
	  echo "CONTROL FAILURE: authoritative executor is not independent of caller-controlled Make argv[0]" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: forged Make argv[0] cannot redirect the authoritative executor"
	+@out=$$(mktemp /tmp/pq-extraction-multigoal-selftest.XXXXXX); \
	if $(_FV_GNU_MAKE) --no-print-directory extract-sphincs-adrs extract-aa-userop >$$out 2>&1; then \
	  echo "CONTROL FAILURE: multiple extract targets shared one Make invocation" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'refusing multiple extract-* targets' $$out; then \
	  echo "CONTROL FAILURE: multi-goal extraction was rejected for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: multi-goal extraction workspace reuse is CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-waiver-selftest.XXXXXX); \
	if $(_FV_GNU_MAKE) --no-print-directory _verify-extraction-regen-loop-self-test >$$out 2>&1; then \
	  echo "CONTROL FAILURE: waived extraction unexpectedly re-extracted but aggregate replay exited zero" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -q 'UNEXPECTED-FRESH' $$out; then \
	  echo "CONTROL FAILURE: recovered-waiver negative control failed for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: unexpectedly fresh waived extraction is CAUGHT"
	+@out=$$(mktemp /tmp/pq-extraction-wrong-waiver-selftest.XXXXXX); \
	if $(_FV_GNU_MAKE) --no-print-directory _verify-extraction-regen-wrong-waiver-self-test >$$out 2>&1; then \
	  echo "CONTROL FAILURE: wrong-stage waived extraction failure was accepted" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	elif ! grep -Fq 'WRONG-WAIVER-FAILURE' $$out; then \
	  echo "CONTROL FAILURE: wrong-stage waiver control failed for the wrong reason" >&2; \
	  sed -n '1,120p' $$out >&2; rm -f $$out; exit 1; \
	fi; \
	rm -f $$out; \
	echo "  ok: wrong-stage waived extraction failure is CAUGHT"

override define _run_extraction_regen_loop
	@echo "=== F1 extraction regen: re-running charon->aeneas + diff for every registry target ==="
	+@fail=0; \
	for t in $$($(_FV_PYTHON3) -c "import json;print(' '.join(e['target'] for e in json.load(open('extraction_registry.json'))['entries'] if e.get('fresh',True)))"); do \
	  if $(1) $$t >/dev/null 2>&1; then echo "  fresh: $$t"; else echo "  DRIFT: $$t (re-extract/re-prove/re-pin via --update $$t)"; fail=1; fi; \
	done; \
	for t in $$($(_FV_PYTHON3) -c "import json;print(' '.join(e['target'] for e in json.load(open('extraction_registry.json'))['entries'] if not e.get('fresh',True)))"); do \
	  waiver_out=$$(mktemp /tmp/pq-extraction-waiver-stage.XXXXXX); \
	  if $(1) $$t >$$waiver_out 2>&1; then \
	    echo "  UNEXPECTED-FRESH (waived entry re-extracts! promote to fresh + --update $$t): $$t"; fail=1; \
	  elif [ "$$t" = "extract-tx-merkle" ] && grep -Fq '$(_TX_MERKLE_WAIVER_MARKER)' $$waiver_out; then \
	    echo "  waived-stale (expected Aeneas stage): $$t"; \
	  else \
	    echo "  WRONG-WAIVER-FAILURE: $$t failed outside its specifically waived generator stage"; \
	    sed -n '1,80p' $$waiver_out; fail=1; \
	  fi; \
	  rm -f $$waiver_out; \
	done; \
	if [ $$fail != 0 ]; then echo "FAIL: a fresh extraction drifted or a waived extraction unexpectedly recovered"; exit 1; fi; \
	echo "OK: all fresh extractions re-extract cleanly; waived entries unchanged"
endef

# The authoritative target has no caller-selectable executor. The only mock is
# isolated in the self-test-only helper, while both paths share the same loop.
_verify-extraction-regen-loop:
	$(call _run_extraction_regen_loop,$(_FV_GNU_MAKE))

_verify-extraction-regen-loop-self-test:
	$(call _run_extraction_regen_loop,/bin/true)

# Succeeds for every fresh target and fails only for the waived target, without
# the required generator-stage marker.  The aggregate loop must reject it.
_verify-extraction-regen-wrong-waiver-self-test:
	$(call _run_extraction_regen_loop,/usr/bin/test extract-tx-merkle !=)

_verify-extraction-make-path-self-test:
	@printf '%s\n' 'trusted=$(_FV_GNU_MAKE)' 'ambient=$(MAKE_COMMAND)'

_verify-lake-path-self-test:
	@printf '%s\n' 'lake=$(LAKE)' 'elan=$(_FV_USER_HOME)/.elan/bin/lake' 'elan_home=$(ELAN_HOME)' 'home=$(HOME)' 'pw_home=$(_FV_USER_HOME)'

# roadmap T1.3 (ii) — extracted-Lean vs shipped-Rust DIFFERENTIAL gate.
# The `extract-*` regen-diff targets catch a Rust change that was not re-extracted;
# they do NOT catch a CONSISTENTLY-WRONG Charon/Aeneas translation. This gate
# EXECUTES the extracted Lean functions on vectors whose EXPECTED outputs were
# produced by running the SHIPPED Rust (`fw-manifest/tests/gen_extract_vectors.rs`)
# and fails on any divergence. Includes a permanent negative control. CORPUS
# evidence (tier C) — shrinks the Charon faithfulness TCB on tested inputs, not a ∀.
# Covered: fw_manifest::signed_preimage (ExtractDiffVectors) +
# pqsigner_tx_core::eip1559::u256_format_decimal (FormatDecimalDiffVectors, M8).
#   make verify-extract-differential          replay committed (Rust-generated) vectors
#   make verify-extract-differential GEN=1    re-execute the Rust to regenerate them
verify-extract-differential: ## Extracted-Lean vs shipped-Rust differential
ifeq ($(GEN),1)
	@echo "=== regenerating EXPECTED outputs from the SHIPPED Rust (ground truth) ==="
	@cd $(REPO_ROOT) && cargo test -p fw-manifest --test gen_extract_vectors --release -- --nocapture 2>&1 \
	  | grep -E 'gen_extract_vectors:|test result'
endif
	@cd $(EXTRACTED_DIR) && $(LAKE) build Extracted.ExtractDiffVectors Extracted.FormatDecimalDiffVectors \
	  Extracted.FwManifest.Funs Extracted.FormatDecimal.Funs 2>&1 | tail -1
	@cd $(EXTRACTED_DIR) && $(LAKE) env lean Extracted/ExtractDiffCheck.lean

verify-extracted: ## S33 Aeneas-extracted build + axiom-discipline
	@cd $(EXTRACTED_DIR) && $(LAKE) build 2>&1 | tee /tmp/pq_extracted_build.out
	@if grep -E "Extracted/[^ ]*\.lean:.*declaration uses" /tmp/pq_extracted_build.out; then \
	  echo "FAIL: an Extracted/ declaration uses 'sorry' (incomplete proof)"; exit 1; fi
	@# #676 (2026-08-20): project-wide axiom INVENTORY census — the closure
	@# gate below only sees axioms CONSUMED by manifest-listed headlines, so
	@# an unconsumed/planted `axiom` anywhere under Extracted/ was invisible.
	@# The census pins the inventory to the 3 disclosed hash postulates +
	@# the quarantined NegativeControl.Evil (and checks the quarantine stays
	@# unimported). Comment-stripped, fail-closed, no lake needed.
	@echo "=== Extracted exact source and elaborated axiom census ==="
	@/usr/bin/bash scripts/lint_extracted_axiom_census.sh
	@$(_FV_PYTHON3) scripts/test_axiom_inventory.py
	@echo "=== Axiom closure of the §33 theorems (expect propext, Classical.choice, Quot.sound + the three disclosed hash-boundary postulates: keccak256_pure, sha256_pure_bytes, hmac_sha512_pure_bytes — NB sha256_pure is a kernel THEOREM, not an axiom) ==="
	@cd $(EXTRACTED_DIR) && $(LAKE) env lean Extracted/AxiomCheck.lean 2>&1 | tee /tmp/pq_axiomcheck.out
	@# F3 (2026-07-16): EXACT PER-HEADLINE axiom allowlist, not just a `grep sorryAx`.
	@# A consumed `axiom Evil : False` prints `depends on axioms: [Evil]` — no
	@# `sorryAx` substring — so the old grep let it pass. The manifest gate is
	@# bidirectional and fails closed: an UNLISTED headline (rogue/undisclosed
	@# theorem), a MISSING headline (silently dropped / dump truncated), or a
	@# closure carrying an undisclosed axiom all fail. Manifest =
	@# extracted/axiom_closure_manifest.txt (57 kernel-only + 4 sha256_pure_bytes
	@# + 1 sha256+hmac + 4 keccak256_pure = 66 headlines).
	@$(_FV_PYTHON3) scripts/check_axiom_closure.py --manifest $(EXTRACTED_DIR)/axiom_closure_manifest.txt /tmp/pq_axiomcheck.out
	@# WIRED-IN NEGATIVE CONTROL: the Evil:False canary MUST be rejected. A *pass*
	@# of the checker here is a *failure* of the meta-gate (the gate is toothless).
	@echo "=== NEGATIVE CONTROL: a consumed axiom Evil:False MUST be rejected by the closure gate ==="
	@cd $(EXTRACTED_DIR) && $(LAKE) env lean Extracted/AxiomCheckNegativeControl.lean > /tmp/pq_axiomcheck_neg.out 2>&1 || true
	@if $(_FV_PYTHON3) scripts/check_axiom_closure.py --manifest $(EXTRACTED_DIR)/axiom_closure_manifest.txt /tmp/pq_axiomcheck_neg.out >/dev/null 2>&1; then \
	  echo "FAIL: the Evil:False negative control PASSED the closure gate — the gate is VACUOUS"; exit 1; \
	else echo "OK: closure gate correctly REJECTS the Evil:False canary (per-headline allowlist enforcement is live)"; fi
	@# WIRED-IN NEGATIVE CONTROL 2: a SHRUNK closure (a pinned axiom silently
	@# dropped from one headline while every name stays listed) MUST be rejected
	@# — the manifest pins the exact non-kernel closure, not a superset of it.
	@echo "=== NEGATIVE CONTROL: an under-reported (shrunk) headline closure MUST be rejected by the closure gate ==="
	@$(_FV_PYTHON3) -c "import re; t=open('/tmp/pq_axiomcheck.out').read(); ax='sha256_pure_bytes'; i=t.find(ax); assert i>=0, 'control setup: expected a pinned axiom in the live dump'; t2=t[:i]+t[i:].replace(ax,'',1); t2=re.sub(r',\s*,',',',t2); t2=re.sub(r'\[\s*,','[',t2); t2=re.sub(r',\s*\]',']',t2); open('/tmp/pq_axiomcheck_shrunk.out','w').write(t2)"
	@if $(_FV_PYTHON3) scripts/check_axiom_closure.py --manifest $(EXTRACTED_DIR)/axiom_closure_manifest.txt /tmp/pq_axiomcheck_shrunk.out >/tmp/pq_axiomcheck_shrunk.msg 2>&1; then \
	  echo "FAIL: the shrunk-closure negative control PASSED the closure gate — the pin is superset-only"; exit 1; \
	elif ! grep -Fq 'no longer carries pinned axiom' /tmp/pq_axiomcheck_shrunk.msg; then \
	  echo "FAIL: shrunk closure was rejected for the WRONG reason"; cat /tmp/pq_axiomcheck_shrunk.msg; exit 1; \
	else echo "OK: closure gate correctly REJECTS an under-reported (shrunk) headline closure"; fi
	@# WIRED-IN NEGATIVE CONTROL 3: a DUPLICATED dump record (a rogue first
	@# record hidden beneath a benign same-name record) MUST be rejected —
	@# last-wins parsing would launder it.
	@echo "=== NEGATIVE CONTROL: a duplicated dump record MUST be rejected by the closure gate ==="
	@$(_FV_PYTHON3) -c "import re; t=open('/tmp/pq_axiomcheck.out').read(); m=re.search(r\"\x27([^\x27]+)\x27 depends on axioms\", t); assert m, 'control setup: no depends-record in the live dump'; open('/tmp/pq_axiomcheck_dup.out','w').write(\"'%s' depends on axioms: [Evil]\n\" % m.group(1) + t)"
	@if $(_FV_PYTHON3) scripts/check_axiom_closure.py --manifest $(EXTRACTED_DIR)/axiom_closure_manifest.txt /tmp/pq_axiomcheck_dup.out >/tmp/pq_axiomcheck_dup.msg 2>&1; then \
	  echo "FAIL: the duplicate-record negative control PASSED the closure gate — last-wins overwrite is live"; exit 1; \
	elif ! grep -Fq 'duplicate dump record' /tmp/pq_axiomcheck_dup.msg; then \
	  echo "FAIL: duplicate record was rejected for the WRONG reason"; cat /tmp/pq_axiomcheck_dup.msg; exit 1; \
	else echo "OK: closure gate correctly REJECTS a duplicated dump record"; fi
	@echo "OK: extracted/ axiom-discipline gate passed — per-headline closure verified, no sorryAx, negative control has teeth"
	@echo "NB: FormatDecimalSpec (M7 WYSIWYS, ~42 GB kernel-TC) is CARVED OUT of this"
	@echo "    16 GB-safe gate — verify it with 'make verify-extracted-heavy' on ≥48 GB RAM."

# ⚠ HIGH-MEMORY carve-out. Kernel-typechecking the single
# `FormatDecimalSpec.format_decimal_spec` declaration (the end-to-end WYSIWYS
# `U256::format_decimal` WP-monad composition) peaks at ~42 GB RSS / ~1470 s
# (measured 2026-07-07 with `/usr/bin/time -v`; profiler confirms it is the ONLY
# `[Kernel]` decl over threshold, i.e. a genuine single-declaration cost, not
# accumulation — a per-bind peel was attempted and reverted as ineffective). It
# is a REAL `qed` (no sorry/admit; closure [propext, Classical.choice,
# Quot.sound]) — only its build SCHEDULING is carved out of the default gate so
# CI stays green on a 16 GB runner. Run this on a machine with ≥48 GB RAM (local
# dev, or a high-memory CI job); the default `verify-extracted` never builds it.
verify-extracted-heavy: ## S33 FormatDecimalSpec M7 (~42 GB kernel-TC) — carved out of the default gate; run on ≥48 GB RAM
	@echo "=== ⚠ HIGH-MEMORY: format_decimal_spec kernel-TC peaks ~42 GB RSS (2026-07-07). Needs ≥48 GB RAM. ==="
	@cd $(EXTRACTED_DIR) && $(LAKE) build ExtractedFormatDecimalHeavy 2>&1 | tee /tmp/pq_extracted_heavy_build.out
	@if grep -E "Extracted/[^ ]*\.lean:.*declaration uses" /tmp/pq_extracted_heavy_build.out; then \
	  echo "FAIL: FormatDecimalSpec declaration uses 'sorry' (incomplete proof)"; exit 1; fi
	@echo "=== Axiom closure of the M7 WYSIWYS theorems (expect propext, Classical.choice, Quot.sound) ==="
	@cd $(EXTRACTED_DIR) && $(LAKE) env lean Extracted/AxiomCheckFormatDecimal.lean 2>&1 | tee /tmp/pq_axiomcheck_fd.out
	@# F3 (2026-07-16): the 3 M7 WYSIWYS theorems close over EXACTLY the kernel
	@# triple (no hash axiom). Enforce the exact three theorem identities and
	@# their exact per-theorem closures rather than only counting records.
	@$(_FV_PYTHON3) scripts/check_axiom_closure.py --manifest $(EXTRACTED_DIR)/axiom_closure_format_decimal_manifest.txt /tmp/pq_axiomcheck_fd.out
	@echo "OK: format_decimal M7 axiom-discipline gate passed — kernel-only closure over exactly 3 headlines"

_extract-sphincs-adrs-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/sphincs-c10 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize \
	  --start-from 'sphincs_c10::address' --dest-file $${EXTRACTION_TMP_ROOT}/adrs.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/out && mkdir -p $${EXTRACTION_TMP_ROOT}/out
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/out $${EXTRACTION_TMP_ROOT}/adrs.llbc
	@diff -u $(EXTRACTED_DIR)/Extracted/Adrs.lean $${EXTRACTION_TMP_ROOT}/out/Adrs.lean \
	  && echo "OK: committed extraction matches the current Rust" \
	  || { echo "DRIFT: address.rs changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-sphincs-adrs $${EXTRACTION_TMP_ROOT}/out

_extract-aa-userop-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/aa && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sha3 \
	  --opaque 'pqsigner_tx_core::hash' \
	  --start-from 'pqsigner_aa::userop::compute_user_op_hash' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/userop.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/uout && mkdir -p $${EXTRACTION_TMP_ROOT}/uout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/uout -split-files $${EXTRACTION_TMP_ROOT}/userop.llbc
	@sed 's/import Userop\./import Extracted.UserOp./' $${EXTRACTION_TMP_ROOT}/uout/Funs.lean > $${EXTRACTION_TMP_ROOT}/uout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/UserOp/Funs.lean $${EXTRACTION_TMP_ROOT}/uout/Funs.fixed.lean \
	  && echo "OK: committed userop extraction matches the current Rust" \
	  || { echo "DRIFT: aa/userop.rs changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-aa-userop $${EXTRACTION_TMP_ROOT}/uout $${EXTRACTION_TMP_ROOT}/uout/Funs.fixed.lean

_extract-fors-index-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/sphincs-c10 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize \
	  --start-from 'sphincs_c10::fors::extract_ht_index' \
	  --start-from 'sphincs_c10::fors::extract_fors_indices' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/fors.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/fout && mkdir -p $${EXTRACTION_TMP_ROOT}/fout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/fout -split-files $${EXTRACTION_TMP_ROOT}/fors.llbc
	@sed 's/import Fors\./import Extracted.Fors./' $${EXTRACTION_TMP_ROOT}/fout/Funs.lean > $${EXTRACTION_TMP_ROOT}/fout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/Fors/Funs.lean $${EXTRACTION_TMP_ROOT}/fout/Funs.fixed.lean \
	  && echo "OK: committed FORS extraction matches the current Rust" \
	  || { echo "DRIFT: fors.rs index path changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-fors-index $${EXTRACTION_TMP_ROOT}/fout $${EXTRACTION_TMP_ROOT}/fout/Funs.fixed.lean

# §33 P1 — guard that the vendored copies in extracted/Extracted/ stay
# faithful to the SphincsCVerify sources they vendor (the version bridge's
# trust rests on the verbatim transcription). Compares the named ByteVec/Adrs
# definitions (SpecVendored.lean) and the FIPS 180-4 SHA-256 definitions
# (Sha256Vendored.lean, source Spec/Sha256Impl.lean).
.PHONY: verify-spec-vendored-fidelity
verify-spec-vendored-fidelity: ## Vendored-spec fidelity check
	@$(_FV_PYTHON3) scripts/check_vendored_spec.py

# §33 — AI-prover loop: drive a headless Claude agent to close ONE proof
# obligation, gated on the Lean kernel + axiom discipline. See
# ai-prover/ai_prove.sh. Usage:
#   make ai-prove MODULE=Extracted.Bits TARGET="Prove lor_eq_add_disjoint ..."
.PHONY: ai-prove
ai-prove:
	@ai-prover/ai_prove.sh "$(MODULE)" "$(TARGET)"

# §33 rank 3 — eip1271 byte-layout extraction (domain_separator + replay_safe_hash).
# keccak is opaque (the single keccak256_pure axiom); reuses UserOp/FunsExternal.
.PHONY: extract-aa-eip1271
_extract-aa-eip1271-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/aa && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sha3 \
	  --opaque 'pqsigner_tx_core::hash' \
	  --start-from 'pqsigner_aa::eip1271::replay_safe_hash' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/eip1271.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/eout && mkdir -p $${EXTRACTION_TMP_ROOT}/eout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/eout -split-files $${EXTRACTION_TMP_ROOT}/eip1271.llbc
	@sed 's/import Eip1271\./import Extracted.Eip1271./' $${EXTRACTION_TMP_ROOT}/eout/Funs.lean > $${EXTRACTION_TMP_ROOT}/eout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/Eip1271/Funs.lean $${EXTRACTION_TMP_ROOT}/eout/Funs.fixed.lean \
	  && echo "OK: committed eip1271 extraction matches the current Rust" \
	  || { echo "DRIFT: aa/eip1271.rs changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-aa-eip1271 $${EXTRACTION_TMP_ROOT}/eout $${EXTRACTION_TMP_ROOT}/eout/Funs.fixed.lean

# §33 rank 4 — wots::extract_digits (independent bit-extractor; proven = same
# closed-form window as read_bits_le). opaque sha2/zeroize like fors.
.PHONY: extract-wots-digits
_extract-wots-digits-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/sphincs-c10 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize \
	  --start-from 'sphincs_c10::wots::extract_digits' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/wots.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/wout && mkdir -p $${EXTRACTION_TMP_ROOT}/wout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/wout -split-files $${EXTRACTION_TMP_ROOT}/wots.llbc
	@sed 's/import Wots\./import Extracted.Wots./' $${EXTRACTION_TMP_ROOT}/wout/Funs.lean > $${EXTRACTION_TMP_ROOT}/wout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/Wots/Funs.lean $${EXTRACTION_TMP_ROOT}/wout/Funs.fixed.lean \
	  && echo "OK: committed wots extraction matches the current Rust" \
	  || { echo "DRIFT: sphincs-c10/src/wots.rs changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-wots-digits $${EXTRACTION_TMP_ROOT}/wout $${EXTRACTION_TMP_ROOT}/wout/Funs.fixed.lean

# §33 rank 7 — tx-core RLP bytes_to_u64 + bytes_to_u256 (canonical BE-int decode).
# into_iter is given a DEF (not axiom) in Extracted/Rlp/FunsExternal.lean.
.PHONY: extract-txcore-rlp
_extract-txcore-rlp-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/tx-core && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sha3 \
	  --start-from 'pqsigner_tx_core::rlp::bytes_to_u64' \
	  --start-from 'pqsigner_tx_core::rlp::bytes_to_u256' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/rlp.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/rout && mkdir -p $${EXTRACTION_TMP_ROOT}/rout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/rout -split-files $${EXTRACTION_TMP_ROOT}/rlp.llbc
	@sed 's/import Rlp\./import Extracted.Rlp./' $${EXTRACTION_TMP_ROOT}/rout/Funs.lean > $${EXTRACTION_TMP_ROOT}/rout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/Rlp/Funs.lean $${EXTRACTION_TMP_ROOT}/rout/Funs.fixed.lean \
	  && echo "OK: committed RLP extraction matches the current Rust" \
	  || { echo "DRIFT: tx-core/src/rlp.rs changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-txcore-rlp $${EXTRACTION_TMP_ROOT}/rout $${EXTRACTION_TMP_ROOT}/rout/Funs.fixed.lean

# §33 rank 12 — fw-manifest signed_preimage (75-byte frozen FW-signing layout).
.PHONY: extract-fwmanifest-preimage
_extract-fwmanifest-preimage-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/fw-manifest && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sphincs_c10 --opaque subtle \
	  --start-from 'fw_manifest::signed_preimage' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/fwman.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/fmout && mkdir -p $${EXTRACTION_TMP_ROOT}/fmout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/fmout -split-files $${EXTRACTION_TMP_ROOT}/fwman.llbc
	@sed 's/import Fwman\./import Extracted.FwManifest./' $${EXTRACTION_TMP_ROOT}/fmout/Funs.lean > $${EXTRACTION_TMP_ROOT}/fmout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/FwManifest/Funs.lean $${EXTRACTION_TMP_ROOT}/fmout/Funs.fixed.lean \
	  && echo "OK: committed fw-manifest extraction matches the current Rust" \
	  || { echo "DRIFT: fw-manifest/src/lib.rs changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-fwmanifest-preimage $${EXTRACTION_TMP_ROOT}/fmout $${EXTRACTION_TMP_ROOT}/fmout/Funs.fixed.lean

# §33 rank 10 — U256::saturating_mul_u64 (via the u256_saturating_mul_u64 wrapper;
# --start-from cannot target inherent-impl methods).
.PHONY: extract-u256-mul
_extract-u256-mul-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/tx-core && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sha3 \
	  --start-from 'pqsigner_tx_core::eip1559::u256_saturating_mul_u64' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/u256mul.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/mout && mkdir -p $${EXTRACTION_TMP_ROOT}/mout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/mout -split-files $${EXTRACTION_TMP_ROOT}/u256mul.llbc
	@sed 's/import U256mul\./import Extracted.U256Mul./' $${EXTRACTION_TMP_ROOT}/mout/Funs.lean > $${EXTRACTION_TMP_ROOT}/mout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/U256Mul/Funs.lean $${EXTRACTION_TMP_ROOT}/mout/Funs.fixed.lean \
	  && echo "OK: committed u256-mul extraction matches the current Rust" \
	  || { echo "DRIFT: tx-core/src/eip1559.rs changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-u256-mul $${EXTRACTION_TMP_ROOT}/mout $${EXTRACTION_TMP_ROOT}/mout/Funs.fixed.lean

# §33 — U256::format_decimal (via the u256_format_decimal wrapper; the four
# fmt_* phase helpers exist BECAUSE the fused body hits an aeneas
# `Unimplemented` — see the note inside format_decimal). The Types.lean dedup:
# this extraction re-defines eip1559.U256, whose canonical home is
# Extracted/U256Mul/Types.lean, so only Funs.lean is committed; the freshly
# generated Types is byte-compared with that canonical module and the Funs
# import is rewritten to it (a duplicate def fails the lake
# build LOUDLY — 'environment already contains ...' — so the dedup cannot
# silently drift).
.PHONY: extract-format-decimal
_extract-format-decimal-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/tx-core && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sha3 \
	  --start-from 'pqsigner_tx_core::eip1559::u256_format_decimal' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/fmtdec.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/fdout && mkdir -p $${EXTRACTION_TMP_ROOT}/fdout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/fdout -split-files $${EXTRACTION_TMP_ROOT}/fmtdec.llbc
	@sed -e 's/^import Fmtdec.Types$$/import Extracted.U256Mul.Types -- canonical eip1559.U256 home (dedup: both extractions define it)/' \
	     -e 's/import Fmtdec\./import Extracted.FormatDecimal./' \
	     $${EXTRACTION_TMP_ROOT}/fdout/Funs.lean > $${EXTRACTION_TMP_ROOT}/fdout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/FormatDecimal/Funs.lean $${EXTRACTION_TMP_ROOT}/fdout/Funs.fixed.lean \
	  && echo "OK: committed format-decimal extraction matches the current Rust" \
	  || { echo "DRIFT: tx-core/src/eip1559.rs changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-format-decimal $${EXTRACTION_TMP_ROOT}/fdout $${EXTRACTION_TMP_ROOT}/fdout/Funs.fixed.lean

# §33 rank 6 — merkle::verify_auth_path (XMSS auth-path walk; th_pair opaque →
# th_pair_pure axiom in Merkle/FunsExternal.lean). The dedup filter drops the
# re-extracted make_adrs / params.H duplicates and imports their canonical homes.
.PHONY: extract-merkle-verify
_extract-merkle-verify-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/sphincs-c10 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize \
	  --opaque 'sphincs_c10::hash::th_pair' \
	  --start-from 'sphincs_c10::merkle::verify_auth_path' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/merkle.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/mkout && mkdir -p $${EXTRACTION_TMP_ROOT}/mkout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/mkout -split-files $${EXTRACTION_TMP_ROOT}/merkle.llbc
	@$(_FV_PYTHON3) scripts/dedup_extraction.py $${EXTRACTION_TMP_ROOT}/mkout/Funs.lean $${EXTRACTION_TMP_ROOT}/mkout/Funs.fixed.lean \
	  --sed-import 'Merkle.=Extracted.Merkle.' \
	  --kill 'sphincs_c10::address::make_adrs' --kill 'sphincs_c10::params::H' \
	  --kill 'sphincs_c10::hash::pad16' --kill 'sphincs_c10::params::N' \
	  --add-import Extracted.Adrs --add-import Extracted.Fors.Funs \
	  --add-import Extracted.Hash.Funs
	@diff -u $(EXTRACTED_DIR)/Extracted/Merkle/Funs.lean $${EXTRACTION_TMP_ROOT}/mkout/Funs.fixed.lean \
	  && echo "OK: committed merkle extraction matches the current Rust" \
	  || { echo "DRIFT: sphincs-c10/src/merkle.rs changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-merkle-verify $${EXTRACTION_TMP_ROOT}/mkout $${EXTRACTION_TMP_ROOT}/mkout/Funs.fixed.lean

# §33 rank 5 — wots::pk_from_sig (verifier-side WOTS+C; wots_digest/chain_hash/
# th_multi opaque → _pure axioms in PkFromSig/FunsExternal.lean; dedup drops
# the re-extracted make_adrs/set_chain_index/extract_digits/params/pad16).
.PHONY: extract-wots-pkfromsig
_extract-wots-pkfromsig-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/sphincs-c10 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize \
	  --opaque 'sphincs_c10::hash::chain_hash' --opaque 'sphincs_c10::hash::th_multi' \
	  --opaque 'sphincs_c10::hash::wots_digest' \
	  --start-from 'sphincs_c10::wots::pk_from_sig' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/pkfs.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/pout && mkdir -p $${EXTRACTION_TMP_ROOT}/pout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/pout -split-files $${EXTRACTION_TMP_ROOT}/pkfs.llbc
	@$(_FV_PYTHON3) scripts/dedup_extraction.py $${EXTRACTION_TMP_ROOT}/pout/Funs.lean $${EXTRACTION_TMP_ROOT}/pout/Funs.fixed.lean \
	  --sed-import 'Pkfs.=Extracted.PkFromSig.' \
	  --kill 'sphincs_c10::address::make_adrs' --kill 'sphincs_c10::address::set_chain_index' \
	  --kill 'sphincs_c10::wots::extract_digits' \
	  --kill 'sphincs_c10::params::W' --kill 'sphincs_c10::params::LOG_W' \
	  --kill 'sphincs_c10::params::L' --kill 'sphincs_c10::params::W_MASK' \
	  --kill 'sphincs_c10::hash::pad16' --kill 'sphincs_c10::params::N' \
	  --add-import Extracted.Adrs --add-import Extracted.Wots.Funs --add-import Extracted.Merkle.Funs
	@diff -u $(EXTRACTED_DIR)/Extracted/PkFromSig/Funs.lean $${EXTRACTION_TMP_ROOT}/pout/Funs.fixed.lean \
	  && echo "OK: committed pk_from_sig extraction matches the current Rust" \
	  || { echo "DRIFT: sphincs-c10/src/wots.rs changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-wots-pkfromsig $${EXTRACTION_TMP_ROOT}/pout $${EXTRACTION_TMP_ROOT}/pout/Funs.fixed.lean

# §33 rank 11 — tx::erc20::merkle::verify_proof (trust-bundle merkle walk;
# leaf_hash/node_hash opaque → _pure axioms in TxMerkle/FunsExternal.lean).
.PHONY: extract-tx-merkle
_extract-tx-merkle-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/tx && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 \
	  --opaque 'pqsigner_tx::erc20::merkle::leaf_hash' \
	  --opaque 'pqsigner_tx::erc20::merkle::node_hash' \
	  --start-from 'pqsigner_tx::erc20::merkle::verify_proof' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/txmk.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/tout && mkdir -p $${EXTRACTION_TMP_ROOT}/tout
	@aeneas_log="$${EXTRACTION_TMP_ROOT}/tx-merkle-aeneas.log"; \
	if $(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/tout -split-files $${EXTRACTION_TMP_ROOT}/txmk.llbc 2>&1 | tee "$$aeneas_log"; then \
	  :; \
	else \
	  rc=$$?; \
	  if grep -Fq 'Unreachable' "$$aeneas_log" \
	     && grep -Fq "Source: 'tx/src/erc20/merkle.rs', lines 53:4-72:1" "$$aeneas_log" \
	     && grep -Fq "Name pattern: 'pqsigner_tx::erc20::merkle::verify_proof'" "$$aeneas_log" \
	     && grep -Fq 'Compiler source: interp/Interp.ml, line 550' "$$aeneas_log"; then \
	    echo '$(_TX_MERKLE_WAIVER_MARKER)' >&2; \
	  else \
	    echo "UNEXPECTED tx-merkle Aeneas failure; stale waiver does not apply" >&2; \
	  fi; \
	  exit $$rc; \
	fi
	@sed 's/import Txmk\./import Extracted.TxMerkle./' $${EXTRACTION_TMP_ROOT}/tout/Funs.lean > $${EXTRACTION_TMP_ROOT}/tout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/TxMerkle/Funs.lean $${EXTRACTION_TMP_ROOT}/tout/Funs.fixed.lean \
	  && echo "OK: committed tx-merkle extraction matches the current Rust" \
	  || { echo "DRIFT: tx/src/erc20/merkle.rs changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-tx-merkle $${EXTRACTION_TMP_ROOT}/tout $${EXTRACTION_TMP_ROOT}/tout/Funs.fixed.lean

# §33 rank 9 — bip39 11-bit pack/unpack round-trip (via the roundtrip_11 pub
# wrapper; private write_11_bits/read_11_bits can't be --start-from'd).
.PHONY: extract-bip39-roundtrip
_extract-bip39-roundtrip-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/bip39 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize --opaque subtle \
	  --start-from 'sphincs_tz_bip39::full::roundtrip_11' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/bip39.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/bout && mkdir -p $${EXTRACTION_TMP_ROOT}/bout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/bout -split-files $${EXTRACTION_TMP_ROOT}/bip39.llbc
	@sed 's/import Bip39\./import Extracted.Bip39./' $${EXTRACTION_TMP_ROOT}/bout/Funs.lean > $${EXTRACTION_TMP_ROOT}/bout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/Bip39/Funs.lean $${EXTRACTION_TMP_ROOT}/bout/Funs.fixed.lean \
	  && echo "OK: committed bip39 extraction matches the current Rust" \
	  || { echo "DRIFT: bip39/src changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-bip39-roundtrip $${EXTRACTION_TMP_ROOT}/bout $${EXTRACTION_TMP_ROOT}/bout/Funs.fixed.lean

# §33 rank 8 — rlp::decode_item (canonical-RLP grammar). Types/FunsExternal are
# hand-deduped against Rlp.* (shared RlpError + into_iter). The recipe now
# reproduces the Types dedup and compares it exactly; the raw external template
# is hash-pinned and its interface must be covered by the committed import closure.
.PHONY: extract-decode-item
_extract-decode-item-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/tx-core && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sha3 \
	  --start-from 'pqsigner_tx_core::rlp::decode_item' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/decode.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/dout && mkdir -p $${EXTRACTION_TMP_ROOT}/dout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/dout -split-files $${EXTRACTION_TMP_ROOT}/decode.llbc
	@sed 's/import Decode\./import Extracted.Decode./' $${EXTRACTION_TMP_ROOT}/dout/Funs.lean > $${EXTRACTION_TMP_ROOT}/dout/Funs.fixed.lean
	@$(_FV_PYTHON3) scripts/dedup_extraction.py $${EXTRACTION_TMP_ROOT}/dout/Types.lean $${EXTRACTION_TMP_ROOT}/dout/Types.fixed.lean \
	  --kill 'pqsigner_tx_core::rlp::RlpError' --add-import Extracted.Rlp.Types
	@diff -u $(EXTRACTED_DIR)/Extracted/Decode/Funs.lean $${EXTRACTION_TMP_ROOT}/dout/Funs.fixed.lean \
	  && echo "OK: committed decode_item extraction matches the current Rust" \
	  || { echo "DRIFT: tx-core/src/rlp.rs changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-decode-item $${EXTRACTION_TMP_ROOT}/dout $${EXTRACTION_TMP_ROOT}/dout/Funs.fixed.lean

# §33 axiom-collapse — the five sphincs-c10 tweakable-hash primitives with
# sha256_bytes as the SINGLE opaque boundary (FunsExternal wires it to the
# vendored FIPS 180-4 sha256_pure). chain_hash extracts its real loop (calls
# th); th/th_pair/th_multi/wots_digest expose their exact preimage assembly.
.PHONY: extract-hash-fns
_extract-hash-fns-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/sphincs-c10 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize \
	  --opaque 'sphincs_c10::hash::sha256_bytes' \
	  --start-from 'sphincs_c10::hash::th' \
	  --start-from 'sphincs_c10::hash::th_pair' \
	  --start-from 'sphincs_c10::hash::th_multi' \
	  --start-from 'sphincs_c10::hash::chain_hash' \
	  --start-from 'sphincs_c10::hash::wots_digest' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/hashfns.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/hout && mkdir -p $${EXTRACTION_TMP_ROOT}/hout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/hout -split-files $${EXTRACTION_TMP_ROOT}/hashfns.llbc
	@$(_FV_PYTHON3) scripts/dedup_extraction.py $${EXTRACTION_TMP_ROOT}/hout/Funs.lean $${EXTRACTION_TMP_ROOT}/hout/Funs.fixed.lean \
	  --sed-import 'Hashfns.=Extracted.Hash.'
	@diff -u $(EXTRACTED_DIR)/Extracted/Hash/Funs.lean $${EXTRACTION_TMP_ROOT}/hout/Funs.fixed.lean \
	  && echo "OK: committed hash-fns extraction matches the current Rust" \
	  || { echo "DRIFT: sphincs-c10/src/hash.rs changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-hash-fns $${EXTRACTION_TMP_ROOT}/hout $${EXTRACTION_TMP_ROOT}/hout/Funs.fixed.lean

# F4 (2026-07-19, fv-deep-review) — domain::{,de}serialize_pin_state (the
# PIN-counter parser; the NON-PRODUCTION mock-SE path). No --opaque flags and
# no RUSTFLAGS override: domain/src has no #[cfg(lean_extract)] gate, and the
# extraction reaches only core items (hand-filled DEFs in
# PinState/{Funs,Types}External.lean) + the cross-crate const
# pqsigner_proto::MAX_ATTEMPTS. TWO committed hand-completions are reproduced
# by the sed below: (i) the "import paths localised" header note; (ii) the
# Chunks Iterator trait-impl record — the aeneas binary emits only the
# OVERRIDDEN fields {next, enumerate}, but the pinned Aeneas.Std
# core.iter.traits.iterator.Iterator structure REQUIRES {next, step_by,
# enumerate, take} (no defaults — an unedited regen does not even build), so
# the step_by/take fields (whose DEFs live in PinState/FunsExternal.lean) are
# re-inserted. TypesExternal/FunsExternal are hand-filled: their raw templates
# are hash-pinned and their interfaces checked against the committed import
# closure. Both normalized Funs.lean and Types.lean are compared exactly.
_extract-pinstate-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/domain && \
	  $(PQLEAN)/charon cargo --preset=aeneas \
	  --start-from 'pqsigner_domain::serialize_pin_state' \
	  --start-from 'pqsigner_domain::deserialize_pin_state' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/pinstate.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/psout && mkdir -p $${EXTRACTION_TMP_ROOT}/psout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/psout -split-files $${EXTRACTION_TMP_ROOT}/pinstate.llbc
	@sed -e '1s|^-- THIS FILE WAS AUTOMATICALLY GENERATED BY AENEAS|-- THIS FILE WAS AUTOMATICALLY GENERATED BY AENEAS (import paths localised:\n-- `Pinstate.*` -> `Extracted.PinState.*` to fit this project'"'"'s module layout).|' \
	     -e 's/import Pinstate\./import Extracted.PinState./' \
	     -e '/^    core\.slice\.iter\.Chunks\.Insts\.CoreIterTraitsIteratorIteratorSharedASlice\.next$$/a\  step_by :=\n    core.slice.iter.Chunks.Insts.CoreIterTraitsIteratorIteratorSharedASlice.step_by' \
	     -e '/^    core\.slice\.iter\.Chunks\.Insts\.CoreIterTraitsIteratorIteratorSharedASlice\.enumerate$$/a\  take :=\n    core.slice.iter.Chunks.Insts.CoreIterTraitsIteratorIteratorSharedASlice.take' \
	     $${EXTRACTION_TMP_ROOT}/psout/Funs.lean > $${EXTRACTION_TMP_ROOT}/psout/Funs.fixed.lean
	@sed -e '1s|^-- THIS FILE WAS AUTOMATICALLY GENERATED BY AENEAS|-- THIS FILE WAS AUTOMATICALLY GENERATED BY AENEAS (import paths localised:\n-- `Pinstate.*` -> `Extracted.PinState.*` to fit this project'"'"'s module layout).|' \
	     -e 's/import Pinstate\./import Extracted.PinState./' \
	     $${EXTRACTION_TMP_ROOT}/psout/Types.lean > $${EXTRACTION_TMP_ROOT}/psout/Types.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/PinState/Funs.lean $${EXTRACTION_TMP_ROOT}/psout/Funs.fixed.lean \
	  && echo "OK: committed pinstate extraction matches the current Rust" \
	  || { echo "DRIFT: domain/src/lib.rs pin-state path changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-pinstate $${EXTRACTION_TMP_ROOT}/psout $${EXTRACTION_TMP_ROOT}/psout/Funs.fixed.lean

# F4 (2026-07-19, fv-deep-review) — domain slot-KDF (slot_master_entropy_from_bip39,
# derive_c10_master_from_bip39_seed, slot_entropy, derive_c10_slot_seeds). The
# two single-shot hash boundaries are opaqued (sha256_bytes -> sha256_pure_bytes,
# hmac_sha512_bytes -> hmac_sha512_pure_bytes — the disclosed axioms in
# SlotKdf/FunsExternal.lean); zeroize is NOT opaqued (its trait impls are
# extracted; the zeroize METHODS are hand-filled identity DEFs in FunsExternal
# — the byte-layout theorems only need the call to succeed). sk.llbc -> Sk.*
# prefix (the .llbc filename sets the aeneas module prefix). No RUSTFLAGS
# override: domain/src has no #[cfg(lean_extract)] gate. Generated Funs/Types
# are compared exactly and the raw external-template inventory is hash-pinned.
_extract-slotkdf-impl:
	@$(_begin_private_extraction)
	@mkdir -p $${EXTRACTION_TMP_ROOT}
	@( cd $(REPO_ROOT)/domain && \
	  $(PQLEAN)/charon cargo --preset=aeneas \
	  --opaque 'pqsigner_domain::sha256_bytes' \
	  --opaque 'pqsigner_domain::hmac_sha512_bytes' \
	  --start-from 'pqsigner_domain::slot_master_entropy_from_bip39' \
	  --start-from 'pqsigner_domain::derive_c10_master_from_bip39_seed' \
	  --start-from 'pqsigner_domain::slot_entropy' \
	  --start-from 'pqsigner_domain::derive_c10_slot_seeds' \
	  --dest-file $${EXTRACTION_TMP_ROOT}/sk.llbc 2>&1 | tail -1 )
	@rm -rf $${EXTRACTION_TMP_ROOT}/skout && mkdir -p $${EXTRACTION_TMP_ROOT}/skout
	@$(PQLEAN)/aeneas -backend lean -dest $${EXTRACTION_TMP_ROOT}/skout -split-files $${EXTRACTION_TMP_ROOT}/sk.llbc
	@sed 's/import Sk\./import Extracted.SlotKdf./' $${EXTRACTION_TMP_ROOT}/skout/Funs.lean > $${EXTRACTION_TMP_ROOT}/skout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/SlotKdf/Funs.lean $${EXTRACTION_TMP_ROOT}/skout/Funs.fixed.lean \
	  && echo "OK: committed slot-kdf extraction matches the current Rust" \
	  || { echo "DRIFT: domain/src/lib.rs slot-KDF path changed — re-extract, re-prove, re-commit"; exit 1; }
	@$(_FV_PYTHON3) scripts/check_extraction_regen_output.py extract-slotkdf $${EXTRACTION_TMP_ROOT}/skout $${EXTRACTION_TMP_ROOT}/skout/Funs.fixed.lean

# Current vendored split artifact (#670, #683-#686). Fast checks do not run proofs.
.PHONY: verify-easycrypt-split-pins verify-easycrypt-split
verify-easycrypt-split-pins: ## Current split identity, unique pins, dependency/assumption census and controls
	cd easycrypt/c10-port && $(_FV_PYTHON3) -B -W ignore::ResourceWarning tools/test_split_contract.py
	cd easycrypt/c10-port && $(_FV_PYTHON3) -B tools/split_contract.py
	cd easycrypt/c10-port && /usr/bin/bash cert_gate_split.sh --identity-only

verify-easycrypt-split: ## Full current split proof replay in the pinned immutable toolchain image
	$(_FV_PYTHON3) -B scripts/run_easycrypt_split.py
