#!/usr/bin/env bash
#
# lint_fv_invariants.sh — CI gate that fails on the formal-verification
# audit anti-patterns ("escape hatches") in the SphincsCVerify (lean/) and
# Aeneas-extracted (extracted/) Lean source trees.
#
# Five independent sub-lints (each can fail the run; all run before exit):
#
#   (a) ESCAPE-HATCH gate — no proof-path use of the kernel-trust escape
#       hatches:  native_decide, `decide +native`, @[csimp],
#       @[implemented_by], @[extern], `unsafe `, `partial `,
#       Lean.ofReduceBool / reduceBool.  Scanned with COMMENTS STRIPPED
#       (-- line comments + nested /- -/ blocks) so prose mentioning the
#       names is fine; IO `lake exe` / audit-script mains (Main.lean,
#       CavpMain.lean, BulkMain.lean, anything under lean/scripts/) are
#       excluded — they are programs, not proofs.
#
#   (b) BreaksHash FIREWALL — no non-comment `¬ BreaksHash`,
#       `Not BreaksHash`, `BreaksHash →/-> ANYTHING` (BreaksHash as an
#       antecedent, any target), or a `(h : BreaksHash)`-style binder
#       (2026-08-20 widening, issue #675: previously only `→ False` was
#       caught).  Assuming the opaque SHA-256 hardness-break token false
#       re-detonates the EUF_CMA inconsistency the 2026-06-14 fix removed.
#
#   (c) GAP-3 CLOSURE TRIPWIRE — runs `lake env lean --run
#       scripts/dump_axioms.lean` and asserts:
#         * the `offchain_nested_disjoint_from_userop_digest` axiom-closure
#           line literally contains `keccak_sha256_cross_separation` (so the
#           Gap-3 `True ∨ BreaksHash` tautology mutation, which would drop
#           that axiom from the closure, fails CI), AND
#         * `theft_free`'s closure contains exactly the expected named
#           premises (A1/A3.1/A4/A5 + kernel triple; A2 proved
#           kernel-only 2026-08-20, no longer an axiom).
#
#   (d) OPAQUE-GUARD — asserts `trivial` / `True.intro` does NOT inhabit
#       `Bridge.evmDeliversCall (default : Wallet.Execute.Call)` by
#       compiling a tiny temp Lean file and confirming it FAILS.  Catches an
#       opaque→`def := fun _ => True` A4 regression that `#print axioms`
#       alone misses (the regressed def would silently drop A4 from
#       theft_free's closure and let `trivial` discharge the marker).
#
# Run from anywhere; resolves the repo root from its own location.
#
# Exit codes:
#   0  every sub-lint passed (PASS)
#   1  at least one sub-lint tripped (FAIL); details on stderr
#   2  internal error (missing tooling / unbuilt Lean project / bad parse)
#
# Tooling required: lake (Lean 4), python3.
#
# Invoked from `make verify-fv-lints` (and from CI).
#
# Robustness note: greps that may legitimately zero-match are wrapped in
# `|| true` so `set -o pipefail` does not abort the lint on a clean tree
# (same convention as lint_axioms.sh).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
VERIF_DIR="${REPO_ROOT}/contracts/verification"
LEAN_DIR="${VERIF_DIR}/lean"
EXTRACTED_DIR="${VERIF_DIR}/extracted"

# The Lean toolchain is part of the evidence trust root: resolve the elan
# shim under the password-database home and force the elan/home root, so a
# caller-planted PATH/ELAN_HOME/HOME cannot reroot the closure tripwire's
# `lake env lean --run dump_axioms.lean` to an attacker-authored dump (same
# class as the wave-2/wave-3 Makefile/ledger findings; those layers are
# pinned, this script must not re-open the channel below them).
FV_HOME="$(/usr/bin/python3 -I -c 'import os,pwd;print(pwd.getpwuid(os.getuid()).pw_dir)')"
export HOME="${FV_HOME}"
export ELAN_HOME="${FV_HOME}/.elan"
unset ELAN_TOOLCHAIN
unset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH
LAKE="${FV_HOME}/.elan/bin/lake"

err() { printf 'lint_fv_invariants.sh: %s\n' "$*" >&2; }

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "missing required tool: $1"
    exit 2
  fi
}

require "${LAKE}"
require /usr/bin/python3
# The comment-stripper below IS the (a)/(b) sub-lints' evidence interpreter:
# a PATH-planted `python3` exiting 0 with no output would leave the stripped
# corpus empty and every escape-hatch/closure grep would pass vacuously
# (wave-4 Opus 5 HIGH, reviewer-reproduced).  Pin it like the Makefile does.
FV_PYTHON3="/usr/bin/python3 -E -S"

# F4/#675: reject every undisclosed axiom, even outside headline closures.
${FV_PYTHON3} "${SCRIPT_DIR}/check_axiom_inventory.py" lean || exit 1

for d in "${LEAN_DIR}" "${EXTRACTED_DIR}"; do
  if [ ! -d "$d" ]; then
    err "source tree missing: $d"
    exit 2
  fi
done

###############################################################################
# Comment-stripping helper.
#
# Emits, for each scanned *.lean SOURCE file (under the SphincsCVerify spec
# tree + the extracted Aeneas tree, EXCLUDING IO/exe/audit-script mains),
# its comment-stripped text prefixed with `path:lineno:` so a downstream
# grep reports a real, human-navigable location.  Handles `--` line
# comments and NESTED `/- ... -/` block comments (mirrors the proven
# stripper in lint_placeholders.py).
###############################################################################

# Files that are IO programs / audit dumps, NOT proofs. The KAT `lake exe`
# mains (Main/CavpMain/BulkMain) and everything under lean/scripts/ are
# allowed to use `partial def`, IO, etc.
strip_comments_py() {
  ${FV_PYTHON3} - "$@" <<'PYEOF'
import sys, os

def strip_comments(text):
    out_lines = []
    in_block = 0  # nested /- -/ depth
    for line in text.splitlines():
        i = 0
        buf = []
        while i < len(line):
            if in_block > 0:
                close_at = line.find("-/", i)
                if close_at == -1:
                    i = len(line)
                else:
                    in_block -= 1
                    i = close_at + 2
            else:
                open_at = line.find("/-", i)
                cmt_at = line.find("--", i)
                if open_at == -1 and cmt_at == -1:
                    buf.append(line[i:]); i = len(line)
                elif cmt_at != -1 and (open_at == -1 or cmt_at < open_at):
                    buf.append(line[i:cmt_at]); i = len(line)
                else:
                    buf.append(line[i:open_at]); in_block += 1; i = open_at + 2
        out_lines.append("".join(buf))
    return out_lines

for path in sys.argv[1:]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        sys.stderr.write(f"strip_comments: cannot read {path}: {exc}\n")
        continue
    for n, ln in enumerate(strip_comments(text), start=1):
        # keep blank lines so a grep -n offset still makes sense, but only
        # print lines that have content (a comment-only line strips to "")
        if ln.strip():
            sys.stdout.write(f"{path}:{n}:{ln}\n")
PYEOF
}

# Build the SOURCE file list: spec proofs + extracted proofs, minus the
# IO/exe/audit mains.
collect_source_files() {
  {
    # SphincsCVerify spec tree (proofs).
    find "${LEAN_DIR}/SphincsCVerify" -name '*.lean'
    # Extracted Aeneas tree (proofs). NB: the Aeneas support *package* under
    # .lake/packages is NOT ours — we only scan extracted/Extracted/.
    find "${EXTRACTED_DIR}/Extracted" -name '*.lean'
  } | while IFS= read -r f; do
    base="$(basename "$f")"
    case "$base" in
      Main.lean|CavpMain.lean|BulkMain.lean) continue ;;   # KAT exe roots
    esac
    # Exclude lean/scripts/ audit + no-sorry IO programs.
    case "$f" in
      */lean/scripts/*) continue ;;
    esac
    printf '%s\n' "$f"
  done
}

OVERALL_EXIT=0

###############################################################################
# (a) ESCAPE-HATCH gate.
###############################################################################
printf '==> [lint_fv] (a) escape-hatch gate (comment-stripped, proof paths only)\n'

# shellcheck disable=SC2046
SRC_FILES=$(collect_source_files)
if [ -z "${SRC_FILES//[[:space:]]/}" ]; then
  err "(a) no source files collected — tree layout changed?"
  exit 2
fi

# Comment-stripped corpus with path:line: prefixes.  An EMPTY or tiny strip
# of a NON-empty source list is not a clean tree — it is the stripper failing
# open (a planted/no-output interpreter, a broken heredoc), which would let
# every grep below pass vacuously.  Fail closed on it.  (Length check, not a
# pattern-replace — `${STRIPPED//[[:space:]]/}` is quadratic over a
# multi-megabyte corpus in pure bash.)
STRIPPED="$(strip_comments_py ${SRC_FILES})" || {
  err "(a) comment-stripper failed"
  exit 2
}
if [ "${#STRIPPED}" -lt 64 ]; then
  err "(a) comment-stripper produced a suspiciously tiny corpus (${#STRIPPED} bytes) over a non-empty source list — refusing to lint vacuously"
  exit 2
fi

# Escape-hatch patterns. Anchored where it matters:
#   - native_decide / reduceBool / ofReduceBool : bare token
#   - `decide +native`                          : the +native config form
#   - @[csimp] @[implemented_by] @[extern]      : attribute brackets
#   - `unsafe ` / `partial `                    : declaration modifiers
# Each grep is `|| true` so a clean (zero-match) tree does not trip pipefail.
ESCAPE_HITS=""
add_hits() {
  # $1 = ERE pattern, $2 = human label
  local hits
  hits="$(printf '%s\n' "${STRIPPED}" | { grep -nE "$1" || true; } | sed "s/^/[$2] /")"
  if [ -n "${hits//[[:space:]]/}" ]; then
    ESCAPE_HITS="${ESCAPE_HITS}${hits}"$'\n'
  fi
}

add_hits '\bnative_decide\b'        'native_decide'
add_hits 'decide[[:space:]]+\+native' 'decide+native'
add_hits '@\[csimp\]'               'csimp'
add_hits '@\[implemented_by'        'implemented_by'
add_hits '@\[extern'                'extern'
add_hits '\bunsafe[[:space:]]'      'unsafe'
add_hits '\bpartial[[:space:]]'     'partial'
add_hits 'ofReduceBool'            'ofReduceBool'
add_hits '\breduceBool\b'           'reduceBool'
# DECLARATION INJECTION (added 2026-08-11).  The Lean 4 kernel soundness bug
# #14576 ("Kernel accepts wrong-structure projections, allowing an axiom-free
# proof of False", 2026-07-28) is reachable ONLY by handing a declaration to the
# kernel directly -- the frontend catches the ill-typed term, so ordinary tactic
# proofs cannot trigger it.  The resulting `False` is AXIOM-FREE: it prints
# "does not depend on any axioms", so dump_axioms / AXIOM_STATUS.json /
# verify-ledger-consistency / the `Evil : False` canary are all blind to it BY
# CONSTRUCTION, and verify-lean4checker replays through the same C++ kernel.
# This lint is therefore the only cheap gate for the class.  It was verified by
# hand on 2026-08-11 that our trees contain none of these; that was a SNAPSHOT,
# and this makes it an INVARIANT -- which matters because this repo runs LLM
# agents over Lean sources and the original exploit was AI-generated
# metaprogramming.  A legitimate need (an audit/exe main) is excluded the same
# way the other hatches are, in collect_source_files().
add_hits '\baddDecl\b'              'addDecl'
add_hits '\baddDeclCore\b'          'addDeclCore'
add_hits '\baddAndCompile\b'        'addAndCompile'
add_hits '\baddInductive\b'         'addInductive'
add_hits '\binductDecl\b'           'inductDecl'
add_hits '\bmkProj\b'               'mkProj'
add_hits 'Expr\.proj\b'             'Expr.proj'

if [ -n "${ESCAPE_HITS//[[:space:]]/}" ]; then
  err ""
  err "(a) FAIL: escape-hatch construct(s) on a proof path (non-comment):"
  printf '%s' "${ESCAPE_HITS}" | sed 's/^/    /' >&2
  err ""
  err "These bypass kernel checking (native_decide / reduceBool), inject"
  err "unverified compiled code (@[implemented_by]/@[extern]/@[csimp]),"
  err "escape totality (unsafe/partial), or hand declarations to the kernel"
  err "directly (addDecl/addAndCompile/inductDecl/mkProj) — the ONLY route to"
  err "the #14576 class, whose forged `False` is axiom-free and therefore"
  err "invisible to every axiom-accounting gate we own. Remove them from proof"
  err "code, or — if this is a new IO/exe/audit main — exclude it in"
  err "collect_source_files()."
  OVERALL_EXIT=1
else
  printf '    PASS — no escape-hatch constructs on proof paths\n'
fi

###############################################################################
# (b) BreaksHash FIREWALL.
###############################################################################
printf '==> [lint_fv] (b) BreaksHash firewall (no `¬ BreaksHash`)\n'

# Match (comment-stripped):
#   ¬ BreaksHash | Not BreaksHash                       (negation forms)
#   BreaksHash (→|->) ANYTHING                          (BreaksHash as an
#     ANTECEDENT — not only the old `→ False`: any `BreaksHash → X` lets
#     the EUF-CMA `isForgery → BreaksHash` reduction conclude `X` vacuously)
#   (h : BreaksHash) / {h : BreaksHash} / [h : BreaksHash]
#     — a BINDER whose type is exactly the break token (same attack written
#     as a hypothesis; dotted prefixes like `Crypto.BreaksHash` included).
# Deliberately NOT matched (legit shipped shapes, verified green on the
# tree 2026-08-20): the `opaque BreaksHash : Prop` declaration, axioms
# CONCLUDING `… → BreaksHash` or `… ∨ BreaksHash` (the reduction form),
# and theorems PROVING `… : BreaksHash := …` from an `isForgery` hyp.
BREAKSHASH_RE='(¬[[:space:]]*BreaksHash|\bNot[[:space:]]+BreaksHash|\bBreaksHash[[:space:]]*(→|->)|[({[][[:space:]]*[^:]*:[[:space:]]*([A-Za-z0-9_]+\.)*BreaksHash[[:space:]]*[])}])'
BREAKSHASH_HITS="$(printf '%s\n' "${STRIPPED}" \
  | { grep -nE "${BREAKSHASH_RE}" || true; })"

# Second pass over a declaration-JOINED view, so a line-wrapped signature
# (`axiom x : BreaksHash` newline `→ False`, or `(h :` newline
# `BreaksHash)`) cannot evade the line-based patterns. A new declaration
# starts at a top-level keyword; continuation lines fold into it.
BREAKSHASH_JOINED="$(printf '%s\n' "${STRIPPED}" | awk '
  function flush() { if (buf != "") print buf; buf = "" }
  {
    line = $0
    rest = line
    sub(/^[^:]*:[0-9]*:/, "", rest)
    if (rest ~ /^[[:space:]]*(@\[|axiom[[:space:]]|theorem[[:space:]]|lemma[[:space:]]|def[[:space:]]|abbrev[[:space:]]|instance[[:space:]]|opaque[[:space:]]|structure[[:space:]]|inductive[[:space:]]|namespace[[:space:]]|end([[:space:]]|$)|open[[:space:]]|section([[:space:]]|$)|import[[:space:]]|#)/) {
      flush()
      buf = line
    } else if (buf != "") {
      gsub(/^[[:space:]]+/, " ", rest)
      buf = buf rest
    } else {
      print line
    }
  }
  END { flush() }')"
BREAKSHASH_HITS_ML="$(printf '%s\n' "${BREAKSHASH_JOINED}" \
  | { grep -nE "${BREAKSHASH_RE}" || true; })"
if [ -n "${BREAKSHASH_HITS_ML//[[:space:]]/}" ]; then
  BREAKSHASH_HITS="${BREAKSHASH_HITS}${BREAKSHASH_HITS_ML}"
fi

if [ -n "${BREAKSHASH_HITS//[[:space:]]/}" ]; then
  err ""
  err "(b) FAIL: \`BreaksHash\` assumed/derivable-false (non-comment):"
  printf '%s\n' "${BREAKSHASH_HITS}" | sed 's/^/    /' >&2
  err ""
  err "\`BreaksHash\` is the opaque SHA-256 hardness-break token. Assuming it"
  err "false (¬ BreaksHash / BreaksHash → X / a (h : BreaksHash) binder)"
  err "collapses the EUF_CMA reduction back to the inconsistency removed on"
  err "2026-06-14. Forbidden."
  OVERALL_EXIT=1
else
  printf '    PASS — no `¬ BreaksHash` / `BreaksHash → …` / `(h : BreaksHash)` on any source path\n'
fi

###############################################################################
# (c) GAP-3 CLOSURE TRIPWIRE.
###############################################################################
printf '==> [lint_fv] (c) Gap-3 + theft_free axiom-closure tripwire\n'

# `lake env lean --run scripts/dump_axioms.lean` prints all `#print axioms`
# blocks then errors on the missing `main` (it is an audit dump, not an exe).
# That trailing `unknown declaration 'main'` makes the exit code non-zero, so
# we DO NOT gate on it — we gate on the emitted #print-axioms CONTENT, which
# is complete before the error. We require the keccak axiom line + theft_free
# closure to be present (a failed elaboration would omit them, which we catch).
DUMP_OUT="$(cd "${LEAN_DIR}" && "${LAKE}" env lean --run scripts/dump_axioms.lean 2>&1)" || true

# Surface a hard internal error if the project clearly is not built / the
# import failed (no #print-axioms lines emitted at all).
if ! printf '%s\n' "${DUMP_OUT}" | grep -q 'depends on axioms:'; then
  err "(c) dump_axioms.lean produced no axiom output — is the Lean project built?"
  err "    Run: (cd ${LEAN_DIR} && lake build SphincsCVerify)"
  printf '%s\n' "${DUMP_OUT}" | tail -20 >&2
  exit 2
fi

# Collapse each per-theorem block (Lean wraps long axiom lists across lines:
# a new block starts at a line beginning with a quote, continuations are
# indented `<axiom>,` lines) into ONE logical line keyed by the quoted name.
COLLAPSED_DUMP="$(printf '%s\n' "${DUMP_OUT}" | awk '
  BEGIN { buf = "" }
  /^'\''/ {                       # line beginning with a single-quote = new block
    if (buf != "") print buf
    buf = $0
    next
  }
  {
    if (buf != "") {
      gsub(/^[[:space:]]+/, " ")  # collapse leading indent to a single space
      buf = buf $0
    }
  }
  END { if (buf != "") print buf }
')"

# (c.1) Gap-3: the offchain closure must contain keccak_sha256_cross_separation AND
# nothing beyond {it + kernel} — an EXACT-set check (tightened 2026-06-18 to match (c.2);
# a presence-only subset check would let a NEW axiom enter the Gap-3 defense's closure
# silently). The kernel `#print axioms` remains the backstop.
OFFCHAIN_LINE="$(printf '%s\n' "${COLLAPSED_DUMP}" \
  | { grep 'offchain_nested_disjoint_from_userop_digest' || true; })"

C_EXIT=0
if [ -z "${OFFCHAIN_LINE//[[:space:]]/}" ]; then
  err "(c) FAIL: no closure line for offchain_nested_disjoint_from_userop_digest"
  C_EXIT=1
elif ! printf '%s\n' "${OFFCHAIN_LINE}" | grep -q 'keccak_sha256_cross_separation'; then
  err ""
  err "(c) FAIL: offchain_nested_disjoint_from_userop_digest closure no longer"
  err "    contains keccak_sha256_cross_separation:"
  err "      ${OFFCHAIN_LINE}"
  err ""
  err "This is the Gap-3 tripwire: if the theorem was mutated to a tautology"
  err "(e.g. \`True ∨ BreaksHash\`), the cited cross-hash axiom drops from its"
  err "closure and the RAW32-oracle defense becomes vacuous. Restore the real"
  err "\`replaySafeHash … ≠ sphincsDigest … ∨ BreaksHash\` reduction."
  C_EXIT=1
else
  # (c.1-exact) no axiom in the offchain closure beyond {keccak_sha256_cross_separation}
  # + kernel. Namespace-agnostic bracket parse (same shape as (c.2)).
  OFF_BRACKET="$(printf '%s\n' "${OFFCHAIN_LINE}" \
    | sed -n 's/.*axioms:[[:space:]]*\[\(.*\)\].*/\1/p')"
  OFF_ALLOWED=( "propext" "Classical.choice" "Quot.sound" \
                "SphincsCVerify.Wallet.OffchainBinding.keccak_sha256_cross_separation" )
  OFF_EXTRA=""
  if [ -z "${OFF_BRACKET//[[:space:]]/}" ]; then
    err "(c.1) FAIL: could not parse the axiom list out of the offchain closure line:"
    err "      ${OFFCHAIN_LINE}"
    C_EXIT=1
  else
    while IFS= read -r ax; do
      [ -z "${ax//[[:space:]]/}" ] && continue
      ok=0
      for a in "${OFF_ALLOWED[@]}"; do if [ "${a}" = "${ax}" ]; then ok=1; break; fi; done
      [ "${ok}" -eq 0 ] && OFF_EXTRA="${OFF_EXTRA} ${ax}"
    done <<< "$(printf '%s\n' "${OFF_BRACKET}" | tr ',' '\n' \
                | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | { grep -v '^$' || true; } | sort -u)"
  fi
  if [ -n "${OFF_EXTRA//[[:space:]]/}" ]; then
    err ""
    err "(c.1) FAIL: offchain closure has UNEXPECTED axiom(s) beyond {keccak_sha256_cross_separation} + kernel:"
    printf '      + %s\n' ${OFF_EXTRA} >&2
    err "      ${OFFCHAIN_LINE}"
    err "    A new axiom entered the Gap-3 defense's closure — confirm intended, then extend OFF_ALLOWED."
    C_EXIT=1
  else
    printf '    PASS (c.1) — offchain closure = EXACTLY {keccak_sha256_cross_separation} + kernel (no missing, no extra)\n'
  fi
fi

# (c.2) theft_free closure must contain exactly the expected named premises.
THEFT_LINE="$(printf '%s\n' "${COLLAPSED_DUMP}" \
  | { grep "'SphincsCVerify.Spec.Theorems.theft_free'" || true; })"

# Expected named (non-kernel) premises in theft_free's closure. The kernel
# triple {propext, Classical.choice, Quot.sound} is checked separately.
# A2 (`entrypoint_honest`) was PROVED kernel-only 2026-08-20 — demoted
# from axiom to theorem, so it no longer appears in any closure.
THEFT_EXPECTED=(
  "SphincsCVerify.Bridge.evm_bytecode_executes_correctly"        # A4
  "SphincsCVerify.Bridge.precompile_0x02_is_FIPS_180_4"          # A1
  "SphincsCVerify.Bridge.solidityVerifier_compiles_correctly"    # A3.1
  "SphincsCVerify.Crypto.EUF_CMA_SPHINCSplusC"                   # A5
  "SphincsCVerify.Crypto.ITSR_F"                                 # A5
  "SphincsCVerify.Crypto.SM_DT_TCR_F"                            # A5
  "SphincsCVerify.Crypto.hMsg_random_oracle"                     # A5
)
THEFT_KERNEL=( "propext" "Classical.choice" "Quot.sound" )

if [ -z "${THEFT_LINE//[[:space:]]/}" ]; then
  err "(c) FAIL: no closure line for SphincsCVerify.Spec.Theorems.theft_free"
  C_EXIT=1
else
  MISSING=""
  for ax in "${THEFT_EXPECTED[@]}" "${THEFT_KERNEL[@]}"; do
    if ! printf '%s\n' "${THEFT_LINE}" | grep -qF "${ax}"; then
      MISSING="${MISSING} ${ax}"
    fi
  done
  if [ -n "${MISSING//[[:space:]]/}" ]; then
    err ""
    err "(c) FAIL: theft_free closure is MISSING expected premise(s):"
    printf '      - %s\n' ${MISSING} >&2
    err "    Actual closure line:"
    err "      ${THEFT_LINE}"
    err ""
    err "A dropped premise means the trust base silently shrank (often a"
    err "regression: an axiom became a discharged def, or a binding was"
    err "deleted). Reconcile the model + update THEFT_EXPECTED if intended."
    C_EXIT=1
  else
    # (c.2-exact) EXACT-set, not subset: the closure must contain NO axiom beyond
    # the expected set. The MISSING loop above is subset-only; without this, a
    # NEWLY-ADDED content-bearing axiom (or one whose TYPE was flipped false→true)
    # entering theft_free's closure passes SILENTLY — `#print axioms` shows NAMES,
    # not TYPES, so a type flip is invisible and an addition was previously caught
    # only by a human reading the dump. (2026-06-18 adversarial-review finding H-2.)
    # Parse the ACTUAL bracketed axiom list (everything between `axioms: [` and the
    # closing `]`) and check EVERY token — namespace-AGNOSTIC, so a new axiom in ANY
    # namespace (not only `SphincsCVerify.*` or the kernel names we happen to know) is
    # caught. A grep for known prefixes would silently miss a `Foo.bar` axiom.
    THEFT_BRACKET="$(printf '%s\n' "${THEFT_LINE}" \
      | sed -n 's/.*axioms:[[:space:]]*\[\(.*\)\].*/\1/p')"
    FOUND_AXII=""
    if [ -z "${THEFT_BRACKET//[[:space:]]/}" ]; then
      err "(c.2) FAIL: could not parse the axiom list out of theft_free's closure line"
      err "    (expected '... depends on axioms: [ ... ]'). Got: ${THEFT_LINE}"
      C_EXIT=1
    else
      FOUND_AXII="$(printf '%s\n' "${THEFT_BRACKET}" | tr ',' '\n' \
        | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | { grep -v '^$' || true; } | sort -u)"
    fi
    EXTRA=""
    while IFS= read -r ax; do
      [ -z "${ax//[[:space:]]/}" ] && continue
      found=0
      for a in "${THEFT_EXPECTED[@]}" "${THEFT_KERNEL[@]}"; do
        if [ "${a}" = "${ax}" ]; then found=1; break; fi
      done
      [ "${found}" -eq 0 ] && EXTRA="${EXTRA} ${ax}"
    done <<< "${FOUND_AXII}"
    if [ -n "${EXTRA//[[:space:]]/}" ]; then
      err ""
      err "(c) FAIL: theft_free closure has UNEXPECTED axiom(s) beyond the expected set:"
      printf '      + %s\n' ${EXTRA} >&2
      err "    Actual closure line:"
      err "      ${THEFT_LINE}"
      err ""
      err "The trust base GREW: a new content-bearing axiom entered theft_free's"
      err "closure, or one was flipped false->true (\`#print axioms\` shows NAMES not"
      err "TYPES, so a type flip is invisible here — confirm by hand). If intended,"
      err "add it to THEFT_EXPECTED with a justification; otherwise it is a regression."
      C_EXIT=1
    else
      printf '    PASS (c.2) — theft_free closure = EXACTLY expected A1/A3.1/A4/A5 + kernel triple (no missing, no extra; A2 proved kernel-only 2026-08-20, no longer an axiom)\n'
    fi
  fi
fi

if [ "${C_EXIT}" -ne 0 ]; then
  OVERALL_EXIT=1
fi

###############################################################################
# (d) OPAQUE-GUARD.
###############################################################################
printf '==> [lint_fv] (d) opaque-guard (trivial must NOT inhabit evmDeliversCall default)\n'

GUARD_TMP="$(mktemp /tmp/lint_fv_opaque_guard.XXXXXX.lean)"
trap 'rm -f "${GUARD_TMP}"' EXIT
cat > "${GUARD_TMP}" <<'LEANEOF'
import SphincsCVerify
open SphincsCVerify
-- If `evmDeliversCall` regressed from `opaque` to `def := fun _ => True`,
-- this `trivial` (which only proves `True`) would type-check. It MUST NOT.
example : Bridge.evmDeliversCall (default : Wallet.Execute.Call) := trivial
LEANEOF

# A clean compile (exit 0) means `trivial` proved it → opaque guard BROKEN.
# A non-zero exit (type mismatch) is the healthy state.
if (cd "${LEAN_DIR}" && "${LAKE}" env lean "${GUARD_TMP}") >/tmp/lint_fv_guard.out 2>&1; then
  err ""
  err "(d) FAIL: \`trivial\` inhabited Bridge.evmDeliversCall default — A4's"
  err "    \`evmDeliversCall\` is no longer opaque (regressed to a True def?)."
  err "    A4 would silently drop from theft_free's closure. Restore"
  err "    \`opaque evmDeliversCall : Wallet.Execute.Call → Prop\` in"
  err "    SphincsCVerify/Bridge/Refinement.lean."
  cat /tmp/lint_fv_guard.out >&2 || true
  OVERALL_EXIT=1
else
  # Sanity: confirm the failure is the EXPECTED type-mismatch, not an
  # unrelated build break (which would falsely "pass" this guard).
  if grep -q 'evmDeliversCall' /tmp/lint_fv_guard.out 2>/dev/null; then
    printf '    PASS — `trivial` correctly rejected (evmDeliversCall stays opaque)\n'
  else
    err "(d) WARN: opaque-guard temp file failed to compile, but NOT with the"
    err "    expected evmDeliversCall type-mismatch. Output:"
    cat /tmp/lint_fv_guard.out >&2 || true
    err "    Treating as internal error (could be an unrelated build break)."
    exit 2
  fi
fi
rm -f /tmp/lint_fv_guard.out


###############################################################################
# (e) VACUOUS-AXIOM gate — REPO-WIDE, deliberately wider than (a).
#
# WHY THIS EXISTS AND WHY ITS SCOPE DIFFERS.  On 2026-08-11 two declarations
#
#     axiom hypertree_verify_equivalent_to_rust (…) : True     [verity/…/Hypertree.lean]
#     axiom verify_byte_equivalent_to_rust      (…) : True     [verity/…/Top.lean]
#
# were found sitting in contracts/verity/, each described in its own docstring
# as "load-bearing" cross-validation of Lean against the Rust reference.  `True`
# asserts NOTHING, so these were not weak assumptions -- they were no-ops
# wearing an axiom's name, in the very tree AXIOM_STATUS.json names as the
# deductive path for closing the A3.1 forall.  A reader, or a census counting
# premises, would have booked a cross-validation that did not exist.
#
# Two separate detectors already existed and BOTH missed them, for the same
# reason -- scope:
#   * lint_axioms.sh DOES fail on True-typed axioms, but enumerates from the
#     elaborated SphincsCVerify environment only;
#   * this script's (a) gate is textual and repo-ish, but collect_source_files()
#     walks only SphincsCVerify/ and extracted/Extracted/.
# contracts/verity/ is in NEITHER.  So the class check is deliberately given its
# own file walk here rather than folded into (a): (a)'s corpus is "proof paths
# we hold to the escape-hatch contract", and widening that to a half-built
# scaffold would change what (a) means.  Vacuity, by contrast, is worth
# forbidding EVERYWHERE -- there is no tree in which `axiom X : True` is
# legitimate.
#
# SCOPE, STATED HONESTLY.  This matches the literal `True` CONCLUSION of an
# axiom declaration across a wrapped signature, ignoring `--` comments —
# conclusion taken after the final depth-0 `:`, past the end of the arrow
# chain, with balanced outer parens stripped, so `: True`, `: (True)`,
# `: ((True))`, and `: … → True` are all caught (widened 2026-08-20, issue
# #675; the first three evaded the original suffix match).  It does
# NOT unfold aliases (`abbrev MyTrue : Prop := True` then `axiom Y : MyTrue`),
# does NOT catch compound vacuities (`: True /\ True`), and by construction does
# NOT cover the sibling shape `theorem X : True := trivial`.  It is a cheap
# TRIPWIRE for the exact shape that actually occurred twice, in the one tree no
# other checker walks -- not a decision procedure for vacuity.  The sound
# version is the elaborated-environment scan in lint_axioms.sh (it unfolds
# aliases and reads the elaborated conclusion); extending THAT to
# contracts/verity, which is a separate lake project, is the tracked follow-up.
###############################################################################
printf '==> [lint_fv] (e) vacuous-axiom gate (repo-wide: no `axiom … : True`)\n'
# Pinned interpreter, same reason the stripper is pinned: a PATH-planted
# `python3` that exits 0 with no output would make THIS gate pass vacuously --
# which would be a vacuity check defeated by vacuity.
#
# THE ROOT IS PASSED IN ABSOLUTE, AND THE WALK IS FAIL-CLOSED.  The first version
# of this gate walked a RELATIVE 'contracts', so running the lint from any other
# directory scanned ZERO files and printed PASS -- a vacuity gate that was itself
# vacuous, which is precisely the defect class it exists to catch.  Caught in
# review 2026-08-11 by invoking it with cwd=/tmp.  It now takes ${REPO_ROOT} and
# ERRORS (exit 2) if the walk yields no .lean files at all, on the same
# anti-fail-open principle as the manifest-truncation guards elsewhere here: a
# check that inspected nothing must not be able to report success.
# THE CORPUS IS THE COMMENT-STRIPPED ONE, via the SAME proven stripper (a)/(b)
# use.  First attempt matched raw text and, once made indent-tolerant, fired on
# the deleted axiom QUOTED INSIDE the /-! … -/ history note that documents its
# deletion -- a false positive that would have red-lined CI forever.  `--` lines
# alone are not enough; nested /- -/ blocks must go too, and that logic already
# exists here, so it is reused rather than re-implemented.
VACUOUS_FILES="$(find "${REPO_ROOT}/contracts" -name '*.lean' -not -path '*/.lake/*' | sort)"
if [ -z "${VACUOUS_FILES//[[:space:]]/}" ]; then
  err "(e) INTERNAL: found no .lean files under ${REPO_ROOT}/contracts — refusing to report PASS"
  exit 2
fi
# The matcher goes to a TEMP FILE, not `python3 -`.  `python3 -` reads its
# PROGRAM from stdin, so `… | python3 - <<'PYEOF'` hands python the heredoc and
# DISCARDS the piped corpus -- the gate then sees empty input.  Caught here only
# because the fail-closed empty-corpus check fired; without it this would have
# been a silent always-PASS.
VACUOUS_PY="$(mktemp)"
trap 'rm -f "${VACUOUS_PY}"' EXIT
cat >"${VACUOUS_PY}" <<'PYEOF'
import sys, re
from collections import OrderedDict

# stdin lines are `path:lineno:stripped-content` (blank lines already dropped).
per_file = OrderedDict()
for raw in sys.stdin:
    raw = raw.rstrip('\n')
    a = raw.find(':'); b = raw.find(':', a + 1)
    if a < 0 or b < 0:
        continue
    path, lineno, content = raw[:a], raw[a+1:b], raw[b+1:]
    try:
        lineno = int(lineno)
    except ValueError:
        continue
    per_file.setdefault(path, []).append((lineno, content))

if not per_file:
    sys.stderr.write('FATAL: vacuous-axiom gate received an EMPTY stripped corpus\n')
    sys.exit(3)

# A declaration boundary: anything that starts a new top-level-ish item.
BOUNDARY = re.compile(
    r'^\s*(@\[|axiom\s|theorem\s|lemma\s|def\s|abbrev\s|instance\s|structure\s|'
    r'inductive\s|namespace\s|end\b|open\s|section\b|import\s|/-)')
AXIOM = re.compile(r'^\s*(?:@\[[^\]]*\]\s*)?axiom\s+([A-Za-z_][A-Za-z0-9_\'!?]*)')

hits = []
for path, entries in per_file.items():
    for idx, (lineno, content) in enumerate(entries):
        m = AXIOM.match(content)
        if not m:
            continue
        parts = [content]
        for lineno2, content2 in entries[idx+1:]:
            if BOUNDARY.match(content2):
                break
            parts.append(content2)
        decl = re.sub(r'\s+', ' ', ' '.join(x.strip() for x in parts)).strip()
        # conclusion = text after the final depth-0 ':' (binder colons sit
        # inside parens/brackets), then past the END of the arrow chain,
        # with balanced outer parens stripped — so `(True)`, `((True))`,
        # and `Hyp → True` (an axiom that CONCLUDES True is vacuous
        # however many hypotheses it carries) are all caught, not just the
        # literal `: True` suffix (2026-08-20 widening, issue #675).
        depth = 0
        last_colon = -1
        for i, ch in enumerate(decl):
            if ch in '([{':
                depth += 1
            elif ch in ')]}':
                depth -= 1
            elif ch == ':' and depth == 0:
                last_colon = i
        concl = decl[last_colon + 1:].strip() if last_colon >= 0 else ''

        def _strip_outer_parens(s):
            while len(s) >= 2 and s[0] == '(' and s[-1] == ')':
                d = 0
                wraps = True
                for i, ch in enumerate(s):
                    if ch == '(':
                        d += 1
                    elif ch == ')':
                        d -= 1
                    if d == 0 and i < len(s) - 1:
                        wraps = False
                        break
                if not wraps:
                    break
                s = s[1:-1].strip()
            return s

        concl = _strip_outer_parens(concl)
        concl = _strip_outer_parens(re.split(r'→|->', concl)[-1].strip())
        if concl == 'True':
            hits.append('%s:%d: %s' % (path, lineno, decl[:110]))

for h in hits:
    print(h)
PYEOF
# shellcheck disable=SC2086
VACUOUS="$(strip_comments_py ${VACUOUS_FILES} | ${FV_PYTHON3} "${VACUOUS_PY}")" \
  || { err "(e) INTERNAL: vacuous-axiom scan failed — refusing to report PASS"; exit 2; }

if [ -n "${VACUOUS//[[:space:]]/}" ]; then
  err ""
  err "(e) FAIL: axiom(s) whose TYPE is \`True\` — these assert NOTHING:"
  printf '%s\n' "${VACUOUS}" | sed 's/^/    /' >&2
  err ""
  err "An \`axiom X : True\` is strictly worse than no axiom: absence is visible,"
  err "vacuity is not, and any premise census counts it as a real assumption."
  err "State a real proposition, or record an OPEN OBLIGATION in prose and delete"
  err "the declaration."
  OVERALL_EXIT=1
else
  printf '    PASS — no `axiom … : True` anywhere under contracts/\n'
fi

###############################################################################
# REPORT.
###############################################################################
if [ "${OVERALL_EXIT}" -eq 0 ]; then
  printf '\n==> [lint_fv] PASS — all five FV-invariant sub-lints green\n'
  printf '    (a) escape-hatch  (b) BreaksHash firewall\n'
  printf '    (c) Gap-3 + theft_free closure  (d) opaque-guard\n'
  printf '    (e) vacuous-axiom (repo-wide)\n'
else
  err ""
  err "==> [lint_fv] FAIL — see sub-lint diagnostics above."
fi

exit "${OVERALL_EXIT}"
