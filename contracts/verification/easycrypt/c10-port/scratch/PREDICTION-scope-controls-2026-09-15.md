# PREDICTION — the last admit's SCOPE ISOLATION becomes a gated, two-sided control set; PHASE 4's floors become equalities (written 2026-09-15, BEFORE the gate run)

## Where this comes from

`scratch/PREDICTION-scope-isolation-probes-2026-09-15.md`: ten probes, all as predicted.
- EasyCrypt reports `FORS_C_TreePort` (home of `extract_op`, the only admit) ABSENT from every headline
  environment.
- Environment witnesses rule out the "smaller environment" artefact.

This unit makes that fact FALSIFIABLE on every gate run rather than a one-off.

## Unit A — five PHASE 3 controls (EXPECT_CTLS 39 -> 44)

| control | polarity | declared reason / role |
|---|---|---|
| `scratch/_scope_neg_op_GprocTCollNamed.ec` | MUST-FAIL | ``unknown variable or constant: `FORS_C_TreePort.fverify_structural'`` |
| `scratch/_scope_neg_lemma.ec` | MUST-FAIL | ``unknown lemma `FORS_C_TreePort.extract_op'`` |
| `scratch/_scope_pos_op.ec` | MUST-PASS | twin of neg_op: the op probe is well-formed once the theory is loaded |
| `scratch/_scope_pos_lemma.ec` | MUST-PASS | twin of neg_lemma, same role for the lemma form |
| `scratch/_scope_env_n_m.ec` | MUST-PASS | after `require GprocTCollNamed.` a symbol 3 require-hops away resolves, so the negatives test the FULL environment |

Only GprocTCollNamed gets a negative probe: the other five headline files are in its own require-cone,
so its environment contains theirs. This stops being true if the family stops being a chain; the header
says so.

**This control set is the tripwire.** If any file in GprocTCollNamed's cone ever requires
FORS_C_TreePort, the negative probes COMPILE and PHASE 3 goes RED. The census would NOT catch that edit:
FORS_C_TreePort is already a closure root, so neither the cone file list nor statement coverage moves.
Only the identity does.

Claim upgrade, stated with its TCB: the bare-`smt()` hole (FINDING-bare-smt-reaches-the-admit.md) does not
apply to `extract_op`. That rests on EasyCrypt building a file's environment from its require closure
alone, and on tactics using only that environment. The hole stays stated in general, because it still
applies to any future admit in a REQUIRED theory.

## Unit B — PHASE 4 floors -> equalities

`g_ok -lt 4` / `st_ok -lt 3` printing literal `4/4` / `3/3` becomes `-ne` against committed
`EXPECT_MARGIN_GUARDS=4` / `EXPECT_MARGIN_SELFTESTS=3`, printing the MEASURED count. Also corrected: the
comment "the byte-identity cert-margin-split.tsv asserts" (that manifest holds 7 figures and no hash;
the pin is INPUTS_SHA256, and the script is byte-identical to PQ1 origin/master, re-checked 2026-09-15).
- Isolated-logic check before the run: extract the new count lines and feed them doctored outputs with
  3 / 4 / 5 guardrail lines and 2 / 3 / 4 self-test lines. Predicted: 4 and 3 give OK, the rest FAIL
  naming the measured count.

## Predictions for the gate run (ec-grind, r2026.02, 25 provers)

- GREEN, identity changes.
- No closure .ec changed: closure 42, cli 46/0, pins 1167, coverage 1082/53, census added=0 removed=0,
  ledger 241 / parameters 221 / bindings 366 / meaning 406 / definitions 443 / total 1677.
- Controls `executed (unique)=44 expected=44`: the two negatives rejected for the declared reason, the
  three positives OK.
- PHASE 4: `margin guardrails 4/4` and `negative controls 3/3`, now measured.
- PHASE 5 unchanged: taint closure 2 / 9 headlines, taint controls pass=11 unique=11, count controls
  pass=4.

## Outcome

- PRE-RUN, scope controls: every probe header grew from 1 comment line to 3, so the [critical]
  line numbers moved (line 4 -> 6/7). The declared reasons carry no line numbers, but that was
  re-checked, not assumed: an untracked runner (`scratch/_run_scope_ctls.sh`) copies PHASE 3's
  compile + first-[critical] + `grep -F` lines, and in ec-grind (r2026.02) it graded 5/5 for the
  declared reason.
- PRE-RUN, PHASE 4 isolated-logic check MATCHED. The BEGIN/END-marked lines, fed doctored output:
  guards 3 -> FAIL "printed 3 ... expectation is 4", 4 -> OK `4/4`, 5 -> FAIL; self-test
  2 -> FAIL, 3 -> OK `3/3`, 4 -> FAIL. Fed the REAL script output: `4/4` and `3/3` OK. Stated
  honestly, the way EXPECT_WATCHED's test was: this is an isolated check of the decision lines,
  not wired into the gate.
- REVIEW (Kimi K3, one leg; GPT-5.6 MCP down). Run against a disposable scratchpad COPY so Run 4's
  hashed inputs could not be touched. After the run the copy differed from the tree only in build
  artifacts (3 .eco, __pycache__); `rsync -rcn` found zero source differences. Kimi's probes ran on the
  HOST EasyCrypt, not ec-grind: corroboration, not a receipt.
  - VERDICT: holds.
  - Reproduced: all five controls, byte-identical `[critical]`; the negative op-probe against EACH of
    the six headline theories (all reject); the cone via an independent looser require scan (0 diffs).
  - Bypass routes refused: `import`/`export` of an unrequired theory, `Top.`-qualified name, `clone`,
    `hint exact`, `require` inside a section.
  - HOLE 1 (medium, adopted): the CHAIN precondition is disclosed but unguarded. All six headline files
    are closure roots (verified: closure-c10-split.txt), so de-chaining one moves nothing.
    Recommended: register per-file negatives (EXPECT_CTLS 44 -> 49), or a per-root cone assertion.
    Until then the claim sentence carries the caveat.
  - HOLE 3 (low): renaming both probed symbols would keep the negatives failing for the declared
    reason. PHASE 2 census rows move on those renames, so this is defence in depth.
- GATE RUN 4 MATCHED EVERY FIGURE. ec-grind, `### TOOLCHAIN GIT hash: r2026.02`,
  `### PROVERS 0a5b3d54dcce300e 25 configurations`; RESULT GREEN, 0 FAIL lines; identity 0ee26aa9
  matched at start and end.
  - Closure: CLOSURE_COMPILED=42; CLI_FILES_RUN=46, CLI_DISAGREEMENTS=0; pins 1167/1167; coverage
    1082 / 53 cone files.
  - Census: added=0 removed=0; ledger=241 parameters=221 bindings=366 meaning=406 definitions=443
    total=1677.
  - Controls: executed (unique)=44 expected=44. The two scope negatives were rejected for the DECLARED
    reason; the three positives OK.
  - PHASE 4 prints measured `4/4` and `3/3`; margin figures 7/7.
  - Taint: closure 2 / 9 headlines; taint controls pass=11 unique=11; count controls pass=4.
