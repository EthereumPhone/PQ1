# PREDICTION — is the last admit OUT OF SCOPE for every headline file? (written BEFORE running)

## Question

`extract_op` (cdrafts-split/FORS_C_TreePort.ec:1485) is the only admit left. The parser says no
cone file requires `FORS_C_TreePort`: none of the 6 headline files' require-cones contains it
(sizes 24..44), and neither does the union cone of the other 45 closure roots (51 files).

If EasyCrypt agrees, no tactic in a headline file can use the admit by ANY route — named
application, bare `smt()` (the 2026-08-28 hole), clone or module argument. Every one of those
needs the theory loaded, and loading means `require`. That would make PHASE 5's containment
scoping-grade for this admit, not just name-level. This is only a feasibility check: probes,
no gate edits.

Why name resolution and not an smt reach test: `extract_op`'s statement is built from `G_Tree`,
`R_op`, `O_OP_Default` and `fverify_structural`, which are all DEFINED in FORS_C_TreePort.ec, so
the statement cannot be restated outside that theory. The 2026-08-28 probes (P1, P2) both
`require import SPHINCS_PLUS`, i.e. they reached the admit through the require-built
environment, which is exactly the channel this test cuts.

## Probes (untracked scratch/_scope_*.ec; `easycrypt compile -I base-c10-split -I cdrafts-split`,
## graded on the first [critical] line, as PHASE 3 does)

| probe | requires | body | prediction |
|---|---|---|---|
| pos_op | GprocTCollNamed + FORS_C_TreePort | `op probe_scope : bool = FORS_C_TreePort.fverify_structural.` | PASS |
| pos_lemma | GprocTCollNamed + FORS_C_TreePort | `have _ := FORS_C_TreePort.extract_op.` | PASS (~60%: module-quantified `have :=` may be rejected) |
| neg_op_<H> x6 | headline theory H only | the op probe | FAIL, reason names an unknown symbol |
| neg_lemma | GprocTCollNamed only | the lemma probe | FAIL, unknown symbol |
| env_n_m / env_dskWOTS | GprocTCollNamed only | `op probe_env = WOTS_TW_ES.<sym>.` (3 require-hops away) | at least one PASS |

## What decides it

- The env witnesses are what keep the negative probes honest. If requiring a headline theory did
  NOT make its transitive dependencies resolvable, a neg probe's environment would be SMALLER than
  the headline file's own, and it would "fail" for the wrong reason. If both env probes fail,
  switch to copy-based probes (the probe appended to a copy of each headline file).
- If any neg_op_<H> PASSES, the parser's cone is wrong about that file and the candidate is dead.
  That would itself be a finding.

## Outcome — EVERY PREDICTION HELD (ec-grind, `GIT hash: r2026.02`, 2-4 s per probe)

```
_scope_pos_op.ec         rc=0
_scope_pos_lemma.ec      rc=0      (the ~60% case held: module-quantified `have :=` is accepted)
_scope_env_n_m.ec        rc=0
_scope_env_dskWOTS.ec    rc=0
_scope_neg_lemma.ec      rc=1  [critical] ... unknown lemma `FORS_C_TreePort.extract_op'
_scope_neg_op_<H>.ec x6  rc=1  [critical] ... unknown variable or constant: `FORS_C_TreePort.fverify_structural'
   H in {GprocChargedQWired, SphincsC10CapstoneWired, GprocQWired, GprocQBound, GprocWotsNamed, GprocTCollNamed}
```

Reading, with its limits:
- The env witnesses PASS: after `require GprocTCollNamed.`, a symbol 3 require-hops away resolves
  by qualified name. If ANY headline theory's dependency set loaded FORS_C_TreePort, its qualified
  name would resolve too, as pos_op shows. So EasyCrypt itself, not the repo's parser, reports the
  admit's theory absent from all 6 headline environments.
- The 5 other headline files are all in GprocTCollNamed's own require-cone, so its probe alone
  covers them. The six separate probes are redundant today; they stop being redundant the moment
  the headline family stops being a chain.
- WHAT THIS RELIES ON (the TCB, stated): EasyCrypt builds a file's environment from its require
  closure plus the prelude, with no ambient loading from the include path, and a tactic (bare
  `smt()` included) can only use facts in that environment. The probes are consistent with that;
  they do not prove EasyCrypt's implementation of it.
- Environment witnesses were run for GprocTCollNamed only.
