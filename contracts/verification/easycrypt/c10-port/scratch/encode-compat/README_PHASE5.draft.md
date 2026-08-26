### UPDATE 2026-08-26 — "neither admit reaches the headline" is now GATE-ENFORCED (PHASE 5)

This artifact has said, in this file and in `project_c10_two_admits_scoped`, that **neither
of the cone's two admits reaches the headline**. That was true, and it was **hand-verified
each time somebody remembered to re-verify it**. Nothing in the gate checked it.

The fail-open was recorded in the admits note verbatim: *"`ledger class = 0` computed
**file-locally** reads as 'admit-free cone' and is a fail-open. Assert instead that the
file never **applies** the tainted lemma."* PHASE 5 does that.

#### What it computes

`tools/taint_closure.py` seeds on the cone's `admit`ed lemmas and takes the fixpoint of
"lemma L's proof body names a tainted lemma", over **comment-stripped** code. The result
is pinned in `cert-taint-closure.tsv`; **entering and leaving are both fatal**, the same
discipline PHASE 2 applies to the census.

```
A  nhchwcoll_hchwpre_msg  (ADMIT)                       base-c10-split/WOTS_TW_ES.ec:1505
     -> Step_Game4_WOTSTWES_SMDTPREC                                              :6338
     -> MEUFGCMA_WOTSTWESNPRF                                                     :6578
     -> EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Unfolded    XmssmtCC_All.ec:8811  <- APPLIED BY NOTHING
B  extract_op              (ADMIT)               FORS_C_TreePort.ec:1485
     -> fors_c_tree_port                                             :1646  <- APPLIED BY NOTHING
```

Six lemmas; **both chains terminate in a dead leaf**, and none of the six headline results
is among them.

**Why this is worth a phase rather than a comment.** `nhchwcoll_hchwpre_msg` is not merely
unproven, it is **REFUTABLE** — a collision falsifies the whole five-hypothesis lemma, for
any `sig`/`sig'`. So the containment is not a tidiness property: wiring
`EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Unfolded` into the headline would promote a **false** lemma
into the certified result. The admits note already names that as *the* regression to guard
("merely wiring `_Unfolded` is a REGRESSION"). Control **T1** performs exactly that wiring
and requires the gate to reject it.

#### Honest scope — this is the deliverable as much as the check is

PHASE 5 is a **NAME-LEVEL OVER-APPROXIMATION**, not a proof-term dependency check.
EasyCrypt has no `#print axioms`. It does **not** see:

* a bare `smt()` that takes a lemma from ambient context without naming it;
* reachability through a clone instantiation or a module argument rather than a named
  application.

The over-approximation direction is the safe one for an *exclusion* claim — a name absent
from the closure is absent from the true closure — **except** through those two holes,
which is precisely why they are written into the tool header, the manifest header and the
phase header rather than left for the next reader to find. A check that reads stronger
than it is becomes the next fail-open.

#### The five controls

A containment check that cannot go RED is decoration. Each control **deletes** a specific
piece of information and must be rejected **for the declared reason** — graded on the
message, not on exit status.

| control | deletes | must report |
|---|---|---|
| T0 | nothing (baseline) | must **PASS**, else every control below is vacuous |
| T1 | the containment itself — wires `_Unfolded` into the headline | `HEADLINE IS TAINTED` |
| T2 | the admit (`admit.` → `trivial.`) | `anti-vacuity` |
| T3 | the manifest contents | `no rows` |
| T4 | a manifest line number's validity | `does not resolve` |

T4 exists because of a defect this repo has hit twice: a check that *runs against nothing*
and agrees with itself (`NOT-FOUND` comparing equal; an empty file digesting to the very
verdict under test). Every manifest site must still **resolve** — file present, line in
range, symbol actually on it.

#### Three defects found while building it, all in my own work

* **The chain I first wrote was wrong.** I claimed `WOTS_TW_ES.ec:6542` sits inside
  `MEUFGCMA_WOTSTWESNPRF`'s proof. But `6542 < 6578` — it is *before* that lemma is
  declared. It is inside `Step_Game4_WOTSTWES_SMDTPREC`, and the real chain has an extra
  link. Caught by adversarial review asking me to confirm enclosure by proof boundaries
  rather than line ordering.
* **The tool had a false positive**, and it is a genuinely hard case:
  `FORS_C_TreePort.ec` declares **both** `op extract_op` (`:1148`) and
  `lemma extract_op` (`:1485`). `op_extract_wins` (`:1173`) uses the **op**. A name-level
  tool cannot tell them apart. Fixed by a *positional rule* — EasyCrypt has no forward
  lemma references, so a mention before the declaration cannot be a use — plus an explicit
  `ambig` label wherever the rule cannot decide, retained rather than dropped (retaining
  can only enlarge the closure, never let a taint escape). The one `ambig` row was then
  resolved **by hand**: `:1674` reads `apply (extract_op A &m struct nd bs los oreg simfid)`
  — adversary and memory arguments, so the lemma. The label stays `ambig` because that is
  what the *tool* can justify; the comment records what a *human* checked. They are
  deliberately not reconciled.
* **T2 silently failed to discriminate on its first run.** The raw source line is
  `admit.    (* <-- THE PRE-EXISTING GAP ... *)`, so an exact `strip()=='admit.'` match
  never fired and the control passed while testing nothing. Diagnosed rather than re-rolled.

#### And the identity calculator went stale, in a new way

`scratch/encode-compat/inputs_id.sh` had **duplicated** the gate's hashed-file list. The
moment PHASE 5 added three files to that list, the calculator confidently produced a wrong
identity (`a86a4a72…` against the gate's `b661e2a6…`). This is the same defect as
hand-rolling the census `comm` diff: *reimplementing what the gate already computes.* It
now **derives** the list from `cert_gate_split.sh` and reproduces the gate's value exactly.
`a86a4a72…` appears nowhere as a real identity and is recorded in `cert-identity.tsv` as
the artefact it is.

#### Cost

No EasyCrypt content changed: no `.ec` file is touched. Census `added=0 removed=0`,
**ledger 242**, pins 1072, coverage 987/987 — all unchanged. This adds a phase, a tool, a
manifest and a control fixture; the identity moves because three files joined the hashed
set. It does **not** remove either admit — that is the separate `ENC_COLL_WOTS` unit the
admits note scopes at 12–18 engineer-days, and it needs its own decision.
