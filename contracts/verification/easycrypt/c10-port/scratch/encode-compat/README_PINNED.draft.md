
### UPDATE 2026-08-27 (second) — the encoder can be PINNED, not merely width-constrained

`EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_PINNED_ENCODER` (same file) carries the
same **two** premises as its sibling, but the second one is different in kind:

```
c <= p_tgts          a parameter choice
emb_in = c10_embg    the SERIALISATION ITSELF, not merely its width
```

The width fact `size (emb_in witness) = 8*n + c10_r` is **derived** here rather than
assumed, from `C10DeployedInstance.ec::c10_embg_size`, which is proved premise-free.

#### This is not a cosmetic re-spelling — the width premise is degenerately satisfiable

The reason is recorded in this tree, from an adversarial review on 2026-08-01
(`C10DeployedInstance.ec:322`):

> *"a CONSTANT `emb_in` satisfies it while collapsing every ThC input and making the
> S-TCR term trivially winnable."*

A constant encoder does not make the sibling's bound **false**. It makes it
**uninformative** — it sends the S-TCR summand to ~1, and the inequality then holds for
reasons that have nothing to do with C10. Pinning `emb_in = c10_embg` excludes exactly
those models.

**And that exclusion is a theorem here, not a comment.**
`GprocChargedQWired.ec::pinned_encoder_is_not_degenerate` proves

```
emb_in = c10_embg => exists (x y : dgstblock * cntr), emb_in x <> emb_in y
```

with **no side condition** — `c10_embg_not_constant` is itself premise-free. Full
injectivity additionally needs the counter-space bound
`STCRC_WC.G.CntrFT.card <= 2 ^ c10_r` and is `c10_embg_inj` /
`c10_embg_meets_LEN_and_INJ`; it is not restated in the capstone file.

#### What it costs, and what it does not buy

**Neither variant supersedes the other, and the README does not pick one for you.**
`emb_in = c10_embg` is a **strictly stronger** premise than the width fact, so this
theorem covers **fewer models** than `_AT_DEPLOYED_PARAMS`. The width form is more
general; this one is more informative. Both are gated closure members. Quote whichever
the claim actually needs — and say which.

**It does not verify the deployment.** `c10_embg` is an EasyCrypt definition
(`DigestBlock.val x.\`1 ++ int2bs c10_r (index x.\`2 …)`). That it matches what
`sphincs-c10` actually serialises is a **fidelity claim**, argued in
`C10DeployedInstance.ec` and **not machine-checked against the Rust**. Pinning the encoder
moves the assumption from *"some encoder of this width"* to *"this specific encoder"*; it
does not close the gap to the implementation.

#### A coverage hole closed in the same change

PHASE 5's `HEADLINE` list is what makes taint containment mean anything: a headline result
**absent** from that list is simply not checked. Adding a capstone without adding it there
is a silent hole, so the new variant was added to the list in the same commit — the phase
now reports *"none of the **7** headline results is in it"*, and the five discriminating
controls were re-run against the extended list (still 5/5).

#### Cost

Predicted before the run and matched: pins 1072 → **1074**, statements 987 → **989**,
coverage 989/989, census `added=0 removed=0`, **ledger 242**, `CONE_FILES` 45, taint
closure 6 — and **zero existing statement digests moved**, since both new lemmas are
additions rather than edits.
