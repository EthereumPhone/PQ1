> **SUPERSEDED IN PART — read before quoting anything below.** (banner added 2026-09-14)
> Two load-bearing claims in this file were **retracted on 2026-08-14 (final)** and the
> numbers that replaced them were **withdrawn on 2026-08-18**:
> * *"C10's WOTS layer never encodes an adversary-chosen value / key-determined nodes"* is
>   **FALSE at the verifier**: the FORS secrets and auth paths that form the WOTS message are
>   read from the signature (`sphincs-c10/src/hypertree.rs`).
> * *"~2^71.95 / ~2^-72, there is no bound to find"* priced the oracle's grinding as adversary
>   work and ignored that one collision side must be a RECORDED entry — retracted.  The
>   `2^-82` / `2^-78.09` figures that replaced it were in turn **withdrawn**: a surface
>   cardinality does not yield an advantage bound without a model nobody has derived.
> Standing position: `Pr[T_COLL_RES_ENUM]` is an **unbounded assumption**; the surface count
> is a theorem; **no derivation connects them.**  Sources: `scratch/FINDING-both-my-claims-were-wrong.md`,
> `scratch/FINDING-do-not-import-the-policy-cap.md`, and the vendored README's
> *CORRECTION 2026-08-14 (final)* and *CONCLUSION 2026-08-18*.
> Why this banner exists: on 2026-09-14 this file was read as current and its retracted
> numbers were drafted into a new theorem header before the README's corrections were found.

# FINDING — seed-withholding is NOT the lever, and the birthday number is already ours

2026-08-13. Kimi K3 review of the charge-placement decision. Two results, pulling
in opposite directions, both verified at source before adoption.

---

## 1. CORRECTION — "seed-withholding is where the bound lives" is WRONG

I have said this repeatedly today, including in pushed commits and in the public
`c10-port/README.md`. **It does not hold.** Verified:

* `WOTS_TW_ES.ec:2526` — `proc choose() : unit { O.query, OC.query }`. The
  adversary **may call `OC.query` during `choose`**.
* `Game4_WOTSTWES_BadEnc.main` — `O_THFC_Default.init(ps)` runs **before**
  `A.choose()`. `OC` is keyed with the real `ps` from the start.

So the adversary evaluates the keyed collection throughout `choose`. Withholding
the *value* of `ps` from `choose` blocks only **oracle-free offline** computation,
which is irrelevant to a collision event it can obtain by querying.

**The mechanical danger Kimi names, and it is the important part:** if I write the
+C assumption *believing* withholding is the protection, I produce a game whose
`choose` has no `OC` — which **under-models the real adversary**. That is a silent
soundness gap in the bridge, not a cosmetic error.

The actual levers are **per-index freshness**, **`dist_wgpidxs`** (which kills
cross-address replay — precisely the singleton-query trick my own `A_coll` uses),
and **`ThC`-mediation of digests**. None of them is seed secrecy.

*(Provenance: this framing was inherited from the previous session's closing
recommendation, which I already retracted once on different grounds — see
`FINDING-seed-withholding-has-no-isolated-step.md`. This is the second, and
deeper, defect in the same idea. It should now be considered dead.)*

## 2. THE "STRONGEST OBJECTION" IS A REDISCOVERY OF OUR OWN FINDING

Kimi's headline objection is a model-level birthday attack costing ~2^70–2^74,
flagged by Kimi as an *estimate* with the exact count left to us. I computed it:

```
|C_T| = [x^205] ((1-x^8)/(1-x))^43
      = 22169393903687611906220091621190388
log2|C_T|          = 114.0941
surface fraction p = 2^-14.9059          (Kimi estimated 2^-14.7)
birthday points    ~ 2^57.05
ThC evals ~ sqrt(|C_T|)/p = 2^71.95      (Kimi estimated 2^70-2^74)
```

Kimi's estimate was accurate to ~0.2 bits. **But this is not new.**
`experiments/tcollres-leg/FINDING-def11-is-unsound-at-c10.md:50` already records
*"birthday-collide inside `|C_T| = 2^114.094` — ~2^72.3–72.95 hashes"*, and `:164`
already records the same 2^114.09 as the reason `two_encodings` is a false axiom.

**Treat this as convergent confirmation, not a new defect.** An independent model,
given only the source, reproduced our own number. That is worth more as
corroboration than it would have been as news.

**And the deployed classification is unchanged.** That same FINDING records why:
C10's WOTS layer never encodes an adversary-chosen value — it encodes
key-determined internal nodes (`sphincs-c10/src/fors.rs:265-268`,
`compute_fors_pk` takes no message argument). Kimi's attack needs the adversary to
choose `x` freely, which the **model** grants and the **deployment** does not.
Proof-technique limitation, not a vulnerability. Unchanged.

## 3. KIMI CORRECTS MY OWN FRAMING — "quantitatively vacuous" was the wrong charge

I described the charged theorem as *"true but quantitatively vacuous"* because its
RHS is ≥ 1 at a generic adversary. Kimi's objection to that framing is right:

> `Pr[G] <= terms + Pr[bad]` is the Bellare–Rogaway fundamental-lemma shape. Such
> a decomposition is *never* expected to be < 1 for all `A`. "RHS ≥ 1 for
> `A_coll`" is not vacuity of the theorem — it is the absence of a bad-event bound
> **at that instantiation**, a defect located at the quotation site, not in the
> theorem.

I was judging a decomposition lemma by its standalone quantitative content. The
architecture is **salvageable**, on two conditions I accept:

1. `MEUFGCMA_WOTSTWESNPRF_Charged` is an **internal decomposition** and must never
   be quoted as a standalone WOTS-TW security statement for arbitrary `A`;
2. the named-assumption term must eventually **replace** the raw
   `Game4_WOTSTWES_BadEnc` term at the headline. Until it does,
   `GprocQWiredWotsCharged` displays that term raw — honest, but an **undischarged
   debt**, and my own countermodel proves it is 1 for some adversaries, so the
   headline currently proves nothing quantitative on that branch.

## 4. WHAT THIS CHANGES ABOUT THE NEXT UNIT

The deliverable is **not** "bound the charge". At C10's deployed parameters the
WOTS-layer term is ~2^-72-class **wherever it is placed and whatever it is named**
— that is a property of `(len=43, w=8, target_sum=205)`, not of the proof
engineering. So the honest next unit is to carry that number to the headline
explicitly, in the genre of `tools/forsc_grinding_margin.py`, rather than to hunt
for a placement that makes it small.

The exact count above is the input that unit needs, and it is now computed.

---

## 5. GPT-5.6's INDEPENDENT VERDICT — and where it goes further than Kimi

**CONVERGENT, both models, both verified at source independently:**

* **Seed-withholding is insufficient.** GPT: *"withholding is a useful
  target-selection timing condition, not a hardness proof."* Same mechanism, same
  citations. Two independent confirmations of a claim I had published — treat it
  as settled.
* **The architecture is salvageable**, and replacing the false admit was genuine
  progress; but the end-to-end charged theorem is **bookkeeping until the bridge
  lands**. GPT: *"this leg contributes no demonstrated nontrivial bound."*

**GPT GOES FURTHER — VERDICT: MOVE THE CHARGE TO +C.** Not a middle position: the
paid security term should no longer be `Game4_WOTSTWES_BadEnc`. Keep the WOTS
disjunction as a proof-local fact only.

**AND IT CORRECTS ME AGAIN.** I wrote that the term can only be bounded "for the
*specific* deployed adversary". **Wrong.** `R_int_WOTSTW` is defined for *every*
`Adv_MEUFGCMA_WOTSC` (`WOTS_C_Interactive.ec:1753`), every signing query becomes
`ThC ps ad m c`, and the relational invariant maps the whole query log
(`:1873`). So a +C theorem can be **uniform over all admissible +C adversaries**,
not merely at `R_top_C(F)`. That is a strictly better statement than the one I
was planning, and my framing would have under-sold it.

GPT also sharpens my countermodel's claim: it proves probability one *conditional
on a gated colliding pair it does not construct*, so "the term is unconditionally
1" is too strong. **What it proves is that the generic theory cannot supply a
nontrivial bound.** Adopt that phrasing.

### The assumption GPT names — and the repo already isolated its branch

`T-COLL-RES-ENUM(encode_msgWOTS o ThC)`. "ENUM" is load-bearing: C10 enumerates
counters **deterministically**, so this is not paper Definition 11, which samples
counter randomness (`IncEnc.ec:276` says a separate coupling is required).

Three design points, each verified by me at source rather than taken on trust:

1. **The discriminator is `d <> d'`, not `m' <> m`.** And this is not new — the
   repo already split it: `experiments/tcollres-leg/Extraction.ec:66-76` names
   **(B1)** ThC digests already collide → S-TCR(+C), and **(B2)** digests differ
   but codewords agree → an `encode_msgWOTS` collision on distinct digests. GPT's
   assumption *is* the B2 branch. **VERIFIED.**
2. **Do not require `c' = grindC ps ad m'`.** `WOTS_C_Scheme.ec`'s `verify` takes
   `sigc : sigWOTS * cntr` and recomputes the encoding from the **supplied**
   counter. **VERIFIED** — requiring the honest counter would model a weaker
   adversary than the scheme admits.
3. **`OC` must stay available during `pick`.** Omitting it models an easier game
   than the real reduction — the identical trap Kimi named from the other
   direction. Two models, same warning.

Placement: a +C "hop 1.5" between `GAME1_INT` and `interactive_hop2`, reusing the
`R_int_STCRC` skeleton. GPT flags honestly that this is **not yet a proved
reduction** — the current BadEnc game uses the artificial Game4 `AltX` oracle
(`WOTS_TW_ES.ec:3206`), so an exact new simulation/coupling is required.

### RECONCILING THE TWO VERDICTS

They are not in conflict. **GPT decides placement; Kimi decides expectations.**

* Move the charge to +C (GPT) — that buys a theorem **uniform over all +C
  adversaries** instead of one instantiation.
* But at `(len=43, w=8, target_sum=205)` the resulting term is **~2^-72-class
  wherever it is placed and however it is named** (Kimi, and our own
  `FINDING-def11-is-unsound-at-c10.md`). Moving it does not make it small.

So the next unit is **both**: build the +C game so the statement is uniform, and
carry the 2^71.95 number to the headline honestly rather than hunting for a
placement that hides it.

---

## 6. CORRECTION TO MY OWN VERIFICATION — `Extraction.ec` is STALE, and I said "VERIFIED"

I cited `experiments/tcollres-leg/Extraction.ec:66-76` as establishing the B1/B2
split and marked it **VERIFIED**. I verified the *prose*. I did not check that the
file **compiles against current source**. It does not:

```
easycrypt compile -I base-c10-split -I cdrafts-split -I experiments/tcollres-leg \
  experiments/tcollres-leg/Extraction.ec
[critical] Extraction.ec:51  no matching operator, named `encode_msgWOTS_C'
__RC=1
```

`coll_splits_by_level` declares `(m m' : msgWOTS)` and applies `ThC ps ad m c`,
but current `ThC` takes `m : dgstblock` (`WOTS_C_Real.ec:214`). The file predates
the message-type split — **the same staleness that killed
`RESULT-premise-reduction.md`**, and the sixth `experiments/` file to go stale.

**The concept survives; the lemma does not.** B1 (equal `ThC` digests → existing
S-TCR(+C)) versus B2 (distinct digests, equal codewords → `T_COLL_RES_ENUM`) is
still the right split, and `T_COLL_RES_ENUM`'s `dg <> dg'` discriminator is still
right. But the split must be **restated against current types** before any
reduction can consume it. Do not `require Extraction.ec`.

**The lesson is about my own rule.** "Verify their load-bearing citations" was
applied at the wrong depth: I confirmed the citation *says* what the reviewer
claimed, not that it is *live*. For a repo with six known-stale experiment files,
"the text is there" and "the lemma holds in this tree" are different facts, and
only the second one can be built on. Compile-test cited lemmas from
`experiments/` before consuming them.
