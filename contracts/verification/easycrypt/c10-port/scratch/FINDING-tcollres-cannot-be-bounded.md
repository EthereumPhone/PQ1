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

# FINDING — `Pr[T_COLL_RES_ENUM]` cannot be usefully bounded, and that is the result

2026-08-14. Written in response to "bound `Pr[T_COLL_RES_ENUM]`". The short
answer is that it cannot be bounded, for a reason that is a **parameter fact**
rather than a proof gap — and establishing that precisely is what the last two
days of work bought.

---

## 1. WHY THERE IS NOTHING TO PROVE HERE

`T_COLL_RES_ENUM` is a **hardness assumption**, not a derived quantity. In a
game-playing proof you do not *prove* a bound on an assumption's advantage; you
either

* (a) **carry it** as a named term — which is what `badenc_le_tcoll` now does; or
* (b) **reduce it** to a more standard assumption; or
* (c) **refute it**, by exhibiting an attack.

Route (b) is closed. Kimi K3 put it plainly and it matches the repo's own
`Extraction.ec` split: *"a codeword collision needs no `ThC` collision, and fibres
are ~2^127-wide, so it is a genuinely new assumption, not a corollary"* of
S-TCR(+C). The whole reason `T_COLL_RES_ENUM` exists is that the **B2** branch —
distinct digests, equal codewords — is not covered by any existing THF assumption
in the development. Reducing it to one would be circular.

So the only quantitative statement available is route (c): **what does the best
generic attack cost?**

## 2. THE NUMBER, COMPUTED EXACTLY

```
|C_T| = [x^205] ((1-x^8)/(1-x))^43
      = 22169393903687611906220091621190388
log2|C_T|          = 114.0941
surface fraction   = |C_T| / 8^43 = 2^-14.9059
birthday points    ~ 2^57.05
ThC evaluations    ~ sqrt(|C_T|) / p = 2^71.95
```

A generic birthday search over the constant-sum surface wins
`T_COLL_RES_ENUM` in ~**2^71.95** `ThC` evaluations, memoryless via
van Oorschot–Wiener. **No proof can bound the advantage below its best generic
attack.** Therefore `Pr[T_COLL_RES_ENUM]` is ~2^-72-class at deployed parameters,
and no placement, naming, or additional hypothesis changes that.

Independently reproduced twice: Kimi estimated 2^-14.7 / 2^70–2^74 from source
alone, and this repo's own
`experiments/tcollres-leg/FINDING-def11-is-unsound-at-c10.md:50` already recorded
`|C_T| = 2^114.094` and `~2^72.3`.

## 3. WHAT THAT MEANS AGAINST THE PROJECT'S OWN FLOOR

`tools/forsc_grinding_margin.py:143` sets `WORK_FLOOR_BITS = 96`. At ~2^71.95
this leg sits roughly **24 bits below** that floor.

**Read this carefully, because two different "96"s exist in this repo** and its
own FINDING warns about conflating them (`:128-129`): the 96 above is a **WORK**
floor. This finding is a statement about **the WOTS leg's proof term**, not a
claim that the product has 72-bit security.

## 4. WHAT IS *NOT* CLAIMED — the boundary that matters

**This is not an attack on the deployed wallet, and nothing here changes that.**
C10's WOTS layer never encodes an adversary-chosen value: it encodes
key-determined internal nodes (`sphincs-c10/src/fors.rs:265-268` —
`compute_fors_pk` takes no message argument). The birthday adversary needs to
choose `x` freely, which the **model** grants and the **deployment** does not.
Classification unchanged since the first Def-11 finding: **proof-technique
limitation, not a vulnerability.**

Also not claimed: that the assumption is *false*. It is a perfectly good
assumption; it simply cannot be assumed at a level above its generic attack.

## 5. SO WHAT DID THE LAST TWO DAYS BUY?

Precision about where the obstruction lives. Before:

* MM45's `:1513` admit was **false** at deployed geometry, and nobody could say
  what replaced it.

After:

* the admit is gone, replaced by an explicit charge (admit-free, closure 32/32);
* that charge is **provably 1** at the WOTS-TW layer (`badenc_is_one`) — so it
  could never have been bounded there;
* it is **moved**, uniformly over all `+C` adversaries, to a named assumption at
  a layer where the message is a keyed digest (`badenc_le_tcoll`);
* and that assumption's generic attack is now **computed exactly**.

The obstruction is therefore located precisely: it is
`(len=43, w=8, target_sum=205)`, a **parameter choice**, not a missing lemma.
That is a far more useful state than "there is an admit and we are not sure what
it costs".

## 6. THE ONLY HONEST NEXT UNITS

1. **Machine-check the count.** `|C_T| = 2^114.0941` is currently Python plus
   prose; nothing in EasyCrypt states it. Making it a theorem over `emsgWOTS`
   (the `Word` clone supplies `Alphabet.enum`/`enum_spec`, so a `FinType` route
   may exist) would put the load-bearing number inside the artifact instead of
   beside it. **Feasibility unmeasured.**
2. **Carry the figure to the headline**, in the genre of
   `tools/forsc_grinding_margin.py`, so the deployed statement quotes its own
   WOTS-leg ceiling rather than leaving it in an experiment directory.
3. **A parameter conversation, which is an owner decision, not a proof task.**
   If this leg must certify above 2^-72, `(len, w, target_sum)` has to change —
   and that changes `sig=4008`, the on-chain verifier, and every KAT. Nothing in
   this repo should make that call unilaterally.

**Do not** spend further effort trying to prove a bound on this term. There is no
bound to find.
