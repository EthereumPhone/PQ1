> **PROMOTED 2026-09-21 — the four proof files have MOVED.**
> `VecDP.ec`, `CountDS.ec`, `C10SurfaceKernel.ec` and `C10Surface.ec` are now certified closure
> members at `cdrafts-split/`, moved (not copied) per the 2026-08-19 PTgtsPin precedent, so there
> is exactly one definition of these facts in the tree. The controls in `controls/` stay here and
> bind to them via `require import` plus the gate's `-I cdrafts-split`; six of the eight are
> registered in `cert-controls-split.tsv` (KctlA and KctlB are not — they fail by
> `anomaly: Stack overflow` rather than by proof, so they do not discriminate; see that file).
> `ScriptProbe.ec`, `run.sh` and `runall.sh` below refer to the pre-move layout and are kept as
> the development record; they no longer run as written.

# `count` — the C10 constant-sum surface size, machine-checked in EasyCrypt

**Question asked.** `scratch/FINDING-tcollres-cannot-be-bounded.md` quotes

```
|C_T| = [x^205] ((1-x^8)/(1-x))^43 = 22169393903687611906220091621190388 = 2^114.0941
```

as Python plus prose. Nothing in the EasyCrypt artifact stated it. This directory
puts it inside the artifact.

**Answer.** T1, T2, T3 and T4 all land, admit-free. `count_ds 43 8 205` is
*evaluated* — not asserted — inside EasyCrypt, in **41 s**.

---

## What is proved

| Target | Statement | File | Tactic that closed it |
|---|---|---|---|
| T1 | `count_ds0`, `count_dsS`, `count_ds_neg` | `CountDS.ec` | `rewrite iter0` / `rewrite iterS` / induction + `big1_seq` |
| T2 | `count_ds_counts_digit_vectors` | `CountDS.ec` | induction + `allpairsP` / `allpairs_uniq` / `count_map` |
| T3 | `c10_surface_count : count_ds 43 8 205 = 22169393903687611906220091621190388` | `C10SurfaceKernel.ec` | `rewrite` chain ending in `by []` (**reduction**, 41 s) |
| T4 | `c10_surface_bits`, `c10_surface_fraction` | `C10Surface.ec` | `rewrite` + literal constant folding |
| T2+T3 | `c10_surface_is_a_cardinality` (composed, no `count_ds` in the statement) | `C10Surface.ec` | `rewrite` + `exact` |

### T1 — the recursion

```
op cstep (b : int) (f : int -> int) : int -> int =
  fun s => bigi predT (fun d => f (s - d)) 0 b.
op count_ds (n b s : int) : int = iter n (cstep b) (fun t => b2i (t = 0)) s.
```

`count_ds` is **not** defined to be 22169…; it is the plain DP recursion, and the
35-digit number is produced by *computing* it.

### T2 — the correctness lemma (the real content)

The **list route** was taken, as the task allowed. `words n b` is the explicit
enumeration `iter n (allpairs cons (range 0 b)) [[]]`, and:

```
lemma count_ds_counts_digit_vectors (n b s : int) : 0 <= n =>
     count_ds n b s = size (filter (fun l => sumz l = s) (words n b))
  /\ uniq (filter (fun l => sumz l = s) (words n b))
  /\ (forall l, (l \in filter (fun l => sumz l = s) (words n b))
                <=> (size l = n /\ all (is_digit b) l /\ sumz l = s)).
```

Read together, the three conjuncts say: `count_ds n b s` is the **size of a
duplicate-free list whose members are exactly** the `int list`s of length `n`
with every entry in `[0,b)` and `sumz` equal to `s`. Uniqueness is proved
(`uniq_words`), so this is a genuine cardinality and not a multiset count.

### T3 — evaluation, and why it works

EasyCrypt's `iota_` (hence `range`, `mkseq`) and `iteri` (hence `iter`, `nseq`)
are **axiomatised, not defined**, so `simplify` cannot reduce them; and `^` on
`int` does not reduce either (measured: `smt()` on `2^114 = <literal>` fails
after 27 s with *cannot prove goal (strict)*). Structural list recursion over
integer literals **does** reduce. `VecDP.ec` therefore restates the DP as a
sliding window in an orientation that makes it a plain structural recursion with
no accumulator:

```
op vstep (b : int) (v : int list) : int list =
  with v = []      => []
  with v = x :: v' => sumz (take b (x :: v')) :: vstep b v'.
```

Position `i` of the state carries the count for target sum `S - i`, so the step
`new[i] = v[i] + … + v[i+b-1]` runs *forward* along the list. `runs` iterates it
using a list as fuel (again: a list, because `iter` is opaque), and `vinit`
builds `[0;…;0;1]`.

`CountDS.ec` bridges the two — `count_ds_kernel` — via `vrep`, `nth_vstep`,
`sumz_take_drop`, `vstep_rep`, `vinit_rep`, `runs_rep`. (`count_ds_neg` is a T1
shape lemma and is *not* load-bearing for the bridge: `vstep_rep` gets the
out-of-range case from the `forall i, 0 <= i` form of `vrep` plus `nth_default`.)

**Without that bridge the 41 s computation would be a fact about an ad-hoc
operator, not about `count_ds`.**

### T4

```
lemma c10_surface_bits : 2 ^ 114 < count_ds 43 8 205 < 2 ^ 115.
lemma c10_surface_fraction :
     8 ^ 43 < count_ds 43 8 205 * 2 ^ 15
  /\ count_ds 43 8 205 * 2 ^ 14 < 8 ^ 43.
```

The second is the surface-fraction bound `2^-15 < p < 2^-14` (exact value
`2^-14.9059`) written as integer inequalities, so no reals are involved. The
powers are evaluated with the same reducible-structural trick (`powl` + `powlE`).

---

## What is **NOT** proved — the `emsgWOTS` gap, enumerated

The counted objects here are `int list`s. **They are not WOTS codewords, and this
directory must not be cited as counting codewords.** To turn
`count_ds 43 8 205 = |C_T|` into a statement about `WOTS_TW_ES.ec`'s
constant-sum surface, all five of the following would have to be supplied:

1. **`len` is abstract.** `WOTS_TW_ES.ec:74` declares `const len : { int | 2 <= len }`.
   Nothing links it to `C10DeployedGeometry.ec:69`'s `c10_len = 43`.
2. **`w` is abstract.** `WOTS_TW_ES.ec:97` gives only `val_w : 4 <= w`. Nothing
   links it to `c10_w = 8`, and nothing establishes that `BaseW.val` ranges
   bijectively over `[0,8)`.
3. **`target_sum` is not 205.** `WOTS_TW_ES.ec:647` *defines*
   `target_sum = digitsum (encode_msgWOTS tgt_witness)` — deliberately, so the
   gate is non-vacuous. `C10DeployedGeometry.ec:101-104` says in as many words
   that "205 is attainable" is proved while "the deployed encoder reaches 205" is
   **not** claimed.
4. **No bridge from `emsgWOTS` to `int list`.** `emsgWOTS` is a `Word` clone
   (`WOTS_TW_ES.ec:275-284`) over the `baseW` subtype with
   `Alphabet.enum = map (oget \o BaseW.insub) (range 0 w)`. Connecting it needs a
   `FinType`/enumeration for `emsgWOTS`, a bijection with length-`len` digit
   lists, and `digitsum e = sumz (that list)` — none of which exists here.
5. **Surface size is not fibre size.** Even fully bridged, `|C_T|` counts
   *codewords*. `T_COLL_RES_ENUM`'s B2 branch is about *messages* colliding
   through `encode_msgWOTS`; the ~2^127-wide fibres are a separate object.

An honest one-line summary: **the number is now a theorem; its identification
with the codeword surface is still prose.**

Likewise, the `~2^71.95` birthday figure in the FINDING is **not** mechanised
here — it needs `sqrt` over reals. T4 gives the two integer facts that figure is
computed from (`2^114 < |C_T| < 2^115`, `2^-15 < p < 2^-14`); the square root is
still arithmetic done outside.

---

## Controls

`controls/` holds must-fail and must-pass controls. **`runall.sh` records every
RC; `receipt.txt` is the receipt.**

| Control | Perturbation | Required | Observed (from `receipt.txt`) |
|---|---|---|---|
| `KctlA` | kernel value `+1` | FAIL | `RC=1 ECO=NO`, `anomaly: Stack overflow`, 47 s |
| `KctlB` | fuel length 43 → 42, value kept | FAIL | `RC=1 ECO=NO`, `anomaly: Stack overflow`, 43 s |
| `KctlC` | **positive**: index 109 (= sum 96 = 43·7−205, complement symmetry) | PASS | `RC=0 ECO=yes`, 24 s |
| `KctlD` | small scale (10 steps), value `0 → 1` | FAIL | `RC=1 ECO=NO`, `[by]: cannot close goals` @ line 7, 5.3 s |
| `KctlE` | **positive** twin of `KctlD` | PASS | `RC=0 ECO=yes`, 0.7 s |
| `CtlSum204` | target sum 205 → **204**, value kept | FAIL | `RC=1 ECO=NO`, `[by]: cannot close goals` @ **line 22** (`ctl_sum204`), 44 s |
| `CtlLen42` | length 43 → **42**, value kept | FAIL | `RC=1 ECO=NO`, `[by]: cannot close goals` @ **line 19** (`ctl_len42`), 43 s |
| `CtlVal` | value `+1`, at the `count_ds` level | FAIL | `RC=1 ECO=NO`, `[by]: cannot close goals` @ **line 17** (`ctl_val`), 43 s |

For the last three, the failing line number is the load-bearing check: it points at
the `ctl_*` lemma, **not** at the `kernel204` / `kernel42` / `kernelT` lemma above
it (lines 13 / 11 / 10). So inside each control file the 43- (resp. 42-) step
reduction *succeeded*, proving the true value at the perturbed instance, and only
the unperturbed constant was rejected — a clean literal-vs-literal mismatch, not
resource exhaustion and not a `nothing to rewrite` no-op.

`KctlC` matters: position 109 is deep inside the state vector, so a reduction
that merely short-circuited on position 0 could not produce it — and the value it
produces is forced by a symmetry (`d ↦ 7−d`) that the DP knows nothing about.

`CtlSum204` / `CtlLen42` / `CtlVal` each *first prove the true value at the
perturbed instance by reduction*, then assert the unperturbed constant. That
makes the failure a clean literal-vs-literal mismatch rather than resource
exhaustion.

### Finding: the reduction is asymmetric

Proving a **true** 43-step equation costs 41 s. **Refuting a false one at the
same scale exhausts the stack** (`KctlA`, `KctlB`). With `ulimit -s unlimited`
`KctlA` ran 435 s and still died (`RC=127`). At small scale the same construction
fails cleanly (`KctlD`: `[by]: cannot close goals`, 4.9 s — versus 0.6 s for its
true twin `KctlE`, i.e. the failing path does ~8× the work). Anyone reusing this
technique should expect *negative* results to be far more expensive than positive
ones, and should build negative controls in the `CtlSum204` shape.

### Related performance trap, paid for the hard way

Any tactic that invokes `trivial` (`by`, `//`, `smt`) on a goal **still
containing** `runs 8 fu43 (vinit fs205)` re-runs the whole 41 s reduction, and
`apply` against such a goal did not terminate inside a 120 s budget (measured
twice). `c10_surface_count` is therefore written with `rewrite` only, so the
single `by` at the end sees the already-rewritten goal `N = N`.

---

## Independent checks on the constant itself

The EasyCrypt DP and the Python DP implement the same recurrence with the same
orientation convention, so agreeing proves nothing about an off-by-one. Four
methods were run and all four agree on
`22169393903687611906220091621190388`:

1. the forward DP (what the EC kernel mirrors);
2. inclusion–exclusion `Σ_j (−1)^j C(43,j) C(205−8j+42, 42)`;
3. straight polynomial multiplication of 43 copies of `1+x+…+x^7`;
4. complement symmetry `d ↦ 7−d`, i.e. `count(43,8,205) = count(43,8,96)` —
   which is *also* checked inside EasyCrypt by `KctlC`.

---

## Ledger

Zero `admit`, zero `axiom`, zero `declare axiom` in every `.ec` in this
directory, controls included (`receipt.txt`, last section). The grep is the
*substring* form — `grep -cE 'admit|axiom'` returns `0` for all 13 files — so
`by admit`, `smt() || admit` and similar shapes are covered, not just bare
`admit.` lines. `VecDP.ec`,
`CountDS.ec`, `C10SurfaceKernel.ec`, `C10Surface.ec` and `ScriptProbe.ec` all
compile `RC=0` with a fresh `.eco` from a wiped cache.

`.eco` **size** is not content-proportional (two unrelated files can both be
3072 bytes), so the receipt criterion is `.eco` **presence** together with `RC`
and the diagnostic — never `.eco` size.

## Reproducing

```
bash experiments/wots-badenc/count/ec.sh CountDS          # one file, host side
sg docker -c "docker exec ec-grind bash -lc \
  'eval \$(opam env); bash /work/experiments/wots-badenc/count/runall.sh'"
cat experiments/wots-badenc/count/receipt.txt
```

`ScriptProbe.ec` is not a convenience file, it is a **positive control on the
bridge**: it instantiates `count_ds_kernel` at a *different* `fu`/`fs` pair,
`(len=5, base=8, target=12) → 1470`, so the bridge cannot be accidentally
specialised to 43/205. (1470 is independently `C(16,4) − 5·C(8,4) = 1820 − 350`.)
It also costs 0.5 s, which is what makes tactic-shape iteration affordable when
the 43-step file costs 41 s per attempt.
