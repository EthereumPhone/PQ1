(* ==========================================================================
   FORS_C10.ec -- a C10-FAITHFUL model of FORS+C's message hash, and its
   ITSR-style game.  This is step (c) of the bottom-up path to a real SPHINCS+C
   scheme module:

       (a) WOTS+C                    DONE, unconditional  (WOTS_C_Scheme)
       (b) hypertree over WOTS+C     DONE, gated          (XMSSMT_C_Scheme)
       (c) FORS+C, C10-faithful      THIS FILE  (model + game; the tight
                                                 security argument is OPEN)
       (d) SPHINCS+C = (b) + (c)     then `p_sphincs_c := Pr[EUF_CMA(...)]`

   ---------------------------------------------------------------------------
   WHY A SECOND FORS+C FILE (do not delete FORS_C.ec)

   `FORS_C.ec` models the PAPER's FORS+C:

       op mco : mkey -> msg -> cntr -> out_t          (* 3-arg              *)
       O.query(m) = { mk <$ dmkey;                    (* key UNIFORM         *)
                      c <- gc mk m;                   (* COUNTER ground      *)
                      ts <- rcons ts (mk, m, c); ... }

   matching the paper's implementation note ("we simply added an extra 4 bytes
   counter value ... We store the counter value that we found as part of the
   signature").

   C10 does the OPPOSITE.  It grinds the randomiser `R` and carries NO counter:

       sphincs-c10/src/params.rs:73
         SIG_FORS_TOTAL = SIG_R + SIG_FORS_SECRETS + SIG_FORS_AUTH
         (the 4-byte count in SIG_HT_LAYER is the WOTS+C counter, not FORS's)
       sphincs-c10/src/fors.rs:98 grind_r()
         for nonce in 0..10_000_000 {
           R = trunc(H(sk_seed || "R_grind" || [opt_rand] || m || nonce))
           digest = h_msg(pk_seed, pk_root, R, m)
           if read_bits_le(digest, (K-1)*A, A) == 0 { return (R, digest) } }

   So in C10 the ITSR message KEY is `R`, and it is the CONDITIONED object.
   Nothing proven over `FORS_C.ec` transfers to C10 without this re-base.
   (Adversarial review 2026-07-09; the 4th of four model/implementation
   mismatches found that day.)

   ---------------------------------------------------------------------------
   THE MODELLING DECISION, STATED PLAINLY

   C10's `R` is RANDOMIZED per signing call: `secure/src/crypto.rs:130-142` draws a
   fresh `opt_rand` (`rng_strong::fill`) on EVERY signature and passes `Some(..)`,
   and `grind_r` folds it into R.  Signing the same message twice may yield different R values; truncation
   permits repeats. `positive_opt_rand_changes_sig_bytes` checks selected vectors,
   not universal distinctness.  We model R as a
   fresh draw from `dmkey` CONDITIONED on `predC_fors (mco R m)`, realised with the
   `dcond` combinator.  Three consequences, all deliberate:

     * This is a random-oracle idealisation of the keyed derivation `H(sk||...)`.
       It is the same idealisation MM45 makes for `mco`'s key (its ITSR oracle
       samples `k <$ dkey`), so the +C delta is isolated to the CONDITIONING.
     * `dcond dmkey (good m)` is well-defined iff a good key has POSITIVE
       PROBABILITY.  That is exactly the paper's p_nu assumption, and here it
       appears WHERE IT BELONGS -- as the quantitative axiom
       `good_pos (m) : 0%r < mu dmkey (good m)`.  It is LOAD-BEARING: `query_ll`
       (oracle losslessness) is proven from it via `dcond_ll`, so DELETING
       `good_pos` BREAKS THE BUILD.  (Two prior drafts of this header were wrong
       about this: the first CLAIMED the hypothesis while the file never stated it;
       the second stated it but consumed it only in `good_exists`, which nothing
       consumed -- so deleting both left every result green.  Both were caught by
       external adversarial review, 2026-07-10.)  Compare the paper: "we assume that
       it is always possible to find a good counter and the adversary can not depend
       its behavior on the existence of a fitting counter."

     * The oracle does NOT memoize.  A memoized oracle would reveal FEWER targets
       than production (one R per message instead of one per signature), which is an
       ADVERSARY RESTRICTION -- a bound proven against it would not transfer.  MM45's
       `mmap : (msg, mkey) fmap` (FORS_ES.ec:2043) models DETERMINISTIC signing,
       which is not what C10 does.  A memoizing version of this file existed for one
       day (2026-07-10) and was a REGRESSION.

   ---------------------------------------------------------------------------
   WHAT IS OPEN (and why the obvious route is a DEAD END -- do not retry it)

   The security content is: bound `Pr[ITSRC10]` for this game.  The obvious move
   is a black-box reduction to MM45's plain ITSR (`KeyedHashFunctions.eca:1519`,
   whose oracle samples `k <$ dkey` UNIFORMLY).  It EXISTS and is sound -- the
   reduction rejection-samples on the uniform oracle; coverage transfers because
   the reduction's target list is a superset and coverage is monotone in it, and
   freshness transfers because rejected targets carry `!predC` while the forgery
   carries `predC`, so they can never collide.

   But it is QUANTITATIVELY USELESS: it registers ~t = 2^11 targets per query, so
   at C10's 2^16 per-chain cap the reduction's game has 2^27 registered targets.
   The bound is ~28.1 bits, versus ~130.6 bits for FORS+C by the direct argument:
   ~102 BITS LOST.  Recomputed by PHASE 4 of cert_gate_split.sh on every gate run,
   from tools/forsc_grinding_margin.py (vendored byte-identical from PQSigner_OS
   contracts/verification/scripts/), and string-matched against the seven pinned
   rows of cert-margin-split.tsv.
   [The preceding sentence replaces, 2026-08-11: "Recomputed by `make -C
   contracts/verification verify-forsc-margin` in the PQSigner_OS repo (script:
   contracts/verification/scripts/forsc_grinding_margin.py; it is NOT in this
   checkout -- this repo is deliberately standalone)."  That went stale the same
   day it was relied upon, when the script was vendored here; caught by Kimi K3
   adversarial review, not by a gate.  READ cert-margin-split.tsv's header before
   quoting any number above: these are heuristic generic-adversary estimates that
   NO EasyCrypt result carries, 130.6 is a per-candidate WORK FACTOR and not a
   security level, and PHASE 4 does NOT verify that the script's guard blocks 1-3
   are live branch logic -- see the retraction in cert-identity.tsv.]

   (Those figures were themselves corrected on 2026-07-10: the first version of the
   script used a high-probability MAX per-instance load, which is not a cryptographic
   bound.  The correct object is the binomial mixture over a FRESH candidate's own
   instance load, G ~ Bin(qs, 1/2^18), with a (q_h+1) union bound.)

   => Closing this file's OPEN OBLIGATION requires mechanising the DIRECT, tight,
   non-black-box DarkSide argument.  The published SPHINCS+C paper does not prove
   it (IEEE S&P 2023 §IV: "we can use the previous ITSR analysis"; §V: "the usage
   of FORS+C is straightforward") -- there is no reduction and no theorem to port.
   This is original work, and it is deliberately NOT admitted here.

   TWO NOTES ON WHAT THIS GAME IS NOT (external review, 2026-07-10):

     * FRESHNESS here is on the PAIR `(mk', m')`, not on the message.  So the game
       admits "sign m, then output (R', m) for a different good R'", which is NOT an
       EUF-CMA forgery.  This is NOT unsound as an upper-bound target -- message
       freshness implies pair freshness, so this is a LARGER event -- and MM45's
       generic ITSR is pair-fresh too (KeyedHashFunctions.eca:1523-1561).  But it is
       a generic ITSR-shaped game, not an EUF game.  An EUF-specific variant would
       carry `m' \notin signed_messages`.

     * There is NO q_h bound: `mco` is a public pure op and the adversary may grind
       for free.  So no concrete bit-level bound is STATABLE for this game as such.
       That is not a defect relative to the standard: MM45's plain ITSR has exactly
       the same shape (its `g` is a pure op too, and it carries no q_h).  It is
       precisely why ITSR is ASSUMED rather than bounded -- MM45's final theorem
       carries `Pr[MCO_ITSR.ITSR(...)]` as an UNREDUCED term, and no lemma anywhere
       in MM45 bounds it.  The concrete bound lives on paper, as it does for us.

   STATUS: model + game + proved bounded-R companion laws.  NO admit.  Axioms: the benign `dmkey_ll`;
   the structural `size_g`/`eqiks_g`/`neqisvs_g`/`rng_g`/`uniq_g` on the index
   extractor (the first four mirror MM45's; `uniq_g` is STRICTLY STRONGER and was
   added 2026-07-10b because MM45's own set admits `g y = nseq k z`, i.e. k copies of
   ONE tuple, under which `neqisvs_g` is vacuous); and `good_pos` (= p_nu, now
   load-bearing via `query_ll`).  The tight bound is OPEN.
   ========================================================================== *)

require import AllCore List Distr.
require import BoundedIID.

abstract theory FORSC10.

(* ------------------------------------------------------------------------ *)
(* FORS parameters (mirror FORS_ES.ec / FORS_C.ec: k trees, a = log2 leaves). *)
(* C10: k = 13, a = 11.                                                       *)
(* ------------------------------------------------------------------------ *)
const k : { int | 1 <= k } as ge1_k.
const a : { int | 1 <= a } as ge1_a.
const t : int = 2 ^ a.   (* leaves per FORS tree; C10: 2^11 = 2048 *)

type mkey.   (* the randomiser R -- the GROUND object in C10 *)
type msg.
type out_t.

(* Message-key distribution.  MM45's ITSR oracle samples its key from `dkey`;
   ours samples from `dmkey` and then CONDITIONS on the +C predicate. *)
op dmkey : mkey distr.
axiom dmkey_ll : is_lossless dmkey.

(* C10's message hash: NO counter argument (contrast FORS_C.ec's 3-arg `mco`). *)
op mco : mkey -> msg -> out_t.

(* Index extraction: the k (instance, tree, leaf) tuples of a digest.

   STRUCTURAL AXIOMS (added 2026-07-10 after an external adversarial review).
   Without these, `g` is an arbitrary op and a LEGAL clone may set `g y = []`:
   then `cover_f = []`, coverage `forall x, x \in [] => ...` is VACUOUSLY TRUE,
   and `predC_fors` reads `nth witness [] (k-1) = witness`.  The abstract theory
   would admit degenerate models unrelated to FORS.  This is exactly the
   abstract-theory-instantiation attack that killed the FORS tree admits.
   Mirrors MM45's constraints on its own `g` (KeyedHashFunctions.eca:1454-1467). *)
op g : out_t -> (int * int * int) list.

(* one tuple per FORS tree *)
axiom size_g (y : out_t) : size (g y) = k.
(* all tuples name the SAME FORS instance *)
axiom eqiks_g (x x' : int * int * int) (y : out_t) :
  x \in g y => x' \in g y => x.`1 = x'.`1.
(* distinct tuples name DISTINCT trees *)
axiom neqisvs_g (x x' : int * int * int) (y : out_t) :
  x \in g y => x' \in g y => x <> x' => x.`2 <> x'.`2.
(* leaf indices are in range *)
axiom rng_g (y : out_t) (x : int * int * int) :
  x \in g y => 0 <= x.`3 < t.

(* F1 FIX (2026-07-10b).  The k tuples name k DISTINCT trees.

   WITHOUT this, `neqisvs_g` is VACUOUS on a list of k copies of one tuple (its
   premise `x <> x'` is never satisfiable there), so the legal clone

       g y = nseq k (0, 0, 0)

   realizes size_g, eqiks_g, neqisvs_g and rng_g while representing exactly ONE
   tree.  Coverage and `predC_fors` then collapse onto a single leaf.  Verified by
   an actual clone (EXIT 0) during adversarial review, 2026-07-10; that clone is
   now a NEGATIVE CONTROL and must fail to realize.

   Note `uniq_g` is strictly stronger than `neqisvs_g` (distinct positions =>
   distinct trees => distinct tuples).  `neqisvs_g` is kept for parity with MM45
   (KeyedHashFunctions.eca:1454-1467), whose own axioms have the same weakness. *)
axiom uniq_g (y : out_t) : uniq (map (fun (x : int * int * int) => x.`2) (g y)).

(* The +C predicate: the LAST FORS tree opens leaf 0.
   C10: `read_bits_le(digest, (K-1)*A, A) == 0` (fors.rs:126), enforced by BOTH
   verifiers -- hypertree.rs:374 and SPHINCsC10Asm.sol:86. *)
op predC_fors (y : out_t) : bool =
  (nth witness (g y) (k - 1)).`3 = 0.

(* A key is `good` for m iff its digest satisfies the +C predicate. *)
op good (m : msg) (mk : mkey) : bool = predC_fors (mco mk m).

(* THE p_nu ASSUMPTION, stated (2026-07-10).  The header used to CLAIM this
   hypothesis while the file never stated it -- claim-vs-code drift, ours, caught
   by external review.  It is what makes the rejection sampler well-defined: a
   good key exists with POSITIVE PROBABILITY.  Compare the paper: "we assume that
   it is always possible to find a good counter". *)
axiom good_pos (m : msg) : 0%r < mu dmkey (good m).

(* Finite IID-R companion of the SAME conditioned-key consumer. Repeated R
   values are allowed: mco is fixed and replaying an R replays its answer.
   These lemmas do not assert that the secret-keyed SHA-derived nonce stream is
   IID, that distinct R values occur, or that the good-key mass is 1/2048.
   Losslessness/exhaustion need dmkey_ll but do not use good_pos. *)
op bounded_r (m : msg) (fuel : unit list) : mkey option distr =
  bounded dmkey (good m) fuel.

lemma bounded_r_ll (m : msg) (fuel : unit list) :
  is_lossless (bounded_r m fuel).
proof. by rewrite /bounded_r; apply bounded_ll; exact dmkey_ll. qed.

lemma bounded_r_exhaustion (m : msg) (fuel : unit list) :
  mu1 (bounded_r m fuel) None = (1%r - mu dmkey (good m)) ^ size fuel.
proof. by rewrite /bounded_r bounded_exhaustion 1:dmkey_ll. qed.

lemma bounded_r_conditioned_mixture (m : msg) (fuel : unit list)
  (event : mkey option -> bool) :
  mu (bounded_r m fuel) event =
    (1%r - mu dmkey (good m)) ^ size fuel * b2r (event None) +
    (1%r - (1%r - mu dmkey (good m)) ^ size fuel) *
      mu (dcond dmkey (good m)) (fun r => event (Some r)).
proof.
  by rewrite /bounded_r bounded_as_conditioned_mixture 1:dmkey_ll 1:good_pos.
qed.

lemma bounded_r_success_le_conditioned (m : msg) (fuel : unit list)
  (event : mkey -> bool) :
  mu (bounded_r m fuel) (fun r => oapp event false r) <=
    mu (dcond dmkey (good m)) event.
proof.
  rewrite /bounded_r bounded_success_mass 1:dmkey_ll 1:good_pos.
  have hf := mu_bounded (bounded_r m fuel) (pred1 None).
  rewrite bounded_r_exhaustion in hf.
  have he := mu_bounded (dcond dmkey (good m)) event.
  smt().
qed.

(* Coverage tuples of a (key, message) pair -- note: NO counter. *)
op hC (mk : mkey) (m : msg) : (int * int * int) list = g (mco mk m).

(* ------------------------------------------------------------------------ *)
(* The ITSR(+C) oracle for C10: sample the message key, REJECT until it is
   good, then record the target.  This is the operational reading of "R drawn
   uniformly, conditioned on predC".                                          *)
(* ------------------------------------------------------------------------ *)
module type Oracle_ITSRC10 = {
  proc init() : unit
  proc query(m : msg) : mkey
  proc get_targets() : (mkey * msg) list
}.

module O_ITSRC10_Default : Oracle_ITSRC10 = {
  var ts : (mkey * msg) list

  proc init() : unit = {
    ts <- [];
  }

  (* F5 FIX (2026-07-10b).  A FRESH conditioned key per query -- NOT memoized.
     Production draws a fresh `opt_rand` on EVERY signing call
     (`secure/src/crypto.rs:130-142`: `rng_strong::fill(&mut opt_rand_buf)`, then
     `Some(&opt_rand_buf)`), and `grind_r` folds it into R
     (`sphincs-c10/src/fors.rs`).  Repeated signing may yield different R values, digests and revealed leaves;
     it does not guarantee distinctness after truncation.
     Regression test: `positive_opt_rand_changes_sig_bytes`
     (sphincs-c10/tests/signing_suite.rs:131).

     An earlier version of this file MEMOIZED the key per message.  That was a
     REGRESSION, introduced on 2026-07-10 in response to a review that observed
     "C10's R is deterministic in (sk,m) when opt_rand = None" -- true, but the
     firmware passes `Some`.  A memoized oracle reveals FEWER targets than
     production, which is an ADVERSARY RESTRICTION: a bound proven against it does
     NOT transfer.  MM45's `mmap : (msg, mkey) fmap` (FORS_ES.ec:2043) models
     DETERMINISTIC signing, which is not what C10 does.

     F2 FIX: the draw is a single sample from the CONDITIONED distribution rather
     than an operational rejection loop.  `dcond dmkey (good m)` is exactly "R
     uniform on dmkey, conditioned on predC", and `dcond_ll` turns `good_pos`
     (= the paper's p_nu) into a LOAD-BEARING hypothesis: without it the oracle is
     not lossless.  Proven below as `query_ll`. *)
  proc query(m : msg) : mkey = {
    var mk : mkey;

    mk <$ dcond dmkey (good m);
    ts <- rcons ts (mk, m);

    return mk;
  }

  proc get_targets() : (mkey * msg) list = {
    return ts;
  }
}.

module type Adv_ITSRC10 (O : Oracle_ITSRC10) = {
  proc find() : mkey * msg { O.query }
}.

(* ------------------------------------------------------------------------ *)
(* The game.  Identical to MM45's ITSR (coverage + freshness) with ONE added
   conjunct -- the +C predicate on the forgery's digest -- and the conditioned
   oracle above.  Those two changes are the whole of the FORS+C delta.        *)
(* ------------------------------------------------------------------------ *)
module ITSRC10 (A : Adv_ITSRC10, O : Oracle_ITSRC10) = {
  proc main() : bool = {
    var mk' : mkey;
    var m'  : msg;
    var ts  : (mkey * msg) list;
    var cover_f, cover_q : (int * int * int) list;

    O.init();
    (mk', m') <@ A(O).find();

    cover_f <- hC mk' m';
    ts      <@ O.get_targets();
    cover_q <- flatten (map (fun (km : mkey * msg) => hC km.`1 km.`2) ts);

    (* (i) the forgery digest is +C-valid (BOTH C10 verifiers enforce this);
       (ii) its coverage tuples are covered by the recorded targets;
       (iii) the forgery pair is fresh. *)
    return    predC_fors (mco mk' m')
           /\ (forall x, x \in cover_f => x \in cover_q)
           /\ ! (mk', m') \in ts;
  }
}.

(* The same game WITHOUT the +C conjunct: MM45's plain-ITSR win condition, over
   the SAME conditioned oracle.  Used only to state the win-set inclusion. *)
module ITSRC10_noC (A : Adv_ITSRC10, O : Oracle_ITSRC10) = {
  proc main() : bool = {
    var mk' : mkey;
    var m'  : msg;
    var ts  : (mkey * msg) list;
    var cover_f, cover_q : (int * int * int) list;

    O.init();
    (mk', m') <@ A(O).find();

    cover_f <- hC mk' m';
    ts      <@ O.get_targets();
    cover_q <- flatten (map (fun (km : mkey * msg) => hC km.`1 km.`2) ts);

    return    (forall x, x \in cover_f => x \in cover_q)
           /\ ! (mk', m') \in ts;
  }
}.

(* ==========================================================================
   STRUCTURAL LEMMAS (proven).  These are the model's sanity gates -- the
   analogue of XMSSMT_C_Scheme's `sign_size_d`: they catch a mis-wired model,
   which is the bug class that has bitten this port four times.
   ========================================================================== *)

(* GATE 1.  Every target the oracle records is +C-valid.  If this failed, the
   game would be recording targets the C10 verifiers would reject, i.e. the
   model would not be modelling C10.  (Mirrors FORS_C.ec's O_ITSRC_query_good,
   but here the +C-validity comes from the REJECTION LOOP's exit condition
   rather than from a ground counter.) *)
lemma query_targets_good :
  hoare[O_ITSRC10_Default.query :
          all (fun (km : mkey * msg) => good km.`2 km.`1) O_ITSRC10_Default.ts
          ==>
          all (fun (km : mkey * msg) => good km.`2 km.`1) O_ITSRC10_Default.ts].
proof.
proc; auto => />; smt(dcond_supp allP mem_rcons).
qed.

(* GATE 0c (F2 FIX).  `good_pos` is now LOAD-BEARING: the oracle is lossless ONLY
   because a good key has positive mass.  Deleting `good_pos` breaks this lemma.
   (Before 2026-07-10b, `good_pos` was consumed only by `good_exists`, which
   nothing consumed -- so deleting both left every result green.  That mutation is
   now a build failure.) *)
lemma query_ll : islossless O_ITSRC10_Default.query.
proof. proc; auto; smt(dcond_ll good_pos). qed.

(* GATE 0a.  `good_pos` is LOAD-BEARING, not decorative: it is exactly what makes
   the rejection sampler well-defined (a good key exists at all).  Proving the
   existential from it also shows the axiom is not vacuous. *)
lemma good_exists (m : msg) : exists (mk : mkey), good m mk.
proof. smt(witness_support good_pos). qed.

(* GATE 0b.  `size_g` is LOAD-BEARING: coverage is over a length-k list, so the
   degenerate `g y = []` model (under which coverage would be VACUOUSLY TRUE and
   `predC_fors` would read `nth witness []`) is excluded.  This is the anti-
   degeneracy gate; without it the whole game is meaningless. *)
lemma hC_size (mk : mkey) (m : msg) : size (hC mk m) = k.
proof. by rewrite /hC size_g. qed.

lemma hC_nonempty (mk : mkey) (m : msg) : hC mk m <> [].
proof. by have := hC_size mk m; smt(ge1_k size_eq0). qed.

(* the coverage list really names k DISTINCT trees -- not k copies of one *)
lemma hC_trees_uniq (mk : mkey) (m : msg) :
  uniq (map (fun (x : int * int * int) => x.`2) (hC mk m)).
proof. by rewrite /hC uniq_g. qed.

(* GATE 2.  The +C conjunct only SHRINKS the win set: an ITSRC10 winner is a
   winner of the plain-ITSR-shaped game over the same oracle.  So FORS+C is
   never easier to break than the corresponding un-gated game -- the direction
   the paper's informal argument claims, here machine-checked at the game level.

   RENAMED 2026-07-10 (`..._SAME_ORACLE`) after external review pointed out the old
   name invited exactly the wrong reading.  What this does NOT say: the two games
   share the CONDITIONED oracle, so this is NOT a bound against MM45's
   uniform-oracle ITSR, and it is NOT the inequality `DS_g^(k-1)/t <= DS_g^k`.
   It is event inclusion, nothing more.  Bridging to MM45's ITSR is the open
   obligation, and the black-box route is the ~102-bit dead end (header). *)
lemma ITSRC10_le_noC_SAME_ORACLE (A <: Adv_ITSRC10{-O_ITSRC10_Default}) &m :
  Pr[ITSRC10(A, O_ITSRC10_Default).main() @ &m : res]
  <= Pr[ITSRC10_noC(A, O_ITSRC10_Default).main() @ &m : res].
proof.
byequiv (: ={glob A} ==> res{1} => res{2}) => //.
proc.
seq 2 2 : (={glob A, glob O_ITSRC10_Default, mk', m'}); 1: by sim.
inline *; wp; skip => /> /#.
qed.

end FORSC10.
