(* ==========================================================================
   WOTS_C_Real.ec  --  The WOTS+C additions instantiated on the REAL
                       FV-SPHINCSPLUS-EC WOTS-TW infrastructure.

   THIRD-INCREMENT ARTIFACT for the C10 (SPHINCS+C) EUF-CMA mechanization.

   This file `require import`s the real `WOTS_TW_ES` (which builds clean under
   the pinned EasyCrypt r2026.02 toolchain — switch `ec-r2026`) and instantiates
   the S-TCR(+C) theory (STCR_C.STCRC) with the REAL SPHINCS+ WOTS types
   (pseed / adrs / dgstblock / msgWOTS).  The upshot:

     * `InSec^{S-TCR(+C)}(Th+C; q6)` — the ONE security term SPHINCS+C adds to
       the SPHINCS+ bound (paper Thm 5.2) — is now a CONCRETE game over the real
       digest / address / public-seed types and the REAL Th_lambda collection
       oracle (FC.Oracle_THFC's sibling), not an abstract placeholder.
     * The +C grinding is the PROVED total op (Grind.grind via STCRC_WC), so
       `wotsc_grind_targets_predC` (grinding always yields a Prop-satisfying
       target when one exists) holds over the real types with NO grindP axiom.

   WHAT REMAINS (honestly): the WOTS+C SCHEME (keygen/sign/verify with the
   chain walk + counter), the d-EU-naCMA game `M_EUF_GCMA_WOTSC_NPRF`, and the
   two reductions (Alg 9 / Alg 10) that discharge Thm C.2 / Thm D.1.  Their
   full statement is written below as a precise composition roadmap keyed to the
   real games/lemmas; the reduction PROOFS are the App-D pRHL fill (the
   person-months core) and are not attempted here.  See PLAN.md §3/§4.
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder.
require import SPHINCS_PLUS.
require STCR_C.

import FSSLXMTWES.         (* n, w, len, d, nr_nodes_ht, pseed, dgst (FLAG-2 rebase) *)
import FSSLXMTWES.WTWES.   (* CONCRETE WOTS-TW instance *)
import HA.Adrs.            (* val / insubd / put on the adrs subtype *)

(* `c` (the WOTS-TW instance count) is SUBSTITUTED AWAY by the concrete clone
   (FL_SL_XMSS_MT_ES.ec:547 `op c <- bigi predT (fun d' => nr_nodes_ht d' 0) 0 d`),
   so the name no longer exists in WTWES. Re-expose it under the SAME name and
   the SAME definition, so every WOTS+C statement stays byte-identical. *)
import Bigint BIA.
op c : int = bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 d.

(* --------------------------------------------------------------------------
   1.  WOTS+C-specific parameters over the REAL WOTS types.
   -------------------------------------------------------------------------- *)
(* r-bit grinding counter (C10: 32-bit word) — finite (carried as the modelling
   axiom STCRC_WC.G.CntrFT.enum_spec once instantiated). *)
type cntr.

(* --------------------------------------------------------------------------
   The SPHINCS+ message-compression embedding (moved here from WOTS_C_Bridge.ec
   so that Th+C can be DEFINED as the SPHINCS+ tweakable hash at the embedded
   message-compression address, discharging the bridge's FLAG-1 `emb_thfc_ThC`
   hypothesis DEFINITIONALLY — see WOTS_C_EmbDischarge.ec).

     emb_tw : maps a WOTS instance address to the SPHINCS+ address at which Th+C
              is evaluated.
     emb_in : serialises a (message, counter) pair to the `dgst` that the
              tweakable hash compresses.

   HONEST NOTE ON THE ADDRESS TYPE (do not misread this).  This op writes type
   `pkcotype`, NOT a distinct type.  The SPHINCS+C PAPER (§VII.B) assigns Th+C a
   dedicated address type 7; that is NOT representable here, because the MM45 base
   `valid_idxvals` (SPHINCS_PLUS.ec:308) admits only the 5 standard types and is
   read-only (adding type 7 would fork the base).  Crucially, the DEPLOYED C10
   firmware ALSO uses no type 7: `sphincs-c10/src/hash.rs:wots_digest` computes
   `sha256(seed || wots_adrs || msg_hash || count)` and domain-separates Th+C from
   the chain/pkco/tree hashes by the full SHA-256 INPUT STRUCTURE (address +
   appended counter + length), not a dedicated type.  So the `pkcotype` here is a
   MODELLING coordinate, and the genuine Th+C-vs-transcript domain separation is
   carried NOT by this type but by the member-aware (input-length) transcript in
   WOTS_C_Interactive.ec PART 1b (S_TCR_C_Int_MA / member_sep_disj) — which is the
   faithful abstraction of the firmware's input-structure separation.  Do NOT
   "fix" this to a distinct type: that would model the paper's abstraction and
   deviate from the deployed code (2026-07-18 decision).

   Both ops stay ABSTRACT (concrete encoding is a downstream instantiation detail);
   Th+C being `thfc` at the embedded address on the embedded input is the faithful,
   non-degenerate modelling fact (paper Thm 5.2: Th+C is a tweakable-hash member). *)
op emb_tw (ad : adrs) : adrs =
  insubd (put (put (put (val ad) 0 0) 1 0) 3 pkcotype).

(* ==========================================================================
   FLAG-2, DISCHARGED IN-PLACE (rebase 2026-07-09).  Previously `emb_tw` was an
   ABSTRACT op over the ABSTRACT `WOTS_TW_ES`, so `emb_disj_wgpidxs` had to be
   carried as a hypothesis all the way to the capstone, while its proof sat in
   `WOTS_C_Flag2Discharge.ec` over the CONCRETE `FSSLXMTWES.WTWES` -- a different
   namespace, hence unusable.  Re-basing this file onto the concrete instance and
   DEFINING `emb_tw` lets the proof live where the premise was.  Ported verbatim
   from WOTS_C_Flag2Discharge.ec (which stays as the standalone record).
   `thfc` / `emb_in` / `predC` STAY ABSTRACT, so the S-TCR(+C) term remains the
   genuine SM-DT-TCR-C assumption -- nothing is trivialised.
   ========================================================================== *)
(* Instance properties: any valid SPHINCS+ address supplies the kpidx/tidx/lidx
   the pkco validity predicate demands (needed by emb_tw_valid). *)
lemma valwadrs_inst (b : adrs) :
     valid_kpidx (nth witness (val b) 2)
  /\ valid_tidx (nth witness (val b) 5) (nth witness (val b) 4)
  /\ valid_lidx (nth witness (val b) 5).
proof.
have vb := valP b.
move: vb; rewrite /valid_adrsidxs => -[_].
rewrite /valid_idxvals /valid_idxvalsch /valid_idxvalspkco /valid_idxvalstrhx.
rewrite /valid_idxvalstrhf /valid_idxvalstrco /valid_kpidx /valid_lidx /l'.
move=> H.
smt(ge1_d IntOrder.expr_gt0).
qed.

lemma emb_tw_valid (b : adrs) :
  valid_adrsidxs (put (put (put (val b) 0 0) 1 0) 3 pkcotype).
proof.
have szb : size (val b) = adrs_len by move: (valP b); rewrite /valid_adrsidxs.
have [hk [ht hl]] := valwadrs_inst b.
rewrite /valid_adrsidxs !size_put szb /=.
rewrite /valid_idxvals; right; left.
rewrite /valid_idxvalspkco.
rewrite !nth_put ?size_put ?szb //= /adrs_len //=.
qed.

lemma emb_tw_val (b : adrs) :
  val (emb_tw b) = put (put (put (val b) 0 0) 1 0) 3 pkcotype.
proof. by rewrite /emb_tw insubdK 1:emb_tw_valid. qed.

lemma nth3_emb_tw (b : adrs) : nth witness (val (emb_tw b)) 3 = pkcotype.
proof.
have sz : size (put (put (val b) 0 0) 1 0) = adrs_len.
+ rewrite !size_put; move: (valP b); rewrite /valid_adrsidxs => -[-> _] //.
rewrite emb_tw_val nth_put; 1: by rewrite sz /adrs_len.
done.
qed.

lemma nth3_valid (a : adrs) : valid_wadrs a => nth witness (val a) 3 = chtype.
proof.
rewrite /valid_wadrs /valid_wadrsidxs /valid_widxvals /valid_widxvalsgp => -[_ [+ _]].
rewrite drop_drop //= => -[_ [+ _]].
by rewrite nth_drop.
qed.

(* NON-VACUITY: the guard premise is live (a valid WOTS signing address exists). *)
lemma nonvac_guard : exists (a : adrs), valid_wadrs a.
proof. exists (WAddress.val witness); exact: WAddress.valP. qed.

(* NON-DEGENERACY: no emb_tw image is itself a valid WOTS chain address, so
   FLAG-2 is not vacuously true via an `a := emb_tw b` self-collision. *)
lemma emb_off_range (b : adrs) : ! valid_wadrs (emb_tw b).
proof.
apply/negP => v.
have := nth3_valid (emb_tw b) v; rewrite nth3_emb_tw.
smt(dist_adrstypes).
qed.

(* THE FLAG-2 FACT ITSELF -- now a THEOREM on the stack, not a hypothesis. *)
lemma emb_disj_concrete (a b : adrs) :
  valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b).
proof.
move=> va; apply/negP => heq.
have e1 : nth witness (get_wgpidxs a) 1 = chtype.
+ by rewrite /get_wgpidxs nth_drop //= (nth3_valid a va).
have e2 : nth witness (get_wgpidxs (emb_tw b)) 1 = pkcotype.
+ by rewrite /get_wgpidxs nth_drop //= nth3_emb_tw.
have : chtype = pkcotype by rewrite -e1 -e2 heq.
smt(dist_adrstypes).
qed.
op emb_in : dgstblock * cntr -> dgst.   (* the +C hash's INPUT is a hypertree NODE *)

(* Th+C : the count-tweaked message-compression hash
   (paper Thm 5.2:  Th+C : P x T x {0,1}^n x {0,1}^r -> {0,1}^n).
   DEFINED as the SPHINCS+ tweakable hash `thfc` at the embedded message-
   compression address `emb_tw tw` on the serialised input `emb_in (m,c)`,
   with the thfc input-length index `size (emb_in (m,c))`.  This makes the
   bridge's `emb_thfc_ThC` hold by construction (it is the DEFINITION of how
   SPHINCS+ realises Th+C), WITHOUT trivialising the S-TCR(+C) term: `thfc`,
   `emb_tw`, `emb_in`, `predC` all stay abstract, so `InSec^{S-TCR(+C)}(Th+C)`
   remains the genuine SM-DT-TCR-C assumption over the abstract tweakable hash. *)
(* ROUTE (D), 2026-08-01.  TWO SERIALISERS INTO THE SAME COLLECTION.  The two
   tags differ in LENGTH, so `emb_in0`/`emb_in1` select two DISTINCT members of
   the ONE existing size-indexed collection `thfc`; the wide digest is their
   `join_dgst`, built OUTSIDE the collection (whose codomain stays `dgstblock`).

   FAITHFULNESS -- this is the point the review wave insisted on.  Under the
   deployed instantiation the tags are DECODED AWAY and both members are read
   off the SAME `sha256` evaluation: `wots_digest`
   (sphincs-c10/src/hash.rs:350-365) is a SINGLE `sha256_bytes` call over a
   128-byte preimage returning 32 bytes.  Member `dfC0` denotes its low 16
   bytes, member `dfC1` its high 16 bytes.  Modelling these as two
   domain-separated hashes of two DIFFERENT preimages would be UNFAITHFUL --
   the deployment performs one hash, not two.

   The price, recorded honestly: the collection is now larger and its two
   message-compression members are CORRELATED under the instantiation, so
   MM45's UD/TCR/PRE hypotheses are being assumed for that enlarged correlated
   collection.  That is a genuinely different (stronger) hypothesis than the
   one MM45 states, not the old assumption for free. *)
op emb_in0 (x : dgstblock * cntr) : dgst = false :: emb_in x.
op emb_in1 (x : dgstblock * cntr) : dgst = false :: false :: emb_in x.

lemma emb_in0_size (x : dgstblock * cntr) : size (emb_in0 x) = 1 + size (emb_in x).
proof. by rewrite /emb_in0 /=; smt(). qed.

lemma emb_in1_size (x : dgstblock * cntr) : size (emb_in1 x) = 2 + size (emb_in x).
proof. by rewrite /emb_in1 /=; smt(). qed.

(* The two members are DISTINCT whenever every `emb_in` output has one length. *)
lemma emb_in01_distinct_members (x y : dgstblock * cntr) :
  (forall (u v : dgstblock * cntr), size (emb_in u) = size (emb_in v)) =>
  size (emb_in0 x) <> size (emb_in1 y).
proof. by move=> hlen; rewrite emb_in0_size emb_in1_size (hlen x y); smt(). qed.

lemma emb_in0_inj (x y : dgstblock * cntr) :
  (forall (u v : dgstblock * cntr), emb_in u = emb_in v => u = v) =>
  emb_in0 x = emb_in0 y => x = y.
proof. by move=> hinj; rewrite /emb_in0 => heq; apply hinj; move: heq; smt(). qed.

op ThC (ps : pseed) (tw : adrs) (m : dgstblock) (c : cntr) : msgWOTS =
  join_dgst (thfc (size (emb_in0 (m, c))) ps (emb_tw tw) (emb_in0 (m, c)))
            (thfc (size (emb_in1 (m, c))) ps (emb_tw tw) (emb_in1 (m, c))).

(* ==========================================================================
   THE +C GATE — TIED, 2026-07-27.  Previously this read

       op predC : dgstblock -> bool.

   with the comment "Abstract here; tied to base_w in the scheme file".  THAT TIE
   WAS NEVER MADE: `target_sum` appeared ZERO times in WOTS_C_Scheme.ec, and
   `predC` carried NO AXIOM ANYWHERE IN THE CLOSURE (the repo recorded this
   itself at SphincsC10Content.ec:492).  So `predC := fun _ => false` was a model
   of the whole development — under which every +C acceptance is false, the LHS
   of the bound is zero, and every statement conditioned on the gate is vacuous.

   IT IS A DEFINITION, NOT AN AXIOM.  This is deliberate: a definition cannot
   introduce inconsistency, whereas `axiom predC_is_sum : ...` could.  Nothing
   is added to the axiom census by this change.

   THE GATE IS SUM-ONLY.  The old comment also claimed "and the first z digits
   are zero".  That is FORS+C's `predC_fors`, NOT deployed WOTS, which gates on
   the digit sum alone — `sphincs-c10/src/wots.rs:160`
   (`if sum != TARGET_SUM { return [0u8; N]; }`) and
   `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol:170`.  A predC
   carrying a leading-zeros conjunct for WOTS would be UNFAITHFUL, not more
   complete.

   WHAT THIS DOES AND DOES NOT BUY.  It removes `fun _ => false` as a FREE
   choice: predC is now determined by `encode_msgWOTS` and `target_sum`.  The
   vacuity question does not vanish — it MOVES, to "does the encoder ever reach
   target_sum?", which is a property of the encoder and is where it belongs.
   That residual is named below as `TargetSumReachable` and is deliberately NOT
   axiomatised.
   ========================================================================== *)
(* digit sum of a codeword.  `EmsgWOTS.val` is the Word theory's word -> list
   projection (Word.ec:24, `op ofword = val`); qualified rather than imported so
   this change adds no names to the file's top-level scope. *)
op cw_sum (em : EmsgWOTS.emsgWOTS) : int =
  sumz (map BaseW.val (EmsgWOTS.val em)).

(* --------------------------------------------------------------------------
   THE TARGET, DEFINED AS AN ATTAINED VALUE (2026-07-28).

   This was `const target_sum : int.` -- a FREE constant, which admitted values
   no encoder reaches.  Those are models with no deployment counterpart: in the
   field the grinder finds counters hitting the target constantly.  Pinning the
   target to a value the encoder ACTUALLY ATTAINS excludes them, and it does so
   by DEFINITION, adding nothing to the axiom census.

   READ THE NAME LITERALLY.  `tgt_witness` is a declared digest; `target_sum` is
   *its* codeword sum.  This does NOT pin the deployed value 205, and it is not
   meant to -- nothing in the model depends on the numeral.
   -------------------------------------------------------------------------- *)
(* ===================================================================== *)
(* TIED TO THE FORK'S `P`, 2026-07-29.                                    *)
(*                                                                        *)
(* This file used to declare its OWN `tgt_witness` and `target_sum` and   *)
(* build `predC` from them.  Those now live in the FORK                   *)
(* (base-c10-fork/WOTS_TW_ES.ec), which is where the WOTS-TW game's gate  *)
(* `P` is defined -- so `predC` IS that gate now, rather than a second    *)
(* predicate that merely looks like it.  Before this, `op predC = P`      *)
(* would NOT have tied them: cdrafts' `target_sum` was a different        *)
(* constant, so the two could denote different sets while typechecking.   *)
(* ===================================================================== *)
op predC (d : msgWOTS) : bool = P d.   (* the gate is on the DIGEST *)

(* the tie, in the fork's own spelling *)
lemma predC_iff_sum (d : msgWOTS) :
  predC d <=> digitsum (encode_msgWOTS d) = target_sum.
proof. by rewrite /predC /P. qed.

op TargetSumReachable : bool = exists (d : msgWOTS), predC d.

(* ==========================================================================
   REACHABILITY IS NOW A THEOREM.  Zero new axioms.
   Since the 2026-07-29 tie it is INHERITED from the fork rather than re-proved:
   `target_sum` is defined there as an attained value, so `P` -- and hence
   `predC`, which now IS `P` -- cannot be identically false.
   ========================================================================== *)
lemma targetSumReachable : TargetSumReachable.
proof. by rewrite /TargetSumReachable /predC; exact P_inhabited. qed.

(* --------------------------------------------------------------------------
   EXACTLY WHAT THAT BUYS, AND WHAT IT DOES NOT.  Do not read the lemma name as
   more than it is.

   KILLED: `predC := fun _ => false`.  That was the DANGEROUS degeneracy -- it
   made `okC` always false, hence acceptance always false, hence the LHS of the
   bound ZERO and every gate-conditioned statement vacuously true.  It is now
   refuted by `targetSumReachable`.

   NOT KILLED: `predC := fun _ => true`.  A CONSTANT `encode_msgWOTS` satisfies
   both `two_encodings` (its hypothesis is never met, so it holds vacuously) and
   `enc_nonzero` (pick a codeword with a nonzero digit), and under it every
   digest attains the target.  This is NOT vacuity -- the bound still says
   something -- but say precisely what: with the gate always true it vanishes
   from acceptance, so the S-TCR(+C) term is then being assumed about a scheme
   with NO filter, which is a DIFFERENT assumption from the one the ledger names.
   Ruling it out needs two digests with different codeword sums, and neither
   base-c10 axiom provides them: incomparable codewords may share a sum (that is
   exactly the constant-sum case).

   NOT TOUCHED: the honest-leg premise N2, `exists c, predC (ThC ps ad m c)`
   (`wotsc_grind_targets_predC`, :314-316 -- this pointer said :260-262 until
   2026-07-28; my own edits above pushed the lemma down and I left the citation
   behind).  The quantifiers are different and the difference is decisive:

       targetSumReachable : exists (d : dgstblock),        predC d
       N2                 : exists (c : cntr),   predC (ThC ps ad m c)

   N2 ranges over `ThC`'s image AT A FIXED (ps, ad, m), indexed by counters.
   `tgt_witness` need not lie in that image for any particular (ps, ad, m), so
   knowing ONE digest attains the target says nothing about whether the grind
   succeeds at a GIVEN instance.  N2 remains a premise, still carrying the
   uncharged probability term (the firmware bounds the grind at
   `0..10_000_000` and PANICS on failure, `sphincs-c10/src/wots.rs:62-74`,
   a strictly smaller search than the model's never-failing `grind`).

   NOT ESTABLISHED: that the DEPLOYED target 205 is reachable for the deployed
   encoder.  That is `experiments/tcollres-leg/ThCWidth.ec predC_sum_inhabited`
   (via Proj129), at C10 geometry, and its transfer to here crosses the
   int/emsgWOTS boundary by HAND TRANSCRIPTION, not machine check.
   -------------------------------------------------------------------------- *)

(* Number of S-TCR(+C) targets the SPHINCS+ reduction places (paper: q6). *)
const p_tgts : { int | 0 <= p_tgts } as ge0_ptgts.

(* --------------------------------------------------------------------------
   2.  THE ADDED TERM, REAL: instantiate S-TCR(+C) on the real types.
   -------------------------------------------------------------------------- *)
clone import STCR_C.STCRC as STCRC_WC with
  type pp_t   <- pseed,
  type tw_t   <- adrs,
  type msg_t  <- dgstblock,
  type cntr   <- cntr,
  type out_t  <- msgWOTS,
  op   ThC    <- ThC,
  op   predC  <- predC,
  op   dpp    <- dpseed,
  op   p_stcr <- p_tgts
  proof dpp_ll, ge0_pstcr.
realize dpp_ll   by exact: dpseed_ll.
realize ge0_pstcr by exact: ge0_ptgts.

(* The concrete real S-TCR(+C) game is now `STCRC_WC.S_TCR_C`, its challenge
   oracle `STCRC_WC.O_STCRC_Default`, and its collection (Th_lambda) oracle
   `STCRC_WC.Col.O_THFC_Default` — all over pseed / adrs / dgstblock. *)

(* Grinding over the REAL types, PROVED (re-export of the discharged gap #1):
   when a Prop-satisfying counter exists, the total grind returns one. *)
lemma wotsc_grind_targets_predC (ps : pseed) (ad : adrs) (m : dgstblock) :
  (exists c, predC (ThC ps ad m c)) => predC (ThC ps ad m (STCRC_WC.G.grind ps ad m)).
proof. exact: STCRC_WC.query_targets_predC. qed.

(* --------------------------------------------------------------------------
   3.  WOTS+C encoding (the count-dependent replacement for encode_msgWOTS).
       CONTRAST the abstract WOTS-TW hook `encode_msgWOTS : msgWOTS -> emsgWOTS`
       (WOTS_TW_ES.ec:624 — the file says :569, measured 2026-08-25) — a pure
       function of the message alone.  WOTS+C's
       encoding additionally depends on (pseed, adrs, counter), which is exactly
       why WOTS+C is a REDUCTION, not an `encode_msgWOTS` instantiation
       (see WOTS_C_Encoding.ec / PLAN.md §1).
   -------------------------------------------------------------------------- *)
(* DEFINED, NOT DECLARED (2026-08-25).  This op was abstract until today, and every
   capstone in the family carried the equation below as the premise `hencb`:

       forall p a x cc, encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)

   Giving it the body MAKES THAT EQUATION DEFINITIONALLY TRUE, so the premise can be
   discharged by reflexivity instead of assumed.  The model class is UNCHANGED: by
   functional extensionality the premise already pinned this op to exactly this value,
   so every model of (free op + premise) IS a model of the definition and conversely.
   One fewer premise, same theorem.

   IT IS A DEFINITION, NOT AN AXIOM -- the same reasoning `predC` was tied under at
   line 279 above.  A definition cannot introduce inconsistency.  Nothing is added to
   the assumption ledger; the census trades one `abstract-op` row for one `defined-op`
   row whose BODY is digest-pinned, so a later change to this body is gate-fatal.

   WHAT THIS IS NOT.  C10DeployedGeometry.ec:453 declined two DIFFERENT moves at this
   seam: an existential receipt `exists E, forall .., E .. = encode_msgWOTS (ThC ..)`
   (trivially true, says nothing about the actual op), and a `clone .. realize`
   (EasyCrypt cannot re-interpret an already-declared op FROM INSIDE the theory).
   This is neither -- it edits the DECLARATION SITE, which is the one place the
   re-interpretation obstruction does not apply, and it constrains THE actual op.
   Geometry:598 calls `hencb` load-bearing, but the stated consequent is that DROPPING
   it kills the reduction to MM45's WOTS-TW.  Nothing is dropped here: the equation
   still holds, now by computation, so R_int_WOTSTW is preserved exactly.
   `encode_msgWOTS` itself REMAINS FREE, so no generality is lost in the encoder. *)
op encode_msgWOTS_C (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr)
  : EmsgWOTS.emsgWOTS =
  encode_msgWOTS (ThC p a x cc).

(* THE BRIDGE EQUATION, KEPT VISIBLE IN THE CLOSURE.  This is verbatim the premise
   `hencb` that the capstone family carried until 2026-08-25.  It is now a THEOREM,
   and the headline family discharges it with this term instead of assuming it.

   It is stated separately rather than left implicit in the definition ON PURPOSE:
   a reader auditing what the artifact commits to about the encoder should find the
   commitment as a NAMED, PINNED result in the closure, not have to notice that an
   op acquired a body.  Pinned twice -- the op body at
   `op:cdrafts-split/WOTS_C_Real.ec::encode_msgWOTS_C` and this statement -- so
   neither the commitment nor its wording can move without the gate saying so. *)
lemma encode_msgWOTS_C_compat (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr) :
  encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc).
proof. by rewrite /encode_msgWOTS_C. qed.

(* The signer's counter search is the proved total grind. *)
op grindC (ps : pseed) (ad : adrs) (m : dgstblock) : cntr = STCRC_WC.G.grind ps ad m.

(* --------------------------------------------------------------------------
   4.  Thm C.2 / Thm D.1 — COMPOSITION ROADMAP (statements below are the goal;
       the WOTS+C scheme + reduction bodies + proofs are the remaining core).

   Thm D.1 (paper App D), the multi-instance form SPHINCS+ needs, in the shape
   of the real `MEUFGCMA_WOTSTWESNPRF` bound (WOTS_TW_ES.ec:6269) with ONE added
   S-TCR(+C) summand — every term on the RHS now nameable and REAL:

     Pr[ M_EUF_GCMA_WOTSC_NPRF(A, O_MEUFGCMA_WOTSC_Default, FC.O_THFC_Default).main() ]  (* REAL now — WOTS_C_Scheme.ec *)
       <=  Pr[ STCRC_WC.S_TCR_C(R_STCRC_WOTSC(A),                        (* REAL, this file *)
                                STCRC_WC.O_STCRC_Default,
                                STCRC_WC.Col.O_THFC_Default).main() ]
         + Pr[ M_EUF_GCMA_WOTSTWESNPRF(R_WOTSTW_WOTSC(A),                 (* REAL, WOTS_TW_ES.ec:2323 *)
                                       O_MEUFGCMA_WOTSTWESNPRF,
                                       FC.O_THFC_Default).main() ].

   Composed with the reused black box `MEUFGCMA_WOTSTWESNPRF` (WOTS_TW_ES.ec:6269),
   the second summand unfolds to (w-2)*SM_DT_UD_C + SM_DT_TCR_C + SM_DT_PRE_C —
   giving the WOTS-layer terms of SPHINCS+C's Thm 5.2 unchanged, plus the single
   new S-TCR(+C) term instantiated in §2.

   The reductions R_STCRC_WOTSC (Alg 9) and R_WOTSTW_WOTSC (Alg 10) live inside a
   `section` with `declare module A <: Adv_MEUFGCMA_WOTSC` mirroring the repo's
   `declare module A` at WOTS_TW_ES.ec:2894; the WOTS-TW theorem is invoked as a
   black box (its 6314-line proof never reopened).  Not built here.
   -------------------------------------------------------------------------- *)

(* Losslessness of the S-TCR(+C) challenge oracle and the Th_lambda collection
   oracle over the real types (zero admits) — deterministic procs; genuine
   prerequisites the Alg-9/Alg-10 reductions consume. *)
lemma O_STCRC_query_ll : islossless STCRC_WC.O_STCRC_Default.query.
proof. by proc; auto. qed.

lemma O_THFC_query_ll : islossless STCRC_WC.Col.O_THFC_Default.query.
proof. by proc; auto. qed.
