(* #########################################################################
   PROMOTED INTO THE CERTIFIED SPLIT CLOSURE 2026-08-31, byte-identical to
   experiments/wots-badenc/base/BadEncCountermodel.ec except for this banner
   and three corrected in-file citations (the file cited the EXPERIMENT's base
   line numbers).  It compiled against
   base-c10-split unchanged -- the promoted BODY is byte-identical to the
   experiment's, verified by diff; only this banner and three corrected
   citations differ.

   WHY IT WAS PROMOTED.  It was proved on 2026-08-12 and left under
   `experiments/`, which `cert_gate_split.sh`'s cone census DOES NOT COVER.  So
   the one fact that stops a reader taking the BadEnc charge for a BOUND was
   invisible to every gate and free to rot against the tree it describes.  The
   charge landed in the closure on 2026-08-30 (`MEUFGCMA_WOTSTWESNPRF_Charged`,
   WOTS_TW_ES.ec:6849); its countermodel now lands beside it.

   INDEPENDENT REPRODUCTION.  Before finding this file, the same result was
   re-derived from scratch against the CURRENT split tree with a different
   adversary (globals rather than abstract ops) and independently compiled
   GREEN -- same helper shape, same losslessness+hoare split, same statement.
   That reproduction is kept at scratch/badenc_replay.ec and is NOT a closure
   member: one statement of this fact belongs in the cone, not two.

   READ THE SCOPE LINE BELOW ("CONDITIONAL, exactly as ...") BEFORE QUOTING
   THIS.  The colliding pair is a HYPOTHESIS.  What is machine-checked is the
   IMPLICATION; that such pairs exist at deployed geometry rests on the
   target-sum antichain bound (2^123.76 < 2^128), which this tree states in
   PROSE at WOTS_TW_ES.ec:711-725 and does NOT mechanize.
   ######################################################################### *)
(* ==========================================================================
   COUNTERMODEL — the BadEnc term is 1, so it CANNOT be bounded at this layer.

   The charged WOTS-TW bound (base-c10-split/WOTS_TW_ES.ec) replaces MM45's admitted
   encoder injectivity with an explicit summand

       Pr[Game4_WOTSTWES_BadEnc(A) : res /\ BadEncFlag.badenc].

   The obvious next question is "how small is it?".  THE ANSWER IS: NOT SMALL.
   For an explicit adversary it is exactly 1, so no non-trivial bound exists at
   the WOTS-TW layer, and the charged theorem — while TRUE — is quantitatively
   VACUOUS when applied to an arbitrary `Adv_MEUFGCMA_WOTSTWESNPRF`.

   WHY.  Verification reads the message ONLY through its codeword:
   `pkWOTS_from_sigWOTS` (:2421) computes `em <- encode_msgWOTS m` (:2429) and
   its loop touches `em` alone.  So under an encoding collision a signature for
   `m` is *already* a signature for `m'`, and the adversary forges by replaying
   it.  Every other win conjunct falls out:

     is_fresh      m' <> m                                    (hypothesis)
     !hchwcoll     em = em' makes the strict digit inequality
                   `BaseW.val em'.[i] < BaseW.val em.[i]` FALSE at every index
     P m'          from P m, since P depends only on the codeword
     dist_wgpidxs  `uniq` of a ONE-element list
     disj_wgpidxs  the adversary never queries OC, so adlOC = []
     0 <= nrqs <= c  one query, and `ge1_c` gives 1 <= c

   THIS IS NOT A NEW DEFECT.  It is the precise formal content of "MM45's WOTS-TW
   theorem is false at deployed C10 geometry": the theorem quantifies over ALL
   msgWOTS, and at deployed widths the encoder is 2^127-to-one.  The charged
   bound is progress toward an HONEST STRUCTURE, not toward a small number — the
   term has to be bounded one layer UP, at +C, where the WOTS message is
   `ThC ps ad x c` and the adversary cannot choose it freely.

   *** THE DEPLOYED WALLET IS NOT AFFECTED, AND THIS IS NOT AN ATTACK. ***
   C10's WOTS layer never encodes an adversary-chosen value — it encodes
   key-determined internal nodes (sphincs-c10/src/fors.rs:265-268;
   `compute_fors_pk` takes no message argument).  The adversary below is a
   MODEL-LEVEL object that the deployment gives no one the ability to build.
   Classification is unchanged: proof-technique limitation, not a vulnerability.

   CONDITIONAL, exactly as `admit_refuted_by_surface_collision` is:
   `encode_msgWOTS` is free here, so the colliding pair is a HYPOTHESIS.  At
   deployed geometry such pairs exist in abundance (residual Q2b supplies them);
   this file does not reach for that identification.
   ========================================================================== *)
require import AllCore List Distr DList StdOrder StdBigop.
require import WOTS_TW_ES.
import EmsgWOTS.

(* The colliding pair, and the address to query at.  Free ops: the collision
   facts are carried as HYPOTHESES of the theorem, not asserted here. *)
op cm  : msgWOTS.
op cm' : msgWOTS.
op wad0 : wadrs.

(* --------------------------------------------------------------------------
   THE LOAD-BEARING FACT.  Verification transfers across an encoding collision.
   -------------------------------------------------------------------------- *)
equiv pkfs_encode_transfer :
  WOTS_TW_ES.pkWOTS_from_sigWOTS ~ WOTS_TW_ES.pkWOTS_from_sigWOTS :
      ={sig, ps, ad}
   /\ encode_msgWOTS m{1} = encode_msgWOTS m{2}
   ==> ={res}.
proof.
proc.
while (={pkWOTS, sig, ps, ad, em}); first by auto.
by auto.
qed.

equiv verify_encode_transfer :
  WOTS_TW_ES.verify ~ WOTS_TW_ES.verify :
      ={pk, sig}
   /\ encode_msgWOTS m{1} = encode_msgWOTS m{2}
   ==> ={res}.
proof.
proc.
by call pkfs_encode_transfer; auto.
qed.

(* --------------------------------------------------------------------------
   THE COUNTERMODEL ADVERSARY.  One query at `wad0` on `cm`; forge `cm'` by
   REPLAYING the signature.  It never queries OC, which is what makes
   `disj_wgpidxs` hold.
   -------------------------------------------------------------------------- *)
module (A_coll : Adv_MEUFGCMA_WOTSTWESNPRF) (O : Oracle_MEUFGCMA_WOTSTWESNPRF, OC : FC.Oracle_THFC) = {
  var sg : sigWOTS

  proc choose() : unit = {
    var pksig : pkWOTS * sigWOTS;
    pksig <@ O.query(wad0, cm);
    sg <- pksig.`2;
  }

  proc forge(ps : pseed) : int * msgWOTS * sigWOTS = {
    return (0, cm', sg);
  }
}.

(* ==========================================================================
   WHAT IS PROVED HERE, AND WHAT IS NOT.   [UPDATE 2026-08-13: the packaging
   step, previously listed here as NOT PROVED, is now MECHANISED -- see
   `badenc_is_one` at the bottom of this file.  This block is rewritten to say
   what the file actually contains; the honest caveats are UNCHANGED and are
   restated below, because none of them was closed by the mechanisation.]

   PROVED (the whole file compiles; 0 admits, 0 axioms, 0 `declare axiom`):
     * `pkfs_encode_transfer` / `verify_encode_transfer` -- verification depends
       on the message ONLY through its codeword, so validity transfers across an
       encoding collision.  This is the load-bearing fact: it is what makes the
       replay forgery work, and it is a THEOREM about MM45's own `verify`, not an
       assumption.
     * `A_coll` -- the explicit adversary, well-typed against MM45's
       `Adv_MEUFGCMA_WOTSTWESNPRF`: one query on `cm`, forge `cm'` by replaying
       the signature, never touch `OC`.
     * `pkfs_fun` + `pkfs_computes_fun` + `altx_query_computes_fun` -- ONE
       functional characterisation pinned to BOTH the oracle's pk-loop and
       `pkWOTS_from_sigWOTS`'s loop, which turns WOTS correctness for the honest
       query into a syntactic equality (no cross-procedure loop invariant).
     * `verify_replay_valid` -- verify accepts the replayed signature.
     * losslessness of every component and of the whole game
       (`pkfs_from_sig_ll`, `verify_ll`, `altx_query_ll`, `acoll_choose_ll`,
        `acoll_forge_ll`, `badenc_game_ll`).
     * `badenc_game_hoare` -- the win condition holds with certainty.
     * `badenc_is_one` -- THE PACKAGING STEP:

           P cm => cm <> cm' => encode_msgWOTS cm = encode_msgWOTS cm'
        => Pr[Game4_WOTSTWES_BadEnc(A_coll).main() @ &m
               : res /\ BadEncFlag.badenc] = 1%r.

       `Game4_WOTSTWES_BadEnc` here is the SAME exported module whose
       probability appears as the charged summand in the split tree's WOTS-TW
       bound `MEUFGCMA_WOTSTWESNPRF_Charged` (base-c10-split/WOTS_TW_ES.ec:6849,
       summand at :6856), so this is a statement about the term that is actually
       paid, not about a look-alike.
       (Citation corrected on promotion 2026-08-31: it read `:6771`, which is an
       experiment-base line number and lands mid-tactic in the split file.)

   STILL NOT PROVED, AND DELIBERATELY SO -- the theorem is CONDITIONAL:
     * `cm`, `cm'`, `wad0` are FREE ops.  The colliding pair is a HYPOTHESIS,
       exactly as it was before the mechanisation; this file does not exhibit
       one and does not reach for the deployed-geometry identification (residual
       Q2b supplies those pairs).  So the content is "IF an encoding collision
       on the constant-sum surface exists, THEN the BadEnc term is 1", not
       "the BadEnc term is 1" unconditionally.
     * Nothing here is an attack on the deployed wallet -- see the header.

   INHERITED, NOT ADDED.  The proof is relative to the ambient MM45/C10-fork
   theory and its declared parameters: `ge2_len`, `ge1_c`,
   `op [lossless] dpseed`, `op [lossless] ddgstblock`.  It never unfolds `cf`,
   so it does NOT use `ch0` / `chS`; and it is stated OUTSIDE
   `section Proof_M_EUF_GCMA_WOTS_TW_ES_NPRF`, so the section-local
   `declare axiom A_choose_ll` / `A_forge_ll` are not in scope (`A_coll` is
   concrete and its losslessness is proved here, not assumed).

   NEGATIVE CONTROLS.  Regenerate with `../mkctl.sh`, run with `../runctl.sh`;
   receipts in `../controls/Ctl?.out`.  A--C each drop exactly one hypothesis
   from BOTH `badenc_game_hoare` and `badenc_is_one`, replacing it by `true` so
   the proof script's intro arity is unchanged (the control deletes INFORMATION,
   it does not break the syntax).  D mutates the conclusion instead.  All four
   MUST FAIL, and all four do:
     CtlA  no `encode_msgWOTS cm = encode_msgWOTS cm'`
           -> fails at `by call verify_replay_valid; skip => />.`
     CtlB  no `cm <> cm'`  -> fails at the `is_fresh` conjunct
                              (`by move: hne; apply/contra => ->.`)
     CtlC  no `P cm`       -> fails at the `P m'` conjunct
                              (`by rewrite /P -hcol; move: hP; rewrite /P.`)
     CtlD  `= 0%r` instead of `= 1%r`
           -> fails at `by conseq badenc_game_ll (badenc_game_hoare ...)`,
              i.e. the packaging step really proves the stated probability.
   ========================================================================== *)

(* ==========================================================================
   MECHANISING Pr[..] = 1.

   The crux is WOTS correctness for the honest query: the `pk` the oracle stored
   must be what `verify` recomputes from the SAME signature.  Proving that by a
   cross-procedure loop invariant is painful, so instead both loops are pinned to
   the SAME FUNCTIONAL characterisation and the equality becomes syntactic.

   `O_Game34_WOTSTWES_AltX.query`'s pk-loop and
   `WOTS_TW_ES.pkWOTS_from_sigWOTS`'s loop are textually identical modulo
   variable names -- both `rcons` a `dgstblock list` of length `len`, both index
   the signature by `nth witness <sigl> (size acc)`.  So one op captures both.
   ========================================================================== *)
op pkfs_fun (ps : pseed) (ad : adrs) (em : EmsgWOTS.emsgWOTS) (sigl : dgstblock list) : dgstblock list =
  mkseq (fun i => cf ps (set_chidx ad i)
                     (BaseW.val em.[i]) (w - 1 - BaseW.val em.[i])
                     (DigestBlock.val (nth witness sigl i))) len.

lemma size_pkfs_fun (ps : pseed) (ad : adrs) (em : EmsgWOTS.emsgWOTS) (sigl : dgstblock list) :
  size (pkfs_fun ps ad em sigl) = len.
proof. by rewrite /pkfs_fun size_mkseq; smt(ge2_len). qed.

(* VERIFY's half: pkWOTS_from_sigWOTS computes exactly pkfs_fun. *)
lemma pkfs_computes_fun (m0 : msgWOTS) (sig0 : sigWOTS) (ps0 : pseed) (ad0 : adrs) :
  hoare[WOTS_TW_ES.pkWOTS_from_sigWOTS :
          m = m0 /\ sig = sig0 /\ ps = ps0 /\ ad = ad0
          ==> DBLL.val res = pkfs_fun ps0 ad0 (encode_msgWOTS m0) (DBLL.val sig0)].
proof.
proc.
while (   ps = ps0 /\ ad = ad0 /\ sig = sig0 /\ em = encode_msgWOTS m0
       /\ 0 <= size pkWOTS <= len
       /\ pkWOTS = mkseq (fun i => cf ps0 (set_chidx ad0 i)
                                      (BaseW.val (encode_msgWOTS m0).[i])
                                      (w - 1 - BaseW.val (encode_msgWOTS m0).[i])
                                      (DigestBlock.val (nth witness (DBLL.val sig0) i)))
                         (size pkWOTS)).
+ auto => /> &hr h1 h2 h3 hlt.
  rewrite size_rcons /=; split; first by smt().
  by rewrite (mkseqS _ (size pkWOTS{hr})) 1:/# -h3.
auto => /> ; rewrite mkseq0 /=; split; first by smt(ge2_len).
(* Goal state read from `easycrypt cli` rather than guessed (one miss already):
   h1..h3 are the three SIZE facts, and the mkseq equation arrives as an
   un-introduced IMPLICATION -- hence the extra `heq`.  And `have -> : size pkl =
   len` was wrong here: it REWRITES the goal instead of supplying insubdK's side
   condition, so it is kept as a named hypothesis. *)
move=> pkl h1 h2 h3 heq.
have hsz : size pkl = len by smt().
(* `-hsz` spawns a trivial `size pkl = size pkl` side goal; without the `//`
   the following `exact heq` lands on THAT goal and reports a proof-term
   mismatch.  Read off `easycrypt cli` (remaining: 2), not guessed. *)
(* The `//` closes BOTH remaining goals -- the trivial `size pkl = size pkl`
   side goal AND the main one, since after `-hsz` the conclusion is literally
   `heq`.  An `exact heq` after this errors with "all goals are closed". *)
by rewrite DBLL.insubdK 1:hsz /pkfs_fun -hsz.
qed.

(* ORACLE's half: O_Game34_WOTSTWES_AltX.query stores exactly pkfs_fun.
   `ps`/`qs` are GLOBALS of O_MEUFGCMA_WOTSTWESNPRF (the oracle `include var`s
   them), so the invariant must name them qualified. *)
lemma altx_query_computes_fun :
  hoare[O_Game34_WOTSTWES_AltX.query :
          wad = wad0 /\ m = cm /\ O_MEUFGCMA_WOTSTWESNPRF.qs = []
          ==>    O_MEUFGCMA_WOTSTWESNPRF.qs = [(WAddress.val wad0, cm, res.`1, res.`2)]
              /\ DBLL.val res.`1
                 = pkfs_fun O_MEUFGCMA_WOTSTWESNPRF.ps (WAddress.val wad0)
                            (encode_msgWOTS cm) (DBLL.val res.`2)].
proof.
proc.
seq 5 : (   ad = WAddress.val wad0 /\ m = cm /\ em = encode_msgWOTS cm
         /\ O_MEUFGCMA_WOTSTWESNPRF.qs = [] /\ size sig = len).
+ while (0 <= size sig <= len).
  - by auto => /> *; rewrite ?size_rcons /#.
  by auto => />; smt(ge2_len).
seq 2 : (   ad = WAddress.val wad0 /\ m = cm /\ em = encode_msgWOTS cm
         /\ O_MEUFGCMA_WOTSTWESNPRF.qs = [] /\ size sig = len
         /\ size pk = len
         /\ pk = pkfs_fun O_MEUFGCMA_WOTSTWESNPRF.ps (WAddress.val wad0)
                          (encode_msgWOTS cm) sig).
+ while (   ad = WAddress.val wad0 /\ m = cm /\ em = encode_msgWOTS cm
         /\ O_MEUFGCMA_WOTSTWESNPRF.qs = [] /\ size sig = len
         /\ 0 <= size pk <= len
         /\ pk = mkseq (fun i => cf O_MEUFGCMA_WOTSTWESNPRF.ps
                                    (set_chidx (WAddress.val wad0) i)
                                    (BaseW.val (encode_msgWOTS cm).[i])
                                    (w - 1 - BaseW.val (encode_msgWOTS cm).[i])
                                    (DigestBlock.val (nth witness sig i)))
                       (size pk)).
  - auto => /> &hr h1 h2 h3 h4 hlt.
    rewrite size_rcons /=; split; first by smt().
    by rewrite (mkseqS _ (size pk{hr})) 1:/# -h4.
  auto => /> &hr hsz.
  split; first by rewrite mkseq0 /=; smt(ge2_len).
  move=> pkl hnlt h1 h2 heq.
  have hlen : size pkl = len by smt().
  split; first exact hlen.
  by rewrite /pkfs_fun -hlen.
auto => /> &hr hsz hszpk.
by rewrite !DBLL.insubdK.
qed.

(* VERIFY accepts the REPLAYED signature under an encoding collision.  Stated
   parameter-free (the precondition mentions only `verify`'s own arguments), so
   the caller needs no `exists*`. *)
lemma verify_replay_valid :
  hoare[WOTS_TW_ES.verify :
             m = cm'
          /\ encode_msgWOTS cm = encode_msgWOTS cm'
          /\ DBLL.val pk.`1 = pkfs_fun pk.`2 pk.`3 (encode_msgWOTS cm) (DBLL.val sig)
          ==> res].
proof.
proc; sp.
exists* m, sig, ps, ad; elim* => m0 sig0 ps0 ad0.
call (pkfs_computes_fun m0 sig0 ps0 ad0).
skip => /> &hr hcol hval r hres.
by apply DBLL.val_inj; rewrite hres -hcol hval.
qed.

(* -------------------------------------------------------------------------
   A_coll's own two procedures, against the concrete oracles the game uses.
   ------------------------------------------------------------------------- *)
lemma acoll_choose_spec :
  hoare[A_coll(O_Game34_WOTSTWES_AltX, FC.O_THFC_Default).choose :
          O_MEUFGCMA_WOTSTWESNPRF.qs = []
          ==> exists (pkx : pkWOTS),
                 O_MEUFGCMA_WOTSTWESNPRF.qs = [(WAddress.val wad0, cm, pkx, A_coll.sg)]
              /\ DBLL.val pkx
                 = pkfs_fun O_MEUFGCMA_WOTSTWESNPRF.ps (WAddress.val wad0)
                            (encode_msgWOTS cm) (DBLL.val A_coll.sg)].
proof.
proc; wp; call altx_query_computes_fun; skip => />.
by move=> &hr r hr'; exists r.`1.
qed.

lemma acoll_forge_spec :
  hoare[A_coll(O_Game34_WOTSTWES_AltX, FC.O_THFC_Default).forge :
          true ==> res = (0, cm', A_coll.sg)].
proof. by proc; auto. qed.

(* -------------------------------------------------------------------------
   Losslessness.  Both `while` loops are bounded by `len`.
   ------------------------------------------------------------------------- *)
lemma pkfs_from_sig_ll : islossless WOTS_TW_ES.pkWOTS_from_sigWOTS.
proof.
proc.
while (true) (len - size pkWOTS).
+ by move=> z; auto => />; smt(size_rcons).
by auto; smt().
qed.

lemma verify_ll : islossless WOTS_TW_ES.verify.
proof. by proc; call pkfs_from_sig_ll; auto. qed.

lemma altx_query_ll : islossless O_Game34_WOTSTWES_AltX.query.
proof.
proc.
wp.
while (true) (len - size pk).
+ by move=> z; auto => />; smt(size_rcons).
wp.
while (true) (len - size sig).
+ move=> z; wp; rnd predT; skip => />; smt(ddgstblock_ll size_rcons).
by auto; smt().
qed.

lemma acoll_choose_ll : islossless A_coll(O_Game34_WOTSTWES_AltX, FC.O_THFC_Default).choose.
proof. by proc; wp; call altx_query_ll; skip. qed.

lemma acoll_forge_ll : islossless A_coll(O_Game34_WOTSTWES_AltX, FC.O_THFC_Default).forge.
proof. by proc; auto. qed.

(* Trivial losslessness of the bookkeeping oracles (no loops). *)
lemma o_init_ll : islossless O_MEUFGCMA_WOTSTWESNPRF.init.
proof. by proc; auto. qed.
lemma o_get_ll : islossless O_MEUFGCMA_WOTSTWESNPRF.get.
proof. by proc; auto. qed.
lemma o_getadl_ll : islossless O_MEUFGCMA_WOTSTWESNPRF.get_addresses.
proof. by proc; auto. qed.
lemma o_nrq_ll : islossless O_MEUFGCMA_WOTSTWESNPRF.nr_queries.
proof. by proc; auto. qed.
lemma o_dist_ll : islossless O_MEUFGCMA_WOTSTWESNPRF.dist_addresses.
proof. by proc; auto. qed.
lemma oc_init_ll : islossless FC.O_THFC_Default.init.
proof. by proc; auto. qed.
lemma oc_gettw_ll : islossless FC.O_THFC_Default.get_tweaks.
proof. by proc; auto. qed.

lemma badenc_game_ll : islossless Game4_WOTSTWES_BadEnc(A_coll).main.
proof.
proc.
wp; call oc_gettw_ll; call o_getadl_ll; call o_dist_ll; call o_nrq_ll; wp.
call verify_ll; call o_get_ll; call acoll_forge_ll; call acoll_choose_ll.
call oc_init_ll; call o_init_ll.
by auto; smt(dpseed_ll).
qed.

(* -------------------------------------------------------------------------
   THE GAME'S WIN CONDITION HOLDS WITH CERTAINTY.
   ------------------------------------------------------------------------- *)
lemma badenc_game_hoare :
     P cm => cm <> cm' => encode_msgWOTS cm = encode_msgWOTS cm'
  => hoare[Game4_WOTSTWES_BadEnc(A_coll).main : true ==> res /\ BadEncFlag.badenc].
proof.
move=> hP hne hcol.
proc.
seq 4 : (   ps = O_MEUFGCMA_WOTSTWESNPRF.ps
         /\ FC.O_THFC_Default.tws = []
         /\ exists (pkx : pkWOTS),
                O_MEUFGCMA_WOTSTWESNPRF.qs = [(WAddress.val wad0, cm, pkx, A_coll.sg)]
             /\ DBLL.val pkx = pkfs_fun O_MEUFGCMA_WOTSTWESNPRF.ps (WAddress.val wad0)
                                        (encode_msgWOTS cm) (DBLL.val A_coll.sg)).
+ by call acoll_choose_spec; inline *; auto.
(* forge + get: the adversary replays, and `get 0` returns the honest entry. *)
seq 2 : (   FC.O_THFC_Default.tws = []
         /\ O_MEUFGCMA_WOTSTWESNPRF.qs = [(WAddress.val wad0, cm, pk, sig)]
         /\ i = 0 /\ m = cm /\ m' = cm' /\ ad = WAddress.val wad0
         /\ sig' = sig
         /\ DBLL.val pk = pkfs_fun ps (WAddress.val wad0)
                                   (encode_msgWOTS cm) (DBLL.val sig)).
+ by inline *; auto => />.
(* verify accepts the replay *)
seq 1 : (   FC.O_THFC_Default.tws = []
         /\ O_MEUFGCMA_WOTSTWESNPRF.qs = [(WAddress.val wad0, cm, pk, sig)]
         /\ i = 0 /\ m = cm /\ m' = cm' /\ ad = WAddress.val wad0
         /\ sig' = sig /\ is_valid).
+ by call verify_replay_valid; skip => />.
(* Everything left is arithmetic/list bookkeeping on a ONE-query transcript.
   `=> />` already discharged `dist_wgpidxs` (uniq of a singleton),
   `disj_wgpidxs` (adlOC = [], A_coll never queries OC), `BadEncFlag.badenc`
   and `P m`; these four are what remains. *)
inline *; auto => /> &hr _.
do ! split.
+ exact ge1_c.
+ by move: hne; apply/contra => ->.
+ (* !hchwcoll: em = em' makes `BaseW.val em'.[i] < BaseW.val em.[i]` FALSE at
     EVERY index -- it is literally `x < x`. *)
  rewrite /has_chwcoll; apply/hasPn => x _.
  by rewrite /is_chwcoll /= -hcol /#.
(* P depends on the message ONLY through its codeword. *)
by rewrite /P -hcol; move: hP; rewrite /P.
qed.

(* =========================================================================
   THE PACKAGING STEP.  Pr[..] = 1: losslessness + the certain win.
   ========================================================================= *)
lemma badenc_is_one &m :
     P cm => cm <> cm' => encode_msgWOTS cm = encode_msgWOTS cm'
  => Pr[Game4_WOTSTWES_BadEnc(A_coll).main() @ &m
         : res /\ BadEncFlag.badenc] = 1%r.
proof.
move=> hP hne hcol.
byphoare => //.
by conseq badenc_game_ll (badenc_game_hoare hP hne hcol).
qed.
