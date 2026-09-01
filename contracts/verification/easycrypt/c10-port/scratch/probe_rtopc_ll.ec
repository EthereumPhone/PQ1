(* PROBE -- losslessness of R_top_C's choose.  Scratch only. *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS XmssmtCC_All RtopCSoundness FxChain GprocFORSC10 GprocVI.
require WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme WOTS_C_Interactive.
require FORS_C10 FORS_C10_Multi DigitalSignatures.
require import BitEncoding. import BS2Int BitChunking.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.

lemma rtopc_choose_ll (F <: Adv_EUFCMA_C) (OC <: FSSLXMTWES.TRHC.Oracle_THFC{-R_top_C}) :
  islossless OC.query => islossless R_top_C(F, OC).choose.
proof.
move=> OCll.
proc.
while (true) (nr_trees 0 - size R_top_C.skFORSnt).
+ move=> z.
  wp.
  while (true) (l' - size skFORSlp).
  - move=> z'.
    wp; call OCll; wp.
    while (true) (k - size skFORScube).
    * move=> z''.
      wp.
      while (true) (a - size nodes).
      + move=> z'''.
        wp.
        while (true) (nr_nodesf (size nodes + 1) - size nodescl).
        - move=> z''''.
          by wp; call OCll; wp; skip => />; smt(size_rcons).
        by wp; skip => />; smt(size_rcons).
      wp.
      while (true) (t - size skFORSet).
      + move=> z'''.
        by wp; call OCll; wp; rnd; skip => />; smt(size_rcons ddgstblock_ll).
      by wp; skip => />; smt(size_rcons).
    by wp; skip => />; smt(size_rcons).
  by wp; skip => />; smt(size_rcons).
by wp; skip => /> /#.
qed.

(* helper: the FORS signing procedure is lossless *)
lemma gen_leaves_ll : islossless FTWES.FL_FORS_ES_NPRF.gen_leaves_single_tree.
proof.
islossless.
while (true) (t - size leaves).
+ by move=> z; auto => />; smt(size_rcons).
by auto => /#.
qed.

lemma fors_sign_ll : islossless FTWES.FL_FORS_ES_NPRF.sign.
proof.
islossless.
while (true) (k - size sig).
+ by move=> z; wp; call gen_leaves_ll; auto => />; smt(size_rcons).
by auto => /#.
qed.

(* Obligation 2.  `forge` calls A(O_CMA).forge, so it needs BOTH the adversary's
   losslessness AND the CMA oracle's -- and the oracle draws
   `mk <$ dcond dmkey (good_fors m)`, a CONDITIONAL distribution.  That is a
   GRIND-REACHABILITY side condition; it is carried as an explicit premise
   because nothing in the closure supplies it. *)
lemma rtopc_forge_ll
  (F <: Adv_EUFCMA_C{-R_top_C}) (OC <: FSSLXMTWES.TRHC.Oracle_THFC{-R_top_C, -F}) :
     (forall (m : msg), is_lossless (dcond dmkey (good_fors m)))
  => (forall (O <: SOracle_CMA_C{-F}), islossless O.sign => islossless F(O).forge)
  => islossless R_top_C(F, OC).forge.
proof.
move=> hgrind Fll.
proc.
call pkfromsig_ll.
wp.
have OCMAll : islossless R_top_C(F, OC).O_CMA.sign.
+ proc; wp; call fors_sign_ll; wp; rnd; skip.
  move=> &hr _; split => [|v _ //].
  by have := hgrind m{hr}; rewrite /is_lossless => <-; apply/mu_eq.
call (Fll (<: R_top_C(F, OC).O_CMA) OCMAll).
by auto.
qed.
