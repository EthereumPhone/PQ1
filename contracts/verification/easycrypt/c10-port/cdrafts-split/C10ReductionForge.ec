(* The actual reduction exposes the complete cube paths to the same observed adversary. *)
require import AllCore List IntDiv BinaryTrees MerkleTrees C10HypertreeCorrect C10CubeCorrect C10HypertreeCoverage XmssmtCC_All.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme.

lemma remaining_cell idx layer : 0 <= layer < d =>
  edivz (remaining_idx idx layer) l' = path_cell idx layer.
proof.
  move=> hl; rewrite /remaining_idx /path_cell.
  have hc : layer = 0 \/ layer = 1 by move: hl; rewrite d_val; smt().
  by case: hc => ->.
qed.

lemma recover_frame : hoare[FL_SL_XMSS_MT_C_ES.pkWOTS_from_sigWOTS_C : true ==> true].
proof. proc; wp; while (true); by auto. qed.

section.
declare module A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF
  {-Observe,-R_MEUFGCMAWOTSC_EUFNAGCMA_C,-O_MEUFGCMA_WOTSC_Default,-FC.O_THFC_Default}.
module RForge = R_MEUFGCMAWOTSC_EUFNAGCMA_C(Observe(A),O_MEUFGCMA_WOTSC_Default,FC.O_THFC_Default).

lemma forge_shape ps0 ad0 ml0 sigs0 leaves0 roots0 :
  hoare[RForge.forge : ps = ps0 /\ RForge.ad = ad0 /\ RForge.ml = ml0 /\
    RForge.sigWOTStd = sigs0 /\ RForge.leavestd = leaves0 /\ RForge.rootstd = roots0 ==>
    Observe.public = (root_at roots0 (d-1) 0,ps0,ad0) /\
    Observe.signatures = mkseq (cube_path ps0 ad0 sigs0 leaves0) l].
proof.
  proc; wp.
  while (Observe.public = (root_at roots0 (d-1) 0,ps0,ad0) /\
    Observe.signatures = mkseq (cube_path ps0 ad0 sigs0 leaves0) l).
  + by wp; call recover_frame; auto.
  wp; inline Observe(A,FC.O_THFC_Default).forge.
  wp; call (_ : true).
  wp; while (ps = ps0 /\ RForge.ad = ad0 /\ RForge.ml = ml0 /\
    RForge.sigWOTStd = sigs0 /\ RForge.leavestd = leaves0 /\ RForge.rootstd = roots0 /\
    size sigl <= l /\ sigl = mkseq (cube_path ps0 ad0 sigs0 leaves0) (size sigl)).
  + wp; while (ps = ps0 /\ RForge.ad = ad0 /\ RForge.ml = ml0 /\
      RForge.sigWOTStd = sigs0 /\ RForge.leavestd = leaves0 /\ RForge.rootstd = roots0 /\
      size sigl < l /\ sigl = mkseq (cube_path ps0 ad0 sigs0 leaves0) (size sigl) /\
      size sapl <= d /\ sapl = mkseq (layer_signature ps0 ad0 sigs0 leaves0 (size sigl)) (size sapl) /\
      tidx = remaining_idx (size sigl) (size sapl)).
    - auto => /> &hr hi hsigs hs hsap hl.
      have hidx : 0 <= size sigl{hr} < l by smt(size_ge0).
      have hly : 0 <= size sapl{hr} < d by smt(size_ge0).
      rewrite size_rcons; split; first by smt().
      split; last exact (remaining_step (size sigl{hr}) (size sapl{hr}) hidx hly).
      by rewrite mkseqS 1:size_ge0 -hsap /= /layer_signature
        -(remaining_cell (size sigl{hr}) (size sapl{hr}) hly) /sig_at /leaves_at /=.
    auto => />; rewrite /remaining_idx /cube_path /=; smt(mkseq0 mkseqS size_rcons ge1_d size_ge0).
  auto => />; rewrite /root_at; smt(ge2_l mkseq0).
qed.
end section.

lemma leaf_query_frame : hoare[O_MEUFGCMA_WOTSC_Default.query : true ==> true].
proof.
  proc*; exists* O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs, wad, m;
    elim* => ps0 qs0 wad0 m0.
  by call (query_correct_spec ps0 qs0 wad0 m0); auto.
qed.

lemma collection_query_frame : hoare[FC.O_THFC_Default.query : true ==> true].
proof. by proc; auto. qed.

section.
declare module A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF
  {-Observe,-R_MEUFGCMAWOTSC_EUFNAGCMA_C,-O_MEUFGCMA_WOTSC_Default,-FC.O_THFC_Default}.
module RMessages = R_MEUFGCMAWOTSC_EUFNAGCMA_C(Observe(A),O_MEUFGCMA_WOTSC_Default,FC.O_THFC_Default).

lemma choose_messages : hoare[RMessages.choose : true ==> RMessages.ml = Observe.messages].
proof.
  proc; while (RMessages.ml = Observe.messages).
  + wp; while (RMessages.ml = Observe.messages).
    - wp; while (RMessages.ml = Observe.messages).
      + wp; while (RMessages.ml = Observe.messages).
        - by wp; call collection_query_frame; auto.
        by auto.
      wp; while (RMessages.ml = Observe.messages).
      + by wp; call collection_query_frame; call leaf_query_frame; auto.
      by auto.
    by auto.
  wp; inline Observe(A,FC.O_THFC_Default).choose.
  wp; call (_ : true); first by proc; auto.
  by auto.
qed.
end section.
