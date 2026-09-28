(* The actual hypertree-to-WOTS reduction constructs a consistent cube and records exactly its leaf queries. *)
require import AllCore List IntDiv StdOrder BinaryTrees MerkleTrees C10CubeConstruction C10CubeCorrect XmssmtCC_All.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES WOTS_C_Real WOTS_C_Scheme.

section.
declare module A <: Adv_EUFNAGCMA_FLSLXMSSMTTWCESNPRF
  {-R_MEUFGCMAWOTSC_EUFNAGCMA_C,-O_MEUFGCMA_WOTSC_Default,-FC.O_THFC_Default}.
module R = R_MEUFGCMAWOTSC_EUFNAGCMA_C(A,O_MEUFGCMA_WOTSC_Default,FC.O_THFC_Default).

lemma choose_build ps0 :
  hoare[R.choose :
    O_MEUFGCMA_WOTSC_Default.ps = ps0 /\ FC.O_THFC_Default.pp = ps0 /\
    O_MEUFGCMA_WOTSC_Default.qs = [] ==>
    R.ad = adz /\ O_MEUFGCMA_WOTSC_Default.ps = ps0 /\ FC.O_THFC_Default.pp = ps0 /\ cube_good ps0 R.ad R.ml R.pkWOTStd R.sigWOTStd R.leavestd R.rootstd /\ size R.pkWOTStd = d /\
    O_MEUFGCMA_WOTSC_Default.qs = cube_records R.ad R.ml R.rootstd R.pkWOTStd R.sigWOTStd].
proof.
  proc; while (R.ad = adz /\ O_MEUFGCMA_WOTSC_Default.ps = ps0 /\ FC.O_THFC_Default.pp = ps0 /\ cube_good ps0 R.ad R.ml R.pkWOTStd R.sigWOTStd R.leavestd R.rootstd /\ O_MEUFGCMA_WOTSC_Default.qs = cube_records R.ad R.ml R.rootstd R.pkWOTStd R.sigWOTStd).
  + wp; while (R.ad = adz /\ O_MEUFGCMA_WOTSC_Default.ps = ps0 /\ FC.O_THFC_Default.pp = ps0 /\ cube_good ps0 R.ad R.ml R.pkWOTStd R.sigWOTStd R.leavestd R.rootstd /\ size R.pkWOTStd < d /\ rootsntp = last R.ml R.rootstd /\ layer_good ps0 R.ad (size R.pkWOTStd) rootsntp pkWOTSnt sigcnt leavesnt rootsnt /\ O_MEUFGCMA_WOTSC_Default.qs = cube_records R.ad R.ml R.rootstd R.pkWOTStd R.sigWOTStd ++ layer_records R.ad (size R.pkWOTStd) rootsntp pkWOTSnt sigcnt).
    - seq 4 : (R.ad = adz /\ O_MEUFGCMA_WOTSC_Default.ps = ps0 /\ FC.O_THFC_Default.pp = ps0 /\ cube_good ps0 R.ad R.ml R.pkWOTStd R.sigWOTStd R.leavestd R.rootstd /\ size R.pkWOTStd < d /\ rootsntp = last R.ml R.rootstd /\ layer_good ps0 R.ad (size R.pkWOTStd) rootsntp pkWOTSnt sigcnt leavesnt rootsnt /\ size pkWOTSnt < nr_trees (size R.pkWOTStd) /\ tree_good ps0 R.ad (size R.pkWOTStd) (size pkWOTSnt) rootsntp pkWOTSlp sigclp leaveslp /\ O_MEUFGCMA_WOTSC_Default.qs = (cube_records R.ad R.ml R.rootstd R.pkWOTStd R.sigWOTStd ++ layer_records R.ad (size R.pkWOTStd) rootsntp pkWOTSnt sigcnt) ++ tree_records R.ad (size R.pkWOTStd) (size pkWOTSnt) rootsntp pkWOTSlp sigclp /\ size pkWOTSlp = l').
      + while (R.ad = adz /\ O_MEUFGCMA_WOTSC_Default.ps = ps0 /\ FC.O_THFC_Default.pp = ps0 /\ cube_good ps0 R.ad R.ml R.pkWOTStd R.sigWOTStd R.leavestd R.rootstd /\ size R.pkWOTStd < d /\ rootsntp = last R.ml R.rootstd /\ layer_good ps0 R.ad (size R.pkWOTStd) rootsntp pkWOTSnt sigcnt leavesnt rootsnt /\ size pkWOTSnt < nr_trees (size R.pkWOTStd) /\ tree_good ps0 R.ad (size R.pkWOTStd) (size pkWOTSnt) rootsntp pkWOTSlp sigclp leaveslp /\ O_MEUFGCMA_WOTSC_Default.qs = (cube_records R.ad R.ml R.rootstd R.pkWOTStd R.sigWOTStd ++ layer_records R.ad (size R.pkWOTStd) rootsntp pkWOTSnt sigcnt) ++ tree_records R.ad (size R.pkWOTStd) (size pkWOTSnt) rootsntp pkWOTSlp sigclp).
    + wp; inline FC.O_THFC_Default.query; wp.
      exists* O_MEUFGCMA_WOTSC_Default.qs, R.ad, R.pkWOTStd, pkWOTSnt, pkWOTSlp, rootsntp;
        elim* => qs0 ad0 pks0 pknt0 pklp0 ms0.
      call (query_correct_spec ps0 qs0
        (WAddress.insubd (ht_chad ad0 (size pks0) (size pknt0) (size pklp0)))
        (nth witness ms0 (size pknt0*l'+size pklp0))).
      auto.
      move=> &hr [hbind [hinv hk]].
      have [#] hqs0 had0 hpks0 hpknt0 hpklp0 hms0 := hbind.
      have [#] ha hps hpp hc hl hrs hlg ht htg hq := hinv.
      subst qs0 ad0 pks0 pknt0 pklp0 ms0.
      split; first by rewrite /ht_chad; smt().
      move=> _ result qs [-> hcorrect].
      have hly : 0 <= size R.pkWOTStd{hr} < d by smt(size_ge0).
      have htr : 0 <= size pkWOTSnt{hr} < nr_trees (size R.pkWOTStd{hr}) by smt(size_ge0).
      have hkey : 0 <= size pkWOTSlp{hr} < l' by smt(size_ge0).
      have hw := cell_waddress (size R.pkWOTStd{hr}) (size pkWOTSnt{hr}) (size pkWOTSlp{hr}) hly htr hkey.
      rewrite -ha in hw.
      have hcorrect1 := hcorrect.
      rewrite hw in hcorrect1.
      rewrite hpp collection_pkco.
      have hnew := tree_good_append ps0 R.ad{hr} (size R.pkWOTStd{hr})
        (size pkWOTSnt{hr}) rootsntp{hr} pkWOTSlp{hr} sigclp{hr} leaveslp{hr}
        result.`1 result.`2
        (pkco ps0 (set_kpidx (set_typeidx (set_ltidx R.ad{hr} (size R.pkWOTStd{hr}) (size pkWOTSnt{hr})) pkcotype) (size pkWOTSlp{hr}))
          (flatten (map DigestBlock.val (DBLL.val result.`1))))
        htg hk hcorrect1 _.
      + by [].
      have hs : size pkWOTSlp{hr} = size sigclp{hr} by move: htg; rewrite /tree_good; smt().
      rewrite (tree_records_append R.ad{hr} (size R.pkWOTStd{hr}) (size pkWOTSnt{hr})
        rootsntp{hr} pkWOTSlp{hr} sigclp{hr} result.`1 result.`2 hs) hw hq.
      rewrite !rcons_cat; by smt(catA).
        by auto; smt(empty_tree_good empty_tree_records cats0).
      wp; while (R.ad = adz /\ O_MEUFGCMA_WOTSC_Default.ps = ps0 /\ FC.O_THFC_Default.pp = ps0 /\ cube_good ps0 R.ad R.ml R.pkWOTStd R.sigWOTStd R.leavestd R.rootstd /\ size R.pkWOTStd < d /\ rootsntp = last R.ml R.rootstd /\ layer_good ps0 R.ad (size R.pkWOTStd) rootsntp pkWOTSnt sigcnt leavesnt rootsnt /\ size pkWOTSnt < nr_trees (size R.pkWOTStd) /\ tree_good ps0 R.ad (size R.pkWOTStd) (size pkWOTSnt) rootsntp pkWOTSlp sigclp leaveslp /\ O_MEUFGCMA_WOTSC_Default.qs = (cube_records R.ad R.ml R.rootstd R.pkWOTStd R.sigWOTStd ++ layer_records R.ad (size R.pkWOTStd) rootsntp pkWOTSnt sigcnt) ++ tree_records R.ad (size R.pkWOTStd) (size pkWOTSnt) rootsntp pkWOTSlp sigclp /\ size pkWOTSlp = l' /\ nodes_good ps0 (set_typeidx (set_ltidx R.ad (size R.pkWOTStd) (size pkWOTSnt)) trhxtype) leaveslp nodes).
      + wp; while (R.ad = adz /\ O_MEUFGCMA_WOTSC_Default.ps = ps0 /\ FC.O_THFC_Default.pp = ps0 /\ cube_good ps0 R.ad R.ml R.pkWOTStd R.sigWOTStd R.leavestd R.rootstd /\ size R.pkWOTStd < d /\ rootsntp = last R.ml R.rootstd /\ layer_good ps0 R.ad (size R.pkWOTStd) rootsntp pkWOTSnt sigcnt leavesnt rootsnt /\ size pkWOTSnt < nr_trees (size R.pkWOTStd) /\ tree_good ps0 R.ad (size R.pkWOTStd) (size pkWOTSnt) rootsntp pkWOTSlp sigclp leaveslp /\ O_MEUFGCMA_WOTSC_Default.qs = (cube_records R.ad R.ml R.rootstd R.pkWOTStd R.sigWOTStd ++ layer_records R.ad (size R.pkWOTStd) rootsntp pkWOTSnt sigcnt) ++ tree_records R.ad (size R.pkWOTStd) (size pkWOTSnt) rootsntp pkWOTSlp sigclp /\ size pkWOTSlp = l' /\ nodes_good ps0 (set_typeidx (set_ltidx R.ad (size R.pkWOTStd) (size pkWOTSnt)) trhxtype) leaveslp nodes /\ size nodes < h' /\ nodespl = last leaveslp nodes /\ size nodescl <= nr_nodesx (size nodes+1) /\ (forall j, 0 <= j < size nodescl => nth witness nodescl j = subtree ps0 (set_typeidx (set_ltidx R.ad (size R.pkWOTStd) (size pkWOTSnt)) trhxtype) leaveslp (size nodes+1) j)).
        - inline FC.O_THFC_Default.query; auto => />.
          smt(row_append).
        auto => />.
        move=> &hr _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ hnsize hnodes hnlt.
        split; first by split; [apply nodes_nonnegative | smt()].
        move=> row hstop hbound hrow.
        rewrite size_rcons; split; first by smt().
        move=> height j hh hlt hj hjlt; rewrite nth_rcons.
        case (height < size nodes{hr}) => hp; first by apply hnodes; smt().
        have he : height = size nodes{hr} by smt().
        rewrite he /=; apply hrow; smt().
      auto; move=> &hr hpre; split; first by smt(nodes_empty).
      move=> ns hstop hinv.
      have [#] ha hps hpp hc hl hrs hlg ht htg hq hwidth hn := hinv.
      have hsize : size leaveslp{hr} = l' by move: htg; rewrite /tree_good; smt().
      have hnlen : size ns = h' by move: hn; rewrite /nodes_good; smt().
      have hroot := nodes_complete ps0
        (set_typeidx (set_ltidx R.ad{hr} (size R.pkWOTStd{hr}) (size pkWOTSnt{hr})) trhxtype)
        leaveslp{hr} ns hsize hn hnlen.
      have hnew := layer_good_append ps0 R.ad{hr} (size R.pkWOTStd{hr}) rootsntp{hr}
        pkWOTSnt{hr} sigcnt{hr} leavesnt{hr} rootsnt{hr}
        pkWOTSlp{hr} sigclp{hr} leaveslp{hr}
        (nth witness (nth witness ns (h'-1)) 0) hlg ht htg hwidth hroot.
      have hs : size pkWOTSnt{hr} = size sigcnt{hr} by move: hlg; rewrite /layer_good; smt().
      rewrite /= (layer_records_append R.ad{hr} (size R.pkWOTStd{hr}) rootsntp{hr}
        pkWOTSnt{hr} sigcnt{hr} pkWOTSlp{hr} sigclp{hr} hs).
      rewrite hnew catA -hq; by smt().
    auto; smt(empty_layer_good empty_layer_records cube_good_append cube_records_append cats0).
  wp; call (_ : FC.O_THFC_Default.pp = ps0).
  + by proc; auto.
  auto => />; rewrite /cube_good /cube_records /=; smt(ge1_d mkseq0).
qed.
end section.
