(* A consistent complete cube and an accepted public transcript imply acceptance of every recorded leaf query. *)
require import AllCore List Distr C10WOTSCorrect WOTS_C_Scheme C10BoundedMA GFailCharged IntDiv BinaryTrees MerkleTrees C10HypertreeCorrect C10HypertreeCoverage XmssmtCC_All.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES WOTS_C_Real WOTS_C_Scheme WOTS_C_Interactive.

type record = adrs * dgstblock * pkWOTS * (sigWOTS * cntr).
op query_correct (ps : pseed) (q : record) =
  valid_wadrs q.`1 /\ q.`4.`2 = grindC ps q.`1 q.`2 /\
  recovered_key q.`4.`1 ps q.`1 (encode_msgWOTS_C ps q.`1 q.`2 q.`4.`2) = q.`3.

lemma keygen_functional pinit ainit :
  hoare[WOTS_C_ES.keygen : ps = pinit /\ ad = ainit ==>
    res.`1 = (public_key res.`2.`1 pinit ainit,pinit,ainit) /\
    res.`2.`2 = pinit /\ res.`2.`3 = ainit].
proof.
  proc; inline WOTS_TW_ES_NPRF.keygen.
  seq 3 : (ps = pinit /\ ad = ainit /\ ps0 = pinit /\ ad0 = ainit).
  + by auto.
  exists* skWOTS; elim* => sk0.
  by wp; call (public_key_spec sk0 pinit ainit); auto.
qed.

lemma query_correct_spec ps0 qs0 wad0 m0 :
  hoare[O_MEUFGCMA_WOTSC_Default.query :
    O_MEUFGCMA_WOTSC_Default.ps = ps0 /\ O_MEUFGCMA_WOTSC_Default.qs = qs0 /\
    wad = wad0 /\ m = m0 ==>
    O_MEUFGCMA_WOTSC_Default.qs = rcons qs0 (WAddress.val wad0,m0,res.`1,res.`2) /\
    query_correct ps0 (WAddress.val wad0,m0,res.`1,res.`2)].
proof.
  proc; seq 1 : (O_MEUFGCMA_WOTSC_Default.ps = ps0 /\ O_MEUFGCMA_WOTSC_Default.qs = qs0 /\
    wad = wad0 /\ m = m0 /\
    pk = (public_key sk.`1 ps0 (WAddress.val wad0),ps0,WAddress.val wad0) /\
    sk.`2 = ps0 /\ sk.`3 = WAddress.val wad0).
  + by call (keygen_functional ps0 (WAddress.val wad0)); auto.
  wp; exists* sk; elim* => sk0.
  call (signature_spec sk0 m0).
  auto => />; rewrite /query_correct /=; smt(recover_signature WAddress.valP).
qed.

lemma query_preserves_correct :
  hoare[O_MEUFGCMA_WOTSC_Default.query :
    all (query_correct O_MEUFGCMA_WOTSC_Default.ps) O_MEUFGCMA_WOTSC_Default.qs ==>
    all (query_correct O_MEUFGCMA_WOTSC_Default.ps) O_MEUFGCMA_WOTSC_Default.qs].
proof.
  proc*; exists* O_MEUFGCMA_WOTSC_Default.ps, O_MEUFGCMA_WOTSC_Default.qs, wad, m;
    elim* => ps0 qs0 wad0 m0.
  by call (query_correct_spec ps0 qs0 wad0 m0); auto; smt(allP mem_rcons).
qed.

lemma accepted_queries_no_failure ps qs :
  all (fun q : record => predC (ThC ps q.`1 q.`2 q.`4.`2)) qs =>
  !gfail_of ps qs.
proof.
  move=> hp; rewrite /gfail_of hasP.
  have hz : forall (q : record), q \in qs => !STCRC_WC.G.grind_fails ps q.`1 q.`2.
  + move=> q hq; have hacc : predC (ThC ps q.`1 q.`2 q.`4.`2) by smt(allP).
    rewrite STCRC_WC.G.grind_fails_iff; smt().
  smt().
qed.

type pkcube = pkWOTS list list list.
type sigcube = (sigWOTS * cntr) list list list.
type leafcube = dgstblock list list list.
type rootcube = dgstblock list list.

op msg_at (ml : dgstblock list) (roots : rootcube) (layer tree key : int) =
  if layer = 0 then nth witness ml (tree*l'+key)
  else nth witness (nth witness roots (layer-1)) (tree*l'+key).

op sig_at (sigs : sigcube) (layer tree key : int) = nth witness (nth witness (nth witness sigs layer) tree) key.
op leaves_at (ls : leafcube) (layer tree : int) = nth witness (nth witness ls layer) tree.
op root_at (rs : rootcube) (layer tree : int) = nth witness (nth witness rs layer) tree.
op pk_at (pks : pkcube) (layer tree key : int) = nth witness (nth witness (nth witness pks layer) tree) key.

op layer_signature ps ad (sigs : sigcube) (ls : leafcube) idx layer =
  let tk = path_cell idx layer in
  (sig_at sigs layer tk.`1 tk.`2,
   cons_ap_trh ps (set_typeidx (set_ltidx ad layer tk.`1) trhxtype)
     (list2tree (leaves_at ls layer tk.`1)) tk.`2).

op cube_path ps ad sigs ls idx = mkseq (layer_signature ps ad sigs ls idx) d.

op consistent_cube ps ad ml pks sigs ls rs =
  forall layer tree, 0 <= layer < d => 0 <= tree < nr_trees layer =>
    size (leaves_at ls layer tree) = l' /\
    root_at rs layer tree = val_bt_trh ps (set_typeidx (set_ltidx ad layer tree) trhxtype)
      (list2tree (leaves_at ls layer tree)) /\
    forall key, 0 <= key < l' =>
      nth witness (leaves_at ls layer tree) key =
        pkco ps (set_kpidx (set_typeidx (set_ltidx ad layer tree) pkcotype) key)
          (flatten (map DigestBlock.val (DBLL.val (pk_at pks layer tree key)))) /\
      recovered_key (sig_at sigs layer tree key).`1 ps (ht_chad ad layer tree key)
        (encode_msgWOTS_C ps (ht_chad ad layer tree key) (msg_at ml rs layer tree key)
          (sig_at sigs layer tree key).`2) = pk_at pks layer tree key.

lemma cube_layer_step ps ad ml pks sigs ls rs idx layer good :
  consistent_cube ps ad ml pks sigs ls rs =>
  0 <= layer < d =>
  0 <= (path_cell idx layer).`1 < nr_trees layer =>
  0 <= (path_cell idx layer).`2 < l' =>
  path_step ps ad
    (remaining_idx idx layer,
     msg_at ml rs layer (path_cell idx layer).`1 (path_cell idx layer).`2, good,layer)
    (layer_signature ps ad sigs ls idx layer) =
  ((path_cell idx layer).`1, root_at rs layer (path_cell idx layer).`1,
    good /\ predC (ThC ps (ht_chad ad layer (path_cell idx layer).`1 (path_cell idx layer).`2)
      (msg_at ml rs layer (path_cell idx layer).`1 (path_cell idx layer).`2)
      (sig_at sigs layer (path_cell idx layer).`1 (path_cell idx layer).`2).`2),layer+1).
proof.
  move=> hc hl ht hk.
  have hr : edivz (remaining_idx idx layer) l' = path_cell idx layer.
  + rewrite /remaining_idx /path_cell.
    have h01 : layer = 0 \/ layer = 1 by move: hl; rewrite d_val; smt().
    by case: h01 => ->.
  have [#] hsize hroot hkeys := hc layer (path_cell idx layer).`1 hl ht.
  have [hleaf hpk] := hkeys (path_cell idx layer).`2 hk.
  rewrite /path_step /layer_signature /= hr /= hpk -hleaf.
  by rewrite (constructed_path_correct ps
    (set_typeidx (set_ltidx ad layer (path_cell idx layer).`1) trhxtype)
    (leaves_at ls layer (path_cell idx layer).`1) (path_cell idx layer).`2 hsize hk) -hroot.
qed.

op cell_accept ps ad ml sigs rs layer tree key =
  predC (ThC ps (ht_chad ad layer tree key) (msg_at ml rs layer tree key)
    (sig_at sigs layer tree key).`2).

lemma path_cell_ranges idx layer :
  0 <= idx < l => 0 <= layer < d =>
  0 <= (path_cell idx layer).`1 < nr_trees layer /\
  0 <= (path_cell idx layer).`2 < l'.
proof.
  move=> hi hl; rewrite tree_count 1:hl /path_cell subtree_width.
  move: hi hl; rewrite ht_capacity d_val => hi hl.
  case (layer = 0) => h0 /=.
  + smt(divz_ge0 ltz_divLR modz_ge0 ltz_pmod).
  smt(divz_ge0 ltz_divLR modz_ge0 ltz_pmod).
qed.

lemma cube_path_predicate ps ad ml pks sigs ls rs idx :
  consistent_cube ps ad ml pks sigs ls rs => 0 <= idx < l =>
  (path_result ps ad (nth witness ml idx) idx (cube_path ps ad sigs ls idx)).`3 =
    (cell_accept ps ad ml sigs rs 0 (path_cell idx 0).`1 (path_cell idx 0).`2 /\
     cell_accept ps ad ml sigs rs 1 (path_cell idx 1).`1 (path_cell idx 1).`2).
proof.
  move=> hc hi.
  have h0 : 0 <= 0 < d by rewrite d_val.
  have h1 : 0 <= 1 < d by rewrite d_val.
  have [ht0 hk0] := path_cell_ranges idx 0 hi h0.
  have [ht1 hk1] := path_cell_ranges idx 1 hi h1.
  have hm0 : msg_at ml rs 0 (path_cell idx 0).`1 (path_cell idx 0).`2 = nth witness ml idx.
  + rewrite /msg_at /path_cell /=; congr; smt(edivzP).
  have hm1 : msg_at ml rs 1 (path_cell idx 1).`1 (path_cell idx 1).`2 = root_at rs 0 (path_cell idx 0).`1.
  + rewrite /msg_at /path_cell /root_at /=; congr; smt(edivzP).
  have hs0 := cube_layer_step ps ad ml pks sigs ls rs idx 0 true hc h0 ht0 hk0.
  rewrite /remaining_idx /= hm0 in hs0.
  have hs1 := cube_layer_step ps ad ml pks sigs ls rs idx 1
    (cell_accept ps ad ml sigs rs 0 (path_cell idx 0).`1 (path_cell idx 0).`2)
    hc h1 ht1 hk1.
  rewrite /remaining_idx /= hm1 in hs1.
  have hp : cube_path ps ad sigs ls idx =
    [layer_signature ps ad sigs ls idx 0;layer_signature ps ad sigs ls idx 1].
  + by rewrite /cube_path d_val (_ : 2 = 1+1) 1:// mkseqS 1://
      (_ : 1 = 0+1) 1:// mkseqS 1:// mkseq0 /=.
  rewrite /path_result hp /= hs0 /=.
  have he : (path_cell idx 0).`1 = idx %/ l' by rewrite /path_cell.
  rewrite /cell_accept in hs1.
  rewrite /cell_accept.
  smt().
qed.

lemma accepted_paths_cover_queries ps ad ml pks sigs ls rs :
  consistent_cube ps ad ml pks sigs ls rs =>
  good_transcript (root_at rs (d-1) 0,ps,ad) ml
    (mkseq (cube_path ps ad sigs ls) l) =>
  forall layer tree key, 0 <= layer < d => 0 <= tree < nr_trees layer => 0 <= key < l' =>
    cell_accept ps ad ml sigs rs layer tree key.
proof.
  move=> hc hg; apply all_paths_cover_cube => idx layer hi hl.
  have [hs hp] := hg.
  have [hz ha] := hp idx hi.
  rewrite nth_mkseq 1:hi /= in ha.
  have he := cube_path_predicate ps ad ml pks sigs ls rs idx hc hi.
  have h01 : layer = 0 \/ layer = 1 by move: hl; rewrite d_val; smt().
  by case: h01 => ->; smt().
qed.

lemma accepted_cube_no_failure ps ad ml pks sigs ls rs qs :
  consistent_cube ps ad ml pks sigs ls rs =>
  good_transcript (root_at rs (d-1) 0,ps,ad) ml
    (mkseq (cube_path ps ad sigs ls) l) =>
  (forall q, q \in qs => exists layer tree key,
    0 <= layer < d /\ 0 <= tree < nr_trees layer /\ 0 <= key < l' /\
    q = (ht_chad ad layer tree key,msg_at ml rs layer tree key,
      pk_at pks layer tree key,sig_at sigs layer tree key)) =>
  !GFailCharged.gfail_of ps qs.
proof.
  move=> hc hg hq; apply accepted_queries_no_failure; rewrite allP => q hmem.
  have [layer tree key hcell] := hq q hmem.
  have hl : 0 <= layer < d by smt().
  have ht : 0 <= tree < nr_trees layer by smt().
  have hk : 0 <= key < l' by smt().
  have he : q = (ht_chad ad layer tree key,msg_at ml rs layer tree key,
      pk_at pks layer tree key,sig_at sigs layer tree key) by smt().
  rewrite he /=.
  exact (accepted_paths_cover_queries ps ad ml pks sigs ls rs hc hg layer tree key hl ht hk).
qed.
