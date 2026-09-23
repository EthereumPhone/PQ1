(* Bottom-up tree construction, cube consistency, and exact leaf-query accounting facts. *)
require import AllCore List IntDiv StdOrder BinaryTrees MerkleTrees XmssmtCC_All C10CubeCorrect C10WOTSCorrect.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES IntOrder WOTS_C_Real WOTS_C_Scheme.

op subtree ps ad (leaves : dgstblock list) height index =
  val_bt_trh_gen ps ad
    (list2tree (take (2^height) (drop (index * 2^height) leaves))) height index.

lemma subtree_leaf ps ad (leaves : dgstblock list) j :
  0 <= j < size leaves => subtree ps ad leaves 0 j = nth witness leaves j.
proof.
  by move=> hj; rewrite /subtree expr0 /= (_ : 1 = 0+1) 1://
    (take_nth witness) 1:size_drop 1:/# 1:/# take0 /= list2tree1
    /val_bt_trh_gen /= nth_drop 1:/# /=.
qed.

op nodes_good ps ad leaves (nodes : dgstblock list list) =
  size nodes <= h' /\ forall height j, 0 <= height < size nodes =>
    0 <= j < nr_nodesx (height+1) =>
    nth witness (nth witness nodes height) j = subtree ps ad leaves (height+1) j.

lemma nodes_input ps ad leaves nodes j :
  size leaves = l' => nodes_good ps ad leaves nodes => size nodes < h' =>
  0 <= j < nr_nodesx (size nodes) =>
  nth witness (last leaves nodes) j = subtree ps ad leaves (size nodes) j.
proof.
  move=> hs [hn hc] hb hj; rewrite -nth_last.
  case (size nodes = 0) => hz.
  + rewrite hz /= (nth_out leaves nodes) 1:/# eq_sym; apply subtree_leaf.
    by move: hj; rewrite hz /nr_nodesx /= -/l' -hs.
  have hh : 0 <= size nodes-1 < size nodes by smt(size_ge0).
  rewrite (nth_change_dfl witness leaves) 1:hh.
  have he : size nodes-1+1 = size nodes by ring.
  have hj' : 0 <= j < nr_nodesx (size nodes-1+1) by rewrite he.
  have hx := hc (size nodes-1) j hh hj'.
  by rewrite he in hx.
qed.

lemma nodes_append ps ad leaves nodes row :
  nodes_good ps ad leaves nodes => size nodes < h' =>
  (forall j, 0 <= j < nr_nodesx (size nodes+1) =>
    nth witness row j = subtree ps ad leaves (size nodes+1) j) =>
  nodes_good ps ad leaves (rcons nodes row).
proof.
  rewrite /nodes_good; move=> [hb hc] hn hr.
  rewrite size_rcons; split; first by smt().
  move=> height j hh hj; case (height < size nodes) => hlt.
  + by rewrite nth_rcons hlt; smt().
  have he : height = size nodes by smt().
  rewrite he nth_rcons; smt().
qed.

lemma subtree_node ps ad (leaves : dgstblock list) height j :
  0 <= height => 0 <= j => 2*(j+1)*2^height <= size leaves =>
  subtree ps ad leaves (height+1) j =
    trh ps (set_thtbidx ad (height+1) j)
      (DigestBlock.val (subtree ps ad leaves height (2*j)) ++
       DigestBlock.val (subtree ps ad leaves height (2*j+1))).
proof.
  move=> hh hj hb.
  have hp : 0 < 2^height by apply expr_gt0.
  have he : 2^(height+1) = 2^height + 2^height.
  + by rewrite exprD_nneg 1:hh // expr1; ring.
  rewrite /subtree he take_take_drop_cat 1,2:/# drop_drop 1,2:/#.
  rewrite (list2treeS height) 1:hh.
  + by rewrite size_take 1:/# size_drop 1:/#; smt().
  + by rewrite size_take 1:/# size_drop 1:/#; smt().
  rewrite /val_bt_trh_gen /trhi /updhbidx /=.
  have he0 : j*(2^height+2^height) = 2*j*2^height by ring.
  have he1 : 2^height+2*j*2^height = (2*j+1)*2^height by ring.
  by rewrite he0 he1.
qed.

lemma subtree_top ps ad (leaves : dgstblock list) :
  size leaves = l' => subtree ps ad leaves h' 0 = val_bt_trh ps ad (list2tree leaves).
proof.
  move=> hs; rewrite /subtree /val_bt_trh_gen /val_bt_trh /=.
  have ht : take (2^h') leaves = leaves by rewrite -/l' -hs take_size.
  by rewrite drop0 ht.
qed.

lemma node_capacity height j :
  0 <= height < h' => 0 <= j < nr_nodesx (height+1) =>
  2*(j+1)*2^height <= l'.
proof.
  move=> hh hj.
  have hp : 0 < 2^height by apply expr_gt0.
  have he : l' = 2 * nr_nodesx (height+1) * 2^height.
  + have he0 : h' = (height+1)+(h'-(height+1)) by ring.
    have he1 : 2^(height+1) = 2*2^height by rewrite exprS 1:/#; ring.
    rewrite /l' {1}he0 exprD_nneg 1:/# 1:/# he1 /nr_nodesx; ring.
  rewrite he; smt().
qed.

lemma nodes_nonnegative height : 0 <= nr_nodesx height.
proof. by rewrite /nr_nodesx; apply expr_ge0. qed.

lemma child_ranges height j :
  0 <= height < h' => 0 <= j < nr_nodesx (height+1) =>
  0 <= 2*j < nr_nodesx height /\ 0 <= 2*j+1 < nr_nodesx height.
proof.
  move=> hh hj.
  have he : nr_nodesx height = 2*nr_nodesx (height+1).
  + have hx : h'-height = (h'-(height+1))+1 by ring.
    by rewrite /nr_nodesx hx exprS 1:/#; ring.
  rewrite he; smt().
qed.

lemma node_step ps ad leaves nodes j :
  size leaves = l' => nodes_good ps ad leaves nodes => size nodes < h' =>
  0 <= j < nr_nodesx (size nodes+1) =>
  thfc (size (DigestBlock.val (nth witness (last leaves nodes) (2*j)) ++
    DigestBlock.val (nth witness (last leaves nodes) (2*j+1)))) ps
    (set_thtbidx ad (size nodes+1) j)
    (DigestBlock.val (nth witness (last leaves nodes) (2*j)) ++
     DigestBlock.val (nth witness (last leaves nodes) (2*j+1))) =
  subtree ps ad leaves (size nodes+1) j.
proof.
  move=> hs hn hb hj.
  have hh : 0 <= size nodes < h' by smt(size_ge0).
  have [hl hr] := child_ranges (size nodes) j hh hj.
  rewrite (nodes_input ps ad leaves nodes (2*j) hs hn hb hl)
    (nodes_input ps ad leaves nodes (2*j+1) hs hn hb hr).
  have hc := node_capacity (size nodes) j hh hj.
  rewrite -hs in hc.
  rewrite (subtree_node ps ad leaves (size nodes) j) 1:size_ge0 1:/# 1:hc
    /trh size_cat !DigestBlock.valP.
  congr; ring.
qed.

lemma row_append ps ad leaves nodes row :
  size leaves = l' => nodes_good ps ad leaves nodes => size nodes < h' =>
  size row < nr_nodesx (size nodes+1) =>
  (forall j, 0 <= j < size row => nth witness row j = subtree ps ad leaves (size nodes+1) j) =>
  let node = thfc (size (DigestBlock.val (nth witness (last leaves nodes) (2*size row)) ++
    DigestBlock.val (nth witness (last leaves nodes) (2*size row+1)))) ps
    (set_thtbidx ad (size nodes+1) (size row))
    (DigestBlock.val (nth witness (last leaves nodes) (2*size row)) ++
     DigestBlock.val (nth witness (last leaves nodes) (2*size row+1))) in
  size (rcons row node) <= nr_nodesx (size nodes+1) /\
  forall j, 0 <= j < size (rcons row node) =>
    nth witness (rcons row node) j = subtree ps ad leaves (size nodes+1) j.
proof.
  move=> hs hn hb hr hc.
  have hj : 0 <= size row < nr_nodesx (size nodes+1) by smt(size_ge0).
  rewrite (node_step ps ad leaves nodes (size row) hs hn hb hj) /= size_rcons.
  split; first by smt().
  move=> j hj'; rewrite nth_rcons; case (j < size row) => hlt; smt().
qed.

lemma nodes_empty ps ad leaves : nodes_good ps ad leaves [].
proof. rewrite /nodes_good /=; smt(ge1_hp). qed.

lemma nodes_complete ps ad leaves nodes :
  size leaves = l' => nodes_good ps ad leaves nodes => size nodes = h' =>
  nth witness (nth witness nodes (h'-1)) 0 = val_bt_trh ps ad (list2tree leaves).
proof.
  move=> hs [hb hc] hn.
  have hh : 0 <= h'-1 < size nodes by smt(ge1_hp).
  have hj : 0 <= 0 < nr_nodesx (h'-1+1) by rewrite /nr_nodesx /= expr0.
  have he := hc (h'-1) 0 hh hj.
  rewrite (_ : h'-1+1 = h') 1:/# in he.
  by rewrite he subtree_top.
qed.

lemma cell_waddress layer tree key :
  0 <= layer < d => 0 <= tree < nr_trees layer => 0 <= key < l' =>
  WAddress.val (WAddress.insubd (ht_chad adz layer tree key)) = ht_chad adz layer tree key.
proof.
  move=> hl ht hk; apply WAddress.insubdK.
  rewrite /ht_chad; apply validxadrs_validwadrs_setallboch.
  + exact valx_adz.
  + by rewrite /valid_lidx.
  + by rewrite /valid_tidx.
  by rewrite /valid_kpidx.
qed.

lemma collection_pkco ps ad pk :
  thfc (size (flatten (map DigestBlock.val (DBLL.val pk)))) ps ad
    (flatten (map DigestBlock.val (DBLL.val pk))) =
  pkco ps ad (flatten (map DigestBlock.val (DBLL.val pk))).
proof. by rewrite size_pkco_input /pkco. qed.

op cell_record ad layer tree (source : dgstblock list)
    (pks : pkWOTS list) (sigs : (sigWOTS * cntr) list) key : record =
  (ht_chad ad layer tree key, nth witness source (tree*l'+key),
    nth witness pks key,nth witness sigs key).

op tree_records ad layer tree source pks sigs =
  mkseq (cell_record ad layer tree source pks sigs) (size pks).

op layer_records ad layer source (pks : pkWOTS list list) (sigs : (sigWOTS * cntr) list list) =
  flatten (mkseq (fun tree => tree_records ad layer tree source
    (nth witness pks tree) (nth witness sigs tree)) (size pks)).

op layer_source (ml : dgstblock list) (roots : rootcube) layer =
  if layer = 0 then ml else nth witness roots (layer-1).

op cube_records ad ml (roots : rootcube) (pks : pkcube) (sigs : sigcube) =
  flatten (mkseq (fun layer => layer_records ad layer (layer_source ml roots layer)
    (nth witness pks layer) (nth witness sigs layer)) (size pks)).

op tree_good ps ad layer tree source (pks : pkWOTS list)
    (sigs : (sigWOTS * cntr) list) (leaves : dgstblock list) =
  size pks = size sigs /\ size pks = size leaves /\ size pks <= l' /\
  forall key, 0 <= key < size pks =>
    query_correct ps (cell_record ad layer tree source pks sigs key) /\
    nth witness leaves key =
      pkco ps (set_kpidx (set_typeidx (set_ltidx ad layer tree) pkcotype) key)
        (flatten (map DigestBlock.val (DBLL.val (nth witness pks key)))).

op layer_good ps ad layer source (pks : pkWOTS list list)
    (sigs : (sigWOTS * cntr) list list) (leaves : dgstblock list list) (roots : dgstblock list) =
  size pks = size sigs /\ size pks = size leaves /\ size pks = size roots /\
  size pks <= nr_trees layer /\ forall tree, 0 <= tree < size pks =>
    tree_good ps ad layer tree source (nth witness pks tree)
      (nth witness sigs tree) (nth witness leaves tree) /\
    size (nth witness pks tree) = l' /\
    nth witness roots tree = val_bt_trh ps (set_typeidx (set_ltidx ad layer tree) trhxtype)
      (list2tree (nth witness leaves tree)).

op cube_good ps ad ml (pks : pkcube) (sigs : sigcube) (leaves : leafcube) (roots : rootcube) =
  size pks = size sigs /\ size pks = size leaves /\ size pks = size roots /\
  size pks <= d /\ forall layer, 0 <= layer < size pks =>
    layer_good ps ad layer (layer_source ml roots layer) (nth witness pks layer)
      (nth witness sigs layer) (nth witness leaves layer) (nth witness roots layer) /\
    size (nth witness pks layer) = nr_trees layer.

lemma tree_records_append ad layer tree source pks sigs pk sigc :
  size pks = size sigs =>
  tree_records ad layer tree source (rcons pks pk) (rcons sigs sigc) =
    rcons (tree_records ad layer tree source pks sigs)
      (ht_chad ad layer tree (size pks),nth witness source (tree*l'+size pks),pk,sigc).
proof.
  move=> hs; rewrite /tree_records size_rcons mkseqS 1:size_ge0.
  congr.
  + apply eq_in_mkseq => key hk; rewrite /cell_record; smt(nth_rcons).
  by rewrite /cell_record !nth_rcons; smt(size_ge0).
qed.

lemma layer_records_append ad layer source pks sigs pk sigc :
  size pks = size sigs =>
  layer_records ad layer source (rcons pks pk) (rcons sigs sigc) =
    layer_records ad layer source pks sigs ++ tree_records ad layer (size pks) source pk sigc.
proof.
  move=> hs; rewrite /layer_records size_rcons mkseqS 1:size_ge0 flatten_rcons.
  congr.
  + congr; apply eq_in_mkseq => tree ht; smt(nth_rcons).
  by rewrite /= !nth_rcons; smt(size_ge0).
qed.

lemma layer_good_append ps ad layer source pks sigs leaves roots pk sigc leaf root :
  layer_good ps ad layer source pks sigs leaves roots => size pks < nr_trees layer =>
  tree_good ps ad layer (size pks) source pk sigc leaf => size pk = l' =>
  root = val_bt_trh ps (set_typeidx (set_ltidx ad layer (size pks)) trhxtype) (list2tree leaf) =>
  layer_good ps ad layer source (rcons pks pk) (rcons sigs sigc) (rcons leaves leaf) (rcons roots root).
proof.
  rewrite /layer_good; move=> [#] hs hl hr hb hc hn ht hp he.
  rewrite !size_rcons; do 4! (split; first by smt()).
  move=> tree hh; case (tree < size pks) => hlt.
  + by rewrite !nth_rcons; smt().
  have heq : tree = size pks by smt().
  rewrite heq !nth_rcons; smt(size_ge0).
qed.

lemma source_append ml roots root layer :
  0 <= layer <= size roots =>
  layer_source ml (rcons roots root) layer = layer_source ml roots layer.
proof. by rewrite /layer_source => hl; case (layer = 0) => //; smt(nth_rcons). qed.

lemma source_last ml roots : layer_source ml roots (size roots) = last ml roots.
proof.
  rewrite /layer_source -nth_last; case (size roots = 0) => he.
  + by rewrite he /= nth_out 1:/#.
  smt(nth_change_dfl size_ge0).
qed.

lemma cube_records_append ad ml roots pks sigs root pk sigc :
  size pks = size sigs => size pks = size roots =>
  cube_records ad ml (rcons roots root) (rcons pks pk) (rcons sigs sigc) =
    cube_records ad ml roots pks sigs ++
    layer_records ad (size pks) (last ml roots) pk sigc.
proof.
  move=> hs hr; rewrite /cube_records size_rcons mkseqS 1:size_ge0 flatten_rcons.
  congr.
  + congr; apply eq_in_mkseq => layer hl.
    rewrite /= source_append 1:/#; smt(nth_rcons).
  rewrite /= source_append 1:/# hr source_last !nth_rcons; smt(size_ge0).
qed.

lemma cube_good_append ps ad ml pks sigs leaves roots pk sigc leaf root :
  cube_good ps ad ml pks sigs leaves roots => size pks < d =>
  layer_good ps ad (size pks) (last ml roots) pk sigc leaf root =>
  size pk = nr_trees (size pks) =>
  cube_good ps ad ml (rcons pks pk) (rcons sigs sigc) (rcons leaves leaf) (rcons roots root).
proof.
  rewrite /cube_good; move=> [#] hs hl hr hb hc hn ht hp.
  rewrite !size_rcons; do 4! (split; first by smt()).
  move=> layer hh; rewrite source_append 1:/#.
  case (layer < size pks) => hlt.
  + by rewrite !nth_rcons; smt().
  have he : layer = size pks by smt().
  rewrite he !nth_rcons hr source_last; smt(size_ge0).
qed.

lemma tree_good_append ps ad layer tree source pks sigs leaves pk sigc leaf :
  tree_good ps ad layer tree source pks sigs leaves => size pks < l' =>
  query_correct ps (ht_chad ad layer tree (size pks),nth witness source (tree*l'+size pks),pk,sigc) =>
  leaf = pkco ps (set_kpidx (set_typeidx (set_ltidx ad layer tree) pkcotype) (size pks))
    (flatten (map DigestBlock.val (DBLL.val pk))) =>
  tree_good ps ad layer tree source (rcons pks pk) (rcons sigs sigc) (rcons leaves leaf).
proof.
  rewrite /tree_good /cell_record; move=> [#] hs hl hb hc hn hq hf.
  rewrite !size_rcons; split; first by smt().
  split; first by smt().
  split; first by smt().
  move=> key hk; case (key < size pks) => hlt.
  + by rewrite !nth_rcons; smt().
  have he : key = size pks by smt().
  rewrite he !nth_rcons; smt(size_ge0).
qed.

lemma empty_tree_good ps ad layer tree source : tree_good ps ad layer tree source [] [] [].
proof. rewrite /tree_good /=; smt(ge2_lp). qed.

lemma empty_tree_records ad layer tree source : tree_records ad layer tree source [] [] = [].
proof. by rewrite /tree_records /= mkseq0. qed.

lemma empty_layer_good ps ad layer source : layer_good ps ad layer source [] [] [] [].
proof. rewrite /layer_good /= /nr_trees; smt(expr_ge0). qed.

lemma empty_layer_records ad layer source : layer_records ad layer source [] [] = [].
proof. by rewrite /layer_records /= mkseq0. qed.

lemma completed_cube_consistent ps ad ml pks sigs leaves roots :
  cube_good ps ad ml pks sigs leaves roots => size pks = d =>
  consistent_cube ps ad ml pks sigs leaves roots.
proof.
  move=> hg hd; rewrite /consistent_cube => layer tree hly htr.
  rewrite /cube_good in hg.
  have [#] hs hl hr hb hc := hg.
  have hly' : 0 <= layer < size pks by rewrite hd.
  have [hgood htcount] := hc layer hly'.
  rewrite /layer_good in hgood.
  have [#] hts htl htrt htb htrees := hgood.
  have htr' : 0 <= tree < size (nth witness pks layer) by rewrite htcount.
  have [#] hleaf hwidth hroot := htrees tree htr'.
  rewrite /tree_good in hleaf.
  have [#] hks hkl hkb hkeys := hleaf.
  rewrite /leaves_at /root_at /pk_at /sig_at.
  split; first by smt().
  split; first exact hroot.
  move=> key hk.
  have hk' : 0 <= key < size (nth witness (nth witness pks layer) tree) by rewrite hwidth.
  have [hrecord hpk] := hkeys key hk'.
  rewrite hpk; split; first by [].
  move: hrecord; rewrite /query_correct /cell_record /layer_source /msg_at /=.
  case (layer = 0); smt().
qed.

lemma completed_cube_records ps ad ml pks sigs leaves roots q :
  cube_good ps ad ml pks sigs leaves roots => size pks = d =>
  q \in cube_records ad ml roots pks sigs => exists layer tree key,
    0 <= layer < d /\ 0 <= tree < nr_trees layer /\ 0 <= key < l' /\
    q = (ht_chad ad layer tree key,msg_at ml roots layer tree key,
      pk_at pks layer tree key,sig_at sigs layer tree key).
proof.
  move=> hg hd.
  rewrite /cube_good in hg.
  have [#] hs hl hr hb hc := hg.
  rewrite /cube_records -flattenP => -[lr [/mkseqP [layer [hly ->]]] hq].
  rewrite /layer_records -flattenP in hq.
  have [tr [/mkseqP [tree [htr ->]]] hq'] := hq.
  rewrite /tree_records mkseqP in hq'.
  have [key [hk hq'']] := hq'.
  have [hlgood htcount] := hc layer hly.
  rewrite /layer_good in hlgood.
  have [#] hts htl htrt htb htrees := hlgood.
  have [#] hleaf hwidth hroot := htrees tree htr.
  exists layer tree key.
  rewrite /cell_record /pk_at /sig_at /msg_at /layer_source in hq''.
  rewrite /pk_at /sig_at /msg_at /layer_source.
  case (layer = 0); smt().
qed.
