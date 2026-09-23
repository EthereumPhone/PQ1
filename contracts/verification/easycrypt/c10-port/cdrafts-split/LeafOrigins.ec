(* The retained initial leaf hashes in the actual FORS catalog. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeCatalog PersistentGrind AcceptedContexts.

op leaf_origins (h : (raw_input,digest) fmap)
    (f : int -> raw_input -> raw_input) (c : node_catalog) =
  forall index value, c.[(0,index)] = Some value =>
    exists secret d, size secret = 16 /\ h.[f index secret] = Some d /\ value = node d.

lemma leaf_origins_empty h f : leaf_origins h f empty.
proof. rewrite /leaf_origins; smt(emptyE). qed.

lemma leaf_origins_history_extends h h' f c :
  extends h h' => leaf_origins h f c => leaf_origins h' f c.
proof.
  rewrite /extends /leaf_origins => he ho index value hc.
  have [secret d [hw [hd hv]]] := ho index value hc.
  exists secret d; smt(domE).
qed.

lemma leaf_origins_parent h f c height parent value :
  0 < height => leaf_origins h f c =>
  leaf_origins h f c.[(height,parent) <- value].
proof.
  rewrite /leaf_origins => hh ho index leaf hc.
  have hc' : c.[(0,index)] = Some leaf by move: hc; rewrite get_setE; smt().
  exact (ho index leaf hc').
qed.

lemma leaf_origins_leaf h f c index secret d :
  leaf_origins h f c => size secret = 16 => h.[f index secret] = Some d =>
  leaf_origins h f c.[(0,index) <- node d].
proof.
  rewrite /leaf_origins => ho hw hd index' value.
  rewrite get_setE /=; case (index' = index) => he.
  + rewrite ?he /=; move=> hv; exists secret d; smt().
  rewrite ?he /=; apply ho.
qed.

require import NodeCatalogDomain.

lemma catalog_target_origin h f c total target :
  0 <= total => 0 <= target < 2^total =>
  catalog_exact c (2^total) => leaf_origins h f c =>
  exists secret d, size secret = 16 /\
    h.[f target secret] = Some d /\ catalog_grid c 0 target = node d.
proof.
  move=> hh ht hc ho.
  have hd := node_due_range total 0 target _ _; first 2 by smt().
  have hm : (0,target) \in c by apply hc.
  have he : c.[(0,target)] = Some (catalog_grid c 0 target)
    by rewrite /catalog_grid; smt(get_some).
  exact (ho target (catalog_grid c 0 target) he).
qed.
