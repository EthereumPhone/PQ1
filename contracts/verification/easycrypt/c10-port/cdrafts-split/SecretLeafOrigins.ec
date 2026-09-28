(* Each leaf is linked to the actual memoized private FORS derivation. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeCatalog NodeCatalogDomain PersistentGrind AcceptedContexts.

op secret_leaf_origins (public private : (raw_input,digest) fmap)
    (f : int -> raw_input -> raw_input) (g : int -> raw_input) (c : node_catalog) =
  forall index value, c.[(0,index)] = Some value =>
    exists sd d, private.[g index] = Some sd /\
      public.[f index (node sd)] = Some d /\ value = node d.

lemma secret_leaf_empty public private f g :
  secret_leaf_origins public private f g empty.
proof. rewrite /secret_leaf_origins; smt(emptyE). qed.

lemma secret_leaf_public_extends public public' private f g c :
  extends public public' => secret_leaf_origins public private f g c =>
  secret_leaf_origins public' private f g c.
proof.
  rewrite /extends /secret_leaf_origins => he ho index value hc.
  have [sd d [hd [he' hv]]] := ho index value hc.
  exists sd d; smt(domE).
qed.

lemma secret_leaf_private_extends public private private' f g c :
  extends private private' => secret_leaf_origins public private f g c =>
  secret_leaf_origins public private' f g c.
proof.
  rewrite /extends /secret_leaf_origins => he ho index value hc.
  have [sd d [hd [he' hv]]] := ho index value hc.
  exists sd d; smt(domE).
qed.

lemma secret_leaf_parent public private f g c height parent value :
  0 < height => secret_leaf_origins public private f g c =>
  secret_leaf_origins public private f g c.[(height,parent) <- value].
proof.
  rewrite /secret_leaf_origins => hh ho index leaf hc.
  have hc' : c.[(0,index)] = Some leaf by move: hc; rewrite get_setE; smt().
  exact (ho index leaf hc').
qed.

lemma secret_leaf_insert public private f g c index sd d :
  secret_leaf_origins public private f g c =>
  private.[g index] = Some sd => public.[f index (node sd)] = Some d =>
  secret_leaf_origins public private f g c.[(0,index) <- node d].
proof.
  rewrite /secret_leaf_origins => ho hs hd index' value.
  rewrite get_setE /=; case (index' = index) => he.
  + rewrite ?he /=; move=> hv; exists sd d; smt().
  rewrite ?he /=; apply ho.
qed.

lemma catalog_target_secret_origin public private f g c total target :
  0 <= total => 0 <= target < 2^total => catalog_exact c (2^total) =>
  secret_leaf_origins public private f g c =>
  exists sd d, private.[g target] = Some sd /\
    public.[f target (node sd)] = Some d /\ catalog_grid c 0 target = node d.
proof.
  move=> hh ht hc ho.
  have hd := node_due_range total 0 target _ _; first 2 by smt().
  have hm : (0,target) \in c by apply hc.
  have he : c.[(0,target)] = Some (catalog_grid c 0 target)
    by rewrite /catalog_grid; smt(get_some).
  exact (ho target (catalog_grid c 0 target) he).
qed.
