(* Canonical queries at the real FORS builder's leaf and merge steps. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import PersistentGrind AcceptedContexts RawForsPathReplay ForsPrivateLeaves.
require import NodeCatalog NodeCatalogDomain SecretLeafOrigins DyadicStack StackProjection StackAlignment.
require import NodeGridIndex CatalogForest CatalogMerge AddressedForsCanonicity AddressedForsLog.

lemma canonical_fors_leaf_member h s seed ht tree index sd :
  fors_address_valid ht tree index => s.[fors_private_key ht tree index]=Some sd =>
  canonical_fors_input h s seed (fors_leaf_input seed ht tree index (node sd)).
proof.
  move=> hv hs; rewrite /canonical_fors_input; left; exists ht tree index.
  rewrite /canonical_fors_leaf_input; smt(domE oget_some).
qed.

lemma canonical_fors_merge_member h s seed ht tree c stack current height n :
  0<=ht<2^64 => 0<=tree<13 => 0<=height<2048 => 0<n<=2048 =>
  canonical_fors_catalog h s seed ht tree c =>
  active_stack (map snd stack) height => stack<>[] => (head ([],0) stack).`2=height =>
  stack_mass (map snd stack)+2^height=n =>
  forest_references c stack (n-2^height) =>
  c.[(height,(n-1) %/ (2^height))]=Some current =>
  canonical_fors_input h s seed
    (fors_pair seed ht tree (height+1) ((n-1) %/ (2^(height+1)))
      (head ([],0) stack).`1 current).
proof.
  move=> hht htree hh hn hc ha hs he hm hf hcur.
  have [ha' hm'] := projected_carry_pop stack [] height ha hs he.
  have hm'' : stack_mass (map snd (behead stack))+2^(height+1)=n by smt().
  have hd := active_stack_alignment (map snd (behead stack)) (height+1) n ha' hm''.
  have [hz [hleft hrest]] := forest_pop c stack n height hf hs he.
  have [hri hli] := aligned_pair_indices n height _ hd; first smt().
  have hp := pow2_pos (height+1) _; first smt().
  have hi : 0<=(n-1) %/ (2^(height+1))<4294967296.
  + rewrite divz_ge0 1:hp ltz_divLR 1:hp; smt().
  rewrite /canonical_fors_input; right.
  exists ht tree (height+1) ((n-1) %/ (2^(height+1))) c.
  rewrite /fors_address_valid /canonical_fors_pair_supported /canonical_fors_pair_input.
  have hl : catalog_grid c height (2*((n-1) %/ (2^(height+1))))=(head ([],0) stack).`1
    by rewrite /catalog_grid; smt(oget_some).
  have hr : catalog_grid c height (2*((n-1) %/ (2^(height+1)))+1)=current
    by rewrite /catalog_grid; smt(oget_some).
  smt(domE).
qed.

lemma canonical_fors_merge_recorded h s seed ht tree c stack current height n d :
  active_stack (map snd stack) height => stack<>[] => (head ([],0) stack).`2=height =>
  stack_mass (map snd stack)+2^height=n => catalog_partial c n height =>
  canonical_fors_catalog h s seed ht tree c => forest_references c stack (n-2^height) =>
  c.[(height,(n-1) %/ (2^height))]=Some current =>
  h.[fors_pair seed ht tree (height+1) ((n-1) %/ (2^(height+1)))
    (head ([],0) stack).`1 current]=Some d =>
  let c'=c.[(height+1,(n-1) %/ (2^(height+1))) <- node d] in
    canonical_fors_catalog h s seed ht tree c' /\
    forest_references c' (behead stack) (n-2^(height+1)) /\
    c'.[(height+1,(n-1) %/ (2^(height+1)))]=Some (node d).
proof.
  move=> ha hs he hm hp [hc ho] hf hcur hd.
  have hr := catalog_merge_recorded h (fors_pair seed ht tree) c stack current height n d
    ha hs he hm hp hc hf hcur hd.
  have hz : 0<=height by move: ha; rewrite /active_stack; smt().
  have ho' := secret_leaf_parent h s (fors_leaf_input seed ht tree) (fors_private_key ht tree)
    c (height+1) ((n-1) %/ (2^(height+1))) (node d) _ ho; first smt().
  rewrite /canonical_fors_catalog; smt().
qed.

lemma hash_records_canonical_fors seed ht tree c base x0 :
  hoare [Independent.hash :
    x=x0 /\ canonical_fors_catalog Independent.rawhistory Independent.secrethistory seed ht tree c /\
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed base Independent.queries /\
    canonical_fors_input Independent.rawhistory Independent.secrethistory seed x0 ==>
    canonical_fors_catalog Independent.rawhistory Independent.secrethistory seed ht tree c /\
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed base Independent.queries /\
    Independent.rawhistory.[x0]=Some res].
proof.
  proc; sp 1; if; auto;
    smt(canonical_fors_catalog_extends canonical_fors_log_push_extends
      extends_insert extends_refl get_set_sameE domE).
qed.

lemma derive_records_canonical_fors seed ht tree c base key :
  hoare [Independent.derive :
    tail=key /\ canonical_fors_catalog Independent.rawhistory Independent.secrethistory seed ht tree c /\
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed base Independent.queries ==>
    canonical_fors_catalog Independent.rawhistory Independent.secrethistory seed ht tree c /\
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed base Independent.queries /\
    Independent.secrethistory.[key]=Some res].
proof.
  proc; if; auto;
    smt(canonical_fors_catalog_extends canonical_fors_log_extends
      extends_insert extends_refl get_set_sameE domE).
qed.

lemma fors_records_canonical_fors seed ht tree c base tail0 :
  hoare [PreparationView(Independent).fors :
    tail=tail0 /\ canonical_fors_catalog Independent.rawhistory Independent.secrethistory seed ht tree c /\
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed base Independent.queries ==>
    canonical_fors_catalog Independent.rawhistory Independent.secrethistory seed ht tree c /\
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed base Independent.queries /\
    Independent.secrethistory.[fors_tag++tail0]=Some res].
proof. proc; call (derive_records_canonical_fors seed ht tree c base (fors_tag++tail0)); auto. qed.
