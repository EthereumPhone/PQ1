(* Every redacted FORS leaf uses at most one public query. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid RoleGrindCost KeygenPrefixes.
require import RawKeygen RawKeygenCost RawFors ForsLeafView LeafOpeningBound.
require import TargetOracleSplit TargetByteView TargetAdapterCost.

lemma target_leaf_cost q :
  hoare [IdealLeaf.leaf : size Independent.queries=q ==>
    q<=size Independent.queries<=q+1 /\ size res=16].
proof.
  proc; sp 1; if.
  + wp; call (independent_derive_count q); auto; smt(node_width).
  wp; call (independent_hash_count q).
  call (_ : true ==> true); first by trivial.
  auto; smt(node_width).
qed.
lemma target_secret_cost q :
  hoare [IdealLeaf.secret : size Independent.queries=q ==>
    size Independent.queries=q /\ size res=16].
proof.
  proc; if.
  + inline RedactedLeafOpening(Independent).reveal; auto; smt(size_nseq).
  wp; call (_ : true ==> true); first by trivial.
  auto; smt(node_width).
qed.
lemma target_fors_tree_public_cost q :
  hoare [LeafFors(IdealLeaf).tree : size Independent.queries=q ==>
    q<=size Independent.queries<=q+4095 /\ size res.`1=16].
proof.
  proc; while (0<=j<=2048 /\ size stack<=j /\ (0<j => stack<>[]) /\
    valid_stack stack /\ q<=size Independent.queries<=q+2*j-size stack).
  + wp; while (0<=j<2048 /\ size stack<=j /\ valid_stack stack /\
      size current=16 /\ q<=size Independent.queries<=q+2*j+1-size stack).
    - exists* Independent.queries; elim* => qs.
      wp; call (independent_hash_count (size qs)); auto;
        smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* Independent.queries; elim* => qs.
    call (target_leaf_cost (size qs)); auto;
      rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.
lemma target_fors_sign_public_cost q :
  hoare [LeafFors(IdealLeaf).sign : size Independent.queries=q ==>
    q<=size Independent.queries<=q+4095 /\ size res.`1=16].
proof.
  proc; call (target_fors_tree_public_cost q).
  call (target_secret_cost q); auto; smt().
qed.
lemma target_fors_root_public_cost q :
  hoare [LeafFors(IdealLeaf).root : size Independent.queries=q ==>
    q<=size Independent.queries<=q+4095 /\ size res=16].
proof. proc; call (target_fors_tree_public_cost q); auto. qed.
