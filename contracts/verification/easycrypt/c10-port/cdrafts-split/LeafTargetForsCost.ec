(* Every redacted FORS leaf contributes at most one variable candidate. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid RoleGrindCost KeygenPrefixes.
require import RawKeygen RawKeygenCost RawFors ForsLeafView LeafOpeningBound.
require import TargetOracleSplit TargetByteView TargetAdapterCost.

require import LeafCandidateCount LeafTargetOracleCost.

lemma leaf_target_leaf_cost q :
  hoare [IdealLeaf.leaf : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+1 /\ size res=16].
proof.
  proc; sp 1; if.
  + wp; call (leaf_variable_derive_bound q); auto; smt(node_width).
  wp; call (leaf_variable_hash_bound q).
  call (_ : true ==> true); first by trivial.
  auto; smt(node_width).
qed.
lemma leaf_target_secret_cost q :
  hoare [IdealLeaf.secret : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q /\ size res=16].
proof.
  proc; if.
  + inline RedactedLeafOpening(Independent).reveal; auto; smt(size_nseq).
  wp; call (_ : true ==> true); first by trivial.
  auto; smt(node_width).
qed.
lemma leaf_target_fors_tree_candidate_cost q :
  hoare [LeafFors(IdealLeaf).tree : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+4095 /\ size res.`1=16].
proof.
  proc; while (0<=j<=2048 /\ size stack<=j /\ (0<j => stack<>[]) /\
    valid_stack stack /\ leaf_variable_count Independent.queries<=q+2*j-size stack).
  + wp; while (0<=j<2048 /\ size stack<=j /\ valid_stack stack /\
      size current=16 /\ leaf_variable_count Independent.queries<=q+2*j+1-size stack).
    - exists* Independent.queries; elim* => qs.
      wp; call (leaf_variable_hash_bound (leaf_variable_count qs)); auto;
        smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* Independent.queries; elim* => qs.
    call (leaf_target_leaf_cost (leaf_variable_count qs)); auto;
      rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.
lemma leaf_target_fors_sign_candidate_cost q :
  hoare [LeafFors(IdealLeaf).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+4095 /\ size res.`1=16].
proof.
  proc; call (leaf_target_fors_tree_candidate_cost q).
  call (leaf_target_secret_cost q); auto; smt().
qed.
lemma leaf_target_fors_root_candidate_cost q :
  hoare [LeafFors(IdealLeaf).root : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+4095 /\ size res=16].
proof. proc; call (leaf_target_fors_tree_candidate_cost q); auto. qed.
