(* Exact projection of the real sign procedure, retaining its internal tree root. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawSignature.
require import PathReplay RawForsPathReplay ForsPrivateLeaves ForsKnownSecret BuilderTotality.

module ForsSignWitness (O : PreparationOracle) = {
  proc sign(seed : raw_input, ht tree target : int) : raw_input * raw_input list * raw_input = {
    var d, secret, result;
    d <@ O.fors(fors_tail ht tree target); secret <- node d;
    result <@ RawFors(O).tree(seed,ht,tree,target);
    return (secret,result.`2,result.`1);
  }
}.

lemma fors_sign_witness_projection (O <: PreparationOracle) :
  equiv [RawFors(O).sign ~ ForsSignWitness(O).sign :
    ={seed,ht,tree,target,glob O} ==>
    res{1} = (res{2}.`1,res{2}.`2) /\ ={glob O}].
proof.
  proc; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  auto.
qed.

lemma fors_sign_witness_path seed0 ht0 tree0 target0 :
  hoare [ForsSignWitness(PreparationView(Independent)).sign :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    size res.`1 = 16 /\ rows_width 11 res.`2 /\ exists d,
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 res.`1] = Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2 /\
      (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
        (node d,0,target0) res.`2).`1 = res.`3].
proof.
  proc; seq 2 : (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    0 <= target0 < 2048 /\ secret = node d /\
    Independent.secrethistory.[fors_private_key ht0 tree0 target0] = Some d).
  + wp; call (fors_records_private_entry (fors_tail ht0 tree0 target0)).
    auto; rewrite /fors_private_key; smt().
  exists* d; elim* => sd0.
  call (fors_tree_known_secret seed0 ht0 tree0 target0 sd0).
  auto; smt(node_width).
qed.

lemma fors_sign_witness_ll :
  islossless ForsSignWitness(PreparationView(Independent)).sign.
proof. proc; call fors_independent_tree_ll; wp; call preparation_fors_ll; auto. qed.
