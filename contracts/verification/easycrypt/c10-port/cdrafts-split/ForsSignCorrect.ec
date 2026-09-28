(* Signing followed by recovery returns the tree root computed during signing. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawSignature.
require import PathReplay RawForsPathReplay RawForsComparison BuilderTotality ForsSignWitness.

module ForsSignRecover (O : PreparationOracle) = {
  proc run(seed : raw_input, ht tree target : int) :
      (raw_input * raw_input list) * raw_input = {
    var signed, recovered;
    signed <@ RawFors(O).sign(seed,ht,tree,target);
    recovered <@ RawFors(O).recover(seed,ht,tree,target,signed.`1,signed.`2);
    return (signed,recovered);
  }
}.

module ForsObservedSignRecover (O : PreparationOracle) = {
  proc run(seed : raw_input, ht tree target : int) :
      (raw_input * raw_input list) * raw_input * raw_input = {
    var signed, recovered;
    signed <@ ForsSignWitness(O).sign(seed,ht,tree,target);
    recovered <@ RawFors(O).recover(seed,ht,tree,target,signed.`1,signed.`2);
    return ((signed.`1,signed.`2),signed.`3,recovered);
  }
}.

lemma fors_sign_recover_projection (O <: PreparationOracle) :
  equiv [ForsSignRecover(O).run ~ ForsObservedSignRecover(O).run :
    ={seed,ht,tree,target,glob O} ==>
    res{1} = (res{2}.`1,res{2}.`3) /\ ={glob O}].
proof.
  proc; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  call (fors_sign_witness_projection O); auto.
qed.

lemma fors_observed_sign_correct seed0 ht0 tree0 target0 :
  hoare [ForsObservedSignRecover(PreparationView(Independent)).run :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    size res.`1.`1 = 16 /\ rows_width 11 res.`1.`2 /\ res.`2 = res.`3].
proof.
  proc; seq 1 : (exists d,
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    size signed.`1 = 16 /\ rows_width 11 signed.`2 /\
    Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 signed.`1] = Some d /\
    path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node d,0,target0) signed.`2 /\
    (path_value Independent.rawhistory (fors_pair seed0 ht0 tree0)
      (node d,0,target0) signed.`2).`1 = signed.`3).
  + call (fors_sign_witness_path seed0 ht0 tree0 target0); auto; smt().
  elim* => d0; exists* signed; elim* => signed0.
  call (fors_recover_recorded_repeat seed0 ht0 tree0 target0
    signed0.`1 signed0.`2 d0 signed0.`3).
  auto; rewrite /rows_width; smt().
qed.

lemma fors_observed_sign_recover_ll :
  islossless ForsObservedSignRecover(PreparationView(Independent)).run.
proof. proc; call fors_independent_recover_ll; call fors_sign_witness_ll; auto. qed.

lemma total_fors_observed_sign_correct seed0 ht0 tree0 target0 :
  phoare [ForsObservedSignRecover(PreparationView(Independent)).run :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ 0 <= target0 < 2048 ==>
    size res.`1.`1 = 16 /\ rows_width 11 res.`1.`2 /\ res.`2 = res.`3] = 1%r.
proof.
  conseq fors_observed_sign_recover_ll (fors_observed_sign_correct seed0 ht0 tree0 target0); smt().
qed.
