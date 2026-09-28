(* Total correctness of the deployed forest convention, including the
   thirteenth root-as-secret and the exact root compression. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawForest RawKeygen.
require import PersistentGrind AcceptedContexts BuilderTotality.
require import ForestWitness ForestSignRecorded ForestRecoveryReplay.

module ActualForestConstruction (O : PreparationOracle) = {
  proc run(seed : raw_input, ht : int, digest : digest, shuffle : raw_input) :
      (raw_input list * raw_input list list * raw_input) * raw_input = {
    var signature, recovered;
    signature <@ RawForest(O).sign(seed,ht,digest,shuffle);
    recovered <@ RawForest(O).recover(seed,ht,digest,signature.`1,signature.`2);
    return (signature,recovered);
  }
}.

lemma actual_forest_correct seed0 ht0 digest0 :
  hoare [ActualForestConstruction(PreparationView(Independent)).run :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 ==> res.`1.`3=res.`2].
proof.
  proc; seq 1 : (exists roots d,
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\
    forest_witness Independent.rawhistory seed0 ht0 digest0 signature.`1 signature.`2 roots /\
    Independent.rawhistory.[forest_compress_input seed0 ht0 roots]=Some d /\ signature.`3=node d).
  + call (forest_sign_recorded seed0 ht0 digest0); auto; smt().
  elim* => roots d.
  exists* signature,Independent.rawhistory,Independent.secrethistory; elim* => sig0 h0 s0.
  call (forest_recover_witness seed0 ht0 digest0 sig0.`1 sig0.`2 roots d s0 h0).
  auto; smt(extends_refl).
qed.

lemma actual_forest_lossless : islossless ActualForestConstruction(PreparationView(Independent)).run.
proof.
  proc; call (forest_recover_lossless (PreparationView(Independent)) independent_hash_ll).
  call (forest_sign_lossless (PreparationView(Independent)) independent_hash_ll preparation_fors_ll); auto.
qed.

lemma total_actual_forest_correct seed0 ht0 digest0 :
  phoare [ActualForestConstruction(PreparationView(Independent)).run :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 ==> res.`1.`3=res.`2] = 1%r.
proof. conseq actual_forest_lossless (actual_forest_correct seed0 ht0 digest0); smt(). qed.
