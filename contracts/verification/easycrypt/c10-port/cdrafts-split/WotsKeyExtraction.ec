(* The extraction theorem also consumes a key produced by actual raw key generation. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawSignature.
require import RawKeygenCost RawWotsReference WotsReferenceRoot BuilderTotality.
require import RawWotsExtraction VerifierWotsOpening MemoNodeCollision PublicNodeZero.

module WotsKeyCompare = {
  proc run(seed : raw_input, layer tree kp : int, message : raw_input,
      sigma : raw_input list, count : int) : raw_input * raw_input = {
    var reference, recovered;
    reference <@ RawKeygen(PreparationView(Independent)).leaf(seed,layer,tree,kp);
    recovered <@ RawWots(PreparationView(Independent)).recover(seed,layer,tree,kp,message,sigma,count);
    return (reference,recovered);
  }
}.

lemma actual_wots_key_extraction seed0 layer0 tree0 kp0 message0 sigma0 count0 :
  hoare [WotsKeyCompare.run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sigma=sigma0 /\ count=count0 /\
    rows_width 43 sigma0 /\ 0<=count0<4294967296 ==>
    res.`2=res.`1 => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      wots_verifier_opening Independent.rawhistory Independent.secrethistory
        seed0 layer0 tree0 kp0 message0 res.`1 (sigma0,count0)].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sigma=sigma0 /\ count=count0 /\
    rows_width 43 sigma0 /\ 0<=count0<4294967296 /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 reference).
  + call (raw_leaf_recorded seed0 layer0 tree0 kp0); auto; rewrite /wots_root; smt().
  exists* reference; elim* => root0; wp.
  call (raw_wots_extracts_opening seed0 layer0 tree0 kp0 message0 sigma0 count0 root0); auto; smt().
qed.

lemma wots_key_compare_ll : islossless WotsKeyCompare.run.
proof.
  proc; call (raw_recover_lossless (PreparationView(Independent)) independent_hash_ll).
  call (leaf_lossless (PreparationView(Independent)) independent_hash_ll preparation_wots_ll); auto.
qed.

lemma total_actual_wots_key_extraction seed0 layer0 tree0 kp0 message0 sigma0 count0 :
  phoare [WotsKeyCompare.run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sigma=sigma0 /\ count=count0 /\
    rows_width 43 sigma0 /\ 0<=count0<4294967296 ==>
    res.`2=res.`1 => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      wots_verifier_opening Independent.rawhistory Independent.secrethistory
        seed0 layer0 tree0 kp0 message0 res.`1 (sigma0,count0)] = 1%r.
proof.
  conseq wots_key_compare_ll (actual_wots_key_extraction seed0 layer0 tree0 kp0 message0 sigma0 count0); smt().
qed.
