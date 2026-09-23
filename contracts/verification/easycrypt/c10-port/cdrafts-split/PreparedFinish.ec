(* External Q2 research: expose the preparation-only interface of complete
   signature construction, with exact correspondence to the frozen signer. *)
require import AllCore List Distr FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawForest RawLayer RawSigner RHistoryOps RTailContexts.

module PreparedFinish (O : PreparationOracle) = {
  proc finish(seed : raw_input, randomizer : raw_input, digest : digest, shuffle : raw_input) : raw_signature option = {
    var ht, forest, current, idx_tree, layer, idx_leaf, signed, layers, ok, result;
    ht <- hypertree_index digest;
    forest <@ RawForest(O).sign(seed,ht,digest,shuffle);
    current <- forest.`3; idx_tree <- ht; layer <- 0; layers <- []; ok <- true;
    while (layer < 2 /\ ok) {
      idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
      signed <@ RawLayer(O).sign(seed,layer,idx_tree,idx_leaf,current,shuffle);
      if (signed = None) { ok <- false; } else {
        layers <- rcons layers (oget signed).`1; current <- (oget signed).`2;
      }
      layer <- layer+1;
    }
    result <- None;
    if (ok) { result <- Some (randomizer,forest.`1,forest.`2,layers); }
    return result;
  }
}.

lemma prepared_finish_refines (O <: PrefixOracle) :
  equiv[RawSigner(O).finish ~ PreparedFinish(PreparationView(O)).finish :
    ={seed,randomizer,digest,shuffle,glob O} ==> ={res,glob O}].
proof. by proc; sim. qed.

module type PreparationFinisher (O : PreparationOracle) = {
  proc finish(seed randomizer : raw_input, digest : digest, shuffle : raw_input) :
    raw_signature option { O.hash, O.wots, O.fors }
}.

lemma prepared_finisher_contexts (F <: PreparationFinisher {-Independent}) contexts :
  hoare[F(PreparationView(Independent)).finish :
    r_history_contexts Independent.secrethistory contexts ==>
    r_history_contexts Independent.secrethistory contexts].
proof.
  proc (r_history_contexts Independent.secrethistory contexts) => //.
  + exact (hash_keeps_contexts contexts).
  + exact (wots_keeps_contexts contexts).
  exact (fors_keeps_contexts contexts).
qed.

lemma prepared_finish_contexts contexts :
  hoare[PreparedFinish(PreparationView(Independent)).finish :
    r_history_contexts Independent.secrethistory contexts ==>
    r_history_contexts Independent.secrethistory contexts].
proof. exact (prepared_finisher_contexts PreparedFinish contexts). qed.

lemma signer_finish_contexts contexts :
  hoare[RawSigner(Independent).finish :
    r_history_contexts Independent.secrethistory contexts ==>
    r_history_contexts Independent.secrethistory contexts].
proof.
  conseq (prepared_finish_refines Independent) (prepared_finish_contexts contexts).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},randomizer{m},digest{m},shuffle{m}).
    smt().
  smt().
qed.
