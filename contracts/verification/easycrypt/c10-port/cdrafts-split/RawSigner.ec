(* Complete signing/verification computation over one PrefixOracle.
   seed/root arguments are the deployed padded public fields. The structured
   signature adapter/width contract is a separate boundary. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains.
require import PrefixGuess PrefixHybrid KeygenPrefixes PreparedGrind RoleGrind RoleGrindCost.
require import RawKeygen RawForest RawLayer.

type raw_signature = raw_input * raw_input list * raw_input list list * layer_signature list.

module RawSigner (O : PrefixOracle) = {
  proc finish(seed : raw_input, randomizer : raw_input, digest : digest, shuffle : raw_input) : raw_signature option = {
    var ht, forest, current, idx_tree, layer, idx_leaf, signed, layers, ok, result;
    ht <- hypertree_index digest;
    forest <@ RawForest(PreparationView(O)).sign(seed,ht,digest,shuffle);
    current <- forest.`3; idx_tree <- ht; layer <- 0; layers <- []; ok <- true;
    while (layer < 2 /\ ok) {
      idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
      signed <@ RawLayer(PreparationView(O)).sign(seed,layer,idx_tree,idx_leaf,current,shuffle);
      if (signed = None) { ok <- false; } else {
        layers <- rcons layers (oget signed).`1; current <- (oget signed).`2;
      }
      layer <- layer+1;
    }
    result <- None;
    if (ok) { result <- Some (randomizer,forest.`1,forest.`2,layers); }
    return result;
  }
  proc sign(seed root random message shuffle : raw_input) : raw_signature option = {
    var accepted, result;
    accepted <@ RoleGrind(O).run(random,message,seed,root);
    result <- None;
    if (accepted <> None) {
      result <@ finish(seed,(oget accepted).`1,(oget accepted).`2,shuffle);
    }
    return result;
  }
  proc verify(seed root message : raw_input, sig : raw_signature) : bool = {
    var digest, ht, current, layer, idx_tree, idx_leaf, result;
    digest <@ O.hash(hmsg_input seed root (pad sig.`1) message);
    result <- false;
    if (accept_digest digest) {
      ht <- hypertree_index digest;
      current <@ RawForest(PreparationView(O)).recover(seed,ht,digest,sig.`2,sig.`3);
      idx_tree <- ht; layer <- 0;
      while (layer < 2) {
        idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
        current <@ RawLayer(PreparationView(O)).recover(seed,layer,idx_tree,idx_leaf,current,nth ([],0,[]) sig.`4 layer);
        layer <- layer+1;
      }
      result <- pad current = root;
    }
    return result;
  }
}.

lemma signer_finish_lossless (O <: PrefixOracle) :
  islossless O.hash => islossless O.derive => islossless RawSigner(O).finish.
proof.
  move=> hh hd; have [#] hvh hvw hvf := preparation_view_lossless O hh hd.
  proc; wp; while true (2-layer).
  + move=> z; wp; call (layer_sign_lossless (PreparationView(O)) hvh hvw); auto; smt().
  wp; call (forest_sign_lossless (PreparationView(O)) hvh hvf); auto; smt().
qed.
lemma signer_sign_lossless (O <: PrefixOracle) :
  islossless O.hash => islossless O.derive => islossless RawSigner(O).sign.
proof.
  move=> hh hd; proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (role_grind_lossless O hh hd); auto.
  sp 1; if; auto; call (signer_finish_lossless O hh hd); auto.
qed.
lemma signer_verify_lossless (O <: PrefixOracle) :
  islossless O.hash => islossless RawSigner(O).verify.
proof.
  move=> hh; proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call hh; auto.
  sp 1; if; auto; wp; while true (2-layer).
  + move=> z; wp; call (layer_recover_lossless (PreparationView(O)) hh); auto; smt().
  wp; call (forest_recover_lossless (PreparationView(O)) hh); auto; smt().
qed.
