(* One deployed hypertree layer, including reconstruction performed by signer. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawShuffle RawWots RawMerkle.

type layer_signature = raw_input list * int * raw_input list.
op layer_label layer = if layer = 0 then [119;111;116;115;45;48;0]
  else [119;111;116;115;45;49;0].

module RawLayer (O : PreparationOracle) = {
  proc recover(seed : raw_input, layer tree leaf : int, message : raw_input, sig : layer_signature) : raw_input = {
    var pk, root;
    pk <@ RawWots(O).recover(seed,layer,tree,leaf,message,sig.`1,sig.`2);
    root <@ RawMerkle(O).recover(seed,layer,tree,pk,leaf,sig.`3);
    return root;
  }
  proc sign(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) : (layer_signature * raw_input) option = {
    var built, subseed, signed, sig, root, result;
    built <@ RawMerkle(O).build(seed,layer,tree,leaf);
    subseed <@ RawShuffle(O).derive(shuffle,layer_label layer);
    signed <@ RawWots(O).sign(seed,layer,tree,leaf,message,subseed);
    result <- None;
    if (signed <> None) {
      sig <- ((oget signed).`1,(oget signed).`2,built.`1);
      root <@ recover(seed,layer,tree,leaf,message,sig);
      result <- Some (sig,root);
    }
    return result;
  }
}.

lemma layer_recover_lossless (O <: PreparationOracle) :
  islossless O.hash => islossless RawLayer(O).recover.
proof.
  move=> hh; proc; call (merkle_recover_lossless O hh); call (raw_recover_lossless O hh); auto.
qed.
lemma layer_sign_lossless (O <: PreparationOracle) :
  islossless O.hash => islossless O.wots => islossless RawLayer(O).sign.
proof.
  move=> hh hw; proc; seq 3 : true 1%r 1%r 0%r 0%r => //.
  + call (raw_sign_lossless O hh hw); call (shuffle_derive_lossless O hh).
    call (merkle_build_lossless O hh hw); auto.
  sp 1; if; auto; wp; call (layer_recover_lossless O hh); auto.
qed.
