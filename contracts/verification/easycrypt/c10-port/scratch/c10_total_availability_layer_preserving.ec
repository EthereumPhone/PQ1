require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawShuffle RawWots RawMerkle.
require import AllCore List Distr FMap IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import PreparedGrind KeygenExhaustion RObservedSigner RoleGrind.
require import RawWots RawLayer RawForest RawSigner RawCompositeWidths.
require import ByteSession RawByteValues RawCompositeBytes.
require import MemoRejectCompletion WotsRejectDomain WotsPhysicalFailure.
require import RawLayer WotsSignerFailure.

module ControlledTotalAvailability (O : PreparationOracle) = {
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
      result <- Some (sig,root ++ []);
    }
    return result;
  }
}.

lemma checked seed0 layer0 tree0 leaf0 message0 :
  hoare[ControlledTotalAvailability(PreparationView(Physical)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ message=message0 /\
    size message0=16 /\ byte_values message0 ==>
    res=None => wots_domain_exhausted seed0 signing_budget Shared.history].
proof.
  proc; seq 3 : (signed=None => wots_domain_exhausted seed0 signing_budget Shared.history).
  + call (physical_wots_failure seed0 layer0 tree0 leaf0 message0).
    call (_ : true ==> true); first by trivial.
    call (_ : true ==> true); first by trivial.
    auto.
  sp 1; if; last by auto; smt().
  wp; call (_ : true ==> true); first by trivial.
  auto.
qed.
