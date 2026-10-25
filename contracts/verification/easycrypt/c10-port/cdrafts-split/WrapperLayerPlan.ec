(* A layer plan retains the public accepted count/digest, authentication path
   and builder root. Its internal WOTS values and recovery need no new table
   entries. Only a later release procedure will request signature values. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawWots RawShuffle RawLayer.
require import WotsReference WotsReferenceRoot WotsSignatureValue WotsSignWitness PersistentGrind.
require import LayerWitness LayerPath LayerWotsSign LayerSignOpening MerkleBuilderWots.
require import WrapperMemoProjection WrapperForestPlan WrapperWotsPlan WrapperWotsPlanProjection WrapperLayerReplay.

type wrapper_layer_plan = int * digest * raw_input list * raw_input.

op wrapper_layer_planned h s seed layer tree leaf
    (signed : (layer_signature * raw_input) option) (planned : wrapper_layer_plan option) =
  (signed=None)=(planned=None) /\
  (signed<>None => (oget signed).`1.`2=(oget planned).`1 /\
    (oget signed).`1.`3=(oget planned).`3 /\ (oget signed).`2=(oget planned).`4 /\
    wots_prefix h s seed layer tree leaf 43 /\
    wots_signature h s seed layer tree leaf (oget planned).`2 (oget signed).`1.`1).

module WrapperLayerPlan (O : PrefixOracle) = {
  proc plan(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) : wrapper_layer_plan option = {
    var built, subseed, signed, result;
    built <@ RawMerkle(PreparationView(O)).build(seed,layer,tree,leaf);
    subseed <@ RawShuffle(PreparationView(O)).derive(shuffle,layer_label layer);
    signed <@ WrapperWotsPlan(O).plan(seed,layer,tree,leaf,message,subseed);
    result <- None;
    if (signed<>None) {
      result <- Some ((oget signed).`1,(oget signed).`2,built.`1,built.`2);
    }
    return result;
  }
}.

module type WrapperMerkleBuilder (O : PrefixOracle) = {
  proc build(seed : raw_input, layer tree target : int) : raw_input list * raw_input { O.hash, O.derive }
}.
module WrapperConcreteMerkle (O : PrefixOracle) = {
  proc build = RawMerkle(PreparationView(O)).build
}.

lemma wrapper_merkle_build_table_projection (B <: WrapperMerkleBuilder {-Independent}) :
  equiv [B(Independent).build ~ B(Independent).build :
    ={arg,glob B,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,glob B,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc (={Independent.rawhistory,Independent.secrethistory}) => //.
  + exact wrapper_memo_hash_projection.
  exact wrapper_memo_derive_projection.
qed.

lemma wrapper_layer_plan_projection seed0 layer0 tree0 leaf0 message0 :
  equiv [RawLayer(PreparationView(Independent)).sign ~ WrapperLayerPlan(Independent).plan :
    seed{1}=seed0 /\ layer{1}=layer0 /\ tree{1}=tree0 /\ leaf{1}=leaf0 /\ message{1}=message0 /\
    0<=leaf0<512 /\ ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wrapper_layer_planned Independent.rawhistory{1} Independent.secrethistory{1}
      seed0 layer0 tree0 leaf0 res{1} res{2}].
proof.
  proc; seq 1 1 : (exists pk,
    seed{1}=seed0 /\ layer{1}=layer0 /\ tree{1}=tree0 /\ leaf{1}=leaf0 /\ message{1}=message0 /\
    ={seed,layer,tree,leaf,message,shuffle,built,Independent.rawhistory,Independent.secrethistory} /\
    layer_witness Independent.rawhistory{1} Independent.secrethistory{1}
      seed0 layer0 tree0 leaf0 pk built{1}.`1 built{1}.`2).
  + call (_ : seed{1}=seed0 /\ layer{1}=layer0 /\ tree{1}=tree0 /\ target{1}=leaf0 /\ 0<=leaf0<512 /\
      ={arg,Independent.rawhistory,Independent.secrethistory} ==>
      ={res,Independent.rawhistory,Independent.secrethistory} /\ exists pk,
      layer_witness Independent.rawhistory{1} Independent.secrethistory{1}
        seed0 layer0 tree0 leaf0 pk res{1}.`1 res{1}.`2).
    - conseq (wrapper_merkle_build_table_projection WrapperConcreteMerkle)
        (merkle_build_wots_path seed0 layer0 tree0 leaf0); rewrite /layer_witness /layer_path; smt().
    auto; smt().
  elim* => pk; exists* built{1}; elim* => built0.
  seq 1 1 : (seed{1}=seed0 /\ layer{1}=layer0 /\ tree{1}=tree0 /\ leaf{1}=leaf0 /\ message{1}=message0 /\ built{1}=built0 /\
    ={seed,layer,tree,leaf,message,built,subseed,Independent.rawhistory,Independent.secrethistory} /\
    layer_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 layer0 tree0 leaf0 pk built0.`1 built0.`2).
  + call (_ : ={arg,Independent.rawhistory,Independent.secrethistory} /\
      layer_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 layer0 tree0 leaf0 pk built0.`1 built0.`2 ==>
      ={res,Independent.rawhistory,Independent.secrethistory} /\
      layer_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 layer0 tree0 leaf0 pk built0.`1 built0.`2).
    - conseq wrapper_shuffle_derive_projection
        (shuffle_keeps_layer_witness seed0 layer0 tree0 leaf0 pk built0.`1 built0.`2); smt().
    auto.
  seq 1 1 : (seed{1}=seed0 /\ layer{1}=layer0 /\ tree{1}=tree0 /\ leaf{1}=leaf0 /\ message{1}=message0 /\ built{1}=built0 /\
    ={seed,layer,tree,leaf,message,built,Independent.rawhistory,Independent.secrethistory} /\
    wrapper_wots_planned Independent.rawhistory{1} Independent.secrethistory{1} seed0 layer0 tree0 leaf0 signed{1} signed{2} /\
    layer_path Independent.rawhistory{1} seed0 layer0 tree0 leaf0 pk built0.`1 built0.`2 /\
    (signed{1}<>None => exists h s,
      wots_opening h s seed0 layer0 tree0 leaf0 message0 pk (oget signed{1}) /\
      extends s Independent.secrethistory{1} /\ extends h Independent.rawhistory{1})).
  + call (_ : seed{1}=seed0 /\ layer{1}=layer0 /\ tree{1}=tree0 /\ kp{1}=leaf0 /\ message{1}=message0 /\
      ={arg,Independent.rawhistory,Independent.secrethistory} /\
      layer_witness Independent.rawhistory{1} Independent.secrethistory{1} seed0 layer0 tree0 leaf0 pk built0.`1 built0.`2 ==>
      ={Independent.rawhistory,Independent.secrethistory} /\
      wrapper_wots_planned Independent.rawhistory{1} Independent.secrethistory{1} seed0 layer0 tree0 leaf0 res{1} res{2} /\
      layer_path Independent.rawhistory{1} seed0 layer0 tree0 leaf0 pk built0.`1 built0.`2 /\
      (res{1}<>None => exists h s,
        wots_opening h s seed0 layer0 tree0 leaf0 message0 pk (oget res{1}) /\
        extends s Independent.secrethistory{1} /\ extends h Independent.rawhistory{1})).
    - conseq (wrapper_wots_plan_projection seed0 layer0 tree0 leaf0 pk)
        (wots_sign_layer_witness seed0 layer0 tree0 leaf0 message0 pk built0.`1 built0.`2);
        rewrite /layer_witness; smt().
    auto.
  sp 1 1; if.
  + auto; rewrite /wrapper_wots_planned; smt().
  + exists* signed{1},signed{2},Independent.rawhistory{1},Independent.secrethistory{1}; elim* => sig0 plan0 h0 s0 h s.
    wp; call{1} (wrapper_layer_recover_total seed0 layer0 tree0 leaf0 message0
      ((oget sig0).`1,(oget sig0).`2,built0.`1) built0.`2 h0 s0).
    auto; rewrite /layer_opening /wrapper_layer_planned /wrapper_wots_planned; smt().
  auto; rewrite /wrapper_layer_planned /wrapper_wots_planned; smt().
qed.
