(* Layer computations preserve earlier private FORS entries and do not depend
   on the passive query log. Neither fact suppresses their actual hash calls. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer.
require import PersistentGrind AcceptedContexts SignerComponentHistory.
require import WrapperMemoProjection WrapperForestMemo.

module type WrapperLayer (O : PrefixOracle) = {
  proc sign(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) :
    (layer_signature * raw_input) option { O.hash, O.derive }
}.
module WrapperConcreteLayer (O : PrefixOracle) = {
  proc sign = RawLayer(PreparationView(O)).sign
}.

lemma wrapper_layer_table_projection (L <: WrapperLayer {-Independent}) :
  equiv [L(Independent).sign ~ L(Independent).sign :
    ={arg,glob L,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,glob L,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc (={Independent.rawhistory,Independent.secrethistory}) => //.
  + exact wrapper_memo_hash_projection.
  exact wrapper_memo_derive_projection.
qed.

lemma wrapper_layer_keeps_fors_memo ht_ref digest_ref secrets_ref visited :
  hoare [RawLayer(PreparationView(Independent)).sign :
    wrapper_fors_memo_prefix Independent.secrethistory ht_ref digest_ref secrets_ref visited ==>
    wrapper_fors_memo_prefix Independent.secrethistory ht_ref digest_ref secrets_ref visited].
proof.
  exists* Independent.secrethistory,Independent.rawhistory; elim* => s0 h0.
  conseq (layer_sign_extends RawLayer s0 h0); smt(extends_refl wrapper_fors_memo_extends).
qed.
