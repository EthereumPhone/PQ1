(* Preserve the complete bounded search and optional signer result while
   delaying ordinary FORS materialization until its layers have succeeded. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RoleGrind RawSigner.
require import ForsLeafView WrapperMemoProjection WrapperDeferredSigner.

module WrapperDeferredSign (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc sign(seed root random message shuffle : raw_input) : raw_signature option = {
    var accepted, result;
    accepted <@ RoleGrind(O).run(random,message,seed,root);
    result <- None;
    if (accepted <> None) {
      result <@ WrapperDeferredSigner(O,F).finish(seed,(oget accepted).`1,(oget accepted).`2,shuffle);
    }
    return result;
  }
}.

module type WrapperGrind (O : PrefixOracle) = {
  proc run(random message seed root : raw_input) : (raw_input * digest) option { O.hash, O.derive }
}.
module WrapperConcreteGrind (O : PrefixOracle) = {
  proc run = RoleGrind(O).run
}.

lemma wrapper_grind_table_projection (G <: WrapperGrind {-Independent}) :
  equiv [G(Independent).run ~ G(Independent).run :
    ={arg,glob G,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,glob G,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc (={Independent.rawhistory,Independent.secrethistory}) => //.
  + exact wrapper_memo_hash_projection.
  exact wrapper_memo_derive_projection.
qed.

lemma wrapper_deferred_sign_projection :
  equiv [RawSigner(Independent).sign ~
    WrapperDeferredSign(Independent,ConcreteForsLeaf(PreparationView(Independent))).sign :
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; seq 1 1 : (={seed,root,random,message,shuffle,accepted,Independent.rawhistory,Independent.secrethistory}).
  + call (wrapper_grind_table_projection WrapperConcreteGrind); auto.
  sp 1 1; if => //.
  exists* seed{1},(oget accepted{1}).`2; elim* => seed_ref digest_ref.
  call (wrapper_deferred_finish_projection seed_ref digest_ref); auto.
qed.
