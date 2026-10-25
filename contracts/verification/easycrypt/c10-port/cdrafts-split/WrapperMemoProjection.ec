(* Passive public-query logs do not affect memo-oracle answers or tables.
   This permits local trusted replay steps to be compared without conflating
   their internal query logs with the client-visible transcript. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawForest.
require import WrapperPrivateSchedule.

module type WrapperForsOne (O : PrefixOracle) = {
  proc one(seed : raw_input, ht tree leaf : int) : raw_input * raw_input list * raw_input { O.hash, O.derive }
}.
module WrapperOriginalForsOne (O : PrefixOracle) = {
  proc one = RawForest(PreparationView(O)).one
}.

lemma wrapper_memo_hash_projection :
  equiv [Independent.hash ~ Independent.hash :
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof. proc; sp 1 1; if; auto. qed.

lemma wrapper_memo_derive_projection :
  equiv [Independent.derive ~ Independent.derive :
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof. proc; if; auto. qed.

lemma wrapper_fors_one_table_projection
  (C <: WrapperForsOne {-Independent}) :
  equiv [C(Independent).one ~ C(Independent).one :
    ={arg,glob C,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,glob C,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc (={Independent.rawhistory,Independent.secrethistory}) => //.
  + exact wrapper_memo_hash_projection.
  exact wrapper_memo_derive_projection.
qed.

lemma wrapper_fors_tree_table_projection
  (C <: WrapperForsTree {-Independent}) :
  equiv [C(Independent).tree ~ C(Independent).tree :
    ={arg,glob C,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,glob C,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc (={Independent.rawhistory,Independent.secrethistory}) => //.
  + exact wrapper_memo_hash_projection.
  exact wrapper_memo_derive_projection.
qed.
