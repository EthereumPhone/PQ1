(* Actual forest and layer clients preserve both memoized oracle tables. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawForest RawLayer.
require import PersistentGrind MonotoneHistory WotsCatalogOracle ForsComponentHistory LayerRecoveryHistory.

module type ForestSigning (O : PreparationOracle) = {
  proc sign(seed : raw_input, ht : int, digest : digest, shuffle : raw_input) :
    raw_input list * raw_input list list * raw_input { O.hash, O.fors }
}.
module type ForestRecovery (O : PreparationOracle) = {
  proc recover(seed : raw_input, ht : int, digest : digest, secrets : raw_input list,
    auths : raw_input list list) : raw_input { O.hash }
}.
module type LayerSigning (O : PreparationOracle) = {
  proc sign(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) :
    (layer_signature * raw_input) option { O.hash, O.wots }
}.

lemma forest_sign_extends (S <: ForestSigning {-Independent}) s0 h0 :
  hoare [S(PreparationView(Independent)).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  exact (preparation_fors_extends s0 h0).
qed.
lemma forest_recovery_extends (S <: ForestRecovery {-Independent}) s0 h0 :
  hoare [S(PreparationView(Independent)).recover :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  exact (independent_hash_extends s0 h0).
qed.
lemma layer_sign_extends (S <: LayerSigning {-Independent}) s0 h0 :
  hoare [S(PreparationView(Independent)).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  exact (preparation_wots_extends s0 h0).
qed.
lemma layer_recovery_extends (S <: LayerRecovery {-Independent}) s0 h0 :
  hoare [S(PreparationView(Independent)).recover :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  exact (independent_hash_extends s0 h0).
qed.
