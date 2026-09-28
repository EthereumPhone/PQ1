(* Actual FORS components retain every already memoized public/private entry. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawFors RawForest.
require import PersistentGrind MonotoneHistory RecoveryHistory.

lemma preparation_fors_extends s0 h0 :
  hoare [PreparationView(Independent).fors :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. proc; call (independent_derive_extends s0 h0); auto. qed.

module type ForsSigning (O : PreparationOracle) = {
  proc sign(seed : raw_input, ht tree target : int) : raw_input * raw_input list { O.hash, O.fors }
}.
module type ForsOne (O : PreparationOracle) = {
  proc one(seed : raw_input, ht tree leaf : int) : raw_input * raw_input list * raw_input { O.hash, O.fors }
}.
module type ForsRoot (O : PreparationOracle) = {
  proc root(seed : raw_input, ht tree : int) : raw_input { O.hash, O.fors }
}.

lemma fors_signing_extends (S <: ForsSigning {-Independent}) s0 h0 :
  hoare [S(PreparationView(Independent)).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  exact (preparation_fors_extends s0 h0).
qed.

lemma fors_one_extends (S <: ForsOne {-Independent}) s0 h0 :
  hoare [S(PreparationView(Independent)).one :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  exact (preparation_fors_extends s0 h0).
qed.

lemma fors_root_extends (S <: ForsRoot {-Independent}) s0 h0 :
  hoare [S(PreparationView(Independent)).root :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  exact (preparation_fors_extends s0 h0).
qed.

lemma fors_recover_extends (S <: ForsRecovery {-Independent}) s0 h0 :
  hoare [S(PreparationView(Independent)).recover :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  exact (independent_hash_extends s0 h0).
qed.
