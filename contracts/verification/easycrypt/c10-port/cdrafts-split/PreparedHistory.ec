(* Adaptive WOTS/FORS preparation preserves the history premises needed by R. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind C10Counter.
require import PrefixGuess PrefixHybrid RawTrial RoleGrind RTailFresh KeygenPrefixes.

lemma wots_preserves_recorded :
  hoare[PreparationView(Independent).wots :
    history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof. by proc; call recorded_derive; auto. qed.
lemma fors_preserves_recorded :
  hoare[PreparationView(Independent).fors :
    history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof. by proc; call recorded_derive; auto. qed.

lemma preparation_preserves_recorded (P <: Preparation {-Independent}) :
  hoare[P(PreparationView(Independent)).run :
    history_recorded Independent.rawhistory Independent.queries ==>
    history_recorded Independent.rawhistory Independent.queries].
proof.
  proc (history_recorded Independent.rawhistory Independent.queries) => //.
  + exact recorded_hash.
  + exact wots_preserves_recorded.
  exact fors_preserves_recorded.
qed.

lemma preparation_preserves_history (P <: Preparation {-Independent}) :
  hoare[P(PreparationView(Independent)).run :
    no_r_tails Independent.secrethistory /\
    history_recorded Independent.rawhistory Independent.queries ==>
    no_r_tails Independent.secrethistory /\
    history_recorded Independent.rawhistory Independent.queries].
proof.
  conseq (preparation_preserves_no_r P) (preparation_preserves_recorded P); smt().
qed.
