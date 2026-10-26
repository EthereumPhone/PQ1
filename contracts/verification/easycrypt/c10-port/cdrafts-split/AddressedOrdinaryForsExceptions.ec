(* The first twelve honest FORS trees never use the exceptional tree index.
   This remains true for arbitrary authentication-path contents. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest.
require import RawForsPathReplay RawForsCost IndependentWidths.
require import AddressedForsException AddressedForsExceptionCount.

lemma exceptional_ordinary_pair seed ht tree level parent lval rval :
  size seed=32 => 0<=tree<12 =>
  !exceptional_fors_query (fors_pair seed ht tree level parent lval rval).
proof.
  move=> hs ht0.
  have he := exceptional_fors_other_tree seed ht tree 0 level parent (pad lval++pad rval) hs ht0.
  by move: he; rewrite /fors_pair -!catA.
qed.

lemma raw_fors_sign_exception_zero seed0 tree0 q :
  hoare [RawFors(PreparationView(Independent)).sign :
    seed=seed0 /\ tree=tree0 /\ size seed0=32 /\ 0<=tree0<12 /\
    exceptional_fors_count Independent.queries=q ==>
    exceptional_fors_count Independent.queries=q].
proof.
  proc; call (raw_fors_tree_exception_count seed0 tree0 q); wp;
    call (exceptional_fors_derive q); auto; smt(b2i0).
qed.

lemma raw_fors_recover_exception_zero seed0 tree0 q :
  hoare [RawFors(PreparationView(Independent)).recover :
    seed=seed0 /\ tree=tree0 /\ size seed0=32 /\ 0<=tree0<12 /\
    exceptional_fors_count Independent.queries=q ==>
    exceptional_fors_count Independent.queries=q].
proof.
  proc; while (seed=seed0 /\ tree=tree0 /\ size seed0=32 /\ 0<=tree0<12 /\
    exceptional_fors_count Independent.queries=q).
  + wp; call (exceptional_hash_excluded q); auto; move=> &m hp.
    have he := exceptional_ordinary_pair seed{m} ht{m} tree{m} (h{m}+1) (idx{m} %/ 2)
      (if idx{m} %% 2=0 then current{m} else nth (nseq 16 0) auth{m} h{m})
      (if idx{m} %% 2=0 then nth (nseq 16 0) auth{m} h{m} else current{m}) _ _; first 2 smt().
    rewrite /fors_pair in he; smt().
  wp; call (exceptional_hash_excluded q); auto; smt(exceptional_fors_other_tree).
qed.

module type WidthForsRoot (O : PreparationOracle) = {
  proc root(seed : raw_input, ht tree : int) : raw_input { O.hash, O.fors }
}.
module type WidthForestOne (O : PreparationOracle) = {
  proc one(seed : raw_input, ht tree leaf : int) : raw_input * raw_input list * raw_input { O.hash, O.fors }
}.

lemma preparation_fors_tables_valid :
  hoare [PreparationView(Independent).fors :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof. proc; call independent_derive_width; auto; smt(). qed.

lemma width_fors_root_valid (R <: WidthForsRoot {-Independent}) :
  hoare [R(PreparationView(Independent)).root :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc (independent_tables_valid Independent.rawhistory Independent.secrethistory) => //.
  + conseq independent_hash_width; smt().
  exact preparation_fors_tables_valid.
qed.

lemma width_forest_one_valid (F <: WidthForestOne {-Independent}) :
  hoare [F(PreparationView(Independent)).one :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc (independent_tables_valid Independent.rawhistory Independent.secrethistory) => //.
  + conseq independent_hash_width; smt().
  exact preparation_fors_tables_valid.
qed.

lemma raw_fors_root_valid_width :
  hoare [RawFors(PreparationView(Independent)).root :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res=16].
proof.
  exists* Independent.queries; elim* => queries.
  conseq (fors_root_public_cost (size queries)) (width_fors_root_valid RawFors); smt().
qed.

lemma raw_forest_one_exception_zero q :
  hoare [RawForest(PreparationView(Independent)).one :
    size seed=32 /\ 0<=tree<12 /\ exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  have hc : hoare [RawForest(PreparationView(Independent)).one :
    size seed=32 /\ 0<=tree<12 /\ exceptional_fors_count Independent.queries=q ==>
    exceptional_fors_count Independent.queries=q].
  + exists* seed,tree; elim* => seed0 tree0.
    proc; call (raw_fors_recover_exception_zero seed0 tree0 q);
      call (raw_fors_sign_exception_zero seed0 tree0 q); auto.
  conseq hc (width_forest_one_valid RawForest); smt().
qed.

lemma raw_fors_root_exception_valid seed0 tree0 q :
  hoare [RawFors(PreparationView(Independent)).root :
    seed=seed0 /\ tree=tree0 /\ size seed0=32 /\ 0<=tree0<13 /\
    exceptional_fors_count Independent.queries=q /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    exceptional_fors_count Independent.queries=q+b2i (tree0=12) /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res=16].
proof. conseq (raw_fors_root_exception_count seed0 tree0 q) raw_fors_root_valid_width; smt(). qed.
