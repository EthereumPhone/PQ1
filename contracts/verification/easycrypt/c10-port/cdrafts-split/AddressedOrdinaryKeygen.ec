(* Initialized actual key generation has no charged inputs: every memo entry
   belongs to the canonical WOTS/Merkle family for its generated public seed. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen KeygenExhaustion IndependentWidths.
require import AddressedQueryProvenance AddressedTreeLog AddressedMerkleTreeQueries AddressedOrdinaryTrees.
require import AddressedCoordinateBounds.

op canonical_keygen_history (h s : (raw_input,digest) fmap) seed =
  forall x, x \in h => canonical_tree_input h s seed x.

lemma canonical_keygen_history_from_log base h s seed queries :
  appended_query_history empty base h queries => canonical_tree_log h s seed base queries =>
  canonical_keygen_history h s seed.
proof.
  move=> hp [inputs [hq hi]] x hx.
  have hm := appended_query_history_member empty base h queries inputs x hp hq hx _; first smt(emptyE domE).
  move: hi; rewrite allP; smt().
qed.

lemma raw_keygen_root_initial_history seed0 layer0 tree0 :
  hoare [RawKeygen(PreparationView(Independent)).root :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=layer0<4294967296 /\ 0<=tree0<2^64 /\
    Independent.rawhistory=empty /\ Independent.queries=[] ==>
    canonical_keygen_history Independent.rawhistory Independent.secrethistory seed0].
proof.
  conseq (raw_keygen_root_canonical_queries seed0 layer0 tree0 [])
    (keygen_root_appended_query_history RawKeygen empty []);
    smt(canonical_tree_log_empty appended_query_history_initial canonical_keygen_history_from_log).
qed.

lemma keygen_preparation_canonical_history :
  hoare [KeygenPreparation(PreparationView(Independent)).run :
    Independent.rawhistory=empty /\ Independent.queries=[] ==>
    canonical_keygen_history Independent.rawhistory Independent.secrethistory res.`3].
proof.
  exists* KeygenInputs.public_seed; elim* => public0.
  proc; call (raw_keygen_root_initial_history (pad (node public0)) 1 0).
  auto; rewrite addressed_tree_field_cardinality; smt().
qed.

lemma keygen_preparation_tables_valid :
  hoare [KeygenPreparation(PreparationView(Independent)).run :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof. proc; call (width_keygen_valid RawKeygen); auto. qed.

lemma keygen_preparation_initial_ordinary :
  hoare [KeygenPreparation(PreparationView(Independent)).run :
    Independent.rawhistory=empty /\ Independent.queries=[] /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    canonical_keygen_history Independent.rawhistory Independent.secrethistory res.`3 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    size res.`3=32 /\ size res.`4=32].
proof.
  have hc : hoare [KeygenPreparation(PreparationView(Independent)).run :
    Independent.rawhistory=empty /\ Independent.queries=[] /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    canonical_keygen_history Independent.rawhistory Independent.secrethistory res.`3 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
  + conseq keygen_preparation_canonical_history keygen_preparation_tables_valid; smt().
  conseq hc keygen_preparation_cost; smt().
qed.
