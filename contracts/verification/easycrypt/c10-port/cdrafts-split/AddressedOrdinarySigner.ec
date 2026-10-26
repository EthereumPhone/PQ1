(* Whole actual signing preserves fresh-input canonicity or the explicit
   FORS exception, including header exhaustion and either refused WOTS layer. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10Randomizer C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawForest RawLayer RawSigner RoleGrind IndependentWidths NodeQueryDomain RawCompositeWidths SignerCoordinates.
require import AddressedOrdinaryInputs AddressedOrdinaryHistory AddressedOrdinaryForest AddressedOrdinaryLayer.
require import AddressedForsExceptionCount AddressedForestExceptionCount BuilderTotality AddressedCoordinateBounds.

lemma forest_sign_ordinary_valid seed0 ht0 digest0 old :
  hoare [RawForest(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ size seed0=32 /\ size shuffle=32 /\ 0<=ht0<2^64 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res.`3=16].
proof.
  exists* Independent.queries; elim* => queries.
  conseq (raw_forest_sign_ordinary_inputs seed0 ht0 digest0 old)
    (raw_forest_sign_exception_count (exceptional_fors_count queries)); smt().
qed.

lemma layer_sign_ordinary_width seed0 layer0 tree0 leaf0 message0 old :
  hoare [RawLayer(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ message=message0 /\
    0<=layer0<4294967296 /\ 0<=tree0<2^64 /\ 0<=leaf0<512 /\
    size seed0=32 /\ size message0=16 /\ size shuffle=32 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    (res<>None => size (oget res).`2=16)].
proof.
  conseq (raw_layer_sign_ordinary_inputs seed0 layer0 tree0 leaf0 message0 old)
    (raw_layer_width (PreparationView(Independent)) independent_hash_ll preparation_wots_ll); smt().
qed.

lemma raw_signer_finish_ordinary_inputs seed0 old :
  hoare [RawSigner(Independent).finish :
    seed=seed0 /\ size seed0=32 /\ size shuffle=32 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  exists* digest; elim* => digest0.
  proc; wp; while (seed=seed0 /\ size seed0=32 /\ size shuffle=32 /\
    size current=16 /\ 0<=layer<=2 /\ 0<=idx_tree<262144 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + exists* layer,idx_tree,current; elim* => l0 idx0 cur0.
    wp; call (layer_sign_ordinary_width seed0 l0 (idx0 %/ 512) (idx0 %% 512) cur0 old).
    auto; rewrite addressed_tree_field_cardinality; smt(addressed_signer_coordinate_bounds).
  wp; call (forest_sign_ordinary_valid seed0 (hypertree_index digest0) digest0 old).
  auto; rewrite addressed_tree_field_cardinality; smt(hypertree_index_range).
qed.

lemma ordinary_derive_new_valid old seed0 :
  hoare [Independent.derive :
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res=256].
proof. conseq (ordinary_derive_new_inputs old seed0) independent_derive_width; smt(). qed.

lemma role_grind_ordinary_inputs old seed0 :
  hoare [RoleGrind(Independent).run :
    size seed=32 /\ size root=32 /\ size message=32 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; while (size seed=32 /\ size root=32 /\ size message=32 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; call (ordinary_hash_new_valid old seed0); wp; call (ordinary_derive_new_valid old seed0).
    auto; smt(randomizer_width node_query_no_hmsg ordinary_public_nonnode size_cat size_nseq).
  auto.
qed.

lemma raw_signer_sign_ordinary_inputs seed0 old :
  hoare [RawSigner(Independent).sign :
    seed=seed0 /\ size seed0=32 /\ size root=32 /\ size message=32 /\ size shuffle=32 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; seq 1 : (seed=seed0 /\ size seed0=32 /\ size shuffle=32 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + call (role_grind_ordinary_inputs old seed0); auto.
  sp 1; if; last by auto.
  call (raw_signer_finish_ordinary_inputs seed0 old); auto.
qed.
