(* Actual Merkle builders and key-generation roots preserve the ordinary
   fresh-input classification, including arbitrary existing memo contents. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle.
require import PersistentGrind AcceptedContexts MonotoneHistory IndependentWidths WotsCatalogOracle MerkleRootPersistence.
require import AddressedQueryProvenance AddressedTreeLog AddressedMerkleTreeQueries AddressedOrdinaryInputs.

lemma ordinary_public_tree h s seed x : canonical_tree_input h s seed x => ordinary_public_input h s seed x.
proof. rewrite /ordinary_public_input /canonical_long_input; smt(). qed.

lemma ordinary_new_inputs_from_tree_log old base h s seed queries :
  appended_query_history old base h queries => canonical_tree_log h s seed base queries =>
  ordinary_new_inputs old h s seed.
proof.
  move=> hp [inputs [hq hi]] x hx; case (x \in old) => ho; first smt().
  have hm := appended_query_history_member old base h queries inputs x hp hq hx ho.
  move: hi; rewrite allP; smt(ordinary_public_tree).
qed.

lemma wots_appended_query_history old base :
  hoare [PreparationView(Independent).wots : appended_query_history old base Independent.rawhistory Independent.queries ==>
    appended_query_history old base Independent.rawhistory Independent.queries].
proof. proc; call (derive_appended_query_history old base); auto. qed.

lemma keygen_root_appended_query_history (K <: WidthKeygen {-Independent}) old base :
  hoare [K(PreparationView(Independent)).root : appended_query_history old base Independent.rawhistory Independent.queries ==>
    appended_query_history old base Independent.rawhistory Independent.queries].
proof.
  proc (appended_query_history old base Independent.rawhistory Independent.queries) => //.
  + exact (hash_appended_query_history old base).
  exact (wots_appended_query_history old base).
qed.

lemma merkle_build_appended_query_history (B <: MerkleBuilding {-Independent}) old base :
  hoare [B(PreparationView(Independent)).build : appended_query_history old base Independent.rawhistory Independent.queries ==>
    appended_query_history old base Independent.rawhistory Independent.queries].
proof.
  proc (appended_query_history old base Independent.rawhistory Independent.queries) => //.
  + exact (hash_appended_query_history old base).
  exact (wots_appended_query_history old base).
qed.

lemma keygen_root_histories_extend (K <: WidthKeygen {-Independent}) s0 h0 :
  hoare [K(PreparationView(Independent)).root :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  exact (preparation_wots_extends s0 h0).
qed.

lemma raw_keygen_root_fresh_inputs seed0 layer0 tree0 old base :
  hoare [RawKeygen(PreparationView(Independent)).root :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=layer0<4294967296 /\ 0<=tree0<2^64 /\
    Independent.rawhistory=old /\ Independent.queries=base ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof.
  conseq (raw_keygen_root_canonical_queries seed0 layer0 tree0 base)
    (keygen_root_appended_query_history RawKeygen old base);
    smt(canonical_tree_log_empty appended_query_history_initial ordinary_new_inputs_from_tree_log).
qed.

lemma raw_merkle_build_fresh_inputs seed0 layer0 tree0 old base :
  hoare [RawMerkle(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=layer0<4294967296 /\ 0<=tree0<2^64 /\
    Independent.rawhistory=old /\ Independent.queries=base ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof.
  conseq (raw_merkle_build_canonical_queries seed0 layer0 tree0 base)
    (merkle_build_appended_query_history RawMerkle old base);
    smt(canonical_tree_log_empty appended_query_history_initial ordinary_new_inputs_from_tree_log).
qed.

lemma ordinary_merkle_build_new_inputs seed0 layer0 tree0 old :
  hoare [RawMerkle(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=layer0<4294967296 /\ 0<=tree0<2^64 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory,Independent.queries; elim* => h0 s0 q0.
  conseq (raw_merkle_build_fresh_inputs seed0 layer0 tree0 h0 q0) (merkle_builder_extends RawMerkle s0 h0);
    smt(extends_refl ordinary_new_inputs_compose).
qed.

lemma ordinary_keygen_root_new_inputs seed0 layer0 tree0 old :
  hoare [RawKeygen(PreparationView(Independent)).root :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=layer0<4294967296 /\ 0<=tree0<2^64 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory,Independent.queries; elim* => h0 s0 q0.
  conseq (raw_keygen_root_fresh_inputs seed0 layer0 tree0 h0 q0) (keygen_root_histories_extend RawKeygen s0 h0);
    smt(extends_refl ordinary_new_inputs_compose).
qed.
