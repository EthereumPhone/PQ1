(* Composition over actual memo-table extensions. An old entry remains old;
   fresh ordinary entries are canonical or belong to the explicit exception. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest.
require import PersistentGrind AcceptedContexts IndependentWidths ForsComponentHistory ForestRootRecording.
require import AddressedOrdinaryInputs AddressedForsCanonicity AddressedForsFreshInputs.

lemma ordinary_public_nonnode h s seed x : !NodeQueryDomain.node_query x => ordinary_public_input h s seed x.
proof. rewrite /ordinary_public_input; smt(). qed.

lemma ordinary_public_short h s seed x : size x<64 => ordinary_public_input h s seed x.
proof. rewrite /ordinary_public_input; smt(). qed.

lemma ordinary_public_fors h s seed x : canonical_fors_input h s seed x => ordinary_public_input h s seed x.
proof. rewrite /ordinary_public_input /canonical_long_input; smt(). qed.

lemma ordinary_new_inputs_private_extends old h s s' seed :
  extends s s' => ordinary_new_inputs old h s seed => ordinary_new_inputs old h s' seed.
proof. rewrite /ordinary_new_inputs; smt(ordinary_public_input_extends extends_refl). qed.

lemma ordinary_new_inputs_from_fors old h s seed :
  canonical_fors_new_inputs old h s seed => ordinary_new_inputs old h s seed.
proof. rewrite /canonical_fors_new_inputs /ordinary_new_inputs; smt(ordinary_public_fors). qed.

lemma ordinary_hash_new_inputs old seed0 :
  hoare [Independent.hash :
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    (ordinary_public_input Independent.rawhistory Independent.secrethistory seed0 x \/
      AddressedForsException.exceptional_fors_query x) ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof. proc; sp 1; if; auto; smt(ordinary_new_inputs_insert). qed.

lemma ordinary_derive_new_inputs old seed0 :
  hoare [Independent.derive :
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof. proc; if; auto; smt(ordinary_new_inputs_private_extends extends_insert). qed.

lemma ordinary_hash_new_valid old seed0 :
  hoare [Independent.hash :
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    (ordinary_public_input Independent.rawhistory Independent.secrethistory seed0 x \/
      AddressedForsException.exceptional_fors_query x) /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size res=256].
proof. conseq (ordinary_hash_new_inputs old seed0) independent_hash_width; smt(). qed.

lemma ordinary_hash_new_records old seed0 x0 s0 h0 :
  hoare [Independent.hash :
    x=x0 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    (ordinary_public_input Independent.rawhistory Independent.secrethistory seed0 x \/
      AddressedForsException.exceptional_fors_query x) ==>
    Independent.rawhistory.[x0]=Some res /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof. conseq (ordinary_hash_new_inputs old seed0) (hash_records_histories x0 s0 h0); smt(). qed.

lemma ordinary_fors_one_new_inputs seed0 ht0 tree0 target0 old :
  hoare [RawForest(PreparationView(Independent)).one :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ leaf=target0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
    0<=target0<2048 /\ ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory,Independent.queries; elim* => h0 s0 q0.
  conseq (raw_forest_one_fresh_inputs seed0 ht0 tree0 target0 h0 q0) (fors_one_extends RawForest s0 h0);
    smt(extends_refl ordinary_new_inputs_from_fors ordinary_new_inputs_compose).
qed.

lemma ordinary_fors_root_new_inputs seed0 ht0 tree0 old :
  hoare [RawFors(PreparationView(Independent)).root :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory,Independent.queries; elim* => h0 s0 q0.
  conseq (raw_fors_root_fresh_inputs seed0 ht0 tree0 h0 q0) (fors_root_extends RawFors s0 h0);
    smt(extends_refl ordinary_new_inputs_from_fors ordinary_new_inputs_compose).
qed.
