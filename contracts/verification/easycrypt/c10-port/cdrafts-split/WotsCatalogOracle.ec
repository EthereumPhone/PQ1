(* Actual leaf construction and parent hashing preserve earlier WOTS leaves. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import PersistentGrind AcceptedContexts MonotoneHistory WotsCatalog WotsReferenceRoot.
require import RawWotsReference WotsReference WotsLeafReference.

module type KeygenLeaf (O : PreparationOracle) = {
  proc leaf(seed : raw_input, layer tree kp : int) : raw_input { O.hash, O.wots }
}.

lemma preparation_wots_extends s0 h0 :
  hoare [PreparationView(Independent).wots :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. proc; call (independent_derive_extends s0 h0); auto. qed.

lemma keygen_leaf_extends (K <: KeygenLeaf {-Independent}) s0 h0 :
  hoare [K(PreparationView(Independent)).leaf :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  exact (preparation_wots_extends s0 h0).
qed.

lemma hash_keeps_wots_catalog seed0 layer0 tree0 c :
  hoare [Independent.hash :
    wots_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 c ==>
    wots_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 c].
proof. proc; sp 1; if; auto; smt(wots_catalog_extends extends_insert extends_refl). qed.

lemma leaf_keeps_wots_catalog seed0 layer0 tree0 c :
  hoare [RawKeygen(PreparationView(Independent)).leaf :
    wots_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 c ==>
    wots_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 c].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (keygen_leaf_extends RawKeygen s0 h0); smt(extends_refl wots_catalog_extends).
qed.

lemma leaf_records_wots_catalog seed0 layer0 tree0 index0 c :
  hoare [RawKeygen(PreparationView(Independent)).leaf :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=index0 /\
    wots_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 c ==>
    wots_catalog Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 c /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 index0 res].
proof.
  conseq (raw_leaf_recorded seed0 layer0 tree0 index0) (leaf_keeps_wots_catalog seed0 layer0 tree0 c).
  + smt().
  rewrite /wots_root; smt().
qed.
