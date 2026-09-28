(* A previously generated Merkle root survives all later oracle-only builders. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle.
require import PersistentGrind AcceptedContexts MonotoneHistory WotsCatalogOracle.
require import MerkleRootWitness RawMerkleRootWitness.

module type MerkleBuilding (O : PreparationOracle) = {
  proc build(seed : raw_input, layer tree target : int) : raw_input list * raw_input { O.hash, O.wots }
}.

lemma merkle_builder_extends (B <: MerkleBuilding {-Independent}) s0 h0 :
  hoare [B(PreparationView(Independent)).build :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  + exact (independent_hash_extends s0 h0).
  exact (preparation_wots_extends s0 h0).
qed.

lemma merkle_build_keeps_root seed0 layer0 tree0 root0 :
  hoare [RawMerkle(PreparationView(Independent)).build :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (merkle_builder_extends RawMerkle s0 h0); smt(extends_refl merkle_root_witness_extends).
qed.

lemma merkle_build_matches_prior_root seed0 layer0 tree0 target0 root0 :
  hoare [RawMerkle(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ target=target0 /\ 0<=target0<512 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    res.`2=root0 /\ merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  conseq (merkle_build_records_root seed0 layer0 tree0 target0)
    (merkle_build_keeps_root seed0 layer0 tree0 root0); smt(merkle_root_witness_unique).
qed.
