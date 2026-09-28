(* Actual FORS and layer signatures retain byte-valued components. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawFors RawWots RawShuffle RawForest RawMerkle RawLayer RawWidths.
require import ByteSession RawByteValues RawWotsBytes RawTreeBytes.

lemma raw_forest_one_bytes (O <: PreparationOracle) :
  islossless O.hash => islossless O.fors =>
  hoare [RawForest(O).one : true ==>
    byte_values res.`1 /\ byte_rows res.`2 /\ byte_values res.`3].
proof.
  move=> hh hf; proc; call (raw_fors_recover_bytes O hh); call (raw_fors_sign_bytes O hh hf); auto.
qed.
lemma raw_forest_bytes (O <: PreparationOracle) :
  islossless O.hash => islossless O.fors =>
  hoare [RawForest(O).sign : true ==>
    byte_rows res.`1 /\ all byte_rows res.`2 /\ byte_values res.`3].
proof.
  move=> hh hf; proc; call (_ : true ==> true); first by conseq hh.
  wp; call (_ : true ==> true); first by conseq hh.
  wp; call (raw_fors_root_bytes O hh hf).
  while (byte_rows secrets /\ all byte_rows auths).
  + wp; call (raw_forest_one_bytes O hh hf); auto; smt(byte_rows_put all_put_preserved).
  wp; call (_ : true ==> true); first by conseq (shuffle_permutation_lossless O hh).
  call (_ : true ==> true); first by conseq (shuffle_derive_lossless O hh).
  auto; smt(all_nseq byte_rows_zeros byte_rows_put node_bytes).
qed.
lemma raw_layer_recover_bytes (O <: PreparationOracle) :
  islossless O.hash => hoare [RawLayer(O).recover : true ==> byte_values res].
proof.
  move=> hh; proc; call (raw_merkle_recover_bytes O hh).
  call (_ : true ==> true); first by conseq (raw_recover_lossless O hh).
  auto.
qed.
lemma raw_layer_bytes (O <: PreparationOracle) :
  islossless O.hash => islossless O.wots =>
  hoare [RawLayer(O).sign : true ==> res<>None => layer_bytes (oget res).`1 /\ byte_values (oget res).`2].
proof.
  move=> hh hw; proc; seq 3 : (byte_rows built.`1 /\ (signed<>None => byte_rows (oget signed).`1)).
  + call (raw_wots_signature_bytes O hh hw).
    call (_ : true ==> true); first by conseq (shuffle_derive_lossless O hh).
    call (raw_merkle_build_bytes O hh hw); auto.
  sp 1; if; last by auto.
  wp; call (raw_layer_recover_bytes O hh); auto; rewrite /layer_bytes; smt().
qed.
