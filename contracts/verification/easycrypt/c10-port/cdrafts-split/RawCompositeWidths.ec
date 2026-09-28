require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawFors RawWots RawShuffle RawForest RawMerkle RawLayer.
require import RawSignature RawWidths RawTreeWidths.

lemma raw_forest_one_width (O <: PreparationOracle) :
  islossless O.hash => islossless O.fors =>
  hoare[RawForest(O).one : true ==>
    size res.`1 = 16 /\ rows_width 11 res.`2 /\ size res.`3 = 16].
proof.
  move=> hh hf; proc; call (raw_fors_recover_width O hh); call (raw_fors_sign_width O hh hf); auto.
qed.
lemma raw_forest_width (O <: PreparationOracle) :
  islossless O.hash => islossless O.fors =>
  hoare[RawForest(O).sign : true ==>
    rows_width 13 res.`1 /\ size res.`2 = 12 /\ all (rows_width 11) res.`2 /\ size res.`3 = 16].
proof.
  move=> hh hf; proc; call (_ : true ==> true); first by conseq hh.
  wp; call (_ : true ==> true); first by conseq hh.
  wp; call (raw_fors_root_width O hh hf).
  while (rows_width 13 secrets /\ size auths = 12 /\ all (rows_width 11) auths).
  + wp; call (raw_forest_one_width O hh hf); auto; smt(rows_put size_put all_put_preserved).
  wp; call (_ : true ==> true); first by conseq (shuffle_permutation_lossless O hh).
  call (_ : true ==> true); first by conseq (shuffle_derive_lossless O hh).
  auto; smt(all_nseq rows_zeros size_nseq rows_put node_width).
qed.
lemma raw_layer_recover_width (O <: PreparationOracle) :
  islossless O.hash => hoare[RawLayer(O).recover : true ==> size res = 16].
proof.
  move=> hh; proc; call (raw_merkle_recover_width O hh).
  call (_ : true ==> true); first by conseq (raw_recover_lossless O hh).
  auto.
qed.
lemma raw_layer_width (O <: PreparationOracle) :
  islossless O.hash => islossless O.wots =>
  hoare[RawLayer(O).sign : true ==> res <> None =>
    layer_width (oget res).`1 /\ size (oget res).`2 = 16].
proof.
  move=> hh hw; proc; seq 3 : (rows_width 9 built.`1 /\
    (signed <> None => rows_width 43 (oget signed).`1 /\ 0 <= (oget signed).`2 < signing_budget)).
  + call (raw_wots_signature_width O hh hw).
    call (_ : true ==> true); first by conseq (shuffle_derive_lossless O hh).
    call (raw_merkle_build_width O hh hw); auto.
  sp 1; if; last by auto.
  wp; call (raw_layer_recover_width O hh); auto; rewrite /layer_width /signing_budget; smt().
qed.
