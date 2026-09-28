(* Successful actual signatures encode to byte-valued lists. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind C10Bytes PrefixGuess PrefixHybrid KeygenPrefixes PreparedGrind RoleGrind RawKeygen RawSigner RawSignature.
require import ByteSession RawByteValues RawCompositeBytes ShuffleBytes.

lemma be_bytes n x : byte_values (be n x).
proof. rewrite /byte_values /be; apply shuffle_bytes_valid. qed.
lemma flatten_byte_rows rows : byte_rows rows => byte_values (flatten rows).
proof. elim: rows => [|x xs ih]; rewrite /byte_rows /byte_values /=; smt(all_cat). qed.
lemma encoded_layer_bytes (sig : RawLayer.layer_signature) :
  layer_bytes sig => byte_values (encode_layer sig).
proof.
  rewrite /layer_bytes /encode_layer /byte_values !all_cat;
    smt(flatten_byte_rows be_bytes).
qed.
lemma encoded_signature_bytes (sig : raw_signature) :
  signature_bytes sig => byte_values (encode_signature sig).
proof.
  rewrite /signature_bytes; move=> [hr [hs [ha hl]]].
  have hba : byte_rows (map flatten sig.`3).
  + rewrite /byte_rows; apply/allP=> x /mapP [row [hin ->]]; apply flatten_byte_rows; smt(allP).
  have hbl : byte_rows (map encode_layer sig.`4).
  + rewrite /byte_rows; apply/allP=> x /mapP [row [hin ->]]; apply encoded_layer_bytes; smt(allP).
  have hf := flatten_byte_rows sig.`2 hs.
  have hfa := flatten_byte_rows (map flatten sig.`3) hba.
  have hfl := flatten_byte_rows (map encode_layer sig.`4) hbl.
  move: hr hf hfa hfl; rewrite /encode_signature /byte_values !all_cat; smt().
qed.

lemma raw_finish_bytes (O <: PrefixOracle) :
  islossless O.hash => islossless O.derive =>
  hoare [RawSigner(O).finish : byte_values randomizer ==> res<>None => signature_bytes (oget res)].
proof.
  move=> hh hd; have [#] hvh hvw hvf := preparation_view_lossless O hh hd.
  proc; wp; while (ok => all layer_bytes layers).
  + wp; call (raw_layer_bytes (PreparationView(O)) hvh hvw); auto; smt(all_cat cats1).
  wp; call (raw_forest_bytes (PreparationView(O)) hvh hvf).
  auto; rewrite /signature_bytes; smt().
qed.
lemma raw_grind_bytes (O <: PrefixOracle) :
  islossless O.hash => islossless O.derive =>
  hoare [RoleGrind(O).run : true ==> res<>None => byte_values (oget res).`1].
proof.
  move=> hh hd; proc; while (result<>None => byte_values (oget result).`1).
  + wp; call (_ : true ==> true); first by conseq hh.
    wp; call (_ : true ==> true); first by conseq hd.
    auto; smt(compact_bytes).
  auto.
qed.
lemma raw_signer_bytes (O <: PrefixOracle) :
  islossless O.hash => islossless O.derive =>
  hoare [RawSigner(O).sign : true ==> res<>None => signature_bytes (oget res)].
proof.
  move=> hh hd; proc; seq 1 : (accepted<>None => byte_values (oget accepted).`1).
  + call (raw_grind_bytes O hh hd); auto.
  sp 1; if; last by auto.
  call (raw_finish_bytes O hh hd); auto.
qed.
