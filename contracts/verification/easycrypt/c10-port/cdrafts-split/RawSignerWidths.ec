(* Successful shared-oracle signer outputs have the deployed wire width. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter.
require import PrefixGuess PrefixHybrid KeygenPrefixes PreparedGrind RoleGrind.
require import RawSigner RawSignature RawWidths RawCompositeWidths.

lemma raw_finish_width (O <: PrefixOracle) :
  islossless O.hash => islossless O.derive =>
  hoare[RawSigner(O).finish : size randomizer = 16 ==>
    res <> None => signature_width (oget res)].
proof.
  move=> hh hd; have [#] hvh hvw hvf := preparation_view_lossless O hh hd.
  proc; wp; while (0 <= layer <= 2 /\
    (ok => size layers = layer /\ all layer_width layers)).
  + wp; call (raw_layer_width (PreparationView(O)) hvh hvw); auto.
    smt(all_cat cats1 size_rcons).
  wp; call (raw_forest_width (PreparationView(O)) hvh hvf).
  auto; rewrite /signature_width; smt().
qed.

lemma role_physical_width :
  hoare[RoleGrind(Physical).run : valid_history Shared.history ==>
    valid_history Shared.history /\
    (res <> None => size (oget res).`1 = 16 /\ size (oget res).`2 = 256)].
proof.
  proc; while (valid_history Shared.history /\
    (result <> None => size (oget result).`1 = 16 /\ size (oget result).`2 = 256)).
  + seq 2 : (valid_history Shared.history /\ size r = 16 /\ result = None).
    - inline Physical.derive; wp; call hash_width; auto; smt(randomizer_width).
    wp; inline Physical.hash; wp; call hash_width; auto; smt().
  auto.
qed.

lemma physical_signer_width :
  hoare[RawSigner(Physical).sign : valid_history Shared.history ==>
    res <> None => signature_width (oget res)].
proof.
  proc; seq 1 : (accepted <> None => size (oget accepted).`1 = 16).
  + call role_physical_width; auto; smt().
  sp 1; if; last by auto.
  call (raw_finish_width Physical physical_hash_ll physical_derive_ll); auto.
qed.
lemma physical_signature_bytes :
  hoare[RawSigner(Physical).sign : valid_history Shared.history ==>
    res <> None => size (encode_signature (oget res)) = 4008].
proof. conseq physical_signer_width; smt(encoded_signature_width). qed.
