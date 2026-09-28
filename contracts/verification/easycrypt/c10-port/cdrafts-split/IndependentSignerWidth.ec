(* Successful actual independent-oracle signatures satisfy the wire widths. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind PrefixGuess PrefixHybrid RoleGrind RawSigner RawSignature RawSignerWidths.
require import IndependentWidths.

lemma role_independent_width :
  hoare [RoleGrind(Independent).run :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    (res<>None => size (oget res).`1=16 /\ size (oget res).`2=256)].
proof.
  proc; while (independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    (result<>None => size (oget result).`1=16 /\ size (oget result).`2=256)).
  + seq 2 : (independent_tables_valid Independent.rawhistory Independent.secrethistory /\ size r=16 /\ result=None).
    - wp; call independent_derive_width; auto; smt(randomizer_width).
    wp; call independent_hash_width; auto; smt().
  auto.
qed.

lemma independent_signer_width :
  hoare [RawSigner(Independent).sign :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    res<>None => signature_width (oget res)].
proof.
  proc; seq 1 : (accepted<>None => size (oget accepted).`1=16).
  + call role_independent_width; auto; smt().
  sp 1; if; last by auto.
  call (raw_finish_width Independent independent_hash_ll independent_derive_ll); auto.
qed.
