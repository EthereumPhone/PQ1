(* Width of successful fixed-backend outputs, discharged from actual calls.
   No successful-search premise is added to the signer contract. *)
require import AllCore List.
require import C10RawOracle C10RawGrind RoleGrind RawSigner RawSignature RawSignerWidths.
require import C10FixedBackend C10FixedCallerBridge.

lemma fixed_functional_derive_width f :
  hoare[FixedPrefix.derive :
    FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\ backend_width f ==>
    FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\ size res = 256].
proof. proc; call (fixed_hash_width f); auto. qed.

lemma fixed_functional_header_width f :
  hoare[RoleGrind(FixedPrefix).run :
    FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\ backend_width f ==>
    FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    (res <> None => size (oget res).`1 = 16 /\ size (oget res).`2 = 256)].
proof.
  proc; while (FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\ backend_width f /\
    (result <> None => size (oget result).`1 = 16 /\ size (oget result).`2 = 256)).
  + seq 2 : (FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\ backend_width f /\
      size r = 16 /\ result = None).
    - wp; call (fixed_functional_derive_width f); auto; smt(randomizer_width).
    wp; call (fixed_hash_width f); auto; smt().
  auto.
qed.

lemma raw_functional_signer_width f :
  hoare[RawSigner(FixedPrefix).sign :
    FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\ backend_width f ==>
    res <> None => signature_width (oget res)].
proof.
  proc; seq 1 : (accepted <> None => size (oget accepted).`1 = 16).
  + call (fixed_functional_header_width f); auto; smt().
  sp 1; if; last by auto.
  call (raw_finish_width FixedPrefix fixed_hash_ll fixed_derive_ll); auto.
qed.
