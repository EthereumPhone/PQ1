(* Exact message-list projection and successful-output count, including repeats. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid RawSigner FullSession ExposureLog.

op exposure_messages (entries : signing_exposure list) = map (fun (entry : signing_exposure) => entry.`1) entries.
op exposure_accounting entries messages calls limit =
  exposure_messages entries=messages /\ size entries<=calls /\ 0<=calls<=limit.

lemma exposure_messages_rcons entries message signature :
  exposure_messages (rcons entries (message,signature)) = rcons (exposure_messages entries) message.
proof. by rewrite /exposure_messages map_rcons. qed.
lemma exposure_new_message entries message :
  !List.mem (exposure_messages entries) message =
  (forall signature, !List.mem entries (message,signature)).
proof. rewrite /exposure_messages; smt(mapP). qed.

lemma exposure_hash_accounting (O <: PrefixOracle {-FullSession,-ExposureLog}) :
  hoare [ExposureSession(O).hash :
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls FullSession.sign_limit ==>
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls FullSession.sign_limit].
proof. proc; sp 1; if; auto; wp; call (_ : true ==> true); first by trivial. auto. qed.

lemma exposure_sign_accounting (O <: PrefixOracle {-FullSession,-ExposureLog}) :
  hoare [ExposureSession(O).sign :
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls FullSession.sign_limit ==>
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls FullSession.sign_limit].
proof.
  proc; inline FullSession(O).sign; wp; sp 4; if.
  + wp; call (_ : true ==> true); first by trivial.
    auto; rewrite /exposure_accounting; smt(exposure_messages_rcons size_rcons).
  auto; rewrite /exposure_accounting; smt().
qed.

lemma exposure_client_accounting
  (A <: FullClient {-FullSession,-ExposureLog}) (O <: PrefixOracle {-A,-FullSession,-ExposureLog}) :
  hoare [A(ExposureSession(O)).run :
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls FullSession.sign_limit ==>
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls FullSession.sign_limit].
proof.
  proc (exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls FullSession.sign_limit) => //.
  + exact (exposure_hash_accounting O).
  exact (exposure_sign_accounting O).
qed.
