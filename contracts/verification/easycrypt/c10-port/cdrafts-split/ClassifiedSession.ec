(* External Q2 research: live adaptive sessions have no partially used
   signing context at call boundaries. Failed signing is sticky. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawSigner FullSession ByteSession VerifierHistory.
require import ClassifiedHistory ClassifiedGrind ClassifiedSigner.

op live_classified s h seed root failed =
  !failed => classified_history s h seed root.

lemma full_hash_classified :
  hoare[FullSession(Independent).hash :
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed ==>
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* FullSession.failed, FullSession.seed, FullSession.root; elim* => failed0 seed0 root0.
  case failed0.
  + call (_ : true ==> true); first by trivial.
    auto; rewrite /live_classified; smt().
  call (hash_keeps_classified seed0 root0); auto; rewrite /live_classified; smt().
qed.

lemma full_sign_classified :
  hoare[FullSession(Independent).sign :
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed ==>
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed].
proof.
  proc; sp 1; if; last by auto.
  wp; exists* FullSession.seed, FullSession.root; elim* => seed0 root0.
  call (signer_sign_classified seed0 root0); auto; rewrite /live_classified; smt().
qed.

lemma full_client_classified (A <: FullClient {-FullSession,-Independent}) :
  hoare[A(FullSession(Independent)).run :
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed ==>
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed].
proof.
  proc (live_classified Independent.secrethistory Independent.rawhistory
    FullSession.seed FullSession.root FullSession.failed) => //.
  + exact full_hash_classified.
  exact full_sign_classified.
qed.

lemma public_verifier_classified (V <: PublicVerifier {-Independent}) seed0 root0 :
  hoare[V(Independent).verify :
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0 ==>
    classified_history Independent.secrethistory Independent.rawhistory seed0 root0].
proof.
  proc (classified_history Independent.secrethistory Independent.rawhistory seed0 root0) => //.
  exact (hash_keeps_classified seed0 root0).
qed.

lemma full_driver_classified (A <: FullClient {-FullSession,-Independent}) :
  hoare[FullDriver(A,Independent).run : no_r_tails Independent.secrethistory ==>
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed].
proof.
  proc; seq 2 : (live_classified Independent.secrethistory Independent.rawhistory
    FullSession.seed FullSession.root FullSession.failed).
  + call (full_client_classified A); inline FullSession(Independent).init;
      auto; rewrite /live_classified; smt(no_r_classified).
  sp 1; if; last by auto.
  exists* FullSession.seed, FullSession.root; elim* => seed0 root0.
  call (public_verifier_classified RawSigner seed0 root0); auto; rewrite /live_classified; smt().
qed.

lemma full_context_classified (A <: FullClient {-FullSession,-Independent}) :
  hoare[FullContext(A,Independent).run : no_r_tails Independent.secrethistory ==>
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed].
proof.
  proc; call (full_driver_classified A).
  call (preparation_preserves_no_r KeygenPreparation); auto.
qed.

lemma full_game_classified (A <: FullClient {-FullSession,-Independent}) :
  hoare[IndependentGame(FullContext(A)).run : true ==>
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed].
proof.
  proc; call (full_context_classified A); inline Independent.init;
    auto; rewrite /no_r_tails; smt(mem_empty).
qed.

lemma byte_client_classified (A <: ByteClient {-FullSession,-Independent}) :
  hoare[A(ByteView(FullSession(Independent))).run :
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed ==>
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed].
proof.
  proc (live_classified Independent.secrethistory Independent.rawhistory
    FullSession.seed FullSession.root FullSession.failed) => //.
  + exact full_hash_classified.
  proc; sp 1; if; last by auto.
  wp; call full_sign_classified; auto.
qed.

lemma byte_driver_classified (A <: ByteClient {-FullSession,-Independent}) :
  hoare[ByteDriver(A,Independent).run : no_r_tails Independent.secrethistory ==>
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed].
proof.
  proc; seq 2 : (live_classified Independent.secrethistory Independent.rawhistory
    FullSession.seed FullSession.root FullSession.failed).
  + call (byte_client_classified A); inline FullSession(Independent).init;
      auto; rewrite /live_classified; smt(no_r_classified).
  sp 1; if; last by auto.
  exists* FullSession.seed, FullSession.root; elim* => seed0 root0.
  call (public_verifier_classified RawSigner seed0 root0); auto; rewrite /live_classified; smt().
qed.

lemma byte_context_classified (A <: ByteClient {-FullSession,-Independent}) :
  hoare[ByteContext(A,Independent).run : no_r_tails Independent.secrethistory ==>
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed].
proof.
  proc; call (byte_driver_classified A).
  call (preparation_preserves_no_r KeygenPreparation); auto.
qed.

lemma byte_game_classified (A <: ByteClient {-FullSession,-Independent}) :
  hoare[IndependentGame(ByteContext(A)).run : true ==>
    live_classified Independent.secrethistory Independent.rawhistory
      FullSession.seed FullSession.root FullSession.failed].
proof.
  proc; call (byte_context_classified A); inline Independent.init;
    auto; rewrite /no_r_tails; smt(mem_empty).
qed.
