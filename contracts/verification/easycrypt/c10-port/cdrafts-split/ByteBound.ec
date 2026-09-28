(* Exact byte/structured game transfer and its costed secret-prefix bound. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion FullSession FullPrefix ByteSession.

lemma real_byte_structured
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Physical,-Shared}) &m :
  Pr[RealGame(ByteContext(A)).run() @ &m : res] =
  Pr[RealGame(FullContext(ByteLift(A))).run() @ &m : res].
proof.
  byequiv (_ : ={glob A,glob FullLimits,glob KeygenInputs} ==> ={res}) => //.
  proc; call (byte_context_equiv A Physical); inline Shared.init; auto.
qed.
lemma independent_byte_structured
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) &m :
  Pr[IndependentGame(ByteContext(A)).run() @ &m : res] =
  Pr[IndependentGame(FullContext(ByteLift(A))).run() @ &m : res].
proof.
  byequiv (_ : ={glob A,glob FullLimits,glob KeygenInputs} ==> ={res}) => //.
  proc; call (byte_context_equiv A Independent); inline Independent.init; auto.
qed.
lemma byte_physical_to_independent
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Physical,-Hybrid,-Shared,-Independent}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0 <= qr => 0 <= qs => FullLimits.raw_cap{m} = qr => FullLimits.sign_cap{m} = qs =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <=
    Pr[IndependentGame(ByteContext(A)).run() @ &m : res] +
    (full_public_budget qr qs)%r * (1%r/2%r)^256.
proof.
  move=> ha hqr hqs hraw hsign.
  rewrite (real_byte_structured A &m) (independent_byte_structured A &m).
  apply (full_physical_to_independent (ByteLift(A)) qr qs &m) => //.
  move=> V hh hs; exact (byte_lift_lossless A V ha hh hs).
qed.
