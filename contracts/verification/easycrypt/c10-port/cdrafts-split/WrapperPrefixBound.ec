(* Same adaptive wrapper client in the physical and independent ideal-oracle
   games. Charge both sign passes and all verification, including withheld
   outputs. This hop leaves the independent forgery probability explicit. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal PrefixState.
require import KeygenPrefixes KeygenExhaustion RawWrapperCost WrapperSession WrapperSessionCost.
require import WrapperLossless WrapperByteSession.

op wrapper_total_public_budget qr qs = 155135+qr+qs*wrapper_public_budget+771.
op wrapper_total_physical_budget qr qs = 177151+qr+qs*wrapper_physical_budget+771.

lemma wrapper_physical_game_cost
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-Physical,-Shared}) qr qs :
  0 <= qr => 0 <= qs =>
  hoare[RealGame(WrapperContext(A)).run : WrapperLimits.raw_cap = qr /\ WrapperLimits.sign_cap = qs ==>
    Shared.calls <= wrapper_total_physical_budget qr qs].
proof.
  move=> hqr hqs; proc; call (wrapper_context_physical_cost A qr qs hqr hqs).
  inline Shared.init; auto; rewrite /wrapper_total_physical_budget; smt().
qed.

lemma wrapper_physical_to_independent
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-Physical,-Hybrid,-Shared,-Independent}) qr qs &m :
  (forall (V <: WrapperClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0 <= qr => 0 <= qs => WrapperLimits.raw_cap{m} = qr => WrapperLimits.sign_cap{m} = qs =>
  Pr[RealGame(WrapperContext(A)).run() @ &m : res] <=
    Pr[IndependentGame(WrapperContext(A)).run() @ &m : res] +
    (wrapper_total_public_budget qr qs)%r * (1%r/2%r)^256.
proof.
  move=> ha hqr hqs hraw hsign.
  have hll : forall (O <: PrefixOracle {-WrapperContext(A)}),
    islossless O.hash => islossless O.derive => islossless WrapperContext(A,O).run.
  + move=> O hh hd; exact (wrapper_context_lossless A O ha hh hd).
  have hq : 0 <= wrapper_total_public_budget qr qs by rewrite /wrapper_total_public_budget /wrapper_public_budget /signing_budget; smt().
  have hb : hoare[WrapperContext(A,Independent).run : Independent.queries = [] /\
    (glob WrapperContext(A)) = (glob WrapperContext(A)){m} ==>
    size Independent.queries <= wrapper_total_public_budget qr qs].
  + conseq (wrapper_context_public_cost A qr qs hqr hqs); auto; rewrite /wrapper_total_public_budget; smt().
  exact (physical_to_independent_at_state (WrapperContext(A)) (wrapper_total_public_budget qr qs) &m hll hq hb).
qed.

lemma real_wrapper_byte_structured
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Physical,-Shared}) &m :
  Pr[RealGame(WrapperByteContext(A)).run() @ &m : res] =
  Pr[RealGame(WrapperContext(WrapperByteLift(A))).run() @ &m : res].
proof.
  byequiv (_ : ={glob A,glob WrapperLimits,glob KeygenInputs} ==> ={res}) => //.
  proc; call (wrapper_byte_context_equiv A Physical); inline Shared.init; auto.
qed.
lemma independent_wrapper_byte_structured
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Independent}) &m :
  Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : res] =
  Pr[IndependentGame(WrapperContext(WrapperByteLift(A))).run() @ &m : res].
proof.
  byequiv (_ : ={glob A,glob WrapperLimits,glob KeygenInputs} ==> ={res}) => //.
  proc; call (wrapper_byte_context_equiv A Independent); inline Independent.init; auto.
qed.
lemma wrapper_byte_physical_to_independent
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Physical,-Hybrid,-Shared,-Independent}) qr qs &m :
  (forall (V <: WrapperByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0 <= qr => 0 <= qs => WrapperLimits.raw_cap{m} = qr => WrapperLimits.sign_cap{m} = qs =>
  Pr[RealGame(WrapperByteContext(A)).run() @ &m : res] <=
    Pr[IndependentGame(WrapperByteContext(A)).run() @ &m : res] +
    (wrapper_total_public_budget qr qs)%r * (1%r/2%r)^256.
proof.
  move=> ha hqr hqs hraw hsign.
  rewrite (real_wrapper_byte_structured A &m) (independent_wrapper_byte_structured A &m).
  apply (wrapper_physical_to_independent (WrapperByteLift(A)) qr qs &m) => //.
  move=> V hh hs; exact (wrapper_byte_lift_lossless A V ha hh hs).
qed.

lemma wrapper_byte_context_public_cost
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-Independent,-Physical}) qr qs :
  0<=qr => 0<=qs =>
  hoare [WrapperByteContext(A,Independent).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\ Independent.queries=[] ==>
    size Independent.queries<=wrapper_total_public_budget qr qs].
proof.
  move=> hr hs.
  conseq (wrapper_byte_context_equiv A Independent)
    (wrapper_context_public_cost (WrapperByteLift(A)) qr qs hr hs).
  + move=> &m hm; smt().
  by rewrite /wrapper_total_public_budget; smt().
qed.

