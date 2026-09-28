(* A costed, same-adversary reduction for the complete structured signing game.
   The remaining IndependentGame forgery probability is NOT replaced by a
   numerical security estimate here. Uniform secret/classical oracle only. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal PrefixState.
require import KeygenPrefixes KeygenExhaustion FullSession FullSessionCost.

op full_public_budget qr qs = 155135+qr+qs*(3*signing_budget+364892)+771.
op full_physical_budget qr qs = 177151+qr+qs*(4*signing_budget+435646)+771.

lemma full_physical_game_cost
  (A <: FullClient {-FullSession,-FullLimits,-Physical,-Shared}) qr qs :
  0 <= qr => 0 <= qs =>
  hoare[RealGame(FullContext(A)).run : FullLimits.raw_cap = qr /\ FullLimits.sign_cap = qs ==>
    Shared.calls <= full_physical_budget qr qs].
proof.
  move=> hqr hqs; proc; call (full_context_physical_cost A qr qs hqr hqs).
  inline Shared.init; auto; rewrite /full_physical_budget; smt().
qed.

lemma full_physical_to_independent
  (A <: FullClient {-FullSession,-FullLimits,-Physical,-Hybrid,-Shared,-Independent}) qr qs &m :
  (forall (V <: FullClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0 <= qr => 0 <= qs => FullLimits.raw_cap{m} = qr => FullLimits.sign_cap{m} = qs =>
  Pr[RealGame(FullContext(A)).run() @ &m : res] <=
    Pr[IndependentGame(FullContext(A)).run() @ &m : res] +
    (full_public_budget qr qs)%r * (1%r/2%r)^256.
proof.
  move=> ha hqr hqs hraw hsign.
  have hll : forall (O <: PrefixOracle {-FullContext(A)}),
    islossless O.hash => islossless O.derive => islossless FullContext(A,O).run.
  + move=> O hh hd; exact (full_context_lossless A O ha hh hd).
  have hq : 0 <= full_public_budget qr qs by rewrite /full_public_budget /signing_budget; smt().
  have hb : hoare[FullContext(A,Independent).run : Independent.queries = [] /\
    (glob FullContext(A)) = (glob FullContext(A)){m} ==>
    size Independent.queries <= full_public_budget qr qs].
  + conseq (full_context_public_cost A qr qs hqr hqs); auto; rewrite /full_public_budget; smt().
  exact (physical_to_independent_at_state (FullContext(A)) (full_public_budget qr qs) &m hll hq hb).
qed.
