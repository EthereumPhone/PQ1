(* External Q research: a real-byte-game hop to the same client's independent
   game with a public digest-prefix collision monitor. The remaining
   collision-free forgery term is explicit and is NOT a numerical EUF bound. *)
require import AllCore List Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion FullSession FullSessionCost FullPrefix.
require import ByteSession ByteBound PrefixAudit AuditPrefix AuditComplete.
import RealOrder.

lemma byte_audited_hop
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Physical,-Hybrid,-Shared,
    -Independent,-PrefixAudit,-AuditedIndependent}) n qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign =>
    islossless A(V).run) =>
  0 <= n <= 256 => 0 <= qr => 0 <= qs =>
  FullLimits.raw_cap{m} = qr => FullLimits.sign_cap{m} = qs =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <=
    Pr[AuditedGame(ByteContext(A)).run(n,full_public_budget qr qs) @ &m :
      res /\ !PrefixAudit.bad] +
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r / 2%r * (1%r/2%r)^n +
    (full_public_budget qr qs)%r * (1%r/2%r)^256.
proof.
  move=> ha hn hr hs hraw hsign.
  have hq : 0 <= full_public_budget qr qs by rewrite /full_public_budget /signing_budget; smt().
  have hp := byte_physical_to_independent A qr qs &m ha hr hs hraw hsign.
  have he := audited_game_observation (ByteContext(A)) n (full_public_budget qr qs) &m.
  have hc := audited_prefix_collision (ByteContext(A)) n (full_public_budget qr qs) &m hn hq.
  have hsplit : Pr[AuditedGame(ByteContext(A)).run(n,full_public_budget qr qs) @ &m : res] <=
    Pr[AuditedGame(ByteContext(A)).run(n,full_public_budget qr qs) @ &m : res /\ !PrefixAudit.bad] +
    Pr[AuditedGame(ByteContext(A)).run(n,full_public_budget qr qs) @ &m : PrefixAudit.bad].
  + rewrite Pr[mu_split !PrefixAudit.bad]; apply ler_add => //.
    by rewrite Pr[mu_sub]; smt().
  smt().
qed.

lemma independent_byte_cost
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-Physical}) qr qs :
  0 <= qr => 0 <= qs =>
  hoare[IndependentGame(ByteContext(A)).run :
    FullLimits.raw_cap = qr /\ FullLimits.sign_cap = qs ==>
    size Independent.queries <= full_public_budget qr qs].
proof.
  move=> hr hs; proc.
  call (_ : FullLimits.raw_cap = qr /\ FullLimits.sign_cap = qs /\
    Independent.queries = [] ==> size Independent.queries <= full_public_budget qr qs).
  + conseq (byte_context_equiv A Independent)
      (full_context_public_cost (ByteLift(A)) qr qs hr hs).
    - move=> &m hm; exists (glob A){m} qr qs KeygenInputs.message{m} KeygenInputs.public_seed{m}
        KeygenInputs.random{m} [] Independent.rawhistory{m} Independent.secrethistory{m}; smt().
    by rewrite /full_public_budget; smt().
  by inline Independent.init; auto.
qed.

lemma audited_byte_cost_at_state
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-Physical,
    -PrefixAudit,-AuditedIndependent}) qr qs &m :
  0 <= qr => 0 <= qs => FullLimits.raw_cap{m} = qr => FullLimits.sign_cap{m} = qs =>
  hoare[AuditedGame(ByteContext(A)).run :
    (glob ByteContext(A)) = (glob ByteContext(A)){m} ==>
    size AuditedIndependent.queries <= full_public_budget qr qs].
proof.
  move=> hr hs hraw hsign.
  apply (audited_game_hoare (ByteContext(A))
    (fun g => g = (glob ByteContext(A)){m})
    (fun queries => size queries <= full_public_budget qr qs)).
  conseq (independent_byte_cost A qr qs hr hs); auto; smt().
qed.

lemma audited_byte_complete_at_state
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent,-Physical,
    -PrefixAudit,-AuditedIndependent}) n0 qr qs &m :
  0 <= qr => 0 <= qs => FullLimits.raw_cap{m} = qr => FullLimits.sign_cap{m} = qs =>
  hoare[AuditedGame(ByteContext(A)).run :
    (glob ByteContext(A)) = (glob ByteContext(A)){m} /\ n = n0 /\ q = full_public_budget qr qs ==>
    !PrefixAudit.bad => prefixes_unique n0 PrefixAudit.history].
proof.
  move=> hr hs hraw hsign.
  have hq : 0 <= full_public_budget qr qs by rewrite /full_public_budget /signing_budget; smt().
  conseq (audited_byte_cost_at_state A qr qs &m hr hs hraw hsign)
    (audited_game_complete (ByteContext(A)) n0 (full_public_budget qr qs) hq); smt().
qed.

lemma byte_prefix_unique_hop
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Physical,-Hybrid,-Shared,
    -Independent,-PrefixAudit,-AuditedIndependent}) n0 qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign =>
    islossless A(V).run) =>
  0 <= n0 <= 256 => 0 <= qr => 0 <= qs =>
  FullLimits.raw_cap{m} = qr => FullLimits.sign_cap{m} = qs =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <=
    Pr[AuditedGame(ByteContext(A)).run(n0,full_public_budget qr qs) @ &m :
      res /\ prefixes_unique n0 PrefixAudit.history] +
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r / 2%r * (1%r/2%r)^n0 +
    (full_public_budget qr qs)%r * (1%r/2%r)^256.
proof.
  move=> ha hn hr hs hraw hsign.
  have hp := byte_audited_hop A n0 qr qs &m ha hn hr hs hraw hsign.
  have hz : Pr[AuditedGame(ByteContext(A)).run(n0,full_public_budget qr qs) @ &m :
    !PrefixAudit.bad /\ !prefixes_unique n0 PrefixAudit.history] = 0%r.
  + byphoare (_ : (glob ByteContext(A)) = (glob ByteContext(A)){m} /\
      n = n0 /\ q = full_public_budget qr qs ==>
      !PrefixAudit.bad /\ !prefixes_unique n0 PrefixAudit.history) => //.
    hoare; conseq (audited_byte_complete_at_state A n0 qr qs &m hr hs hraw hsign); smt().
  have hsub : Pr[AuditedGame(ByteContext(A)).run(n0,full_public_budget qr qs) @ &m :
      res /\ !PrefixAudit.bad] <=
    Pr[AuditedGame(ByteContext(A)).run(n0,full_public_budget qr qs) @ &m :
      res /\ prefixes_unique n0 PrefixAudit.history] +
    Pr[AuditedGame(ByteContext(A)).run(n0,full_public_budget qr qs) @ &m :
      !PrefixAudit.bad /\ !prefixes_unique n0 PrefixAudit.history].
  + rewrite Pr[mu_split (prefixes_unique n0 PrefixAudit.history)]; apply ler_add;
      by rewrite Pr[mu_sub]; smt().
  smt().
qed.
