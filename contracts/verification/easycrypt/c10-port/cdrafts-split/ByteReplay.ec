(* External Q research: costed exact-coordinate replay branch only.
   The residual forgery term includes adaptive combination of FORS openings. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Counter C10HashDomains C10RawGrind RawForest PrefixGuess PrefixHybrid PrefixGames PrefixIdeal.
require import KeygenPrefixes KeygenExhaustion FullSession FullSessionCost FullPrefix.
require import ByteSession ByteBound PrefixAudit AuditPrefix AuditComplete ByteAudit DigestCoordinates.
import RealOrder.

lemma hmsg_message_injective (seed root r1 r2 m1 m2 : raw_input) :
  size r1 = size r2 =>
  hmsg_input seed root r1 m1 = hmsg_input seed root r2 m2 => m1 = m2.
proof.
  rewrite /hmsg_input => hs he.
  have hh := catIs _ _ (nseq 32 255) he.
  have hd : drop (size (seed ++ root ++ r1)) ((seed ++ root ++ r1) ++ m1) =
    drop (size (seed ++ root ++ r1)) ((seed ++ root ++ r2) ++ m2) by rewrite hh.
  have h1 : drop (size (seed ++ root ++ r1)) ((seed ++ root ++ r1) ++ m1) = m1
    by apply drop_size_cat.
  have h2 : drop (size (seed ++ root ++ r1)) ((seed ++ root ++ r2) ++ m2) = m2.
  + apply drop_size_cat; rewrite !size_cat; smt().
  smt().
qed.

lemma different_message_coordinates h seed root r1 r2 m1 m2 u v :
  accepted_coordinates_unique h => size r1 = size r2 => m1 <> m2 =>
  h.[hmsg_input seed root r1 m1] = Some u =>
  h.[hmsg_input seed root r2 m2] = Some v =>
  size u = 256 => size v = 256 => accept_digest u => accept_digest v =>
  !((forall t, 0 <= t < 12 => forest_index u t = forest_index v t) /\
    hypertree_index u = hypertree_index v).
proof.
  rewrite /accepted_coordinates_unique => hp hr hm hu hv hsu hsv hau hav.
  have hi := hmsg_message_injective seed root r1 r2 m1 m2 hr.
  smt().
qed.

lemma byte_coordinate_replay_hop
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Physical,-Hybrid,-Shared,
    -Independent,-PrefixAudit,-AuditedIndependent}) qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign =>
    islossless A(V).run) =>
  0 <= qr => 0 <= qs =>
  FullLimits.raw_cap{m} = qr => FullLimits.sign_cap{m} = qs =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <=
    Pr[AuditedGame(ByteContext(A)).run(161,full_public_budget qr qs) @ &m :
      res /\ accepted_coordinates_unique PrefixAudit.history] +
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r / 2%r * (1%r/2%r)^161 +
    (full_public_budget qr qs)%r * (1%r/2%r)^256.
proof.
  move=> ha hr hs hraw hsign.
  have hn : 0 <= 161 <= 256 by smt().
  have hp := byte_prefix_unique_hop A 161 qr qs &m ha hn hr hs hraw hsign.
  have hsub : Pr[AuditedGame(ByteContext(A)).run(161,full_public_budget qr qs) @ &m :
      res /\ prefixes_unique 161 PrefixAudit.history] <=
    Pr[AuditedGame(ByteContext(A)).run(161,full_public_budget qr qs) @ &m :
      res /\ accepted_coordinates_unique PrefixAudit.history].
  + rewrite Pr[mu_sub]; smt(prefix_unique_coordinates).
  smt().
qed.
