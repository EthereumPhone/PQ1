require import AllCore List Distr FMap Xreal StdOrder.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid PrefixGames.
require import RawWots WotsAcceptanceMass MemoRejectCompletion WotsRejectDomain.
import RField RealOrder.
require import PhysicalRejectBound.

lemma checked
    (A <: PrefixContext {-Physical,-Shared}) seed n &m : 0<=n<=2^256 =>
  Pr[RealGame(A).run() @ &m : wots_domain_exhausted seed n Shared.history] <=
    wots_domain_charge n-1%r.
proof. exact (physical_wots_domain_bound A seed n &m). qed.
