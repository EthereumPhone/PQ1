require import AllCore List Distr FMap Xreal StdOrder.
require import C10RawOracle C10Randomizer.
import RField RealOrder.
require import MemoRejectCompletion.

lemma checked (A <: Context {-Shared}) accept xs &m : uniq xs =>
  Pr[A(Shared).run() @ &m : memo_complete_rejection accept Shared.history xs] <=
    memo_reject_completion accept Shared.history{m} xs.
proof. exact (memo_reject_prefilled_bound A accept xs &m). qed.
