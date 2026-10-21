require import AllCore List Distr FMap Xreal StdOrder.
require import C10RawOracle C10Randomizer.
import RField RealOrder.
require import MemoRejectCompletion.

lemma checked (A <: Context {-Shared}) accept xs &m : uniq xs =>
  Pr[MemoRejectGame(A).run() @ &m : memo_complete_rejection accept Shared.history xs] <=
    memo_reject_mass accept ^ size xs.
proof. exact (memo_reject_initialized_bound A accept xs &m). qed.
