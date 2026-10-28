require import AllCore StdOrder.
require import WrapperLeafSessionCost WrapperLeafOpeningBound.
import RealOrder.
lemma witness : wrapper_leaf_candidate_budget 3 2=1617019.
proof. rewrite /wrapper_leaf_candidate_budget /wrapper_leaf_public_budget; smt(). qed.
