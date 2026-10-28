require import AllCore StdOrder.
require import WrapperLeafSessionCost WrapperLeafOpeningBound.
import RealOrder.
lemma witness : best_wrapper_leaf_charge 0 0<=retained_wrapper_fors_charge 0 0.
proof. rewrite /best_wrapper_leaf_charge; smt(). qed.
