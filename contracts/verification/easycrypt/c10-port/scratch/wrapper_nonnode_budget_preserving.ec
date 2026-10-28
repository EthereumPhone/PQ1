require import AllCore StdOrder.
require import WrapperLeafSessionCost WrapperLeafOpeningBound.
import RealOrder.

op regrouped_budget qr qs = 155135+qr+qs*(364892+771+364892)+771.
lemma checked qr qs : regrouped_budget qr qs=wrapper_leaf_candidate_budget qr qs.
proof. rewrite /regrouped_budget /wrapper_leaf_candidate_budget /wrapper_leaf_public_budget; smt(). qed.
