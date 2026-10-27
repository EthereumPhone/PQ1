require import AllCore StdOrder.
require import AddressedWrapperMemoSession AddressedWrapperByteCollision.
import RealOrder.
lemma witness : wrapper_exceptional_public_budget 3 2=2324.
proof. by rewrite /wrapper_exceptional_public_budget; smt(). qed.
lemma checked : wrapper_exceptional_public_budget 3 2=1553.
proof. exact witness. qed.
