require import AllCore StdOrder.
require import AddressedWrapperMemoSession AddressedWrapperByteCollision.
import RealOrder.
lemma witness : best_wrapper_addressed_node_charge 0 0<=retained_wrapper_node_charge 0 0.
proof. rewrite /best_wrapper_addressed_node_charge; smt(). qed.
lemma checked : retained_wrapper_node_charge 0 0<best_wrapper_addressed_node_charge 0 0.
proof. exact witness. qed.
