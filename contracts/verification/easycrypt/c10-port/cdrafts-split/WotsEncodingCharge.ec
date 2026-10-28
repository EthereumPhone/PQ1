(* The localized event is a subset of the preceding accepted-encoding event.
   Taking the minimum retains the old charge for every configured budget. *)
require import AllCore List FMap StdOrder.
require import C10RawOracle SelectedWotsCollision AcceptedWotsCollision.
require import WotsAcceptedPool AcceptedEncodingPool.
import RealOrder.

op best_wots_encoding_charge q n =
  if accepted_encoding_charge q<=conditional_encoding_charge n
  then accepted_encoding_charge q else conditional_encoding_charge n.

lemma selected_collision_is_accepted h :
  selected_accepted_collision h => accepted_wots_encoding_collision h.
proof. rewrite /selected_accepted_collision /accepted_wots_encoding_collision; smt(). qed.

lemma best_wots_encoding_charge_retains q n :
  best_wots_encoding_charge q n<=accepted_encoding_charge q.
proof. rewrite /best_wots_encoding_charge; smt(). qed.

lemma best_wots_encoding_charge_conditional q n :
  best_wots_encoding_charge q n<=conditional_encoding_charge n.
proof. rewrite /best_wots_encoding_charge; smt(). qed.
