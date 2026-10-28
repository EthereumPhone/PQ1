require import AllCore List FMap StdOrder.
require import C10RawOracle SelectedWotsCollision AcceptedWotsCollision.
require import WotsAcceptedPool AcceptedEncodingPool.
import RealOrder.
require import WotsEncodingCharge.
lemma checked h :
  accepted_wots_encoding_collision h => selected_accepted_collision h.
proof. exact (selected_collision_is_accepted h). qed.
