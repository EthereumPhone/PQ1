require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Randomizer RawKeygen PrefixGuess.
require import ProjectedBirthday MemoNodeCollision ProjectedMemoOracle PublicCollisionGame PublicCollisionBound NodeCollisionEvents.
import RealOrder.

lemma no_recording h (nodes : raw_input list) : public_node_collision h => !uniq nodes.
proof. exact (recorded_collision_implies_repeat h nodes). qed.
