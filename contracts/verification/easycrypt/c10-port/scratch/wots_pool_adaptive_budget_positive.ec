require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid.
require import WotsAcceptedPrefix WotsAcceptedPool WotsMemoOracle WotsPoolRecords.
require import WotsPoolGame WotsPoolCollision SelectedWotsCollision AcceptedEncodingPool.
import RealOrder.
require import WotsConditionalCollision.
lemma checked
  (C <: PrefixContext {-WotsMemo,-WotsAcceptedSamples}) n &m :
  0<=n => Pr[WotsMemoGame(C).run() @ &m :
    WotsMemo.accepted_calls<=n /\ selected_accepted_collision WotsMemo.rawhistory]
    <=conditional_encoding_charge n.
proof. exact (wots_game_conditional_collision_bound C n &m). qed.
