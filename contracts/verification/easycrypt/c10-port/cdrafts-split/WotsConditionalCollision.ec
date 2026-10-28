(* The accepted-call budget is explicit here. Actual callers discharge it in
   their initialized games; this lemma alone is not a forgery bound. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid.
require import WotsAcceptedPrefix WotsAcceptedPool WotsMemoOracle WotsPoolRecords.
require import WotsPoolGame WotsPoolCollision SelectedWotsCollision AcceptedEncodingPool.
import RealOrder.

lemma wots_game_collision_recorded (C <: PrefixContext {-WotsMemo,-WotsAcceptedSamples}) :
  hoare [WotsMemoGame(C).run : true ==>
    size WotsAcceptedSamples.nodes<=WotsMemo.accepted_calls /\
    (selected_accepted_collision WotsMemo.rawhistory =>
      accepted_encoding_pool_collision WotsAcceptedSamples.nodes)].
proof.
  conseq (wots_game_records C); smt(selected_collision_in_pool).
qed.

lemma wots_game_conditional_collision_bound
  (C <: PrefixContext {-WotsMemo,-WotsAcceptedSamples}) n &m :
  0<=n => Pr[WotsMemoGame(C).run() @ &m :
    WotsMemo.accepted_calls<=n /\ selected_accepted_collision WotsMemo.rawhistory]
    <=conditional_encoding_charge n.
proof.
  move=> hn.
  have hz : Pr[WotsMemoGame(C).run() @ &m :
    !(size WotsAcceptedSamples.nodes<=WotsMemo.accepted_calls /\
      (selected_accepted_collision WotsMemo.rawhistory =>
        accepted_encoding_pool_collision WotsAcceptedSamples.nodes))]=0%r.
  + byphoare (_ : true ==> _) => //.
    hoare; conseq (wots_game_collision_recorded C); smt().
  have hb := wots_game_pool_bound C n &m hn.
  have hsub : Pr[WotsMemoGame(C).run() @ &m :
      WotsMemo.accepted_calls<=n /\ selected_accepted_collision WotsMemo.rawhistory] <=
    Pr[WotsMemoGame(C).run() @ &m :
      (size WotsAcceptedSamples.nodes<=n /\ accepted_encoding_pool_collision WotsAcceptedSamples.nodes) \/
      !(size WotsAcceptedSamples.nodes<=WotsMemo.accepted_calls /\
        (selected_accepted_collision WotsMemo.rawhistory =>
          accepted_encoding_pool_collision WotsAcceptedSamples.nodes))].
  + rewrite Pr[mu_sub]; smt().
  move: hsub; rewrite Pr[mu_or] hz; smt(ge0_mu).
qed.
